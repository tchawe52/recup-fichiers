"""
Récupérateur de fichiers supprimés - Windows
---------------------------------------------
Deux modes de récupération :
1. Corbeille Windows : retrouve les fichiers encore présents dans la Corbeille,
   avec leur nom d'origine et le dossier d'où ils viennent.
2. Scan par signature (carving) : cherche dans l'espace disque libre des
   fichiers dont l'en-tête correspond à un type connu (jpg, png, mp4, docx...),
   même s'ils ont été supprimés "définitivement" (vidés de la Corbeille).
   Ce mode ne garantit PAS de retrouver le dossier d'origine : plus le temps
   passe depuis la suppression, plus les chances baissent, car Windows peut
   avoir réécrit l'espace disque entre-temps.

Nécessite d'être lancé en tant qu'administrateur pour le scan par signature
(accès brut au disque).
"""

import os
import sys
import ctypes
import shutil
import struct
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime

import mft_recovery

# ----------------------------------------------------------------------
# Détection des droits administrateur (nécessaires pour le scan profond)
# ----------------------------------------------------------------------

def est_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def relancer_en_administrateur():
    """
    Relance le programme avec élévation UAC (demande la confirmation
    Windows standard), pour éviter d'obliger l'utilisateur à faire un
    clic droit -> "Exécuter en tant qu'administrateur" lui-même.

    Fonctionne pour tout compte membre du groupe Administrateurs. Pour un
    compte réellement standard (non-admin), Windows demandera un mot de
    passe administrateur — c'est une protection du système, impossible
    et dangereux à contourner.
    """
    if getattr(sys, "frozen", False):
        # Version compilée (.exe) : on relance l'exécutable lui-même.
        executable = sys.executable
        parametres = subprocess.list2cmdline(sys.argv[1:])
    else:
        # Version script (.py) : on relance via python.exe.
        executable = sys.executable
        parametres = subprocess.list2cmdline([os.path.abspath(sys.argv[0])] + sys.argv[1:])

    resultat = ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, parametres, None, 1)
    # ShellExecuteW renvoie une valeur <= 32 en cas d'échec (UAC refusé,
    # bloqué par un antivirus, etc.) — on le signale à l'appelant pour ne
    # pas fermer le programme dans le vide si la relance a échoué.
    return resultat > 32


# ----------------------------------------------------------------------
# Mode 1 : scan de la Corbeille Windows
# ----------------------------------------------------------------------

def lister_corbeille():
    """
    Retourne une liste de dicts : nom, chemin d'origine, date de suppression,
    et chemin réel du fichier dans $Recycle.Bin.
    Utilise pywin32 si disponible, sinon lecture directe de $Recycle.Bin.
    """
    resultats = []
    try:
        import win32com.client
        shell = win32com.client.Dispatch("Shell.Application")
        corbeille = shell.Namespace(10)  # 10 = dossier spécial Corbeille
        for item in corbeille.Items():
            try:
                chemin_origine = corbeille.GetDetailsOf(item, 0)
                date_suppr = corbeille.GetDetailsOf(item, 2)
                dossier_origine = corbeille.GetDetailsOf(item, 1)
                resultats.append({
                    "nom": item.Name,
                    "dossier_origine": dossier_origine,
                    "date_suppression": date_suppr,
                    "chemin_reel": item.Path,
                })
            except Exception:
                continue
    except ImportError:
        resultats.append({
            "nom": "(module pywin32 manquant)",
            "dossier_origine": "Installez pywin32 : pip install pywin32",
            "date_suppression": "",
            "chemin_reel": "",
        })
    return resultats


def restaurer_depuis_corbeille(chemin_reel, dossier_destination):
    os.makedirs(dossier_destination, exist_ok=True)
    nom_fichier = os.path.basename(chemin_reel)
    cible = os.path.join(dossier_destination, nom_fichier)
    shutil.copy2(chemin_reel, cible)
    return cible


# ----------------------------------------------------------------------
# Mode 2 : scan par signature dans l'espace disque libre (carving)
# ----------------------------------------------------------------------

SIGNATURES = {
    "jpg": (b"\xFF\xD8\xFF", b"\xFF\xD9"),
    "png": (b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82"),
    "mp4": (b"\x00\x00\x00\x18ftyp", None),
    "pdf": (b"%PDF-", b"%%EOF"),
    "docx": (b"PK\x03\x04", None),
}

TAILLE_BLOC = 1024 * 1024  # 1 Mo par lecture
TAILLE_MAX_FICHIER = 50 * 1024 * 1024  # on arrête la recherche de fin après 50 Mo


def scanner_disque(lettre_lecteur, extensions, dossier_destination, callback_progression=None):
    """
    Scan brut du disque à la recherche de signatures de fichiers connues.
    lettre_lecteur : ex. "C"
    extensions : liste parmi les clés de SIGNATURES, ex. ["jpg", "png"]
    Nécessite les droits administrateur.
    """
    if not est_admin():
        raise PermissionError("Ce scan nécessite de lancer le programme en tant qu'administrateur.")

    os.makedirs(dossier_destination, exist_ok=True)
    chemin_disque = rf"\\.\{lettre_lecteur}:"

    trouves = 0
    try:
        with open(chemin_disque, "rb") as disque:
            offset = 0
            tampon_precedent = b""
            while True:
                bloc = disque.read(TAILLE_BLOC)
                if not bloc:
                    break
                zone = tampon_precedent + bloc

                for ext in extensions:
                    debut_sig, fin_sig = SIGNATURES[ext]
                    pos = 0
                    while True:
                        idx = zone.find(debut_sig, pos)
                        if idx == -1:
                            break
                        if fin_sig:
                            idx_fin = zone.find(fin_sig, idx + len(debut_sig))
                            if idx_fin != -1:
                                contenu = zone[idx: idx_fin + len(fin_sig)]
                                trouves += 1
                                nom = f"recupere_{trouves:04d}.{ext}"
                                with open(os.path.join(dossier_destination, nom), "wb") as f:
                                    f.write(contenu)
                        pos = idx + len(debut_sig)

                tampon_precedent = zone[-64:]
                offset += len(bloc)
                if callback_progression:
                    callback_progression(offset, trouves)
    except PermissionError:
        raise
    except OSError as e:
        raise OSError(f"Impossible de lire le disque {lettre_lecteur}: : {e}")

    return trouves


# ----------------------------------------------------------------------
# Interface graphique
# ----------------------------------------------------------------------

class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Récupérateur de fichiers supprimés")
        self.geometry("760x520")
        self.resizable(True, True)

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.onglet_corbeille = ttk.Frame(self.notebook)
        self.onglet_scan = ttk.Frame(self.notebook)
        self.onglet_mft = ttk.Frame(self.notebook)
        self.notebook.add(self.onglet_corbeille, text="Corbeille")
        self.notebook.add(self.onglet_scan, text="Scan approfondi (disque)")
        self.notebook.add(self.onglet_mft, text="Scan MFT (noms & dossiers)")

        self._construire_onglet_corbeille()
        self._construire_onglet_scan()
        self._construire_onglet_mft()

    # --- Onglet Corbeille -------------------------------------------------
    def _construire_onglet_corbeille(self):
        f = self.onglet_corbeille

        ligne_filtre = ttk.Frame(f)
        ligne_filtre.pack(fill="x", padx=8, pady=(8, 0))
        ttk.Label(ligne_filtre, text="Dossier cible (optionnel, ex: Videos) :").pack(side="left")
        self.var_dossier_cible_corbeille = tk.StringVar()
        ttk.Entry(ligne_filtre, textvariable=self.var_dossier_cible_corbeille, width=30).pack(side="left", padx=5)

        bouton = ttk.Button(f, text="Lister les fichiers de la Corbeille", command=self._charger_corbeille)
        bouton.pack(pady=8)

        colonnes = ("nom", "dossier_origine", "date_suppression")
        self.arbre = ttk.Treeview(f, columns=colonnes, show="headings", selectmode="extended")
        for col, titre in zip(colonnes, ["Nom", "Dossier d'origine", "Date de suppression"]):
            self.arbre.heading(col, text=titre)
            self.arbre.column(col, width=230)
        self.arbre.pack(fill="both", expand=True, padx=8, pady=8)

        bas = ttk.Frame(f)
        bas.pack(fill="x", padx=8, pady=8)
        ttk.Label(bas, text="Dossier de destination :").pack(side="left")
        self.var_dest_corbeille = tk.StringVar()
        ttk.Entry(bas, textvariable=self.var_dest_corbeille, width=40).pack(side="left", padx=5)
        ttk.Button(bas, text="Choisir...", command=lambda: self._choisir_dossier(self.var_dest_corbeille)).pack(side="left")
        ttk.Button(bas, text="Restaurer la sélection", command=self._restaurer_selection).pack(side="right")

    def _charger_corbeille(self):
        for i in self.arbre.get_children():
            self.arbre.delete(i)
        tous = lister_corbeille()
        filtre = self.var_dossier_cible_corbeille.get().strip().lower()
        if filtre:
            tous = [item for item in tous if filtre in item["dossier_origine"].lower()]
        self._items_corbeille = tous
        for item in self._items_corbeille:
            self.arbre.insert("", "end", values=(item["nom"], item["dossier_origine"], item["date_suppression"]))

    def _restaurer_selection(self):
        dest = self.var_dest_corbeille.get().strip()
        if not dest:
            messagebox.showwarning("Dossier manquant", "Choisissez un dossier de destination.")
            return
        selection = self.arbre.selection()
        if not selection:
            messagebox.showwarning("Aucune sélection", "Sélectionnez au moins un fichier.")
            return
        restaures = 0
        for iid in selection:
            idx = self.arbre.index(iid)
            item = self._items_corbeille[idx]
            if not item["chemin_reel"]:
                continue
            try:
                restaurer_depuis_corbeille(item["chemin_reel"], dest)
                restaures += 1
            except Exception as e:
                messagebox.showerror("Erreur", f"Échec pour {item['nom']} : {e}")
        messagebox.showinfo("Terminé", f"{restaures} fichier(s) restauré(s) vers {dest}")

    # --- Onglet Scan approfondi --------------------------------------------
    def _construire_onglet_scan(self):
        f = self.onglet_scan

        ligne1 = ttk.Frame(f)
        ligne1.pack(fill="x", padx=8, pady=8)
        ttk.Label(ligne1, text="Lecteur à scanner (ex: C) :").pack(side="left")
        self.var_lecteur = tk.StringVar(value="C")
        ttk.Entry(ligne1, textvariable=self.var_lecteur, width=5).pack(side="left", padx=5)

        ligne2 = ttk.Frame(f)
        ligne2.pack(fill="x", padx=8, pady=8)
        ttk.Label(ligne2, text="Types de fichiers à chercher :").pack(side="left")
        self.vars_extensions = {}
        for ext in SIGNATURES:
            v = tk.BooleanVar(value=(ext in ("jpg", "png")))
            self.vars_extensions[ext] = v
            ttk.Checkbutton(ligne2, text=ext, variable=v).pack(side="left", padx=4)

        ligne3 = ttk.Frame(f)
        ligne3.pack(fill="x", padx=8, pady=8)
        ttk.Label(ligne3, text="Dossier de destination :").pack(side="left")
        self.var_dest_scan = tk.StringVar()
        ttk.Entry(ligne3, textvariable=self.var_dest_scan, width=40).pack(side="left", padx=5)
        ttk.Button(ligne3, text="Choisir...", command=lambda: self._choisir_dossier(self.var_dest_scan)).pack(side="left")

        self.bouton_scan = ttk.Button(f, text="Lancer le scan", command=self._lancer_scan)
        self.bouton_scan.pack(pady=10)

        self.barre = ttk.Progressbar(f, mode="indeterminate")
        self.barre.pack(fill="x", padx=8, pady=8)

        self.label_etat = ttk.Label(f, text="")
        self.label_etat.pack(pady=4)

        avertissement = (
            "⚠ Ce scan lit le disque entier à la recherche de fichiers. Il peut prendre\n"
            "de longues minutes à plusieurs heures selon la taille du disque.\n"
            "Il nécessite d'être lancé en tant qu'administrateur.\n"
            "Plus le temps écoulé depuis la suppression est long, plus les chances de\n"
            "récupération diminuent (l'espace disque peut avoir été réutilisé)."
        )
        ttk.Label(f, text=avertissement, foreground="#aa4400", justify="left").pack(padx=8, pady=8, anchor="w")

    def _choisir_dossier(self, variable):
        d = filedialog.askdirectory()
        if d:
            variable.set(d)

    def _lancer_scan(self):
        lecteur = self.var_lecteur.get().strip().rstrip(":")
        dest = self.var_dest_scan.get().strip()
        extensions = [ext for ext, v in self.vars_extensions.items() if v.get()]

        if not lecteur or not dest or not extensions:
            messagebox.showwarning("Champs manquants", "Renseignez le lecteur, le dossier de destination et au moins un type de fichier.")
            return

        self.bouton_scan.config(state="disabled")
        self.barre.start(10)

        def worker():
            def progression(offset, trouves):
                self.label_etat.config(text=f"{offset // (1024*1024)} Mo lus — {trouves} fichier(s) trouvé(s)")

            try:
                total = scanner_disque(lecteur, extensions, dest, callback_progression=progression)
                self.after(0, lambda: messagebox.showinfo("Terminé", f"Scan terminé : {total} fichier(s) récupéré(s) dans {dest}"))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Erreur", str(e)))
            finally:
                self.after(0, lambda: (self.barre.stop(), self.bouton_scan.config(state="normal")))

        threading.Thread(target=worker, daemon=True).start()

    # --- Onglet Scan MFT (noms & dossiers d'origine) -----------------------
    EXTENSIONS_COURANTES_MFT = [
        "jpg", "jpeg", "png", "gif", "bmp",
        "mp4", "avi", "mov", "mp3", "wav",
        "pdf", "docx", "doc", "xlsx", "xls",
        "pptx", "ppt", "txt", "zip", "rar",
    ]

    def _construire_onglet_mft(self):
        f = self.onglet_mft
        self._lignes_mft = {}       # iid Treeview -> EntreeMFT (pour la restauration)
        self._stop_event_mft = None

        ligne1 = ttk.Frame(f)
        ligne1.pack(fill="x", padx=8, pady=8)
        ttk.Label(ligne1, text="Lecteur à scanner (ex: C) :").pack(side="left")
        self.var_lecteur_mft = tk.StringVar(value="C")
        ttk.Entry(ligne1, textvariable=self.var_lecteur_mft, width=5).pack(side="left", padx=5)

        # --- Cases à cocher pour les extensions ---
        cadre_ext = ttk.LabelFrame(f, text="Types de fichiers à chercher (aucune case cochée = tous les types)")
        cadre_ext.pack(fill="x", padx=8, pady=6)
        self.vars_extensions_mft = {}
        for i, ext in enumerate(self.EXTENSIONS_COURANTES_MFT):
            v = tk.BooleanVar(value=False)
            self.vars_extensions_mft[ext] = v
            ttk.Checkbutton(cadre_ext, text=ext, variable=v).grid(row=i // 10, column=i % 10, sticky="w", padx=4, pady=2)

        ligne_autres = ttk.Frame(f)
        ligne_autres.pack(fill="x", padx=8, pady=(0, 6))
        ttk.Label(ligne_autres, text="Autres extensions (séparées par des virgules) :").pack(side="left")
        self.var_autres_extensions_mft = tk.StringVar(value="")
        ttk.Entry(ligne_autres, textvariable=self.var_autres_extensions_mft, width=20).pack(side="left", padx=5)

        # --- Dossier cible, avec sélecteur ---
        ligne_cible = ttk.Frame(f)
        ligne_cible.pack(fill="x", padx=8, pady=6)
        ttk.Label(ligne_cible, text="Dossier cible (optionnel) :").pack(side="left")
        self.var_dossier_cible_mft = tk.StringVar()
        ttk.Entry(ligne_cible, textvariable=self.var_dossier_cible_mft, width=30).pack(side="left", padx=5)
        ttk.Button(ligne_cible, text="Choisir...", command=self._choisir_dossier_cible_mft).pack(side="left")

        ligne_boutons = ttk.Frame(f)
        ligne_boutons.pack(pady=6)
        self.bouton_scan_mft = ttk.Button(ligne_boutons, text="Scanner la table MFT", command=self._lancer_scan_mft)
        self.bouton_scan_mft.pack(side="left", padx=4)
        self.bouton_arreter_mft = ttk.Button(ligne_boutons, text="Arrêter", command=self._arreter_scan_mft, state="disabled")
        self.bouton_arreter_mft.pack(side="left", padx=4)

        self.label_etat_mft = ttk.Label(f, text="")
        self.label_etat_mft.pack(pady=2)

        colonnes = ("nom", "dossier_origine", "taille")
        self.arbre_mft = ttk.Treeview(f, columns=colonnes, show="headings", selectmode="extended")
        for col, titre, largeur in zip(colonnes, ["Nom d'origine", "Dossier d'origine (probable)", "Taille (octets)"], [180, 320, 120]):
            self.arbre_mft.heading(col, text=titre)
            self.arbre_mft.column(col, width=largeur)
        self.arbre_mft.pack(fill="both", expand=True, padx=8, pady=8)

        bas = ttk.Frame(f)
        bas.pack(fill="x", padx=8, pady=8)
        ttk.Label(bas, text="Dossier de destination (où seront restaurés les fichiers choisis) :").pack(side="left")
        self.var_dest_mft = tk.StringVar()
        ttk.Entry(bas, textvariable=self.var_dest_mft, width=30).pack(side="left", padx=5)
        ttk.Button(bas, text="Choisir...", command=lambda: self._choisir_dossier(self.var_dest_mft)).pack(side="left")
        ttk.Button(bas, text="Restaurer la sélection", command=self._restaurer_selection_mft).pack(side="right")

        avertissement = (
            "⚠ Ce scan lit toute la table du système de fichiers (MFT) et peut prendre\n"
            "plusieurs minutes. Nécessite d'être lancé en tant qu'administrateur, et un\n"
            "disque NTFS (pas FAT32/exFAT, souvent utilisé sur les clés USB).\n"
            "Les résultats s'affichent au fur et à mesure du scan. Le dossier d'origine\n"
            "indiqué est une reconstruction, mise à jour une fois le scan terminé : si\n"
            "l'entrée du dossier parent a elle-même été réécrite, il sera marqué\n"
            "'(dossier parent inconnu)'. Le contenu du fichier n'est récupérable que si\n"
            "l'espace disque correspondant n'a pas été réutilisé depuis la suppression."
        )
        ttk.Label(f, text=avertissement, foreground="#aa4400", justify="left").pack(padx=8, pady=8, anchor="w")

    def _choisir_dossier_cible_mft(self):
        d = filedialog.askdirectory()
        if d:
            self.var_dossier_cible_mft.set(d)

    def _extensions_cochees_mft(self):
        extensions = [ext for ext, v in self.vars_extensions_mft.items() if v.get()]
        autres_brut = self.var_autres_extensions_mft.get().strip()
        if autres_brut:
            extensions += [e.strip().lower() for e in autres_brut.split(",") if e.strip()]
        return extensions or None  # None = pas de filtre, on prend tous les types

    def _filtre_dossier_cible_mft(self, lettre):
        """Convertit le dossier choisi (chemin complet, ex: C:/Users/Jean/Videos)
        en une sous-chaîne comparable au chemin reconstruit depuis la MFT
        (qui ne contient pas la lettre de lecteur)."""
        brut = self.var_dossier_cible_mft.get().strip()
        if not brut:
            return ""
        brut = brut.replace("/", "\\")
        prefixe_lecteur = f"{lettre}:\\"
        if brut.lower().startswith(prefixe_lecteur.lower()):
            brut = brut[len(prefixe_lecteur):]
        return brut.strip("\\").lower()

    def _arreter_scan_mft(self):
        if self._stop_event_mft is not None:
            self._stop_event_mft.set()
            self.label_etat_mft.config(text="Arrêt demandé... (les résultats déjà trouvés restent affichés)")

    def _lancer_scan_mft(self):
        lettre = self.var_lecteur_mft.get().strip().rstrip(":")
        extensions = self._extensions_cochees_mft()
        dossier_cible = self._filtre_dossier_cible_mft(lettre)

        if not lettre:
            messagebox.showwarning("Champ manquant", "Indiquez la lettre du lecteur.")
            return
        if not est_admin():
            messagebox.showerror("Droits insuffisants", "Relancez le programme en tant qu'administrateur pour scanner la MFT.")
            return

        self.bouton_scan_mft.config(state="disabled")
        self.bouton_arreter_mft.config(state="normal")
        for i in self.arbre_mft.get_children():
            self.arbre_mft.delete(i)
        self._lignes_mft = {}

        stop_event = threading.Event()
        self._stop_event_mft = stop_event

        def worker():
            entrees = {}
            correspondances = []  # liste d'EntreeMFT déjà affichées (avant filtre dossier cible)

            def progression(n):
                self.label_etat_mft.config(text=f"{n} entrées analysées... — {len(correspondances)} fichier(s) correspondant(s) trouvé(s) jusqu'ici")

            try:
                for entree in mft_recovery.scanner_mft_stream(lettre, stop_event=stop_event, callback_progression=progression):
                    entrees[entree.numero] = entree
                    if entree.supprime and not entree.est_dossier and entree.nom not in (".", ".."):
                        ext = os.path.splitext(entree.nom)[1].lower().lstrip(".")
                        if extensions and ext not in extensions:
                            continue
                        correspondances.append(entree)

                        def ajouter_ligne(item=entree):
                            iid = self.arbre_mft.insert("", "end", values=(item.nom, "(dossier en cours de localisation...)", item.taille))
                            self._lignes_mft[iid] = item

                        self.after(0, ajouter_ligne)

                # Scan terminé (ou arrêté) : on résout les chemins d'origine
                # maintenant que la table complète est connue, et on applique
                # le filtre "dossier cible" s'il a été renseigné.
                def finaliser():
                    nb_retires = 0
                    for iid, item in list(self._lignes_mft.items()):
                        chemin = mft_recovery.chemin_origine(entrees, item)
                        if dossier_cible and dossier_cible not in chemin.lower():
                            self.arbre_mft.delete(iid)
                            del self._lignes_mft[iid]
                            nb_retires += 1
                        else:
                            self.arbre_mft.set(iid, "dossier_origine", chemin)
                    etat = "Scan arrêté" if stop_event.is_set() else "Scan terminé"
                    self.label_etat_mft.config(
                        text=f"{etat} : {len(self._lignes_mft)} fichier(s) affiché(s)"
                        + (f" ({nb_retires} écarté(s) car hors du dossier cible)" if nb_retires else "")
                    )

                self.after(0, finaliser)
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Erreur", str(e)))
            finally:
                self.after(0, lambda: (self.bouton_scan_mft.config(state="normal"), self.bouton_arreter_mft.config(state="disabled")))

        threading.Thread(target=worker, daemon=True).start()

    def _restaurer_selection_mft(self):
        dest = self.var_dest_mft.get().strip()
        if not dest:
            messagebox.showwarning("Dossier manquant", "Choisissez un dossier de destination.")
            return
        selection = self.arbre_mft.selection()
        if not selection:
            messagebox.showwarning("Aucune sélection", "Sélectionnez au moins un fichier.")
            return

        lettre = self.var_lecteur_mft.get().strip().rstrip(":")
        try:
            disque_tmp = open(rf"\\.\{lettre}:", "rb")
            infos = mft_recovery.lire_secteur_boot(disque_tmp)
            disque_tmp.close()
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de relire le disque : {e}")
            return

        restaures, echecs = 0, 0
        for iid in selection:
            item = self._lignes_mft.get(iid)
            if item is None:
                continue
            try:
                mft_recovery.restaurer_fichier(lettre, item, infos["octets_par_cluster"], dest)
                restaures += 1
            except Exception:
                echecs += 1
        messagebox.showinfo("Terminé", f"{restaures} fichier(s) restauré(s), {echecs} échec(s) (données probablement écrasées).")


if __name__ == "__main__":
    if os.name != "nt":
        print("Ce programme est conçu pour Windows.")
        sys.exit(1)

    if not est_admin():
        relance_reussie = False
        try:
            relance_reussie = relancer_en_administrateur()
        except Exception:
            relance_reussie = False

        if relance_reussie:
            # La copie élevée a été lancée avec succès : cette instance-ci
            # n'a plus rien à faire.
            sys.exit(0)
        # Sinon (UAC refusé, bloqué par un antivirus, etc.) : on continue
        # normalement sans droits administrateur plutôt que de fermer le
        # programme sans explication. Les onglets qui nécessitent ces
        # droits (Scan approfondi, Scan MFT) afficheront un message clair
        # au moment où l'utilisateur essaiera de les utiliser.

    app = Application()
    app.mainloop()
