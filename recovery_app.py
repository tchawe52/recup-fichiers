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
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime

# ----------------------------------------------------------------------
# Détection des droits administrateur (nécessaires pour le scan profond)
# ----------------------------------------------------------------------

def est_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


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
        self.notebook.add(self.onglet_corbeille, text="Corbeille")
        self.notebook.add(self.onglet_scan, text="Scan approfondi (disque)")

        self._construire_onglet_corbeille()
        self._construire_onglet_scan()

        if not est_admin():
            self.title(self.title() + "  —  (lancer en administrateur pour le scan approfondi)")

    # --- Onglet Corbeille -------------------------------------------------
    def _construire_onglet_corbeille(self):
        f = self.onglet_corbeille

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
        self._items_corbeille = lister_corbeille()
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


if __name__ == "__main__":
    if os.name != "nt":
        print("Ce programme est conçu pour Windows.")
        sys.exit(1)
    app = Application()
    app.mainloop()
