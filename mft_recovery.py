"""
Lecture de la table MFT (Master File Table) d'un disque NTFS.
--------------------------------------------------------------
Permet de retrouver, pour un fichier supprimé, son nom d'origine et le
dossier dans lequel il se trouvait — tant que son entrée dans la table
n'a pas été réécrite par Windows depuis la suppression.

Fonctionne uniquement sur des volumes NTFS. Nécessite les droits
administrateur (accès brut au disque).
"""

import struct
import os


class EntreeMFT:
    def __init__(self, numero, nom, ref_parent, supprime, est_dossier, plages_donnees, taille):
        self.numero = numero
        self.nom = nom
        self.ref_parent = ref_parent  # numéro d'enregistrement MFT du dossier parent
        self.supprime = supprime
        self.est_dossier = est_dossier
        self.plages_donnees = plages_donnees  # liste de (cluster_debut, nb_clusters)
        self.taille = taille


def lire_secteur_boot(disque):
    disque.seek(0)
    boot = disque.read(512)
    if len(boot) < 512:
        raise OSError("Impossible de lire le secteur de démarrage.")
    octets_par_secteur = struct.unpack("<H", boot[11:13])[0]
    secteurs_par_cluster = boot[13]
    cluster_mft = struct.unpack("<Q", boot[48:56])[0]
    taille_record_brute = struct.unpack("<b", boot[64:65])[0]
    octets_par_cluster = octets_par_secteur * secteurs_par_cluster
    if taille_record_brute > 0:
        taille_record_mft = taille_record_brute * octets_par_cluster
    else:
        taille_record_mft = 1 << (-taille_record_brute)
    return {
        "octets_par_secteur": octets_par_secteur,
        "octets_par_cluster": octets_par_cluster,
        "offset_mft": cluster_mft * octets_par_cluster,
        "taille_record_mft": taille_record_mft,
    }


def _appliquer_fixup(enregistrement, octets_par_secteur):
    """Corrige les 2 derniers octets de chaque secteur (protection NTFS)."""
    try:
        offset_usa = struct.unpack("<H", enregistrement[4:6])[0]
        nb_usa = struct.unpack("<H", enregistrement[6:8])[0]
        usa = enregistrement[offset_usa: offset_usa + nb_usa * 2]
        enregistrement = bytearray(enregistrement)
        for i in range(1, nb_usa):
            fin_secteur = i * octets_par_secteur
            pos = fin_secteur - 2
            if pos + 2 <= len(enregistrement):
                enregistrement[pos:pos + 2] = usa[i * 2: i * 2 + 2]
        return bytes(enregistrement)
    except Exception:
        return enregistrement


def _lire_data_runs(data):
    plages = []
    i = 0
    cluster_courant = 0
    while i < len(data):
        entete = data[i]
        if entete == 0:
            break
        taille_longueur = entete & 0x0F
        taille_offset = (entete >> 4) & 0x0F
        i += 1
        longueur = int.from_bytes(data[i:i + taille_longueur], "little")
        i += taille_longueur
        if taille_offset > 0:
            decalage = int.from_bytes(data[i:i + taille_offset], "little", signed=True)
        else:
            decalage = 0
        i += taille_offset
        cluster_courant += decalage
        plages.append((cluster_courant, longueur))
    return plages


def _analyser_enregistrement(record, numero, octets_par_secteur):
    if record[0:4] != b"FILE":
        return None
    record = _appliquer_fixup(record, octets_par_secteur)
    drapeaux = struct.unpack("<H", record[22:24])[0]
    en_cours_utilisation = bool(drapeaux & 0x01)
    est_dossier = bool(drapeaux & 0x02)
    offset_attributs = struct.unpack("<H", record[20:22])[0]

    nom = None
    ref_parent = None
    plages_donnees = []
    taille = 0

    offset = offset_attributs
    while offset < len(record) - 8:
        type_attr = struct.unpack("<I", record[offset:offset + 4])[0]
        if type_attr == 0xFFFFFFFF:
            break
        longueur_attr = struct.unpack("<I", record[offset + 4:offset + 8])[0]
        if longueur_attr == 0 or offset + longueur_attr > len(record):
            break
        non_resident = record[offset + 8]

        if type_attr == 0x30:  # $FILE_NAME : nom + référence du dossier parent
            if non_resident == 0:
                offset_contenu = struct.unpack("<H", record[offset + 20:offset + 22])[0]
                base = offset + offset_contenu
                ref_brute = struct.unpack("<Q", record[base:base + 8])[0]
                candidat_parent = ref_brute & 0x0000FFFFFFFFFFFF
                longueur_nom = record[base + 64]
                espace_nom = record[base + 65]
                brut = record[base + 66: base + 66 + longueur_nom * 2]
                try:
                    candidat_nom = brut.decode("utf-16-le")
                    if nom is None or espace_nom in (0, 1, 3):
                        nom = candidat_nom
                        ref_parent = candidat_parent
                except Exception:
                    pass

        elif type_attr == 0x80:  # $DATA : contenu du fichier
            if non_resident == 0:
                taille = struct.unpack("<I", record[offset + 16:offset + 20])[0]
            else:
                taille = struct.unpack("<Q", record[offset + 48:offset + 56])[0]
                offset_runs = struct.unpack("<H", record[offset + 32:offset + 34])[0]
                donnees_runs = record[offset + offset_runs: offset + longueur_attr]
                plages_donnees = _lire_data_runs(donnees_runs)

        offset += longueur_attr

    if nom is None:
        return None

    return EntreeMFT(numero, nom, ref_parent, not en_cours_utilisation, est_dossier, plages_donnees, taille)


def scanner_mft(lettre_lecteur, callback_progression=None, limite_entrees=None):
    """
    Scanne toute la table MFT du lecteur donné et retourne :
    - un dict {numero_entree: EntreeMFT} pour tous les enregistrements lisibles
    - permet ensuite de reconstruire le chemin d'origine d'un fichier supprimé
      en remontant la chaîne des dossiers parents.
    """
    chemin_disque = rf"\\.\{lettre_lecteur}:"
    with open(chemin_disque, "rb") as disque:
        infos = lire_secteur_boot(disque)
        taille_record = infos["taille_record_mft"]
        disque.seek(infos["offset_mft"])

        entrees = {}
        numero = 0
        while True:
            if limite_entrees and numero >= limite_entrees:
                break
            data = disque.read(taille_record)
            if len(data) < taille_record:
                break
            entree = _analyser_enregistrement(data, numero, infos["octets_par_secteur"])
            if entree is not None:
                entrees[numero] = entree
            numero += 1
            if callback_progression and numero % 2000 == 0:
                callback_progression(numero)

    return entrees


def chemin_origine(entrees, entree, profondeur_max=40):
    """
    Reconstruit le chemin d'origine probable d'une entrée en remontant la
    chaîne de dossiers parents. Si un parent n'est plus retrouvable dans la
    table (son entrée a été réécrite), le chemin s'arrête à ce niveau et
    est marqué comme partiel.
    """
    segments = []
    courant = entree
    profondeur = 0
    complet = True

    while profondeur < profondeur_max:
        if courant.ref_parent is None or courant.ref_parent == courant.numero:
            break
        parent = entrees.get(courant.ref_parent)
        if parent is None:
            complet = False
            break
        if parent.nom and parent.nom != ".":
            segments.append(parent.nom)
        if parent.ref_parent == 5 or parent.ref_parent is None:
            break
        courant = parent
        profondeur += 1

    segments.reverse()
    prefixe = "" if complet else "(dossier parent inconnu)\\"
    return prefixe + "\\".join(segments)


def lister_fichiers_supprimes(entrees, extensions=None):
    """Retourne la liste des entrées supprimées (fichiers, pas dossiers),
    filtrée par extension si précisé."""
    resultats = []
    for entree in entrees.values():
        if not entree.supprime or entree.est_dossier:
            continue
        if not entree.nom or entree.nom in (".", ".."):
            continue
        if extensions:
            ext = os.path.splitext(entree.nom)[1].lower().lstrip(".")
            if ext not in extensions:
                continue
        resultats.append(entree)
    return resultats


def restaurer_fichier(lettre_lecteur, entree, octets_par_cluster, dossier_destination):
    """Relit les clusters du fichier directement sur le disque brut et les
    écrit dans le dossier de destination sous le nom d'origine."""
    if not entree.plages_donnees:
        raise ValueError("Aucune donnée récupérable pour ce fichier (probablement écrasée).")

    os.makedirs(dossier_destination, exist_ok=True)
    nom_sain = "".join(c for c in entree.nom if c not in '\\/:*?"<>|')
    cible = os.path.join(dossier_destination, nom_sain)

    base, ext = os.path.splitext(cible)
    compteur = 1
    while os.path.exists(cible):
        cible = f"{base}_{compteur}{ext}"
        compteur += 1

    chemin_disque = rf"\\.\{lettre_lecteur}:"
    octets_restants = entree.taille
    with open(chemin_disque, "rb") as disque, open(cible, "wb") as sortie:
        for cluster_debut, nb_clusters in entree.plages_donnees:
            disque.seek(cluster_debut * octets_par_cluster)
            a_lire = min(nb_clusters * octets_par_cluster, octets_restants) if octets_restants > 0 else nb_clusters * octets_par_cluster
            bloc = disque.read(nb_clusters * octets_par_cluster)
            if octets_restants > 0:
                bloc = bloc[:a_lire]
                octets_restants -= a_lire
            sortie.write(bloc)

    return cible
