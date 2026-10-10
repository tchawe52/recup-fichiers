# Récupérateur de fichiers supprimés — Windows

Application avec interface graphique pour :
- Retrouver les fichiers encore présents dans la **Corbeille** (avec leur dossier d'origine)
- Faire un **scan approfondi** du disque pour tenter de retrouver des fichiers
  supprimés définitivement (vidés de la Corbeille), par reconnaissance de signature
  (jpg, png, mp4, pdf, docx)

---

## Étape 1 — Mettre le projet sur GitHub depuis Termux

1. Installe Git dans Termux (si ce n'est pas déjà fait) :
   ```
   pkg install git -y
   ```

2. Crée un dépôt vide sur https://github.com (bouton "New repository"),
   par exemple nommé `recup-fichiers`. Ne coche aucune case (pas de README,
   pas de licence) — le dépôt doit être totalement vide.

3. Dans Termux, place-toi dans le dossier du projet (celui que je t'ai donné,
   décompressé) et envoie-le vers GitHub :
   ```
   cd recup-fichiers
   git init
   git add .
   git commit -m "Première version"
   git branch -M main
   git remote add origin https://github.com/TON-NOM-UTILISATEUR/recup-fichiers.git
   git push -u origin main
   ```
   Il te demandera ton identifiant GitHub et un **token** (pas ton mot de
   passe) — tu le crées sur GitHub dans Settings → Developer settings →
   Personal access tokens → Generate new token (coche juste "repo").

---

## Étape 2 — Récupérer le fichier .exe compilé automatiquement

Dès que le `push` est terminé, GitHub compile automatiquement l'application
pour Windows (grâce au fichier `.github/workflows/build-windows.yml`).

1. Va sur ton dépôt GitHub, onglet **"Actions"**
2. Clique sur le dernier workflow en cours ou terminé ("Build Windows EXE")
3. Une fois qu'il est vert (terminé), descends en bas de la page jusqu'à
   **"Artifacts"**
4. Télécharge `RecupFichiers-Windows` (c'est un .zip contenant le .exe)

Ce `.exe` est **portable** : pas besoin d'installer quoi que ce soit sur
le Windows cible. Tu le copies (clé USB, mail, etc.) sur n'importe quel
PC Windows, tu doubles-cliques dessus, et ça marche — même si Windows n'a
jamais eu Python installé.

Pour le scan approfondi (onglet "Scan approfondi"), il faut faire
clic droit → **"Exécuter en tant qu'administrateur"**.

---

## Étape 3 — Modifier l'application plus tard

Si tu veux changer quelque chose, modifie `app/recovery_app.py`, puis :
```
git add .
git commit -m "Modification"
git push
```
GitHub recompile automatiquement un nouveau .exe à chaque envoi.

---

## Limites importantes à expliquer à tes clients

- La Corbeille retrouve le nom **et** le dossier d'origine, de façon fiable,
  tant qu'elle n'a pas été vidée.
- Le scan approfondi retrouve le **contenu** d'un fichier supprimé définitivement,
  mais ne peut pas toujours dire de quel dossier il venait — cette information
  n'est conservée que si l'entrée du système de fichiers n'a pas été réécrite
  depuis la suppression.
- Plus le temps passe entre la suppression et la tentative de récupération,
  plus les chances baissent, car Windows réutilise l'espace disque libre.
