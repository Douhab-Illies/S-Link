# Gestionnaire de coffre chiffré

Interface web locale pour gérer des dossiers chiffrés avec plusieurs utilisateurs.

Cette version stocke l'authentification dans une base SQL au choix : **SQLite**, **PostgreSQL** ou **MySQL/MariaDB**.

## Lancement rapide avec SQLite

SQLite est le mode par défaut et ne demande aucune dépendance supplémentaire.

```bash
pip install -r requirements.txt
python3 main.py
```

Puis ouvrir :

```text
http://127.0.0.1:8765
```

Par défaut, la base SQLite est ici :

```text
~/.secure_vault_app/auth.sqlite3
```

Les coffres restent dans :

```text
~/.secure_vault_app/users/<utilisateur>/vaults/
```

## Choisir la base de données

### SQLite

```bash
VAULT_DB_BACKEND=sqlite python3 main.py
```

Changer le chemin du fichier SQLite :

```bash
VAULT_DB_BACKEND=sqlite \
VAULT_SQLITE_FILE=/home/illies/vault_auth.sqlite3 \
python3 main.py
```

### PostgreSQL

Installer le driver :

```bash
pip install -r requirements.txt
pip install -r optional-requirements-postgres.txt
```

Créer une base PostgreSQL, puis lancer l'application :

```bash
VAULT_DB_BACKEND=postgres \
VAULT_POSTGRES_DSN="dbname=vault_app user=vault_user password=secret host=127.0.0.1 port=5432" \
python3 main.py
```

### MySQL / MariaDB

Installer le driver :

```bash
pip install -r requirements.txt
pip install -r optional-requirements-mysql.txt
```

Créer une base MySQL/MariaDB, puis lancer l'application :

```bash
VAULT_DB_BACKEND=mysql \
VAULT_MYSQL_HOST=127.0.0.1 \
VAULT_MYSQL_PORT=3306 \
VAULT_MYSQL_USER=vault_user \
VAULT_MYSQL_PASSWORD=secret \
VAULT_MYSQL_DATABASE=vault_app \
python3 main.py
```

## Ce qui est stocké en base SQL

La base SQL contient :

```text
users
├── username
├── salt
├── password_hash
├── iterations
└── created_at

sessions
├── token
├── username
└── created_at
```

Les mots de passe utilisateurs ne sont pas stockés en clair. L'application stocke seulement un hash PBKDF2 avec un sel aléatoire.

## Ce qui reste sur disque

Les coffres chiffrés restent sur le disque, séparés par utilisateur :

```text
~/.secure_vault_app/
└── users/
    └── <utilisateur>/
        └── vaults/
            └── <coffre>/
                ├── meta.json
                ├── manifest.fernet
                └── blobs/
```

Tu peux changer le dossier de stockage des coffres avec :

```bash
VAULT_APP_DATA=/chemin/perso python3 main.py
```

## Migration automatique

Si tu avais déjà une version avec :

```text
~/.secure_vault_app/users.json
~/.secure_vault_app/sessions.json
```

ou avec l'ancien dossier local :

```text
vault_web_project/app_data/
```

l'application essaie de migrer automatiquement les comptes, sessions et coffres vers la nouvelle base SQL au premier lancement.

## Fonctionnalités

- Page de connexion avec identifiant et mot de passe utilisateur.
- Création de compte utilisateur.
- Authentification stockée dans SQLite, PostgreSQL ou MySQL/MariaDB.
- Un répertoire séparé par utilisateur.
- Chaque utilisateur voit uniquement ses propres coffres.
- Après connexion, l'utilisateur peut :
  - voir la liste de ses coffres ;
  - créer un nouveau coffre ;
  - ouvrir uniquement un coffre de sa propre liste.
- Gestion des fichiers dans le coffre ouvert : ajout depuis le navigateur client, extraction par téléchargement côté client, suppression, téléchargement simple ou multiple.

## Mot de passe utilisateur et mot de passe du coffre

Il y a deux niveaux :

1. le mot de passe utilisateur sert à se connecter à l'application ;
2. le mot de passe du coffre sert à chiffrer/déchiffrer le contenu du coffre.

Tu peux utiliser le même mot de passe pour les deux pendant tes tests, mais pour une vraie utilisation il est préférable de les distinguer.

## Ajout de fichiers côté client

Le bouton **Sélectionner fichier(s)** utilise maintenant le sélecteur de fichiers du navigateur :

```html
<input type="file" multiple>
```

Cela signifie que la fenêtre ouvre les fichiers de l'ordinateur du **client**, puis les fichiers sont envoyés au serveur et chiffrés dans le coffre.

Conséquence normale d'une application web : le navigateur ne transmet pas le vrai chemin local du fichier et ne permet pas de supprimer automatiquement l'original sur l'ordinateur du client.

Le code ne dépend pas de Tkinter, PyQt, Zenity, KDialog ou Yad.


## Extraction côté client

La fonctionnalité **Extraire un fichier** ne demande plus de dossier de destination serveur.
L'utilisateur choisit un fichier dans le coffre, puis le navigateur télécharge le fichier déchiffré sur l'ordinateur du **client**.

L'option **Supprimer du coffre après l’extraction** reste disponible : le serveur prépare le téléchargement, puis supprime la version chiffrée du coffre si l'option est cochée.

## Compatibilité des coffres

Le format du coffre reste compatible :

```text
mon_coffre/
├── meta.json
├── manifest.fernet
└── blobs/
```

Pour faire apparaître un ancien coffre dans la liste d'un utilisateur, place son dossier dans :

```text
~/.secure_vault_app/users/<utilisateur>/vaults/
```

Exemple :

```bash
mkdir -p ~/.secure_vault_app/users/illies/vaults
cp -r /home/illies/Documents/Projet_Perso/mon_coffre ~/.secure_vault_app/users/illies/vaults/mon_coffre
```
