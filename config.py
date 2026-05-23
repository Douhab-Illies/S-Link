from __future__ import annotations

import os
from pathlib import Path

META_FILE = "meta.json"
MANIFEST_FILE = "manifest.fernet"
BLOBS_DIR = "blobs"

MIN_PASSWORD_LENGTH = 12
MIN_USER_PASSWORD_LENGTH = 8
HOST = "127.0.0.1"
PORT = 8765

# Dossier du projet. L'ancien stockage relatif utilisait ./app_data.
PROJECT_DIR = Path(__file__).resolve().parent
LEGACY_APP_DATA_DIR = PROJECT_DIR / "app_data"
LEGACY_USERS_DIR = LEGACY_APP_DATA_DIR / "users"
LEGACY_USER_DB_FILE = LEGACY_APP_DATA_DIR / "users.json"
LEGACY_SESSIONS_FILE = LEGACY_APP_DATA_DIR / "sessions.json"

# Stockage persistant des coffres utilisateurs et, par défaut, de SQLite.
# Tu peux changer le dossier avec : VAULT_APP_DATA=/chemin/perso python3 main.py
APP_DATA_DIR = Path(os.environ.get("VAULT_APP_DATA", "./.secure_vault_app")).expanduser().resolve()
USERS_DIR = APP_DATA_DIR / "users"

# Anciens fichiers JSON de la version précédente. Ils servent uniquement à migrer
# automatiquement les comptes/sessions vers la base SQL.
USER_DB_FILE = APP_DATA_DIR / "users.json"
SESSIONS_FILE = APP_DATA_DIR / "sessions.json"

# Base de données pour l'authentification : sqlite, postgres ou mysql.
# Par défaut : sqlite, sans dépendance externe.
DB_BACKEND = os.environ.get("VAULT_DB_BACKEND", "sqlite").strip().lower()
DB_SQLITE_FILE = Path(os.environ.get("VAULT_SQLITE_FILE", APP_DATA_DIR / "auth.sqlite3")).expanduser().resolve()

# PostgreSQL : exemple
# VAULT_DB_BACKEND=postgres
# VAULT_POSTGRES_DSN="dbname=vault_app user=vault_user password=secret host=127.0.0.1 port=5432"
DB_POSTGRES_DSN = os.environ.get("VAULT_POSTGRES_DSN", "")

# MySQL / MariaDB : exemple
# VAULT_DB_BACKEND=mysql
# VAULT_MYSQL_HOST=127.0.0.1 VAULT_MYSQL_USER=vault_user VAULT_MYSQL_PASSWORD=secret VAULT_MYSQL_DATABASE=vault_app
DB_MYSQL_HOST = os.environ.get("VAULT_MYSQL_HOST", "127.0.0.1")
DB_MYSQL_PORT = int(os.environ.get("VAULT_MYSQL_PORT", "3306"))
DB_MYSQL_USER = os.environ.get("VAULT_MYSQL_USER", "root")
DB_MYSQL_PASSWORD = os.environ.get("VAULT_MYSQL_PASSWORD", "")
DB_MYSQL_DATABASE = os.environ.get("VAULT_MYSQL_DATABASE", "vault_app")

SESSION_COOKIE_NAME = "vault_session"
SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 14


def database_label() -> str:
    if DB_BACKEND == "sqlite":
        return f"SQLite — {DB_SQLITE_FILE}"
    if DB_BACKEND == "postgres":
        return "PostgreSQL"
    if DB_BACKEND == "mysql":
        return "MySQL / MariaDB"
    return DB_BACKEND
