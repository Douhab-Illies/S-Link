from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import (
    DB_BACKEND,
    DB_MYSQL_DATABASE,
    DB_MYSQL_HOST,
    DB_MYSQL_PASSWORD,
    DB_MYSQL_PORT,
    DB_MYSQL_USER,
    DB_POSTGRES_DSN,
    DB_SQLITE_FILE,
    LEGACY_SESSIONS_FILE,
    LEGACY_USER_DB_FILE,
    LEGACY_USERS_DIR,
    MIN_USER_PASSWORD_LENGTH,
    SESSIONS_FILE,
    USER_DB_FILE,
    USERS_DIR,
)
from vault_core import VaultError, vault_paths

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
VAULT_NAME_RE = re.compile(r"^[A-Za-z0-9_. -]{1,64}$")
PBKDF2_ITERATIONS = 240_000


class SQLAuthDatabase:
    """Petite couche SQL pour l'authentification.

    Backends supportés : SQLite, PostgreSQL et MySQL/MariaDB.
    SQLite ne demande aucune dépendance externe. PostgreSQL et MySQL demandent
    respectivement psycopg2-binary ou PyMySQL.
    """

    def __init__(self) -> None:
        self.backend = DB_BACKEND
        if self.backend not in {"sqlite", "postgres", "mysql"}:
            raise VaultError("VAULT_DB_BACKEND doit valoir sqlite, postgres ou mysql.")
        self.initialize_schema()

    @property
    def placeholder(self) -> str:
        return "?" if self.backend == "sqlite" else "%s"

    def connect(self):
        if self.backend == "sqlite":
            import sqlite3

            DB_SQLITE_FILE.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(DB_SQLITE_FILE)
            connection.row_factory = sqlite3.Row
            return connection

        if self.backend == "postgres":
            if not DB_POSTGRES_DSN.strip():
                raise VaultError("VAULT_POSTGRES_DSN est obligatoire avec VAULT_DB_BACKEND=postgres.")
            try:
                import psycopg2
                from psycopg2.extras import RealDictCursor
            except ImportError as exc:
                raise VaultError("Installe le driver PostgreSQL : pip install psycopg2-binary") from exc
            return psycopg2.connect(DB_POSTGRES_DSN, cursor_factory=RealDictCursor)

        if self.backend == "mysql":
            try:
                import pymysql
            except ImportError as exc:
                raise VaultError("Installe le driver MySQL : pip install PyMySQL") from exc
            return pymysql.connect(
                host=DB_MYSQL_HOST,
                port=DB_MYSQL_PORT,
                user=DB_MYSQL_USER,
                password=DB_MYSQL_PASSWORD,
                database=DB_MYSQL_DATABASE,
                charset="utf8mb4",
                cursorclass=pymysql.cursors.DictCursor,
            )

        raise VaultError("Base de données non prise en charge.")

    def initialize_schema(self) -> None:
        user_sql = """
        CREATE TABLE IF NOT EXISTS users (
            username VARCHAR(32) PRIMARY KEY,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            iterations INTEGER NOT NULL,
            created_at TEXT NOT NULL
        )
        """
        session_sql = """
        CREATE TABLE IF NOT EXISTS sessions (
            token VARCHAR(128) PRIMARY KEY,
            username VARCHAR(32) NOT NULL,
            created_at DOUBLE PRECISION NOT NULL
        )
        """
        self.execute(user_sql)
        self.execute(session_sql)

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        connection = self.connect()
        cursor = connection.cursor()
        try:
            cursor.execute(sql, params)
            connection.commit()
        finally:
            cursor.close()
            connection.close()

    def fetchone(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        connection = self.connect()
        cursor = connection.cursor()
        try:
            cursor.execute(sql, params)
            row = cursor.fetchone()
            if row is None:
                return None
            return dict(row)
        finally:
            cursor.close()
            connection.close()

    def fetchall(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        connection = self.connect()
        cursor = connection.cursor()
        try:
            cursor.execute(sql, params)
            return [dict(row) for row in cursor.fetchall()]
        finally:
            cursor.close()
            connection.close()

    def user_count(self) -> int:
        row = self.fetchone("SELECT COUNT(*) AS count FROM users")
        return int(row["count"] if row else 0)


class AuthManager:
    def __init__(self, users_dir: Path = USERS_DIR) -> None:
        self.users_dir = users_dir
        self.db = SQLAuthDatabase()
        self._ensure_storage()

    def _ensure_storage(self) -> None:
        self.users_dir.mkdir(parents=True, exist_ok=True)

        # Migration des anciens dossiers de coffres vers le stockage persistant.
        if LEGACY_USERS_DIR.exists() and LEGACY_USERS_DIR.resolve() != self.users_dir.resolve():
            shutil.copytree(LEGACY_USERS_DIR, self.users_dir, dirs_exist_ok=True)

        self._migrate_json_users()
        self._migrate_json_sessions()

    def _migrate_json_users(self) -> None:
        """Migre les comptes de l'ancienne version JSON vers la base SQL."""

        for json_file in (USER_DB_FILE, LEGACY_USER_DB_FILE):
            if not json_file.exists():
                continue
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue

            for username, user in data.get("users", {}).items():
                try:
                    username = self.normalize_username(username)
                    if self.user_exists(username):
                        continue
                    self._insert_user_hash(
                        username=username,
                        salt=str(user["salt"]),
                        password_hash=str(user["password_hash"]),
                        iterations=int(user.get("iterations", PBKDF2_ITERATIONS)),
                        created_at=str(user.get("created_at") or datetime.now(timezone.utc).isoformat()),
                    )
                except Exception:
                    # On ignore seulement l'entrée abîmée, pas toute la base.
                    continue

    def _migrate_json_sessions(self) -> None:
        """Migre les sessions de l'ancienne version JSON vers la base SQL."""

        for json_file in (SESSIONS_FILE, LEGACY_SESSIONS_FILE):
            if not json_file.exists():
                continue
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue

            for token, session in data.get("sessions", {}).items():
                try:
                    username = self.normalize_username(str(session.get("username", "")))
                    created_at = float(session.get("created_at", time.time()))
                    if self.user_exists(username):
                        self.save_session(str(token), username, created_at)
                except Exception:
                    continue

    def normalize_username(self, username: str) -> str:
        username = username.strip()
        if not USERNAME_RE.match(username):
            raise VaultError("Identifiant invalide. Utilise 3 à 32 caractères : lettres, chiffres, tiret, point ou underscore.")
        return username.lower()

    def validate_password(self, password: str) -> None:
        if len(password) < MIN_USER_PASSWORD_LENGTH:
            raise VaultError(f"Le mot de passe utilisateur doit contenir au moins {MIN_USER_PASSWORD_LENGTH} caractères.")

    def _hash_password(self, password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)

    def _insert_user_hash(self, username: str, salt: str, password_hash: str, iterations: int, created_at: str) -> None:
        p = self.db.placeholder
        self.db.execute(
            f"INSERT INTO users (username, salt, password_hash, iterations, created_at) VALUES ({p}, {p}, {p}, {p}, {p})",
            (username, salt, password_hash, iterations, created_at),
        )

    def _fetch_user(self, username: str) -> dict[str, Any] | None:
        p = self.db.placeholder
        return self.db.fetchone(
            f"SELECT username, salt, password_hash, iterations, created_at FROM users WHERE username = {p}",
            (username,),
        )

    def user_exists(self, username: str) -> bool:
        try:
            username = self.normalize_username(username)
        except VaultError:
            return False
        return self._fetch_user(username) is not None

    def create_user(self, username: str, password: str, confirmation: str) -> str:
        username = self.normalize_username(username)
        self.validate_password(password)
        if password != confirmation:
            raise VaultError("Les deux mots de passe utilisateur ne correspondent pas.")

        if self.user_exists(username):
            raise VaultError("Cet utilisateur existe déjà.")

        salt = os.urandom(16)
        digest = self._hash_password(password, salt)
        self._insert_user_hash(
            username=username,
            salt=base64.b64encode(salt).decode("ascii"),
            password_hash=base64.b64encode(digest).decode("ascii"),
            iterations=PBKDF2_ITERATIONS,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self.user_root(username).mkdir(parents=True, exist_ok=True)
        self.user_vaults_root(username).mkdir(parents=True, exist_ok=True)
        return username

    def verify_user(self, username: str, password: str) -> str:
        username = self.normalize_username(username)
        user = self._fetch_user(username)
        if not user:
            raise VaultError("Identifiant ou mot de passe incorrect.")

        salt = base64.b64decode(user["salt"])
        expected = base64.b64decode(user["password_hash"])
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            int(user.get("iterations", PBKDF2_ITERATIONS)),
        )
        if not hmac.compare_digest(digest, expected):
            raise VaultError("Identifiant ou mot de passe incorrect.")

        self.user_root(username).mkdir(parents=True, exist_ok=True)
        self.user_vaults_root(username).mkdir(parents=True, exist_ok=True)
        return username

    def save_session(self, token: str, username: str, created_at: float) -> None:
        p = self.db.placeholder
        existing = self.db.fetchone(f"SELECT token FROM sessions WHERE token = {p}", (token,))
        if existing:
            self.db.execute(
                f"UPDATE sessions SET username = {p}, created_at = {p} WHERE token = {p}",
                (username, created_at, token),
            )
        else:
            self.db.execute(
                f"INSERT INTO sessions (token, username, created_at) VALUES ({p}, {p}, {p})",
                (token, username, created_at),
            )

    def list_sessions(self) -> list[dict[str, Any]]:
        return self.db.fetchall("SELECT token, username, created_at FROM sessions")

    def delete_session(self, token: str) -> None:
        p = self.db.placeholder
        self.db.execute(f"DELETE FROM sessions WHERE token = {p}", (token,))

    def delete_expired_sessions(self, cutoff_created_at: float) -> None:
        p = self.db.placeholder
        self.db.execute(f"DELETE FROM sessions WHERE created_at < {p}", (cutoff_created_at,))

    def user_root(self, username: str) -> Path:
        username = self.normalize_username(username)
        return self.users_dir / username

    def user_vaults_root(self, username: str) -> Path:
        return self.user_root(username) / "vaults"

    def clean_vault_name(self, vault_name: str) -> str:
        vault_name = vault_name.strip()
        if not VAULT_NAME_RE.match(vault_name):
            raise VaultError("Nom de coffre invalide. Utilise lettres, chiffres, espaces, tiret, point ou underscore.")
        if vault_name in {".", ".."}:
            raise VaultError("Nom de coffre invalide.")
        return vault_name

    def user_vault_path(self, username: str, vault_name: str) -> Path:
        vault_name = self.clean_vault_name(vault_name)
        root = self.user_vaults_root(username).resolve()
        path = (root / vault_name).resolve()
        if root != path and root not in path.parents:
            raise VaultError("Chemin de coffre refusé.")
        return path

    def list_vaults(self, username: str) -> list[dict[str, str]]:
        root = self.user_vaults_root(username)
        root.mkdir(parents=True, exist_ok=True)
        vaults: list[dict[str, str]] = []

        for path in sorted(root.iterdir(), key=lambda p: p.name.lower()):
            if not path.is_dir():
                continue
            meta_path, manifest_path, blobs_path = vault_paths(path)
            if meta_path.exists() and manifest_path.exists() and blobs_path.exists():
                vaults.append({"name": path.name, "path": str(path)})

        return vaults

    def vault_exists(self, username: str, vault_name: str) -> bool:
        path = self.user_vault_path(username, vault_name)
        meta_path, manifest_path, blobs_path = vault_paths(path)
        return meta_path.exists() and manifest_path.exists() and blobs_path.exists()
