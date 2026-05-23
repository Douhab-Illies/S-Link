from __future__ import annotations

import base64
import json
import os
import shutil
import uuid
from pathlib import Path, PurePosixPath

from cryptography.fernet import Fernet, InvalidToken

from config import BLOBS_DIR, MANIFEST_FILE, META_FILE, MIN_PASSWORD_LENGTH
from vault_crypto import decrypt_json, derive_key, encrypt_json


class VaultError(Exception):
    """Erreur utilisateur pour le coffre chiffré."""


def vault_paths(vault: Path) -> tuple[Path, Path, Path]:
    return vault / META_FILE, vault / MANIFEST_FILE, vault / BLOBS_DIR


def human_size(size: int) -> str:
    units = ["o", "Ko", "Mo", "Go", "To"]
    value = float(size)

    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "o":
                return f"{int(value)} {unit}"
            return f"{value:.2f} {unit}"
        value /= 1024

    return f"{size} o"


def clean_archive_name(name: str) -> str:
    """Nettoie un nom reçu depuis le navigateur avant stockage dans le coffre.

    Un navigateur peut envoyer un simple nom de fichier ou un chemin relatif
    quand l'utilisateur sélectionne un dossier. On refuse les chemins absolus,
    les retours parent `..` et les noms vides.
    """

    raw = name.replace("\\", "/").strip()
    if not raw:
        raise VaultError("Nom de fichier vide.")

    path = PurePosixPath(raw)
    if path.is_absolute():
        raise VaultError("Chemin absolu refusé pour un fichier importé.")

    parts = [part for part in path.parts if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts):
        raise VaultError("Nom de fichier importé dangereux.")

    return str(PurePosixPath(*parts))


def iter_source_files(source: Path):
    if source.is_file():
        yield source, source.name
        return

    if source.is_dir():
        root_name = source.name
        for file_path in source.rglob("*"):
            if file_path.is_file():
                archived_name = str(Path(root_name) / file_path.relative_to(source))
                yield file_path, archived_name
        return

    raise VaultError("Fichier ou dossier introuvable.")


def safe_output_path(destination: Path, archived_name: str) -> Path:
    destination = destination.resolve()
    output = (destination / archived_name).resolve()

    if destination != output and destination not in output.parents:
        raise VaultError("Chemin de sortie dangereux détecté.")

    return output


class VaultCore:
    def __init__(self) -> None:
        self.vault_path: Path | None = None
        self.fernet: Fernet | None = None
        self.manifest: dict | None = None
        self.blobs_path: Path | None = None

    @property
    def is_open(self) -> bool:
        return self.vault_path is not None and self.fernet is not None and self.manifest is not None

    def close(self) -> None:
        self.vault_path = None
        self.fernet = None
        self.manifest = None
        self.blobs_path = None

    def require_open(self) -> tuple[Path, Fernet, dict, Path]:
        if not self.is_open:
            raise VaultError("Aucun coffre ouvert.")

        assert self.vault_path is not None
        assert self.fernet is not None
        assert self.manifest is not None
        assert self.blobs_path is not None
        return self.vault_path, self.fernet, self.manifest, self.blobs_path

    def save_manifest(self) -> None:
        vault_path, fernet, manifest, _ = self.require_open()
        manifest_path = vault_path / MANIFEST_FILE
        manifest_path.write_bytes(encrypt_json(fernet, manifest))

    def create(self, vault_dir: str, password: str, confirmation: str) -> None:
        if not vault_dir.strip():
            raise VaultError("Indique un chemin de coffre.")

        if len(password) < MIN_PASSWORD_LENGTH:
            raise VaultError(f"Le mot de passe doit contenir au moins {MIN_PASSWORD_LENGTH} caractères.")

        if password != confirmation:
            raise VaultError("Les deux mots de passe ne correspondent pas.")

        vault = Path(vault_dir).expanduser().resolve()
        meta_path, manifest_path, blobs_path = vault_paths(vault)

        if meta_path.exists() or manifest_path.exists():
            raise VaultError("Un coffre existe déjà dans ce dossier.")

        vault.mkdir(parents=True, exist_ok=True)
        blobs_path.mkdir(exist_ok=True)

        salt = os.urandom(16)
        key = derive_key(password, salt)
        fernet = Fernet(key)

        meta = {
            "version": 1,
            "kdf": "scrypt",
            "salt": base64.b64encode(salt).decode("ascii"),
            "scrypt": {"n": 2**14, "r": 8, "p": 1},
        }

        manifest = {
            "version": 1,
            "files": {},
        }

        meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        manifest_path.write_bytes(encrypt_json(fernet, manifest))

        self.vault_path = vault
        self.fernet = fernet
        self.manifest = manifest
        self.blobs_path = blobs_path

    def open(self, vault_dir: str, password: str) -> None:
        if not vault_dir.strip():
            raise VaultError("Indique un chemin de coffre.")

        vault = Path(vault_dir).expanduser().resolve()
        meta_path, manifest_path, blobs_path = vault_paths(vault)

        if not meta_path.exists() or not manifest_path.exists() or not blobs_path.exists():
            raise VaultError("Ce dossier n’est pas un coffre valide.")

        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        salt = base64.b64decode(meta["salt"])
        key = derive_key(password, salt)
        fernet = Fernet(key)

        try:
            manifest = decrypt_json(fernet, manifest_path.read_bytes())
        except InvalidToken as exc:
            raise VaultError("Mot de passe incorrect ou coffre corrompu.") from exc

        self.vault_path = vault
        self.fernet = fernet
        self.manifest = manifest
        self.blobs_path = blobs_path

    def list_files(self) -> list[tuple[str, dict]]:
        _, _, manifest, _ = self.require_open()
        return sorted(manifest.get("files", {}).items())

    def add_path(self, source_path: str, move_after_add: bool) -> int:
        _, fernet, manifest, blobs_path = self.require_open()

        if not source_path.strip():
            raise VaultError("Indique le chemin du fichier ou dossier à ajouter.")

        source = Path(source_path).expanduser().resolve()
        added = 0
        written_blobs: list[Path] = []

        try:
            for file_path, archived_name in iter_source_files(source):
                blob_name = uuid.uuid4().hex + ".bin"
                blob_path = blobs_path / blob_name

                encrypted = fernet.encrypt(file_path.read_bytes())
                blob_path.write_bytes(encrypted)
                written_blobs.append(blob_path)

                old = manifest["files"].get(archived_name)
                if old:
                    old_blob = blobs_path / old["blob"]
                    if old_blob.exists():
                        old_blob.unlink()

                manifest["files"][archived_name] = {
                    "blob": blob_name,
                    "size": file_path.stat().st_size,
                }
                added += 1

            self.save_manifest()

            if move_after_add:
                if source.is_dir():
                    shutil.rmtree(source)
                elif source.exists():
                    source.unlink()

            return added

        except Exception:
            for blob_path in written_blobs:
                if blob_path.exists():
                    blob_path.unlink()
            raise

    def add_bytes(self, archived_name: str, data: bytes) -> None:
        """Ajoute un fichier au coffre depuis des octets reçus par l'interface web."""

        _, fernet, manifest, blobs_path = self.require_open()
        safe_name = clean_archive_name(archived_name)

        blob_name = uuid.uuid4().hex + ".bin"
        blob_path = blobs_path / blob_name

        try:
            encrypted = fernet.encrypt(data)
            blob_path.write_bytes(encrypted)

            old = manifest["files"].get(safe_name)
            if old:
                old_blob = blobs_path / old["blob"]
                if old_blob.exists():
                    old_blob.unlink()

            manifest["files"][safe_name] = {
                "blob": blob_name,
                "size": len(data),
            }
            self.save_manifest()

        except Exception:
            if blob_path.exists():
                blob_path.unlink()
            raise

    def add_uploaded_files(self, files: list[tuple[str, bytes]]) -> int:
        if not files:
            raise VaultError("Aucun fichier sélectionné.")

        added = 0
        for filename, data in files:
            if filename:
                self.add_bytes(filename, data)
                added += 1

        if added == 0:
            raise VaultError("Aucun fichier valide sélectionné.")

        return added

    def extract(self, name: str, destination_dir: str, delete_after_extract: bool = False) -> Path:
        _, fernet, manifest, blobs_path = self.require_open()

        if not name.strip():
            raise VaultError("Indique le nom du fichier à extraire.")

        if not destination_dir.strip():
            raise VaultError("Indique un dossier de destination.")

        entry = manifest["files"].get(name)
        if not entry:
            raise VaultError("Fichier introuvable dans le coffre.")

        destination = Path(destination_dir).expanduser().resolve()
        destination.mkdir(parents=True, exist_ok=True)

        encrypted = (blobs_path / entry["blob"]).read_bytes()

        try:
            plain = fernet.decrypt(encrypted)
        except InvalidToken as exc:
            raise VaultError("Fichier chiffré corrompu ou clé incorrecte.") from exc

        output = safe_output_path(destination, name)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(plain)

        if delete_after_extract:
            self.delete(name)

        return output

    def delete(self, name: str) -> None:
        _, _, manifest, blobs_path = self.require_open()

        if not name.strip():
            raise VaultError("Indique le nom du fichier à supprimer.")

        entry = manifest["files"].pop(name, None)
        if not entry:
            raise VaultError("Fichier introuvable dans le coffre.")

        blob = blobs_path / entry["blob"]
        if blob.exists():
            blob.unlink()

        self.save_manifest()


    def delete_many(self, names: list[str]) -> int:
        _, _, manifest, blobs_path = self.require_open()

        unique_names: list[str] = []
        seen: set[str] = set()
        for name in names:
            clean_name = name.strip()
            if clean_name and clean_name not in seen:
                unique_names.append(clean_name)
                seen.add(clean_name)

        if not unique_names:
            raise VaultError("Sélectionne au moins un fichier à supprimer.")

        missing = [name for name in unique_names if name not in manifest["files"]]
        if missing:
            raise VaultError("Fichier introuvable dans le coffre : " + missing[0])

        for name in unique_names:
            entry = manifest["files"].pop(name)
            blob = blobs_path / entry["blob"]
            if blob.exists():
                blob.unlink()

        self.save_manifest()
        return len(unique_names)

    def get_file_bytes(self, name: str) -> tuple[str, bytes]:
        _, fernet, manifest, blobs_path = self.require_open()

        entry = manifest["files"].get(name)
        if not entry:
            raise VaultError("Fichier introuvable dans le coffre.")

        encrypted = (blobs_path / entry["blob"]).read_bytes()

        try:
            data = fernet.decrypt(encrypted)
        except InvalidToken as exc:
            raise VaultError("Fichier chiffré corrompu ou clé incorrecte.") from exc

        return Path(name).name, data
