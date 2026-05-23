from __future__ import annotations

import base64
import json

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_json(fernet: Fernet, data: dict) -> bytes:
    raw = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
    return fernet.encrypt(raw)


def decrypt_json(fernet: Fernet, token: bytes) -> dict:
    raw = fernet.decrypt(token)
    return json.loads(raw.decode("utf-8"))
