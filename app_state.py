from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field

from auth import AuthManager
from config import SESSION_MAX_AGE_SECONDS
from vault_core import VaultCore


@dataclass
class UserSession:
    username: str
    vault: VaultCore = field(default_factory=VaultCore)
    current_vault_name: str | None = None
    last_message: str = ""
    last_error: str = ""

    def set_message(self, message: str = "", error: str = "") -> None:
        self.last_message = message
        self.last_error = error

    def close_vault(self) -> None:
        self.vault.close()
        self.current_vault_name = None


class AppState:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.auth = AuthManager()
        self.sessions: dict[str, UserSession] = {}
        self.session_created_at: dict[str, float] = {}
        self._load_sessions_from_database()

    def _load_sessions_from_database(self) -> None:
        now = time.time()
        cutoff = now - SESSION_MAX_AGE_SECONDS
        self.auth.delete_expired_sessions(cutoff)

        for row in self.auth.list_sessions():
            token = str(row.get("token", ""))
            username = str(row.get("username", ""))
            created_at = float(row.get("created_at", 0))

            if not token or now - created_at > SESSION_MAX_AGE_SECONDS or not self.auth.user_exists(username):
                if token:
                    self.auth.delete_session(token)
                continue

            self.sessions[token] = UserSession(username=username)
            self.session_created_at[token] = created_at

    def create_session(self, username: str) -> str:
        token = secrets.token_urlsafe(32)
        created_at = time.time()
        self.sessions[token] = UserSession(username=username)
        self.session_created_at[token] = created_at
        self.auth.save_session(token, username, created_at)
        return token

    def get_session(self, token: str | None) -> UserSession | None:
        if not token:
            return None
        session = self.sessions.get(token)
        if not session:
            return None

        created_at = self.session_created_at.get(token, 0)
        if time.time() - created_at > SESSION_MAX_AGE_SECONDS:
            self.delete_session(token)
            return None

        return session

    def delete_session(self, token: str | None) -> None:
        if token:
            self.sessions.pop(token, None)
            self.session_created_at.pop(token, None)
            self.auth.delete_session(token)


STATE = AppState()
