from __future__ import annotations

import io
from email.parser import BytesParser
from email.policy import default as email_policy
import mimetypes
import zipfile
from http import cookies
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from app_state import STATE, UserSession
from config import SESSION_COOKIE_NAME
from vault_core import VaultCore, clean_archive_name
from views import index_body, login_body, page


def first_value(form: dict[str, list[str]], key: str) -> str:
    values = form.get(key, [""])
    return values[0] if values else ""


class VaultHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:
        return

    def get_session_token(self) -> str | None:
        raw_cookie = self.headers.get("Cookie", "")
        if not raw_cookie:
            return None
        jar = cookies.SimpleCookie()
        try:
            jar.load(raw_cookie)
        except cookies.CookieError:
            return None
        morsel = jar.get(SESSION_COOKIE_NAME)
        return morsel.value if morsel else None

    def current_session(self) -> UserSession | None:
        return STATE.get_session(self.get_session_token())

    def send_html(self, session: UserSession | None = None, status: int = 200, message: str = "", error: str = "") -> None:
        if session:
            data = page(
                "Coffre chiffré",
                index_body(session),
                session=session,
                message=message or session.last_message,
                error=error or session.last_error,
            )
        else:
            data = page("Connexion", login_body(), session=None, message=message, error=error)

        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def redirect_home(self) -> None:
        self.send_response(303)
        self.send_header("Location", "/")
        self.end_headers()

    def redirect_with_session_cookie(self, token: str) -> None:
        self.send_response(303)
        self.send_header("Location", "/")
        self.send_header(
            "Set-Cookie",
            f"{SESSION_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax",
        )
        self.end_headers()

    def redirect_and_clear_cookie(self) -> None:
        self.send_response(303)
        self.send_header("Location", "/")
        self.send_header(
            "Set-Cookie",
            f"{SESSION_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax",
        )
        self.end_headers()

    def read_form(self) -> dict[str, list[str]]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8")
        return parse_qs(raw, keep_blank_values=True)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/":
            with STATE.lock:
                self.send_html(self.current_session())
            return

        if parsed.path == "/download":
            self.handle_download(parsed.query)
            return


        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"Not found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/upload-files":
            self.handle_upload_files()
            return

        form = self.read_form()

        if parsed.path == "/login":
            self.handle_login(form)
            return

        if parsed.path == "/register":
            self.handle_register(form)
            return

        if parsed.path == "/logout":
            self.handle_logout()
            return

        if parsed.path == "/download-selected":
            self.handle_download_selected(form.get("names", []))
            return

        if parsed.path == "/extract-download":
            self.handle_extract_download(form)
            return

        with STATE.lock:
            session = self.current_session()
            if not session:
                self.send_html(error="Connecte-toi d’abord.", status=401)
                return

            try:
                if parsed.path == "/create-user-vault":
                    vault_name = STATE.auth.clean_vault_name(first_value(form, "vault_name"))
                    if STATE.auth.vault_exists(session.username, vault_name):
                        raise ValueError("Un coffre avec ce nom existe déjà dans ton espace.")

                    vault_path = STATE.auth.user_vault_path(session.username, vault_name)
                    session.vault = VaultCore()
                    session.vault.create(
                        str(vault_path),
                        first_value(form, "password"),
                        first_value(form, "confirmation"),
                    )
                    session.current_vault_name = vault_name
                    session.set_message("Coffre créé et ouvert.")

                elif parsed.path == "/open-user-vault":
                    vault_name = STATE.auth.clean_vault_name(first_value(form, "vault_name"))
                    if not STATE.auth.vault_exists(session.username, vault_name):
                        raise ValueError("Ce coffre n’existe pas dans ton espace utilisateur.")

                    vault_path = STATE.auth.user_vault_path(session.username, vault_name)
                    session.vault = VaultCore()
                    session.vault.open(str(vault_path), first_value(form, "password"))
                    session.current_vault_name = vault_name
                    session.set_message("Coffre ouvert.")

                elif parsed.path == "/close-vault":
                    session.close_vault()
                    session.set_message("Coffre fermé. Tu es revenu à ta liste de coffres.")

                elif parsed.path == "/delete":
                    session.vault.delete(first_value(form, "name"))
                    session.set_message("Fichier supprimé du coffre.")

                elif parsed.path == "/delete-selected":
                    count = session.vault.delete_many(form.get("names", []))
                    session.set_message(f"{count} fichier(s) supprimé(s) du coffre.")

                else:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"Not found")
                    return

            except Exception as exc:
                session.set_message("", str(exc))

        self.redirect_home()

    def handle_login(self, form: dict[str, list[str]]) -> None:
        with STATE.lock:
            try:
                username = STATE.auth.verify_user(first_value(form, "username"), first_value(form, "password"))
                token = STATE.create_session(username)
            except Exception as exc:
                self.send_html(error=str(exc), status=401)
                return

        self.redirect_with_session_cookie(token)

    def handle_register(self, form: dict[str, list[str]]) -> None:
        with STATE.lock:
            try:
                username = STATE.auth.create_user(
                    first_value(form, "username"),
                    first_value(form, "password"),
                    first_value(form, "confirmation"),
                )
                token = STATE.create_session(username)
                session = STATE.get_session(token)
                if session:
                    session.set_message("Compte créé. Tu peux maintenant créer ton premier coffre.")
            except Exception as exc:
                self.send_html(error=str(exc), status=400)
                return

        self.redirect_with_session_cookie(token)

    def handle_logout(self) -> None:
        token = self.get_session_token()
        with STATE.lock:
            session = STATE.get_session(token)
            if session:
                session.close_vault()
            STATE.delete_session(token)
        self.redirect_and_clear_cookie()

    def read_uploaded_files(self) -> list[tuple[str, bytes]]:
        content_type = self.headers.get("Content-Type", "")
        if not content_type.lower().startswith("multipart/form-data"):
            raise ValueError("Formulaire d’envoi invalide.")

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Taille d’envoi invalide.") from exc

        if length <= 0:
            return []

        body = self.rfile.read(length)

        # Le module email sait parser un message multipart complet.
        # On préfixe donc le corps HTTP avec les en-têtes MIME nécessaires.
        mime_message = (
            f"Content-Type: {content_type}\r\n"
            "MIME-Version: 1.0\r\n"
            "\r\n"
        ).encode("utf-8") + body

        message = BytesParser(policy=email_policy).parsebytes(mime_message)
        if not message.is_multipart():
            raise ValueError("Aucun fichier reçu.")

        files: list[tuple[str, bytes]] = []
        for part in message.iter_parts():
            disposition = part.get_content_disposition()
            field_name = part.get_param("name", header="content-disposition")
            filename = part.get_filename()

            if disposition != "form-data" or field_name != "files" or not filename:
                continue

            data = part.get_payload(decode=True)
            files.append((filename, data or b""))

        return files

    def handle_upload_files(self) -> None:
        with STATE.lock:
            session = self.current_session()
            if not session:
                self.send_html(error="Connecte-toi d’abord.", status=401)
                return

            if not session.vault.is_open:
                session.set_message("", "Ouvre un coffre avant d’ajouter des fichiers.")
                self.redirect_home()
                return

        try:
            files = self.read_uploaded_files()
        except Exception as exc:
            with STATE.lock:
                session = self.current_session()
                if session:
                    session.set_message("", str(exc))
            self.redirect_home()
            return

        with STATE.lock:
            session = self.current_session()
            if not session:
                self.send_html(error="Connecte-toi d’abord.", status=401)
                return

            try:
                count = session.vault.add_uploaded_files(files)
                session.set_message(f"{count} fichier(s) importé(s) depuis le navigateur. Les originaux restent sur l’ordinateur du client.")
            except Exception as exc:
                session.set_message("", str(exc))

        self.redirect_home()

    def handle_extract_download(self, form: dict[str, list[str]]) -> None:
        name = first_value(form, "name")
        delete_after_extract = first_value(form, "delete_after_extract") == "1"

        with STATE.lock:
            session = self.current_session()
            if not session:
                self.send_html(error="Connecte-toi d’abord.", status=401)
                return

            if not session.vault.is_open:
                session.set_message("", "Ouvre un coffre avant d’extraire un fichier.")
                self.redirect_home()
                return

            try:
                filename, data = session.vault.get_file_bytes(name)
                if delete_after_extract:
                    session.vault.delete(name)
                    session.set_message("Fichier téléchargé sur le client et supprimé du coffre.")
                else:
                    session.set_message("Fichier téléchargé sur le client.")
            except Exception as exc:
                session.set_message("", str(exc))
                self.redirect_home()
                return

        mime_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        safe_filename = Path(filename).name.replace('"', "")

        self.send_response(200)
        self.send_header("Content-Type", mime_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition", f'attachment; filename="{safe_filename}"')
        self.end_headers()
        self.wfile.write(data)

    def handle_download(self, query: str) -> None:
        params = parse_qs(query)
        name = unquote(params.get("name", [""])[0])

        with STATE.lock:
            session = self.current_session()
            if not session:
                self.send_html(error="Connecte-toi d’abord.", status=401)
                return
            try:
                filename, data = session.vault.get_file_bytes(name)
            except Exception as exc:
                session.set_message("", str(exc))
                self.redirect_home()
                return

        mime_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        safe_filename = Path(filename).name.replace('"', "")

        self.send_response(200)
        self.send_header("Content-Type", mime_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition", f'attachment; filename="{safe_filename}"')
        self.end_headers()
        self.wfile.write(data)

    def handle_download_selected(self, names: list[str]) -> None:
        unique_names: list[str] = []
        seen: set[str] = set()
        for name in names:
            clean_name = name.strip()
            if clean_name and clean_name not in seen:
                unique_names.append(clean_name)
                seen.add(clean_name)

        with STATE.lock:
            session = self.current_session()
            if not session:
                self.send_html(error="Connecte-toi d’abord.", status=401)
                return

            if not unique_names:
                session.set_message("", "Sélectionne au moins un fichier à télécharger.")
                self.redirect_home()
                return

            try:
                memory_file = io.BytesIO()
                used_arc_names: set[str] = set()

                with zipfile.ZipFile(memory_file, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
                    for name in unique_names:
                        _, data = session.vault.get_file_bytes(name)
                        arc_name = clean_archive_name(name)

                        if arc_name in used_arc_names:
                            stem = Path(arc_name).stem
                            suffix = Path(arc_name).suffix
                            index = 2
                            while f"{stem}_{index}{suffix}" in used_arc_names:
                                index += 1
                            arc_name = f"{stem}_{index}{suffix}"

                        used_arc_names.add(arc_name)
                        archive.writestr(arc_name, data)

                zip_data = memory_file.getvalue()

            except Exception as exc:
                session.set_message("", str(exc))
                self.redirect_home()
                return

        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Length", str(len(zip_data)))
        self.send_header("Content-Disposition", 'attachment; filename="coffre_selection.zip"')
        self.end_headers()
        self.wfile.write(zip_data)
