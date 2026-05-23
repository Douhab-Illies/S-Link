from __future__ import annotations

import webbrowser
from http.server import ThreadingHTTPServer

from config import HOST, PORT, database_label
from web_server import VaultHandler


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), VaultHandler)
    url = f"http://{HOST}:{PORT}"

    print(f"Interface ouverte sur {url}")
    print(f"Base authentification : {database_label()}")
    print("Appuie sur Ctrl+C pour arrêter le serveur.")

    try:
        webbrowser.open(url)
    except Exception:
        pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nArrêt du serveur.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
