from __future__ import annotations

import html
from urllib.parse import quote

from app_state import STATE, UserSession
from config import database_label
from vault_core import human_size


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def vault_options(session: UserSession) -> str:
    vault = session.vault
    if not vault.is_open:
        return ""

    options = []
    for name, _ in vault.list_files():
        options.append(f'<option value="{esc(name)}">{esc(name)}</option>')
    return "".join(options)


def message_block(message: str = "", error: str = "") -> str:
    blocks = []
    if message:
        blocks.append(f'<div class="alert success">{esc(message)}</div>')
    if error:
        blocks.append(f'<div class="alert error">{esc(error)}</div>')
    return "".join(blocks)


def page(title: str, body: str, session: UserSession | None = None, message: str = "", error: str = "") -> bytes:
    if session:
        vault_label = f"Connecté : {session.username}"
        if session.current_vault_name and session.vault.vault_path:
            vault_label += f" — Coffre ouvert : {session.current_vault_name}"
    else:
        vault_label = "Connexion requise"

    content = f"""<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{esc(title)}</title>
  <style>
    :root {{
      --bg: #f4f6fb;
      --card: #ffffff;
      --text: #152033;
      --muted: #6b7280;
      --border: #d8dee9;
      --primary: #1f5eff;
      --danger: #c62828;
      --success: #0f7b3f;
      --dark: #101827;
      --green: #0f9f56;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--text);
    }}
    header {{
      background: var(--dark);
      color: white;
      padding: 18px 24px;
    }}
    header h1 {{ margin: 0; font-size: 22px; }}
    header p {{ margin: 6px 0 0; color: #cbd5e1; }}
    main {{
      max-width: 1160px;
      margin: 24px auto;
      padding: 0 16px 36px;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 16px;
    }}
    .card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 18px;
      box-shadow: 0 8px 22px rgba(15, 23, 42, 0.07);
    }}
    .card h2 {{ margin: 0 0 12px; font-size: 18px; }}
    label {{ display: block; margin: 10px 0 6px; font-weight: 650; }}
    input[type="text"], input[type="password"], select {{
      width: 100%;
      padding: 11px 12px;
      border: 1px solid var(--border);
      border-radius: 10px;
      font-size: 15px;
      background: white;
    }}
    input[type="checkbox"] {{ transform: translateY(1px); }}
    .file-checkbox, #select-all-files {{
      width: 18px;
      height: 18px;
      cursor: pointer;
    }}
    button, .button {{
      display: inline-block;
      border: 0;
      background: var(--primary);
      color: white;
      padding: 10px 14px;
      border-radius: 10px;
      font-weight: 700;
      cursor: pointer;
      text-decoration: none;
      margin-top: 12px;
      font-size: 14px;
    }}
    button:disabled {{
      opacity: 0.45;
      cursor: not-allowed;
    }}
    .button.secondary, button.secondary {{ background: #334155; }}
    .button.danger, button.danger {{ background: var(--danger); }}
    .button.green, button.green {{ background: var(--green); }}
    .muted {{ color: var(--muted); font-size: 14px; }}
    .small {{ font-size: 13px; }}
    .alert {{
      padding: 12px 14px;
      border-radius: 12px;
      margin-bottom: 14px;
      font-weight: 650;
    }}
    .success {{ background: #e8f8ef; color: var(--success); border: 1px solid #b9e5c9; }}
    .error {{ background: #fff0f0; color: var(--danger); border: 1px solid #ffc4c4; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      overflow: hidden;
      border-radius: 14px;
    }}
    th, td {{
      padding: 12px;
      border-bottom: 1px solid var(--border);
      text-align: left;
      vertical-align: middle;
    }}
    th {{ background: #eef2ff; }}
    th.select-column, td.select-column {{ width: 54px; text-align: center; }}
    td.actions {{ white-space: nowrap; text-align: right; }}
    .inline-form {{ display: inline; }}
    .toolbar {{ display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }}
    .field-actions {{ display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }}
    .field-actions button {{ margin-top: 8px; }}
    .hidden-file-input {{ display: none; }}
    .file-picker-row {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center;
      margin-top: 8px;
    }}
    .file-selection-label {{
      display: inline-block;
      max-width: 100%;
      padding: 8px 10px;
      border: 1px dashed var(--border);
      border-radius: 10px;
      background: #fbfdff;
      color: var(--muted);
    }}
    .vault-list {{ display: grid; gap: 12px; }}
    .vault-item {{
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 14px;
      background: #fbfdff;
    }}
    .vault-item strong {{ display: block; margin-bottom: 8px; }}
    code {{ background: #eef2f7; padding: 2px 6px; border-radius: 6px; }}
  </style>
</head>
<body>
  <header>
    <h1>Gestionnaire de coffre chiffré</h1>
    <p>{esc(vault_label)}</p>
  </header>
  <main>
    {message_block(message, error)}
    {body}
  </main>
  <script>
    function triggerClientFilePicker() {{
      const input = document.getElementById('client-files');
      if (input) input.click();
    }}

    function updateUploadFileLabel() {{
      const input = document.getElementById('client-files');
      const label = document.getElementById('upload-file-label');
      if (!input || !label) return;

      const files = Array.from(input.files || []);
      if (files.length === 0) {{
        label.textContent = 'Aucun fichier sélectionné';
        return;
      }}

      if (files.length === 1) {{
        label.textContent = files[0].name;
        return;
      }}

      label.textContent = `${{files.length}} fichiers sélectionnés`;
    }}

    function selectedFileNames() {{
      return Array.from(document.querySelectorAll('.file-checkbox:checked')).map((box) => box.value);
    }}

    function updateBulkButtons() {{
      const selectedCount = selectedFileNames().length;
      const downloadButton = document.getElementById('download-selected-button');
      const deleteButton = document.getElementById('delete-selected-button');
      const counter = document.getElementById('selected-count');

      if (downloadButton) downloadButton.disabled = selectedCount === 0;
      if (deleteButton) deleteButton.disabled = selectedCount === 0;
      if (counter) counter.textContent = selectedCount === 0 ? 'Aucun fichier sélectionné' : `${{selectedCount}} fichier(s) sélectionné(s)`;
    }}

    function toggleAllFiles(source) {{
      document.querySelectorAll('.file-checkbox').forEach((box) => {{
        box.checked = source.checked;
      }});
      updateBulkButtons();
    }}

    function submitSelected(actionUrl, confirmMessage) {{
      const names = selectedFileNames();
      if (names.length === 0) {{
        alert('Sélectionne au moins un fichier.');
        return;
      }}

      if (confirmMessage && !confirm(confirmMessage.replace('{{count}}', names.length))) {{
        return;
      }}

      const form = document.createElement('form');
      form.method = 'post';
      form.action = actionUrl;

      for (const name of names) {{
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'names';
        input.value = name;
        form.appendChild(input);
      }}

      document.body.appendChild(form);
      form.submit();
    }}

    document.addEventListener('DOMContentLoaded', updateBulkButtons);
  </script>
</body>
</html>"""
    return content.encode("utf-8")


def login_body() -> str:
    db_label = esc(database_label())
    return f"""
<div class="grid">
  <section class="card">
    <h2>Connexion</h2>
    <form method="post" action="/login">
      <label>Identifiant</label>
      <input type="text" name="username" autocomplete="username" required>
      <label>Mot de passe</label>
      <input type="password" name="password" autocomplete="current-password" required>
      <button type="submit">Se connecter</button>
    </form>
    <p class="muted small">Après connexion, tu verras uniquement tes propres dossiers chiffrés.</p>
    <p class="muted small">Base utilisée pour l’authentification : <code>{db_label}</code>.</p>
  </section>

  <section class="card">
    <h2>Créer un utilisateur</h2>
    <form method="post" action="/register">
      <label>Identifiant</label>
      <input type="text" name="username" autocomplete="username" placeholder="illies" required>
      <label>Mot de passe utilisateur</label>
      <input type="password" name="password" autocomplete="new-password" required>
      <label>Confirmation</label>
      <input type="password" name="confirmation" autocomplete="new-password" required>
      <button class="green" type="submit">Créer le compte</button>
    </form>
    <p class="muted small">Le compte est enregistré dans la base SQL choisie. Les coffres restent dans ton répertoire utilisateur local.</p>
  </section>
</div>
"""


def dashboard_body(session: UserSession) -> str:
    vaults = STATE.auth.list_vaults(session.username)
    root = STATE.auth.user_vaults_root(session.username)

    if vaults:
        vault_cards = []
        for vault in vaults:
            name = esc(vault["name"])
            path = esc(vault["path"])
            vault_cards.append(f"""
<div class="vault-item">
  <strong>{name}</strong>
  <p class="muted small"><code>{path}</code></p>
  <form method="post" action="/open-user-vault">
    <input type="hidden" name="vault_name" value="{name}">
    <label>Mot de passe du coffre</label>
    <input type="password" name="password" required>
    <button type="submit">Ouvrir ce coffre</button>
  </form>
</div>
""")
        vault_list_html = '<div class="vault-list">' + "".join(vault_cards) + "</div>"
    else:
        vault_list_html = '<p class="muted">Aucun coffre dans ton espace pour le moment. Crée ton premier coffre à gauche.</p>'

    return f"""
<section class="card" style="margin-bottom: 16px;">
  <div class="toolbar">
    <h2 style="margin-right:auto;">Espace utilisateur : {esc(session.username)}</h2>
    <form method="post" action="/logout">
      <button class="secondary" type="submit">Déconnexion</button>
    </form>
  </div>
  <p class="muted">Répertoire de tes coffres : <code>{esc(root)}</code></p>
  <p class="muted small">Authentification stockée dans : <code>{esc(database_label())}</code></p>
</section>

<div class="grid">
  <section class="card">
    <h2>Créer un nouveau coffre</h2>
    <form method="post" action="/create-user-vault">
      <label>Nom du coffre</label>
      <input type="text" name="vault_name" placeholder="documents_personnels" required>
      <label>Mot de passe du coffre</label>
      <input type="password" name="password" required>
      <label>Confirmation</label>
      <input type="password" name="confirmation" required>
      <button class="green" type="submit">Créer le coffre</button>
    </form>
    <p class="muted small">Le dossier sera créé automatiquement dans ton répertoire utilisateur. Les autres utilisateurs ne le verront pas.</p>
  </section>

  <section class="card">
    <h2>Mes coffres</h2>
    {vault_list_html}
  </section>
</div>
"""


def open_vault_tools(session: UserSession) -> str:
    options = vault_options(session)
    has_files = bool(options)
    disabled_if_empty = "" if has_files else " disabled"
    empty_note = "" if has_files else '<p class="muted">Aucun fichier dans le coffre pour le moment.</p>'

    return f"""
<section class="card" style="margin-bottom: 16px;">
  <div class="toolbar">
    <h2 style="margin-right:auto;">Coffre ouvert : {esc(session.current_vault_name or "")}</h2>
    <form method="post" action="/close-vault">
      <button class="secondary" type="submit">Retour à mes coffres</button>
    </form>
    <form method="post" action="/logout">
      <button class="secondary" type="submit">Déconnexion</button>
    </form>
  </div>
  <p class="muted">Ce coffre appartient à <strong>{esc(session.username)}</strong>. Les autres utilisateurs ne le voient pas dans leur liste.</p>
</section>

<div class="grid">
  <section class="card">
    <h2>Ajouter des fichiers depuis cet ordinateur</h2>
    <form method="post" action="/upload-files" enctype="multipart/form-data">
      <label>Fichier(s) à envoyer dans le coffre</label>
      <input id="client-files" class="hidden-file-input" type="file" name="files" multiple required onchange="updateUploadFileLabel()">
      <div class="file-picker-row">
        <button class="secondary" type="button" onclick="triggerClientFilePicker()">Sélectionner fichier(s)</button>
        <span id="upload-file-label" class="file-selection-label">Aucun fichier sélectionné</span>
      </div>
      <button type="submit">Ajouter au coffre</button>
    </form>
    <p class="muted small">La fenêtre de sélection s’ouvre côté client, dans le navigateur. Le fichier est ensuite envoyé au serveur puis chiffré dans le coffre.</p>
    <p class="muted small">Le navigateur ne donne pas le vrai chemin local et ne permet pas de supprimer l’original sur l’ordinateur du client.</p>
  </section>

  <section class="card">
    <h2>Extraire un fichier</h2>
    <form method="post" action="/extract-download">
      <label>Fichier du coffre</label>
      <select id="extract-select" name="name" required{disabled_if_empty}>
        {options}
      </select>
      {empty_note}
      <label>
        <input type="checkbox" name="delete_after_extract" value="1">
        Supprimer du coffre après l’extraction
      </label>
      <button type="submit"{disabled_if_empty}>Extraire et télécharger</button>
    </form>
    <p class="muted small">Le fichier déchiffré est téléchargé par le navigateur sur l’ordinateur du client. Aucun chemin serveur n’est demandé.</p>
  </section>

  <section class="card">
    <h2>Supprimer un fichier du coffre-fort</h2>
    <form method="post" action="/delete" onsubmit="return confirm('Supprimer ce fichier du coffre ?');">
      <label>Fichier du coffre</label>
      <select id="delete-select" name="name" required{disabled_if_empty}>
        {options}
      </select>
      {empty_note}
      <button class="danger" type="submit"{disabled_if_empty}>Supprimer du coffre</button>
    </form>
    <p class="muted small">Cette action supprime uniquement la version chiffrée dans le coffre.</p>
  </section>
</div>
"""


def files_table(session: UserSession) -> str:
    vault = session.vault

    if not vault.is_open:
        return ""

    rows = []
    for name, info in vault.list_files():
        quoted_name = esc(quote(name))
        safe_name = esc(name)
        rows.append(f"""
<tr>
  <td class="select-column"><input class="file-checkbox" type="checkbox" value="{safe_name}" onchange="updateBulkButtons()"></td>
  <td><code>{safe_name}</code></td>
  <td>{human_size(int(info.get('size', 0)))}</td>
  <td class="actions">
    <a class="button secondary" href="/download?name={quoted_name}">Télécharger</a>
    <form class="inline-form" method="post" action="/delete" onsubmit="return confirm('Supprimer ce fichier du coffre ?');">
      <input type="hidden" name="name" value="{safe_name}">
      <button class="danger" type="submit">Supprimer</button>
    </form>
  </td>
</tr>
""")

    if not rows:
        return """
<section class="card" style="margin-top: 16px;">
  <h2>Fichiers dans le coffre</h2>
  <p class="muted">Le coffre est vide.</p>
</section>
"""

    return f"""
<section class="card" style="margin-top: 16px;">
  <div class="toolbar">
    <h2 style="margin-right:auto;">Fichiers dans le coffre</h2>
    <span id="selected-count" class="muted small">Aucun fichier sélectionné</span>
    <button id="download-selected-button" class="secondary" type="button" onclick="submitSelected('/download-selected', '')" disabled>Télécharger la sélection</button>
    <button id="delete-selected-button" class="danger" type="button" onclick="submitSelected('/delete-selected', 'Supprimer {{count}} fichier(s) du coffre ?')" disabled>Supprimer la sélection</button>
    <a class="button secondary" href="/">Rafraîchir</a>
  </div>
  <table>
    <thead>
      <tr>
        <th class="select-column"><input id="select-all-files" type="checkbox" onchange="toggleAllFiles(this)" title="Tout sélectionner"></th>
        <th>Nom</th>
        <th>Taille</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</section>
"""


def index_body(session: UserSession) -> str:
    if session.vault.is_open:
        return open_vault_tools(session) + files_table(session)

    return dashboard_body(session)
