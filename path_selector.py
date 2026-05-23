from __future__ import annotations

import platform
import shutil
import subprocess
from pathlib import Path

from vault_core import VaultError


VALID_MODES = {"file", "directory"}


def select_path(mode: str) -> str:
    """Ouvre une fenêtre système pour sélectionner un fichier ou un dossier.

    Cette fonction n'utilise aucune dépendance Python externe. Elle appelle le
    sélecteur natif disponible sur le système : zenity/kdialog/yad sous Linux,
    AppleScript sous macOS ou PowerShell sous Windows.
    """

    if mode not in VALID_MODES:
        raise VaultError("Mode de sélection invalide.")

    system = platform.system().lower()

    if system == "linux":
        return _select_linux(mode)

    if system == "darwin":
        return _select_macos(mode)

    if system == "windows":
        return _select_windows(mode)

    raise VaultError("Sélection système non prise en charge sur cet OS.")


def _run(command: list[str]) -> str:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise VaultError(f"Sélecteur introuvable : {command[0]}") from exc

    if completed.returncode != 0:
        raise VaultError("Sélection annulée ou impossible.")

    value = completed.stdout.strip()
    if not value:
        raise VaultError("Aucun chemin sélectionné.")

    return str(Path(value).expanduser())


def _select_linux(mode: str) -> str:
    # GNOME / Ubuntu standard
    if shutil.which("zenity"):
        command = ["zenity", "--file-selection", "--title=Sélectionner"]
        if mode == "directory":
            command.append("--directory")
        return _run(command)

    # KDE
    if shutil.which("kdialog"):
        if mode == "directory":
            return _run(["kdialog", "--getexistingdirectory", str(Path.home())])
        return _run(["kdialog", "--getopenfilename", str(Path.home())])

    # Alternative Linux
    if shutil.which("yad"):
        command = ["yad", "--file-selection", "--title=Sélectionner"]
        if mode == "directory":
            command.append("--directory")
        return _run(command)

    raise VaultError(
        "Aucun sélecteur système trouvé. Sur Ubuntu/Debian, installe zenity : sudo apt install zenity"
    )


def _select_macos(mode: str) -> str:
    if not shutil.which("osascript"):
        raise VaultError("osascript introuvable sur macOS.")

    script = "POSIX path of (choose folder)" if mode == "directory" else "POSIX path of (choose file)"
    return _run(["osascript", "-e", script])


def _select_windows(mode: str) -> str:
    if not shutil.which("powershell") and not shutil.which("powershell.exe"):
        raise VaultError("PowerShell introuvable sur Windows.")

    powershell = shutil.which("powershell") or shutil.which("powershell.exe") or "powershell"

    if mode == "directory":
        script = r'''
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.FolderBrowserDialog
$dialog.Description = "Sélectionner un dossier"
if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
  Write-Output $dialog.SelectedPath
  exit 0
}
exit 1
'''
    else:
        script = r'''
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.Title = "Sélectionner un fichier"
$dialog.Multiselect = $false
if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
  Write-Output $dialog.FileName
  exit 0
}
exit 1
'''

    return _run([powershell, "-NoProfile", "-Command", script])
