from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from importlib.metadata import PackageNotFoundError, version as metadata_version

from packaging.version import InvalidVersion, Version

from . import __version__ as fallback_version

UPDATE_CHECK_ENV = "HEXPROXY_SKIP_UPDATE_CHECK"
PACKAGE_NAME = "hexproxy"
PYPI_JSON_URL = f"https://pypi.org/pypi/{PACKAGE_NAME}/json"
REQUEST_TIMEOUT = 5
USER_AGENT = "HexProxy update checker"


def run_update_check() -> bool:
    if _is_update_check_disabled() or not _can_prompt():
        return False
    current = _get_installed_version()
    if current is None:
        return False
    latest = _fetch_latest_version()
    if latest is None or latest <= current:
        return False
    if not _confirm_update(current, latest):
        return False
    if _install_update(latest):
        print(
            f"HexProxy se ha actualizado a {latest}. "
            "Reinicia la aplicación para usar la nueva versión."
        )
        return True
    print("No se pudo completar la actualización; HexProxy continuará con la versión actual.")
    return False


def _is_update_check_disabled() -> bool:
    value = os.environ.get(UPDATE_CHECK_ENV, "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _can_prompt() -> bool:
    return (
        sys.stdin is not None
        and sys.stdout is not None
        and sys.stdin.isatty()
        and sys.stdout.isatty()
    )


def _get_installed_version() -> Version | None:
    try:
        return Version(metadata_version(PACKAGE_NAME))
    except PackageNotFoundError:
        pass
    try:
        return Version(fallback_version)
    except InvalidVersion:
        return None


def _fetch_latest_version() -> Version | None:
    request = urllib.request.Request(PYPI_JSON_URL, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            payload = json.load(response)
    except (urllib.error.URLError, ValueError):
        return None
    version_str = payload.get("info", {}).get("version")
    if not isinstance(version_str, str):
        return None
    try:
        return Version(version_str)
    except InvalidVersion:
        return None


def _confirm_update(current: Version, latest: Version) -> bool:
    print(f"Actualización disponible: HexProxy {current} → {latest}.")
    print("  1) Actualizar ahora")
    print("  2) Omitir por ahora")
    while True:
        try:
            choice = input("Selecciona 1 o 2: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        if choice in {"1", "actualizar", "a", "u", "update"}:
            return True
        if choice in {"2", "omitir", "o", "skip", ""}:
            return False
        print("Elige 1 para actualizar o 2 para omitir.")


def _install_update(latest: Version) -> bool:
    print(f"Actualizando HexProxy a {latest}...")
    command = [sys.executable, "-m", "pip", "install", "--upgrade", PACKAGE_NAME]
    result = subprocess.run(command)
    if result.returncode == 0:
        return True
    print(f"La actualización falló (código {result.returncode}).")
    return False
