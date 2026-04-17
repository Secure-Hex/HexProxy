from importlib.metadata import version, PackageNotFoundError
from pathlib import Path

import tomllib

try:
    __version__ = version("hexproxy")
except PackageNotFoundError:
    # Cuando se ejecuta en desarrollo sin instalar.
    __version__ = "0.0.0"
    try:
        pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
        payload = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        __version__ = str(payload.get("project", {}).get("version") or __version__)
    except Exception:
        pass
