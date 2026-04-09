from __future__ import annotations

import json
import os
from pathlib import Path


PREFERENCES_VERSION = 1


class ApplicationPreferences:
    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path is not None else self.default_path()
        self._keybindings: dict[str, str] = {}

    @staticmethod
    def default_path() -> Path:
        if configured := os.environ.get("HEXPROXY_CONFIG"):
            return Path(configured).expanduser()
        xdg_home = os.environ.get("XDG_CONFIG_HOME")
        if xdg_home:
            return Path(xdg_home).expanduser() / "hexproxy" / "config.json"
        return Path.home() / ".config" / "hexproxy" / "config.json"

    @property
    def path(self) -> Path:
        return self._path

    def keybindings(self) -> dict[str, str]:
        return dict(self._keybindings)

    def set_keybindings(self, bindings: dict[str, str]) -> None:
        normalized: dict[str, str] = {}
        seen: set[str] = set()
        for action, key in bindings.items():
            action_name = str(action).strip()
            key_name = str(key)
            if not action_name:
                continue
            if len(key_name) != 1:
                raise ValueError(f"keybinding {action_name!r}: key must be a single character")
            if key_name in seen:
                raise ValueError(f"duplicate keybinding detected for {key_name!r}")
            normalized[action_name] = key_name
            seen.add(key_name)
        self._keybindings = normalized

    def load(self) -> None:
        if not self._path.exists():
            return
        payload = json.loads(self._path.read_text(encoding="utf-8"))
        if payload.get("version") != PREFERENCES_VERSION:
            raise ValueError(f"unsupported preferences version: {payload.get('version')!r}")
        self.set_keybindings(payload.get("keybindings", {}))

    def save(self) -> Path:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": PREFERENCES_VERSION,
            "keybindings": self._keybindings,
        }
        self._path.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        return self._path
