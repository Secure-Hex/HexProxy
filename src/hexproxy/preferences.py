from __future__ import annotations

import json
import os
from pathlib import Path
from pathlib import PureWindowsPath


PREFERENCES_VERSION = 1


def default_config_dir() -> Path:
    if os.name == "nt":
        appdata = os.environ.get("APPDATA") or os.environ.get("LOCALAPPDATA")
        if appdata:
            return Path(str(PureWindowsPath(appdata) / "hexproxy"))
        return Path(str(PureWindowsPath(Path.home()) / "AppData" / "Roaming" / "hexproxy"))
    xdg_home = os.environ.get("XDG_CONFIG_HOME")
    if xdg_home:
        return Path(xdg_home).expanduser() / "hexproxy"
    return Path.home() / ".config" / "hexproxy"


class ApplicationPreferences:
    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path is not None else self.default_path()
        self._keybindings: dict[str, str] = {}
        self._theme_name = "default"
        self._plugin_state: dict[str, dict[str, object]] = {}

    @staticmethod
    def default_path() -> Path:
        if configured := os.environ.get("HEXPROXY_CONFIG"):
            return Path(configured).expanduser()
        return default_config_dir() / "config.json"

    @property
    def path(self) -> Path:
        return self._path

    def keybindings(self) -> dict[str, str]:
        return dict(self._keybindings)

    def theme_name(self) -> str:
        return self._theme_name

    def plugin_state(self, plugin_id: str | None = None) -> dict[str, object] | dict[str, dict[str, object]]:
        if plugin_id is None:
            return {
                name: dict(values)
                for name, values in self._plugin_state.items()
            }
        return dict(self._plugin_state.get(str(plugin_id).strip(), {}))

    def set_keybindings(self, bindings: dict[str, str]) -> None:
        normalized: dict[str, str] = {}
        seen: set[str] = set()
        for action, key in bindings.items():
            action_name = str(action).strip()
            key_name = str(key)
            if not action_name:
                continue
            if len(key_name) not in {1, 2}:
                raise ValueError(f"keybinding {action_name!r}: key must be one or two characters")
            if any((not character.isprintable()) or character.isspace() for character in key_name):
                raise ValueError(f"keybinding {action_name!r}: binding must use visible characters")
            if key_name in seen:
                raise ValueError(f"duplicate keybinding detected for {key_name!r}")
            normalized[action_name] = key_name
            seen.add(key_name)
        for action_name, key_name in normalized.items():
            for other_action, other_key in normalized.items():
                if action_name == other_action:
                    continue
                if other_key.startswith(key_name) or key_name.startswith(other_key):
                    raise ValueError(f"ambiguous keybinding between {action_name!r} and {other_action!r}")
        self._keybindings = normalized

    def set_theme_name(self, theme_name: str) -> None:
        normalized = str(theme_name).strip()
        if not normalized:
            raise ValueError("theme name must not be empty")
        self._theme_name = normalized

    def set_plugin_state(self, plugin_id: str, values: dict[str, object]) -> None:
        normalized_id = str(plugin_id).strip()
        if not normalized_id:
            raise ValueError("plugin id must not be empty")
        if not isinstance(values, dict):
            raise ValueError("plugin state must be a dict")
        self._plugin_state[normalized_id] = dict(values)

    def plugin_value(self, plugin_id: str, key: str, default: object = None) -> object:
        return self._plugin_state.get(str(plugin_id).strip(), {}).get(str(key), default)

    def set_plugin_value(self, plugin_id: str, key: str, value: object) -> None:
        normalized_id = str(plugin_id).strip()
        normalized_key = str(key).strip()
        if not normalized_id or not normalized_key:
            raise ValueError("plugin id and key must not be empty")
        bucket = dict(self._plugin_state.get(normalized_id, {}))
        bucket[normalized_key] = value
        self._plugin_state[normalized_id] = bucket

    def load(self) -> None:
        if not self._path.exists():
            return
        payload = json.loads(self._path.read_text(encoding="utf-8"))
        if payload.get("version") != PREFERENCES_VERSION:
            raise ValueError(f"unsupported preferences version: {payload.get('version')!r}")
        self.set_keybindings(payload.get("keybindings", {}))
        self.set_theme_name(payload.get("theme", "default"))
        plugin_state = payload.get("plugin_state", {})
        if not isinstance(plugin_state, dict):
            raise ValueError("plugin_state must be a JSON object")
        self._plugin_state = {
            str(plugin_id).strip(): dict(values)
            for plugin_id, values in plugin_state.items()
            if str(plugin_id).strip() and isinstance(values, dict)
        }

    def save(self) -> Path:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": PREFERENCES_VERSION,
            "keybindings": self._keybindings,
            "theme": self._theme_name,
            "plugin_state": self._plugin_state,
        }
        self._path.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        return self._path
