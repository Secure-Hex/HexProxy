from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from .preferences import default_config_dir


THEME_ROLES = (
    "chrome",
    "selection",
    "success",
    "error",
    "warning",
    "accent",
    "keyword",
    "info",
)
COLOR_NAMES = {
    "default",
    "black",
    "red",
    "green",
    "yellow",
    "blue",
    "magenta",
    "cyan",
    "white",
}

BUILTIN_THEME_DEFINITIONS: dict[str, dict[str, object]] = {
    "default": {
        "description": "Balanced cyan/blue terminal palette.",
        "colors": {
            "chrome": {"fg": "black", "bg": "blue"},
            "selection": {"fg": "black", "bg": "cyan"},
            "success": {"fg": "green", "bg": "default"},
            "error": {"fg": "red", "bg": "default"},
            "warning": {"fg": "yellow", "bg": "default"},
            "accent": {"fg": "cyan", "bg": "default"},
            "keyword": {"fg": "magenta", "bg": "default"},
            "info": {"fg": "blue", "bg": "default"},
        },
    },
    "amber": {
        "description": "Warm amber terminal look with bright highlights.",
        "colors": {
            "chrome": {"fg": "black", "bg": "yellow"},
            "selection": {"fg": "black", "bg": "yellow"},
            "success": {"fg": "yellow", "bg": "default"},
            "error": {"fg": "red", "bg": "default"},
            "warning": {"fg": "magenta", "bg": "default"},
            "accent": {"fg": "yellow", "bg": "default"},
            "keyword": {"fg": "red", "bg": "default"},
            "info": {"fg": "white", "bg": "default"},
        },
    },
    "ocean": {
        "description": "Cool blues and teals for a calmer workspace.",
        "colors": {
            "chrome": {"fg": "black", "bg": "cyan"},
            "selection": {"fg": "black", "bg": "blue"},
            "success": {"fg": "green", "bg": "default"},
            "error": {"fg": "magenta", "bg": "default"},
            "warning": {"fg": "yellow", "bg": "default"},
            "accent": {"fg": "cyan", "bg": "default"},
            "keyword": {"fg": "blue", "bg": "default"},
            "info": {"fg": "white", "bg": "default"},
        },
    },
    "forest": {
        "description": "Green-heavy palette with earthy accents.",
        "colors": {
            "chrome": {"fg": "black", "bg": "green"},
            "selection": {"fg": "black", "bg": "green"},
            "success": {"fg": "green", "bg": "default"},
            "error": {"fg": "red", "bg": "default"},
            "warning": {"fg": "yellow", "bg": "default"},
            "accent": {"fg": "green", "bg": "default"},
            "keyword": {"fg": "cyan", "bg": "default"},
            "info": {"fg": "blue", "bg": "default"},
        },
    },
    "mono": {
        "description": "High-contrast monochrome theme.",
        "colors": {
            "chrome": {"fg": "black", "bg": "white"},
            "selection": {"fg": "black", "bg": "white"},
            "success": {"fg": "white", "bg": "default"},
            "error": {"fg": "white", "bg": "default"},
            "warning": {"fg": "white", "bg": "default"},
            "accent": {"fg": "white", "bg": "default"},
            "keyword": {"fg": "white", "bg": "default"},
            "info": {"fg": "white", "bg": "default"},
        },
    },
}


@dataclass(slots=True)
class ThemeDefinition:
    name: str
    description: str
    colors: dict[str, tuple[str, str]]
    source: str


class ThemeManager:
    def __init__(self, theme_dirs: list[Path] | None = None) -> None:
        configured = theme_dirs if theme_dirs is not None else [self.default_user_dir()]
        self._theme_dirs = [Path(path).expanduser() for path in configured]
        self._themes: dict[str, ThemeDefinition] = {}
        self._load_errors: list[str] = []

    @staticmethod
    def default_user_dir() -> Path:
        return default_config_dir() / "themes"

    def load(self) -> None:
        self._themes = {}
        self._load_errors = []
        for name, payload in BUILTIN_THEME_DEFINITIONS.items():
            self._themes[name] = self._build_theme_definition(
                name=name,
                description=str(payload.get("description", "")),
                colors=dict(payload.get("colors", {})),
                source="builtin",
                base_theme=None,
            )
        for directory in self._theme_dirs:
            if not directory.exists():
                continue
            for path in sorted(directory.glob("*.json")):
                try:
                    theme = self._load_theme_file(path)
                except Exception as exc:
                    self._load_errors.append(f"{path}: {exc}")
                    continue
                self._themes[theme.name] = theme

    def theme_dir(self) -> Path:
        return self._theme_dirs[0]

    def available_themes(self) -> list[ThemeDefinition]:
        return sorted(self._themes.values(), key=lambda theme: theme.name)

    def theme_names(self) -> list[str]:
        return [theme.name for theme in self.available_themes()]

    def get(self, name: str) -> ThemeDefinition | None:
        return self._themes.get(name)

    def default_theme(self) -> ThemeDefinition:
        return self._themes["default"]

    def load_errors(self) -> list[str]:
        return list(self._load_errors)

    def _load_theme_file(self, path: Path) -> ThemeDefinition:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("theme file must be a JSON object")
        name = str(payload.get("name", path.stem)).strip()
        if not name:
            raise ValueError("theme name must not be empty")
        description = str(payload.get("description", "")).strip()
        extends = str(payload.get("extends", "default")).strip() or "default"
        base_theme = self._themes.get(extends)
        if base_theme is None:
            raise ValueError(f"unknown base theme {extends!r}")
        colors = payload.get("colors", {})
        if not isinstance(colors, dict):
            raise ValueError("colors must be a JSON object")
        return self._build_theme_definition(
            name=name,
            description=description,
            colors=colors,
            source=str(path),
            base_theme=base_theme,
        )

    def _build_theme_definition(
        self,
        *,
        name: str,
        description: str,
        colors: dict[str, object],
        source: str,
        base_theme: ThemeDefinition | None,
    ) -> ThemeDefinition:
        merged: dict[str, tuple[str, str]] = {}
        if base_theme is not None:
            merged.update(base_theme.colors)
        for role in THEME_ROLES:
            if role in colors:
                color_spec = colors[role]
                if not isinstance(color_spec, dict):
                    raise ValueError(f"{role}: color entry must be an object")
                fg = str(color_spec.get("fg", merged.get(role, ("default", "default"))[0])).strip().lower()
                bg = str(color_spec.get("bg", merged.get(role, ("default", "default"))[1])).strip().lower()
                if fg not in COLOR_NAMES:
                    raise ValueError(f"{role}: unsupported fg color {fg!r}")
                if bg not in COLOR_NAMES:
                    raise ValueError(f"{role}: unsupported bg color {bg!r}")
                merged[role] = (fg, bg)
            elif role not in merged:
                raise ValueError(f"missing required theme role {role!r}")
        for role in colors:
            if role not in THEME_ROLES:
                raise ValueError(f"unknown theme role {role!r}")
        return ThemeDefinition(
            name=name,
            description=description,
            colors=merged,
            source=source,
        )
