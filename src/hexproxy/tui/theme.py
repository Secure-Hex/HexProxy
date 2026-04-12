from __future__ import annotations

import curses
from typing import Iterable

from ..themes import ThemeDefinition


class ThemeMixin:
    def theme_name(self) -> str:
        return self._theme_name

    def _available_themes(self) -> list[ThemeDefinition]:
        themes = self.theme_manager.available_themes()
        if not themes:
            self.theme_manager.load()
            themes = self.theme_manager.available_themes()
        return themes

    def _current_theme(self) -> ThemeDefinition:
        if self._theme_preview_override is not None:
            return self._theme_preview_override
        theme = self.theme_manager.get(self._theme_name)
        if theme is not None:
            return theme
        default_theme = self.theme_manager.default_theme()
        self._theme_name = default_theme.name
        return default_theme

    def _sync_theme_selection(self, prefer_current: bool = False) -> None:
        themes = self._available_themes()
        if not themes:
            self.theme_selected_index = 0
            return
        current_index = next(
            (
                index
                for index, theme in enumerate(themes)
                if theme.name == self._theme_name
            ),
            None,
        )
        if prefer_current and current_index is not None:
            self.theme_selected_index = current_index
            return
        self.theme_selected_index = max(
            0, min(self.theme_selected_index, len(themes) - 1)
        )

    def _selected_theme(self) -> ThemeDefinition | None:
        themes = self._available_themes()
        if not themes:
            return None
        self._sync_theme_selection()
        return themes[self.theme_selected_index]

    def _apply_theme_colors(self) -> None:
        self._apply_theme_definition(self._current_theme())

    def _apply_theme_definition(self, theme: ThemeDefinition) -> None:
        if not self._colors_enabled():
            return
        for role, pair_id in self.THEME_PAIR_IDS.items():
            fg_name, bg_name = theme.colors[role]
            curses.init_pair(
                pair_id,
                self._theme_color_code(fg_name),
                self._theme_color_code(bg_name),
            )

    def _chrome_attr(self) -> int:
        if self._colors_enabled():
            return curses.color_pair(self.THEME_PAIR_IDS["chrome"])
        return curses.A_REVERSE

    @staticmethod
    def _colors_enabled() -> bool:
        try:
            return curses.has_colors()
        except curses.error:
            return False

    @staticmethod
    def _theme_color_code(name: str) -> int:
        if name.startswith("#"):
            return ThemeMixin._nearest_terminal_color(name)
        mapping = {
            "default": -1,
            "black": curses.COLOR_BLACK,
            "red": curses.COLOR_RED,
            "green": curses.COLOR_GREEN,
            "yellow": curses.COLOR_YELLOW,
            "blue": curses.COLOR_BLUE,
            "magenta": curses.COLOR_MAGENTA,
            "cyan": curses.COLOR_CYAN,
            "white": curses.COLOR_WHITE,
        }
        return mapping.get(name, -1)

    @staticmethod
    def _nearest_terminal_color(value: str) -> int:
        red, green, blue = ThemeMixin._parse_hex_color(value)
        palette = {
            curses.COLOR_BLACK: (0, 0, 0),
            curses.COLOR_RED: (205, 49, 49),
            curses.COLOR_GREEN: (13, 188, 121),
            curses.COLOR_YELLOW: (229, 229, 16),
            curses.COLOR_BLUE: (36, 114, 200),
            curses.COLOR_MAGENTA: (188, 63, 188),
            curses.COLOR_CYAN: (17, 168, 205),
            curses.COLOR_WHITE: (229, 229, 229),
        }
        return min(
            palette,
            key=lambda code: (
                (palette[code][0] - red) ** 2
                + (palette[code][1] - green) ** 2
                + (palette[code][2] - blue) ** 2
            ),
        )

    @staticmethod
    def _parse_hex_color(value: str) -> tuple[int, int, int]:
        if len(value) == 4:
            return tuple(int(character * 2, 16) for character in value[1:4])
        return int(value[1:3], 16), int(value[3:5], 16), int(value[5:7], 16)
