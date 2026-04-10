from __future__ import annotations

import curses
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
from time import monotonic
from typing import Callable

from .bodyview import BodyDocument, build_body_document
from .certs import CertificateAuthority
from .extensions import PluginManager
from .models import HeaderList, MatchReplaceRule, TrafficEntry
from .proxy import ParsedRequest, parse_request_text, parse_response_text
from .store import PendingInterceptionView, TrafficStore
from .themes import ThemeDefinition, ThemeManager


@dataclass(slots=True)
class RepeaterSession:
    request_text: str
    response_text: str = ""
    source_entry_id: int | None = None
    last_error: str = ""
    last_sent_at: datetime | None = None
    request_scroll: int = 0
    response_scroll: int = 0
    request_x_scroll: int = 0
    response_x_scroll: int = 0


@dataclass(slots=True)
class SitemapItem:
    label: str
    depth: int
    entry_id: int | None
    kind: str


@dataclass(slots=True)
class SettingsItem:
    label: str
    kind: str
    description: str


@dataclass(slots=True)
class KeybindingItem:
    section: str
    action: str
    key: str
    description: str


@dataclass(slots=True)
class MatchReplaceDraft:
    enabled: bool = True
    scope: str = "request"
    mode: str = "literal"
    match: str = ""
    replace: str = ""
    description: str = ""


@dataclass(slots=True)
class MatchReplaceFieldItem:
    label: str
    kind: str
    description: str


class ProxyTUI:
    THEME_PAIR_IDS: dict[str, int] = {
        "selection": 1,
        "success": 2,
        "error": 3,
        "warning": 4,
        "accent": 5,
        "keyword": 6,
        "info": 7,
        "chrome": 8,
    }
    TABS = [
        "Overview",
        "Intercept",
        "Repeater",
        "Sitemap",
        "Match/Replace",
        "Request",
        "Response",
        "Settings",
        "Keybindings",
        "Rule Builder",
    ]
    TAB_ACTIONS: dict[str, int] = {
        "open_overview": 0,
        "open_intercept": 1,
        "open_repeater": 2,
        "open_sitemap": 3,
        "open_match_replace": 4,
        "open_request": 5,
        "open_response": 6,
        "open_settings": 7,
        "open_keybindings": 8,
    }
    DEFAULT_KEYBINDINGS: dict[str, str] = {
        "open_overview": "1",
        "open_intercept": "2",
        "open_repeater": "3",
        "open_sitemap": "4",
        "open_match_replace": "5",
        "open_request": "6",
        "open_response": "7",
        "open_settings": "w",
        "open_keybindings": "0",
        "save_project": "s",
        "load_repeater": "y",
        "edit_match_replace": "r",
        "toggle_body_view": "p",
        "toggle_word_wrap": "z",
        "toggle_intercept_mode": "i",
        "forward_send": "a",
        "drop_item": "x",
        "edit_item": "e",
        "repeater_send_alt": "g",
        "repeater_prev_session": "[",
        "repeater_next_session": "/",
    }
    KEYBINDING_DESCRIPTIONS: dict[str, str] = {
        "open_overview": "Open the Overview workspace",
        "open_intercept": "Open the Intercept workspace",
        "open_repeater": "Open the Repeater workspace",
        "open_sitemap": "Open the Sitemap workspace",
        "open_match_replace": "Open the Match/Replace workspace",
        "open_request": "Open the Request workspace",
        "open_response": "Open the Response workspace",
        "open_settings": "Open the Settings workspace",
        "open_keybindings": "Open the Keybindings workspace",
        "save_project": "Save the current project",
        "load_repeater": "Load selected flow into Repeater",
        "edit_match_replace": "Edit Match/Replace rules",
        "toggle_body_view": "Toggle raw/pretty body mode",
        "toggle_word_wrap": "Toggle word wrap in text panes",
        "toggle_intercept_mode": "Cycle interception mode",
        "forward_send": "Forward intercepted item or send Repeater request",
        "drop_item": "Drop intercepted item",
        "edit_item": "Edit intercepted item or Repeater request",
        "repeater_send_alt": "Alternate key to send Repeater request",
        "repeater_prev_session": "Go to previous Repeater session",
        "repeater_next_session": "Go to next Repeater session",
    }
    KEYBINDING_SECTIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
        (
            "Workspaces",
            (
                "open_overview",
                "open_intercept",
                "open_repeater",
                "open_sitemap",
                "open_match_replace",
                "open_request",
                "open_response",
                "open_settings",
                "open_keybindings",
            ),
        ),
        (
            "Flow Actions",
            (
                "save_project",
                "load_repeater",
                "edit_match_replace",
                "toggle_body_view",
                "toggle_word_wrap",
                "toggle_intercept_mode",
            ),
        ),
        (
            "Editing And Send",
            (
                "forward_send",
                "drop_item",
                "edit_item",
                "repeater_send_alt",
            ),
        ),
        (
            "Repeater Sessions",
            (
                "repeater_prev_session",
                "repeater_next_session",
            ),
        ),
    )
    LEGACY_KEYBINDING_ACTIONS: dict[str, str] = {
        "open_request_headers": "open_request",
        "open_request_body": "open_request",
        "open_response_headers": "open_response",
        "open_response_body": "open_response",
    }

    def __init__(
        self,
        store: TrafficStore,
        listen_host: str,
        listen_port: int,
        certificate_authority: CertificateAuthority,
        plugin_manager: PluginManager | None = None,
        theme_manager: ThemeManager | None = None,
        repeater_sender: Callable[[str], str] | None = None,
        initial_keybindings: dict[str, str] | None = None,
        keybinding_saver: Callable[[dict[str, str]], object] | None = None,
        initial_theme_name: str | None = None,
        theme_saver: Callable[[str], object] | None = None,
    ) -> None:
        self.store = store
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.certificate_authority = certificate_authority
        self.plugin_manager = plugin_manager or PluginManager()
        self.theme_manager = theme_manager or ThemeManager()
        if not self.theme_manager.available_themes():
            self.theme_manager.load()
        self.repeater_sender = repeater_sender
        self._custom_keybindings = self._normalize_custom_keybindings(initial_keybindings or {})
        self._keybinding_saver = keybinding_saver
        self._theme_saver = theme_saver
        self._theme_name = initial_theme_name or "default"
        self.selected_index = 0
        self.active_tab = 0
        self.status_message = ""
        self.status_until = 0.0
        self.request_body_view_mode = "pretty"
        self.response_body_view_mode = "pretty"
        self.word_wrap_enabled = False
        self.active_pane = "flows"
        self.flow_x_scroll = 0
        self.intercept_selected_index = 0
        self.detail_scroll = 0
        self.detail_x_scroll = 0
        self.detail_page_rows = 0
        self._last_detail_entry_id: int | None = None
        self._last_detail_tab = self.active_tab
        self.match_replace_selected_index = 0
        self.repeater_sessions: list[RepeaterSession] = []
        self.repeater_index = 0
        self.sitemap_selected_index = 0
        self.sitemap_tree_scroll = 0
        self.sitemap_tree_x_scroll = 0
        self.sitemap_request_scroll = 0
        self.sitemap_request_x_scroll = 0
        self.sitemap_response_scroll = 0
        self.sitemap_response_x_scroll = 0
        self._last_sitemap_entry_id: int | None = None
        self.settings_selected_index = 0
        self.settings_menu_x_scroll = 0
        self.settings_detail_scroll = 0
        self.settings_detail_x_scroll = 0
        self.theme_selected_index = 0
        self.keybindings_selected_index = 0
        self.keybindings_menu_x_scroll = 0
        self.keybindings_detail_scroll = 0
        self.keybindings_detail_x_scroll = 0
        self.keybinding_capture_action: str | None = None
        self.keybinding_capture_buffer = ""
        self.keybinding_error_message = ""
        self.rule_builder_selected_index = 0
        self.rule_builder_menu_x_scroll = 0
        self.rule_builder_detail_scroll = 0
        self.rule_builder_detail_x_scroll = 0
        self.rule_builder_draft = MatchReplaceDraft()
        self.rule_builder_error_message = ""
        self._pending_action_sequence = ""

    def run(self) -> None:
        curses.wrapper(self._main)

    @classmethod
    def _normalize_custom_keybindings(cls, bindings: dict[str, str]) -> dict[str, str]:
        normalized: dict[str, str] = {}
        for action, key in bindings.items():
            mapped_action = cls.LEGACY_KEYBINDING_ACTIONS.get(action, action)
            if mapped_action not in cls.KEYBINDING_DESCRIPTIONS:
                continue
            normalized[mapped_action] = key
        return normalized

    def theme_name(self) -> str:
        return self._theme_name

    def _available_themes(self) -> list[ThemeDefinition]:
        themes = self.theme_manager.available_themes()
        if not themes:
            self.theme_manager.load()
            themes = self.theme_manager.available_themes()
        return themes

    def _current_theme(self) -> ThemeDefinition:
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
        current_index = next((index for index, theme in enumerate(themes) if theme.name == self._theme_name), None)
        if prefer_current and current_index is not None:
            self.theme_selected_index = current_index
            return
        self.theme_selected_index = max(0, min(self.theme_selected_index, len(themes) - 1))

    def _selected_theme(self) -> ThemeDefinition | None:
        themes = self._available_themes()
        if not themes:
            return None
        self._sync_theme_selection()
        return themes[self.theme_selected_index]

    def _settings_tab_index(self) -> int:
        return self.TABS.index("Settings")

    def _keybindings_tab_index(self) -> int:
        return self.TABS.index("Keybindings")

    def _rule_builder_tab_index(self) -> int:
        return self.TABS.index("Rule Builder")

    def _is_settings_tab(self) -> bool:
        return self.active_tab == self._settings_tab_index()

    def _is_keybindings_tab(self) -> bool:
        return self.active_tab == self._keybindings_tab_index()

    def _is_rule_builder_tab(self) -> bool:
        return self.active_tab == self._rule_builder_tab_index()

    @staticmethod
    def _colors_enabled() -> bool:
        try:
            return curses.has_colors()
        except curses.error:
            return False

    @staticmethod
    def _theme_color_code(name: str) -> int:
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

    def _apply_theme_colors(self) -> None:
        if not self._colors_enabled():
            return
        theme = self._current_theme()
        for role, pair_id in self.THEME_PAIR_IDS.items():
            fg_name, bg_name = theme.colors[role]
            curses.init_pair(pair_id, self._theme_color_code(fg_name), self._theme_color_code(bg_name))

    def _chrome_attr(self) -> int:
        if self._colors_enabled():
            return curses.color_pair(self.THEME_PAIR_IDS["chrome"])
        return curses.A_REVERSE

    def _main(self, stdscr) -> None:
        curses.curs_set(0)
        stdscr.keypad(True)
        stdscr.timeout(150)
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            self._apply_theme_colors()

        while True:
            entries = self.store.visible_entries()
            pending = self.store.pending_interceptions()
            intercept_items = self.store.interception_history()
            self._sync_selection(entries, pending)
            self._sync_active_pane()
            if self.active_tab == 1:
                self._sync_intercept_selection(intercept_items)
                selected_intercept = self._selected_intercept_item(intercept_items)
                selected_pending = selected_intercept if selected_intercept is not None and selected_intercept.active else None
                selected = self._entry_for_pending(entries, selected_pending)
                self._sync_detail_scroll(selected_intercept.record_id if selected_intercept is not None else None)
            else:
                selected_intercept = None
                selected = entries[self.selected_index] if entries else None
                selected_pending = self._selected_pending_interception(selected.id if selected is not None else None)
                self._sync_detail_scroll(selected.id if selected is not None else None)

            self._draw(stdscr, entries, selected, pending, selected_pending, intercept_items, selected_intercept)

            key = stdscr.getch()
            if self._is_keybindings_tab() and self._handle_keybinding_capture(key):
                continue
            if key in (ord("q"), ord("Q")):
                self._pending_action_sequence = ""
                return
            if key in (getattr(curses, "KEY_SLEFT", -1), ord("H")):
                self._pending_action_sequence = ""
                self._scroll_horizontal_active_pane(-8)
                continue
            if key in (getattr(curses, "KEY_SRIGHT", -1), ord("L")):
                self._pending_action_sequence = ""
                self._scroll_horizontal_active_pane(8)
                continue
            if key in (curses.KEY_LEFT, ord("h")):
                self._pending_action_sequence = ""
                if self.active_tab == 2:
                    self.active_pane = "repeater_request"
                elif self.active_tab == 3:
                    self._move_sitemap_focus(-1)
                elif self._is_settings_tab():
                    self._move_settings_focus(-1)
                elif self._is_keybindings_tab():
                    self._move_keybindings_focus(-1)
                elif self._is_rule_builder_tab():
                    self._move_rule_builder_focus(-1)
                else:
                    self.active_pane = "flows"
            elif key in (curses.KEY_RIGHT, ord("l")):
                self._pending_action_sequence = ""
                if self.active_tab == 2:
                    self.active_pane = "repeater_response"
                elif self.active_tab == 3:
                    self._move_sitemap_focus(1)
                elif self._is_settings_tab():
                    self._move_settings_focus(1)
                elif self._is_keybindings_tab():
                    self._move_keybindings_focus(1)
                elif self._is_rule_builder_tab():
                    self._move_rule_builder_focus(1)
                else:
                    self.active_pane = "detail"
            elif key in (curses.KEY_UP, ord("k")):
                self._pending_action_sequence = ""
                self._move_active_pane(-1, len(entries))
            elif key in (curses.KEY_DOWN, ord("j")):
                self._pending_action_sequence = ""
                self._move_active_pane(1, len(entries))
            elif key in (9, curses.KEY_BTAB):
                self._pending_action_sequence = ""
                self.active_tab = (self.active_tab + 1) % len(self.TABS)
            elif key == curses.KEY_NPAGE:
                self._pending_action_sequence = ""
                if self.active_tab == 2:
                    self._scroll_repeater_active_pane(self._repeater_page_rows(stdscr) or 1)
                elif self.active_tab == 3:
                    self._scroll_sitemap_active_pane(self._sitemap_page_rows(stdscr) or 1, entries)
                elif self._is_settings_tab():
                    self._scroll_settings_active_pane(self._settings_page_rows(stdscr) or 1)
                elif self._is_keybindings_tab():
                    self._scroll_keybindings_active_pane(self._keybindings_page_rows(stdscr) or 1)
                elif self._is_rule_builder_tab():
                    self._scroll_rule_builder_active_pane(self._rule_builder_page_rows(stdscr) or 1)
                else:
                    self._scroll_detail(self.detail_page_rows or 1)
            elif key == curses.KEY_PPAGE:
                self._pending_action_sequence = ""
                if self.active_tab == 2:
                    self._scroll_repeater_active_pane(-(self._repeater_page_rows(stdscr) or 1))
                elif self.active_tab == 3:
                    self._scroll_sitemap_active_pane(-(self._sitemap_page_rows(stdscr) or 1), entries)
                elif self._is_settings_tab():
                    self._scroll_settings_active_pane(-(self._settings_page_rows(stdscr) or 1))
                elif self._is_keybindings_tab():
                    self._scroll_keybindings_active_pane(-(self._keybindings_page_rows(stdscr) or 1))
                elif self._is_rule_builder_tab():
                    self._scroll_rule_builder_active_pane(-(self._rule_builder_page_rows(stdscr) or 1))
                else:
                    self._scroll_detail(-(self.detail_page_rows or 1))
            elif key == curses.KEY_HOME:
                self._pending_action_sequence = ""
                if self.active_tab == 2:
                    self._set_repeater_active_scroll(0)
                elif self.active_tab == 3:
                    self._set_sitemap_active_scroll(0)
                elif self._is_settings_tab():
                    self._set_settings_active_scroll(0)
                elif self._is_keybindings_tab():
                    self._set_keybindings_active_scroll(0)
                elif self._is_rule_builder_tab():
                    self._set_rule_builder_active_scroll(0)
                else:
                    self.detail_scroll = 0
            elif key == curses.KEY_END:
                self._pending_action_sequence = ""
                if self.active_tab == 2:
                    self._set_repeater_active_scroll(10**9)
                elif self.active_tab == 3:
                    self._set_sitemap_active_scroll(10**9)
                elif self._is_settings_tab():
                    self._set_settings_active_scroll(10**9)
                elif self._is_keybindings_tab():
                    self._set_keybindings_active_scroll(10**9)
                elif self._is_rule_builder_tab():
                    self._set_rule_builder_active_scroll(10**9)
                else:
                    self.detail_scroll = 10**9
            else:
                action = self._consume_bound_action(key)
                if action in self.TAB_ACTIONS:
                    self._open_workspace(action)
                elif action == "save_project":
                    self._save_project(stdscr)
                elif action == "load_repeater":
                    if self.active_tab == 3:
                        self._load_repeater_from_selected_flow(self._selected_sitemap_entry(entries))
                    else:
                        self._load_repeater_from_selected_flow(selected)
                elif action == "edit_match_replace":
                    self._edit_match_replace_rules(stdscr)
                elif action == "toggle_body_view":
                    self._toggle_body_view_mode()
                elif action == "toggle_word_wrap":
                    self._toggle_word_wrap()
                elif action == "toggle_intercept_mode":
                    self._toggle_intercept_mode()
                elif action == "forward_send":
                    if self.active_tab == 2:
                        self._send_repeater_request()
                    elif self._is_settings_tab():
                        self._activate_settings_item(stdscr)
                    elif self._is_keybindings_tab():
                        self._activate_keybinding_item()
                    elif self._is_rule_builder_tab():
                        self._commit_rule_builder_draft()
                    else:
                        self._forward_intercepted_request(selected_pending)
                elif action == "drop_item":
                    if self._is_rule_builder_tab():
                        self._close_rule_builder_workspace("Rule builder cancelled.")
                    elif self.active_tab == 4:
                        self._delete_selected_match_replace_rule()
                    else:
                        self._drop_intercepted_request(selected_pending)
                elif action == "edit_item":
                    if self.active_tab == 2:
                        self._edit_repeater_request(stdscr)
                    elif self._is_settings_tab():
                        self._activate_settings_item(stdscr)
                    elif self._is_keybindings_tab():
                        self._activate_keybinding_item()
                    elif self._is_rule_builder_tab():
                        self._activate_rule_builder_item(stdscr)
                    else:
                        self._edit_intercepted_request(stdscr, selected_pending)
                elif action == "repeater_send_alt":
                    self._send_repeater_request()
                elif action == "repeater_prev_session":
                    self._switch_repeater_session(-1)
                elif action == "repeater_next_session":
                    self._switch_repeater_session(1)
                elif key in (ord("c"),):
                    self._pending_action_sequence = ""
                    if self._is_settings_tab():
                        self._ensure_certificate_authority()
                elif key in (ord("C"),):
                    self._pending_action_sequence = ""
                    if self._is_settings_tab():
                        self._regenerate_certificate_authority()
                elif key in (curses.KEY_ENTER, 10, 13):
                    self._pending_action_sequence = ""
                    if self._is_settings_tab():
                        self._activate_settings_item(stdscr)
                    elif self._is_keybindings_tab():
                        self._activate_keybinding_item()
                    elif self._is_rule_builder_tab():
                        self._activate_rule_builder_item(stdscr)
                elif key == curses.KEY_RESIZE:
                    self._pending_action_sequence = ""
                    stdscr.erase()

    def _draw(
        self,
        stdscr,
        entries: list[TrafficEntry],
        selected: TrafficEntry | None,
        pending: list[PendingInterceptionView],
        selected_pending: PendingInterceptionView | None,
        intercept_items: list[PendingInterceptionView],
        selected_intercept: PendingInterceptionView | None,
    ) -> None:
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        if height < 12 or width < 60:
            stdscr.addnstr(0, 0, "Terminal too small for HexProxy.", max(1, width - 1))
            stdscr.refresh()
            return

        left_width = max(38, width // 2)
        right_x = left_width + 1
        right_width = width - right_x - 1

        project_path = self.store.project_path()
        project_label = str(project_path) if project_path is not None else "no project"
        intercept_mode = self.store.intercept_mode().upper()
        plugins_loaded = len(self.plugin_manager.loaded_plugins())
        repeater_count = len(self.repeater_sessions)
        header = (
            f" HexProxy HTTP | listening on {self.listen_host}:{self.listen_port} | captured: {len(entries)} "
            f"| intercept: {intercept_mode} | pending: {len(pending)} | plugins: {plugins_loaded} "
            f"| repeater: {repeater_count} | project: {project_label} "
        )
        stdscr.addnstr(0, 0, header.ljust(width - 1), width - 1, self._chrome_attr())

        if self.active_tab == 2:
            stdscr.addnstr(
                height - 1,
                0,
                self._footer_text(width, selected_pending).ljust(width - 1),
                width - 1,
                self._chrome_attr(),
            )
            self._draw_repeater_workspace(stdscr, height, width)
            stdscr.refresh()
            return
        if self.active_tab == 3:
            stdscr.addnstr(
                height - 1,
                0,
                self._footer_text(width, selected_pending).ljust(width - 1),
                width - 1,
                self._chrome_attr(),
            )
            self._draw_sitemap_workspace(stdscr, height, width, entries)
            stdscr.refresh()
            return
        if self._is_settings_tab():
            stdscr.addnstr(
                height - 1,
                0,
                self._footer_text(width, selected_pending).ljust(width - 1),
                width - 1,
                self._chrome_attr(),
            )
            self._draw_settings_workspace(stdscr, height, width)
            stdscr.refresh()
            return
        if self._is_keybindings_tab():
            stdscr.addnstr(
                height - 1,
                0,
                self._footer_text(width, selected_pending).ljust(width - 1),
                width - 1,
                self._chrome_attr(),
            )
            self._draw_keybindings_workspace(stdscr, height, width)
            stdscr.refresh()
            return
        if self._is_rule_builder_tab():
            stdscr.addnstr(
                height - 1,
                0,
                self._footer_text(width, selected_pending).ljust(width - 1),
                width - 1,
                self._chrome_attr(),
            )
            self._draw_rule_builder_workspace(stdscr, height, width)
            stdscr.refresh()
            return

        flows_label = "Pending" if self.active_tab == 1 else "Flows"
        flows_title = f"{flows_label} [active]" if self.active_pane == "flows" else flows_label
        detail_title = f"{self.TABS[self.active_tab]} [active]" if self.active_pane == "detail" else self.TABS[self.active_tab]
        self._draw_box(stdscr, 1, 0, height - 3, left_width, flows_title)
        self._draw_box(stdscr, 1, right_x, height - 3, right_width, detail_title)
        stdscr.addnstr(
            height - 1,
            0,
            self._footer_text(width, selected_pending).ljust(width - 1),
            width - 1,
            self._chrome_attr(),
        )

        if self.active_tab == 1:
            self._draw_intercept_list(stdscr, 2, 1, height - 5, left_width - 2, entries, intercept_items)
        else:
            self._draw_flow_list(stdscr, 2, 1, height - 5, left_width - 2, entries)
        self.detail_page_rows = max(1, height - 5)
        self._draw_detail(
            stdscr,
            2,
            right_x + 1,
            height - 5,
            right_width - 2,
            selected,
            pending,
            selected_pending,
            selected_intercept,
        )
        stdscr.refresh()

    def _draw_repeater_workspace(self, stdscr, height: int, width: int) -> None:
        session = self._current_repeater_session()
        if session is None:
            self._draw_box(stdscr, 1, 0, height - 3, width, "Repeater")
            empty_lines = [
                "No repeater sessions loaded.",
                "",
                "Controls:",
                "y load selected flow into a new repeater tab",
                "[ and ] switch between repeater sessions",
                "h/l or left/right change the active pane",
                "j/k or up/down scroll the active pane",
            ]
            for offset, line in enumerate(empty_lines):
                stdscr.addnstr(3 + offset, 2, self._trim(line, max(1, width - 4)).ljust(max(1, width - 4)), max(1, width - 4))
            return

        session_bar = self._build_repeater_session_bar(width - 1)
        stdscr.addnstr(1, 0, session_bar.ljust(width - 1), width - 1, self._chrome_attr())

        pane_y = 2
        pane_height = height - 5
        left_width = max(30, width // 2)
        right_x = left_width + 1
        right_width = width - right_x - 1

        request_title = "Request [active]" if self.active_pane == "repeater_request" else "Request"
        response_title = "Response [active]" if self.active_pane == "repeater_response" else "Response"
        self._draw_box(stdscr, pane_y, 0, pane_height, left_width, request_title)
        self._draw_box(stdscr, pane_y, right_x, pane_height, right_width, response_title)

        request_lines = self._repeater_request_lines(session)
        response_lines = self._repeater_response_lines(session)
        self._draw_repeater_pane(
            stdscr,
            pane_y + 1,
            1,
            pane_height - 1,
            left_width - 2,
            request_lines,
            "request",
            session,
        )
        self._draw_repeater_pane(
            stdscr,
            pane_y + 1,
            right_x + 1,
            pane_height - 1,
            right_width - 2,
            response_lines,
            "response",
            session,
        )

    def _draw_sitemap_workspace(self, stdscr, height: int, width: int, entries: list[TrafficEntry]) -> None:
        items = self._build_sitemap_items(entries)
        self._sync_sitemap_selection(items)
        selected_entry = self._selected_sitemap_entry(entries, items)
        self._sync_sitemap_detail_scroll(selected_entry.id if selected_entry is not None else None)

        pane_y = 1
        pane_height = height - 3
        tree_width = max(28, width // 3)
        detail_x = tree_width + 1
        detail_width = width - detail_x - 1
        request_height = max(5, pane_height // 2)
        response_height = max(4, pane_height - request_height - 1)

        tree_title = "Sitemap [active]" if self.active_pane == "sitemap_tree" else "Sitemap"
        request_title = "Request [active]" if self.active_pane == "sitemap_request" else "Request"
        response_title = "Response [active]" if self.active_pane == "sitemap_response" else "Response"
        self._draw_box(stdscr, pane_y, 0, pane_height, tree_width, tree_title)
        self._draw_box(stdscr, pane_y, detail_x, request_height, detail_width, request_title)
        self._draw_box(stdscr, pane_y + request_height + 1, detail_x, response_height, detail_width, response_title)

        self._draw_sitemap_tree(stdscr, pane_y + 1, 1, pane_height - 1, tree_width - 2, items)
        self._draw_sitemap_detail_pane(
            stdscr,
            pane_y + 1,
            detail_x + 1,
            request_height - 1,
            detail_width - 2,
            self._sitemap_request_lines(selected_entry),
            "sitemap_request",
        )
        self._draw_sitemap_detail_pane(
            stdscr,
            pane_y + request_height + 2,
            detail_x + 1,
            max(1, response_height - 1),
            detail_width - 2,
            self._sitemap_response_lines(selected_entry),
            "sitemap_response",
        )

    def _draw_settings_workspace(self, stdscr, height: int, width: int) -> None:
        items = self._settings_items()
        self._sync_settings_selection(items)
        selected_item = items[self.settings_selected_index] if items else None

        pane_y = 1
        pane_height = height - 3
        left_width = max(28, width // 3)
        right_x = left_width + 1
        right_width = width - right_x - 1

        menu_title = "Settings [active]" if self.active_pane == "settings_menu" else "Settings"
        detail_title = f"{selected_item.label} [active]" if self.active_pane == "settings_detail" and selected_item else "Details"
        self._draw_box(stdscr, pane_y, 0, pane_height, left_width, menu_title)
        self._draw_box(stdscr, pane_y, right_x, pane_height, right_width, detail_title)
        self._draw_settings_menu(stdscr, pane_y + 1, 1, pane_height - 1, left_width - 2, items)
        self._draw_settings_detail(stdscr, pane_y + 1, right_x + 1, pane_height - 1, right_width - 2, selected_item)

    def _draw_keybindings_workspace(self, stdscr, height: int, width: int) -> None:
        items = self._keybinding_items()
        self._sync_keybinding_selection(items)
        selected_item = items[self.keybindings_selected_index] if items else None

        pane_y = 1
        pane_height = height - 3
        left_width = max(32, width // 3)
        right_x = left_width + 1
        right_width = width - right_x - 1

        menu_title = "Keybindings [active]" if self.active_pane == "keybindings_menu" else "Keybindings"
        detail_title = (
            f"{selected_item.action} [active]"
            if self.active_pane == "keybindings_detail" and selected_item is not None
            else "Details"
        )
        self._draw_box(stdscr, pane_y, 0, pane_height, left_width, menu_title)
        self._draw_box(stdscr, pane_y, right_x, pane_height, right_width, detail_title)
        self._draw_keybindings_menu(stdscr, pane_y + 1, 1, pane_height - 1, left_width - 2, items)
        self._draw_keybindings_detail(stdscr, pane_y + 1, right_x + 1, pane_height - 1, right_width - 2, selected_item)

    def _draw_rule_builder_workspace(self, stdscr, height: int, width: int) -> None:
        items = self._rule_builder_items()
        self._sync_rule_builder_selection(items)
        selected_item = items[self.rule_builder_selected_index] if items else None

        pane_y = 1
        pane_height = height - 3
        left_width = max(32, width // 3)
        right_x = left_width + 1
        right_width = width - right_x - 1

        menu_title = "Rule Builder [active]" if self.active_pane == "rule_builder_menu" else "Rule Builder"
        detail_title = (
            f"{selected_item.label} [active]"
            if self.active_pane == "rule_builder_detail" and selected_item is not None
            else "Details"
        )
        self._draw_box(stdscr, pane_y, 0, pane_height, left_width, menu_title)
        self._draw_box(stdscr, pane_y, right_x, pane_height, right_width, detail_title)
        self._draw_rule_builder_menu(stdscr, pane_y + 1, 1, pane_height - 1, left_width - 2, items)
        self._draw_rule_builder_detail(stdscr, pane_y + 1, right_x + 1, pane_height - 1, right_width - 2, selected_item)

    def _draw_settings_menu(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        items: list[SettingsItem],
    ) -> None:
        lines = [item.label for item in items]
        x_scroll = self._normalize_horizontal_scroll(self.settings_menu_x_scroll, self._max_display_width(lines), width)
        self.settings_menu_x_scroll = x_scroll
        for offset in range(min(height, len(items))):
            item = items[offset]
            attr = curses.A_NORMAL
            if offset == self.settings_selected_index and curses.has_colors():
                attr = curses.color_pair(1)
            elif offset == self.settings_selected_index:
                attr = curses.A_REVERSE
            self._draw_text_line(stdscr, y + offset, x, width, item.label, x_scroll=x_scroll, attr=attr)

    def _draw_settings_detail(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        item: SettingsItem | None,
    ) -> None:
        if item is not None and item.kind == "themes":
            self._draw_theme_settings_detail(stdscr, y, x, height, width)
            return
        lines = self._settings_detail_lines(item)
        rows, x_scroll = self._prepare_plain_visual_rows(lines, width, self.settings_detail_x_scroll)
        start = self._window_start(self.settings_detail_scroll, len(rows), height)
        self.settings_detail_scroll = start
        self.settings_detail_x_scroll = x_scroll
        visible_rows = rows[start : start + height]
        for offset, (_, line) in enumerate(visible_rows):
            self._draw_text_line(stdscr, y + offset, x, width, line, x_scroll=x_scroll)
        self._draw_detail_scroll_indicators(stdscr, y, x, height, width, start, len(visible_rows), len(rows))

    def _draw_theme_settings_detail(self, stdscr, y: int, x: int, height: int, width: int) -> None:
        lines = self._theme_detail_lines()
        available = self._available_themes()
        selected_row = 10 + self.theme_selected_index if available else 0
        rows, x_scroll = self._prepare_plain_visual_rows(lines, width, self.settings_detail_x_scroll)
        target_row = next((index for index, (source_index, _) in enumerate(rows) if source_index >= selected_row), 0)
        start = self._window_start(max(self.settings_detail_scroll, target_row), len(rows), height)
        self.settings_detail_scroll = start
        self.settings_detail_x_scroll = x_scroll
        visible_rows = rows[start : start + height]
        for offset, (source_index, line) in enumerate(visible_rows):
            attr = curses.A_NORMAL
            if available and source_index >= 10 and source_index < 10 + len(available):
                theme_index = source_index - 10
                if theme_index == self.theme_selected_index and curses.has_colors():
                    attr = curses.color_pair(1)
                elif theme_index == self.theme_selected_index:
                    attr = curses.A_REVERSE
                elif line.startswith("  ") and curses.has_colors():
                    attr = curses.color_pair(5)
            self._draw_text_line(stdscr, y + offset, x, width, line, x_scroll=x_scroll, attr=attr)
        self._draw_detail_scroll_indicators(stdscr, y, x, height, width, start, len(visible_rows), len(rows))

    def _draw_keybindings_menu(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        items: list[KeybindingItem],
    ) -> None:
        if height <= 0 or width <= 0:
            return
        rows = self._keybinding_menu_rows(items)
        selected_row = next(
            (index for index, row in enumerate(rows) if row[0] == "action" and row[1] == self.keybindings_selected_index),
            0,
        )
        start = self._window_start(selected_row, len(rows), height)
        row_lines = [line for _, _, line in rows]
        x_scroll = self._normalize_horizontal_scroll(
            self.keybindings_menu_x_scroll,
            self._max_display_width(row_lines),
            width,
        )
        self.keybindings_menu_x_scroll = x_scroll
        visible_rows = rows[start : start + height]
        for offset, (row_kind, item_index, line) in enumerate(visible_rows):
            attr = curses.A_NORMAL
            if row_kind == "section" and curses.has_colors():
                attr = curses.color_pair(5) | curses.A_BOLD
            elif row_kind == "section":
                attr = curses.A_BOLD
            elif item_index == self.keybindings_selected_index and curses.has_colors():
                attr = curses.color_pair(1)
            elif item_index == self.keybindings_selected_index:
                attr = curses.A_REVERSE
            self._draw_text_line(stdscr, y + offset, x, width, line, x_scroll=x_scroll, attr=attr)
        self._draw_detail_scroll_indicators(stdscr, y, x, height, width, start, len(visible_rows), len(rows))

    def _draw_keybindings_detail(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        item: KeybindingItem | None,
    ) -> None:
        lines = self._keybinding_detail_lines(item)
        rows, x_scroll = self._prepare_plain_visual_rows(lines, width, self.keybindings_detail_x_scroll)
        start = self._window_start(self.keybindings_detail_scroll, len(rows), height)
        self.keybindings_detail_scroll = start
        self.keybindings_detail_x_scroll = x_scroll
        visible_rows = rows[start : start + height]
        for offset, (_, line) in enumerate(visible_rows):
            safe_line = self._sanitize_display_text(line)
            attr = curses.A_NORMAL
            if safe_line.startswith("Error:") and curses.has_colors():
                attr = curses.color_pair(3)
            elif safe_line.startswith("Waiting for key") and curses.has_colors():
                attr = curses.color_pair(4)
            self._draw_text_line(stdscr, y + offset, x, width, line, x_scroll=x_scroll, attr=attr)
        self._draw_detail_scroll_indicators(stdscr, y, x, height, width, start, len(visible_rows), len(rows))

    def _draw_rule_builder_menu(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        items: list[MatchReplaceFieldItem],
    ) -> None:
        if height <= 0 or width <= 0:
            return
        lines = [self._rule_builder_menu_label(item) for item in items]
        start = self._window_start(self.rule_builder_selected_index, len(items), height)
        x_scroll = self._normalize_horizontal_scroll(
            self.rule_builder_menu_x_scroll,
            self._max_display_width(lines),
            width,
        )
        self.rule_builder_menu_x_scroll = x_scroll
        visible_items = items[start : start + height]
        for offset, item in enumerate(visible_items):
            absolute_index = start + offset
            line = lines[absolute_index]
            attr = curses.A_NORMAL
            if absolute_index == self.rule_builder_selected_index and curses.has_colors():
                attr = curses.color_pair(1)
            elif absolute_index == self.rule_builder_selected_index:
                attr = curses.A_REVERSE
            self._draw_text_line(stdscr, y + offset, x, width, line, x_scroll=x_scroll, attr=attr)
        self._draw_detail_scroll_indicators(stdscr, y, x, height, width, start, len(visible_items), len(items))

    def _draw_rule_builder_detail(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        item: MatchReplaceFieldItem | None,
    ) -> None:
        lines = self._rule_builder_detail_lines(item)
        rows, x_scroll = self._prepare_plain_visual_rows(lines, width, self.rule_builder_detail_x_scroll)
        start = self._window_start(self.rule_builder_detail_scroll, len(rows), height)
        self.rule_builder_detail_scroll = start
        self.rule_builder_detail_x_scroll = x_scroll
        visible_rows = rows[start : start + height]
        for offset, (_, line) in enumerate(visible_rows):
            safe_line = self._sanitize_display_text(line)
            attr = curses.A_NORMAL
            if safe_line.startswith("Error:") and curses.has_colors():
                attr = curses.color_pair(3)
            elif safe_line.startswith("{") and curses.has_colors():
                attr = curses.color_pair(5)
            self._draw_text_line(stdscr, y + offset, x, width, line, x_scroll=x_scroll, attr=attr)
        self._draw_detail_scroll_indicators(stdscr, y, x, height, width, start, len(visible_rows), len(rows))

    def _settings_items(self) -> list[SettingsItem]:
        return [
            SettingsItem("Themes", "themes", "Choose the active color theme and inspect custom theme files."),
            SettingsItem("Plugins", "plugins", "Inspect loaded plugins, plugin directories and installation guidance."),
            SettingsItem("Plugin Developer Docs", "plugin_docs", "Read the HexProxy plugin API and extension guide."),
            SettingsItem("Certificates: Generate CA", "cert_generate", "Generate the local CA if it does not exist."),
            SettingsItem("Certificates: Regenerate CA", "cert_regenerate", "Regenerate the CA and discard old leaf certs."),
            SettingsItem("Scope", "scope", "Edit the interception allowlist."),
            SettingsItem("Keybindings", "keybindings", "Open the Keybindings workspace to edit configurable shortcuts."),
        ]

    def _settings_detail_lines(self, item: SettingsItem | None) -> list[str]:
        if item is None:
            return ["No settings item selected."]
        if item.kind == "themes":
            return self._theme_detail_lines()
        if item.kind == "plugins":
            return self._plugin_settings_lines()
        if item.kind == "plugin_docs":
            return self._plugin_docs_lines()
        if item.kind == "cert_generate":
            return [
                item.label,
                "",
                item.description,
                "",
                f"CA status: {'ready' if self.certificate_authority.is_ready() else 'missing'}",
                f"CA path: {self.certificate_authority.cert_path()}",
                "",
                f"Press {self._binding_label('edit_item')} or Enter to generate the CA.",
            ]
        if item.kind == "cert_regenerate":
            return [
                item.label,
                "",
                item.description,
                "",
                f"CA path: {self.certificate_authority.cert_path()}",
                "",
                f"Press {self._binding_label('edit_item')} or Enter to regenerate the CA.",
            ]
        if item.kind == "scope":
            scope_hosts = self.store.scope_hosts()
            lines = [
                item.label,
                "",
                item.description,
                "",
                "Current scope:",
            ]
            if scope_hosts:
                lines.extend(scope_hosts)
            else:
                lines.append("All hosts are currently in scope.")
            lines.extend(["", f"Press {self._binding_label('edit_item')} or Enter to edit the scope."])
            return lines
        bindings = self._render_keybindings_lines()
        return [
            item.label,
            "",
            item.description,
            "",
            *bindings,
            "",
            f"Press {self._binding_label('edit_item')} or Enter to open the Keybindings workspace.",
        ]

    def _theme_detail_lines(self) -> list[str]:
        current = self._current_theme()
        selected = self._selected_theme()
        themes = self._available_themes()
        lines = [
            "Themes",
            "",
            f"Current theme: {current.name}",
            f"Selected theme: {selected.name if selected is not None else '-'}",
            f"Theme directory: {self.theme_manager.theme_dir()}",
            "",
            "Add custom themes by dropping one JSON file per theme into that directory.",
            "Select a theme with j/k while this panel is active, then press Enter or e to apply it.",
            "",
            "Available themes:",
        ]
        if not themes:
            lines.append("No themes loaded.")
        else:
            for index, theme in enumerate(themes):
                marker = ">" if index == self.theme_selected_index else " "
                description = f" - {theme.description}" if theme.description else ""
                lines.append(f"{marker} {theme.name} [{theme.source}]{description}")
        if errors := self.theme_manager.load_errors():
            lines.extend(["", "Load errors:"])
            lines.extend(f"- {message}" for message in errors)
        return lines

    def _plugin_settings_lines(self) -> list[str]:
        plugin_dirs = self.plugin_manager.plugin_dirs()
        loaded_plugins = self.plugin_manager.loaded_plugins()
        load_errors = self.plugin_manager.load_errors()
        lines = [
            "Plugins",
            "",
            f"Loaded plugins: {len(loaded_plugins)}",
            f"Load errors: {len(load_errors)}",
            "",
            "Plugin directories:",
        ]
        if plugin_dirs:
            lines.extend(str(path) for path in plugin_dirs)
        else:
            lines.append("No plugin directories configured.")
        lines.extend(["", "Installed plugins:"])
        if loaded_plugins:
            for plugin in loaded_plugins:
                lines.append(f"- {plugin.name} | {plugin.path}")
        else:
            lines.append("No plugins loaded.")
        if load_errors:
            lines.extend(["", "Load errors:"])
            lines.extend(f"- {message}" for message in load_errors)
        lines.extend(
            [
                "",
                "Install more plugins:",
                "- Drop a .py plugin file into plugins/",
                "- Or start HexProxy with --plugin-dir /path/to/plugins",
                "- Then restart HexProxy to reload plugins",
                "",
                "Developer references:",
                f"- Example plugin: {Path('examples/add_header_plugin.py')}",
                f"- Local guide: {self._plugin_docs_path()}",
            ]
        )
        return lines

    def _plugin_docs_lines(self) -> list[str]:
        path = self._plugin_docs_path()
        if not path.exists():
            return [
                "Plugin Developer Docs",
                "",
                f"Documentation file not found: {path}",
                "",
                "Expected topics:",
                "- plugin loading model",
                "- register()/PLUGIN entrypoints",
                "- HookContext",
                "- ParsedRequest and ParsedResponse",
                "- hook lifecycle and examples",
            ]
        return path.read_text(encoding="utf-8").splitlines()

    @staticmethod
    def _plugin_docs_path() -> Path:
        return Path(__file__).resolve().parents[2] / "docs" / "plugin-development.md"

    def _keybinding_items(self) -> list[KeybindingItem]:
        bindings = self._current_keybindings()
        items: list[KeybindingItem] = []
        for section, actions in self.KEYBINDING_SECTIONS:
            for action in actions:
                items.append(
                    KeybindingItem(
                        section=section,
                        action=action,
                        key=bindings[action],
                        description=self.KEYBINDING_DESCRIPTIONS[action],
                    )
                )
        return items

    def _keybinding_menu_rows(self, items: list[KeybindingItem]) -> list[tuple[str, int | None, str]]:
        rows: list[tuple[str, int | None, str]] = []
        current_section: str | None = None
        for index, item in enumerate(items):
            if item.section != current_section:
                current_section = item.section
                rows.append(("section", None, f"[{current_section}]"))
            rows.append(("action", index, f"{item.key:<3} {item.action}"))
        return rows

    def _rule_builder_items(self) -> list[MatchReplaceFieldItem]:
        return [
            MatchReplaceFieldItem("Enabled", "enabled", "Enable or disable the rule."),
            MatchReplaceFieldItem("Scope", "scope", "Choose whether the rule applies to request, response or both."),
            MatchReplaceFieldItem("Mode", "mode", "Choose literal or regex matching."),
            MatchReplaceFieldItem("Description", "description", "Optional human-readable label for the rule."),
            MatchReplaceFieldItem("Match", "match", "The text or regex pattern to search for."),
            MatchReplaceFieldItem("Replace", "replace", "The replacement text to apply."),
            MatchReplaceFieldItem("Create Rule", "create", "Validate the form and append the rule to Match/Replace."),
            MatchReplaceFieldItem("Cancel", "cancel", "Discard the draft and return to Match/Replace."),
        ]

    def _rule_builder_menu_label(self, item: MatchReplaceFieldItem) -> str:
        values = {
            "enabled": "on" if self.rule_builder_draft.enabled else "off",
            "scope": self.rule_builder_draft.scope,
            "mode": self.rule_builder_draft.mode,
            "description": self.rule_builder_draft.description or "-",
            "match": self._trim(self.rule_builder_draft.match or "-", 18),
            "replace": self._trim(self.rule_builder_draft.replace or "-", 18),
            "create": "append rule",
            "cancel": "discard draft",
        }
        return f"{item.label}: {values[item.kind]}"

    def _keybinding_detail_lines(self, item: KeybindingItem | None) -> list[str]:
        if item is None:
            return ["No keybinding action selected."]
        lines = [
            item.action,
            "",
            f"Section: {item.section}",
            "",
            item.description,
            "",
            f"Current key: {item.key}",
            "",
            "Each action must keep a unique binding of one or two visible characters.",
        ]
        if self.keybinding_capture_action == item.action:
            pending = self.keybinding_capture_buffer or "-"
            lines.extend(
                [
                    "",
                    "Waiting for key input.",
                    f"Pending: {pending}",
                    "Type one or two characters, Enter to apply, Backspace to delete, Esc cancels.",
                ]
            )
        else:
            lines.extend(["", f"Press {self._binding_label('edit_item')} or Enter to rebind this action."])
        if self.keybinding_error_message:
            lines.extend(["", f"Error: {self.keybinding_error_message}"])
        return lines

    def _rule_builder_detail_lines(self, item: MatchReplaceFieldItem | None) -> list[str]:
        if item is None:
            return ["No rule builder field selected."]
        draft = self.rule_builder_draft
        lines = [
            item.label,
            "",
            item.description,
            "",
            f"Current value: {self._rule_builder_value(item.kind)}",
            "",
            "Generated JSON preview:",
            "",
            *self._render_match_replace_rules_document_from_rules(
                [*self.store.match_replace_rules(), self._draft_match_replace_rule()]
            ).splitlines(),
        ]
        if item.kind in {"enabled", "scope", "mode", "create", "cancel"}:
            lines.extend(["", f"Press {self._binding_label('edit_item')} or Enter to activate this item."])
        else:
            lines.extend(["", f"Press {self._binding_label('edit_item')} or Enter to edit this field."])
        if self.rule_builder_error_message:
            lines.extend(["", f"Error: {self.rule_builder_error_message}"])
        return lines

    def _rule_builder_value(self, kind: str) -> str:
        draft = self.rule_builder_draft
        mapping = {
            "enabled": "on" if draft.enabled else "off",
            "scope": draft.scope,
            "mode": draft.mode,
            "description": draft.description or "-",
            "match": draft.match or "-",
            "replace": draft.replace or "-",
            "create": "append rule",
            "cancel": "discard draft",
        }
        return mapping[kind]

    def _draw_sitemap_tree(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        items: list[SitemapItem],
    ) -> None:
        if height <= 0 or width <= 0:
            return
        tree_lines = [f"{'  ' * item.depth}{item.label}" for item in items]
        rows, x_scroll = self._prepare_plain_visual_rows(tree_lines, width, self.sitemap_tree_x_scroll)
        selected_row = next(
            (index for index, (source_index, _) in enumerate(rows) if source_index == self.sitemap_selected_index),
            0,
        )
        start = self._window_start(max(self.sitemap_tree_scroll, selected_row), len(rows), height)
        self.sitemap_tree_scroll = start
        self.sitemap_tree_x_scroll = x_scroll
        visible_rows = rows[start : start + height]
        if not visible_rows:
            stdscr.addnstr(y, x, "No traffic yet.".ljust(width), width)
            return
        for offset, (source_index, line) in enumerate(visible_rows):
            row_y = y + offset
            attr = curses.A_NORMAL
            if source_index == self.sitemap_selected_index and curses.has_colors():
                attr = curses.color_pair(1)
            elif source_index == self.sitemap_selected_index:
                attr = curses.A_REVERSE
            self._draw_text_line(stdscr, row_y, x, width, line, x_scroll=x_scroll, attr=attr)
        self._draw_detail_scroll_indicators(stdscr, y, x, height, width, start, len(visible_rows), len(rows))

    def _draw_sitemap_detail_pane(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        lines: list[str],
        pane: str,
    ) -> None:
        if height <= 0 or width <= 0:
            return
        scroll = self.sitemap_request_scroll if pane == "sitemap_request" else self.sitemap_response_scroll
        initial_x_scroll = self.sitemap_request_x_scroll if pane == "sitemap_request" else self.sitemap_response_x_scroll
        rows, x_scroll = self._prepare_plain_visual_rows(lines, width, initial_x_scroll)
        start = self._window_start(scroll, len(rows), height)
        if pane == "sitemap_request":
            self.sitemap_request_scroll = start
            self.sitemap_request_x_scroll = x_scroll
        else:
            self.sitemap_response_scroll = start
            self.sitemap_response_x_scroll = x_scroll
        visible_rows = rows[start : start + height]
        for offset, (_, line) in enumerate(visible_rows):
            self._draw_text_line(stdscr, y + offset, x, width, line, x_scroll=x_scroll)
        self._draw_detail_scroll_indicators(stdscr, y, x, height, width, start, len(visible_rows), len(rows))

    def _build_sitemap_items(self, entries: list[TrafficEntry]) -> list[SitemapItem]:
        latest_by_endpoint: dict[tuple[str, str], TrafficEntry] = {}
        for entry in entries:
            host = entry.request.host or entry.summary_host or "-"
            path = entry.request.path or entry.request.target or "/"
            key = (host, path)
            existing = latest_by_endpoint.get(key)
            if existing is None or entry.id > existing.id:
                latest_by_endpoint[key] = entry

        items: list[SitemapItem] = []
        hosts: dict[str, dict[str, object]] = {}
        for (host, path), entry in latest_by_endpoint.items():
            host_bucket = hosts.setdefault(host, {"entry": entry, "paths": []})
            if entry.id > host_bucket["entry"].id:
                host_bucket["entry"] = entry
            host_bucket["paths"].append((path, entry))

        for host in sorted(hosts):
            host_entry = hosts[host]["entry"]
            items.append(SitemapItem(label=host, depth=0, entry_id=host_entry.id, kind="host"))
            prefixes_seen: set[tuple[str, ...]] = set()
            path_entries = sorted(hosts[host]["paths"], key=lambda item: item[0])
            for path, entry in path_entries:
                segments = [segment for segment in path.split("/") if segment] or ["/"]
                for depth, segment in enumerate(segments, start=1):
                    prefix = tuple(segments[:depth])
                    is_leaf = depth == len(segments)
                    if not is_leaf and prefix not in prefixes_seen:
                        items.append(SitemapItem(label=f"{segment}/", depth=depth, entry_id=entry.id, kind="folder"))
                        prefixes_seen.add(prefix)
                    elif is_leaf:
                        status = self._status_label(entry)
                        label = f"{segment} [{entry.request.method} {status}]"
                        items.append(SitemapItem(label=label, depth=depth, entry_id=entry.id, kind="leaf"))
        return items

    def _build_repeater_session_bar(self, width: int) -> str:
        if not self.repeater_sessions:
            return " Repeater | no sessions "
        labels: list[str] = []
        for index, session in enumerate(self.repeater_sessions, start=1):
            marker = "*" if index - 1 == self.repeater_index else "-"
            source = f"#{session.source_entry_id}" if session.source_entry_id is not None else "manual"
            labels.append(f"{marker}{index}:{source}")
        current = self._current_repeater_session()
        sent = self._format_save_time(current.last_sent_at) if current is not None else "-"
        error = current.last_error if current is not None and current.last_error else "-"
        bar = f" Repeater [{' '.join(labels)}] | sent: {sent} | error: {error} "
        return self._trim(bar, max(1, width))

    def _draw_repeater_pane(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        lines: list[str],
        pane: str,
        session: RepeaterSession,
    ) -> None:
        if height <= 0 or width <= 0:
            return
        scroll = session.request_scroll if pane == "request" else session.response_scroll
        initial_x_scroll = session.request_x_scroll if pane == "request" else session.response_x_scroll
        rows, x_scroll = self._prepare_plain_visual_rows(lines, width, initial_x_scroll)
        start = self._window_start(scroll, len(rows), height)
        if pane == "request":
            session.request_scroll = start
            session.request_x_scroll = x_scroll
        else:
            session.response_scroll = start
            session.response_x_scroll = x_scroll
        visible_rows = rows[start : start + height]
        for offset, (_, line) in enumerate(visible_rows):
            self._draw_text_line(stdscr, y + offset, x, width, line, x_scroll=x_scroll)
        self._draw_detail_scroll_indicators(stdscr, y, x, height, width, start, len(visible_rows), len(rows))

    def _repeater_request_lines(self, session: RepeaterSession) -> list[str]:
        lines = [
            f"Session: {self.repeater_index + 1}/{len(self.repeater_sessions)}",
            f"Source flow: #{session.source_entry_id}" if session.source_entry_id is not None else "Source flow: -",
            "",
        ]
        request_lines = session.request_text.splitlines() or ([session.request_text] if session.request_text else [])
        if not request_lines:
            request_lines = ["No repeater request loaded."]
        lines.extend(request_lines)
        return lines

    def _repeater_response_lines(self, session: RepeaterSession) -> list[str]:
        lines = [
            f"Last sent: {self._format_save_time(session.last_sent_at)}",
            f"Last error: {session.last_error or '-'}",
            "",
        ]
        response_lines = session.response_text.splitlines() or ([session.response_text] if session.response_text else [])
        if not response_lines:
            response_lines = ["No repeater response yet."]
        lines.extend(response_lines)
        return lines

    def _draw_flow_list(self, stdscr, y: int, x: int, height: int, width: int, entries: list[TrafficEntry]) -> None:
        header = f"{'#':<4} {'M':<6} {'S':<5} {'Host':<18} Path"
        lines = [header, *(self._flow_list_line(entry) for entry in entries)]
        x_scroll = self._normalize_horizontal_scroll(self.flow_x_scroll, self._max_display_width(lines), width)
        self.flow_x_scroll = x_scroll
        self._draw_text_line(stdscr, y, x, width, header, x_scroll=x_scroll, attr=curses.A_BOLD)

        start_index, visible_entries = self._visible_flow_entries(entries, max(0, height - 1))
        for offset, entry in enumerate(visible_entries):
            row_y = y + 1 + offset
            line = self._flow_list_line(entry)

            attr = curses.A_NORMAL
            absolute_index = start_index + offset
            if absolute_index == self.selected_index and curses.has_colors():
                attr = curses.color_pair(1)
            elif absolute_index == self.selected_index:
                attr = curses.A_REVERSE
            elif entry.state in {"error", "dropped"} and curses.has_colors():
                attr = curses.color_pair(3)
            elif entry.state == "intercepted" and curses.has_colors():
                attr = curses.color_pair(4)
            elif entry.response.status_code and curses.has_colors():
                attr = curses.color_pair(2)
            self._draw_text_line(stdscr, row_y, x, width, line, x_scroll=x_scroll, attr=attr)

        if start_index > 0:
            stdscr.addnstr(y, max(x, x + width - 3), " ^ ", min(3, width), curses.A_BOLD)
        if start_index + len(visible_entries) < len(entries):
            stdscr.addnstr(y + height - 1, max(x, x + width - 3), " v ", min(3, width), curses.A_BOLD)

    def _draw_intercept_list(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        entries: list[TrafficEntry],
        intercept_items: list[PendingInterceptionView],
    ) -> None:
        header = f"{'#':<4} {'P':<8} {'D':<8} {'M':<6} {'Host':<18} Path"
        lines = [
            header,
            *(self._intercept_list_line(item, self._entry_for_pending(entries, item)) for item in intercept_items),
        ]
        x_scroll = self._normalize_horizontal_scroll(self.flow_x_scroll, self._max_display_width(lines), width)
        self.flow_x_scroll = x_scroll
        self._draw_text_line(stdscr, y, x, width, header, x_scroll=x_scroll, attr=curses.A_BOLD)

        start_index, visible_pending = self._visible_intercept_entries(intercept_items, max(0, height - 1))
        if not visible_pending:
            self._draw_text_line(stdscr, y + 1, x, width, "No intercepted items yet.", x_scroll=x_scroll)
            return
        for offset, item in enumerate(visible_pending):
            row_y = y + 1 + offset
            line = self._intercept_list_line(item, self._entry_for_pending(entries, item))
            attr = curses.A_NORMAL
            absolute_index = start_index + offset
            if absolute_index == self.intercept_selected_index and curses.has_colors():
                attr = curses.color_pair(1)
            elif absolute_index == self.intercept_selected_index:
                attr = curses.A_REVERSE
            elif item.active and curses.has_colors():
                attr = curses.color_pair(4)
            self._draw_text_line(stdscr, row_y, x, width, line, x_scroll=x_scroll, attr=attr)

        if start_index > 0:
            stdscr.addnstr(y, max(x, x + width - 3), " ^ ", min(3, width), curses.A_BOLD)
        if start_index + len(visible_pending) < len(intercept_items):
            stdscr.addnstr(y + height - 1, max(x, x + width - 3), " v ", min(3, width), curses.A_BOLD)

    def _flow_list_line(self, entry: TrafficEntry) -> str:
        status = self._status_label(entry)
        host = entry.summary_host
        path = entry.summary_path
        return f"{entry.id:<4} {entry.request.method[:6]:<6} {status:<5} {host:<18} {path}"

    def _intercept_list_line(self, pending: PendingInterceptionView, entry: TrafficEntry | None) -> str:
        method = entry.request.method[:6] if entry is not None else "-"
        host = entry.summary_host if entry is not None else "-"
        path = entry.summary_path if entry is not None else "-"
        decision = pending.decision if pending.active else f"{pending.decision}/done"
        return f"{pending.entry_id:<4} {pending.phase:<8} {decision:<8} {method:<6} {host:<18} {path}"

    def _draw_detail(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        entry: TrafficEntry | None,
        pending: list[PendingInterceptionView],
        selected_pending: PendingInterceptionView | None,
        selected_intercept: PendingInterceptionView | None,
    ) -> None:
        if self.active_tab in {5, 6}:
            self._draw_message_detail(stdscr, y, x, height, width, entry)
            return
        lines = self._build_detail_lines(entry, pending, selected_pending, selected_intercept)
        rows, x_scroll = self._prepare_plain_visual_rows(lines, width, self.detail_x_scroll)
        start = self._detail_window_start(len(rows), height)
        self.detail_x_scroll = x_scroll
        visible_rows = rows[start : start + height]
        for offset, (_, line) in enumerate(visible_rows):
            self._draw_text_line(stdscr, y + offset, x, width, line, x_scroll=x_scroll)
        self._draw_detail_scroll_indicators(stdscr, y, x, height, width, start, len(visible_rows), len(rows))

    def _build_detail_lines(
        self,
        entry: TrafficEntry | None,
        pending: list[PendingInterceptionView],
        selected_pending: PendingInterceptionView | None = None,
        selected_intercept: PendingInterceptionView | None = None,
    ) -> list[str]:
        if self.active_tab == 1:
            return self._build_intercept_lines(entry, pending, selected_intercept, selected_pending)
        if self.active_tab == 2:
            return self._build_repeater_lines()
        if self.active_tab == 3:
            return self._build_sitemap_overview_lines()
        if entry is None:
            return ["No traffic yet."]

        last_save_at, last_save_error = self.store.save_status()
        match self.active_tab:
            case 0:
                started = entry.started_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                duration = f"{entry.duration_ms:.1f} ms" if entry.duration_ms is not None else "-"
                saved = self._format_save_time(last_save_at)
                cert_status = "ready" if self.certificate_authority.is_ready() else "missing"
                cert_path = self.certificate_authority.cert_path()
                scope_hosts = self.store.scope_hosts()
                scope_label = "all traffic" if not scope_hosts else f"{len(scope_hosts)} host(s)"
                return [
                    f"ID: {entry.id}",
                    f"Client: {entry.client_addr}",
                    f"Upstream: {entry.upstream_addr or '-'}",
                    f"State: {entry.state}",
                    f"Started: {started}",
                    f"Duration: {duration}",
                    "",
                    f"Request: {entry.request.method} {entry.request.path} {entry.request.version}",
                    f"Response: {entry.response.status_code or '-'} {entry.response.reason}",
                    f"Req bytes: {entry.request_size}",
                    f"Res bytes: {entry.response_size}",
                    "",
                    f"Plugins loaded: {len(self.plugin_manager.loaded_plugins())}",
                    f"Last save: {saved}",
                    f"Save error: {last_save_error or '-'}",
                    f"Scope: {scope_label}",
                    f"Scope hosts: {', '.join(scope_hosts) if scope_hosts else '-'}",
                    f"CA status: {cert_status}",
                    f"CA path: {cert_path}",
                    "CA download URL: http://hexproxy/",
                    "",
                    f"Error: {entry.error or '-'}",
                ]
            case 4:
                return self._build_match_replace_lines()
            case 5:
                return []
            case 6:
                return []
        return []

    def _draw_message_detail(self, stdscr, y: int, x: int, height: int, width: int, entry: TrafficEntry | None) -> None:
        if entry is None:
            stdscr.addnstr(y, x, "No traffic yet.".ljust(width), width)
            return
        lines = self._build_message_detail_lines(entry)
        rows, x_scroll = self._prepare_message_visual_rows(lines, width, self.detail_x_scroll)
        start = self._detail_window_start(len(rows), height)
        self.detail_x_scroll = x_scroll
        visible_rows = rows[start : start + height]

        row = y
        for _, line, style_kind in visible_rows:
            if style_kind is None:
                self._draw_text_line(stdscr, row, x, width, str(line), x_scroll=x_scroll)
            else:
                segments = line if isinstance(line, list) else self._style_body_line(str(line), style_kind)
                self._draw_styled_line(stdscr, row, x, width, segments, x_scroll=x_scroll)
            row += 1
        self._draw_detail_scroll_indicators(stdscr, y, x, height, width, start, len(visible_rows), len(rows))

    def _build_message_detail_lines(self, entry: TrafficEntry) -> list[tuple[str, str | None]]:
        if self.active_tab == 5:
            headers = entry.request.headers
            start_line = f"{entry.request.method} {entry.request.target} {entry.request.version}"
            body = entry.request.body
            document = build_body_document(entry.request.headers, body) if body else None
            mode = self.request_body_view_mode
        else:
            headers = entry.response.headers
            status_code = entry.response.status_code or "-"
            start_line = f"{entry.response.version} {status_code}"
            if entry.response.reason:
                start_line = f"{start_line} {entry.response.reason}"
            body = entry.response.body
            document = build_body_document(entry.response.headers, body) if body else None
            mode = self.response_body_view_mode
        if document is not None and mode == "pretty" and not document.pretty_available:
            mode = "raw"

        lines: list[tuple[str, str | None]] = [(start_line, None)]
        if headers:
            lines.extend((f"{name}: {value}", None) for name, value in headers)
        if document is not None:
            lines.append(("", None))
            body_text = self._body_text_for_mode(document, mode)
            body_lines = body_text.splitlines() or [body_text]
            lines.extend((line, document.kind) for line in body_lines)
        return lines

    def _build_intercept_lines(
        self,
        entry: TrafficEntry | None,
        pending: list[PendingInterceptionView],
        selected_intercept: PendingInterceptionView | None,
        selected_pending: PendingInterceptionView | None,
    ) -> list[str]:
        mode = self.store.intercept_mode()
        lines = [
            f"Intercept mode: {mode}",
            f"Pending queue: {len(pending)}",
            "",
            "Controls:",
            "i cycle mode: off -> request -> response -> both",
            "",
        ]
        if selected_pending is not None:
            lines.insert(5, f"e edit {selected_pending.phase} | a forward | x drop")
        if selected_intercept is None:
            lines.append("No intercepted item selected.")
            if pending:
                lines.append(f"Oldest pending flow: #{pending[0].entry_id}")
            return lines

        created = selected_intercept.created_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        updated = selected_intercept.updated_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines.extend(
            [
                f"Intercepted flow: #{selected_intercept.entry_id}",
                f"Phase: {selected_intercept.phase}",
                f"Decision: {selected_intercept.decision}",
                f"Active: {'yes' if selected_intercept.active else 'no'}",
                f"Request: {entry.request.method} {entry.request.path} {entry.request.version}" if entry is not None else "Request: -",
                f"Created: {created}",
                f"Updated: {updated}",
                "",
                f"Raw {selected_intercept.phase}:",
                "",
            ]
        )
        raw_lines = selected_intercept.raw_text.splitlines() or [selected_intercept.raw_text]
        lines.extend(raw_lines)
        return lines

    def _build_match_replace_lines(self) -> list[str]:
        rules = self.store.match_replace_rules()
        self._sync_match_replace_selection(rules)
        lines = [
            "Match/Replace rules",
            "",
            "Controls:",
            "r open the guided rule builder",
            "x delete selected rule",
            "",
            "Fields: enabled, scope(request|response|both), mode(literal|regex), match, replace, description",
            "",
        ]
        if not rules:
            lines.append("No rules configured.")
            lines.append("Press r to create a rule in the builder workspace.")
            return lines

        for index, rule in enumerate(rules, start=1):
            status = "on" if rule.enabled else "off"
            description = rule.description or "-"
            marker = ">" if index - 1 == self.match_replace_selected_index else " "
            lines.extend(
                [
                    f"{marker}[{index}] {status} | {rule.scope} | {rule.mode} | {description}",
                    f"match: {rule.match}",
                    f"replace: {rule.replace}",
                    "",
                ]
            )
        return lines

    def _build_repeater_lines(self) -> list[str]:
        session = self._current_repeater_session()
        if session is None:
            return [
                "Repeater",
                "",
                "No repeater sessions loaded.",
                "Press y on a selected flow to create one.",
            ]
        lines = ["Repeater", "", *self._repeater_request_lines(session), "", *self._repeater_response_lines(session)]
        return lines

    def _build_sitemap_overview_lines(self) -> list[str]:
        return [
            "Sitemap",
            "",
            "Workspace mode.",
            "Use the dedicated Sitemap tab layout instead of the generic detail view.",
            "",
            "Controls:",
            "h/l change active pane",
            "j/k move tree selection or scroll request/response",
            "y load selected sitemap item into repeater",
        ]

    @staticmethod
    def _body_text_for_mode(document: BodyDocument, mode: str) -> str:
        if mode == "pretty" and document.pretty_available and document.pretty_text is not None:
            return document.pretty_text
        return document.raw_text

    def _style_body_line(self, line: str, kind: str) -> list[tuple[str, int]]:
        if kind == "json":
            return self._style_json_line(line)
        if kind in {"xml", "html"}:
            return self._style_markup_line(line)
        if kind == "form":
            return self._style_form_line(line)
        if kind == "javascript":
            return self._style_javascript_line(line)
        if kind == "css":
            return self._style_css_line(line)
        if kind == "binary":
            return self._style_hexdump_line(line)
        return [(line, curses.A_NORMAL)]

    def _style_json_line(self, line: str) -> list[tuple[str, int]]:
        colors = self._colors_enabled()
        segments: list[tuple[str, int]] = []
        index = 0
        while index < len(line):
            character = line[index]
            if character in "{}[]:,":
                attr = curses.color_pair(6) if colors else curses.A_BOLD
                segments.append((character, attr))
                index += 1
                continue
            if character == '"':
                end = index + 1
                escaped = False
                while end < len(line):
                    current = line[end]
                    if current == '"' and not escaped:
                        end += 1
                        break
                    escaped = current == "\\" and not escaped
                    if current != "\\":
                        escaped = False
                    end += 1
                attr = curses.color_pair(2) if colors else curses.A_NORMAL
                segments.append((line[index:end], attr))
                index = end
                continue
            match = re.match(r"-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?", line[index:])
            if match:
                attr = curses.color_pair(5) if colors else curses.A_NORMAL
                segments.append((match.group(0), attr))
                index += len(match.group(0))
                continue
            keyword_match = re.match(r"\b(true|false|null)\b", line[index:])
            if keyword_match:
                attr = curses.color_pair(4) if colors else curses.A_BOLD
                segments.append((keyword_match.group(0), attr))
                index += len(keyword_match.group(0))
                continue
            segments.append((character, curses.A_NORMAL))
            index += 1
        return segments

    def _style_markup_line(self, line: str) -> list[tuple[str, int]]:
        colors = self._colors_enabled()
        segments: list[tuple[str, int]] = []
        parts = re.split(r"(<[^>]+>)", line)
        for part in parts:
            if not part:
                continue
            if part.startswith("<") and part.endswith(">"):
                tag_attr = curses.color_pair(5) if colors else curses.A_BOLD
                segments.append((part, tag_attr))
            else:
                segments.append((part, curses.A_NORMAL))
        return segments

    def _style_form_line(self, line: str) -> list[tuple[str, int]]:
        if " = " not in line:
            return [(line, curses.A_NORMAL)]
        key, value = line.split(" = ", 1)
        colors = self._colors_enabled()
        key_attr = curses.color_pair(7) if colors else curses.A_BOLD
        value_attr = curses.color_pair(2) if colors else curses.A_NORMAL
        return [(key, key_attr), (" = ", curses.A_NORMAL), (value, value_attr)]

    def _style_hexdump_line(self, line: str) -> list[tuple[str, int]]:
        match = re.match(r"^([0-9a-f]{8})(\s{2}.*?\s{2})(.*)$", line)
        if match is None:
            return [(line, curses.A_NORMAL)]
        colors = self._colors_enabled()
        offset_attr = curses.color_pair(4) if colors else curses.A_BOLD
        hex_attr = curses.color_pair(5) if colors else curses.A_NORMAL
        ascii_attr = curses.color_pair(2) if colors else curses.A_NORMAL
        return [
            (match.group(1), offset_attr),
            (match.group(2), hex_attr),
            (match.group(3), ascii_attr),
        ]

    def _style_javascript_line(self, line: str) -> list[tuple[str, int]]:
        colors = self._colors_enabled()
        keyword_pattern = re.compile(
            r"\b(const|let|var|function|return|if|else|for|while|switch|case|break|continue|new|class|true|false|null|undefined)\b"
        )
        string_pattern = re.compile(r"""("(?:\\.|[^"])*"|'(?:\\.|[^'])*')""")
        comment_pattern = re.compile(r"(//.*$)")
        number_pattern = re.compile(r"\b\d+(?:\.\d+)?\b")
        return self._style_with_patterns(
            line,
            [
                (comment_pattern, curses.color_pair(4) if colors else curses.A_DIM),
                (string_pattern, curses.color_pair(2) if colors else curses.A_NORMAL),
                (keyword_pattern, curses.color_pair(6) if colors else curses.A_BOLD),
                (number_pattern, curses.color_pair(5) if colors else curses.A_NORMAL),
            ],
        )

    def _style_css_line(self, line: str) -> list[tuple[str, int]]:
        colors = self._colors_enabled()
        property_pattern = re.compile(r"\b([a-zA-Z-]+)(\s*:)")
        selector_pattern = re.compile(r"^\s*([^{]+)(\s*\{)")
        string_pattern = re.compile(r"""("(?:\\.|[^"])*"|'(?:\\.|[^'])*')""")

        segments = self._style_with_patterns(
            line,
            [
                (string_pattern, curses.color_pair(2) if colors else curses.A_NORMAL),
            ],
        )
        if selector_match := selector_pattern.match(line):
            selector_attr = curses.color_pair(7) if colors else curses.A_BOLD
            brace_attr = curses.color_pair(6) if colors else curses.A_BOLD
            return [
                (selector_match.group(1), selector_attr),
                (selector_match.group(2), brace_attr),
                (line[selector_match.end() :], curses.A_NORMAL),
            ]

        styled: list[tuple[str, int]] = []
        source = "".join(text for text, _ in segments)
        cursor = 0
        for match in property_pattern.finditer(source):
            if match.start() > cursor:
                styled.append((source[cursor : match.start()], curses.A_NORMAL))
            styled.append((match.group(1), curses.color_pair(7) if colors else curses.A_BOLD))
            styled.append((match.group(2), curses.color_pair(6) if colors else curses.A_BOLD))
            cursor = match.end()
        if cursor < len(source):
            styled.append((source[cursor:], curses.A_NORMAL))
        return styled or [(line, curses.A_NORMAL)]

    def _style_with_patterns(self, line: str, patterns: list[tuple[re.Pattern[str], int]]) -> list[tuple[str, int]]:
        segments: list[tuple[str, int]] = []
        index = 0
        while index < len(line):
            for pattern, attr in patterns:
                match = pattern.match(line, index)
                if match is None:
                    continue
                segments.append((match.group(0), attr))
                index = match.end()
                break
            else:
                segments.append((line[index], curses.A_NORMAL))
                index += 1
        return segments

    def _draw_styled_line(
        self,
        stdscr,
        y: int,
        x: int,
        width: int,
        segments: list[tuple[str, int]],
        x_scroll: int = 0,
    ) -> None:
        if width <= 0:
            return
        remaining = width
        cursor_x = x
        skip = max(0, x_scroll)
        for text, attr in segments:
            if remaining <= 0:
                break
            if not text:
                continue
            visible_text = self._sanitize_display_text(text)
            if skip >= len(visible_text):
                skip -= len(visible_text)
                continue
            visible = visible_text[skip : skip + remaining]
            skip = 0
            if not visible:
                continue
            stdscr.addnstr(y, cursor_x, visible, remaining, attr)
            cursor_x += len(visible)
            remaining -= len(visible)

    def _draw_text_line(
        self,
        stdscr,
        y: int,
        x: int,
        width: int,
        text: str,
        *,
        x_scroll: int = 0,
        attr: int = curses.A_NORMAL,
    ) -> None:
        if width <= 0:
            return
        visible = self._slice_display_text(text, width, x_scroll)
        stdscr.addnstr(y, x, visible.ljust(width), width, attr)

    @classmethod
    def _wrap_display_text(cls, text: str, width: int) -> list[str]:
        if width <= 0:
            return [""]
        sanitized = cls._sanitize_display_text(text)
        if not sanitized:
            return [""]
        return [sanitized[index : index + width] for index in range(0, len(sanitized), width)]

    def _prepare_plain_visual_rows(
        self,
        lines: list[str],
        width: int,
        x_scroll: int,
    ) -> tuple[list[tuple[int, str]], int]:
        if self.word_wrap_enabled:
            rows: list[tuple[int, str]] = []
            for index, line in enumerate(lines):
                rows.extend((index, chunk) for chunk in self._wrap_display_text(line, max(1, width)))
            return rows, 0
        normalized = self._normalize_horizontal_scroll(x_scroll, self._max_display_width(lines), width)
        return list(enumerate(lines)), normalized

    def _prepare_message_visual_rows(
        self,
        lines: list[tuple[str, str | None]],
        width: int,
        x_scroll: int,
    ) -> tuple[list[tuple[int, str | list[tuple[str, int]], str | None]], int]:
        if self.word_wrap_enabled:
            rows: list[tuple[int, str | list[tuple[str, int]], str | None]] = []
            for index, (line, style_kind) in enumerate(lines):
                if style_kind is None:
                    rows.extend((index, chunk, None) for chunk in self._wrap_display_text(line, max(1, width)))
                    continue
                wrapped_segments = self._wrap_styled_segments(self._style_body_line(line, style_kind), max(1, width))
                rows.extend((index, segments, style_kind) for segments in wrapped_segments)
            return rows, 0
        max_line_width = max((self._display_width(line) for line, _ in lines), default=0)
        normalized = self._normalize_horizontal_scroll(x_scroll, max_line_width, width)
        return [(index, line, style_kind) for index, (line, style_kind) in enumerate(lines)], normalized

    def _wrap_styled_segments(self, segments: list[tuple[str, int]], width: int) -> list[list[tuple[str, int]]]:
        if width <= 0:
            return [[("", curses.A_NORMAL)]]
        if not segments:
            return [[("", curses.A_NORMAL)]]

        rows: list[list[tuple[str, int]]] = []
        current_row: list[tuple[str, int]] = []
        remaining = width

        for text, attr in segments:
            visible = self._sanitize_display_text(text)
            if not visible:
                continue
            while visible:
                chunk = visible[:remaining]
                if chunk:
                    current_row.append((chunk, attr))
                    visible = visible[len(chunk) :]
                    remaining -= len(chunk)
                if remaining == 0:
                    rows.append(current_row or [("", curses.A_NORMAL)])
                    current_row = []
                    remaining = width

        if current_row or not rows:
            rows.append(current_row or [("", curses.A_NORMAL)])
        return rows

    @staticmethod
    def _sanitize_display_text(text: str) -> str:
        sanitized: list[str] = []
        for character in text:
            codepoint = ord(character)
            if character in {"\t", "\n"} or 32 <= codepoint <= 126:
                sanitized.append(character)
                continue
            if character == "\x00":
                sanitized.append("\\0")
                continue
            if codepoint < 32 or codepoint == 127:
                sanitized.append(f"\\x{codepoint:02x}")
                continue
            sanitized.append(character)
        return "".join(sanitized)

    @classmethod
    def _slice_display_text(cls, text: str, width: int, x_scroll: int = 0) -> str:
        if width <= 0:
            return ""
        sanitized = cls._sanitize_display_text(text)
        start = max(0, x_scroll)
        if start >= len(sanitized):
            return ""
        return sanitized[start : start + width]

    @classmethod
    def _display_width(cls, text: str) -> int:
        return len(cls._sanitize_display_text(text))

    def _max_display_width(self, lines: list[str]) -> int:
        return max((self._display_width(line) for line in lines), default=0)

    @staticmethod
    def _normalize_horizontal_scroll(scroll: int, max_line_width: int, width: int) -> int:
        if width <= 0 or max_line_width <= width:
            return 0
        max_start = max(0, max_line_width - width)
        return max(0, min(scroll, max_start))

    @staticmethod
    def _draw_box(stdscr, y: int, x: int, height: int, width: int, title: str) -> None:
        stdscr.addnstr(y, x + 2, f" {title} ", max(1, width - 4), curses.A_BOLD)
        stdscr.vline(y + 1, x, curses.ACS_VLINE, height - 1)
        stdscr.vline(y + 1, x + width - 1, curses.ACS_VLINE, height - 1)
        stdscr.hline(y + height, x, curses.ACS_HLINE, width)
        stdscr.hline(y + 1, x, curses.ACS_HLINE, width)
        stdscr.addch(y + 1, x, curses.ACS_ULCORNER)
        stdscr.addch(y + 1, x + width - 1, curses.ACS_URCORNER)
        stdscr.addch(y + height, x, curses.ACS_LLCORNER)
        stdscr.addch(y + height, x + width - 1, curses.ACS_LRCORNER)

    @staticmethod
    def _trim(text: str, width: int) -> str:
        if width <= 1:
            return text[:width]
        if len(text) <= width:
            return text
        return text[: width - 1] + "…"

    def _save_project(self, stdscr) -> None:
        project_path = self.store.project_path()
        if project_path is None:
            project_path = self._prompt_project_path(stdscr)
            if project_path is None:
                self._set_status("Save cancelled.")
                return
            self.store.set_project_path(project_path)
        try:
            self.store.save()
        except Exception as exc:
            self._set_status(f"Save failed: {exc}")
            return
        self._set_status(f"Project saved: {project_path}")

    def _edit_match_replace_rules(self, stdscr) -> None:
        if self.active_tab != 4:
            return
        self._open_rule_builder_workspace()

    def _edit_scope_hosts(self, stdscr) -> None:
        edited = self._open_external_editor(stdscr, self._render_scope_document())
        if edited is None:
            self._set_status("Scope edit cancelled.")
            return

        try:
            hosts = self._parse_scope_document(edited)
            self.store.set_scope_hosts(hosts)
        except Exception as exc:
            self._set_status(f"Invalid scope document: {exc}")
            return
        if hosts:
            self._set_status(f"Loaded scope for {len(hosts)} host(s).")
            return
        self._set_status("Scope cleared. Interception applies to all hosts.")

    def _ensure_certificate_authority(self) -> None:
        try:
            cert_path = self.certificate_authority.ensure_ready()
        except Exception as exc:
            self._set_status(f"CA generation failed: {exc}")
            return
        self._set_status(f"CA ready: {cert_path}")

    def _regenerate_certificate_authority(self) -> None:
        try:
            cert_path = self.certificate_authority.regenerate()
        except Exception as exc:
            self._set_status(f"CA regeneration failed: {exc}")
            return
        self._set_status(f"CA regenerated: {cert_path}")

    def _forward_intercepted_request(self, pending: PendingInterceptionView | None) -> None:
        if pending is None:
            self._set_status("Select a paused intercepted flow first.")
            return
        try:
            self.store.forward_pending_interception_record(pending.record_id)
        except KeyError:
            self._set_status("Selected flow is not intercepted.")
            return
        self._set_status(f"Forwarded intercepted {pending.phase} for flow #{pending.entry_id}.")

    def _drop_intercepted_request(self, pending: PendingInterceptionView | None) -> None:
        if pending is None:
            self._set_status("Select a paused intercepted flow first.")
            return
        try:
            self.store.drop_pending_interception_record(pending.record_id)
        except KeyError:
            self._set_status("Selected flow is not intercepted.")
            return
        self._set_status(f"Dropped intercepted {pending.phase} for flow #{pending.entry_id}.")

    def _edit_intercepted_request(self, stdscr, pending: PendingInterceptionView | None) -> None:
        if pending is None:
            self._set_status("Select a paused intercepted flow first.")
            return

        edited = self._open_external_editor(stdscr, pending.raw_text)
        if edited is None:
            self._set_status("Edit cancelled.")
            return

        try:
            if pending.phase == "request":
                parse_request_text(edited)
            else:
                parse_response_text(edited)
        except Exception as exc:
            self._set_status(f"Invalid edited {pending.phase}: {exc}")
            return

        self.store.update_pending_interception_record(pending.record_id, edited)
        self._set_status(f"Updated intercepted {pending.phase} for flow #{pending.entry_id}.")

    def _load_repeater_from_selected_flow(self, entry: TrafficEntry | None) -> None:
        if entry is None:
            self._set_status("Select a flow first.")
            return
        session = RepeaterSession(
            request_text=self._render_repeater_request(entry),
            source_entry_id=entry.id,
        )
        self.repeater_sessions.append(session)
        self.repeater_index = len(self.repeater_sessions) - 1
        self.active_tab = 2
        self.active_pane = "repeater_request"
        self._set_status(f"Loaded flow #{entry.id} into repeater {self.repeater_index + 1}.")

    def _edit_repeater_request(self, stdscr) -> None:
        if self.active_tab != 2:
            return
        session = self._current_repeater_session()
        if session is None or not session.request_text:
            self._set_status("Load a flow into repeater first.")
            return
        edited = self._open_external_editor(stdscr, session.request_text)
        if edited is None:
            self._set_status("Repeater edit cancelled.")
            return
        try:
            parse_request_text(edited)
        except Exception as exc:
            self._set_status(f"Invalid repeater request: {exc}")
            return
        session.request_text = edited
        session.request_scroll = 0
        session.request_x_scroll = 0
        self._set_status("Updated repeater request.")

    def _send_repeater_request(self) -> None:
        if self.active_tab != 2:
            return
        session = self._current_repeater_session()
        if self.repeater_sender is None:
            self._set_status("Repeater is not available in this runtime.")
            return
        if session is None or not session.request_text:
            self._set_status("Load a flow into repeater first.")
            return
        try:
            session.response_text = self.repeater_sender(session.request_text)
            session.response_scroll = 0
            session.response_x_scroll = 0
            session.last_error = ""
            session.last_sent_at = datetime.now(timezone.utc)
        except Exception as exc:
            session.last_error = str(exc)
            self._set_status(f"Repeater send failed: {exc}")
            return
        self._set_status("Repeater response received.")

    def _switch_repeater_session(self, delta: int) -> None:
        if self.active_tab != 2 or not self.repeater_sessions:
            return
        self.repeater_index = (self.repeater_index + delta) % len(self.repeater_sessions)
        self._set_status(f"Repeater session {self.repeater_index + 1}/{len(self.repeater_sessions)}.")

    def _scroll_repeater_active_pane(self, delta: int) -> None:
        session = self._current_repeater_session()
        if session is None:
            return
        if self.active_pane == "repeater_response":
            session.response_scroll = max(0, session.response_scroll + delta)
            return
        session.request_scroll = max(0, session.request_scroll + delta)

    def _set_repeater_active_scroll(self, value: int) -> None:
        session = self._current_repeater_session()
        if session is None:
            return
        if self.active_pane == "repeater_response":
            session.response_scroll = max(0, value)
            return
        session.request_scroll = max(0, value)

    def _repeater_page_rows(self, stdscr) -> int:
        height, _ = stdscr.getmaxyx()
        return max(1, height - 6)

    def _selected_sitemap_entry(
        self,
        entries: list[TrafficEntry],
        items: list[SitemapItem] | None = None,
    ) -> TrafficEntry | None:
        current_items = items if items is not None else self._build_sitemap_items(entries)
        if not current_items:
            return None
        self._sync_sitemap_selection(current_items)
        selected_item = current_items[self.sitemap_selected_index]
        if selected_item.entry_id is None:
            return None
        return next((entry for entry in entries if entry.id == selected_item.entry_id), None)

    def _sync_sitemap_selection(self, items: list[SitemapItem]) -> None:
        if not items:
            self.sitemap_selected_index = 0
            self.sitemap_tree_scroll = 0
            self.sitemap_tree_x_scroll = 0
            return
        self.sitemap_selected_index = max(0, min(self.sitemap_selected_index, len(items) - 1))

    def _sync_sitemap_detail_scroll(self, entry_id: int | None) -> None:
        if entry_id != self._last_sitemap_entry_id:
            self.sitemap_request_scroll = 0
            self.sitemap_request_x_scroll = 0
            self.sitemap_response_scroll = 0
            self.sitemap_response_x_scroll = 0
            self._last_sitemap_entry_id = entry_id

    def _move_sitemap_focus(self, delta: int) -> None:
        panes = ["sitemap_tree", "sitemap_request", "sitemap_response"]
        if self.active_pane not in panes:
            self.active_pane = "sitemap_tree"
            return
        index = panes.index(self.active_pane)
        index = max(0, min(len(panes) - 1, index + delta))
        self.active_pane = panes[index]

    def _scroll_sitemap_active_pane(self, delta: int, entries: list[TrafficEntry]) -> None:
        if self.active_pane == "sitemap_request":
            self.sitemap_request_scroll = max(0, self.sitemap_request_scroll + delta)
            return
        if self.active_pane == "sitemap_response":
            self.sitemap_response_scroll = max(0, self.sitemap_response_scroll + delta)
            return
        items = self._build_sitemap_items(entries)
        if not items:
            self.sitemap_selected_index = 0
            return
        self.sitemap_selected_index = max(0, min(len(items) - 1, self.sitemap_selected_index + delta))

    def _set_sitemap_active_scroll(self, value: int) -> None:
        if self.active_pane == "sitemap_request":
            self.sitemap_request_scroll = max(0, value)
            return
        if self.active_pane == "sitemap_response":
            self.sitemap_response_scroll = max(0, value)
            return
        self.sitemap_tree_scroll = max(0, value)

    def _sitemap_page_rows(self, stdscr) -> int:
        height, _ = stdscr.getmaxyx()
        return max(1, height - 6)

    def _sitemap_request_lines(self, entry: TrafficEntry | None) -> list[str]:
        if entry is None:
            return ["No sitemap item selected."]
        request_text = self._render_repeater_request(entry)
        lines = [
            f"Flow: #{entry.id}",
            f"Host: {entry.summary_host}",
            f"Path: {entry.summary_path}",
            "",
        ]
        request_lines = request_text.splitlines() or [request_text]
        lines.extend(request_lines)
        return lines

    def _sitemap_response_lines(self, entry: TrafficEntry | None) -> list[str]:
        if entry is None:
            return ["No sitemap item selected."]
        document = build_body_document(entry.response.headers, entry.response.body)
        lines = [
            f"State: {entry.state}",
            f"Status: {entry.response.status_code or '-'} {entry.response.reason}",
            f"Detected: {document.display_name}",
            f"Encoding: {document.encoding_summary}",
            "",
        ]
        status_line = f"{entry.response.version} {entry.response.status_code or '-'}"
        if entry.response.reason:
            status_line = f"{status_line} {entry.response.reason}"
        response_head = [status_line, *(f"{name}: {value}" for name, value in entry.response.headers), ""]
        body_text = document.raw_text
        response_lines = response_head + (body_text.splitlines() or [body_text])
        lines.extend(response_lines)
        return lines

    def _toggle_body_view_mode(self) -> None:
        if self.active_tab == 5:
            self.request_body_view_mode = "raw" if self.request_body_view_mode == "pretty" else "pretty"
            mode = self.request_body_view_mode
        elif self.active_tab == 6:
            self.response_body_view_mode = "raw" if self.response_body_view_mode == "pretty" else "pretty"
            mode = self.response_body_view_mode
        else:
            return
        self._set_status(f"Body view mode: {mode}.")

    def _toggle_word_wrap(self) -> None:
        self.word_wrap_enabled = not self.word_wrap_enabled
        self._reset_horizontal_scrolls()
        state = "on" if self.word_wrap_enabled else "off"
        self._set_status(f"Word wrap: {state}.")

    def _toggle_intercept_mode(self) -> None:
        if self.active_tab != 1:
            return
        current_mode = self.store.intercept_mode()
        modes = ["off", "request", "response", "both"]
        next_mode = modes[(modes.index(current_mode) + 1) % len(modes)]
        self.store.set_intercept_mode(next_mode)
        self._set_status(f"Intercept mode: {next_mode}.")

    def _footer_text(self, width: int, selected_pending: PendingInterceptionView | None) -> str:
        wrap_label = f"{self._binding_label('toggle_word_wrap')} wrap:{'on' if self.word_wrap_enabled else 'off'}"
        if self.active_tab == 1:
            controls = (
                f" q quit | h/l pane | j/k move | H/L pan | {wrap_label} | tab switch | "
                f"{self._binding_label('toggle_intercept_mode')} intercept mode | "
                f"{self._binding_label('save_project')} save "
            )
            if selected_pending is not None:
                controls = (
                    f"{controls}| {self._binding_label('edit_item')} edit | "
                    f"{self._binding_label('forward_send')} send | "
                    f"{self._binding_label('drop_item')} drop "
                )
        elif self.active_tab == 2:
            controls = (
                f" q quit | h/l pane | j/k move | H/L pan | {wrap_label} | tab switch | "
                f"prev:{self._binding_label('repeater_prev_session')} next:{self._binding_label('repeater_next_session')} | "
                f"{self._binding_label('load_repeater')} new repeater | "
                f"{self._binding_label('edit_item')} edit req | "
                f"{self._binding_label('forward_send')} send | "
                f"{self._binding_label('repeater_send_alt')} send "
            )
        elif self.active_tab == 3:
            controls = (
                f" q quit | h/l pane | j/k move | H/L pan | {wrap_label} | tab switch | "
                f"{self._binding_label('load_repeater')} to repeater | PgUp/PgDn page "
            )
        elif self.active_tab == 4:
            controls = (
                f" q quit | h/l pane | j/k move | H/L pan | {wrap_label} | tab switch | "
                f"{self._binding_label('save_project')} save | "
                f"{self._binding_label('edit_match_replace')} new rule | "
                f"{self._binding_label('drop_item')} delete rule "
            )
        elif self.active_tab in {5, 6}:
            controls = (
                f" q quit | h/l pane | j/k move | H/L pan | {wrap_label} | tab switch | "
                f"{self._binding_label('save_project')} save | "
                f"{self._binding_label('toggle_body_view')} raw/pretty | PgUp/PgDn page "
            )
        elif self._is_settings_tab():
            controls = (
                f" q quit | h/l pane | j/k move | H/L pan | {wrap_label} | tab switch | "
                f"{self._binding_label('edit_item')} run/edit | Enter run/edit "
            )
        elif self._is_keybindings_tab():
            controls = (
                f" q quit | h/l pane | j/k move | H/L pan | {wrap_label} | tab switch | "
                f"{self._binding_label('edit_item')} rebind | Enter rebind | Esc cancel "
            )
        elif self._is_rule_builder_tab():
            controls = (
                f" q quit | h/l pane | j/k move | H/L pan | {wrap_label} | tab switch | "
                f"{self._binding_label('edit_item')} edit field | "
                f"{self._binding_label('forward_send')} create rule | "
                f"{self._binding_label('drop_item')} cancel "
            )
        else:
            controls = (
                f" q quit | h/l pane | j/k move | H/L pan | {wrap_label} | tab switch | "
                f"{self._binding_label('save_project')} save "
            )
        controls = f"{controls}| {self._binding_label('open_settings')} settings "
        if self.status_message and monotonic() < self.status_until:
            return self._trim(f"{controls}| {self.status_message}", max(1, width - 1))
        return controls

    def _visible_flow_entries(self, entries: list[TrafficEntry], rows: int) -> tuple[int, list[TrafficEntry]]:
        if rows <= 0 or not entries:
            return 0, []
        if len(entries) <= rows:
            return 0, entries

        max_start = max(0, len(entries) - rows)
        start_index = max(0, self.selected_index - rows + 1)
        start_index = min(start_index, max_start)
        end_index = min(len(entries), start_index + rows)
        return start_index, entries[start_index:end_index]

    def _visible_intercept_entries(
        self,
        pending: list[PendingInterceptionView],
        rows: int,
    ) -> tuple[int, list[PendingInterceptionView]]:
        if rows <= 0 or not pending:
            return 0, []
        if len(pending) <= rows:
            return 0, pending

        max_start = max(0, len(pending) - rows)
        start_index = max(0, self.intercept_selected_index - rows + 1)
        start_index = min(start_index, max_start)
        end_index = min(len(pending), start_index + rows)
        return start_index, pending[start_index:end_index]

    def _set_status(self, message: str) -> None:
        self.status_message = message
        self.status_until = monotonic() + 4

    def _current_keybindings(self) -> dict[str, str]:
        bindings = dict(self.DEFAULT_KEYBINDINGS)
        bindings.update(self._custom_keybindings)
        return bindings

    def custom_keybindings(self) -> dict[str, str]:
        return dict(self._custom_keybindings)

    def _binding_key(self, action: str) -> str:
        return self._current_keybindings().get(action, self.DEFAULT_KEYBINDINGS[action])

    def _binding_label(self, action: str) -> str:
        return self._binding_key(action)

    def _action_for_binding(self, binding: str) -> str | None:
        for action, value in self._current_keybindings().items():
            if value == binding:
                return action
        return None

    def _consume_bound_action(self, key: int) -> str | None:
        key_name = self._captured_key_name(key)
        if key_name is None:
            self._pending_action_sequence = ""
            return None

        if self._pending_action_sequence:
            candidate = f"{self._pending_action_sequence}{key_name}"
            self._pending_action_sequence = ""
            action = self._action_for_binding(candidate)
            if action is not None:
                return action

        action = self._action_for_binding(key_name)
        if action is not None:
            return action

        if any(
            len(binding) == 2 and binding.startswith(key_name)
            for binding in self._current_keybindings().values()
        ):
            self._pending_action_sequence = key_name
            self._set_status(f"Key sequence: {key_name}")
            return None
        return None

    def _open_workspace(self, action: str) -> None:
        tab_index = self.TAB_ACTIONS[action]
        self.active_tab = tab_index
        if self._is_settings_tab():
            self.active_pane = "settings_menu"
            return
        if self._is_keybindings_tab():
            self.active_pane = "keybindings_menu"
            return
        self._sync_active_pane()

    def _sync_detail_scroll(self, entry_id: int | None) -> None:
        if entry_id != self._last_detail_entry_id or self.active_tab != self._last_detail_tab:
            self.detail_scroll = 0
            self.detail_x_scroll = 0
            self._last_detail_entry_id = entry_id
            self._last_detail_tab = self.active_tab

    def _sync_match_replace_selection(self, rules: list[MatchReplaceRule]) -> None:
        if not rules:
            self.match_replace_selected_index = 0
            return
        self.match_replace_selected_index = max(0, min(self.match_replace_selected_index, len(rules) - 1))

    def _move_match_replace_selection(self, delta: int) -> None:
        rules = self.store.match_replace_rules()
        if not rules:
            self.match_replace_selected_index = 0
            return
        self.match_replace_selected_index = max(0, min(len(rules) - 1, self.match_replace_selected_index + delta))

    def _delete_selected_match_replace_rule(self) -> None:
        rules = self.store.match_replace_rules()
        if not rules:
            self._set_status("No Match/Replace rules to delete.")
            return
        self._sync_match_replace_selection(rules)
        removed = rules.pop(self.match_replace_selected_index)
        self.store.set_match_replace_rules(rules)
        if rules:
            self.match_replace_selected_index = min(self.match_replace_selected_index, len(rules) - 1)
        else:
            self.match_replace_selected_index = 0
        label = removed.description or removed.match or "rule"
        self._set_status(f"Deleted Match/Replace rule: {self._trim(label, 40)}")

    def _sync_settings_selection(self, items: list[SettingsItem]) -> None:
        if not items:
            self.settings_selected_index = 0
            self.settings_detail_scroll = 0
            self.settings_detail_x_scroll = 0
            self.theme_selected_index = 0
            return
        self.settings_selected_index = max(0, min(self.settings_selected_index, len(items) - 1))

    def _sync_keybinding_selection(self, items: list[KeybindingItem]) -> None:
        if not items:
            self.keybindings_selected_index = 0
            self.keybindings_detail_scroll = 0
            self.keybindings_detail_x_scroll = 0
            return
        self.keybindings_selected_index = max(0, min(self.keybindings_selected_index, len(items) - 1))

    def _sync_rule_builder_selection(self, items: list[MatchReplaceFieldItem]) -> None:
        if not items:
            self.rule_builder_selected_index = 0
            self.rule_builder_detail_scroll = 0
            self.rule_builder_detail_x_scroll = 0
            return
        self.rule_builder_selected_index = max(0, min(self.rule_builder_selected_index, len(items) - 1))

    def _move_settings_focus(self, delta: int) -> None:
        panes = ["settings_menu", "settings_detail"]
        if self.active_pane not in panes:
            self.active_pane = "settings_menu"
            return
        index = panes.index(self.active_pane)
        index = max(0, min(len(panes) - 1, index + delta))
        self.active_pane = panes[index]

    def _move_keybindings_focus(self, delta: int) -> None:
        panes = ["keybindings_menu", "keybindings_detail"]
        if self.active_pane not in panes:
            self.active_pane = "keybindings_menu"
            return
        index = panes.index(self.active_pane)
        index = max(0, min(len(panes) - 1, index + delta))
        self.active_pane = panes[index]

    def _move_rule_builder_focus(self, delta: int) -> None:
        panes = ["rule_builder_menu", "rule_builder_detail"]
        if self.active_pane not in panes:
            self.active_pane = "rule_builder_menu"
            return
        index = panes.index(self.active_pane)
        index = max(0, min(len(panes) - 1, index + delta))
        self.active_pane = panes[index]

    def _scroll_settings_active_pane(self, delta: int) -> None:
        items = self._settings_items()
        if self.active_pane == "settings_detail":
            current_item = items[self.settings_selected_index] if items else None
            if current_item is not None and current_item.kind == "themes":
                self._move_theme_selection(delta)
                return
            self.settings_detail_scroll = max(0, self.settings_detail_scroll + delta)
            return
        if not items:
            self.settings_selected_index = 0
            return
        previous = self.settings_selected_index
        self.settings_selected_index = max(0, min(len(items) - 1, self.settings_selected_index + delta))
        if previous != self.settings_selected_index:
            self.settings_detail_scroll = 0
            self.settings_detail_x_scroll = 0
            self._sync_theme_selection(prefer_current=True)

    def _scroll_keybindings_active_pane(self, delta: int) -> None:
        items = self._keybinding_items()
        if self.active_pane == "keybindings_detail":
            self.keybindings_detail_scroll = max(0, self.keybindings_detail_scroll + delta)
            return
        if not items:
            self.keybindings_selected_index = 0
            return
        previous = self.keybindings_selected_index
        self.keybindings_selected_index = max(0, min(len(items) - 1, self.keybindings_selected_index + delta))
        if previous != self.keybindings_selected_index:
            self.keybindings_detail_scroll = 0
            self.keybindings_detail_x_scroll = 0

    def _scroll_rule_builder_active_pane(self, delta: int) -> None:
        items = self._rule_builder_items()
        if self.active_pane == "rule_builder_detail":
            self.rule_builder_detail_scroll = max(0, self.rule_builder_detail_scroll + delta)
            return
        if not items:
            self.rule_builder_selected_index = 0
            return
        previous = self.rule_builder_selected_index
        self.rule_builder_selected_index = max(0, min(len(items) - 1, self.rule_builder_selected_index + delta))
        if previous != self.rule_builder_selected_index:
            self.rule_builder_detail_scroll = 0
            self.rule_builder_detail_x_scroll = 0

    def _set_settings_active_scroll(self, value: int) -> None:
        if self.active_pane == "settings_detail":
            self.settings_detail_scroll = max(0, value)
            return
        self.settings_selected_index = max(0, value)

    def _set_keybindings_active_scroll(self, value: int) -> None:
        if self.active_pane == "keybindings_detail":
            self.keybindings_detail_scroll = max(0, value)
            return
        self.keybindings_selected_index = max(0, value)

    def _set_rule_builder_active_scroll(self, value: int) -> None:
        if self.active_pane == "rule_builder_detail":
            self.rule_builder_detail_scroll = max(0, value)
            return
        self.rule_builder_selected_index = max(0, value)

    def _settings_page_rows(self, stdscr) -> int:
        height, _ = stdscr.getmaxyx()
        return max(1, height - 6)

    def _keybindings_page_rows(self, stdscr) -> int:
        height, _ = stdscr.getmaxyx()
        return max(1, height - 6)

    def _rule_builder_page_rows(self, stdscr) -> int:
        height, _ = stdscr.getmaxyx()
        return max(1, height - 6)

    def _activate_settings_item(self, stdscr) -> None:
        items = self._settings_items()
        self._sync_settings_selection(items)
        if not items:
            return
        item = items[self.settings_selected_index]
        if item.kind == "themes":
            if self.active_pane != "settings_detail":
                self.theme_manager.load()
                self._sync_theme_selection(prefer_current=True)
                self.active_pane = "settings_detail"
                self.settings_detail_scroll = 0
                self.settings_detail_x_scroll = 0
                self._set_status("Select a theme with j/k and press Enter to apply it.")
                return
            self._apply_selected_theme()
            return
        if item.kind == "cert_generate":
            self._ensure_certificate_authority()
            return
        if item.kind == "cert_regenerate":
            self._regenerate_certificate_authority()
            return
        if item.kind in {"plugins", "plugin_docs"}:
            self.active_pane = "settings_detail"
            self.settings_detail_scroll = 0
            self.settings_detail_x_scroll = 0
            self._set_status(f"Viewing {item.label}.")
            return
        if item.kind == "scope":
            self._edit_scope_hosts(stdscr)
            return
        if item.kind == "keybindings":
            self._open_keybindings_workspace()

    def _move_theme_selection(self, delta: int) -> None:
        themes = self._available_themes()
        if not themes:
            self.theme_selected_index = 0
            return
        self.theme_selected_index = max(0, min(len(themes) - 1, self.theme_selected_index + delta))
        selected_row = 10 + self.theme_selected_index
        self.settings_detail_scroll = max(0, selected_row - 3)

    def _apply_selected_theme(self) -> None:
        selected = self._selected_theme()
        if selected is None:
            self._set_status("No themes available.")
            return
        self._theme_name = selected.name
        if self._colors_enabled():
            self._apply_theme_colors()
        if self._theme_saver is not None:
            self._theme_saver(selected.name)
        self._set_status(f"Theme applied: {selected.name}.")

    def _open_rule_builder_workspace(self) -> None:
        self.active_tab = self._rule_builder_tab_index()
        self.active_pane = "rule_builder_menu"
        self.rule_builder_selected_index = 0
        self.rule_builder_detail_scroll = 0
        self.rule_builder_detail_x_scroll = 0
        self.rule_builder_draft = MatchReplaceDraft()
        self.rule_builder_error_message = ""
        self._set_status("Rule builder opened.")

    def _activate_rule_builder_item(self, stdscr) -> None:
        items = self._rule_builder_items()
        self._sync_rule_builder_selection(items)
        if not items:
            return
        item = items[self.rule_builder_selected_index]
        if item.kind == "enabled":
            self.rule_builder_draft.enabled = not self.rule_builder_draft.enabled
            self.rule_builder_error_message = ""
            self._set_status(f"Rule enabled: {self.rule_builder_draft.enabled}.")
            return
        if item.kind == "scope":
            modes = ["request", "response", "both"]
            index = modes.index(self.rule_builder_draft.scope)
            self.rule_builder_draft.scope = modes[(index + 1) % len(modes)]
            self.rule_builder_error_message = ""
            self._set_status(f"Rule scope: {self.rule_builder_draft.scope}.")
            return
        if item.kind == "mode":
            modes = ["literal", "regex"]
            index = modes.index(self.rule_builder_draft.mode)
            self.rule_builder_draft.mode = modes[(index + 1) % len(modes)]
            self.rule_builder_error_message = ""
            self._set_status(f"Rule mode: {self.rule_builder_draft.mode}.")
            return
        if item.kind == "description":
            self._edit_rule_builder_text_field(stdscr, "description", self.rule_builder_draft.description)
            return
        if item.kind == "match":
            self._edit_rule_builder_text_field(stdscr, "match", self.rule_builder_draft.match)
            return
        if item.kind == "replace":
            self._edit_rule_builder_text_field(stdscr, "replace", self.rule_builder_draft.replace)
            return
        if item.kind == "create":
            self._commit_rule_builder_draft()
            return
        if item.kind == "cancel":
            self._close_rule_builder_workspace("Rule builder cancelled.")

    def _edit_rule_builder_text_field(self, stdscr, field_name: str, initial_value: str) -> None:
        edited = self._open_external_editor(stdscr, initial_value)
        if edited is None:
            self._set_status(f"{field_name} edit cancelled.")
            return
        value = edited.rstrip("\n")
        setattr(self.rule_builder_draft, field_name, value)
        self.rule_builder_error_message = ""
        self._set_status(f"Updated rule {field_name}.")

    def _draft_match_replace_rule(self) -> MatchReplaceRule:
        draft = self.rule_builder_draft
        return MatchReplaceRule(
            enabled=draft.enabled,
            scope=draft.scope,
            mode=draft.mode,
            match=draft.match,
            replace=draft.replace,
            description=draft.description,
        )

    def _commit_rule_builder_draft(self) -> None:
        rule = self._draft_match_replace_rule()
        all_rules = [*self.store.match_replace_rules(), rule]
        try:
            raw_document = self._render_match_replace_rules_document_from_rules(all_rules)
            parsed_rules = self._parse_match_replace_rules_document(raw_document)
            self.store.set_match_replace_rules(parsed_rules)
        except Exception as exc:
            self.rule_builder_error_message = str(exc)
            self._set_status(f"Invalid match/replace rule: {exc}")
            return
        self.rule_builder_error_message = ""
        self._close_rule_builder_workspace("Match/Replace rule added.")

    def _close_rule_builder_workspace(self, status: str) -> None:
        self.active_tab = 4
        self.active_pane = "detail"
        self.rule_builder_error_message = ""
        self.rule_builder_detail_scroll = 0
        self.rule_builder_detail_x_scroll = 0
        self._set_status(status)

    def _open_keybindings_workspace(self) -> None:
        self.active_tab = self._keybindings_tab_index()
        self.active_pane = "keybindings_menu"
        self.keybindings_detail_scroll = 0
        self.keybindings_detail_x_scroll = 0
        self.keybinding_capture_action = None
        self.keybinding_capture_buffer = ""
        self.keybinding_error_message = ""

    def _activate_keybinding_item(self) -> None:
        items = self._keybinding_items()
        self._sync_keybinding_selection(items)
        if not items:
            return
        item = items[self.keybindings_selected_index]
        self.keybinding_capture_action = item.action
        self.keybinding_capture_buffer = ""
        self.keybinding_error_message = ""
        self._set_status(f"Type one or two keys for {item.action}. Enter applies, Esc cancels.")

    def _handle_keybinding_capture(self, key: int) -> bool:
        action = self.keybinding_capture_action
        if action is None or key == -1:
            return False
        if key == 27:
            self.keybinding_capture_action = None
            self.keybinding_capture_buffer = ""
            self.keybinding_error_message = ""
            self._set_status("Keybinding change cancelled.")
            return True
        if key in (curses.KEY_ENTER, 10, 13):
            if len(self.keybinding_capture_buffer) not in {1, 2}:
                self.keybinding_error_message = "Bindings must contain one or two visible characters."
                self._set_status(self.keybinding_error_message)
                return True
            sequence = self.keybinding_capture_buffer
            self.keybinding_capture_action = None
            self.keybinding_capture_buffer = ""
            self._apply_keybinding_update(action, sequence)
            return True
        if key in (curses.KEY_BACKSPACE, 127, 8):
            self.keybinding_capture_buffer = self.keybinding_capture_buffer[:-1]
            self.keybinding_error_message = ""
            self._set_status(
                f"Pending binding for {action}: {self.keybinding_capture_buffer or '-'}"
            )
            return True
        key_name = self._captured_key_name(key)
        if key_name is None:
            self.keybinding_error_message = "Only visible one or two-character bindings are allowed."
            self._set_status(self.keybinding_error_message)
            return True
        if len(self.keybinding_capture_buffer) >= 2:
            self.keybinding_error_message = "Bindings can contain at most two characters."
            self._set_status(self.keybinding_error_message)
            return True
        self.keybinding_capture_buffer += key_name
        self.keybinding_error_message = ""
        self._set_status(f"Pending binding for {action}: {self.keybinding_capture_buffer}")
        return True

    def _captured_key_name(self, key: int) -> str | None:
        if not 0 <= key <= 255:
            return None
        key_name = chr(key)
        if len(key_name) != 1 or not key_name.isprintable() or key_name.isspace():
            return None
        return key_name

    def _apply_keybinding_update(self, action: str, key_name: str) -> None:
        bindings = self._current_keybindings()
        current_key = bindings.get(action)
        if current_key == key_name:
            self.keybinding_error_message = ""
            self._set_status(f"{action} already uses {key_name!r}.")
            return
        duplicate_action = next(
            (name for name, value in bindings.items() if name != action and value == key_name),
            None,
        )
        if duplicate_action is not None:
            self.keybinding_error_message = f"{key_name!r} is already assigned to {duplicate_action}."
            self._set_status(self.keybinding_error_message)
            return
        bindings[action] = key_name
        try:
            normalized = self._parse_keybindings_document(json.dumps({"bindings": bindings}))
            self._custom_keybindings = normalized
            if self._keybinding_saver is not None:
                self._keybinding_saver(normalized)
        except Exception as exc:
            self.keybinding_error_message = str(exc)
            self._set_status(f"Invalid keybinding change: {exc}")
            return
        self.keybinding_error_message = ""
        self._set_status(f"Assigned {action} to {key_name!r}.")

    def _sync_active_pane(self) -> None:
        if self.active_tab == 2:
            if self.active_pane not in {"repeater_request", "repeater_response"}:
                self.active_pane = "repeater_request"
            return
        if self.active_tab == 3:
            if self.active_pane not in {"sitemap_tree", "sitemap_request", "sitemap_response"}:
                self.active_pane = "sitemap_tree"
            return
        if self._is_settings_tab():
            if self.active_pane not in {"settings_menu", "settings_detail"}:
                self.active_pane = "settings_menu"
            return
        if self._is_keybindings_tab():
            if self.active_pane not in {"keybindings_menu", "keybindings_detail"}:
                self.active_pane = "keybindings_menu"
            return
        if self._is_rule_builder_tab():
            if self.active_pane not in {"rule_builder_menu", "rule_builder_detail"}:
                self.active_pane = "rule_builder_menu"
            return
        if self.active_pane not in {"flows", "detail"}:
            self.active_pane = "flows"

    def _scroll_detail(self, delta: int) -> None:
        self.detail_scroll = max(0, self.detail_scroll + delta)

    def _move_active_pane(self, delta: int, entry_count: int) -> None:
        if self.active_tab == 2:
            self._scroll_repeater_active_pane(delta)
            return
        if self.active_tab == 3:
            self._scroll_sitemap_active_pane(delta, self.store.visible_entries())
            return
        if self.active_tab == 1:
            if self.active_pane == "detail":
                self._scroll_detail(delta)
            else:
                self._move_intercept_selection(delta, self.store.interception_history())
            return
        if self._is_settings_tab():
            self._scroll_settings_active_pane(delta)
            return
        if self._is_keybindings_tab():
            self._scroll_keybindings_active_pane(delta)
            return
        if self._is_rule_builder_tab():
            self._scroll_rule_builder_active_pane(delta)
            return
        if self.active_tab == 4 and self.active_pane == "detail":
            self._move_match_replace_selection(delta)
            return
        if self.active_pane == "detail":
            self._scroll_detail(delta)
            return
        if delta < 0:
            self.selected_index = max(0, self.selected_index - 1)
            return
        self.selected_index = min(max(0, entry_count - 1), self.selected_index + 1)

    def _scroll_horizontal_active_pane(self, delta: int) -> None:
        if self.word_wrap_enabled:
            return
        if self.active_tab == 2:
            session = self._current_repeater_session()
            if session is None:
                return
            if self.active_pane == "repeater_response":
                session.response_x_scroll = max(0, session.response_x_scroll + delta)
                return
            session.request_x_scroll = max(0, session.request_x_scroll + delta)
            return
        if self.active_tab == 3:
            if self.active_pane == "sitemap_request":
                self.sitemap_request_x_scroll = max(0, self.sitemap_request_x_scroll + delta)
                return
            if self.active_pane == "sitemap_response":
                self.sitemap_response_x_scroll = max(0, self.sitemap_response_x_scroll + delta)
                return
            self.sitemap_tree_x_scroll = max(0, self.sitemap_tree_x_scroll + delta)
            return
        if self._is_settings_tab():
            if self.active_pane == "settings_menu":
                self.settings_menu_x_scroll = max(0, self.settings_menu_x_scroll + delta)
                return
            if self.active_pane == "settings_detail":
                self.settings_detail_x_scroll = max(0, self.settings_detail_x_scroll + delta)
            return
        if self._is_keybindings_tab():
            if self.active_pane == "keybindings_menu":
                self.keybindings_menu_x_scroll = max(0, self.keybindings_menu_x_scroll + delta)
                return
            if self.active_pane == "keybindings_detail":
                self.keybindings_detail_x_scroll = max(0, self.keybindings_detail_x_scroll + delta)
            return
        if self._is_rule_builder_tab():
            if self.active_pane == "rule_builder_menu":
                self.rule_builder_menu_x_scroll = max(0, self.rule_builder_menu_x_scroll + delta)
                return
            if self.active_pane == "rule_builder_detail":
                self.rule_builder_detail_x_scroll = max(0, self.rule_builder_detail_x_scroll + delta)
            return
        if self.active_pane == "flows":
            self.flow_x_scroll = max(0, self.flow_x_scroll + delta)
            return
        if self.active_pane == "detail":
            self.detail_x_scroll = max(0, self.detail_x_scroll + delta)

    def _reset_horizontal_scrolls(self) -> None:
        self.flow_x_scroll = 0
        self.detail_x_scroll = 0
        self.sitemap_tree_x_scroll = 0
        self.sitemap_request_x_scroll = 0
        self.sitemap_response_x_scroll = 0
        self.settings_menu_x_scroll = 0
        self.settings_detail_x_scroll = 0
        self.keybindings_menu_x_scroll = 0
        self.keybindings_detail_x_scroll = 0
        self.rule_builder_menu_x_scroll = 0
        self.rule_builder_detail_x_scroll = 0
        for session in self.repeater_sessions:
            session.request_x_scroll = 0
            session.response_x_scroll = 0

    def _detail_window_start(self, total_lines: int, rows: int) -> int:
        start = self._window_start(self.detail_scroll, total_lines, rows)
        self.detail_scroll = start
        return start

    @staticmethod
    def _window_start(scroll: int, total_lines: int, rows: int) -> int:
        if rows <= 0 or total_lines <= rows:
            return 0
        max_start = max(0, total_lines - rows)
        return max(0, min(scroll, max_start))

    def _draw_detail_scroll_indicators(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        start: int,
        visible_count: int,
        total_lines: int,
    ) -> None:
        if total_lines <= height or width <= 0 or height <= 0:
            return
        indicator_x = max(x, x + width - 3)
        if start > 0:
            stdscr.addnstr(y, indicator_x, " ^ ", min(3, width), curses.A_BOLD)
        if start + visible_count < total_lines:
            stdscr.addnstr(y + height - 1, indicator_x, " v ", min(3, width), curses.A_BOLD)

    def _prompt_project_path(self, stdscr) -> Path | None:
        height, width = stdscr.getmaxyx()
        prompt = " Project name or path: "
        stdscr.move(height - 1, 0)
        stdscr.clrtoeol()
        stdscr.addnstr(height - 1, 0, prompt, width - 1, self._chrome_attr())
        stdscr.refresh()

        previous_cursor = None
        stdscr.timeout(-1)
        try:
            try:
                previous_cursor = curses.curs_set(1)
            except curses.error:
                previous_cursor = None
            curses.echo()
            raw_value = stdscr.getstr(height - 1, len(prompt), max(1, width - len(prompt) - 1))
        finally:
            curses.noecho()
            if previous_cursor is not None:
                try:
                    curses.curs_set(previous_cursor)
                except curses.error:
                    pass
            stdscr.timeout(150)

        value = raw_value.decode("utf-8", errors="replace").strip()
        if not value:
            return None
        return self._resolve_project_path(value)

    def _open_external_editor(self, stdscr, initial_text: str) -> str | None:
        editor = os.environ.get("EDITOR", "vi")
        command = shlex.split(editor)
        if not command:
            command = ["vi"]

        with tempfile.NamedTemporaryFile("w+", encoding="iso-8859-1", suffix=".http", delete=False) as handle:
            temp_path = Path(handle.name)
            handle.write(initial_text)
            handle.flush()

        curses.def_prog_mode()
        curses.endwin()
        try:
            completed = subprocess.run([*command, str(temp_path)], check=False)
            if completed.returncode != 0:
                return None
            return temp_path.read_text(encoding="iso-8859-1")
        finally:
            temp_path.unlink(missing_ok=True)
            curses.reset_prog_mode()
            stdscr.refresh()
            try:
                curses.curs_set(0)
            except curses.error:
                pass
            stdscr.keypad(True)
            stdscr.timeout(150)

    def _render_match_replace_rules_document(self) -> str:
        return self._render_match_replace_rules_document_from_rules(self.store.match_replace_rules())

    def _render_match_replace_rules_document_from_rules(self, rules: list[MatchReplaceRule]) -> str:
        payload = {
            "rules": [
                {
                    "enabled": rule.enabled,
                    "scope": rule.scope,
                    "mode": rule.mode,
                    "match": rule.match,
                    "replace": rule.replace,
                    "description": rule.description,
                }
                for rule in rules
            ]
        }
        return json.dumps(payload, indent=2, ensure_ascii=True) + "\n"

    def _render_scope_document(self) -> str:
        lines = [
            "# One host per line.",
            "# example.com also matches subdomains like api.example.com.",
            "# Leave this file empty to intercept all hosts.",
            "",
        ]
        lines.extend(self.store.scope_hosts())
        return "\n".join(lines).rstrip() + "\n"

    def _render_keybindings_document(self) -> str:
        payload = {
            "bindings": self._current_keybindings(),
        }
        return json.dumps(payload, indent=2, ensure_ascii=True) + "\n"

    def _render_keybindings_lines(self) -> list[str]:
        bindings = self._current_keybindings()
        lines: list[str] = []
        for action in sorted(self.KEYBINDING_DESCRIPTIONS):
            lines.append(f"{action}: {bindings[action]} | {self.KEYBINDING_DESCRIPTIONS[action]}")
        return lines

    @staticmethod
    def _parse_match_replace_rules_document(raw_text: str) -> list[MatchReplaceRule]:
        payload = json.loads(raw_text or "{}")
        if isinstance(payload, list):
            rules_payload = payload
        elif isinstance(payload, dict):
            rules_payload = payload.get("rules", [])
        else:
            raise ValueError("document must be a JSON object or JSON array")
        if not isinstance(rules_payload, list):
            raise ValueError("rules must be a JSON array")

        rules: list[MatchReplaceRule] = []
        for index, item in enumerate(rules_payload, start=1):
            if not isinstance(item, dict):
                raise ValueError(f"rule {index}: expected JSON object")
            rules.append(
                MatchReplaceRule(
                    enabled=bool(item.get("enabled", True)),
                    scope=str(item.get("scope", "request")),
                    mode=str(item.get("mode", "literal")),
                    match=str(item.get("match", "")),
                    replace=str(item.get("replace", "")),
                    description=str(item.get("description", "")),
                )
            )
        return rules

    @staticmethod
    def _parse_scope_document(raw_text: str) -> list[str]:
        hosts: list[str] = []
        seen: set[str] = set()
        for line in raw_text.splitlines():
            candidate = line.strip()
            if not candidate or candidate.startswith("#"):
                continue
            normalized = TrafficStore._normalize_scope_host(candidate)
            if not normalized:
                continue
            if normalized in seen:
                continue
            hosts.append(normalized)
            seen.add(normalized)
        return hosts

    @classmethod
    def _parse_keybindings_document(cls, raw_text: str) -> dict[str, str]:
        payload = json.loads(raw_text or "{}")
        if not isinstance(payload, dict):
            raise ValueError("keybinding document must be a JSON object")
        bindings = payload.get("bindings", payload)
        if not isinstance(bindings, dict):
            raise ValueError("bindings must be a JSON object")
        bindings = {
            cls.LEGACY_KEYBINDING_ACTIONS.get(str(action), str(action)): value
            for action, value in bindings.items()
        }

        normalized: dict[str, str] = {}
        seen: set[str] = set()
        for action in cls.KEYBINDING_DESCRIPTIONS:
            key = bindings.get(action, cls.DEFAULT_KEYBINDINGS[action])
            key_name = str(key)
            if len(key_name) not in {1, 2}:
                raise ValueError(f"{action}: key must be one or two characters")
            if any((not character.isprintable()) or character.isspace() for character in key_name):
                raise ValueError(f"{action}: binding must use visible characters")
            if key_name in seen:
                raise ValueError(f"duplicate keybinding detected for {key_name!r}")
            normalized[action] = key_name
            seen.add(key_name)
        for action, key_name in normalized.items():
            for other_action, other_key in normalized.items():
                if action == other_action:
                    continue
                if other_key.startswith(key_name) or key_name.startswith(other_key):
                    raise ValueError(f"ambiguous keybinding between {action!r} and {other_action!r}")
        return normalized

    def _sync_selection(self, entries: list[TrafficEntry], pending: list[PendingInterceptionView]) -> None:
        if self.active_tab == 1:
            return
        if not entries:
            self.selected_index = 0
            return

        self.selected_index = max(0, min(self.selected_index, len(entries) - 1))
        if self.active_tab != 1 or not pending:
            return

        pending_ids = {item.entry_id for item in pending}
        if entries[self.selected_index].id in pending_ids:
            return

        for index, entry in enumerate(entries):
            if entry.id in pending_ids:
                self.selected_index = index
                return

    def _sync_intercept_selection(self, intercept_items: list[PendingInterceptionView]) -> None:
        if not intercept_items:
            self.intercept_selected_index = 0
            return
        self.intercept_selected_index = max(0, min(self.intercept_selected_index, len(intercept_items) - 1))

    def _move_intercept_selection(self, delta: int, intercept_items: list[PendingInterceptionView]) -> None:
        if not intercept_items:
            self.intercept_selected_index = 0
            return
        self.intercept_selected_index = max(0, min(len(intercept_items) - 1, self.intercept_selected_index + delta))

    def _selected_intercept_item(
        self,
        intercept_items: list[PendingInterceptionView],
    ) -> PendingInterceptionView | None:
        if not intercept_items:
            return None
        self._sync_intercept_selection(intercept_items)
        return intercept_items[self.intercept_selected_index]

    @staticmethod
    def _entry_for_pending(
        entries: list[TrafficEntry],
        pending: PendingInterceptionView | None,
    ) -> TrafficEntry | None:
        if pending is None:
            return None
        return next((entry for entry in entries if entry.id == pending.entry_id), None)

    def _selected_pending_interception(self, entry_id: int | None) -> PendingInterceptionView | None:
        if entry_id is None:
            return None
        return self.store.get_pending_interception(entry_id)

    def _current_repeater_session(self) -> RepeaterSession | None:
        if not self.repeater_sessions:
            return None
        self.repeater_index = max(0, min(self.repeater_index, len(self.repeater_sessions) - 1))
        return self.repeater_sessions[self.repeater_index]

    def _render_repeater_request(self, entry: TrafficEntry) -> str:
        request = ParsedRequest(
            method=entry.request.method,
            target=self._repeater_target(entry),
            version=entry.request.version,
            headers=list(entry.request.headers),
            body=entry.request.body,
        )
        lines = [f"{request.method} {request.target} {request.version}"]
        lines.extend(f"{name}: {value}" for name, value in request.headers)
        body = request.body.decode("iso-8859-1", errors="replace")
        return "\n".join(lines) + f"\n\n{body}"

    def _repeater_target(self, entry: TrafficEntry) -> str:
        target = entry.request.target
        lowered = target.lower()
        if lowered.startswith(("http://", "https://", "ws://", "wss://")):
            return target
        scheme = "https" if entry.request.port == 443 else "http"
        host = entry.request.host or entry.summary_host
        default_port = 443 if scheme == "https" else 80
        authority = host if entry.request.port == default_port else f"{host}:{entry.request.port}"
        path = entry.request.path or entry.request.target or "/"
        return f"{scheme}://{authority}{path}"

    @staticmethod
    def _resolve_project_path(value: str) -> Path:
        path = Path(value).expanduser()
        if path.suffix:
            return path
        if path.parent == Path("."):
            return Path("projects") / f"{path.name}.hexproxy.json"
        return path.with_suffix(".hexproxy.json")

    @staticmethod
    def _status_label(entry: TrafficEntry) -> str:
        if entry.state == "intercepted":
            return "INT"
        if entry.state == "dropped":
            return "DROP"
        if entry.state == "error":
            return "ERR"
        if entry.response.status_code:
            return str(entry.response.status_code)
        return "-"

    @staticmethod
    def _format_save_time(value: datetime | None) -> str:
        if value is None:
            return "-"
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    @property
    def repeater_request_text(self) -> str:
        session = self._current_repeater_session()
        return session.request_text if session is not None else ""

    @property
    def repeater_response_text(self) -> str:
        session = self._current_repeater_session()
        return session.response_text if session is not None else ""

    @property
    def repeater_source_entry_id(self) -> int | None:
        session = self._current_repeater_session()
        return session.source_entry_id if session is not None else None
