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


@dataclass(slots=True)
class RepeaterSession:
    request_text: str
    response_text: str = ""
    source_entry_id: int | None = None
    last_error: str = ""
    last_sent_at: datetime | None = None
    request_scroll: int = 0
    response_scroll: int = 0


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
    action: str
    key: str
    description: str


class ProxyTUI:
    TABS = [
        "Overview",
        "Intercept",
        "Repeater",
        "Sitemap",
        "Match/Replace",
        "Req Headers",
        "Req Body",
        "Res Headers",
        "Res Body",
        "Settings",
        "Keybindings",
    ]
    DEFAULT_KEYBINDINGS: dict[str, str] = {
        "open_settings": "w",
        "save_project": "s",
        "load_repeater": "y",
        "edit_match_replace": "r",
        "toggle_body_view": "p",
        "toggle_intercept_mode": "i",
        "forward_send": "a",
        "drop_item": "x",
        "edit_item": "e",
        "repeater_send_alt": "g",
        "repeater_prev_session": "[",
        "repeater_next_session": "/",
    }
    KEYBINDING_DESCRIPTIONS: dict[str, str] = {
        "open_settings": "Open the Settings workspace",
        "save_project": "Save the current project",
        "load_repeater": "Load selected flow into Repeater",
        "edit_match_replace": "Edit Match/Replace rules",
        "toggle_body_view": "Toggle raw/pretty body mode",
        "toggle_intercept_mode": "Cycle interception mode",
        "forward_send": "Forward intercepted item or send Repeater request",
        "drop_item": "Drop intercepted item",
        "edit_item": "Edit intercepted item or Repeater request",
        "repeater_send_alt": "Alternate key to send Repeater request",
        "repeater_prev_session": "Go to previous Repeater session",
        "repeater_next_session": "Go to next Repeater session",
    }

    def __init__(
        self,
        store: TrafficStore,
        listen_host: str,
        listen_port: int,
        certificate_authority: CertificateAuthority,
        plugin_manager: PluginManager | None = None,
        repeater_sender: Callable[[str], str] | None = None,
        initial_keybindings: dict[str, str] | None = None,
        keybinding_saver: Callable[[dict[str, str]], object] | None = None,
    ) -> None:
        self.store = store
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.certificate_authority = certificate_authority
        self.plugin_manager = plugin_manager or PluginManager()
        self.repeater_sender = repeater_sender
        self._custom_keybindings = dict(initial_keybindings or {})
        self._keybinding_saver = keybinding_saver
        self.selected_index = 0
        self.active_tab = 0
        self.status_message = ""
        self.status_until = 0.0
        self.request_body_view_mode = "pretty"
        self.response_body_view_mode = "pretty"
        self.active_pane = "flows"
        self.detail_scroll = 0
        self.detail_page_rows = 0
        self._last_detail_entry_id: int | None = None
        self._last_detail_tab = self.active_tab
        self.repeater_sessions: list[RepeaterSession] = []
        self.repeater_index = 0
        self.sitemap_selected_index = 0
        self.sitemap_tree_scroll = 0
        self.sitemap_request_scroll = 0
        self.sitemap_response_scroll = 0
        self._last_sitemap_entry_id: int | None = None
        self.settings_selected_index = 0
        self.settings_detail_scroll = 0
        self.keybindings_selected_index = 0
        self.keybindings_detail_scroll = 0
        self.keybinding_capture_action: str | None = None
        self.keybinding_error_message = ""

    def run(self) -> None:
        curses.wrapper(self._main)

    def _settings_tab_index(self) -> int:
        return self.TABS.index("Settings")

    def _keybindings_tab_index(self) -> int:
        return self.TABS.index("Keybindings")

    def _is_settings_tab(self) -> bool:
        return self.active_tab == self._settings_tab_index()

    def _is_keybindings_tab(self) -> bool:
        return self.active_tab == self._keybindings_tab_index()

    def _main(self, stdscr) -> None:
        curses.curs_set(0)
        stdscr.keypad(True)
        stdscr.timeout(150)
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)
            curses.init_pair(2, curses.COLOR_GREEN, -1)
            curses.init_pair(3, curses.COLOR_RED, -1)
            curses.init_pair(4, curses.COLOR_YELLOW, -1)
            curses.init_pair(5, curses.COLOR_CYAN, -1)
            curses.init_pair(6, curses.COLOR_MAGENTA, -1)
            curses.init_pair(7, curses.COLOR_BLUE, -1)

        while True:
            entries = self.store.snapshot()
            pending = self.store.pending_interceptions()
            self._sync_selection(entries, pending)
            self._sync_active_pane()
            selected = entries[self.selected_index] if entries else None
            selected_pending = self._selected_pending_interception(selected.id if selected is not None else None)
            self._sync_detail_scroll(selected.id if selected is not None else None)

            self._draw(stdscr, entries, selected, pending, selected_pending)

            key = stdscr.getch()
            if self._is_keybindings_tab() and self._handle_keybinding_capture(key):
                continue
            selected_id = selected.id if selected is not None else None
            if key in (ord("q"), ord("Q")):
                return
            if self._matches_action("open_settings", key):
                self.active_tab = self._settings_tab_index()
                self.active_pane = "settings_menu"
                continue
            if key in (curses.KEY_LEFT, ord("h")):
                if self.active_tab == 2:
                    self.active_pane = "repeater_request"
                elif self.active_tab == 3:
                    self._move_sitemap_focus(-1)
                elif self._is_settings_tab():
                    self._move_settings_focus(-1)
                elif self._is_keybindings_tab():
                    self._move_keybindings_focus(-1)
                else:
                    self.active_pane = "flows"
            elif key in (curses.KEY_RIGHT, ord("l")):
                if self.active_tab == 2:
                    self.active_pane = "repeater_response"
                elif self.active_tab == 3:
                    self._move_sitemap_focus(1)
                elif self._is_settings_tab():
                    self._move_settings_focus(1)
                elif self._is_keybindings_tab():
                    self._move_keybindings_focus(1)
                else:
                    self.active_pane = "detail"
            elif key in (curses.KEY_UP, ord("k")):
                self._move_active_pane(-1, len(entries))
            elif key in (curses.KEY_DOWN, ord("j")):
                self._move_active_pane(1, len(entries))
            elif key in (9, curses.KEY_BTAB):
                self.active_tab = (self.active_tab + 1) % len(self.TABS)
            elif key in (ord(self._binding_key("repeater_prev_session")),):
                self._switch_repeater_session(-1)
            elif key in (ord(self._binding_key("repeater_next_session")), ord("]"), ord("}")):
                self._switch_repeater_session(1)
            elif key == curses.KEY_NPAGE:
                if self.active_tab == 2:
                    self._scroll_repeater_active_pane(self._repeater_page_rows(stdscr) or 1)
                elif self.active_tab == 3:
                    self._scroll_sitemap_active_pane(self._sitemap_page_rows(stdscr) or 1, entries)
                elif self._is_settings_tab():
                    self._scroll_settings_active_pane(self._settings_page_rows(stdscr) or 1)
                elif self._is_keybindings_tab():
                    self._scroll_keybindings_active_pane(self._keybindings_page_rows(stdscr) or 1)
                else:
                    self._scroll_detail(self.detail_page_rows or 1)
            elif key == curses.KEY_PPAGE:
                if self.active_tab == 2:
                    self._scroll_repeater_active_pane(-(self._repeater_page_rows(stdscr) or 1))
                elif self.active_tab == 3:
                    self._scroll_sitemap_active_pane(-(self._sitemap_page_rows(stdscr) or 1), entries)
                elif self._is_settings_tab():
                    self._scroll_settings_active_pane(-(self._settings_page_rows(stdscr) or 1))
                elif self._is_keybindings_tab():
                    self._scroll_keybindings_active_pane(-(self._keybindings_page_rows(stdscr) or 1))
                else:
                    self._scroll_detail(-(self.detail_page_rows or 1))
            elif key == curses.KEY_HOME:
                if self.active_tab == 2:
                    self._set_repeater_active_scroll(0)
                elif self.active_tab == 3:
                    self._set_sitemap_active_scroll(0)
                elif self._is_settings_tab():
                    self._set_settings_active_scroll(0)
                elif self._is_keybindings_tab():
                    self._set_keybindings_active_scroll(0)
                else:
                    self.detail_scroll = 0
            elif key == curses.KEY_END:
                if self.active_tab == 2:
                    self._set_repeater_active_scroll(10**9)
                elif self.active_tab == 3:
                    self._set_sitemap_active_scroll(10**9)
                elif self._is_settings_tab():
                    self._set_settings_active_scroll(10**9)
                elif self._is_keybindings_tab():
                    self._set_keybindings_active_scroll(10**9)
                else:
                    self.detail_scroll = 10**9
            elif self._matches_action("save_project", key):
                self._save_project(stdscr)
            elif self._matches_action("load_repeater", key):
                if self.active_tab == 3:
                    self._load_repeater_from_selected_flow(self._selected_sitemap_entry(entries))
                else:
                    self._load_repeater_from_selected_flow(selected)
            elif self._matches_action("edit_match_replace", key):
                self._edit_match_replace_rules(stdscr)
            elif self._matches_action("toggle_body_view", key):
                self._toggle_body_view_mode()
            elif self._matches_action("toggle_intercept_mode", key):
                self._toggle_intercept_mode()
            elif self._matches_action("forward_send", key):
                if self.active_tab == 2:
                    self._send_repeater_request()
                elif self._is_settings_tab():
                    self._activate_settings_item(stdscr)
                elif self._is_keybindings_tab():
                    self._activate_keybinding_item()
                else:
                    self._forward_intercepted_request(selected_pending)
            elif self._matches_action("drop_item", key):
                self._drop_intercepted_request(selected_pending)
            elif self._matches_action("edit_item", key):
                if self.active_tab == 2:
                    self._edit_repeater_request(stdscr)
                elif self._is_settings_tab():
                    self._activate_settings_item(stdscr)
                elif self._is_keybindings_tab():
                    self._activate_keybinding_item()
                else:
                    self._edit_intercepted_request(stdscr, selected_pending)
            elif self._matches_action("repeater_send_alt", key):
                self._send_repeater_request()
            elif key in (ord("c"),):
                if self._is_settings_tab():
                    self._ensure_certificate_authority()
            elif key in (ord("C"),):
                if self._is_settings_tab():
                    self._regenerate_certificate_authority()
            elif key in (curses.KEY_ENTER, 10, 13):
                if self._is_settings_tab():
                    self._activate_settings_item(stdscr)
                elif self._is_keybindings_tab():
                    self._activate_keybinding_item()
            elif key == curses.KEY_RESIZE:
                stdscr.erase()

    def _draw(
        self,
        stdscr,
        entries: list[TrafficEntry],
        selected: TrafficEntry | None,
        pending: list[PendingInterceptionView],
        selected_pending: PendingInterceptionView | None,
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
        stdscr.addnstr(0, 0, header.ljust(width - 1), width - 1, curses.A_REVERSE)

        if self.active_tab == 2:
            stdscr.addnstr(
                height - 1,
                0,
                self._footer_text(width, selected_pending).ljust(width - 1),
                width - 1,
                curses.A_REVERSE,
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
                curses.A_REVERSE,
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
                curses.A_REVERSE,
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
                curses.A_REVERSE,
            )
            self._draw_keybindings_workspace(stdscr, height, width)
            stdscr.refresh()
            return

        flows_title = "Flows [active]" if self.active_pane == "flows" else "Flows"
        detail_title = f"{self.TABS[self.active_tab]} [active]" if self.active_pane == "detail" else self.TABS[self.active_tab]
        self._draw_box(stdscr, 1, 0, height - 3, left_width, flows_title)
        self._draw_box(stdscr, 1, right_x, height - 3, right_width, detail_title)
        stdscr.addnstr(
            height - 1,
            0,
            self._footer_text(width, selected_pending).ljust(width - 1),
            width - 1,
            curses.A_REVERSE,
        )

        self._draw_flow_list(stdscr, 2, 1, height - 5, left_width - 2, entries)
        self.detail_page_rows = max(1, height - 5)
        self._draw_detail(stdscr, 2, right_x + 1, height - 5, right_width - 2, selected, pending)
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
        stdscr.addnstr(1, 0, session_bar.ljust(width - 1), width - 1, curses.A_REVERSE)

        pane_y = 2
        pane_height = height - 5
        left_width = max(30, width // 2)
        right_x = left_width + 1
        right_width = width - right_x - 1

        request_title = "Request [active]" if self.active_pane == "repeater_request" else "Request"
        response_title = "Response [active]" if self.active_pane == "repeater_response" else "Response"
        self._draw_box(stdscr, pane_y, 0, pane_height, left_width, request_title)
        self._draw_box(stdscr, pane_y, right_x, pane_height, right_width, response_title)

        request_lines = self._repeater_request_lines(session, left_width - 2)
        response_lines = self._repeater_response_lines(session, right_width - 2)
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
            self._sitemap_request_lines(selected_entry, detail_width - 2),
            "sitemap_request",
        )
        self._draw_sitemap_detail_pane(
            stdscr,
            pane_y + request_height + 2,
            detail_x + 1,
            max(1, response_height - 1),
            detail_width - 2,
            self._sitemap_response_lines(selected_entry, detail_width - 2),
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

    def _draw_settings_menu(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        items: list[SettingsItem],
    ) -> None:
        for offset in range(min(height, len(items))):
            item = items[offset]
            attr = curses.A_NORMAL
            if offset == self.settings_selected_index and curses.has_colors():
                attr = curses.color_pair(1)
            elif offset == self.settings_selected_index:
                attr = curses.A_REVERSE
            stdscr.addnstr(y + offset, x, self._trim(item.label, width).ljust(width), width, attr)

    def _draw_settings_detail(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        item: SettingsItem | None,
    ) -> None:
        lines = self._settings_detail_lines(item, width)
        start = self._window_start(self.settings_detail_scroll, len(lines), height)
        self.settings_detail_scroll = start
        visible_lines = lines[start : start + height]
        for offset, line in enumerate(visible_lines):
            safe_line = self._sanitize_display_text(line)
            stdscr.addnstr(y + offset, x, self._trim(safe_line, width).ljust(width), width)
        self._draw_detail_scroll_indicators(stdscr, y, x, height, width, start, len(visible_lines), len(lines))

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
        start = self._window_start(self.keybindings_selected_index, len(items), height)
        visible_items = items[start : start + height]
        for offset, item in enumerate(visible_items):
            absolute_index = start + offset
            line = f"{item.key:<3} {item.action}"
            attr = curses.A_NORMAL
            if absolute_index == self.keybindings_selected_index and curses.has_colors():
                attr = curses.color_pair(1)
            elif absolute_index == self.keybindings_selected_index:
                attr = curses.A_REVERSE
            stdscr.addnstr(y + offset, x, self._trim(line, width).ljust(width), width, attr)
        self._draw_detail_scroll_indicators(stdscr, y, x, height, width, start, len(visible_items), len(items))

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
        start = self._window_start(self.keybindings_detail_scroll, len(lines), height)
        self.keybindings_detail_scroll = start
        visible_lines = lines[start : start + height]
        for offset, line in enumerate(visible_lines):
            safe_line = self._sanitize_display_text(line)
            attr = curses.A_NORMAL
            if safe_line.startswith("Error:") and curses.has_colors():
                attr = curses.color_pair(3)
            elif safe_line.startswith("Waiting for key") and curses.has_colors():
                attr = curses.color_pair(4)
            stdscr.addnstr(y + offset, x, self._trim(safe_line, width).ljust(width), width, attr)
        self._draw_detail_scroll_indicators(stdscr, y, x, height, width, start, len(visible_lines), len(lines))

    def _settings_items(self) -> list[SettingsItem]:
        return [
            SettingsItem("Plugins", "plugins", "Inspect loaded plugins, plugin directories and installation guidance."),
            SettingsItem("Plugin Developer Docs", "plugin_docs", "Read the HexProxy plugin API and extension guide."),
            SettingsItem("Certificates: Generate CA", "cert_generate", "Generate the local CA if it does not exist."),
            SettingsItem("Certificates: Regenerate CA", "cert_regenerate", "Regenerate the CA and discard old leaf certs."),
            SettingsItem("Scope", "scope", "Edit the interception allowlist."),
            SettingsItem("Keybindings", "keybindings", "Open the Keybindings workspace to edit single-key shortcuts."),
        ]

    def _settings_detail_lines(self, item: SettingsItem | None, width: int) -> list[str]:
        if item is None:
            return ["No settings item selected."]
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
        for action, description in self.KEYBINDING_DESCRIPTIONS.items():
            items.append(KeybindingItem(action=action, key=bindings[action], description=description))
        return items

    def _keybinding_detail_lines(self, item: KeybindingItem | None) -> list[str]:
        if item is None:
            return ["No keybinding action selected."]
        lines = [
            item.action,
            "",
            item.description,
            "",
            f"Current key: {item.key}",
            "",
            "Each action must keep a unique single visible character.",
        ]
        if self.keybinding_capture_action == item.action:
            lines.extend(["", "Waiting for key input.", "Press the new key now. Esc cancels."])
        else:
            lines.extend(["", f"Press {self._binding_label('edit_item')} or Enter to rebind this action."])
        if self.keybinding_error_message:
            lines.extend(["", f"Error: {self.keybinding_error_message}"])
        return lines

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
        start = self._window_start(self.sitemap_tree_scroll, len(items), height)
        self.sitemap_tree_scroll = start
        visible_items = items[start : start + height]
        if not visible_items:
            stdscr.addnstr(y, x, "No traffic yet.".ljust(width), width)
            return
        for offset, item in enumerate(visible_items):
            row_y = y + offset
            prefix = "  " * item.depth
            line = f"{prefix}{item.label}"
            attr = curses.A_NORMAL
            absolute_index = start + offset
            if absolute_index == self.sitemap_selected_index and curses.has_colors():
                attr = curses.color_pair(1)
            elif absolute_index == self.sitemap_selected_index:
                attr = curses.A_REVERSE
            stdscr.addnstr(row_y, x, self._trim(line, width).ljust(width), width, attr)
        self._draw_detail_scroll_indicators(stdscr, y, x, height, width, start, len(visible_items), len(items))

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
        start = self._window_start(scroll, len(lines), height)
        if pane == "sitemap_request":
            self.sitemap_request_scroll = start
        else:
            self.sitemap_response_scroll = start
        visible_lines = lines[start : start + height]
        for offset, line in enumerate(visible_lines):
            safe_line = self._sanitize_display_text(line)
            stdscr.addnstr(y + offset, x, self._trim(safe_line, width).ljust(width), width)
        self._draw_detail_scroll_indicators(stdscr, y, x, height, width, start, len(visible_lines), len(lines))

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
        start = self._window_start(scroll, len(lines), height)
        if pane == "request":
            session.request_scroll = start
        else:
            session.response_scroll = start
        visible_lines = lines[start : start + height]
        for offset, line in enumerate(visible_lines):
            safe_line = self._sanitize_display_text(line)
            stdscr.addnstr(y + offset, x, self._trim(safe_line, width).ljust(width), width)
        self._draw_detail_scroll_indicators(stdscr, y, x, height, width, start, len(visible_lines), len(lines))

    def _repeater_request_lines(self, session: RepeaterSession, width: int) -> list[str]:
        lines = [
            f"Session: {self.repeater_index + 1}/{len(self.repeater_sessions)}",
            f"Source flow: #{session.source_entry_id}" if session.source_entry_id is not None else "Source flow: -",
            "",
        ]
        request_lines = session.request_text.splitlines() or ([session.request_text] if session.request_text else [])
        if not request_lines:
            request_lines = ["No repeater request loaded."]
        lines.extend(self._trim(line, width) for line in request_lines)
        return lines

    def _repeater_response_lines(self, session: RepeaterSession, width: int) -> list[str]:
        lines = [
            f"Last sent: {self._format_save_time(session.last_sent_at)}",
            f"Last error: {session.last_error or '-'}",
            "",
        ]
        response_lines = session.response_text.splitlines() or ([session.response_text] if session.response_text else [])
        if not response_lines:
            response_lines = ["No repeater response yet."]
        lines.extend(self._trim(line, width) for line in response_lines)
        return lines

    def _draw_flow_list(self, stdscr, y: int, x: int, height: int, width: int, entries: list[TrafficEntry]) -> None:
        header = f"{'#':<4} {'M':<6} {'S':<5} {'Host':<18} Path"
        stdscr.addnstr(y, x, header.ljust(width), width, curses.A_BOLD)

        start_index, visible_entries = self._visible_flow_entries(entries, max(0, height - 1))
        for offset, entry in enumerate(visible_entries):
            row_y = y + 1 + offset
            status = self._status_label(entry)
            host = self._trim(entry.summary_host, 18)
            path = self._trim(entry.summary_path, max(1, width - 37))
            line = f"{entry.id:<4} {entry.request.method[:6]:<6} {status:<5} {host:<18} {path}"

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
            stdscr.addnstr(row_y, x, line.ljust(width), width, attr)

        if start_index > 0:
            stdscr.addnstr(y, max(x, x + width - 3), " ^ ", min(3, width), curses.A_BOLD)
        if start_index + len(visible_entries) < len(entries):
            stdscr.addnstr(y + height - 1, max(x, x + width - 3), " v ", min(3, width), curses.A_BOLD)

    def _draw_detail(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        entry: TrafficEntry | None,
        pending: list[PendingInterceptionView],
    ) -> None:
        if self.active_tab in {6, 8}:
            self._draw_body_detail(stdscr, y, x, height, width, entry)
            return
        lines = self._build_detail_lines(entry, pending, width)
        start = self._detail_window_start(len(lines), height)
        visible_lines = lines[start : start + height]
        for offset, line in enumerate(visible_lines):
            safe_line = self._sanitize_display_text(line)
            stdscr.addnstr(y + offset, x, safe_line.ljust(width), width)
        self._draw_detail_scroll_indicators(stdscr, y, x, height, width, start, len(visible_lines), len(lines))

    def _build_detail_lines(
        self,
        entry: TrafficEntry | None,
        pending: list[PendingInterceptionView],
        width: int,
    ) -> list[str]:
        if self.active_tab == 1:
            return self._build_intercept_lines(entry, pending, width)
        if self.active_tab == 2:
            return self._build_repeater_lines(width)
        if self.active_tab == 3:
            return self._build_sitemap_overview_lines(width)
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
                return self._build_match_replace_lines(width)
            case 5:
                return self._headers_to_lines(entry.request.headers, width)
            case 6:
                return []
            case 7:
                return self._headers_to_lines(entry.response.headers, width)
            case 8:
                return []
        return []

    def _build_intercept_lines(
        self,
        entry: TrafficEntry | None,
        pending: list[PendingInterceptionView],
        width: int,
    ) -> list[str]:
        intercept_enabled = self.store.intercept_enabled()
        mode = self.store.intercept_mode()
        lines = [
            f"Intercept mode: {mode}",
            f"Pending queue: {len(pending)}",
            "",
            "Controls:",
            "i cycle mode: off -> request -> response -> both",
            "",
        ]
        if current := self._selected_pending_interception(entry.id if entry is not None else None):
            lines.insert(5, f"e edit {current.phase} | a forward | x drop")
        if entry is None:
            lines.append("No traffic selected.")
            return lines

        current = self.store.get_pending_interception(entry.id)
        if current is None:
            lines.append("Selected flow is not currently paused in the interceptor.")
            if pending:
                lines.append(f"Oldest pending flow: #{pending[0].entry_id}")
            return lines

        created = current.created_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        updated = current.updated_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines.extend(
            [
                f"Intercepted flow: #{current.entry_id}",
                f"Phase: {current.phase}",
                f"Created: {created}",
                f"Updated: {updated}",
                "",
                f"Raw {current.phase}:",
                "",
            ]
        )
        raw_lines = current.raw_text.splitlines() or [current.raw_text]
        lines.extend(self._trim(line, width) for line in raw_lines)
        return lines

    def _build_match_replace_lines(self, width: int) -> list[str]:
        rules = self.store.match_replace_rules()
        lines = [
            "Match/Replace rules",
            "",
            "Controls:",
            "r edit rules in external editor",
            "",
            "Fields: enabled, scope(request|response|both), mode(literal|regex), match, replace, description",
            "",
        ]
        if not rules:
            lines.append("No rules configured.")
            lines.append("Press r to create a JSON rules document.")
            return lines

        for index, rule in enumerate(rules, start=1):
            status = "on" if rule.enabled else "off"
            description = rule.description or "-"
            lines.extend(
                [
                    f"[{index}] {status} | {rule.scope} | {rule.mode} | {description}",
                    f"match: {self._trim(rule.match, width)}",
                    f"replace: {self._trim(rule.replace, width)}",
                    "",
                ]
            )
        return lines

    def _build_repeater_lines(self, width: int) -> list[str]:
        session = self._current_repeater_session()
        if session is None:
            return [
                "Repeater",
                "",
                "No repeater sessions loaded.",
                "Press y on a selected flow to create one.",
            ]
        lines = ["Repeater", "", *self._repeater_request_lines(session, width), "", *self._repeater_response_lines(session, width)]
        return lines

    def _build_sitemap_overview_lines(self, width: int) -> list[str]:
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
    def _headers_to_lines(headers: HeaderList, width: int) -> list[str]:
        if not headers:
            return ["No headers."]
        return [ProxyTUI._trim(f"{name}: {value}", width) for name, value in headers]

    @staticmethod
    def _body_to_lines(body: bytes, width: int) -> list[str]:
        if not body:
            return ["No body."]
        text = body.decode("utf-8", errors="replace")
        return [ProxyTUI._trim(line, width) for line in text.splitlines() or [text]]

    def _draw_body_detail(self, stdscr, y: int, x: int, height: int, width: int, entry: TrafficEntry | None) -> None:
        if entry is None:
            stdscr.addnstr(y, x, "No traffic yet.".ljust(width), width)
            return

        document, mode = self._current_body_document(entry)
        lines = self._build_body_detail_lines(document, mode)
        start = self._detail_window_start(len(lines), height)
        visible_lines = lines[start : start + height]

        row = y
        for line, style_kind in visible_lines:
            if style_kind is None:
                stdscr.addnstr(row, x, self._trim(line, width).ljust(width), width)
            else:
                safe_line = self._sanitize_display_text(line)
                self._draw_styled_line(stdscr, row, x, width, self._style_body_line(safe_line, style_kind))
            row += 1
        self._draw_detail_scroll_indicators(stdscr, y, x, height, width, start, len(visible_lines), len(lines))

    def _current_body_document(self, entry: TrafficEntry) -> tuple[BodyDocument, str]:
        if self.active_tab == 6:
            document = build_body_document(entry.request.headers, entry.request.body)
            mode = self.request_body_view_mode
        else:
            document = build_body_document(entry.response.headers, entry.response.body)
            mode = self.response_body_view_mode
        if mode == "pretty" and not document.pretty_available:
            mode = "raw"
        return document, mode

    @staticmethod
    def _body_text_for_mode(document: BodyDocument, mode: str) -> str:
        if mode == "pretty" and document.pretty_available and document.pretty_text is not None:
            return document.pretty_text
        return document.raw_text

    def _build_body_detail_lines(self, document: BodyDocument, mode: str) -> list[tuple[str, str | None]]:
        lines: list[tuple[str, str | None]] = [
            (f"Detected: {document.display_name}", None),
            (f"Media-Type: {document.media_type}", None),
            (f"Encoding: {document.encoding_summary}", None),
            (f"Mode: {mode}", None),
            ("Controls: p toggle raw/pretty | PgUp/PgDn scroll", None),
            ("", None),
        ]
        body_text = self._body_text_for_mode(document, mode)
        body_lines = body_text.splitlines() or [body_text]
        lines.extend((line, document.kind) for line in body_lines)
        return lines

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
        segments: list[tuple[str, int]] = []
        index = 0
        while index < len(line):
            character = line[index]
            if character in "{}[]:,":
                attr = curses.color_pair(6) if curses.has_colors() else curses.A_BOLD
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
                attr = curses.color_pair(2) if curses.has_colors() else curses.A_NORMAL
                segments.append((line[index:end], attr))
                index = end
                continue
            match = re.match(r"-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?", line[index:])
            if match:
                attr = curses.color_pair(5) if curses.has_colors() else curses.A_NORMAL
                segments.append((match.group(0), attr))
                index += len(match.group(0))
                continue
            keyword_match = re.match(r"\b(true|false|null)\b", line[index:])
            if keyword_match:
                attr = curses.color_pair(4) if curses.has_colors() else curses.A_BOLD
                segments.append((keyword_match.group(0), attr))
                index += len(keyword_match.group(0))
                continue
            segments.append((character, curses.A_NORMAL))
            index += 1
        return segments

    def _style_markup_line(self, line: str) -> list[tuple[str, int]]:
        segments: list[tuple[str, int]] = []
        parts = re.split(r"(<[^>]+>)", line)
        for part in parts:
            if not part:
                continue
            if part.startswith("<") and part.endswith(">"):
                tag_attr = curses.color_pair(5) if curses.has_colors() else curses.A_BOLD
                segments.append((part, tag_attr))
            else:
                segments.append((part, curses.A_NORMAL))
        return segments

    def _style_form_line(self, line: str) -> list[tuple[str, int]]:
        if " = " not in line:
            return [(line, curses.A_NORMAL)]
        key, value = line.split(" = ", 1)
        key_attr = curses.color_pair(7) if curses.has_colors() else curses.A_BOLD
        value_attr = curses.color_pair(2) if curses.has_colors() else curses.A_NORMAL
        return [(key, key_attr), (" = ", curses.A_NORMAL), (value, value_attr)]

    def _style_hexdump_line(self, line: str) -> list[tuple[str, int]]:
        match = re.match(r"^([0-9a-f]{8})(\s{2}.*?\s{2})(.*)$", line)
        if match is None:
            return [(line, curses.A_NORMAL)]
        offset_attr = curses.color_pair(4) if curses.has_colors() else curses.A_BOLD
        hex_attr = curses.color_pair(5) if curses.has_colors() else curses.A_NORMAL
        ascii_attr = curses.color_pair(2) if curses.has_colors() else curses.A_NORMAL
        return [
            (match.group(1), offset_attr),
            (match.group(2), hex_attr),
            (match.group(3), ascii_attr),
        ]

    def _style_javascript_line(self, line: str) -> list[tuple[str, int]]:
        keyword_pattern = re.compile(
            r"\b(const|let|var|function|return|if|else|for|while|switch|case|break|continue|new|class|true|false|null|undefined)\b"
        )
        string_pattern = re.compile(r"""("(?:\\.|[^"])*"|'(?:\\.|[^'])*')""")
        comment_pattern = re.compile(r"(//.*$)")
        number_pattern = re.compile(r"\b\d+(?:\.\d+)?\b")
        return self._style_with_patterns(
            line,
            [
                (comment_pattern, curses.color_pair(4) if curses.has_colors() else curses.A_DIM),
                (string_pattern, curses.color_pair(2) if curses.has_colors() else curses.A_NORMAL),
                (keyword_pattern, curses.color_pair(6) if curses.has_colors() else curses.A_BOLD),
                (number_pattern, curses.color_pair(5) if curses.has_colors() else curses.A_NORMAL),
            ],
        )

    def _style_css_line(self, line: str) -> list[tuple[str, int]]:
        property_pattern = re.compile(r"\b([a-zA-Z-]+)(\s*:)")
        selector_pattern = re.compile(r"^\s*([^{]+)(\s*\{)")
        string_pattern = re.compile(r"""("(?:\\.|[^"])*"|'(?:\\.|[^'])*')""")

        segments = self._style_with_patterns(
            line,
            [
                (string_pattern, curses.color_pair(2) if curses.has_colors() else curses.A_NORMAL),
            ],
        )
        if selector_match := selector_pattern.match(line):
            selector_attr = curses.color_pair(7) if curses.has_colors() else curses.A_BOLD
            brace_attr = curses.color_pair(6) if curses.has_colors() else curses.A_BOLD
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
            styled.append((match.group(1), curses.color_pair(7) if curses.has_colors() else curses.A_BOLD))
            styled.append((match.group(2), curses.color_pair(6) if curses.has_colors() else curses.A_BOLD))
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

    def _draw_styled_line(self, stdscr, y: int, x: int, width: int, segments: list[tuple[str, int]]) -> None:
        if width <= 0:
            return
        remaining = width
        cursor_x = x
        for text, attr in segments:
            if remaining <= 0:
                break
            if not text:
                continue
            visible = self._sanitize_display_text(text[:remaining])
            if not visible:
                continue
            stdscr.addnstr(y, cursor_x, visible, remaining, attr)
            cursor_x += len(visible)
            remaining -= len(visible)

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

        edited = self._open_external_editor(stdscr, self._render_match_replace_rules_document())
        if edited is None:
            self._set_status("Rule edit cancelled.")
            return

        try:
            rules = self._parse_match_replace_rules_document(edited)
            self.store.set_match_replace_rules(rules)
        except Exception as exc:
            self._set_status(f"Invalid match/replace rules: {exc}")
            return
        self._set_status(f"Loaded {len(rules)} match/replace rule(s).")

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

    def _toggle_intercept_mode(self) -> None:
        current_mode = self.store.intercept_mode()
        modes = ["off", "request", "response", "both"]
        next_mode = modes[(modes.index(current_mode) + 1) % len(modes)]
        self.store.set_intercept_mode(next_mode)
        self._set_status(f"Intercept mode: {next_mode}.")

    def _forward_intercepted_request(self, pending: PendingInterceptionView | None) -> None:
        if pending is None:
            self._set_status("Select a paused intercepted flow first.")
            return
        try:
            self.store.forward_pending_interception(pending.entry_id)
        except KeyError:
            self._set_status("Selected flow is not intercepted.")
            return
        self._set_status(f"Forwarded intercepted {pending.phase} for flow #{pending.entry_id}.")

    def _drop_intercepted_request(self, pending: PendingInterceptionView | None) -> None:
        if pending is None:
            self._set_status("Select a paused intercepted flow first.")
            return
        try:
            self.store.drop_pending_interception(pending.entry_id)
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

        self.store.update_pending_interception(pending.entry_id, edited)
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
            return
        self.sitemap_selected_index = max(0, min(self.sitemap_selected_index, len(items) - 1))

    def _sync_sitemap_detail_scroll(self, entry_id: int | None) -> None:
        if entry_id != self._last_sitemap_entry_id:
            self.sitemap_request_scroll = 0
            self.sitemap_response_scroll = 0
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

    def _sitemap_request_lines(self, entry: TrafficEntry | None, width: int) -> list[str]:
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
        lines.extend(self._trim(line, width) for line in request_lines)
        return lines

    def _sitemap_response_lines(self, entry: TrafficEntry | None, width: int) -> list[str]:
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
        lines.extend(self._trim(line, width) for line in response_lines)
        return lines

    def _toggle_body_view_mode(self) -> None:
        if self.active_tab == 6:
            self.request_body_view_mode = "raw" if self.request_body_view_mode == "pretty" else "pretty"
            mode = self.request_body_view_mode
        elif self.active_tab == 8:
            self.response_body_view_mode = "raw" if self.response_body_view_mode == "pretty" else "pretty"
            mode = self.response_body_view_mode
        else:
            return
        self._set_status(f"Body view mode: {mode}.")

    def _footer_text(self, width: int, selected_pending: PendingInterceptionView | None) -> str:
        if self.active_tab == 2:
            controls = (
                f" q quit | h/l pane | j/k move | tab switch | "
                f"prev:{self._binding_label('repeater_prev_session')} next:{self._binding_label('repeater_next_session')} | "
                f"{self._binding_label('load_repeater')} new repeater | "
                f"{self._binding_label('edit_item')} edit req | "
                f"{self._binding_label('forward_send')} send | "
                f"{self._binding_label('repeater_send_alt')} send "
            )
        elif self.active_tab == 3:
            controls = (
                f" q quit | h/l pane | j/k move | tab switch | "
                f"{self._binding_label('load_repeater')} to repeater | PgUp/PgDn page "
            )
        elif self.active_tab == 4:
            controls = (
                f" q quit | h/l pane | j/k move | tab switch | "
                f"{self._binding_label('toggle_intercept_mode')} intercept mode | "
                f"{self._binding_label('save_project')} save | "
                f"{self._binding_label('edit_match_replace')} edit rules "
            )
        elif self.active_tab in {6, 8}:
            controls = (
                f" q quit | h/l pane | j/k move | tab switch | "
                f"{self._binding_label('toggle_intercept_mode')} intercept mode | "
                f"{self._binding_label('save_project')} save | "
                f"{self._binding_label('toggle_body_view')} raw/pretty | PgUp/PgDn page "
            )
        elif self._is_settings_tab():
            controls = (
                f" q quit | h/l pane | j/k move | tab switch | "
                f"{self._binding_label('edit_item')} run/edit | Enter run/edit "
            )
        elif self._is_keybindings_tab():
            controls = (
                f" q quit | h/l pane | j/k move | tab switch | "
                f"{self._binding_label('edit_item')} rebind | Enter rebind | Esc cancel "
            )
        else:
            controls = (
                f" q quit | h/l pane | j/k move | tab switch | "
                f"{self._binding_label('toggle_intercept_mode')} intercept mode | "
                f"{self._binding_label('save_project')} save "
            )
            if selected_pending is not None:
                controls = (
                    f"{controls}| {self._binding_label('edit_item')} edit | "
                    f"{self._binding_label('forward_send')} send | "
                    f"{self._binding_label('drop_item')} drop "
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

    def _matches_action(self, action: str, key: int) -> bool:
        binding = self._binding_key(action)
        return key == ord(binding)

    def _sync_detail_scroll(self, entry_id: int | None) -> None:
        if entry_id != self._last_detail_entry_id or self.active_tab != self._last_detail_tab:
            self.detail_scroll = 0
            self._last_detail_entry_id = entry_id
            self._last_detail_tab = self.active_tab

    def _sync_settings_selection(self, items: list[SettingsItem]) -> None:
        if not items:
            self.settings_selected_index = 0
            self.settings_detail_scroll = 0
            return
        self.settings_selected_index = max(0, min(self.settings_selected_index, len(items) - 1))

    def _sync_keybinding_selection(self, items: list[KeybindingItem]) -> None:
        if not items:
            self.keybindings_selected_index = 0
            self.keybindings_detail_scroll = 0
            return
        self.keybindings_selected_index = max(0, min(self.keybindings_selected_index, len(items) - 1))

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

    def _scroll_settings_active_pane(self, delta: int) -> None:
        items = self._settings_items()
        if self.active_pane == "settings_detail":
            self.settings_detail_scroll = max(0, self.settings_detail_scroll + delta)
            return
        if not items:
            self.settings_selected_index = 0
            return
        previous = self.settings_selected_index
        self.settings_selected_index = max(0, min(len(items) - 1, self.settings_selected_index + delta))
        if previous != self.settings_selected_index:
            self.settings_detail_scroll = 0

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

    def _settings_page_rows(self, stdscr) -> int:
        height, _ = stdscr.getmaxyx()
        return max(1, height - 6)

    def _keybindings_page_rows(self, stdscr) -> int:
        height, _ = stdscr.getmaxyx()
        return max(1, height - 6)

    def _activate_settings_item(self, stdscr) -> None:
        items = self._settings_items()
        self._sync_settings_selection(items)
        if not items:
            return
        item = items[self.settings_selected_index]
        if item.kind == "cert_generate":
            self._ensure_certificate_authority()
            return
        if item.kind == "cert_regenerate":
            self._regenerate_certificate_authority()
            return
        if item.kind in {"plugins", "plugin_docs"}:
            self.active_pane = "settings_detail"
            self.settings_detail_scroll = 0
            self._set_status(f"Viewing {item.label}.")
            return
        if item.kind == "scope":
            self._edit_scope_hosts(stdscr)
            return
        if item.kind == "keybindings":
            self._open_keybindings_workspace()

    def _open_keybindings_workspace(self) -> None:
        self.active_tab = self._keybindings_tab_index()
        self.active_pane = "keybindings_menu"
        self.keybindings_detail_scroll = 0
        self.keybinding_capture_action = None
        self.keybinding_error_message = ""

    def _activate_keybinding_item(self) -> None:
        items = self._keybinding_items()
        self._sync_keybinding_selection(items)
        if not items:
            return
        item = items[self.keybindings_selected_index]
        self.keybinding_capture_action = item.action
        self.keybinding_error_message = ""
        self._set_status(f"Press the new key for {item.action}. Esc cancels.")

    def _handle_keybinding_capture(self, key: int) -> bool:
        action = self.keybinding_capture_action
        if action is None or key == -1:
            return False
        if key == 27:
            self.keybinding_capture_action = None
            self.keybinding_error_message = ""
            self._set_status("Keybinding change cancelled.")
            return True
        key_name = self._captured_key_name(key)
        if key_name is None:
            self.keybinding_error_message = "Only visible single-character keys can be assigned."
            self._set_status(self.keybinding_error_message)
            return True
        self.keybinding_capture_action = None
        self._apply_keybinding_update(action, key_name)
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
        if self.active_pane not in {"flows", "detail"}:
            self.active_pane = "flows"

    def _scroll_detail(self, delta: int) -> None:
        self.detail_scroll = max(0, self.detail_scroll + delta)

    def _move_active_pane(self, delta: int, entry_count: int) -> None:
        if self.active_tab == 2:
            self._scroll_repeater_active_pane(delta)
            return
        if self.active_tab == 3:
            self._scroll_sitemap_active_pane(delta, self.store.snapshot())
            return
        if self._is_settings_tab():
            self._scroll_settings_active_pane(delta)
            return
        if self._is_keybindings_tab():
            self._scroll_keybindings_active_pane(delta)
            return
        if self.active_pane == "detail":
            self._scroll_detail(delta)
            return
        if delta < 0:
            self.selected_index = max(0, self.selected_index - 1)
            return
        self.selected_index = min(max(0, entry_count - 1), self.selected_index + 1)

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
        stdscr.addnstr(height - 1, 0, prompt, width - 1, curses.A_REVERSE)
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
                for rule in self.store.match_replace_rules()
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

        normalized: dict[str, str] = {}
        seen: set[str] = set()
        for action in cls.KEYBINDING_DESCRIPTIONS:
            key = bindings.get(action, cls.DEFAULT_KEYBINDINGS[action])
            key_name = str(key)
            if len(key_name) != 1:
                raise ValueError(f"{action}: key must be a single character")
            if key_name in seen:
                raise ValueError(f"duplicate keybinding detected for {key_name!r}")
            normalized[action] = key_name
            seen.add(key_name)
        return normalized

    def _sync_selection(self, entries: list[TrafficEntry], pending: list[PendingInterceptionView]) -> None:
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
