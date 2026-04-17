from __future__ import annotations

from dataclasses import dataclass
from collections import Counter
import base64
import curses
from datetime import datetime, timezone
import html
import json
from pathlib import Path
import re
import shlex
import sys
import webbrowser
from time import monotonic
from typing import Callable

from .. import __version__
from ..bodyview import BodyDocument, build_body_document
from ..certs import CertificateAuthority
from ..clipboard import copy_text_to_clipboard
from .constants import TUIConstants
from ..extensions import (
    BUILTIN_WORKSPACE_IDS,
    PluginExporterContribution,
    PluginKeybindingContribution,
    PluginManager,
    PluginMetadataContribution,
    PluginPanelContribution,
    PluginRenderContext,
    PluginSettingFieldContribution,
    PluginWorkspaceContribution,
)
from ..models import HeaderList, MatchReplaceRule, TrafficEntry
from ..proxy import (
    ParsedRequest,
    ParsedResponse,
    parse_request_text,
    parse_response_text,
    render_response_text,
)
from ..store import PendingInterceptionView, TrafficStore, ViewFilterSettings
from ..themes import ThemeDefinition, ThemeManager
from .layout import SplitLayout
from .theme import ThemeMixin
from .navigation import NavigationMixin
from .events import EventLoopMixin
from .state import (
    ExportFormatItem,
    ExportRequestSource,
    FilterItem,
    KeybindingItem,
    MatchReplaceDraft,
    MatchReplaceFieldItem,
    RepeaterExchange,
    RepeaterSession,
    ScopeItem,
    SettingsItem,
    SitemapItem,
    ThemeBuilderFieldItem,
    ThemeDraft,
)
from .state_manager import TUIState
from ..security.analysis import SecurityFinding, SecurityScanner
from ..resources import plugin_docs_path, plugin_docs_resource
from ..resources import (
    securehex_logo_ascii_resource,
    securehex_logo_ascii_path,
    securehex_logo_braille_resource,
    securehex_logo_braille_path,
)


@dataclass(slots=True)
class ClickableRegion:
    action: str
    x: int
    y: int
    width: int
    height: int = 1
    payload: object | None = None


@dataclass(slots=True)
class FooterClickAction:
    start: int
    length: int
    action: str


class FooterBuilder:
    def __init__(self) -> None:
        self.text = ""
        self.actions: list[FooterClickAction] = []

    def append(self, value: str, action: str | None = None) -> None:
        if not value:
            return
        start = len(self.text)
        self.text += value
        if action:
            self.actions.append(FooterClickAction(start, len(value), action))


@dataclass(slots=True)
class WorkspacePanelLayout:
    workspace_key: str
    workspace_label: str
    horizontal_label: str
    horizontal_ratio_key: str
    horizontal_layout: SplitLayout
    vertical_label: str | None = None
    vertical_ratio_key: str | None = None
    vertical_layout: SplitLayout | None = None


class ProxyTUI(ThemeMixin, NavigationMixin, EventLoopMixin, TUIConstants):
    STATE_FIELDS = frozenset(TUIState.__annotations__)
    SEVERITY_PRIORITY = {"critical": 0, "warning": 1, "info": 2}
    LAYOUT_ADJUST_STEP = 0.05

    def __getattr__(self, name: str) -> object:
        if name in self.STATE_FIELDS:
            return getattr(object.__getattribute__(self, "state"), name)
        raise AttributeError(f"{type(self).__name__!r} object has no attribute {name!r}")

    def __setattr__(self, name: str, value: object) -> None:
        if name in self.STATE_FIELDS:
            object.__getattribute__(self, "state").__setattr__(name, value)
            return
        super().__setattr__(name, value)


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
        clipboard_copy: Callable[[str], str | None] | None = None,
    ) -> None:
        object.__setattr__(self, "state", TUIState())
        self.store = store
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.certificate_authority = certificate_authority
        self.plugin_manager = plugin_manager or PluginManager()
        self.theme_manager = theme_manager or ThemeManager()
        if not self.theme_manager.available_themes():
            self.theme_manager.load()
        self.repeater_sender = repeater_sender
        self._custom_keybindings = self._normalize_custom_keybindings(
            initial_keybindings or {}
        )
        self._keybinding_saver = keybinding_saver
        self._theme_saver = theme_saver
        self._clipboard_copy = clipboard_copy or copy_text_to_clipboard
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
        self.http_request_scroll = 0
        self.http_request_x_scroll = 0
        self.http_response_scroll = 0
        self.http_response_x_scroll = 0
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
        self.scope_selected_index = 0
        self.scope_menu_x_scroll = 0
        self.scope_detail_scroll = 0
        self.scope_detail_x_scroll = 0
        self.scope_error_message = ""
        self.filters_selected_index = 0
        self.filters_menu_x_scroll = 0
        self.filters_detail_scroll = 0
        self.filters_detail_x_scroll = 0
        self.filters_error_message = ""
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
        self.rule_builder_edit_index: int | None = None
        self.rule_builder_error_message = ""
        self.theme_builder_selected_index = 0
        self.theme_builder_menu_x_scroll = 0
        self.theme_builder_detail_scroll = 0
        self.theme_builder_detail_x_scroll = 0
        self.theme_builder_draft = ThemeDraft()
        self.theme_builder_error_message = ""
        self.theme_builder_restore_name: str | None = None
        self._theme_preview_override: ThemeDefinition | None = None
        self.export_selected_index = 0
        self.export_menu_x_scroll = 0
        self.export_detail_scroll = 0
        self.export_detail_x_scroll = 0
        self.export_source: ExportRequestSource | None = None
        self.plugin_workspace_selected_index: dict[str, int] = {}
        self.plugin_workspace_menu_x_scroll: dict[str, int] = {}
        self.plugin_workspace_detail_scroll: dict[str, int] = {}
        self.plugin_workspace_detail_x_scroll: dict[str, int] = {}
        self._clickable_regions: list[ClickableRegion] = []
        self._footer_click_actions: list[FooterClickAction] = []
        self._mouse_cursor_x = -1
        self._mouse_cursor_y = -1
        self._last_footer_line = ""
        self._last_mouse_click_time = 0.0
        self._last_mouse_region: tuple[str, int, int, int, int, object | None] | None = None
        self._pending_action_sequence = ""
        self.findings_scanner = SecurityScanner()
        self._last_findings: list[SecurityFinding] = []
        self._workspace_layouts: dict[str, WorkspacePanelLayout] = {
            "overview": WorkspacePanelLayout(
                workspace_key="overview",
                workspace_label="Overview workspace",
                horizontal_label="Flows pane",
                horizontal_ratio_key="overview",
                horizontal_layout=SplitLayout(min_primary=34, min_secondary=28),
            ),
            "intercept": WorkspacePanelLayout(
                workspace_key="intercept",
                workspace_label="Intercept workspace",
                horizontal_label="Pending pane",
                horizontal_ratio_key="intercept",
                horizontal_layout=SplitLayout(min_primary=34, min_secondary=28),
            ),
            "match_replace": WorkspacePanelLayout(
                workspace_key="match_replace",
                workspace_label="Match/Replace workspace",
                horizontal_label="Flows pane",
                horizontal_ratio_key="match_replace",
                horizontal_layout=SplitLayout(min_primary=34, min_secondary=28),
            ),
            "http": WorkspacePanelLayout(
                workspace_key="http",
                workspace_label="HTTP workspace",
                horizontal_label="Flows pane",
                horizontal_ratio_key="http",
                horizontal_layout=SplitLayout(min_primary=34, min_secondary=20),
                vertical_label="Request pane",
                vertical_ratio_key="http_detail",
                vertical_layout=SplitLayout(min_primary=5, min_secondary=4),
            ),
            "repeater": WorkspacePanelLayout(
                workspace_key="repeater",
                workspace_label="Repeater workspace",
                horizontal_label="History pane",
                horizontal_ratio_key="repeater",
                horizontal_layout=SplitLayout(min_primary=26, min_secondary=26),
                vertical_label="Request pane",
                vertical_ratio_key="repeater_detail",
                vertical_layout=SplitLayout(min_primary=5, min_secondary=4),
            ),
            "sitemap": WorkspacePanelLayout(
                workspace_key="sitemap",
                workspace_label="Sitemap workspace",
                horizontal_label="Tree pane",
                horizontal_ratio_key="sitemap",
                horizontal_layout=SplitLayout(min_primary=28, min_secondary=30),
                vertical_label="Request pane",
                vertical_ratio_key="sitemap_detail",
                vertical_layout=SplitLayout(min_primary=5, min_secondary=4),
            ),
            "settings": WorkspacePanelLayout(
                workspace_key="settings",
                workspace_label="Settings workspace",
                horizontal_label="Settings menu",
                horizontal_ratio_key="settings",
                horizontal_layout=SplitLayout(min_primary=28, min_secondary=32),
            ),
            "export": WorkspacePanelLayout(
                workspace_key="export",
                workspace_label="Export workspace",
                horizontal_label="Export menu",
                horizontal_ratio_key="export",
                horizontal_layout=SplitLayout(min_primary=28, min_secondary=32),
            ),
            "scope": WorkspacePanelLayout(
                workspace_key="scope",
                workspace_label="Scope workspace",
                horizontal_label="Scope menu",
                horizontal_ratio_key="scope",
                horizontal_layout=SplitLayout(min_primary=32, min_secondary=32),
            ),
            "filters": WorkspacePanelLayout(
                workspace_key="filters",
                workspace_label="Filters workspace",
                horizontal_label="Filters menu",
                horizontal_ratio_key="filters",
                horizontal_layout=SplitLayout(min_primary=32, min_secondary=32),
            ),
            "keybindings": WorkspacePanelLayout(
                workspace_key="keybindings",
                workspace_label="Keybindings workspace",
                horizontal_label="Keybindings menu",
                horizontal_ratio_key="keybindings",
                horizontal_layout=SplitLayout(min_primary=32, min_secondary=32),
            ),
            "rule_builder": WorkspacePanelLayout(
                workspace_key="rule_builder",
                workspace_label="Rule Builder workspace",
                horizontal_label="Rule builder menu",
                horizontal_ratio_key="rule_builder",
                horizontal_layout=SplitLayout(min_primary=32, min_secondary=32),
            ),
            "theme_builder": WorkspacePanelLayout(
                workspace_key="theme_builder",
                workspace_label="Theme Builder workspace",
                horizontal_label="Theme menu",
                horizontal_ratio_key="theme_builder",
                horizontal_layout=SplitLayout(min_primary=36, min_secondary=32),
            ),
            "findings": WorkspacePanelLayout(
                workspace_key="findings",
                workspace_label="Findings workspace",
                horizontal_label="Findings list",
                horizontal_ratio_key="findings",
                horizontal_layout=SplitLayout(min_primary=32, min_secondary=32),
            ),
            "plugin": WorkspacePanelLayout(
                workspace_key="plugin",
                workspace_label="Plugin workspace",
                horizontal_label="Plugin panels",
                horizontal_ratio_key="plugin",
                horizontal_layout=SplitLayout(min_primary=28, min_secondary=32),
            ),
        }

    def _is_inspect_tab(self) -> bool:
        return self._workspace_id_for_tab(self.active_tab) == "inspect"

    def _inspect_tab_index(self) -> int:
        return BUILTIN_WORKSPACE_IDS.index("inspect")

    def _inspect_target_entry(self) -> TrafficEntry | None:
        if self.inspect_source != "entry" or self.inspect_entry_id is None:
            return None
        return self.store.get(self.inspect_entry_id)

    def _inspect_message_lines(self) -> list[tuple[str, str | None]]:
        mode = self.inspect_mode if self.inspect_mode in {"request", "response"} else "request"
        if self.inspect_source == "intercept":
            header = "Intercepted Request" if mode == "request" else "Intercepted Response"
            text = self.inspect_request_text if mode == "request" else self.inspect_response_text
            view_mode = (
                self.request_body_view_mode
                if mode == "request"
                else self.response_body_view_mode
            )
            rendered = self._format_http_text_for_display(text, mode, mode=view_mode)
            content_lines = rendered.splitlines() or ([rendered] if rendered else ["No content."])
            return [
                (header, None),
                ("", None),
                *[(line, "http") for line in content_lines],
            ]
        if self.inspect_source == "repeater":
            header = "Repeater Request" if mode == "request" else "Repeater Response"
            text = self.inspect_request_text if mode == "request" else self.inspect_response_text
            view_mode = (
                self.request_body_view_mode
                if mode == "request"
                else self.response_body_view_mode
            )
            rendered = self._format_http_text_for_display(text, mode, mode=view_mode)
            content_lines = rendered.splitlines() or ([rendered] if rendered else ["No content."])
            return [
                (header, None),
                ("", None),
                *[(line, "http") for line in content_lines],
            ]

        entry = self._inspect_target_entry()
        if entry is None:
            return [("No flow selected.", None)]

        summary = f"Flow #{entry.id} | {entry.request.method} {entry.summary_host}{entry.summary_path}"
        if mode == "response":
            status_code = entry.response.status_code or "-"
            summary = f"Flow #{entry.id} | {status_code} {entry.summary_host}{entry.summary_path}"
        return [
            (summary, None),
            ("", None),
            *self._http_message_lines(entry, mode),
        ]

    def _draw_inspect_workspace(self, stdscr, height: int, width: int) -> None:
        pane_y = 1
        pane_height = height - 3
        pane_width = width
        title_mode = "Request" if self.inspect_mode == "request" else "Response"
        title = f"Inspect {title_mode} [active]" if self.active_pane == "inspect" else f"Inspect {title_mode}"
        self._draw_box(stdscr, pane_y, 0, pane_height, pane_width, title)
        self._register_clickable_region(
            "focus_pane",
            1,
            pane_y + 1,
            max(1, pane_width - 2),
            max(1, pane_height - 1),
            payload="inspect",
        )

        rows, x_scroll = self._prepare_message_visual_rows(
            self._inspect_message_lines(),
            max(1, pane_width - 2),
            self.inspect_x_scroll,
        )
        start = self._window_start(self.inspect_scroll, len(rows), max(1, pane_height - 1))
        self.inspect_scroll = start
        self.inspect_x_scroll = x_scroll
        visible_rows = rows[start : start + max(1, pane_height - 1)]
        for offset, (_, line, style_kind) in enumerate(visible_rows):
            if style_kind is None:
                self._draw_text_line(
                    stdscr,
                    pane_y + 1 + offset,
                    1,
                    max(1, pane_width - 2),
                    str(line),
                    x_scroll=x_scroll,
                )
                continue
            segments = (
                line
                if isinstance(line, list)
                else self._style_body_line(str(line), style_kind)
            )
            self._draw_styled_line(
                stdscr,
                pane_y + 1 + offset,
                1,
                max(1, pane_width - 2),
                segments,
                x_scroll=x_scroll,
            )
        self._draw_detail_scroll_indicators(
            stdscr,
            pane_y,
            0,
            pane_height,
            pane_width,
            start,
            len(visible_rows),
            len(rows),
        )
    def run(self) -> None:
        curses.wrapper(self._main)

    def _normalize_custom_keybindings(self, bindings: dict[str, str]) -> dict[str, str]:
        normalized: dict[str, str] = {}
        descriptions = self._all_keybinding_descriptions()
        for action, key in bindings.items():
            mapped_action = self.LEGACY_KEYBINDING_ACTIONS.get(action, action)
            if mapped_action not in descriptions:
                continue
            normalized[mapped_action] = key
        return normalized



    def _plugin_analyzer_lines(self, entry: TrafficEntry | None) -> list[str]:
        if entry is None:
            return []
        lines: list[str] = []
        if entry.plugin_findings:
            lines.extend(["", "Plugin Findings"])
            for plugin_id, values in sorted(entry.plugin_findings.items()):
                lines.append(f"[{plugin_id}]")
                lines.extend(f"- {value}" for value in values)
        for contribution in self.plugin_manager.analyzer_contributions():
            payload_lines = self._render_plugin_contribution_lines(
                contribution.plugin_id,
                contribution.analyze,
                title=f"Analyzer: {contribution.label}",
                entry=entry,
                workspace_id="http",
            )
            if payload_lines[-1:] == ["No content."]:
                continue
            lines.extend(["", *payload_lines])
        return lines

    @staticmethod
    def _colors_enabled() -> bool:
        try:
            return curses.has_colors()
        except curses.error:
            return False

    @staticmethod
    def _theme_color_code(name: str) -> int:
        if name.startswith("#"):
            return ProxyTUI._nearest_terminal_color(name)
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
        red, green, blue = ProxyTUI._parse_hex_color(value)
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
                stdscr.addnstr(
                    3 + offset,
                    2,
                    self._trim(line, max(1, width - 4)).ljust(max(1, width - 4)),
                    max(1, width - 4),
                )
            return

        session_bar = self._build_repeater_session_bar(width - 1)
        stdscr.addnstr(
            1, 0, session_bar.ljust(width - 1), width - 1, self._chrome_attr()
        )

        pane_y = 2
        pane_height = height - 5
        history_width, detail_width = self._split_horizontal(width, "repeater")
        detail_x = history_width + 1
        available_height = max(pane_height - 1, 0)
        request_height, response_height = self._split_vertical(
            available_height, "repeater"
        )

        history_title = (
            "History [active]" if self.active_pane == "repeater_history" else "History"
        )
        request_title = (
            "Request [active]" if self.active_pane == "repeater_request" else "Request"
        )
        response_title = (
            "Response [active]"
            if self.active_pane == "repeater_response"
            else "Response"
        )
        self._draw_box(stdscr, pane_y, 0, pane_height, history_width, history_title)
        self._draw_box(
            stdscr, pane_y, detail_x, request_height, detail_width, request_title
        )
        self._draw_box(
            stdscr,
            pane_y + request_height + 1,
            detail_x,
            response_height,
            detail_width,
            response_title,
        )

        self._register_clickable_region(
            "focus_pane",
            1,
            pane_y + 1,
            history_width - 2,
            pane_height - 1,
            payload="repeater_history",
        )
        self._register_clickable_region(
            "focus_pane",
            detail_x + 1,
            pane_y + 1,
            detail_width - 2,
            request_height - 1,
            payload="repeater_request",
        )
        self._register_clickable_region(
            "focus_pane",
            detail_x + 1,
            pane_y + request_height + 2,
            detail_width - 2,
            max(1, response_height - 1),
            payload="repeater_response",
        )

        self._draw_repeater_history(
            stdscr,
            pane_y + 1,
            1,
            pane_height - 1,
            history_width - 2,
            session,
        )
        self._draw_repeater_pane(
            stdscr,
            pane_y + 1,
            detail_x + 1,
            request_height - 1,
            detail_width - 2,
            self._repeater_request_lines(session),
            "request",
            session,
        )
        self._draw_repeater_pane(
            stdscr,
            pane_y + request_height + 2,
            detail_x + 1,
            max(1, response_height - 1),
            detail_width - 2,
            self._repeater_response_lines(session),
            "response",
            session,
        )

    def _draw_http_workspace(
        self,
        stdscr,
        height: int,
        width: int,
        entries: list[TrafficEntry],
        selected: TrafficEntry | None,
    ) -> None:
        pane_y = 1
        pane_height = height - 3
        left_width, detail_width = self._split_horizontal(width, "http")
        detail_x = left_width + 1
        available_detail_height = max(pane_height - 1, 0)
        request_height, response_height = self._split_vertical(
            available_detail_height, "http"
        )

        flows_title = "Flows [active]" if self.active_pane == "flows" else "Flows"
        request_title = (
            "Request [active]" if self.active_pane == "http_request" else "Request"
        )
        response_title = (
            "Response [active]" if self.active_pane == "http_response" else "Response"
        )
        self._draw_box(stdscr, pane_y, 0, pane_height, left_width, flows_title)
        self._draw_box(
            stdscr, pane_y, detail_x, request_height, detail_width, request_title
        )
        self._draw_box(
            stdscr,
            pane_y + request_height + 1,
            detail_x,
            response_height,
            detail_width,
            response_title,
        )

        self._register_clickable_region(
            "focus_pane",
            1,
            pane_y + 1,
            left_width - 2,
            pane_height - 1,
            payload="flows",
        )
        self._register_clickable_region(
            "focus_pane",
            detail_x + 1,
            pane_y + 1,
            detail_width - 2,
            request_height - 1,
            payload="http_request",
        )
        self._register_clickable_region(
            "focus_pane",
            detail_x + 1,
            pane_y + request_height + 2,
            detail_width - 2,
            max(1, response_height - 1),
            payload="http_response",
        )

        self._draw_flow_list(
            stdscr, pane_y + 1, 1, pane_height - 1, left_width - 2, entries
        )
        self._draw_http_message_pane(
            stdscr,
            pane_y + 1,
            detail_x + 1,
            request_height - 1,
            detail_width - 2,
            self._http_message_lines(selected, "request"),
            "request",
        )
        self._draw_http_message_pane(
            stdscr,
            pane_y + request_height + 2,
            detail_x + 1,
            max(1, response_height - 1),
            detail_width - 2,
            self._http_compact_message_lines(selected, "response"),
            "response",
        )

    def _draw_sitemap_workspace(
        self, stdscr, height: int, width: int, entries: list[TrafficEntry]
    ) -> None:
        items = self._build_sitemap_items(entries)
        self._sync_sitemap_selection(items)
        selected_entry = self._selected_sitemap_entry(entries, items)
        self._sync_sitemap_detail_scroll(
            selected_entry.id if selected_entry is not None else None
        )

        pane_y = 1
        pane_height = height - 3
        tree_width, detail_width = self._split_horizontal(width, "sitemap")
        detail_x = tree_width + 1
        available_detail_height = max(pane_height - 1, 0)
        request_height, response_height = self._split_vertical(
            available_detail_height, "sitemap"
        )

        tree_title = (
            "Sitemap [active]" if self.active_pane == "sitemap_tree" else "Sitemap"
        )
        request_title = (
            "Request [active]" if self.active_pane == "sitemap_request" else "Request"
        )
        response_title = (
            "Response [active]"
            if self.active_pane == "sitemap_response"
            else "Response"
        )
        self._draw_box(stdscr, pane_y, 0, pane_height, tree_width, tree_title)
        self._draw_box(
            stdscr, pane_y, detail_x, request_height, detail_width, request_title
        )
        self._draw_box(
            stdscr,
            pane_y + request_height + 1,
            detail_x,
            response_height,
            detail_width,
            response_title,
        )

        self._register_clickable_region(
            "focus_pane",
            1,
            pane_y + 1,
            tree_width - 2,
            pane_height - 1,
            payload="sitemap_tree",
        )
        self._register_clickable_region(
            "focus_pane",
            detail_x + 1,
            pane_y + 1,
            detail_width - 2,
            request_height - 1,
            payload="sitemap_request",
        )
        self._register_clickable_region(
            "focus_pane",
            detail_x + 1,
            pane_y + request_height + 2,
            detail_width - 2,
            max(1, response_height - 1),
            payload="sitemap_response",
        )

        self._draw_sitemap_tree(
            stdscr, pane_y + 1, 1, pane_height - 1, tree_width - 2, items
        )
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
            self._sitemap_compact_response_lines(selected_entry),
            "sitemap_response",
        )

    def _draw_settings_workspace(self, stdscr, height: int, width: int) -> None:
        items = self._settings_items()
        self._sync_settings_selection(items)
        selected_item = items[self.settings_selected_index] if items else None

        pane_y = 1
        pane_height = height - 3
        left_width, right_width = self._split_horizontal(width, "settings")
        right_x = left_width + 1

        menu_title = (
            "Settings [active]" if self.active_pane == "settings_menu" else "Settings"
        )
        detail_title = (
            f"{selected_item.label} [active]"
            if self.active_pane == "settings_detail" and selected_item
            else "Details"
        )
        self._draw_box(stdscr, pane_y, 0, pane_height, left_width, menu_title)
        self._draw_box(stdscr, pane_y, right_x, pane_height, right_width, detail_title)

        self._register_clickable_region(
            "focus_pane",
            1,
            pane_y + 1,
            left_width - 2,
            pane_height - 1,
            payload="settings_menu",
        )
        self._register_clickable_region(
            "focus_pane",
            right_x + 1,
            pane_y + 1,
            right_width - 2,
            pane_height - 1,
            payload="settings_detail",
        )

        self._draw_settings_menu(
            stdscr, pane_y + 1, 1, pane_height - 1, left_width - 2, items
        )
        self._draw_settings_detail(
            stdscr,
            pane_y + 1,
            right_x + 1,
            pane_height - 1,
            right_width - 2,
            selected_item,
        )

    def _draw_export_workspace(self, stdscr, height: int, width: int) -> None:
        items = self._export_format_items()
        self._sync_export_selection(items)
        selected_item = items[self.export_selected_index] if items else None

        pane_y = 1
        pane_height = height - 3
        left_width, right_width = self._split_horizontal(width, "export")
        right_x = left_width + 1

        menu_title = (
            "Export [active]" if self.active_pane == "export_menu" else "Export"
        )
        detail_title = (
            f"{selected_item.label} [active]"
            if self.active_pane == "export_detail" and selected_item
            else "Preview"
        )
        self._draw_box(stdscr, pane_y, 0, pane_height, left_width, menu_title)
        self._draw_box(stdscr, pane_y, right_x, pane_height, right_width, detail_title)

        self._register_clickable_region(
            "focus_pane",
            1,
            pane_y + 1,
            left_width - 2,
            pane_height - 1,
            payload="export_menu",
        )
        self._register_clickable_region(
            "focus_pane",
            right_x + 1,
            pane_y + 1,
            right_width - 2,
            pane_height - 1,
            payload="export_detail",
        )

        self._draw_export_menu(
            stdscr, pane_y + 1, 1, pane_height - 1, left_width - 2, items
        )
        self._draw_export_detail(
            stdscr,
            pane_y + 1,
            right_x + 1,
            pane_height - 1,
            right_width - 2,
            selected_item,
        )

    def _draw_scope_workspace(self, stdscr, height: int, width: int) -> None:
        items = self._scope_items()
        self._sync_scope_selection(items)
        selected_item = items[self.scope_selected_index] if items else None

        pane_y = 1
        pane_height = height - 3
        left_width, right_width = self._split_horizontal(width, "scope")
        right_x = left_width + 1

        menu_title = "Scope [active]" if self.active_pane == "scope_menu" else "Scope"
        detail_title = (
            f"{selected_item.label} [active]"
            if self.active_pane == "scope_detail" and selected_item is not None
            else "Details"
        )
        self._draw_box(stdscr, pane_y, 0, pane_height, left_width, menu_title)
        self._draw_box(stdscr, pane_y, right_x, pane_height, right_width, detail_title)

        self._register_clickable_region(
            "focus_pane",
            1,
            pane_y + 1,
            left_width - 2,
            pane_height - 1,
            payload="scope_menu",
        )
        self._register_clickable_region(
            "focus_pane",
            right_x + 1,
            pane_y + 1,
            right_width - 2,
            pane_height - 1,
            payload="scope_detail",
        )

        self._draw_scope_menu(
            stdscr, pane_y + 1, 1, pane_height - 1, left_width - 2, items
        )
        self._draw_scope_detail(
            stdscr,
            pane_y + 1,
            right_x + 1,
            pane_height - 1,
            right_width - 2,
            selected_item,
        )

    def _draw_keybindings_workspace(self, stdscr, height: int, width: int) -> None:
        items = self._keybinding_items()
        self._sync_keybinding_selection(items)
        selected_item = items[self.keybindings_selected_index] if items else None

        pane_y = 1
        pane_height = height - 3
        left_width, right_width = self._split_horizontal(width, "keybindings")
        right_x = left_width + 1

        menu_title = (
            "Keybindings [active]"
            if self.active_pane == "keybindings_menu"
            else "Keybindings"
        )
        detail_title = (
            f"{selected_item.action} [active]"
            if self.active_pane == "keybindings_detail" and selected_item is not None
            else "Details"
        )
        self._draw_box(stdscr, pane_y, 0, pane_height, left_width, menu_title)
        self._draw_box(stdscr, pane_y, right_x, pane_height, right_width, detail_title)

        self._register_clickable_region(
            "focus_pane",
            1,
            pane_y + 1,
            left_width - 2,
            pane_height - 1,
            payload="keybindings_menu",
        )
        self._register_clickable_region(
            "focus_pane",
            right_x + 1,
            pane_y + 1,
            right_width - 2,
            pane_height - 1,
            payload="keybindings_detail",
        )

        self._draw_keybindings_menu(
            stdscr, pane_y + 1, 1, pane_height - 1, left_width - 2, items
        )
        self._draw_keybindings_detail(
            stdscr,
            pane_y + 1,
            right_x + 1,
            pane_height - 1,
            right_width - 2,
            selected_item,
        )

    def _draw_filters_workspace(self, stdscr, height: int, width: int) -> None:
        items = self._filter_items()
        self._sync_filter_selection(items)
        selected_item = items[self.filters_selected_index] if items else None

        pane_y = 1
        pane_height = height - 3
        left_width, right_width = self._split_horizontal(width, "filters")
        right_x = left_width + 1

        menu_title = (
            "Filters [active]" if self.active_pane == "filters_menu" else "Filters"
        )
        detail_title = (
            f"{selected_item.label} [active]"
            if self.active_pane == "filters_detail" and selected_item is not None
            else "Details"
        )
        self._draw_box(stdscr, pane_y, 0, pane_height, left_width, menu_title)
        self._draw_box(stdscr, pane_y, right_x, pane_height, right_width, detail_title)

        self._register_clickable_region(
            "focus_pane",
            1,
            pane_y + 1,
            left_width - 2,
            pane_height - 1,
            payload="filters_menu",
        )
        self._register_clickable_region(
            "focus_pane",
            right_x + 1,
            pane_y + 1,
            right_width - 2,
            pane_height - 1,
            payload="filters_detail",
        )

        self._draw_filters_menu(
            stdscr, pane_y + 1, 1, pane_height - 1, left_width - 2, items
        )
        self._draw_filters_detail(
            stdscr,
            pane_y + 1,
            right_x + 1,
            pane_height - 1,
            right_width - 2,
            selected_item,
        )

    def _draw_rule_builder_workspace(self, stdscr, height: int, width: int) -> None:
        items = self._rule_builder_items()
        self._sync_rule_builder_selection(items)
        selected_item = items[self.rule_builder_selected_index] if items else None

        pane_y = 1
        pane_height = height - 3
        left_width, right_width = self._split_horizontal(width, "rule_builder")
        right_x = left_width + 1

        menu_title = (
            "Rule Builder [active]"
            if self.active_pane == "rule_builder_menu"
            else "Rule Builder"
        )
        detail_title = (
            f"{selected_item.label} [active]"
            if self.active_pane == "rule_builder_detail" and selected_item is not None
            else "Details"
        )
        self._draw_box(stdscr, pane_y, 0, pane_height, left_width, menu_title)
        self._draw_box(stdscr, pane_y, right_x, pane_height, right_width, detail_title)

        self._register_clickable_region(
            "focus_pane",
            1,
            pane_y + 1,
            left_width - 2,
            pane_height - 1,
            payload="rule_builder_menu",
        )
        self._register_clickable_region(
            "focus_pane",
            right_x + 1,
            pane_y + 1,
            right_width - 2,
            pane_height - 1,
            payload="rule_builder_detail",
        )

        self._draw_rule_builder_menu(
            stdscr, pane_y + 1, 1, pane_height - 1, left_width - 2, items
        )
        self._draw_rule_builder_detail(
            stdscr,
            pane_y + 1,
            right_x + 1,
            pane_height - 1,
            right_width - 2,
            selected_item,
        )

    def _draw_theme_builder_workspace(self, stdscr, height: int, width: int) -> None:
        items = self._theme_builder_items()
        self._sync_theme_builder_selection(items)
        selected_item = items[self.theme_builder_selected_index] if items else None

        pane_y = 1
        pane_height = height - 3
        left_width, right_width = self._split_horizontal(width, "theme_builder")
        right_x = left_width + 1

        menu_title = (
            "Theme Builder [active]"
            if self.active_pane == "theme_builder_menu"
            else "Theme Builder"
        )
        detail_title = (
            f"{selected_item.label} [active]"
            if self.active_pane == "theme_builder_detail" and selected_item is not None
            else "Preview"
        )
        self._draw_box(stdscr, pane_y, 0, pane_height, left_width, menu_title)
        self._draw_box(stdscr, pane_y, right_x, pane_height, right_width, detail_title)

        self._register_clickable_region(
            "focus_pane",
            1,
            pane_y + 1,
            left_width - 2,
            pane_height - 1,
            payload="theme_builder_menu",
        )
        self._register_clickable_region(
            "focus_pane",
            right_x + 1,
            pane_y + 1,
            right_width - 2,
            pane_height - 1,
            payload="theme_builder_detail",
        )

        self._draw_theme_builder_menu(
            stdscr, pane_y + 1, 1, pane_height - 1, left_width - 2, items
        )
        self._draw_theme_builder_detail(
            stdscr,
            pane_y + 1,
            right_x + 1,
            pane_height - 1,
            right_width - 2,
            selected_item,
        )

    def _current_plugin_workspace(self) -> PluginWorkspaceContribution | None:
        return self._plugin_workspace_by_id(self._workspace_id_for_tab(self.active_tab))

    def _sync_plugin_workspace_selection(
        self,
        workspace_id: str,
        panels: list[PluginPanelContribution],
    ) -> None:
        if not panels:
            self.plugin_workspace_selected_index[workspace_id] = 0
            return
        current = self.plugin_workspace_selected_index.get(workspace_id, 0)
        self.plugin_workspace_selected_index[workspace_id] = max(
            0, min(current, len(panels) - 1)
        )

    def _selected_plugin_workspace_panel(
        self,
        workspace_id: str,
        panels: list[PluginPanelContribution],
    ) -> PluginPanelContribution | None:
        if not panels:
            return None
        self._sync_plugin_workspace_selection(workspace_id, panels)
        return panels[self.plugin_workspace_selected_index.get(workspace_id, 0)]

    def _draw_plugin_workspace(
        self,
        stdscr,
        height: int,
        width: int,
        selected: TrafficEntry | None,
    ) -> None:
        workspace = self._current_plugin_workspace()
        if workspace is None:
            self._draw_box(stdscr, 1, 0, height - 3, width, "Plugin Workspace")
            self._draw_text_line(stdscr, 2, 1, width - 2, "Plugin workspace not found.")
            return
        panels = self.plugin_manager.panel_contributions(workspace.workspace_id)
        self._sync_plugin_workspace_selection(workspace.workspace_id, panels)
        selected_panel = self._selected_plugin_workspace_panel(workspace.workspace_id, panels)

        pane_y = 1
        pane_height = height - 3
        left_width, right_width = self._split_horizontal(width, "plugin")
        right_x = left_width + 1
        menu_title = (
            f"{workspace.label} [active]"
            if self.active_pane == "plugin_workspace_menu"
            else workspace.label
        )
        detail_title = (
            f"{selected_panel.title} [active]"
            if self.active_pane == "plugin_workspace_detail" and selected_panel is not None
            else "Details"
        )
        self._draw_box(stdscr, pane_y, 0, pane_height, left_width, menu_title)
        self._draw_box(stdscr, pane_y, right_x, pane_height, right_width, detail_title)

        self._register_clickable_region(
            "focus_pane",
            1,
            pane_y + 1,
            left_width - 2,
            pane_height - 1,
            payload="plugin_workspace_menu",
        )
        self._register_clickable_region(
            "focus_pane",
            right_x + 1,
            pane_y + 1,
            right_width - 2,
            pane_height - 1,
            payload="plugin_workspace_detail",
        )

        self._draw_plugin_workspace_menu(
            stdscr,
            pane_y + 1,
            1,
            pane_height - 1,
            left_width - 2,
            workspace.workspace_id,
            panels,
        )
        self._draw_plugin_workspace_detail(
            stdscr,
            pane_y + 1,
            right_x + 1,
            pane_height - 1,
            right_width - 2,
            workspace,
            selected_panel,
            selected,
        )

    def _draw_plugin_workspace_menu(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        workspace_id: str,
        panels: list[PluginPanelContribution],
    ) -> None:
        if height <= 0 or width <= 0:
            return
        if not panels:
            self._draw_text_line(stdscr, y, x, width, "No plugin panels registered.")
            return
        selected_index = self.plugin_workspace_selected_index.get(workspace_id, 0)
        lines = [panel.title for panel in panels]
        start = self._window_start(selected_index, len(lines), height)
        x_scroll = self._normalize_horizontal_scroll(
            self.plugin_workspace_menu_x_scroll.get(workspace_id, 0),
            self._max_display_width(lines),
            width,
        )
        self.plugin_workspace_menu_x_scroll[workspace_id] = x_scroll
        visible_lines = lines[start : start + height]
        for offset, line in enumerate(visible_lines):
            absolute_index = start + offset
            attr = curses.A_NORMAL
            if absolute_index == selected_index and curses.has_colors():
                attr = curses.color_pair(1)
            elif absolute_index == selected_index:
                attr = curses.A_REVERSE
            row_y = y + offset
            self._register_clickable_region(
                "plugin_workspace_menu_row",
                x,
                row_y,
                width,
                payload=absolute_index,
            )
            if self._is_mouse_over(x, row_y, width, 1):
                attr |= curses.A_REVERSE
            self._draw_text_line(stdscr, y + offset, x, width, line, x_scroll=x_scroll, attr=attr)
        self._draw_detail_scroll_indicators(
            stdscr, y, x, height, width, start, len(visible_lines), len(lines)
        )

    def _draw_plugin_workspace_detail(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        workspace: PluginWorkspaceContribution,
        panel: PluginPanelContribution | None,
        selected: TrafficEntry | None,
    ) -> None:
        if height <= 0 or width <= 0:
            return
        if panel is None:
            self._draw_text_line(stdscr, y, x, width, workspace.description or "No panels registered.")
            return
        lines = self._render_plugin_contribution_lines(
            panel.plugin_id,
            panel.render_lines,
            title=panel.title,
            entry=selected,
            workspace_id=workspace.workspace_id,
            panel_id=panel.panel_id,
        )
        rows, x_scroll = self._prepare_plain_visual_rows(
            lines,
            width,
            self.plugin_workspace_detail_x_scroll.get(workspace.workspace_id, 0),
        )
        start = self._window_start(
            self.plugin_workspace_detail_scroll.get(workspace.workspace_id, 0),
            len(rows),
            height,
        )
        self.plugin_workspace_detail_scroll[workspace.workspace_id] = start
        self.plugin_workspace_detail_x_scroll[workspace.workspace_id] = x_scroll
        visible_rows = rows[start : start + height]
        for offset, (_, line) in enumerate(visible_rows):
            self._draw_text_line(stdscr, y + offset, x, width, line, x_scroll=x_scroll)
        self._draw_detail_scroll_indicators(
            stdscr, y, x, height, width, start, len(visible_rows), len(rows)
        )

    def _draw_findings_workspace(
        self, stdscr, height: int, width: int, entries: list[TrafficEntry]
    ) -> None:
        findings = self._findings(entries)
        self._last_findings = findings
        pane_y = 1
        pane_height = height - 3
        left_width, detail_width = self._split_horizontal(width, "findings")
        detail_x = left_width + 1
        list_height = max(1, pane_height - 4)

        list_title = (
            "Findings [active]"
            if self.active_pane == "findings_list"
            else "Findings"
        )
        detail_title = (
            "Details [active]"
            if self.active_pane == "findings_detail"
            else "Details"
        )
        self._draw_box(stdscr, pane_y, 0, pane_height, left_width, list_title)
        self._draw_box(stdscr, pane_y, detail_x, pane_height, detail_width, detail_title)

        self._register_clickable_region(
            "focus_pane",
            1,
            pane_y + 1,
            left_width - 2,
            pane_height - 1,
            payload="findings_list",
        )
        self._register_clickable_region(
            "focus_pane",
            detail_x + 1,
            pane_y + 1,
            detail_width - 2,
            pane_height - 1,
            payload="findings_detail",
        )

        flagged_count = self._flagged_findings_count(findings)
        summary = (
            f"{self._findings_summary_text(findings)} | flagged {flagged_count}"
        )
        controls = f"Controls: {self._binding_label('open_export')} export | m toggle risk flag"
        self._draw_text_line(
            stdscr, pane_y + 1, 1, left_width - 2, summary, attr=curses.A_BOLD
        )
        self._draw_text_line(
            stdscr, pane_y + 2, 1, left_width - 2, controls, attr=curses.A_DIM
        )

        lines = self._findings_list_lines(findings)
        start = self._window_start(self.findings_list_scroll, len(lines), list_height)
        visible_lines = lines[start : start + list_height]
        for offset, (index, entry_id, line, severity) in enumerate(visible_lines):
            attr = curses.A_NORMAL
            if index == self.findings_selected_index:
                attr = curses.A_REVERSE
            elif severity == "critical" and curses.has_colors():
                attr = curses.color_pair(3)
            elif severity == "warning" and curses.has_colors():
                attr = curses.color_pair(4)
            elif severity == "info" and curses.has_colors():
                attr = curses.color_pair(7)
            marker = "* " if entry_id in self.findings_flagged_entries else "  "
            display = f"{marker}{line}"
            row_y = pane_y + 3 + offset
            self._register_clickable_region(
                "findings_row",
                1,
                row_y,
                left_width - 2,
                payload=index,
            )
            if self._is_mouse_over(1, row_y, left_width - 2, 1):
                attr |= curses.A_REVERSE
            self._draw_text_line(
                stdscr,
                row_y,
                1,
                left_width - 2,
                display,
                attr=attr,
            )
        detail_lines = self._findings_detail_lines(
            self._selected_findings_finding(findings)
        )
        rows, x_scroll = self._prepare_plain_visual_rows(
            detail_lines, detail_width - 2, self.findings_detail_scroll
        )
        start = self._window_start(self.findings_detail_scroll, len(rows), list_height)
        self.findings_detail_scroll = start
        visible_rows = rows[start : start + list_height]
        for offset, (_, line) in enumerate(visible_rows):
            self._draw_text_line(
                stdscr,
                pane_y + 1 + offset,
                detail_x + 1,
                detail_width - 2,
                line,
                x_scroll=x_scroll,
            )
        self._draw_detail_scroll_indicators(
            stdscr,
            pane_y,
            detail_x,
            pane_height,
            detail_width,
            start,
            len(visible_rows),
            len(rows),
        )

    def _findings_list_lines(
        self, findings: list[SecurityFinding]
    ) -> list[tuple[int, int, str, str]]:
        if not findings:
            return [(0, 0, "No findings detected.", "info")]
        rows: list[tuple[int, int, str, str]] = []
        for index, finding in enumerate(findings):
            prefix = f"[{finding.severity.upper():7}] #{finding.entry_id}"
            rows.append((index, finding.entry_id, f"{prefix} {finding.title}", finding.severity))
        return rows

    def _findings_detail_lines(self, finding: SecurityFinding | None) -> list[str]:
        if finding is None:
            return ["Select a finding to see details."]
        lines = [
            f"Severity: {finding.severity.capitalize()}",
            f"Entry ID: {finding.entry_id}",
            f"Title: {finding.title}",
            "",
            finding.description,
        ]
        if finding.library:
            version = finding.version or "unknown"
            lines.append(f"Library: {finding.library} {version}")
        if finding.header:
            lines.append(f"Header: {finding.header}")
        if finding.recommendation:
            lines.append("")
            lines.append(f"Recommendation: {finding.recommendation}")
        if finding.entry_id in self.findings_flagged_entries:
            lines.append("")
            lines.append("Flagged as critical risk.")
        lines.extend(
            [
                "",
                "Controls:",
                f"- {self._binding_label('open_export')} export selected flow",
                "- m toggle critical risk flag",
            ]
        )
        return lines

    def _selected_findings_finding(
        self, findings: list[SecurityFinding]
    ) -> SecurityFinding | None:
        if not findings:
            self.findings_selected_index = 0
            return None
        index = max(0, min(self.findings_selected_index, len(findings) - 1))
        self.findings_selected_index = index
        return findings[index]

    def _findings(self, entries: list[TrafficEntry]) -> list[SecurityFinding]:
        findings = self.findings_scanner.scan_entries(entries)
        return sorted(
            findings,
            key=lambda finding: (
                self.SEVERITY_PRIORITY.get(finding.severity, 99),
                finding.entry_id,
            ),
        )

    def _move_findings_focus(self, delta: int) -> None:
        panes = ["findings_list", "findings_detail"]
        current = self.active_pane if self.active_pane in panes else panes[0]
        index = panes.index(current)
        index = max(0, min(index + delta, len(panes) - 1))
        self.active_pane = panes[index]

    def _findings_page_rows(self, stdscr) -> int:
        height, _ = stdscr.getmaxyx()
        return max(1, height - 6)

    def _scroll_findings_active_pane(self, delta: int) -> None:
        if self.active_pane == "findings_list":
            self._set_findings_active_scroll(
                self.findings_list_scroll + delta,
                len(self._last_findings),
            )
        else:
            self.findings_detail_scroll = max(0, self.findings_detail_scroll + delta)

    def _set_findings_active_scroll(
        self, value: int, count: int | None = None
    ) -> None:
        if count is None:
            count = len(self._last_findings)
        max_scroll = max(0, count - 1)
        self.findings_list_scroll = max(0, min(value, max_scroll))
        if count <= 0:
            self.findings_selected_index = 0
            return
        self.findings_selected_index = min(
            max(0, self.findings_list_scroll),
            count - 1,
        )

    def _findings_summary_text(self, findings: list[SecurityFinding]) -> str:
        counts = Counter(finding.severity for finding in findings)
        return (
            f"Findings ({len(findings)}): "
            f"critical {counts['critical']}, warning {counts['warning']}, info {counts['info']}"
        )

    def _flagged_findings_count(self, findings: list[SecurityFinding]) -> int:
        if not findings:
            return 0
        ids = {finding.entry_id for finding in findings}
        return len(self.findings_flagged_entries & ids)

    def _toggle_findings_flag(self, finding: SecurityFinding | None) -> None:
        if finding is None:
            self._set_status("Select a finding to mark as critical risk.")
            return
        flagged = self.findings_flagged_entries
        if finding.entry_id in flagged:
            flagged.remove(finding.entry_id)
            self._set_status(f"Flow #{finding.entry_id} unmarked as critical risk.")
        else:
            flagged.add(finding.entry_id)
            self._set_status(f"Flow #{finding.entry_id} flagged as critical risk.")

    def _draw_settings_menu(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        items: list[SettingsItem],
    ) -> None:
        rows = self._settings_menu_rows(items)
        selected_row = next(
            (
                index
                for index, row in enumerate(rows)
                if row[0] == "item" and row[1] == self.settings_selected_index
            ),
            0,
        )
        start = self._window_start(selected_row, len(rows), height)
        lines = [line for _, _, line in rows]
        x_scroll = self._normalize_horizontal_scroll(
            self.settings_menu_x_scroll, self._max_display_width(lines), width
        )
        self.settings_menu_x_scroll = x_scroll
        visible_rows = rows[start : start + height]
        for offset, (row_kind, item_index, line) in enumerate(visible_rows):
            attr = curses.A_NORMAL
            if row_kind == "section" and curses.has_colors():
                attr = curses.color_pair(5) | curses.A_BOLD
            elif row_kind == "section":
                attr = curses.A_BOLD
            elif item_index == self.settings_selected_index and curses.has_colors():
                attr = curses.color_pair(1)
            elif item_index == self.settings_selected_index:
                attr = curses.A_REVERSE
            row_y = y + offset
            if row_kind == "item":
                self._register_clickable_region(
                    "settings_menu_row",
                    x,
                    row_y,
                    width,
                    payload=item_index,
                )
                if self._is_mouse_over(x, row_y, width, 1):
                    attr |= curses.A_REVERSE
            self._draw_text_line(
                stdscr, y + offset, x, width, line, x_scroll=x_scroll, attr=attr
            )
        self._draw_detail_scroll_indicators(
            stdscr, y, x, height, width, start, len(visible_rows), len(rows)
        )

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
        rows, x_scroll = self._prepare_plain_visual_rows(
            lines, width, self.settings_detail_x_scroll
        )
        start = self._window_start(self.settings_detail_scroll, len(rows), height)
        self.settings_detail_scroll = start
        self.settings_detail_x_scroll = x_scroll
        visible_rows = rows[start : start + height]
        for offset, (_, line) in enumerate(visible_rows):
            attr = curses.A_NORMAL
            url = None
            match = re.search(r"https?://\\S+", line)
            if match is not None:
                url = match.group(0).rstrip(").,")
                row_y = y + offset
                self._register_clickable_region(
                    "open_url",
                    x,
                    row_y,
                    width,
                    payload=url,
                )
                attr |= curses.A_UNDERLINE
                if self._is_mouse_over(x, row_y, width, 1):
                    attr |= curses.A_REVERSE
            self._draw_text_line(
                stdscr,
                y + offset,
                x,
                width,
                line,
                x_scroll=x_scroll,
                attr=attr,
            )
        self._draw_detail_scroll_indicators(
            stdscr, y, x, height, width, start, len(visible_rows), len(rows)
        )

    def _draw_theme_settings_detail(
        self, stdscr, y: int, x: int, height: int, width: int
    ) -> None:
        lines = self._theme_detail_lines()
        available = self._available_themes()
        theme_list_start = self._theme_list_start_index(lines)
        selected_row = theme_list_start + self.theme_selected_index if available else 0
        rows, x_scroll = self._prepare_plain_visual_rows(
            lines, width, self.settings_detail_x_scroll
        )
        target_row = next(
            (
                index
                for index, (source_index, _) in enumerate(rows)
                if source_index >= selected_row
            ),
            0,
        )
        start = self._window_start(
            max(self.settings_detail_scroll, target_row), len(rows), height
        )
        self.settings_detail_scroll = start
        self.settings_detail_x_scroll = x_scroll
        visible_rows = rows[start : start + height]
        for offset, (source_index, line) in enumerate(visible_rows):
            attr = curses.A_NORMAL
            if (
                available
                and source_index >= theme_list_start
                and source_index < theme_list_start + len(available)
            ):
                theme_index = source_index - theme_list_start
                if theme_index == self.theme_selected_index and curses.has_colors():
                    attr = curses.color_pair(1)
                elif theme_index == self.theme_selected_index:
                    attr = curses.A_REVERSE
                elif line.startswith("  ") and curses.has_colors():
                    attr = curses.color_pair(5)
            self._draw_text_line(
                stdscr, y + offset, x, width, line, x_scroll=x_scroll, attr=attr
            )
        self._draw_detail_scroll_indicators(
            stdscr, y, x, height, width, start, len(visible_rows), len(rows)
        )

    def _draw_scope_menu(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        items: list[ScopeItem],
    ) -> None:
        if height <= 0 or width <= 0:
            return
        rows = self._scope_menu_rows(items)
        selected_row = next(
            (
                index
                for index, row in enumerate(rows)
                if row[0] == "item" and row[1] == self.scope_selected_index
            ),
            0,
        )
        start = self._window_start(selected_row, len(rows), height)
        row_lines = [line for _, _, line in rows]
        x_scroll = self._normalize_horizontal_scroll(
            self.scope_menu_x_scroll,
            self._max_display_width(row_lines),
            width,
        )
        self.scope_menu_x_scroll = x_scroll
        visible_rows = rows[start : start + height]
        for offset, (row_kind, item_index, line) in enumerate(visible_rows):
            attr = curses.A_NORMAL
            if row_kind == "section" and curses.has_colors():
                attr = curses.color_pair(5) | curses.A_BOLD
            elif row_kind == "section":
                attr = curses.A_BOLD
            elif item_index == self.scope_selected_index and curses.has_colors():
                attr = curses.color_pair(1)
            elif item_index == self.scope_selected_index:
                attr = curses.A_REVERSE
            row_y = y + offset
            if row_kind == "item":
                self._register_clickable_region(
                    "scope_menu_row",
                    x,
                    row_y,
                    width,
                    payload=item_index,
                )
                if self._is_mouse_over(x, row_y, width, 1):
                    attr |= curses.A_REVERSE
            self._draw_text_line(
                stdscr, y + offset, x, width, line, x_scroll=x_scroll, attr=attr
            )
        self._draw_detail_scroll_indicators(
            stdscr, y, x, height, width, start, len(visible_rows), len(rows)
        )

    def _draw_scope_detail(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        item: ScopeItem | None,
    ) -> None:
        lines = self._scope_detail_lines(item)
        rows, x_scroll = self._prepare_plain_visual_rows(
            lines, width, self.scope_detail_x_scroll
        )
        start = self._window_start(self.scope_detail_scroll, len(rows), height)
        self.scope_detail_scroll = start
        self.scope_detail_x_scroll = x_scroll
        visible_rows = rows[start : start + height]
        for offset, (_, line) in enumerate(visible_rows):
            safe_line = self._sanitize_display_text(line)
            attr = curses.A_NORMAL
            if safe_line.startswith("Error:") and curses.has_colors():
                attr = curses.color_pair(3)
            elif safe_line.startswith("Meaning:") and curses.has_colors():
                attr = curses.color_pair(5) | curses.A_BOLD
            self._draw_text_line(
                stdscr, y + offset, x, width, line, x_scroll=x_scroll, attr=attr
            )
        self._draw_detail_scroll_indicators(
            stdscr, y, x, height, width, start, len(visible_rows), len(rows)
        )

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
            (
                index
                for index, row in enumerate(rows)
                if row[0] == "action" and row[1] == self.keybindings_selected_index
            ),
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
            row_y = y + offset
            if row_kind == "action":
                self._register_clickable_region(
                    "keybindings_menu_row",
                    x,
                    row_y,
                    width,
                    payload=item_index,
                )
                if self._is_mouse_over(x, row_y, width, 1):
                    attr |= curses.A_REVERSE
            self._draw_text_line(
                stdscr, y + offset, x, width, line, x_scroll=x_scroll, attr=attr
            )
        self._draw_detail_scroll_indicators(
            stdscr, y, x, height, width, start, len(visible_rows), len(rows)
        )

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
        rows, x_scroll = self._prepare_plain_visual_rows(
            lines, width, self.keybindings_detail_x_scroll
        )
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
            self._draw_text_line(
                stdscr, y + offset, x, width, line, x_scroll=x_scroll, attr=attr
            )
        self._draw_detail_scroll_indicators(
            stdscr, y, x, height, width, start, len(visible_rows), len(rows)
        )

    def _draw_filters_menu(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        items: list[FilterItem],
    ) -> None:
        if height <= 0 or width <= 0:
            return
        rows = self._filter_menu_rows(items)
        selected_row = next(
            (
                index
                for index, row in enumerate(rows)
                if row[0] == "item" and row[1] == self.filters_selected_index
            ),
            0,
        )
        start = self._window_start(selected_row, len(rows), height)
        row_lines = [line for _, _, line in rows]
        x_scroll = self._normalize_horizontal_scroll(
            self.filters_menu_x_scroll,
            self._max_display_width(row_lines),
            width,
        )
        self.filters_menu_x_scroll = x_scroll
        visible_rows = rows[start : start + height]
        for offset, (row_kind, item_index, line) in enumerate(visible_rows):
            attr = curses.A_NORMAL
            if row_kind == "section" and curses.has_colors():
                attr = curses.color_pair(5) | curses.A_BOLD
            elif row_kind == "section":
                attr = curses.A_BOLD
            elif item_index == self.filters_selected_index and curses.has_colors():
                attr = curses.color_pair(1)
            elif item_index == self.filters_selected_index:
                attr = curses.A_REVERSE
            row_y = y + offset
            if row_kind == "item":
                self._register_clickable_region(
                    "filters_menu_row",
                    x,
                    row_y,
                    width,
                    payload=item_index,
                )
                if self._is_mouse_over(x, row_y, width, 1):
                    attr |= curses.A_REVERSE
            self._draw_text_line(
                stdscr, y + offset, x, width, line, x_scroll=x_scroll, attr=attr
            )
        self._draw_detail_scroll_indicators(
            stdscr, y, x, height, width, start, len(visible_rows), len(rows)
        )

    def _draw_filters_detail(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        item: FilterItem | None,
    ) -> None:
        lines = self._filter_detail_lines(item)
        rows, x_scroll = self._prepare_plain_visual_rows(
            lines, width, self.filters_detail_x_scroll
        )
        start = self._window_start(self.filters_detail_scroll, len(rows), height)
        self.filters_detail_scroll = start
        self.filters_detail_x_scroll = x_scroll
        visible_rows = rows[start : start + height]
        for offset, (_, line) in enumerate(visible_rows):
            safe_line = self._sanitize_display_text(line)
            attr = curses.A_NORMAL
            if safe_line.startswith("Error:") and curses.has_colors():
                attr = curses.color_pair(3)
            elif safe_line.startswith("Meaning:") and curses.has_colors():
                attr = curses.color_pair(5) | curses.A_BOLD
            self._draw_text_line(
                stdscr, y + offset, x, width, line, x_scroll=x_scroll, attr=attr
            )
        self._draw_detail_scroll_indicators(
            stdscr, y, x, height, width, start, len(visible_rows), len(rows)
        )

    def _draw_export_menu(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        items: list[ExportFormatItem],
    ) -> None:
        if height <= 0 or width <= 0:
            return
        lines = [item.label for item in items]
        start = self._window_start(self.export_selected_index, len(items), height)
        x_scroll = self._normalize_horizontal_scroll(
            self.export_menu_x_scroll,
            self._max_display_width(lines),
            width,
        )
        self.export_menu_x_scroll = x_scroll
        visible_items = items[start : start + height]
        for offset, item in enumerate(visible_items):
            absolute_index = start + offset
            attr = curses.A_NORMAL
            if absolute_index == self.export_selected_index and curses.has_colors():
                attr = curses.color_pair(1)
            elif absolute_index == self.export_selected_index:
                attr = curses.A_REVERSE
            row_y = y + offset
            self._register_clickable_region(
                "export_menu_row",
                x,
                row_y,
                width,
                payload=absolute_index,
            )
            if self._is_mouse_over(x, row_y, width, 1):
                attr |= curses.A_REVERSE
            self._draw_text_line(
                stdscr, y + offset, x, width, item.label, x_scroll=x_scroll, attr=attr
            )
        self._draw_detail_scroll_indicators(
            stdscr, y, x, height, width, start, len(visible_items), len(items)
        )

    def _draw_export_detail(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        item: ExportFormatItem | None,
    ) -> None:
        lines = self._export_detail_content(item)
        rows, x_scroll = self._prepare_message_visual_rows(
            lines, width, self.export_detail_x_scroll
        )
        start = self._window_start(self.export_detail_scroll, len(rows), height)
        self.export_detail_scroll = start
        self.export_detail_x_scroll = x_scroll
        visible_rows = rows[start : start + height]
        for offset, (_, line, style_kind) in enumerate(visible_rows):
            if style_kind is None:
                self._draw_text_line(
                    stdscr, y + offset, x, width, str(line), x_scroll=x_scroll
                )
                continue
            segments = (
                line
                if isinstance(line, list)
                else self._style_body_line(str(line), style_kind)
            )
            self._draw_styled_line(
                stdscr, y + offset, x, width, segments, x_scroll=x_scroll
            )
        self._draw_detail_scroll_indicators(
            stdscr, y, x, height, width, start, len(visible_rows), len(rows)
        )

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
            if (
                absolute_index == self.rule_builder_selected_index
                and curses.has_colors()
            ):
                attr = curses.color_pair(1)
            elif absolute_index == self.rule_builder_selected_index:
                attr = curses.A_REVERSE
            row_y = y + offset
            self._register_clickable_region(
                "rule_builder_menu_row",
                x,
                row_y,
                width,
                payload=absolute_index,
            )
            if self._is_mouse_over(x, row_y, width, 1):
                attr |= curses.A_REVERSE
            self._draw_text_line(
                stdscr, y + offset, x, width, line, x_scroll=x_scroll, attr=attr
            )
        self._draw_detail_scroll_indicators(
            stdscr, y, x, height, width, start, len(visible_items), len(items)
        )

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
        rows, x_scroll = self._prepare_plain_visual_rows(
            lines, width, self.rule_builder_detail_x_scroll
        )
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
            self._draw_text_line(
                stdscr, y + offset, x, width, line, x_scroll=x_scroll, attr=attr
            )
        self._draw_detail_scroll_indicators(
            stdscr, y, x, height, width, start, len(visible_rows), len(rows)
        )

    def _draw_theme_builder_menu(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        items: list[ThemeBuilderFieldItem],
    ) -> None:
        if height <= 0 or width <= 0:
            return
        rows = self._theme_builder_menu_rows(items)
        selected_row = next(
            (
                index
                for index, row in enumerate(rows)
                if row[0] == "item" and row[1] == self.theme_builder_selected_index
            ),
            0,
        )
        start = self._window_start(selected_row, len(rows), height)
        row_lines = [line for _, _, line in rows]
        x_scroll = self._normalize_horizontal_scroll(
            self.theme_builder_menu_x_scroll,
            self._max_display_width(row_lines),
            width,
        )
        self.theme_builder_menu_x_scroll = x_scroll
        visible_rows = rows[start : start + height]
        for offset, (row_kind, item_index, line) in enumerate(visible_rows):
            attr = curses.A_NORMAL
            if row_kind == "section" and curses.has_colors():
                attr = curses.color_pair(5) | curses.A_BOLD
            elif row_kind == "section":
                attr = curses.A_BOLD
            elif item_index == self.theme_builder_selected_index and curses.has_colors():
                attr = curses.color_pair(1)
            elif item_index == self.theme_builder_selected_index:
                attr = curses.A_REVERSE
            row_y = y + offset
            if row_kind == "item":
                self._register_clickable_region(
                    "theme_builder_menu_row",
                    x,
                    row_y,
                    width,
                    payload=item_index,
                )
                if self._is_mouse_over(x, row_y, width, 1):
                    attr |= curses.A_REVERSE
            self._draw_text_line(
                stdscr, y + offset, x, width, line, x_scroll=x_scroll, attr=attr
            )
        self._draw_detail_scroll_indicators(
            stdscr, y, x, height, width, start, len(visible_rows), len(rows)
        )

    def _draw_theme_builder_detail(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        item: ThemeBuilderFieldItem | None,
    ) -> None:
        rows = self._theme_builder_detail_rows(item)
        plain_lines = [line for _, line in rows]
        prepared, x_scroll = self._prepare_plain_visual_rows(
            plain_lines, width, self.theme_builder_detail_x_scroll
        )
        start = self._window_start(self.theme_builder_detail_scroll, len(prepared), height)
        self.theme_builder_detail_scroll = start
        self.theme_builder_detail_x_scroll = x_scroll
        visible_rows = prepared[start : start + height]
        for offset, (source_index, line) in enumerate(visible_rows):
            role = rows[source_index][0] if 0 <= source_index < len(rows) else None
            attr = self._theme_role_attr(role)
            safe_line = self._sanitize_display_text(line)
            if safe_line.startswith("Error:") and curses.has_colors():
                attr = curses.color_pair(3)
            elif safe_line.startswith("Current value:") and curses.has_colors():
                attr = curses.color_pair(5) | curses.A_BOLD
            self._draw_text_line(
                stdscr, y + offset, x, width, line, x_scroll=x_scroll, attr=attr
            )
        self._draw_detail_scroll_indicators(
            stdscr, y, x, height, width, start, len(visible_rows), len(prepared)
        )

    def _settings_items(self) -> list[SettingsItem]:
        items = [
            SettingsItem(
                "Appearance",
                "Themes",
                "themes",
                "Choose the active color theme and inspect custom theme files.",
            ),
            SettingsItem(
                "Appearance",
                "Theme Builder",
                "theme_builder",
                "Create a custom theme inside the TUI with live preview and JSON export.",
            ),
            SettingsItem(
                "Extensions",
                "Plugins",
                "plugins",
                "Inspect loaded plugins, plugin directories and installation guidance.",
            ),
            SettingsItem(
                "Extensions",
                "Plugin Developer Docs",
                "plugin_docs",
                "Read the HexProxy plugin API and extension guide.",
            ),
            SettingsItem(
                "TLS",
                "Certificates: Generate CA",
                "cert_generate",
                "Generate the local CA if it does not exist.",
            ),
            SettingsItem(
                "TLS",
                "Certificates: Regenerate CA",
                "cert_regenerate",
                "Regenerate the CA and discard old leaf certs.",
            ),
            SettingsItem(
                "Traffic",
                "Scope",
                "scope",
                "Open the Scope workspace to manage in-scope and out-of-scope patterns.",
            ),
            SettingsItem(
                "Traffic",
                "Filters",
                "filters",
                "Configure which traffic is shown in Flows and Sitemap.",
            ),
            SettingsItem(
                "Controls",
                "Keybindings",
                "keybindings",
                "Open the Keybindings workspace to edit configurable shortcuts.",
            ),
            SettingsItem(
                "About",
                "About HexProxy",
                "about",
                "Show license, maintainer, and running version information.",
            ),
        ]
        for field in self.plugin_manager.setting_field_contributions():
            items.append(
                SettingsItem(
                    f"Plugin Settings / {field.section}",
                    f"[{field.plugin_id}] {field.label}",
                    "plugin_setting",
                    field.description,
                    plugin_id=field.plugin_id,
                    field_id=field.field_id,
                )
            )
        return items

    def _settings_detail_lines(self, item: SettingsItem | None) -> list[str]:
        if item is None:
            return ["No settings item selected."]
        if item.kind == "themes":
            return self._theme_detail_lines()
        if item.kind == "about":
            logo_lines = self._securehex_logo_lines(width=48, height=12)
            return [
                *logo_lines,
                "",
                "HexProxy",
                "",
                f"Version: {__version__}",
                "License: MIT",
                "Developed by: Secure Hex",
                "",
                "Links:",
                "- https://github.com/Secure-Hex/HexProxy",
                "- https://hexproxy.securehex.cl",
                "- https://securehex.cl",
                "- https://pypi.org/project/hexproxy/",
                "",
                "Notes:",
                "- The version is resolved from installed package metadata when available.",
                f"- Logo source: {self._securehex_logo_source_path()}",
            ]
        if item.kind == "theme_builder":
            return [
                item.label,
                "",
                f"Section: {item.section}",
                "",
                item.description,
                "",
                "What it does:",
                "- creates a theme JSON file inside the configured themes directory",
                "- applies each color change immediately so you can preview it live",
                "- shows sample UI elements using the current draft colors",
                "",
                f"Theme directory: {self.theme_manager.theme_dir()}",
                "",
                f"Press {self._binding_label('edit_item')} or Enter to open the Theme Builder workspace.",
            ]
        if item.kind == "plugins":
            return self._plugin_settings_lines()
        if item.kind == "plugin_docs":
            return self._plugin_docs_lines()
        if item.kind == "plugin_setting":
            field = self._plugin_setting_field(item.plugin_id, item.field_id)
            if field is None:
                return [
                    item.label,
                    "",
                    "This plugin field is no longer available.",
                ]
            value_text = self._plugin_setting_value_text(field)
            lines = [
                item.label,
                "",
                f"Section: {item.section}",
                f"Plugin: {field.plugin_id}",
                f"Field ID: {field.field_id}",
                f"Scope: {field.scope}",
                f"Type: {field.kind}",
                f"Current value: {value_text}",
                "",
                item.description,
            ]
            if field.kind == "choice" and field.options:
                lines.extend(["", "Available options:"])
                lines.extend(f"- {option}" for option in field.options)
            if field.kind == "text" and field.placeholder:
                lines.extend(["", f"Placeholder: {field.placeholder}"])
            lines.extend(
                [
                    "",
                    f"Press {self._binding_label('edit_item')} or Enter to change this field.",
                ]
            )
            return lines
        if item.kind == "cert_generate":
            return [
                item.label,
                "",
                f"Section: {item.section}",
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
                f"Section: {item.section}",
                "",
                item.description,
                "",
                f"CA path: {self.certificate_authority.cert_path()}",
                "",
                f"Press {self._binding_label('edit_item')} or Enter to regenerate the CA.",
            ]
        if item.kind == "scope":
            scope_hosts = self.store.scope_hosts()
            included = [host for host in scope_hosts if not host.startswith("!")]
            excluded = [host[1:] for host in scope_hosts if host.startswith("!")]
            lines = [
                item.label,
                "",
                f"Section: {item.section}",
                "",
                item.description,
                "",
                "In-scope patterns:",
            ]
            if included:
                lines.extend(included)
            else:
                lines.append("All hosts are currently in scope.")
            lines.extend(["", "Out-of-scope patterns:"])
            if excluded:
                lines.extend(excluded)
            else:
                lines.append("No explicit exclusions configured.")
            lines.extend(
                [
                    "",
                    f"Press {self._binding_label('edit_item')} or Enter to open the Scope workspace.",
                ]
            )
            return lines
        if item.kind == "filters":
            return self._filter_settings_lines()
        bindings = self._render_keybindings_lines()
        return [
            item.label,
            "",
            f"Section: {item.section}",
            "",
            item.description,
            "",
            *bindings,
            "",
            f"Press {self._binding_label('edit_item')} or Enter to open the Keybindings workspace.",
        ]

    def _filter_settings_lines(self) -> list[str]:
        filters = self.store.view_filters()
        methods = ", ".join(filters.methods) if filters.methods else "all methods"
        hidden_methods = (
            ", ".join(filters.hidden_methods) if filters.hidden_methods else "none"
        )
        hidden_extensions = (
            ", ".join(filters.hidden_extensions)
            if filters.hidden_extensions
            else "none"
        )
        scope_hosts = self.store.scope_hosts()
        scope_state = (
            "all traffic visible"
            if filters.show_out_of_scope
            else "only in-scope traffic"
        )
        if not scope_hosts:
            scope_state = "scope is empty, so all traffic is visible"
        return [
            "Filters",
            "",
            "These filters apply to both Flows and Sitemap.",
            "Open the dedicated Filters workspace to toggle them without leaving the TUI.",
            "",
            f"Scope visibility: {scope_state}",
            f"Query filter: {filters.query_mode}",
            f"Failure filter: {filters.failure_mode}",
            f"Body filter: {filters.body_mode}",
            f"Visible methods allowlist: {methods}",
            f"Hidden methods denylist: {hidden_methods}",
            f"Hidden file types: {hidden_extensions}",
            "",
            "Supported values:",
            "- query_mode: all, with_query, without_query",
            "- failure_mode: all, failures, hide_failures, client_errors, server_errors, connection_errors",
            "- body_mode: all, with_body, without_body",
            "- methods: optional allowlist such as GET, POST, PUT",
            "- hidden_methods: optional denylist to hide specific methods without building an allowlist",
            "- hidden_extensions: any number of file types such as jpg, png, js",
            "",
            f"Press {self._binding_label('edit_item')} or Enter to open the Filters workspace.",
        ]

    @staticmethod
    def _securehex_logo_fallback() -> list[str]:
        return [
            "SECURE HEX",
            "──────────",
        ]

    @staticmethod
    def _supports_braille() -> bool:
        encoding = sys.stdout.encoding or "utf-8"
        try:
            "⣿".encode(encoding)
        except Exception:
            return False
        return True

    def _securehex_logo_source_path(self) -> str:
        return securehex_logo_braille_path() if self._supports_braille() else securehex_logo_ascii_path()

    def _securehex_logo_lines(self, *, width: int, height: int) -> list[str]:
        if self._supports_braille():
            resource = securehex_logo_braille_resource()
            if resource is not None:
                return self._read_logo_text(resource, width=width, height=height)

        resource = securehex_logo_ascii_resource()
        if resource is None:
            return self._securehex_logo_fallback()
        try:
            return self._read_logo_text(resource, width=width, height=height)
        except Exception:
            return self._securehex_logo_fallback()

    def _read_logo_text(self, resource, *, width: int, height: int) -> list[str]:
        lines = resource.read_text(encoding="utf-8").splitlines()
        lines = [line.rstrip("\n\r") for line in lines]
        if not any(line.strip() for line in lines):
            return self._securehex_logo_fallback()
        trimmed = [self._trim(line.rstrip(), max(1, width)) for line in lines]
        trimmed = trimmed[: max(1, height)]
        if not trimmed:
            return self._securehex_logo_fallback()
        return trimmed

    def _theme_detail_lines(self) -> list[str]:
        current = self._current_theme()
        selected = self._selected_theme()
        themes = self._available_themes()
        lines = [
            "Themes",
            "",
            "Section: Appearance",
            "",
            f"Current theme: {current.name}",
            f"Selected theme: {selected.name if selected is not None else '-'}",
            f"Theme directory: {self.theme_manager.theme_dir()}",
            "",
            "Add custom themes by dropping one JSON file per theme into that directory.",
            "Use Theme Builder in Appearance to create and preview a custom theme inside the app.",
            "Move with j/k while this panel is active to preview and apply a theme immediately.",
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
        lines.extend(
            [
                "",
                "Theme JSON structure:",
                "{",
                '  "name": "sunset",',
                '  "description": "Warm custom palette",',
                '  "extends": "default",',
                '  "colors": {',
                '    "chrome": { "fg": "#1d3557", "bg": "#f1c40f" },',
                '    "accent": { "fg": "red", "bg": "default" }',
                "  }",
                "}",
                "",
                "Supported top-level keys:",
                "- name: required unique theme name",
                "- description: optional human-readable summary",
                "- extends: optional base theme, defaults to default",
                "- colors: object keyed by role name",
                "",
                "Supported roles:",
                "- chrome, selection, success, error, warning, accent, keyword, info",
                "",
                "Supported color values:",
                "- named colors: default, black, red, green, yellow, blue, magenta, cyan, white",
                "- hex colors: #RGB or #RRGGBB",
                "",
                "Hex color notes:",
                "- Hex colors are accepted in theme JSON files.",
                "- The terminal view maps them to the nearest supported terminal color at runtime.",
                "- This keeps themes portable even on basic curses terminals.",
            ]
        )
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
            f"Plugin workspaces: {len(self.plugin_manager.workspace_contributions())}",
            f"Plugin panels: {len(self.plugin_manager.panel_contributions())}",
            f"Plugin exporters: {len(self.plugin_manager.exporter_contributions())}",
            f"Plugin keybindings: {len(self.plugin_manager.keybinding_contributions())}",
            f"Plugin analyzers: {len(self.plugin_manager.analyzer_contributions())}",
            f"Plugin metadata providers: {len(self.plugin_manager.metadata_contributions())}",
            f"Plugin settings fields: {len(self.plugin_manager.setting_field_contributions())}",
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
                "API v2 highlights:",
                "- register(api) and contribute(api)",
                "- plugin workspaces and panels",
                "- exporters, keybindings, analyzers and metadata",
                "- plugin-defined Settings fields with global or project scope",
                "",
                "Developer references:",
                f"- Example plugin: {Path('examples/add_header_plugin.py')}",
                f"- Local guide: {plugin_docs_path()}",
            ]
        )
        return lines

    def _plugin_docs_lines(self) -> list[str]:
        resource = plugin_docs_resource()
        display_path = plugin_docs_path()
        if resource is None:
            return [
                "Plugin Developer Docs",
                "",
                f"Documentation resource not found: {display_path}",
                "",
                "Expected topics:",
                "- plugin loading model",
                "- register()/PLUGIN entrypoints",
                "- HookContext",
                "- ParsedRequest and ParsedResponse",
                "- hook lifecycle and examples",
            ]
        return resource.read_text(encoding="utf-8").splitlines()

    def _plugin_setting_field(
        self, plugin_id: str, field_id: str
    ) -> PluginSettingFieldContribution | None:
        for field in self.plugin_manager.setting_field_contributions():
            if field.plugin_id == plugin_id and field.field_id == field_id:
                return field
        return None

    def _plugin_setting_value(self, field: PluginSettingFieldContribution) -> object:
        if field.scope == "project":
            return self.store.plugin_value(field.plugin_id, field.field_id, field.default)
        state = self.plugin_manager.global_value(field.plugin_id, field.field_id, field.default)
        return field.default if state is None else state

    def _set_plugin_setting_value(
        self,
        field: PluginSettingFieldContribution,
        value: object,
    ) -> None:
        if field.scope == "project":
            self.store.set_plugin_value(field.plugin_id, field.field_id, value)
        else:
            self.plugin_manager.set_global_value(field.plugin_id, field.field_id, value)

    def _plugin_setting_value_text(self, field: PluginSettingFieldContribution) -> str:
        value = self._plugin_setting_value(field)
        if field.kind == "toggle":
            return "on" if bool(value) else "off"
        if field.kind == "choice":
            return str(value if value is not None else field.default or "")
        if field.kind == "action":
            return field.action_label
        text = str(value if value is not None else field.default or "")
        return text or "-"

    def _keybinding_items(self) -> list[KeybindingItem]:
        bindings = self._current_keybindings()
        descriptions = self._all_keybinding_descriptions()
        items: list[KeybindingItem] = []
        for section, actions in self._all_keybinding_sections():
            for action in actions:
                items.append(
                    KeybindingItem(
                        section=section,
                        action=action,
                        key=bindings[action],
                        description=descriptions[action],
                    )
                )
        return items

    def _filter_items(self) -> list[FilterItem]:
        items: list[FilterItem] = [
            FilterItem(
                section="Scope Visibility",
                label="Show traffic outside scope",
                kind="show_out_of_scope",
                description="Toggle whether Flows and Sitemap keep showing entries that do not match the current scope.",
            ),
            FilterItem(
                section="Request Shape",
                label="Query parameters",
                kind="query_mode",
                description="Limit the view to requests with query parameters, without them, or both.",
            ),
            FilterItem(
                section="Request Shape",
                label="Body presence",
                kind="body_mode",
                description="Limit the view to HTTP messages that have a body, do not have one, or both.",
            ),
            FilterItem(
                section="Failures",
                label="Failure mode",
                kind="failure_mode",
                description="Show all traffic, only failures, hide failures, only 4xx, only 5xx, or only connection errors.",
            ),
        ]
        for method in (
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "HEAD",
            "OPTIONS",
            "TRACE",
            "CONNECT",
        ):
            items.append(
                FilterItem(
                    section="HTTP Methods",
                    label=method,
                    kind=f"method:{method}",
                    description=f"Toggle whether {method} requests are included in the optional HTTP method allowlist.",
                )
            )
        for method in (
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "HEAD",
            "OPTIONS",
            "TRACE",
            "CONNECT",
        ):
            items.append(
                FilterItem(
                    section="Hidden HTTP Methods",
                    label=method,
                    kind=f"exclude_method:{method}",
                    description=f"Toggle whether {method} requests are hidden even when the request would otherwise be visible.",
                )
            )
        items.extend(
            [
                FilterItem(
                    section="HTTP Methods",
                    label="Clear method allowlist",
                    kind="clear_methods",
                    description="Remove the HTTP method allowlist so all methods become visible again.",
                ),
                FilterItem(
                    section="Hidden HTTP Methods",
                    label="Clear hidden methods",
                    kind="clear_hidden_methods",
                    description="Remove the hidden-method denylist so no methods are suppressed.",
                ),
                FilterItem(
                    section="File Types",
                    label="Edit hidden file types",
                    kind="edit_hidden_extensions",
                    description="Type a comma-separated list of file extensions to hide, such as jpg, png or js.",
                ),
                FilterItem(
                    section="File Types",
                    label="Clear hidden file types",
                    kind="clear_hidden_extensions",
                    description="Remove every hidden file type so static assets are shown again.",
                ),
                FilterItem(
                    section="Actions",
                    label="Reset all filters",
                    kind="reset_filters",
                    description="Restore the default view filters for Flows and Sitemap.",
                ),
            ]
        )
        return items

    def _scope_items(self) -> list[ScopeItem]:
        scope_hosts = self.store.scope_hosts()
        included = [host for host in scope_hosts if not host.startswith("!")]
        excluded = [host[1:] for host in scope_hosts if host.startswith("!")]
        items: list[ScopeItem] = [
            ScopeItem(
                section="In-Scope Patterns",
                label="Add in-scope pattern",
                kind="add_include",
                description="Add a host or wildcard pattern that should be considered in scope.",
            )
        ]
        items.extend(
            ScopeItem(
                section="In-Scope Patterns",
                label=pattern,
                kind="include_pattern",
                description="This pattern is currently treated as in scope.",
                value=pattern,
            )
            for pattern in included
        )
        items.append(
            ScopeItem(
                section="Out-of-Scope Patterns",
                label="Add out-of-scope pattern",
                kind="add_exclude",
                description="Add a host or wildcard pattern that should be excluded even if another rule includes it.",
            )
        )
        items.extend(
            ScopeItem(
                section="Out-of-Scope Patterns",
                label=pattern,
                kind="exclude_pattern",
                description="This pattern is currently excluded from scope.",
                value=pattern,
            )
            for pattern in excluded
        )
        items.append(
            ScopeItem(
                section="Actions",
                label="Clear scope",
                kind="clear_scope",
                description="Remove every in-scope and out-of-scope pattern and return to intercepting all hosts.",
            )
        )
        return items

    def _keybinding_menu_rows(
        self, items: list[KeybindingItem]
    ) -> list[tuple[str, int | None, str]]:
        rows: list[tuple[str, int | None, str]] = []
        current_section: str | None = None
        for index, item in enumerate(items):
            if item.section != current_section:
                current_section = item.section
                rows.append(("section", None, f"[{current_section}]"))
            rows.append(("action", index, f"{item.key:<3} {item.action}"))
        return rows

    def _filter_menu_rows(
        self, items: list[FilterItem]
    ) -> list[tuple[str, int | None, str]]:
        rows: list[tuple[str, int | None, str]] = []
        current_section: str | None = None
        for index, item in enumerate(items):
            if item.section != current_section:
                current_section = item.section
                rows.append(("section", None, f"[{current_section}]"))
            rows.append(("item", index, self._filter_menu_label(item)))
        return rows

    def _scope_menu_rows(
        self, items: list[ScopeItem]
    ) -> list[tuple[str, int | None, str]]:
        rows: list[tuple[str, int | None, str]] = []
        current_section: str | None = None
        for index, item in enumerate(items):
            if item.section != current_section:
                current_section = item.section
                rows.append(("section", None, f"[{current_section}]"))
            rows.append(("item", index, self._scope_menu_label(item)))
        return rows

    def _settings_menu_rows(
        self, items: list[SettingsItem]
    ) -> list[tuple[str, int | None, str]]:
        rows: list[tuple[str, int | None, str]] = []
        current_section: str | None = None
        for index, item in enumerate(items):
            if item.section != current_section:
                current_section = item.section
                rows.append(("section", None, f"[{current_section}]"))
            rows.append(("item", index, item.label))
        return rows

    def _rule_builder_items(self) -> list[MatchReplaceFieldItem]:
        return [
            MatchReplaceFieldItem("Enabled", "enabled", "Enable or disable the rule."),
            MatchReplaceFieldItem(
                "Scope",
                "scope",
                "Choose whether the rule applies to request, response or both.",
            ),
            MatchReplaceFieldItem("Mode", "mode", "Choose literal or regex matching."),
            MatchReplaceFieldItem(
                "Description",
                "description",
                "Optional human-readable label for the rule.",
            ),
            MatchReplaceFieldItem(
                "Match", "match", "The text or regex pattern to search for."
            ),
            MatchReplaceFieldItem(
                "Replace", "replace", "The replacement text to apply."
            ),
            MatchReplaceFieldItem(
                "Create Rule",
                "create",
                "Validate the form and append the rule to Match/Replace.",
            ),
            MatchReplaceFieldItem(
                "Cancel", "cancel", "Discard the draft and return to Match/Replace."
            ),
        ]

    def _theme_builder_items(self) -> list[ThemeBuilderFieldItem]:
        items = [
            ThemeBuilderFieldItem(
                "Theme",
                "Name",
                "name",
                "Unique theme name used for the saved JSON file and theme selector.",
            ),
            ThemeBuilderFieldItem(
                "Theme",
                "Description",
                "description",
                "Short human-readable summary shown in the theme list.",
            ),
            ThemeBuilderFieldItem(
                "Theme",
                "Base theme",
                "extends",
                "Built-in or custom theme to use as a starting point.",
            ),
        ]
        for role in self.THEME_PAIR_IDS:
            items.extend(
                [
                    ThemeBuilderFieldItem(
                        "Colors",
                        f"{role} fg",
                        f"{role}:fg",
                        f"Foreground color for the {role} role. Named or hex colors are accepted.",
                    ),
                    ThemeBuilderFieldItem(
                        "Colors",
                        f"{role} bg",
                        f"{role}:bg",
                        f"Background color for the {role} role. Named or hex colors are accepted.",
                    ),
                ]
            )
        items.extend(
            [
                ThemeBuilderFieldItem(
                    "Actions",
                    "Save theme",
                    "save",
                    "Write the theme JSON file and keep it selected as the active theme.",
                ),
                ThemeBuilderFieldItem(
                    "Actions",
                    "Cancel",
                    "cancel",
                    "Discard the current draft and restore the theme that was active before opening the builder.",
                ),
            ]
        )
        return items

    def _export_format_items(self) -> list[ExportFormatItem]:
        items = [
            ExportFormatItem(
                "HTTP request + response",
                "http_pair",
                "Generate a clean raw HTTP request/response transcript for evidence.",
            ),
            ExportFormatItem(
                "Python requests",
                "python_requests",
                "Generate a Python snippet using the requests library.",
            ),
            ExportFormatItem(
                "curl (bash)",
                "curl_bash",
                "Generate a bash-friendly curl command with shell-safe quoting.",
            ),
            ExportFormatItem(
                "curl (windows)",
                "curl_windows",
                "Generate a PowerShell-friendly curl.exe command for Windows.",
            ),
            ExportFormatItem(
                "Node.js fetch",
                "node_fetch",
                "Generate a Node.js snippet using the built-in fetch API.",
            ),
            ExportFormatItem(
                "Go net/http",
                "go_http",
                "Generate a Go snippet using net/http from the standard library.",
            ),
            ExportFormatItem(
                "PHP cURL",
                "php_curl",
                "Generate a PHP snippet using cURL functions.",
            ),
            ExportFormatItem(
                "Rust reqwest",
                "rust_reqwest",
                "Generate a Rust snippet using reqwest blocking client.",
            ),
        ]
        for contribution in self.plugin_manager.exporter_contributions():
            items.append(
                ExportFormatItem(
                    contribution.label,
                    f"plugin:{contribution.exporter_id}",
                    contribution.description,
                    style_kind=contribution.style_kind,
                )
            )
        if self.export_source and self.export_source.finding is not None:
            items.extend(
                [
                    ExportFormatItem(
                        "Findings (text)",
                        "findings_text",
                        "Textual summary of the finding with the request and response attached.",
                    ),
                    ExportFormatItem(
                        "Findings (JSON)",
                        "findings_json",
                        "Structured JSON representation that includes the finding metadata.",
                    ),
                    ExportFormatItem(
                        "Findings (HTML)",
                        "findings_html",
                        "HTML report embedding the finding context and HTTP exchange.",
                    ),
                    ExportFormatItem(
                        "Findings (XML)",
                        "findings_xml",
                        "XML representation that wraps the finding and HTTP data.",
                    ),
                ]
            )
        return items

    def _theme_builder_menu_rows(
        self, items: list[ThemeBuilderFieldItem]
    ) -> list[tuple[str, int | None, str]]:
        rows: list[tuple[str, int | None, str]] = []
        current_section: str | None = None
        for index, item in enumerate(items):
            if item.section != current_section:
                current_section = item.section
                rows.append(("section", None, f"[{current_section}]"))
            rows.append(("item", index, self._theme_builder_menu_label(item)))
        return rows

    def _rule_builder_menu_label(self, item: MatchReplaceFieldItem) -> str:
        create_label = (
            "save changes"
            if self.rule_builder_edit_index is not None
            else "append rule"
        )
        cancel_label = (
            "cancel edit"
            if self.rule_builder_edit_index is not None
            else "discard draft"
        )
        values = {
            "enabled": "on" if self.rule_builder_draft.enabled else "off",
            "scope": self.rule_builder_draft.scope,
            "mode": self.rule_builder_draft.mode,
            "description": self._single_line_preview(
                self.rule_builder_draft.description or "-", 18
            ),
            "match": self._single_line_preview(
                self.rule_builder_draft.match or "-", 18
            ),
            "replace": self._single_line_preview(
                self.rule_builder_draft.replace or "-", 18
            ),
            "create": create_label,
            "cancel": cancel_label,
        }
        return f"{item.label}: {values[item.kind]}"

    def _theme_builder_menu_label(self, item: ThemeBuilderFieldItem) -> str:
        if item.kind == "name":
            return f"{item.label}: {self.theme_builder_draft.name or '-'}"
        if item.kind == "description":
            return (
                f"{item.label}: "
                f"{self._single_line_preview(self.theme_builder_draft.description or '-', 18)}"
            )
        if item.kind == "extends":
            return f"{item.label}: {self.theme_builder_draft.extends}"
        if item.kind == "save":
            return item.label
        if item.kind == "cancel":
            return item.label
        role, axis = item.kind.split(":", 1)
        colors = self.theme_builder_draft.colors or self._current_theme().colors
        fg, bg = colors[role]
        return f"{item.label}: {fg if axis == 'fg' else bg}"

    def _filter_menu_label(self, item: FilterItem) -> str:
        filters = self.store.view_filters()
        if item.kind == "show_out_of_scope":
            value = "on" if filters.show_out_of_scope else "off"
            return f"{item.label}: {value}"
        if item.kind == "query_mode":
            return f"{item.label}: {filters.query_mode}"
        if item.kind == "body_mode":
            return f"{item.label}: {filters.body_mode}"
        if item.kind == "failure_mode":
            return f"{item.label}: {filters.failure_mode}"
        if item.kind.startswith("method:"):
            method = item.kind.split(":", 1)[1]
            marker = "[x]" if method in filters.methods else "[ ]"
            if not filters.methods:
                marker = "[~]"
            return f"{marker} {method}"
        if item.kind.startswith("exclude_method:"):
            method = item.kind.split(":", 1)[1]
            marker = "[x]" if method in filters.hidden_methods else "[ ]"
            return f"{marker} {method}"
        if item.kind == "clear_methods":
            return f"{item.label}: {', '.join(filters.methods) if filters.methods else 'all methods'}"
        if item.kind == "clear_hidden_methods":
            return f"{item.label}: {', '.join(filters.hidden_methods) if filters.hidden_methods else 'none'}"
        if item.kind == "edit_hidden_extensions":
            value = (
                ", ".join(filters.hidden_extensions)
                if filters.hidden_extensions
                else "none"
            )
            return f"{item.label}: {value}"
        if item.kind == "clear_hidden_extensions":
            value = (
                f"{len(filters.hidden_extensions)} configured"
                if filters.hidden_extensions
                else "none"
            )
            return f"{item.label}: {value}"
        if item.kind == "reset_filters":
            return item.label
        return item.label

    def _scope_menu_label(self, item: ScopeItem) -> str:
        if item.kind == "add_include":
            return "+ Add in-scope pattern"
        if item.kind == "add_exclude":
            return "+ Add out-of-scope pattern"
        if item.kind == "include_pattern":
            return f"[+] {item.value}"
        if item.kind == "exclude_pattern":
            return f"[-] {item.value}"
        return item.label

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
            lines.extend(
                [
                    "",
                    f"Press {self._binding_label('edit_item')} or Enter to rebind this action.",
                ]
            )
        if self.keybinding_error_message:
            lines.extend(["", f"Error: {self.keybinding_error_message}"])
        return lines

    def _filter_detail_lines(self, item: FilterItem | None) -> list[str]:
        if item is None:
            return ["No filter selected."]
        filters = self.store.view_filters()
        lines = [
            item.label,
            "",
            f"Section: {item.section}",
            "",
            f"Meaning: {item.description}",
            "",
            f"Current value: {self._filter_value_text(item, filters)}",
        ]
        if item.kind == "show_out_of_scope":
            lines.extend(
                [
                    "",
                    "Effect:",
                    "- off: when scope has hosts, Flows and Sitemap hide traffic outside that scope",
                    "- on: Flows and Sitemap show both in-scope and out-of-scope traffic",
                    "- this never changes interception rules, only what you see",
                ]
            )
        elif item.kind == "query_mode":
            lines.extend(
                [
                    "",
                    "Effect:",
                    "- all: keep every request",
                    "- with_query: only requests whose URL contains ?param=value",
                    "- without_query: only requests with no query string",
                ]
            )
        elif item.kind == "body_mode":
            lines.extend(
                [
                    "",
                    "Effect:",
                    "- all: keep both body and bodyless traffic",
                    "- with_body: only entries where the request or response contains a body",
                    "- without_body: only entries with no request and no response body",
                ]
            )
        elif item.kind == "failure_mode":
            lines.extend(
                [
                    "",
                    "Effect:",
                    "- failures: 4xx, 5xx and connection/runtime errors",
                    "- hide_failures: hide 4xx, 5xx and connection/runtime errors",
                    "- client_errors: only HTTP 4xx",
                    "- server_errors: only HTTP 5xx",
                    "- connection_errors: only proxy/upstream failures without relying on status code",
                ]
            )
        elif item.kind.startswith("method:"):
            method = item.kind.split(":", 1)[1]
            lines.extend(
                [
                    "",
                    "Effect:",
                    "- once you select one or more methods, the list becomes an allowlist",
                    "- only the checked methods remain visible",
                    f"- current method: {method}",
                ]
            )
        elif item.kind.startswith("exclude_method:"):
            method = item.kind.split(":", 1)[1]
            lines.extend(
                [
                    "",
                    "Effect:",
                    "- this is a denylist for methods you want to hide quickly",
                    "- useful when you only want to hide one noisy method without building a full allowlist",
                    f"- current method: {method}",
                ]
            )
        elif item.kind == "clear_methods":
            lines.extend(
                [
                    "",
                    "Effect:",
                    "- clears the method allowlist completely",
                    "- after clearing, every HTTP method becomes visible again",
                ]
            )
        elif item.kind == "clear_hidden_methods":
            lines.extend(
                [
                    "",
                    "Effect:",
                    "- clears the hidden-method denylist completely",
                    "- methods are no longer hidden unless the allowlist excludes them",
                ]
            )
        elif item.kind == "edit_hidden_extensions":
            lines.extend(
                [
                    "",
                    "Effect:",
                    "- hides requests whose path or inferred response type matches one of these extensions",
                    "- useful to remove noise such as jpg, png, css, js, woff or map files",
                    "- type a comma-separated list inside the TUI when you activate this item",
                ]
            )
        elif item.kind == "clear_hidden_extensions":
            lines.extend(
                [
                    "",
                    "Effect:",
                    "- clears every hidden file type",
                    "- static assets become visible again immediately",
                ]
            )
        elif item.kind == "reset_filters":
            lines.extend(
                [
                    "",
                    "Effect:",
                    "- resets all view filters to defaults",
                    "- scope itself is preserved",
                    "- scope visibility goes back to showing only in-scope traffic when scope exists",
                ]
            )
        lines.extend(
            [
                "",
                f"Press {self._binding_label('edit_item')} or Enter to modify this filter.",
            ]
        )
        if self.filters_error_message:
            lines.extend(["", f"Error: {self.filters_error_message}"])
        return lines

    def _scope_detail_lines(self, item: ScopeItem | None) -> list[str]:
        if item is None:
            return ["No scope item selected."]
        scope_hosts = self.store.scope_hosts()
        included = [host for host in scope_hosts if not host.startswith("!")]
        excluded = [host[1:] for host in scope_hosts if host.startswith("!")]
        lines = [
            item.label,
            "",
            f"Section: {item.section}",
            "",
            f"Meaning: {item.description}",
            "",
            f"In scope now: {', '.join(included) if included else 'all hosts'}",
            f"Out of scope now: {', '.join(excluded) if excluded else 'none'}",
        ]
        if item.kind == "add_include":
            lines.extend(
                [
                    "",
                    "Examples:",
                    "- example.com: includes example.com and subdomains",
                    "- *.example.com: includes only subdomains",
                    "- *: includes everything",
                    "",
                    f"Press {self._binding_label('edit_item')} or Enter to add a new in-scope pattern.",
                ]
            )
        elif item.kind == "add_exclude":
            lines.extend(
                [
                    "",
                    "Examples:",
                    "- test.example.com: exclude one host",
                    "- *.internal.example.com: exclude matching subdomains",
                    "",
                    f"Press {self._binding_label('edit_item')} or Enter to add a new out-of-scope pattern.",
                ]
            )
        elif item.kind in {"include_pattern", "exclude_pattern"}:
            lines.extend(
                [
                    "",
                    "Actions:",
                    f"- {self._binding_label('edit_item')} or Enter edits this pattern",
                    f"- {self._binding_label('drop_item')} deletes this pattern",
                ]
            )
        elif item.kind == "clear_scope":
            lines.extend(
                [
                    "",
                    "Effect:",
                    "- removes every include and exclude pattern",
                    "- interception returns to all hosts",
                    "- Flows and Sitemap stop using scope restrictions",
                    "",
                    f"Press {self._binding_label('drop_item')} to clear the full scope.",
                ]
            )
        if self.scope_error_message:
            lines.extend(["", f"Error: {self.scope_error_message}"])
        return lines

    def _filter_value_text(self, item: FilterItem, filters: ViewFilterSettings) -> str:
        if item.kind == "show_out_of_scope":
            return (
                "show everything"
                if filters.show_out_of_scope
                else "hide out-of-scope traffic"
            )
        if item.kind == "query_mode":
            return filters.query_mode
        if item.kind == "body_mode":
            return filters.body_mode
        if item.kind == "failure_mode":
            return filters.failure_mode
        if item.kind.startswith("method:"):
            method = item.kind.split(":", 1)[1]
            if not filters.methods:
                return f"{method} is currently visible because no method allowlist is active"
            return "checked" if method in filters.methods else "unchecked"
        if item.kind.startswith("exclude_method:"):
            method = item.kind.split(":", 1)[1]
            return "hidden" if method in filters.hidden_methods else "visible"
        if item.kind == "clear_methods":
            return ", ".join(filters.methods) if filters.methods else "all methods"
        if item.kind == "clear_hidden_methods":
            return (
                ", ".join(filters.hidden_methods) if filters.hidden_methods else "none"
            )
        if item.kind == "edit_hidden_extensions":
            return (
                ", ".join(filters.hidden_extensions)
                if filters.hidden_extensions
                else "none"
            )
        if item.kind == "clear_hidden_extensions":
            return (
                f"{len(filters.hidden_extensions)} configured"
                if filters.hidden_extensions
                else "none"
            )
        if item.kind == "reset_filters":
            return "restore defaults"
        return "-"

    def _export_detail_lines(self, item: ExportFormatItem | None) -> list[str]:
        if item is None:
            return ["No export format selected."]
        source = self.export_source
        if source is None:
            return [
                "No request loaded.",
                "",
                f"Open this workspace with {self._binding_label('open_export')} while a request is selected.",
                "Supported sources: Flows, Intercept, Repeater and Sitemap.",
            ]
        try:
            export_text = self._render_export_text(item.kind, source)
        except Exception as exc:
            return [
                item.label,
                "",
                f"Source: {source.label}",
                f"Error: {exc}",
            ]
        return [
            item.label,
            "",
            f"Source: {source.label}",
            f"Format: {item.description}",
            "",
            *export_text.splitlines(),
        ]

    def _theme_builder_detail_rows(
        self, item: ThemeBuilderFieldItem | None
    ) -> list[tuple[str | None, str]]:
        if item is None:
            return [(None, "No theme builder field selected.")]
        lines: list[tuple[str | None, str]] = [
            (None, item.label),
            (None, ""),
            (None, f"Section: {item.section}"),
            (None, ""),
            (None, f"Meaning: {item.description}"),
            (None, ""),
            (None, f"Current value: {self._theme_builder_value(item.kind)}"),
        ]
        if item.kind == "extends":
            lines.extend(
                [
                    (None, ""),
                    (None, "Available bases:"),
                    *[(None, f"- {theme.name}") for theme in self._available_themes()],
                ]
            )
        elif ":" in item.kind:
            lines.extend(
                [
                    (None, ""),
                    (None, "Accepted values:"),
                    (None, "- named colors: default, black, red, green, yellow, blue, magenta, cyan, white"),
                    (None, "- hex colors: #RGB or #RRGGBB"),
                    (None, "- edits are applied immediately to the live preview"),
                ]
            )
        lines.extend(
            [
                (None, ""),
                (None, "Preview samples:"),
                ("chrome", " Chrome sample: header/footer and section bars "),
                ("selection", " Selection sample: active row highlight "),
                ("success", " Success sample: 200 OK / saved successfully "),
                ("error", " Error sample: 500 Server Error "),
                ("warning", " Warning sample: certificate needs attention "),
                ("accent", " Accent sample: highlighted labels and links "),
                ("keyword", " Keyword sample: GET POST CONNECT export "),
                ("info", " Info sample: host, path and metadata hints "),
            ]
        )
        if self.theme_builder_error_message:
            lines.extend([(None, ""), (None, f"Error: {self.theme_builder_error_message}")])
        return lines

    def _theme_builder_value(self, kind: str) -> str:
        if kind == "name":
            return self.theme_builder_draft.name or "-"
        if kind == "description":
            return self.theme_builder_draft.description or "-"
        if kind == "extends":
            return self.theme_builder_draft.extends
        if kind == "save":
            return "write JSON and keep current preview active"
        if kind == "cancel":
            return "restore the previously active theme"
        role, axis = kind.split(":", 1)
        fg, bg = self.theme_builder_draft.colors[role]
        return fg if axis == "fg" else bg

    def _theme_role_attr(self, role: str | None) -> int:
        if role is None:
            return curses.A_NORMAL
        if self._colors_enabled() and role in self.THEME_PAIR_IDS:
            return curses.color_pair(self.THEME_PAIR_IDS[role])
        if role == "chrome":
            return curses.A_REVERSE
        if role in {"selection", "keyword"}:
            return curses.A_BOLD
        if role in {"error", "warning"}:
            return curses.A_BOLD
        return curses.A_NORMAL

    def _export_detail_content(
        self, item: ExportFormatItem | None
    ) -> list[tuple[str, str | None]]:
        lines = self._export_detail_lines(item)
        if item is None:
            return [(line, None) for line in lines]
        style_kind = item.style_kind or self._export_style_kind(item.kind)
        if style_kind is None:
            return [(line, None) for line in lines]
        blank_count = 0
        content: list[tuple[str, str | None]] = []
        for line in lines:
            if blank_count < 2:
                content.append((line, None))
                if line == "":
                    blank_count += 1
                continue
            content.append((line, style_kind))
        return content

    @staticmethod
    def _export_style_kind(kind: str) -> str | None:
        if kind.startswith("plugin:"):
            return None
        if kind == "http_pair":
            return "http"
        if kind == "python_requests":
            return "python"
        if kind in {"curl_bash", "curl_windows"}:
            return "shell"
        if kind == "node_fetch":
            return "javascript"
        if kind == "php_curl":
            return "php"
        if kind == "go_http":
            return "go"
        if kind == "rust_reqwest":
            return "rust"
        if kind == "findings_json":
            return "json"
        if kind == "findings_html":
            return "html"
        if kind == "findings_xml":
            return "xml"
        return None

    def _rule_builder_detail_lines(
        self, item: MatchReplaceFieldItem | None
    ) -> list[str]:
        if item is None:
            return ["No rule builder field selected."]
        preview_rules = self.store.match_replace_rules()
        draft_rule = self._draft_match_replace_rule()
        if self.rule_builder_edit_index is None:
            preview_rules = [*preview_rules, draft_rule]
        elif 0 <= self.rule_builder_edit_index < len(preview_rules):
            preview_rules[self.rule_builder_edit_index] = draft_rule
        lines = [
            item.label,
            "",
            item.description,
            "",
            f"Mode: {'edit existing rule' if self.rule_builder_edit_index is not None else 'create new rule'}",
            "",
            f"Current value: {self._rule_builder_value(item.kind)}",
            "",
            "Generated JSON preview:",
            "",
            *self._render_match_replace_rules_document_from_rules(
                preview_rules
            ).splitlines(),
        ]
        if item.kind in {"enabled", "scope", "mode", "create", "cancel"}:
            lines.extend(
                [
                    "",
                    f"Press {self._binding_label('edit_item')} or Enter to activate this item.",
                ]
            )
        else:
            lines.extend(
                [
                    "",
                    f"Press {self._binding_label('edit_item')} or Enter to edit this field.",
                ]
            )
        if self.rule_builder_error_message:
            lines.extend(["", f"Error: {self.rule_builder_error_message}"])
        return lines

    def _rule_builder_value(self, kind: str) -> str:
        draft = self.rule_builder_draft
        mapping = {
            "enabled": "on" if draft.enabled else "off",
            "scope": draft.scope,
            "mode": draft.mode,
            "description": self._single_line_preview(draft.description or "-"),
            "match": self._single_line_preview(draft.match or "-"),
            "replace": self._single_line_preview(draft.replace or "-"),
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
        rows, x_scroll = self._prepare_plain_visual_rows(
            tree_lines, width, self.sitemap_tree_x_scroll
        )
        selected_row = next(
            (
                index
                for index, (source_index, _) in enumerate(rows)
                if source_index == self.sitemap_selected_index
            ),
            0,
        )
        start = self._window_start(self.sitemap_tree_scroll, len(rows), height)
        if selected_row < start:
            start = selected_row
        elif selected_row >= start + height:
            start = max(0, selected_row - height + 1)
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
            self._draw_text_line(
                stdscr, row_y, x, width, line, x_scroll=x_scroll, attr=attr
            )
        self._draw_detail_scroll_indicators(
            stdscr, y, x, height, width, start, len(visible_rows), len(rows)
        )

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
        scroll = (
            self.sitemap_request_scroll
            if pane == "sitemap_request"
            else self.sitemap_response_scroll
        )
        initial_x_scroll = (
            self.sitemap_request_x_scroll
            if pane == "sitemap_request"
            else self.sitemap_response_x_scroll
        )
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
        self._draw_detail_scroll_indicators(
            stdscr, y, x, height, width, start, len(visible_rows), len(rows)
        )

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
            items.append(
                SitemapItem(label=host, depth=0, entry_id=host_entry.id, kind="host")
            )
            prefixes_seen: set[tuple[str, ...]] = set()
            path_entries = sorted(hosts[host]["paths"], key=lambda item: item[0])
            for path, entry in path_entries:
                segments = [segment for segment in path.split("/") if segment] or ["/"]
                for depth, segment in enumerate(segments, start=1):
                    prefix = tuple(segments[:depth])
                    is_leaf = depth == len(segments)
                    if not is_leaf and prefix not in prefixes_seen:
                        items.append(
                            SitemapItem(
                                label=f"{segment}/",
                                depth=depth,
                                entry_id=entry.id,
                                kind="folder",
                            )
                        )
                        prefixes_seen.add(prefix)
                    elif is_leaf:
                        status = self._status_label(entry)
                        label = f"{segment} [{entry.request.method} {status}]"
                        items.append(
                            SitemapItem(
                                label=label, depth=depth, entry_id=entry.id, kind="leaf"
                            )
                        )
        return items

    def _build_repeater_session_bar(self, width: int) -> str:
        if not self.repeater_sessions:
            return " Repeater | no sessions "
        labels: list[str] = []
        for index, session in enumerate(self.repeater_sessions, start=1):
            marker = "*" if index - 1 == self.repeater_index else "-"
            source = (
                f"#{session.source_entry_id}"
                if session.source_entry_id is not None
                else "manual"
            )
            labels.append(f"{marker}{index}:{source}/{len(session.exchanges)}")
        current = self._current_repeater_session()
        sent = (
            self._format_save_time(current.last_sent_at) if current is not None else "-"
        )
        error = (
            current.last_error if current is not None and current.last_error else "-"
        )
        bar = f" Repeater [{' '.join(labels)}] | sent: {sent} | error: {error} "
        return self._trim(bar, max(1, width))

    @staticmethod
    def _repeater_history_items(session: RepeaterSession) -> list[str]:
        return [
            "Draft",
            *[f"Send #{index}" for index, _ in enumerate(session.exchanges, start=1)],
        ]

    def _sync_repeater_history_selection(self, session: RepeaterSession) -> None:
        item_count = len(self._repeater_history_items(session))
        session.selected_exchange_index = max(
            0, min(session.selected_exchange_index, item_count - 1)
        )

    def _selected_repeater_exchange(
        self, session: RepeaterSession
    ) -> RepeaterExchange | None:
        self._sync_repeater_history_selection(session)
        if session.selected_exchange_index == 0:
            return None
        return session.exchanges[session.selected_exchange_index - 1]

    def _repeater_history_label(self, session: RepeaterSession, item_index: int) -> str:
        if item_index == 0:
            return f"Draft | {self._single_line_preview(session.request_text.splitlines()[0] if session.request_text else '-', 40)}"
        exchange = session.exchanges[item_index - 1]
        sent = self._format_save_time(exchange.sent_at)
        status = "ERR" if exchange.last_error else "OK"
        first_line = (
            exchange.request_text.splitlines()[0] if exchange.request_text else "-"
        )
        return f"Send #{item_index} | {status} | {sent} | {self._single_line_preview(first_line, 28)}"

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
        scroll = (
            session.request_scroll if pane == "request" else session.response_scroll
        )
        initial_x_scroll = (
            session.request_x_scroll if pane == "request" else session.response_x_scroll
        )
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
        self._draw_detail_scroll_indicators(
            stdscr, y, x, height, width, start, len(visible_rows), len(rows)
        )

    def _draw_http_message_pane(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        lines: list[tuple[str, str | None]],
        pane: str,
    ) -> None:
        if height <= 0 or width <= 0:
            return
        scroll = (
            self.http_request_scroll if pane == "request" else self.http_response_scroll
        )
        initial_x_scroll = (
            self.http_request_x_scroll
            if pane == "request"
            else self.http_response_x_scroll
        )
        rows, x_scroll = self._prepare_message_visual_rows(
            lines, width, initial_x_scroll
        )
        start = self._window_start(scroll, len(rows), height)
        if pane == "request":
            self.http_request_scroll = start
            self.http_request_x_scroll = x_scroll
        else:
            self.http_response_scroll = start
            self.http_response_x_scroll = x_scroll
        visible_rows = rows[start : start + height]
        for offset, (_, line, style_kind) in enumerate(visible_rows):
            if style_kind is None:
                self._draw_text_line(
                    stdscr, y + offset, x, width, str(line), x_scroll=x_scroll
                )
                continue
            segments = (
                line
                if isinstance(line, list)
                else self._style_body_line(str(line), style_kind)
            )
            self._draw_styled_line(
                stdscr, y + offset, x, width, segments, x_scroll=x_scroll
            )
        self._draw_detail_scroll_indicators(
            stdscr, y, x, height, width, start, len(visible_rows), len(rows)
        )

    def _draw_repeater_history(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        session: RepeaterSession,
    ) -> None:
        items = self._repeater_history_items(session)
        self._sync_repeater_history_selection(session)
        lines = [
            self._repeater_history_label(session, item_index)
            for item_index in range(len(items))
        ]
        start = self._window_start(session.selected_exchange_index, len(lines), height)
        rows, x_scroll = self._prepare_plain_visual_rows(
            lines, width, session.history_x_scroll
        )
        session.history_scroll = start
        session.history_x_scroll = x_scroll
        visible_rows = rows[start : start + height]
        for offset, (source_index, line) in enumerate(visible_rows):
            attr = curses.A_NORMAL
            if source_index == session.selected_exchange_index and curses.has_colors():
                attr = curses.color_pair(1)
            elif source_index == session.selected_exchange_index:
                attr = curses.A_REVERSE
            row_y = y + offset
            self._register_clickable_region(
                "repeater_history_row",
                x,
                row_y,
                width,
                payload=source_index,
            )
            if self._is_mouse_over(x, row_y, width, 1):
                attr |= curses.A_REVERSE
            self._draw_text_line(
                stdscr, y + offset, x, width, line, x_scroll=x_scroll, attr=attr
            )
        self._draw_detail_scroll_indicators(
            stdscr, y, x, height, width, start, len(visible_rows), len(rows)
        )

    def _repeater_request_lines(self, session: RepeaterSession) -> list[str]:
        exchange = self._selected_repeater_exchange(session)
        source_entry = (
            self.store.get(session.source_entry_id)
            if session.source_entry_id is not None
            else None
        )
        lines = [
            f"Session: {self.repeater_index + 1}/{len(self.repeater_sessions)}",
            f"Source flow: #{session.source_entry_id}"
            if session.source_entry_id is not None
            else "Source flow: -",
            f"Selection: {'Draft' if exchange is None else f'Send #{session.selected_exchange_index}'}",
            "",
        ]
        request_text = (
            session.request_text if exchange is None else exchange.request_text
        )
        rendered = self._format_http_text_for_display(
            request_text or "",
            "request",
            mode=self.request_body_view_mode,
        )
        request_lines = rendered.splitlines() or ([rendered] if rendered else [])
        if not request_lines:
            request_lines = ["No repeater request loaded."]
        lines.extend(request_lines)
        plugin_sections = self._plugin_panel_sections("repeater_request", entry=source_entry)
        if plugin_sections:
            lines.extend(["", *plugin_sections])
        return lines

    def _repeater_response_lines(self, session: RepeaterSession) -> list[str]:
        exchange = self._selected_repeater_exchange(session)
        source_entry = (
            self.store.get(session.source_entry_id)
            if session.source_entry_id is not None
            else None
        )
        lines = [
            f"Last sent: {self._format_save_time(session.last_sent_at if exchange is None else exchange.sent_at)}",
            f"Last error: {(session.last_error if exchange is None else exchange.last_error) or '-'}",
            "",
        ]
        response_text = (
            session.response_text if exchange is None else exchange.response_text
        )
        rendered = self._format_http_text_for_display(
            response_text or "",
            "response",
            mode=self.response_body_view_mode,
        )
        response_lines = rendered.splitlines() or ([rendered] if rendered else [])
        if not response_lines:
            response_lines = ["No repeater response yet."]
        lines.extend(response_lines)
        plugin_sections = self._plugin_panel_sections("repeater_response", entry=source_entry)
        if plugin_sections:
            lines.extend(["", *plugin_sections])
        return lines

    def _draw_flow_list(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        entries: list[TrafficEntry],
    ) -> None:
        header = f"{'#':<4} {'M':<6} {'S':<5} {'Host':<18} Path"
        lines = [header, *(self._flow_list_line(entry) for entry in entries)]
        x_scroll = self._normalize_horizontal_scroll(
            self.flow_x_scroll, self._max_display_width(lines), width
        )
        self.flow_x_scroll = x_scroll
        self._draw_text_line(
            stdscr, y, x, width, header, x_scroll=x_scroll, attr=curses.A_BOLD
        )

        start_index, visible_entries = self._visible_flow_entries(
            entries, max(0, height - 1)
        )
        for offset, entry in enumerate(visible_entries):
            row_y = y + 1 + offset
            line = self._flow_list_line(entry)

            attr = curses.A_NORMAL
            absolute_index = start_index + offset
            self._register_clickable_region(
                "flow_row",
                x,
                row_y,
                width,
                payload=absolute_index,
            )
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
            if self._is_mouse_over(x, row_y, width, 1):
                attr |= curses.A_REVERSE
            self._draw_text_line(
                stdscr, row_y, x, width, line, x_scroll=x_scroll, attr=attr
            )

        if start_index > 0:
            stdscr.addnstr(
                y, max(x, x + width - 3), " ^ ", min(3, width), curses.A_BOLD
            )
        if start_index + len(visible_entries) < len(entries):
            stdscr.addnstr(
                y + height - 1,
                max(x, x + width - 3),
                " v ",
                min(3, width),
                curses.A_BOLD,
            )

    def _draw_intercept_list(
        self,
        stdscr,
        y: int,
        x: int,
        height: int,
        width: int,
        entries: list[TrafficEntry],
        intercept_items: list[PendingInterceptionView],
        double_click: bool = False,
    ) -> None:
        header = f"{'#':<4} {'P':<8} {'D':<8} {'M':<6} {'Host':<18} Path"
        lines = [
            header,
            *(
                self._intercept_list_line(item, self._entry_for_pending(entries, item))
                for item in intercept_items
            ),
        ]
        x_scroll = self._normalize_horizontal_scroll(
            self.flow_x_scroll, self._max_display_width(lines), width
        )
        self.flow_x_scroll = x_scroll
        self._draw_text_line(
            stdscr, y, x, width, header, x_scroll=x_scroll, attr=curses.A_BOLD
        )

        start_index, visible_pending = self._visible_intercept_entries(
            intercept_items, max(0, height - 1)
        )
        if not visible_pending:
            self._draw_text_line(
                stdscr, y + 1, x, width, "No intercepted items yet.", x_scroll=x_scroll
            )
            return
        for offset, item in enumerate(visible_pending):
            row_y = y + 1 + offset
            line = self._intercept_list_line(
                item, self._entry_for_pending(entries, item)
            )
            attr = curses.A_NORMAL
            absolute_index = start_index + offset
            self._register_clickable_region(
                "intercept_row",
                x,
                row_y,
                width,
                payload=absolute_index,
            )
            if absolute_index == self.intercept_selected_index and curses.has_colors():
                attr = curses.color_pair(1)
            elif absolute_index == self.intercept_selected_index:
                attr = curses.A_REVERSE
            elif item.active and curses.has_colors():
                attr = curses.color_pair(4)
            if self._is_mouse_over(x, row_y, width, 1):
                attr |= curses.A_REVERSE
            self._draw_text_line(
                stdscr, row_y, x, width, line, x_scroll=x_scroll, attr=attr
            )

        if start_index > 0:
            stdscr.addnstr(
                y, max(x, x + width - 3), " ^ ", min(3, width), curses.A_BOLD
            )
        if start_index + len(visible_pending) < len(intercept_items):
            stdscr.addnstr(
                y + height - 1,
                max(x, x + width - 3),
                " v ",
                min(3, width),
                curses.A_BOLD,
            )

    def _flow_list_line(self, entry: TrafficEntry) -> str:
        status = self._status_label(entry)
        host = entry.summary_host
        path = entry.summary_path
        return (
            f"{entry.id:<4} {entry.request.method[:6]:<6} {status:<5} {host:<18} {path}"
        )

    def _intercept_list_line(
        self, pending: PendingInterceptionView, entry: TrafficEntry | None
    ) -> str:
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
        lines = self._build_detail_lines(
            entry, pending, selected_pending, selected_intercept
        )
        rows, x_scroll = self._prepare_plain_visual_rows(
            lines, width, self.detail_x_scroll
        )
        start = self._detail_window_start(len(rows), height)
        self.detail_x_scroll = x_scroll
        visible_rows = rows[start : start + height]
        for offset, (_, line) in enumerate(visible_rows):
            self._draw_text_line(stdscr, y + offset, x, width, line, x_scroll=x_scroll)
        self._draw_detail_scroll_indicators(
            stdscr, y, x, height, width, start, len(visible_rows), len(rows)
        )

    def _build_detail_lines(
        self,
        entry: TrafficEntry | None,
        pending: list[PendingInterceptionView],
        selected_pending: PendingInterceptionView | None = None,
        selected_intercept: PendingInterceptionView | None = None,
    ) -> list[str]:
        if self.active_tab == 1:
            return self._build_intercept_lines(
                entry, pending, selected_intercept, selected_pending
            )
        if self.active_tab == 2:
            return self._build_repeater_lines()
        if self.active_tab == 3:
            return self._build_sitemap_overview_lines()
        if entry is None:
            return ["No traffic yet."]

        last_save_at, last_save_error = self.store.save_status()
        match self.active_tab:
            case 0:
                started = entry.started_at.astimezone(timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S UTC"
                )
                duration = (
                    f"{entry.duration_ms:.1f} ms"
                    if entry.duration_ms is not None
                    else "-"
                )
                saved = self._format_save_time(last_save_at)
                cert_status = (
                    "ready" if self.certificate_authority.is_ready() else "missing"
                )
                cert_path = self.certificate_authority.cert_path()
                scope_hosts = self.store.scope_hosts()
                scope_label = (
                    "all traffic" if not scope_hosts else f"{len(scope_hosts)} host(s)"
                )
                lines = [
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
                plugin_sections = self._plugin_panel_sections("overview_detail", entry=entry)
                if plugin_sections:
                    lines.extend(["", *plugin_sections])
                return lines
            case 4:
                return self._build_match_replace_lines()
        return []

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

        created = selected_intercept.created_at.astimezone(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
        updated = selected_intercept.updated_at.astimezone(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
        lines.extend(
            [
                f"Intercepted flow: #{selected_intercept.entry_id}",
                f"Phase: {selected_intercept.phase}",
                f"Decision: {selected_intercept.decision}",
                f"Active: {'yes' if selected_intercept.active else 'no'}",
                f"Request: {entry.request.method} {entry.request.path} {entry.request.version}"
                if entry is not None
                else "Request: -",
                f"Created: {created}",
                f"Updated: {updated}",
                "",
                f"Raw {selected_intercept.phase}:",
                "",
            ]
        )
        view_mode = (
            self.response_body_view_mode
            if selected_intercept.phase == "response"
            else self.request_body_view_mode
        )
        rendered = self._format_http_text_for_display(
            selected_intercept.raw_text,
            selected_intercept.phase,
            mode=view_mode,
        )
        raw_lines = rendered.splitlines() or [rendered]
        lines.extend(raw_lines)
        return lines

    def _http_message_lines(
        self, entry: TrafficEntry | None, pane: str
    ) -> list[tuple[str, str | None]]:
        if entry is None:
            title = (
                "No request selected." if pane == "request" else "No response selected."
            )
            return [(title, None)]
        if pane == "request":
            headers = entry.request.headers
            start_line = (
                f"{entry.request.method} {entry.request.target} {entry.request.version}"
            )
            body = entry.request.body
            document = (
                build_body_document(entry.request.headers, body) if body else None
            )
            mode = self.request_body_view_mode
        else:
            headers = entry.response.headers
            status_code = entry.response.status_code or "-"
            start_line = f"{entry.response.version} {status_code}"
            if entry.response.reason:
                start_line = f"{start_line} {entry.response.reason}"
            body = entry.response.body
            document = (
                build_body_document(entry.response.headers, body) if body else None
            )
            mode = self.response_body_view_mode
        if document is not None and mode == "pretty" and not document.pretty_available:
            mode = "raw"

        lines: list[tuple[str, str | None]] = [(start_line, "http")]
        if headers:
            lines.extend((f"{name}: {value}", "http") for name, value in headers)
        if document is not None:
            lines.append(("", None))
            body_text = self._body_text_for_mode(document, mode)
            body_lines = body_text.splitlines() or [body_text]
            lines.extend((line, document.kind) for line in body_lines)
        panel_workspace = "http_request" if pane == "request" else "http_response"
        plugin_sections = self._plugin_panel_sections(panel_workspace, entry=entry)
        if pane == "response":
            plugin_sections.extend(self._plugin_metadata_lines(entry))
            plugin_sections.extend(self._plugin_analyzer_lines(entry))
        if plugin_sections:
            lines.append(("", None))
            lines.extend((line, None) for line in plugin_sections)
        return lines

    def _http_compact_message_lines(
        self, entry: TrafficEntry | None, pane: str
    ) -> list[tuple[str, str | None]]:
        if entry is None:
            return self._http_message_lines(entry, pane)
        if pane != "response":
            return self._http_message_lines(entry, pane)
        if entry.response_size <= self.MAX_COMPACT_RESPONSE_BYTES:
            return self._http_message_lines(entry, pane)

        status_code = entry.response.status_code or "-"
        start_line = f"{entry.response.version} {status_code}"
        if entry.response.reason:
            start_line = f"{start_line} {entry.response.reason}"
        binding = self._binding_label("open_expand")
        return [
            (start_line, "http"),
            ("", None),
            (f"Response preview disabled ({entry.response_size} bytes).", None),
            ("This response is too large to render safely in the compact pane.", None),
            ("", None),
            (
                f"To view it: focus the Request pane, then press {binding} to open Inspect.",
                None,
            ),
            (f"Inside Inspect, press {binding} to switch Request/Response.", None),
        ]

    def _build_match_replace_lines(self) -> list[str]:
        rules = self.store.match_replace_rules()
        self._sync_match_replace_selection(rules)
        lines = [
            "Match/Replace rules",
            "",
            "Controls:",
            "r open the guided rule builder",
            "e edit selected rule",
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
            description = self._single_line_preview(rule.description or "-", 40)
            marker = ">" if index - 1 == self.match_replace_selected_index else " "
            lines.extend(
                [
                    f"{marker}[{index}] {status} | {rule.scope} | {rule.mode} | {description}",
                    f"match: {self._single_line_preview(rule.match, 80)}",
                    f"replace: {self._single_line_preview(rule.replace, 80)}",
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
        lines = [
            "Repeater",
            "",
            *self._repeater_request_lines(session),
            "",
            *self._repeater_response_lines(session),
        ]
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
        if (
            mode == "pretty"
            and document.pretty_available
            and document.pretty_text is not None
        ):
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
        if kind == "http":
            return self._style_http_line(line)
        if kind == "python":
            return self._style_python_line(line)
        if kind == "shell":
            return self._style_shell_line(line)
        if kind == "php":
            return self._style_php_line(line)
        if kind == "go":
            return self._style_go_line(line)
        if kind == "rust":
            return self._style_rust_line(line)
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
            styled.append(
                (match.group(1), curses.color_pair(7) if colors else curses.A_BOLD)
            )
            styled.append(
                (match.group(2), curses.color_pair(6) if colors else curses.A_BOLD)
            )
            cursor = match.end()
        if cursor < len(source):
            styled.append((source[cursor:], curses.A_NORMAL))
        return styled or [(line, curses.A_NORMAL)]

    def _style_python_line(self, line: str) -> list[tuple[str, int]]:
        colors = self._colors_enabled()
        keyword_pattern = re.compile(
            r"\b(import|from|as|def|class|return|if|elif|else|for|while|try|except|with|in|None|True|False)\b"
        )
        string_pattern = re.compile(r"""("(?:\\.|[^"])*"|'(?:\\.|[^'])*')""")
        comment_pattern = re.compile(r"(#.*$)")
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

    def _style_shell_line(self, line: str) -> list[tuple[str, int]]:
        colors = self._colors_enabled()
        command_pattern = re.compile(r"\b(curl|curl\.exe)\b")
        option_pattern = re.compile(r"--[a-zA-Z0-9-]+")
        string_pattern = re.compile(
            r"""("(?:\\.|[^"])*"|'(?:\\.|[^'])*'|\$'(?:\\.|[^'])*')"""
        )
        return self._style_with_patterns(
            line,
            [
                (string_pattern, curses.color_pair(2) if colors else curses.A_NORMAL),
                (option_pattern, curses.color_pair(7) if colors else curses.A_BOLD),
                (command_pattern, curses.color_pair(6) if colors else curses.A_BOLD),
            ],
        )

    def _style_http_line(self, line: str) -> list[tuple[str, int]]:
        colors = self._colors_enabled()
        if re.match(
            r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+\s+HTTP/\d\.\d$", line
        ):
            return [(line, curses.color_pair(6) if colors else curses.A_BOLD)]
        if re.match(r"^HTTP/\d\.\d\s+\d{3}", line):
            return [(line, curses.color_pair(6) if colors else curses.A_BOLD)]
        if ": " in line:
            name, value = line.split(": ", 1)
            return [
                (name, curses.color_pair(7) if colors else curses.A_BOLD),
                (": ", curses.A_NORMAL),
                (value, curses.color_pair(2) if colors else curses.A_NORMAL),
            ]
        return [(line, curses.A_NORMAL)]

    def _style_php_line(self, line: str) -> list[tuple[str, int]]:
        colors = self._colors_enabled()
        keyword_pattern = re.compile(
            r"\b(<?php|curl_init|curl_setopt|curl_exec|curl_close|return|if|else|true|false|null)\b"
        )
        variable_pattern = re.compile(r"\$[a-zA-Z_][a-zA-Z0-9_]*")
        string_pattern = re.compile(r"""("(?:\\.|[^"])*"|'(?:\\.|[^'])*')""")
        return self._style_with_patterns(
            line,
            [
                (string_pattern, curses.color_pair(2) if colors else curses.A_NORMAL),
                (variable_pattern, curses.color_pair(7) if colors else curses.A_BOLD),
                (keyword_pattern, curses.color_pair(6) if colors else curses.A_BOLD),
            ],
        )

    def _style_go_line(self, line: str) -> list[tuple[str, int]]:
        colors = self._colors_enabled()
        keyword_pattern = re.compile(
            r"\b(package|import|func|var|if|else|return|nil)\b"
        )
        string_pattern = re.compile(r'("(?:\\.|[^"])*"|`[^`]*`)')
        return self._style_with_patterns(
            line,
            [
                (string_pattern, curses.color_pair(2) if colors else curses.A_NORMAL),
                (keyword_pattern, curses.color_pair(6) if colors else curses.A_BOLD),
            ],
        )

    def _style_rust_line(self, line: str) -> list[tuple[str, int]]:
        colors = self._colors_enabled()
        keyword_pattern = re.compile(
            r"\b(use|fn|let|mut|if|else|match|return|Ok|Err)\b"
        )
        string_pattern = re.compile(r'("(?:\\.|[^"])*"|r#".*"#)')
        macro_pattern = re.compile(r"\b[a-zA-Z_][a-zA-Z0-9_]*!")
        return self._style_with_patterns(
            line,
            [
                (string_pattern, curses.color_pair(2) if colors else curses.A_NORMAL),
                (macro_pattern, curses.color_pair(7) if colors else curses.A_BOLD),
                (keyword_pattern, curses.color_pair(6) if colors else curses.A_BOLD),
            ],
        )

    def _style_with_patterns(
        self, line: str, patterns: list[tuple[re.Pattern[str], int]]
    ) -> list[tuple[str, int]]:
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
        return [
            sanitized[index : index + width]
            for index in range(0, len(sanitized), width)
        ]

    def _prepare_plain_visual_rows(
        self,
        lines: list[str],
        width: int,
        x_scroll: int,
    ) -> tuple[list[tuple[int, str]], int]:
        if self.word_wrap_enabled:
            rows: list[tuple[int, str]] = []
            for index, line in enumerate(lines):
                rows.extend(
                    (index, chunk)
                    for chunk in self._wrap_display_text(line, max(1, width))
                )
            return rows, 0
        normalized = self._normalize_horizontal_scroll(
            x_scroll, self._max_display_width(lines), width
        )
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
                    rows.extend(
                        (index, chunk, None)
                        for chunk in self._wrap_display_text(line, max(1, width))
                    )
                    continue
                wrapped_segments = self._wrap_styled_segments(
                    self._style_body_line(line, style_kind), max(1, width)
                )
                rows.extend(
                    (index, segments, style_kind) for segments in wrapped_segments
                )
            return rows, 0
        max_line_width = max(
            (self._display_width(line) for line, _ in lines), default=0
        )
        normalized = self._normalize_horizontal_scroll(x_scroll, max_line_width, width)
        return [
            (index, line, style_kind) for index, (line, style_kind) in enumerate(lines)
        ], normalized

    def _wrap_styled_segments(
        self, segments: list[tuple[str, int]], width: int
    ) -> list[list[tuple[str, int]]]:
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
            if 32 <= codepoint <= 126:
                sanitized.append(character)
                continue
            if character == "\n":
                sanitized.append("\\n")
                continue
            if character == "\t":
                sanitized.append("    ")
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
    def _normalize_horizontal_scroll(
        scroll: int, max_line_width: int, width: int
    ) -> int:
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

    @classmethod
    def _single_line_preview(cls, text: str, width: int | None = None) -> str:
        preview = cls._sanitize_display_text(text).replace("\r", "\\r")
        if width is None:
            return preview
        return cls._trim(preview, width)

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

    def _handle_quit_sequence(self, stdscr) -> bool:
        if self._prompt_yes_no(
            stdscr,
            "Save project before exiting HexProxy?",
            default=True,
        ):
            self._save_project(stdscr)
        if self._prompt_yes_no(
            stdscr,
            "Really exit HexProxy?",
            default=False,
        ):
            return True
        self._set_status("Exit cancelled.")
        return False

    def _prompt_yes_no(
        self,
        stdscr,
        prompt: str,
        default: bool,
    ) -> bool:
        hint = "[Y/n]" if default else "[y/N]"
        message = f"{prompt} {hint}"
        stdscr.timeout(-1)
        try:
            while True:
                height, width = stdscr.getmaxyx()
                stdscr.move(height - 1, 0)
                stdscr.clrtoeol()
                stdscr.addnstr(
                    height - 1,
                    0,
                    message,
                    width - 1,
                    self._chrome_attr(),
                )
                stdscr.refresh()
                key = stdscr.getch()
                if key in (ord("y"), ord("Y")):
                    return True
                if key in (ord("n"), ord("N"), 27):
                    return False
                if key in (curses.KEY_ENTER, 10, 13):
                    return default
        finally:
            stdscr.timeout(150)

    def _edit_match_replace_rules(self, stdscr) -> None:
        if self.active_tab != 4:
            return
        self._open_rule_builder_workspace()

    def _edit_selected_match_replace_rule(self) -> None:
        if self.active_tab != 4:
            return
        rules = self.store.match_replace_rules()
        if not rules:
            self._set_status("No Match/Replace rules to edit.")
            return
        self._sync_match_replace_selection(rules)
        rule = rules[self.match_replace_selected_index]
        draft = MatchReplaceDraft(
            enabled=rule.enabled,
            scope=rule.scope,
            mode=rule.mode,
            match=rule.match,
            replace=rule.replace,
            description=rule.description,
        )
        self._open_rule_builder_workspace(
            draft, edit_index=self.match_replace_selected_index
        )

    def _edit_scope_hosts(self, stdscr) -> None:
        edited = self._open_text_editor(
            stdscr, "Edit Scope", self._render_scope_document()
        )
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

    def _forward_intercepted_request(
        self, pending: PendingInterceptionView | None
    ) -> None:
        if pending is None:
            self._set_status("Select a paused intercepted flow first.")
            return
        try:
            self.store.forward_pending_interception_record(pending.record_id)
        except KeyError:
            self._set_status("Selected flow is not intercepted.")
            return
        self._set_status(
            f"Forwarded intercepted {pending.phase} for flow #{pending.entry_id}."
        )

    def _drop_intercepted_request(
        self, pending: PendingInterceptionView | None
    ) -> None:
        if pending is None:
            self._set_status("Select a paused intercepted flow first.")
            return
        try:
            self.store.drop_pending_interception_record(pending.record_id)
        except KeyError:
            self._set_status("Selected flow is not intercepted.")
            return
        self._set_status(
            f"Dropped intercepted {pending.phase} for flow #{pending.entry_id}."
        )

    def _edit_intercepted_request(
        self, stdscr, pending: PendingInterceptionView | None
    ) -> None:
        if pending is None:
            self._set_status("Select a paused intercepted flow first.")
            return

        edited = self._open_text_editor(
            stdscr, f"Edit Intercepted {pending.phase.title()}", pending.raw_text
        )
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
        self._set_status(
            f"Updated intercepted {pending.phase} for flow #{pending.entry_id}."
        )

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
        self._set_status(
            f"Loaded flow #{entry.id} into repeater {self.repeater_index + 1}."
        )

    def _edit_repeater_request(self, stdscr) -> None:
        if self.active_tab != 2:
            return
        session = self._current_repeater_session()
        if session is None or not session.request_text:
            self._set_status("Load a flow into repeater first.")
            return
        exchange = self._selected_repeater_exchange(session)
        initial_request = (
            session.request_text if exchange is None else exchange.request_text
        )
        edited = self._open_text_editor(
            stdscr, "Edit Repeater Request", initial_request
        )
        if edited is None:
            self._set_status("Repeater edit cancelled.")
            return
        try:
            parse_request_text(edited)
        except Exception as exc:
            self._set_status(f"Invalid repeater request: {exc}")
            return
        session.request_text = edited
        session.selected_exchange_index = 0
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
        sent_at = datetime.now(timezone.utc)
        try:
            response_text = self.repeater_sender(session.request_text)
            session.response_text = response_text
            session.response_scroll = 0
            session.response_x_scroll = 0
            session.last_error = ""
            session.last_sent_at = sent_at
            session.exchanges.append(
                RepeaterExchange(
                    request_text=session.request_text,
                    response_text=response_text,
                    last_error="",
                    sent_at=sent_at,
                )
            )
            session.selected_exchange_index = len(session.exchanges)
        except Exception as exc:
            session.last_error = str(exc)
            session.last_sent_at = sent_at
            session.exchanges.append(
                RepeaterExchange(
                    request_text=session.request_text,
                    response_text="",
                    last_error=str(exc),
                    sent_at=sent_at,
                )
            )
            session.selected_exchange_index = len(session.exchanges)
            self._set_status(f"Repeater send failed: {exc}")
            return
        self._set_status("Repeater response received.")

    def _switch_repeater_session(self, delta: int) -> None:
        if self.active_tab != 2 or not self.repeater_sessions:
            return
        self.repeater_index = (self.repeater_index + delta) % len(
            self.repeater_sessions
        )
        self._set_status(
            f"Repeater session {self.repeater_index + 1}/{len(self.repeater_sessions)}."
        )

    def _move_repeater_focus(self, delta: int) -> None:
        panes = ["repeater_history", "repeater_request", "repeater_response"]
        if self.active_pane not in panes:
            self.active_pane = "repeater_history"
            return
        index = panes.index(self.active_pane)
        index = max(0, min(len(panes) - 1, index + delta))
        self.active_pane = panes[index]

    def _scroll_repeater_active_pane(self, delta: int) -> None:
        session = self._current_repeater_session()
        if session is None:
            return
        if self.active_pane == "repeater_history":
            item_count = len(self._repeater_history_items(session))
            session.selected_exchange_index = max(
                0, min(item_count - 1, session.selected_exchange_index + delta)
            )
            return
        if self.active_pane == "repeater_response":
            session.response_scroll = max(0, session.response_scroll + delta)
            return
        session.request_scroll = max(0, session.request_scroll + delta)

    def _set_repeater_active_scroll(self, value: int) -> None:
        session = self._current_repeater_session()
        if session is None:
            return
        if self.active_pane == "repeater_history":
            item_count = len(self._repeater_history_items(session))
            session.selected_exchange_index = max(0, min(item_count - 1, value))
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
        current_items = (
            items if items is not None else self._build_sitemap_items(entries)
        )
        if not current_items:
            return None
        self._sync_sitemap_selection(current_items)
        selected_item = current_items[self.sitemap_selected_index]
        if selected_item.entry_id is None:
            return None
        return next(
            (entry for entry in entries if entry.id == selected_item.entry_id), None
        )

    def _sync_sitemap_selection(self, items: list[SitemapItem]) -> None:
        if not items:
            self.sitemap_selected_index = 0
            self.sitemap_tree_scroll = 0
            self.sitemap_tree_x_scroll = 0
            return
        self.sitemap_selected_index = max(
            0, min(self.sitemap_selected_index, len(items) - 1)
        )

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

    def _scroll_sitemap_active_pane(
        self, delta: int, entries: list[TrafficEntry]
    ) -> None:
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
        self.sitemap_selected_index = max(
            0, min(len(items) - 1, self.sitemap_selected_index + delta)
        )

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
        rendered = self._format_http_text_for_display(
            request_text,
            "request",
            mode=self.request_body_view_mode,
        )
        request_lines = rendered.splitlines() or [rendered]
        lines.extend(request_lines)
        plugin_sections = self._plugin_panel_sections("sitemap_request", entry=entry)
        if plugin_sections:
            lines.extend(["", *plugin_sections])
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
        response_head = [
            status_line,
            *(f"{name}: {value}" for name, value in entry.response.headers),
            "",
        ]
        body_text = self._body_text_for_mode(document, self.response_body_view_mode)
        response_lines = response_head + (body_text.splitlines() or [body_text])
        lines.extend(response_lines)
        plugin_sections = self._plugin_panel_sections("sitemap_response", entry=entry)
        if plugin_sections:
            lines.extend(["", *plugin_sections])
        return lines

    def _sitemap_compact_response_lines(self, entry: TrafficEntry | None) -> list[str]:
        if entry is None:
            return self._sitemap_response_lines(entry)
        if entry.response_size <= self.MAX_COMPACT_RESPONSE_BYTES:
            return self._sitemap_response_lines(entry)

        binding = self._binding_label("open_expand")
        return [
            f"Response preview disabled ({entry.response_size} bytes).",
            "",
            "This response is too large to render safely in the compact pane.",
            "",
            f"To view it: focus the Request pane, then press {binding} to open Inspect.",
            f"Inside Inspect, press {binding} to switch Request/Response.",
        ]

    def _toggle_body_view_mode(self) -> None:
        target = self._body_view_target_for_context()
        if target is None:
            self._set_status("Focus a request/response view first.")
            return
        if target == "response":
            self.response_body_view_mode = (
                "raw" if self.response_body_view_mode == "pretty" else "pretty"
            )
            mode = self.response_body_view_mode
        else:
            self.request_body_view_mode = (
                "raw" if self.request_body_view_mode == "pretty" else "pretty"
            )
            mode = self.request_body_view_mode
        self._set_status(f"Body view mode ({target}): {mode}.")

    def _body_view_target_for_context(self) -> str | None:
        if self._is_inspect_tab():
            return (
                "response"
                if self.inspect_mode == "response"
                else "request"
            )
        if self.active_pane in {"http_response", "sitemap_response", "repeater_response"}:
            return "response"
        if self.active_pane in {"http_request", "sitemap_request", "repeater_request"}:
            return "request"
        if self.active_tab == 1:
            intercept_items = self.store.interception_history()
            selected_intercept = self._selected_intercept_item(intercept_items)
            if selected_intercept is not None:
                return "response" if selected_intercept.phase == "response" else "request"
        return None

    def _format_http_text_for_display(
        self,
        raw_text: str,
        pane: str,
        *,
        mode: str,
    ) -> str:
        if pane not in {"request", "response"}:
            pane = "request"
        if mode not in {"raw", "pretty"}:
            mode = "raw"
        normalized = (raw_text or "").replace("\r\n", "\n").replace("\r", "\n")
        if "\n\n" not in normalized:
            return normalized
        try:
            if pane == "request":
                parsed_request = parse_request_text(normalized)
                start_line = f"{parsed_request.method} {parsed_request.target} {parsed_request.version}"
                headers = parsed_request.headers
                body = parsed_request.body
            else:
                parsed_response = parse_response_text(normalized)
                start_line = f"{parsed_response.version} {parsed_response.status_code}"
                if parsed_response.reason:
                    start_line = f"{start_line} {parsed_response.reason}"
                headers = parsed_response.headers
                body = parsed_response.body
        except Exception:
            return normalized

        head_lines = [start_line, *(f"{name}: {value}" for name, value in headers)]
        if not body:
            return "\n".join(head_lines)
        document = build_body_document(headers, body)
        body_text = self._body_text_for_mode(document, mode)
        return f"{'\n'.join(head_lines)}\n\n{body_text}"

    def _toggle_word_wrap(self) -> None:
        self.word_wrap_enabled = not self.word_wrap_enabled
        self._reset_horizontal_scrolls()
        state = "on" if self.word_wrap_enabled else "off"
        self._set_status(f"Word wrap: {state}.")

    def _toggle_scope_view(self) -> None:
        if not self.store.scope_hosts():
            self._set_status("Scope filter is unavailable because scope is empty.")
            return
        filters = self.store.view_filters()
        filters.show_out_of_scope = not filters.show_out_of_scope
        self.store.set_view_filters(filters)
        state = "all traffic" if filters.show_out_of_scope else "in-scope only"
        self._reset_visible_entry_navigation()
        self._set_status(f"Scope view: {state}.")

    def _add_selected_host_to_scope(self, entry: TrafficEntry | None) -> None:
        if entry is None:
            self._set_status("Select a flow first.")
            return
        host = TrafficStore._normalize_scope_pattern(
            entry.request.host or entry.summary_host
        )
        if not host or host == "*":
            self._set_status("Selected flow does not have a usable host.")
            return
        current = self.store.scope_hosts()
        if host in current:
            self._set_status(f"{host} is already in scope.")
            return
        self.store.set_scope_hosts([*current, host])
        self._set_status(f"Added {host} to scope.")

    def _toggle_intercept_mode(self) -> None:
        if self.active_tab != 1:
            return
        current_mode = self.store.intercept_mode()
        modes = ["off", "request", "response", "both"]
        next_mode = modes[(modes.index(current_mode) + 1) % len(modes)]
        self.store.set_intercept_mode(next_mode)
        self._set_status(f"Intercept mode: {next_mode}.")

    def _footer_text(
        self, width: int, selected_pending: PendingInterceptionView | None
    ) -> str:
        visible_width = max(1, width - 1)
        wrap_label = f"{self._binding_label('toggle_word_wrap')} wrap:{'on' if self.word_wrap_enabled else 'off'}"
        scope_hosts = self.store.scope_hosts()
        state = (
            "all" if self.store.view_filters().show_out_of_scope else "in"
        ) if scope_hosts else ""

        def _build_footer(compact: bool) -> tuple[str, list[FooterClickAction]]:
            sep = "|" if compact else " | "
            builder = FooterBuilder()
            if compact:
                builder.append("q", "quit")
                builder.append(sep)
                if not self._is_inspect_tab():
                    builder.append("h", "pane_left")
                    builder.append(sep)
                    builder.append("l", "pane_right")
                    builder.append(sep)
                builder.append("k", "move_up")
                builder.append(sep)
                builder.append("j", "move_down")
                if not self.word_wrap_enabled:
                    builder.append(sep)
                    builder.append("H", "pan_left")
                    builder.append(sep)
                    builder.append("L", "pan_right")
                builder.append(sep)
                builder.append(wrap_label, "toggle_word_wrap")
                builder.append(sep)
                builder.append("tab", "tab_switch")
                builder.append(sep)
            else:
                builder.append(" q quit ", "quit")
                builder.append("| ")
                if not self._is_inspect_tab():
                    builder.append("h pane", "pane_left")
                    builder.append(" | ")
                    builder.append("l pane", "pane_right")
                    builder.append(" | ")
                builder.append("k up", "move_up")
                builder.append(" | ")
                builder.append("j down", "move_down")
                if not self.word_wrap_enabled:
                    builder.append(" | ")
                    builder.append("H pan", "pan_left")
                    builder.append(" | ")
                    builder.append("L pan", "pan_right")
                builder.append(" | ")
                builder.append(wrap_label, "toggle_word_wrap")
                builder.append(" | ")
                builder.append("tab switch", "tab_switch")
                builder.append(" | ")

            if self.active_tab == 1:
                if compact:
                    builder.append(f"{self._binding_label('toggle_intercept_mode')} int", "toggle_intercept_mode")
                    builder.append(sep)
                    builder.append(f"{self._binding_label('save_project')} save", "save_project")
                    builder.append(sep)
                    builder.append(f"{self._binding_label('open_export')} exp", "open_export")
                else:
                    builder.append(
                        f"{self._binding_label('toggle_intercept_mode')} intercept mode | ",
                        "toggle_intercept_mode",
                    )
                    builder.append(
                        f"{self._binding_label('save_project')} save | ", "save_project"
                    )
                    builder.append(
                        f"{self._binding_label('open_export')} export ", "open_export"
                    )
                intercept_items = self.store.interception_history()
                selected_intercept = self._selected_intercept_item(intercept_items)
                if selected_pending is not None:
                    builder.append(sep if compact else "| ")
                    builder.append(f"{self._binding_label('edit_item')} edit", "edit_item")
                    builder.append(sep if compact else " | ")
                    builder.append(f"{self._binding_label('forward_send')} send", "forward_send")
                    builder.append(sep if compact else " | ")
                    builder.append(f"{self._binding_label('drop_item')} drop", "drop_item")
                if selected_intercept is not None:
                    builder.append(sep if compact else " | ")
                    builder.append(
                        f"{self._binding_label('toggle_body_view')} raw",
                        "toggle_body_view",
                    )
            elif self.active_tab == 2:
                if compact:
                    builder.append(f"prev:{self._binding_label('repeater_prev_session')}", "repeater_prev_session")
                    builder.append(sep)
                    builder.append(f"next:{self._binding_label('repeater_next_session')}", "repeater_next_session")
                    builder.append(sep)
                    builder.append(f"{self._binding_label('load_repeater')} new", "load_repeater")
                    builder.append(sep)
                    builder.append(f"{self._binding_label('open_export')} exp", "open_export")
                    builder.append(sep)
                    builder.append(f"{self._binding_label('edit_item')} edit", "edit_item")
                    builder.append(sep)
                    builder.append(f"{self._binding_label('forward_send')} send", "forward_send")
                    if self.active_pane in {"repeater_request", "repeater_response"}:
                        builder.append(sep)
                        builder.append(f"{self._binding_label('toggle_body_view')} raw", "toggle_body_view")
                        builder.append(sep)
                        builder.append(f"{self._binding_label('open_expand')} expnd", "open_expand")
                else:
                    builder.append("prev:")
                    builder.append(
                        self._binding_label("repeater_prev_session"),
                        "repeater_prev_session",
                    )
                    builder.append(" next:")
                    builder.append(
                        self._binding_label("repeater_next_session"),
                        "repeater_next_session",
                    )
                    builder.append(" | ")
                    builder.append(
                        f"{self._binding_label('load_repeater')} new repeater | ",
                        "load_repeater",
                    )
                    builder.append(
                        f"{self._binding_label('open_export')} export | ", "open_export"
                    )
                    builder.append(
                        f"{self._binding_label('edit_item')} edit req | ", "edit_item"
                    )
                    builder.append(
                        f"{self._binding_label('forward_send')} send", "forward_send"
                    )
                    if self.active_pane in {"repeater_request", "repeater_response"}:
                        builder.append(" | ")
                        builder.append(
                            f"{self._binding_label('toggle_body_view')} raw/pretty | ",
                            "toggle_body_view",
                        )
                        builder.append(
                            f"{self._binding_label('open_expand')} expand ",
                            "open_expand",
                        )
            elif self.active_tab == 3:
                if compact:
                    builder.append(f"{self._binding_label('add_scope_host')} scope", "add_scope_host")
                    builder.append(sep)
                    builder.append(f"{self._binding_label('load_repeater')} rep", "load_repeater")
                    builder.append(sep)
                    builder.append(f"{self._binding_label('open_export')} exp", "open_export")
                    if self.active_pane in {"sitemap_request", "sitemap_response"}:
                        builder.append(sep)
                        builder.append(f"{self._binding_label('toggle_body_view')} raw", "toggle_body_view")
                        builder.append(sep)
                        builder.append(f"{self._binding_label('open_expand')} expnd", "open_expand")
                    builder.append(sep)
                    builder.append("Pg page")
                else:
                    builder.append(
                        f"{self._binding_label('add_scope_host')} add scope | ",
                        "add_scope_host",
                    )
                    builder.append(
                        f"{self._binding_label('load_repeater')} to repeater | ",
                        "load_repeater",
                    )
                    builder.append(
                        f"{self._binding_label('open_export')} export | ",
                        "open_export",
                    )
                    if self.active_pane in {"sitemap_request", "sitemap_response"}:
                        builder.append(
                            f"{self._binding_label('toggle_body_view')} raw/pretty | ",
                            "toggle_body_view",
                        )
                        builder.append(
                            f"{self._binding_label('open_expand')} expand | ",
                            "open_expand",
                        )
                    builder.append("PgUp/PgDn page ")
            elif self.active_tab == 4:
                if compact:
                    builder.append(f"{self._binding_label('save_project')} save", "save_project")
                    builder.append(sep)
                    builder.append(f"{self._binding_label('edit_match_replace')} rule", "edit_match_replace")
                    builder.append(sep)
                    builder.append(f"{self._binding_label('edit_item')} edit", "edit_item")
                    builder.append(sep)
                    builder.append(f"{self._binding_label('drop_item')} del", "drop_item")
                else:
                    builder.append(
                        f"{self._binding_label('save_project')} save | ", "save_project"
                    )
                    builder.append(
                        f"{self._binding_label('edit_match_replace')} new rule | ",
                        "edit_match_replace",
                    )
                    builder.append(
                        f"{self._binding_label('edit_item')} edit rule | ", "edit_item"
                    )
                    builder.append(
                        f"{self._binding_label('drop_item')} delete rule ", "drop_item"
                    )
            elif self.active_tab == 5:
                if compact:
                    builder.append(f"{self._binding_label('save_project')} save", "save_project")
                    builder.append(sep)
                    builder.append(f"{self._binding_label('add_scope_host')} scope", "add_scope_host")
                    builder.append(sep)
                    builder.append(f"{self._binding_label('open_export')} exp", "open_export")
                    if self.active_pane in {"http_request", "http_response"}:
                        builder.append(sep)
                        builder.append(f"{self._binding_label('toggle_body_view')} raw", "toggle_body_view")
                        builder.append(sep)
                        builder.append(f"{self._binding_label('open_expand')} expnd", "open_expand")
                    builder.append(sep)
                    builder.append("Pg page")
                else:
                    builder.append(
                        f"{self._binding_label('save_project')} save | ", "save_project"
                    )
                    builder.append(
                        f"{self._binding_label('add_scope_host')} add scope | ",
                        "add_scope_host",
                    )
                    builder.append(
                        f"{self._binding_label('open_export')} export | ", "open_export"
                    )
                    if self.active_pane in {"http_request", "http_response"}:
                        builder.append(
                            f"{self._binding_label('toggle_body_view')} raw/pretty | ",
                            "toggle_body_view",
                        )
                        builder.append(
                            f"{self._binding_label('open_expand')} expand | ",
                            "open_expand",
                        )
                    builder.append("PgUp/PgDn page ")
            elif self._is_inspect_tab():
                if compact:
                    builder.append(f"{self._binding_label('back')} back", "back")
                    builder.append(sep)
                    builder.append(f"{self._binding_label('toggle_body_view')} raw", "toggle_body_view")
                    builder.append(sep)
                    builder.append(f"{self._binding_label('open_expand')} switch", "open_expand")
                    builder.append(sep)
                    builder.append("Pg page")
                else:
                    builder.append(
                        f"{self._binding_label('back')} back | ",
                        "back",
                    )
                    builder.append(
                        f"{self._binding_label('toggle_body_view')} raw/pretty | ",
                        "toggle_body_view",
                    )
                    builder.append(
                        f"{self._binding_label('open_expand')} switch req/resp | ",
                        "open_expand",
                    )
                    builder.append("PgUp/PgDn page ")
            elif self._is_export_tab():
                if compact:
                    builder.append(f"{self._binding_label('forward_send')} copy", "forward_send")
                    builder.append(sep)
                    builder.append("Enter", "activate")
                    builder.append(sep)
                    builder.append(f"{self._binding_label('open_export')} refresh", "open_export")
                else:
                    builder.append(
                        f"{self._binding_label('forward_send')} copy | ",
                        "forward_send",
                    )
                    builder.append("Enter copy", "activate")
                    builder.append(" | ")
                    builder.append(
                        f"{self._binding_label('open_export')} refresh export ",
                        "open_export",
                    )
            elif self._is_settings_tab():
                builder.append(
                    f"{self._binding_label('edit_item')} run/edit | ", "edit_item"
                )
                builder.append("Enter run/edit", "activate")
            elif self._is_scope_tab():
                builder.append(
                    f"{self._binding_label('edit_item')} add/edit | ", "edit_item"
                )
                builder.append("Enter add/edit", "activate")
                builder.append(" | ")
                builder.append(
                    f"{self._binding_label('drop_item')} delete/clear ", "drop_item"
                )
            elif self._is_filters_tab():
                builder.append(
                    f"{self._binding_label('edit_item')} toggle/edit | ", "edit_item"
                )
                builder.append("Enter toggle/edit", "activate")
                builder.append(" | ")
                builder.append(
                    f"{self._binding_label('drop_item')} clear/reset ", "drop_item"
                )
            elif self._is_keybindings_tab():
                builder.append(
                    f"{self._binding_label('edit_item')} rebind | ", "edit_item"
                )
                builder.append("Enter rebind", "activate")
                if self.keybinding_capture_action is not None:
                    builder.append(" | Esc cancel ")
            elif self._is_rule_builder_tab():
                builder.append(
                    f"{self._binding_label('edit_item')} edit field | ", "edit_item"
                )
                builder.append(
                    f"{self._binding_label('forward_send')} create rule | ",
                    "forward_send",
                )
                builder.append(
                    f"{self._binding_label('drop_item')} cancel ", "drop_item"
                )
            elif self._is_theme_builder_tab():
                builder.append(
                    f"{self._binding_label('edit_item')} edit field | ", "edit_item"
                )
                builder.append(
                    f"{self._binding_label('forward_send')} save theme | ",
                    "forward_send",
                )
                builder.append(
                    f"{self._binding_label('drop_item')} cancel ", "drop_item"
                )
            elif self._is_findings_tab():
                builder.append(
                    f"{self._binding_label('open_export')} export | ",
                    "open_export",
                )
                builder.append(
                    "m toggle risk flag",
                    "toggle_findings_flag",
                )
            elif self._is_plugin_workspace_tab():
                builder.append(
                    "plugin workspace "
                )
            else:
                builder.append(
                    f"{self._binding_label('save_project')} save | ", "save_project"
                )
                builder.append(
                    f"{self._binding_label('add_scope_host')} add scope ", "add_scope_host"
                )

            if self.active_tab in {0, 3, 4, 5} and scope_hosts and not compact:
                builder.append(" | ")
                builder.append(
                    self._binding_label("toggle_scope_view"), "toggle_scope_view"
                )
                builder.append(f" scope:{state}")

            builder.append(sep if compact else "| ")
            builder.append(
                (f"{self._binding_label('open_settings')} set" if compact else f"{self._binding_label('open_settings')} settings "),
                "open_settings",
            )
            return builder.text, builder.actions

        base_line, base_actions = _build_footer(compact=False)
        visible_width = max(1, width - 1)
        if self.status_message and monotonic() < self.status_until:
            line_with_status = f"{base_line}| {self.status_message}"
            trimmed, trimmed_actions = self._trim_footer_line(
                line_with_status, visible_width, base_actions
            )
            self._footer_click_actions = trimmed_actions
            self._last_footer_line = trimmed
            return trimmed
        if len(base_line) > visible_width:
            base_line, base_actions = _build_footer(compact=True)
        trimmed, trimmed_actions = self._trim_footer_line(
            base_line, visible_width, base_actions
        )
        self._footer_click_actions = trimmed_actions
        self._last_footer_line = trimmed
        return trimmed

    def _clamp_footer_actions(
        self, actions: list[FooterClickAction], width: int
    ) -> list[FooterClickAction]:
        clamped: list[FooterClickAction] = []
        limit = max(0, width)
        for action in actions:
            if action.start >= limit:
                continue
            length = min(action.length, limit - action.start)
            if length <= 0:
                continue
            clamped.append(
                FooterClickAction(action.start, length, action.action)
            )
        return clamped

    def _trim_footer_line(
        self,
        text: str,
        width: int,
        actions: list[FooterClickAction],
    ) -> tuple[str, list[FooterClickAction]]:
        trimmed = self._trim(text, width)
        return trimmed, self._clamp_footer_actions(actions, len(trimmed))

    def _render_footer_line(
        self,
        stdscr,
        height: int,
        width: int,
        selected_pending: PendingInterceptionView | None,
    ) -> None:
        y = max(0, height - 1)
        footer_line = self._footer_text(width, selected_pending)
        line_width = max(1, width - 1)
        stdscr.addnstr(
            y,
            0,
            footer_line.ljust(line_width),
            line_width,
            self._chrome_attr(),
        )
        for action in self._footer_click_actions:
            region_width = min(action.length, max(0, line_width - action.start))
            if region_width <= 0:
                continue
            self._register_clickable_region(
                "footer_action",
                action.start,
                y,
                region_width,
                payload=action.action,
            )
        if self._mouse_cursor_y != y:
            return
        for action in self._footer_click_actions:
            start = action.start
            length = min(action.length, max(0, line_width - start))
            if length <= 0:
                continue
            if (
                self._mouse_cursor_x >= start
                and self._mouse_cursor_x < start + length
            ):
                highlight_text = footer_line[start : start + length]
                stdscr.addnstr(y, start, highlight_text, length, curses.A_REVERSE)
                break

    def _register_clickable_region(
        self,
        action: str,
        x: int,
        y: int,
        width: int,
        height: int = 1,
        payload: object | None = None,
    ) -> None:
        if width <= 0 or height <= 0:
            return
        self._clickable_regions.append(
            ClickableRegion(action=action, x=x, y=y, width=width, height=height, payload=payload)
        )

    def _find_clickable_region(self, x: int, y: int) -> ClickableRegion | None:
        for region in reversed(self._clickable_regions):
            if region.x <= x < region.x + region.width and region.y <= y < region.y + region.height:
                return region
        return None

    def _region_identifier(self, region: ClickableRegion) -> tuple[str, int, int, int, int, object | None]:
        return (region.action, region.x, region.y, region.width, region.height, region.payload)

    def _is_mouse_over(self, x: int, y: int, width: int, height: int = 1) -> bool:
        if self._mouse_cursor_x < 0 or self._mouse_cursor_y < 0:
            return False
        if width <= 0 or height <= 0:
            return False
        return (
            x <= self._mouse_cursor_x < x + width
            and y <= self._mouse_cursor_y < y + height
        )

    def _handle_mouse_event(
        self,
        stdscr,
        entries: list[TrafficEntry],
        selected: TrafficEntry | None,
        selected_intercept: PendingInterceptionView | None,
        selected_pending: PendingInterceptionView | None,
        intercept_items: list[PendingInterceptionView],
    ) -> bool:
        try:
            _, x, y, _, bstate = curses.getmouse()
        except curses.error:
            return False
        self._mouse_cursor_x = x
        self._mouse_cursor_y = y
        motion_mask = getattr(curses, "REPORT_MOUSE_POSITION", 0)
        if motion_mask and (bstate & motion_mask):
            return False

        wheel_up = getattr(curses, "BUTTON4_PRESSED", 0)
        wheel_down = getattr(curses, "BUTTON5_PRESSED", 0)
        if wheel_up and (bstate & wheel_up):
            region = self._find_clickable_region(x, y)
            if region is not None:
                self._apply_mouse_focus_region(region)
            for _ in range(3):
                self.execute_action(
                    stdscr,
                    "move_up",
                    entries,
                    selected,
                    selected_intercept,
                    selected_pending,
                )
            return False
        if wheel_down and (bstate & wheel_down):
            region = self._find_clickable_region(x, y)
            if region is not None:
                self._apply_mouse_focus_region(region)
            for _ in range(3):
                self.execute_action(
                    stdscr,
                    "move_down",
                    entries,
                    selected,
                    selected_intercept,
                    selected_pending,
                )
            return False

        actionable_buttons = (
            curses.BUTTON1_CLICKED
            | curses.BUTTON1_DOUBLE_CLICKED
            | curses.BUTTON1_TRIPLE_CLICKED
            | curses.BUTTON1_RELEASED
        )
        if not (bstate & actionable_buttons):
            return False
        region = self._find_clickable_region(x, y)
        if region is None:
            return False
        current_time = monotonic()
        region_id = self._region_identifier(region)
        is_double_click = (
            self._last_mouse_region == region_id
            and current_time - self._last_mouse_click_time <= 0.4
        )
        self._last_mouse_click_time = current_time
        self._last_mouse_region = region_id
        return bool(self._activate_clickable_region(
            region,
            stdscr,
            entries,
            selected,
            selected_intercept,
            selected_pending,
            intercept_items,
            double_click=is_double_click,
        ))

    def _apply_mouse_focus_region(self, region: ClickableRegion) -> None:
        if region.action == "focus_pane":
            pane = str(region.payload) if region.payload is not None else ""
            if pane:
                self.active_pane = pane
            return
        if region.action in {"flow_row", "intercept_row"}:
            self.active_pane = "flows"
            return
        mapping = {
            "repeater_history_row": "repeater_history",
            "settings_menu_row": "settings_menu",
            "scope_menu_row": "scope_menu",
            "filters_menu_row": "filters_menu",
            "keybindings_menu_row": "keybindings_menu",
            "rule_builder_menu_row": "rule_builder_menu",
            "theme_builder_menu_row": "theme_builder_menu",
            "export_menu_row": "export_menu",
            "plugin_workspace_menu_row": "plugin_workspace_menu",
            "findings_row": "findings_list",
        }
        pane = mapping.get(region.action)
        if pane:
            self.active_pane = pane

    def _activate_clickable_region(
        self,
        region: ClickableRegion,
        stdscr,
        entries: list[TrafficEntry],
        selected: TrafficEntry | None,
        selected_intercept: PendingInterceptionView | None,
        selected_pending: PendingInterceptionView | None,
        intercept_items: list[PendingInterceptionView],
        double_click: bool = False,
    ) -> bool:
        if region.action == "focus_pane":
            pane = str(region.payload) if region.payload is not None else ""
            if pane:
                self.active_pane = pane
            if double_click and pane:
                self._execute_bound_action(
                    stdscr,
                    "open_expand",
                    entries,
                    selected,
                    selected_intercept,
                    selected_pending,
                )
            return False
        if region.action == "flow_row":
            if not entries:
                return False
            index = int(region.payload) if isinstance(region.payload, int) else 0
            self.selected_index = max(0, min(len(entries) - 1, index))
            self.active_pane = "flows"
            return False
        if region.action == "intercept_row":
            if not intercept_items:
                return False
            index = int(region.payload) if isinstance(region.payload, int) else 0
            self.intercept_selected_index = max(
                0, min(len(intercept_items) - 1, index)
            )
            self.active_pane = "flows"
            return False
        if region.action == "findings_row":
            index = int(region.payload) if isinstance(region.payload, int) else 0
            self._set_findings_active_scroll(index, len(self._last_findings))
            self.active_pane = "findings_list"
            return False
        if region.action == "repeater_history_row":
            session = self._current_repeater_session()
            if session is None:
                return False
            index = int(region.payload) if isinstance(region.payload, int) else 0
            session.selected_exchange_index = index
            self._sync_repeater_history_selection(session)
            self.active_pane = "repeater_history"
            return False
        if region.action == "plugin_workspace_menu_row":
            workspace = self._current_plugin_workspace()
            if workspace is None:
                return
            panels = self.plugin_manager.panel_contributions(workspace.workspace_id)
            if not panels:
                return
            index = int(region.payload) if isinstance(region.payload, int) else 0
            index = max(0, min(len(panels) - 1, index))
            self.plugin_workspace_selected_index[workspace.workspace_id] = index
            self.active_pane = "plugin_workspace_menu"
            return
        if region.action == "settings_menu_row":
            items = self._settings_items()
            if not items:
                return
            index = int(region.payload) if isinstance(region.payload, int) else 0
            self.settings_selected_index = max(0, min(len(items) - 1, index))
            self.active_pane = "settings_menu"
            self._execute_bound_action(
                stdscr,
                "forward_send",
                entries,
                selected,
                selected_intercept,
                selected_pending,
            )
            return
        if region.action == "scope_menu_row":
            items = self._scope_items()
            if not items:
                return
            index = int(region.payload) if isinstance(region.payload, int) else 0
            self.scope_selected_index = max(0, min(len(items) - 1, index))
            self.active_pane = "scope_menu"
            self._execute_bound_action(
                stdscr,
                "forward_send",
                entries,
                selected,
                selected_intercept,
                selected_pending,
            )
            return
        if region.action == "filters_menu_row":
            items = self._filter_items()
            if not items:
                return
            index = int(region.payload) if isinstance(region.payload, int) else 0
            self.filters_selected_index = max(0, min(len(items) - 1, index))
            self.active_pane = "filters_menu"
            self._execute_bound_action(
                stdscr,
                "forward_send",
                entries,
                selected,
                selected_intercept,
                selected_pending,
            )
            return
        if region.action == "keybindings_menu_row":
            items = self._keybinding_items()
            if not items:
                return
            index = int(region.payload) if isinstance(region.payload, int) else 0
            self.keybindings_selected_index = max(0, min(len(items) - 1, index))
            self.active_pane = "keybindings_menu"
            self._execute_bound_action(
                stdscr,
                "forward_send",
                entries,
                selected,
                selected_intercept,
                selected_pending,
            )
            return
        if region.action == "rule_builder_menu_row":
            items = self._rule_builder_items()
            if not items:
                return
            index = int(region.payload) if isinstance(region.payload, int) else 0
            self.rule_builder_selected_index = max(0, min(len(items) - 1, index))
            self.active_pane = "rule_builder_menu"
            self._execute_bound_action(
                stdscr,
                "forward_send",
                entries,
                selected,
                selected_intercept,
                selected_pending,
            )
            return
        if region.action == "theme_builder_menu_row":
            items = self._theme_builder_items()
            if not items:
                return
            index = int(region.payload) if isinstance(region.payload, int) else 0
            self.theme_builder_selected_index = max(0, min(len(items) - 1, index))
            self.active_pane = "theme_builder_menu"
            self._execute_bound_action(
                stdscr,
                "forward_send",
                entries,
                selected,
                selected_intercept,
                selected_pending,
            )
            return
        if region.action == "export_menu_row":
            items = self._export_format_items()
            if not items:
                return False
            index = int(region.payload) if isinstance(region.payload, int) else 0
            self.export_selected_index = max(0, min(len(items) - 1, index))
            self.active_pane = "export_menu"
            self._execute_bound_action(
                stdscr,
                "forward_send",
                entries,
                selected,
                selected_intercept,
                selected_pending,
            )
            return False
        if region.action == "open_url":
            url = str(region.payload) if region.payload is not None else ""
            if not url:
                return False
            try:
                opened = webbrowser.open(url, new=2)
            except Exception as exc:
                self._set_status(f"Open URL failed: {exc}")
                return False
            if opened:
                self._set_status(f"Opened: {url}")
            else:
                self._set_status(f"Could not open: {url}")
            return False
        if region.action == "quit":
            return self.execute_action(
                stdscr,
                "quit",
                entries,
                selected,
                selected_intercept,
                selected_pending,
            )
        if region.action == "footer_action":
            action_name = str(region.payload) if region.payload is not None else ""
            if action_name:
                if self.execute_action(
                    stdscr,
                    action_name,
                    entries,
                    selected,
                    selected_intercept,
                    selected_pending,
                ):
                    return True
            return False
        return False

    def execute_action(
        self,
        stdscr,
        action: str,
        entries: list[TrafficEntry],
        selected: TrafficEntry | None,
        selected_intercept: PendingInterceptionView | None,
        selected_pending: PendingInterceptionView | None,
    ) -> bool:
        action_name = str(action).strip()
        if not action_name:
            return False

        if action_name == "quit":
            return bool(self._handle_quit_sequence(stdscr))

        if action_name == "pane_left":
            if self._is_inspect_tab():
                self._inspect_toggle_mode()
            elif self.active_tab == 5:
                self._move_http_focus(-1)
            elif self.active_tab == 2:
                self._move_repeater_focus(-1)
            elif self.active_tab == 3:
                self._move_sitemap_focus(-1)
            elif self._is_export_tab():
                self._move_export_focus(-1)
            elif self._is_settings_tab():
                self._move_settings_focus(-1)
            elif self._is_scope_tab():
                self._move_scope_focus(-1)
            elif self._is_filters_tab():
                self._move_filters_focus(-1)
            elif self._is_keybindings_tab():
                self._move_keybindings_focus(-1)
            elif self._is_rule_builder_tab():
                self._move_rule_builder_focus(-1)
            elif self._is_theme_builder_tab():
                self._move_theme_builder_focus(-1)
            elif self._is_plugin_workspace_tab():
                self._move_plugin_workspace_focus(-1)
            elif self._is_findings_tab():
                self._move_findings_focus(-1)
            else:
                self.active_pane = "flows"
            return False

        if action_name == "pane_right":
            if self._is_inspect_tab():
                self._inspect_toggle_mode()
            elif self.active_tab == 5:
                self._move_http_focus(1)
            elif self.active_tab == 2:
                self._move_repeater_focus(1)
            elif self.active_tab == 3:
                self._move_sitemap_focus(1)
            elif self._is_export_tab():
                self._move_export_focus(1)
            elif self._is_settings_tab():
                self._move_settings_focus(1)
            elif self._is_scope_tab():
                self._move_scope_focus(1)
            elif self._is_filters_tab():
                self._move_filters_focus(1)
            elif self._is_keybindings_tab():
                self._move_keybindings_focus(1)
            elif self._is_rule_builder_tab():
                self._move_rule_builder_focus(1)
            elif self._is_theme_builder_tab():
                self._move_theme_builder_focus(1)
            elif self._is_plugin_workspace_tab():
                self._move_plugin_workspace_focus(1)
            elif self._is_findings_tab():
                self._move_findings_focus(1)
            else:
                self.active_pane = "detail"
            return False

        if action_name == "move_up":
            self._move_active_pane(-1, len(entries))
            return False

        if action_name == "move_down":
            self._move_active_pane(1, len(entries))
            return False

        if action_name == "pan_left":
            self._scroll_horizontal_active_pane(-8)
            return False

        if action_name == "pan_right":
            self._scroll_horizontal_active_pane(8)
            return False

        if action_name == "page_down":
            if self._is_inspect_tab():
                self._set_inspect_active_scroll(
                    self.inspect_scroll + (self._inspect_page_rows(stdscr) or 1)
                )
            elif self.active_tab == 5:
                self._scroll_http_active_pane(self._http_page_rows(stdscr) or 1, len(entries))
            elif self.active_tab == 2:
                self._scroll_repeater_active_pane(self._repeater_page_rows(stdscr) or 1)
            elif self.active_tab == 3:
                self._scroll_sitemap_active_pane(self._sitemap_page_rows(stdscr) or 1, entries)
            elif self._is_export_tab():
                self._scroll_export_active_pane(self._export_page_rows(stdscr) or 1)
            elif self._is_settings_tab():
                self._scroll_settings_active_pane(self._settings_page_rows(stdscr) or 1)
            elif self._is_scope_tab():
                self._scroll_scope_active_pane(self._scope_page_rows(stdscr) or 1)
            elif self._is_filters_tab():
                self._scroll_filters_active_pane(self._filters_page_rows(stdscr) or 1)
            elif self._is_keybindings_tab():
                self._scroll_keybindings_active_pane(self._keybindings_page_rows(stdscr) or 1)
            elif self._is_rule_builder_tab():
                self._scroll_rule_builder_active_pane(self._rule_builder_page_rows(stdscr) or 1)
            elif self._is_theme_builder_tab():
                self._scroll_theme_builder_active_pane(self._theme_builder_page_rows(stdscr) or 1)
            elif self._is_plugin_workspace_tab():
                self._scroll_plugin_workspace_active_pane(self._keybindings_page_rows(stdscr) or 1)
            elif self._is_findings_tab():
                self._scroll_findings_active_pane(self._findings_page_rows(stdscr) or 1)
            else:
                self._scroll_detail(self.detail_page_rows or 1)
            return False

        if action_name == "page_up":
            if self._is_inspect_tab():
                self._set_inspect_active_scroll(
                    self.inspect_scroll - (self._inspect_page_rows(stdscr) or 1)
                )
            elif self.active_tab == 5:
                self._scroll_http_active_pane(-(self._http_page_rows(stdscr) or 1), len(entries))
            elif self.active_tab == 2:
                self._scroll_repeater_active_pane(-(self._repeater_page_rows(stdscr) or 1))
            elif self.active_tab == 3:
                self._scroll_sitemap_active_pane(-(self._sitemap_page_rows(stdscr) or 1), entries)
            elif self._is_export_tab():
                self._scroll_export_active_pane(-(self._export_page_rows(stdscr) or 1))
            elif self._is_settings_tab():
                self._scroll_settings_active_pane(-(self._settings_page_rows(stdscr) or 1))
            elif self._is_scope_tab():
                self._scroll_scope_active_pane(-(self._scope_page_rows(stdscr) or 1))
            elif self._is_filters_tab():
                self._scroll_filters_active_pane(-(self._filters_page_rows(stdscr) or 1))
            elif self._is_keybindings_tab():
                self._scroll_keybindings_active_pane(-(self._keybindings_page_rows(stdscr) or 1))
            elif self._is_rule_builder_tab():
                self._scroll_rule_builder_active_pane(-(self._rule_builder_page_rows(stdscr) or 1))
            elif self._is_theme_builder_tab():
                self._scroll_theme_builder_active_pane(-(self._theme_builder_page_rows(stdscr) or 1))
            elif self._is_plugin_workspace_tab():
                self._scroll_plugin_workspace_active_pane(-(self._keybindings_page_rows(stdscr) or 1))
            elif self._is_findings_tab():
                self._scroll_findings_active_pane(-(self._findings_page_rows(stdscr) or 1))
            else:
                self._scroll_detail(-(self.detail_page_rows or 1))
            return False

        if action_name == "activate":
            if self._is_export_tab():
                self._copy_selected_export()
            elif self.active_tab == 4:
                self._edit_selected_match_replace_rule()
            elif self._is_settings_tab():
                self._activate_settings_item(stdscr)
            elif self._is_scope_tab():
                self._activate_scope_item(stdscr)
            elif self._is_filters_tab():
                self._activate_filter_item(stdscr)
            elif self._is_keybindings_tab():
                self._activate_keybinding_item()
            elif self._is_rule_builder_tab():
                self._activate_rule_builder_item(stdscr)
            elif self._is_theme_builder_tab():
                self._activate_theme_builder_item(stdscr)
            return False

        if action_name == "toggle_findings_flag":
            self._toggle_findings_flag(self._selected_findings_finding(self._last_findings))
            return False

        self._execute_bound_action(stdscr, action_name, entries, selected, selected_intercept, selected_pending)
        return False

    def _visible_flow_entries(
        self, entries: list[TrafficEntry], rows: int
    ) -> tuple[int, list[TrafficEntry]]:
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

    def _layout_key_for_tab(self) -> str | None:
        if self._is_plugin_workspace_tab():
            return "plugin"
        if 0 <= self.active_tab < len(self.TABS):
            builtin_key = BUILTIN_WORKSPACE_IDS[self.active_tab]
            if builtin_key in self._workspace_layouts:
                return builtin_key
        return None

    def _split_horizontal(self, width: int, layout_key: str) -> tuple[int, int]:
        available = max(width - 2, 0)
        config = self._workspace_layouts.get(layout_key)
        if config is None:
            primary = max(28, width // 3)
            primary = min(primary, available)
            return primary, max(available - primary, 0)
        ratio = self.workspace_horizontal_ratios.get(config.horizontal_ratio_key, 0.33)
        primary, secondary = config.horizontal_layout.partition(available, ratio)
        total = max(available, 1)
        self.workspace_horizontal_ratios[config.horizontal_ratio_key] = primary / total
        return primary, secondary

    def _split_vertical(self, height: int, layout_key: str) -> tuple[int, int]:
        config = self._workspace_layouts.get(layout_key)
        if (
            config is None
            or config.vertical_layout is None
            or config.vertical_ratio_key is None
        ):
            primary = max(5, height // 2)
            primary = min(primary, max(height, 0))
            return primary, max(height - primary, 0)
        ratio = self.workspace_vertical_ratios.get(config.vertical_ratio_key, 0.5)
        primary, secondary = config.vertical_layout.partition(height, ratio)
        total = max(height, 1)
        self.workspace_vertical_ratios[config.vertical_ratio_key] = primary / total
        return primary, secondary

    def _workspace_layout_context(self) -> WorkspacePanelLayout | None:
        key = self._layout_key_for_tab()
        if key is None:
            return None
        return self._workspace_layouts.get(key)

    def _adjust_layout_horizontal(self, delta: float) -> None:
        context = self._workspace_layout_context()
        if context is None:
            self._set_status(
                "Layout adjustments only work inside multi-panel workspaces."
            )
            return
        ratio_key = context.horizontal_ratio_key
        current = self.workspace_horizontal_ratios.get(ratio_key, 0.33)
        updated = context.horizontal_layout.adjust_ratio(current, delta)
        self.workspace_horizontal_ratios[ratio_key] = updated
        percent = round(updated * 100)
        self._set_status(
            f"{context.horizontal_label} is now {percent}% of {context.workspace_label} width."
        )

    def _adjust_layout_vertical(self, delta: float) -> None:
        context = self._workspace_layout_context()
        if (
            context is None
            or context.vertical_layout is None
            or context.vertical_ratio_key is None
        ):
            self._set_status(
                "Vertical layout adjustments only work inside stacked-pane workspaces."
            )
            return
        ratio_key = context.vertical_ratio_key
        current = self.workspace_vertical_ratios.get(ratio_key, 0.5)
        updated = context.vertical_layout.adjust_ratio(current, delta)
        self.workspace_vertical_ratios[ratio_key] = updated
        percent = round(updated * 100)
        self._set_status(
            f"{context.vertical_label} is now {percent}% of {context.workspace_label} height."
        )

    def _plugin_workspace_keybindings(self) -> list[PluginKeybindingContribution]:
        items: list[PluginKeybindingContribution] = []
        for workspace in self._plugin_workspaces():
            if not workspace.shortcut:
                continue
            items.append(
                PluginKeybindingContribution(
                    plugin_id=workspace.plugin_id,
                    action=f"open_plugin_workspace:{workspace.workspace_id}",
                    key=workspace.shortcut,
                    description=f"Open the {workspace.label} workspace",
                    handler=lambda _context, workspace_id=workspace.workspace_id: (
                        self.open_workspace_by_id(workspace_id) or True
                    ),
                    section="Plugin Workspaces",
                )
            )
        return items

    def _plugin_keybinding_contributions(self) -> list[PluginKeybindingContribution]:
        return [
            *self._plugin_workspace_keybindings(),
            *self.plugin_manager.keybinding_contributions(),
        ]

    def _all_default_keybindings(self) -> dict[str, str]:
        bindings = dict(self.DEFAULT_KEYBINDINGS)
        for contribution in self._plugin_keybinding_contributions():
            bindings[contribution.action] = contribution.key
        return bindings

    def _all_keybinding_descriptions(self) -> dict[str, str]:
        descriptions = dict(self.KEYBINDING_DESCRIPTIONS)
        for contribution in self._plugin_keybinding_contributions():
            descriptions[contribution.action] = contribution.description
        return descriptions

    def _all_keybinding_sections(self) -> tuple[tuple[str, tuple[str, ...]], ...]:
        sections: list[tuple[str, tuple[str, ...]]] = list(self.KEYBINDING_SECTIONS)
        grouped: dict[str, list[str]] = {}
        for contribution in self._plugin_keybinding_contributions():
            grouped.setdefault(contribution.section, []).append(contribution.action)
        for section, actions in grouped.items():
            sections.append((section, tuple(actions)))
        return tuple(sections)

    def _current_keybindings(self) -> dict[str, str]:
        bindings = self._all_default_keybindings()
        bindings.update(self._custom_keybindings)
        return bindings

    def _entries_for_view(self) -> list[TrafficEntry]:
        return self.store.visible_entries()

    def _reset_visible_entry_navigation(self) -> None:
        self.selected_index = 0
        self.sitemap_selected_index = 0
        self.flow_x_scroll = 0
        self.sitemap_tree_scroll = 0
        self.sitemap_tree_x_scroll = 0

    def custom_keybindings(self) -> dict[str, str]:
        return dict(self._custom_keybindings)

    def _binding_key(self, action: str) -> str:
        defaults = self._all_default_keybindings()
        return self._current_keybindings().get(action, defaults[action])

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

    def _open_workspace(
        self,
        action: str,
        entries: list[TrafficEntry] | None = None,
        selected: TrafficEntry | None = None,
        selected_intercept: PendingInterceptionView | None = None,
    ) -> None:
        if action.startswith("open_plugin_workspace:"):
            self.open_workspace_by_id(action.split(":", 1)[1])
            return
        if action == "open_export":
            self._open_export_workspace(entries or [], selected, selected_intercept)
            return
        if action in {"open_request", "open_response"}:
            self.active_tab = self.TAB_ACTIONS[action]
            self.active_pane = (
                "http_request" if action == "open_request" else "http_response"
            )
            return
        if action == "open_inspect":
            self.inspect_return_tab = self.active_tab
            self.inspect_return_pane = self.active_pane
            self.active_tab = self.TAB_ACTIONS[action]
            self.active_pane = "inspect"
            return
        tab_index = self.TAB_ACTIONS[action]
        self.active_tab = tab_index
        if self._is_settings_tab():
            self.active_pane = "settings_menu"
            return
        if self._is_export_tab():
            self.active_pane = "export_menu"
            return
        if self._is_scope_tab():
            self.active_pane = "scope_menu"
            return
        if self._is_filters_tab():
            self.active_pane = "filters_menu"
            return
        if self._is_keybindings_tab():
            self.active_pane = "keybindings_menu"
            return
        self._sync_active_pane()

    def open_workspace_by_id(self, workspace_id: str) -> None:
        workspace_name = str(workspace_id).strip()
        if not workspace_name:
            return
        if workspace_name in BUILTIN_WORKSPACE_IDS:
            try:
                self.active_tab = BUILTIN_WORKSPACE_IDS.index(workspace_name)
            except ValueError:
                return
        else:
            tab_index = self._plugin_workspace_tab_index(workspace_name)
            if tab_index is None:
                return
            self.active_tab = tab_index
        self._sync_active_pane()

    def _cycle_tab(self) -> None:
        tabs = self._workspace_tabs()
        if not tabs:
            return
        self.active_tab = (self.active_tab + 1) % len(tabs)
        self._sync_active_pane()

    def _execute_bound_action(
        self,
        stdscr,
        action: str,
        entries: list[TrafficEntry],
        selected: TrafficEntry | None,
        selected_intercept: PendingInterceptionView | None,
        selected_pending: PendingInterceptionView | None,
    ) -> None:
        if action == "tab_switch":
            self._cycle_tab()
            return
        if action in self.TAB_ACTIONS:
            self._open_workspace(action, entries, selected, selected_intercept)
            return
        if action == "save_project":
            self._save_project(stdscr)
            return
        if action == "add_scope_host":
            if self.active_tab == 3:
                self._add_selected_host_to_scope(self._selected_sitemap_entry(entries))
            else:
                self._add_selected_host_to_scope(selected)
            return
        if action == "load_repeater":
            if self.active_tab == 3:
                self._load_repeater_from_selected_flow(self._selected_sitemap_entry(entries))
            else:
                self._load_repeater_from_selected_flow(selected)
            return
        if action == "edit_match_replace":
            self._edit_match_replace_rules(stdscr)
            return
        if action == "toggle_body_view":
            self._toggle_body_view_mode()
            return
        if action == "toggle_word_wrap":
            self._toggle_word_wrap()
            return
        if action == "toggle_scope_view":
            self._toggle_scope_view()
            return
        if action == "toggle_intercept_mode":
            self._toggle_intercept_mode()
            return
        if action == "open_expand":
            if self._is_inspect_tab():
                self._inspect_toggle_mode()
                return
            mode = self._expand_mode_for_active_pane()
            if mode is None:
                self._set_status("Focus the Request/Response pane first.")
                return
            self._open_inspector_workspace(
                mode,
                entries,
                selected,
                selected_intercept,
            )
            return
        if action == "back":
            self._back_from_inspector()
            return
        if action == "forward_send":
            if self.active_tab == 2:
                self._send_repeater_request()
            elif self._is_export_tab():
                self._copy_selected_export()
            elif self._is_settings_tab():
                self._activate_settings_item(stdscr)
            elif self._is_scope_tab():
                self._activate_scope_item(stdscr)
            elif self._is_filters_tab():
                self._activate_filter_item(stdscr)
            elif self._is_keybindings_tab():
                self._activate_keybinding_item()
            elif self._is_rule_builder_tab():
                self._commit_rule_builder_draft()
            elif self._is_theme_builder_tab():
                self._commit_theme_builder_draft()
            else:
                self._forward_intercepted_request(selected_pending)
            return
        if action == "drop_item":
            if self._is_rule_builder_tab():
                self._close_rule_builder_workspace("Rule builder cancelled.")
            elif self._is_theme_builder_tab():
                self._close_theme_builder_workspace(
                    "Theme builder cancelled.",
                    restore_preview=True,
                )
            elif self._is_scope_tab():
                self._clear_selected_scope_item()
            elif self._is_filters_tab():
                self._clear_selected_filter_item()
            elif self.active_tab == 4:
                self._delete_selected_match_replace_rule()
            else:
                self._drop_intercepted_request(selected_pending)
            return
        if action == "edit_item":
            if self.active_tab == 2:
                self._edit_repeater_request(stdscr)
            elif self.active_tab == 4:
                self._edit_selected_match_replace_rule()
            elif self._is_settings_tab():
                self._activate_settings_item(stdscr)
            elif self._is_scope_tab():
                self._activate_scope_item(stdscr)
            elif self._is_filters_tab():
                self._activate_filter_item(stdscr)
            elif self._is_keybindings_tab():
                self._activate_keybinding_item()
            elif self._is_rule_builder_tab():
                self._activate_rule_builder_item(stdscr)
            elif self._is_theme_builder_tab():
                self._activate_theme_builder_item(stdscr)
            else:
                self._edit_intercepted_request(stdscr, selected_pending)
            return
        if action == "repeater_prev_session":
            self._switch_repeater_session(-1)
            return
        if action == "repeater_next_session":
            self._switch_repeater_session(1)
            return
        if action == "increase_http_horizontal_split":
            self._adjust_layout_horizontal(self.LAYOUT_ADJUST_STEP)
            return
        if action == "decrease_http_horizontal_split":
            self._adjust_layout_horizontal(-self.LAYOUT_ADJUST_STEP)
            return
        if action == "increase_http_vertical_split":
            self._adjust_layout_vertical(self.LAYOUT_ADJUST_STEP)
            return
        if action == "decrease_http_vertical_split":
            self._adjust_layout_vertical(-self.LAYOUT_ADJUST_STEP)
            return
        self._handle_plugin_bound_action(
            action,
            selected=selected,
            selected_intercept=selected_intercept,
        )

    def _handle_plugin_bound_action(
        self,
        action: str,
        *,
        selected: TrafficEntry | None,
        selected_intercept: PendingInterceptionView | None,
    ) -> bool:
        for contribution in self._plugin_keybinding_contributions():
            if contribution.action != action:
                continue
            context = self._build_plugin_context(
                plugin_id=contribution.plugin_id,
                entry=selected,
                intercept=selected_intercept,
                export_source=self.export_source,
                workspace_id=self._workspace_id_for_tab(self.active_tab),
                tui=self,
            )
            try:
                handled = contribution.handler(context)
            except Exception as exc:
                self._set_status(f"Plugin action error: {exc}")
                return True
            return bool(True if handled is None else handled)
        return False

    def _open_inspector_workspace(
        self,
        mode: str,
        entries: list[TrafficEntry],
        selected: TrafficEntry | None,
        selected_intercept: PendingInterceptionView | None,
    ) -> None:
        if mode not in {"request", "response"}:
            mode = "request"

        if self._is_inspect_tab():
            self._inspect_set_mode(mode)
            return

        inspect_source = ""
        inspect_entry_id: int | None = None
        request_text = ""
        response_text = ""

        if self.active_tab == 2:
            session = self._current_repeater_session()
            if session is None:
                self._set_status("No repeater session loaded.")
                return
            exchange = self._selected_repeater_exchange(session)
            inspect_source = "repeater"
            if exchange is None:
                request_text = session.request_text or ""
                response_text = session.response_text or ""
            else:
                request_text = exchange.request_text or ""
                response_text = exchange.response_text or ""
        elif self.active_tab == 1 and selected_intercept is not None:
            inspect_source = "intercept"
            if selected_intercept.phase == "request":
                request_text = selected_intercept.raw_text or ""
            else:
                response_text = selected_intercept.raw_text or ""
        else:
            if self.active_tab == 3:
                selected = self._selected_sitemap_entry(entries)
            if selected is None:
                self._set_status("Select a flow first.")
                return
            inspect_source = "entry"
            inspect_entry_id = selected.id

        self.inspect_return_tab = self.active_tab
        self.inspect_return_pane = self.active_pane
        self.inspect_mode = mode
        self.inspect_source = inspect_source
        self.inspect_entry_id = inspect_entry_id
        self.inspect_request_text = request_text
        self.inspect_response_text = response_text
        self.inspect_scroll = 0
        self.inspect_x_scroll = 0
        self.active_tab = self._inspect_tab_index()
        self.active_pane = "inspect"

    def _expand_mode_for_active_pane(self) -> str | None:
        if self._is_inspect_tab():
            return (
                self.inspect_mode
                if self.inspect_mode in {"request", "response"}
                else "request"
            )
        if self.active_pane in {"http_request", "sitemap_request", "repeater_request"}:
            return "request"
        if self.active_pane in {"http_response", "sitemap_response", "repeater_response"}:
            return "response"
        return "request"

    def _inspect_set_mode(self, mode: str) -> None:
        if mode not in {"request", "response"}:
            mode = "request"
        self.inspect_mode = mode
        self.inspect_scroll = 0
        self.inspect_x_scroll = 0
        self.active_pane = "inspect"

    def _inspect_toggle_mode(self) -> None:
        target = "response" if self.inspect_mode == "request" else "request"
        self._inspect_set_mode(target)

    def _back_from_inspector(self) -> None:
        if not self._is_inspect_tab():
            self._set_status("Back is only available in Inspect.")
            return
        self.active_tab = self.inspect_return_tab
        self.active_pane = self.inspect_return_pane
        self._sync_active_pane()

    def _sync_detail_scroll(self, entry_id: int | None) -> None:
        if (
            entry_id != self._last_detail_entry_id
            or self.active_tab != self._last_detail_tab
        ):
            self.detail_scroll = 0
            self.detail_x_scroll = 0
            self.http_request_scroll = 0
            self.http_request_x_scroll = 0
            self.http_response_scroll = 0
            self.http_response_x_scroll = 0
            self._last_detail_entry_id = entry_id
            self._last_detail_tab = self.active_tab

    def _sync_match_replace_selection(self, rules: list[MatchReplaceRule]) -> None:
        if not rules:
            self.match_replace_selected_index = 0
            return
        self.match_replace_selected_index = max(
            0, min(self.match_replace_selected_index, len(rules) - 1)
        )

    def _move_match_replace_selection(self, delta: int) -> None:
        rules = self.store.match_replace_rules()
        if not rules:
            self.match_replace_selected_index = 0
            return
        self.match_replace_selected_index = max(
            0, min(len(rules) - 1, self.match_replace_selected_index + delta)
        )

    def _delete_selected_match_replace_rule(self) -> None:
        rules = self.store.match_replace_rules()
        if not rules:
            self._set_status("No Match/Replace rules to delete.")
            return
        self._sync_match_replace_selection(rules)
        removed = rules.pop(self.match_replace_selected_index)
        self.store.set_match_replace_rules(rules)
        if rules:
            self.match_replace_selected_index = min(
                self.match_replace_selected_index, len(rules) - 1
            )
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
        self.settings_selected_index = max(
            0, min(self.settings_selected_index, len(items) - 1)
        )

    def _sync_keybinding_selection(self, items: list[KeybindingItem]) -> None:
        if not items:
            self.keybindings_selected_index = 0
            self.keybindings_detail_scroll = 0
            self.keybindings_detail_x_scroll = 0
            return
        self.keybindings_selected_index = max(
            0, min(self.keybindings_selected_index, len(items) - 1)
        )

    def _sync_scope_selection(self, items: list[ScopeItem]) -> None:
        if not items:
            self.scope_selected_index = 0
            self.scope_detail_scroll = 0
            self.scope_detail_x_scroll = 0
            return
        self.scope_selected_index = max(
            0, min(self.scope_selected_index, len(items) - 1)
        )

    def _sync_filter_selection(self, items: list[FilterItem]) -> None:
        if not items:
            self.filters_selected_index = 0
            self.filters_detail_scroll = 0
            self.filters_detail_x_scroll = 0
            return
        self.filters_selected_index = max(
            0, min(self.filters_selected_index, len(items) - 1)
        )

    def _sync_export_selection(self, items: list[ExportFormatItem]) -> None:
        if not items:
            self.export_selected_index = 0
            self.export_detail_scroll = 0
            self.export_detail_x_scroll = 0
            return
        self.export_selected_index = max(
            0, min(self.export_selected_index, len(items) - 1)
        )

    def _sync_rule_builder_selection(self, items: list[MatchReplaceFieldItem]) -> None:
        if not items:
            self.rule_builder_selected_index = 0
            self.rule_builder_detail_scroll = 0
            self.rule_builder_detail_x_scroll = 0
            return
        self.rule_builder_selected_index = max(
            0, min(self.rule_builder_selected_index, len(items) - 1)
        )

    def _sync_theme_builder_selection(self, items: list[ThemeBuilderFieldItem]) -> None:
        if not items:
            self.theme_builder_selected_index = 0
            self.theme_builder_detail_scroll = 0
            self.theme_builder_detail_x_scroll = 0
            return
        self.theme_builder_selected_index = max(
            0, min(self.theme_builder_selected_index, len(items) - 1)
        )

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

    def _move_scope_focus(self, delta: int) -> None:
        panes = ["scope_menu", "scope_detail"]
        if self.active_pane not in panes:
            self.active_pane = "scope_menu"
            return
        index = panes.index(self.active_pane)
        index = max(0, min(len(panes) - 1, index + delta))
        self.active_pane = panes[index]

    def _move_filters_focus(self, delta: int) -> None:
        panes = ["filters_menu", "filters_detail"]
        if self.active_pane not in panes:
            self.active_pane = "filters_menu"
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

    def _move_theme_builder_focus(self, delta: int) -> None:
        panes = ["theme_builder_menu", "theme_builder_detail"]
        if self.active_pane not in panes:
            self.active_pane = "theme_builder_menu"
            return
        index = panes.index(self.active_pane)
        index = max(0, min(len(panes) - 1, index + delta))
        self.active_pane = panes[index]

    def _move_plugin_workspace_focus(self, delta: int) -> None:
        panes = ["plugin_workspace_menu", "plugin_workspace_detail"]
        if self.active_pane not in panes:
            self.active_pane = "plugin_workspace_menu"
            return
        index = panes.index(self.active_pane)
        index = max(0, min(len(panes) - 1, index + delta))
        self.active_pane = panes[index]

    def _move_http_focus(self, delta: int) -> None:
        panes = ["flows", "http_request", "http_response"]
        if self.active_pane not in panes:
            self.active_pane = "flows"
            return
        index = panes.index(self.active_pane)
        index = max(0, min(len(panes) - 1, index + delta))
        self.active_pane = panes[index]

    def _move_export_focus(self, delta: int) -> None:
        panes = ["export_menu", "export_detail"]
        if self.active_pane not in panes:
            self.active_pane = "export_menu"
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
        self.settings_selected_index = max(
            0, min(len(items) - 1, self.settings_selected_index + delta)
        )
        if previous != self.settings_selected_index:
            self.settings_detail_scroll = 0
            self.settings_detail_x_scroll = 0
            self._sync_theme_selection(prefer_current=True)

    def _scroll_http_active_pane(self, delta: int, entry_count: int) -> None:
        if self.active_pane == "http_request":
            self.http_request_scroll = max(0, self.http_request_scroll + delta)
            return
        if self.active_pane == "http_response":
            self.http_response_scroll = max(0, self.http_response_scroll + delta)
            return
        if delta < 0:
            self.selected_index = max(0, self.selected_index - 1)
            return
        self.selected_index = min(max(0, entry_count - 1), self.selected_index + 1)

    def _scroll_keybindings_active_pane(self, delta: int) -> None:
        items = self._keybinding_items()
        if self.active_pane == "keybindings_detail":
            self.keybindings_detail_scroll = max(
                0, self.keybindings_detail_scroll + delta
            )
            return
        if not items:
            self.keybindings_selected_index = 0
            return
        previous = self.keybindings_selected_index
        self.keybindings_selected_index = max(
            0, min(len(items) - 1, self.keybindings_selected_index + delta)
        )
        if previous != self.keybindings_selected_index:
            self.keybindings_detail_scroll = 0
            self.keybindings_detail_x_scroll = 0

    def _scroll_scope_active_pane(self, delta: int) -> None:
        items = self._scope_items()
        if self.active_pane == "scope_detail":
            self.scope_detail_scroll = max(0, self.scope_detail_scroll + delta)
            return
        if not items:
            self.scope_selected_index = 0
            return
        previous = self.scope_selected_index
        self.scope_selected_index = max(
            0, min(len(items) - 1, self.scope_selected_index + delta)
        )
        if previous != self.scope_selected_index:
            self.scope_detail_scroll = 0
            self.scope_detail_x_scroll = 0
            self.scope_error_message = ""

    def _scroll_filters_active_pane(self, delta: int) -> None:
        items = self._filter_items()
        if self.active_pane == "filters_detail":
            self.filters_detail_scroll = max(0, self.filters_detail_scroll + delta)
            return
        if not items:
            self.filters_selected_index = 0
            return
        previous = self.filters_selected_index
        self.filters_selected_index = max(
            0, min(len(items) - 1, self.filters_selected_index + delta)
        )
        if previous != self.filters_selected_index:
            self.filters_detail_scroll = 0
            self.filters_detail_x_scroll = 0
            self.filters_error_message = ""

    def _scroll_rule_builder_active_pane(self, delta: int) -> None:
        items = self._rule_builder_items()
        if self.active_pane == "rule_builder_detail":
            self.rule_builder_detail_scroll = max(
                0, self.rule_builder_detail_scroll + delta
            )
            return
        if not items:
            self.rule_builder_selected_index = 0
            return
        previous = self.rule_builder_selected_index
        self.rule_builder_selected_index = max(
            0, min(len(items) - 1, self.rule_builder_selected_index + delta)
        )
        if previous != self.rule_builder_selected_index:
            self.rule_builder_detail_scroll = 0
            self.rule_builder_detail_x_scroll = 0

    def _scroll_theme_builder_active_pane(self, delta: int) -> None:
        items = self._theme_builder_items()
        if self.active_pane == "theme_builder_detail":
            self.theme_builder_detail_scroll = max(
                0, self.theme_builder_detail_scroll + delta
            )
            return
        if not items:
            self.theme_builder_selected_index = 0
            return
        previous = self.theme_builder_selected_index
        self.theme_builder_selected_index = max(
            0, min(len(items) - 1, self.theme_builder_selected_index + delta)
        )
        if previous != self.theme_builder_selected_index:
            self.theme_builder_detail_scroll = 0
            self.theme_builder_detail_x_scroll = 0

    def _scroll_plugin_workspace_active_pane(self, delta: int) -> None:
        workspace = self._current_plugin_workspace()
        if workspace is None:
            return
        panels = self.plugin_manager.panel_contributions(workspace.workspace_id)
        if self.active_pane == "plugin_workspace_detail":
            current = self.plugin_workspace_detail_scroll.get(workspace.workspace_id, 0)
            self.plugin_workspace_detail_scroll[workspace.workspace_id] = max(0, current + delta)
            return
        if not panels:
            self.plugin_workspace_selected_index[workspace.workspace_id] = 0
            return
        previous = self.plugin_workspace_selected_index.get(workspace.workspace_id, 0)
        self.plugin_workspace_selected_index[workspace.workspace_id] = max(
            0,
            min(len(panels) - 1, previous + delta),
        )
        if previous != self.plugin_workspace_selected_index[workspace.workspace_id]:
            self.plugin_workspace_detail_scroll[workspace.workspace_id] = 0
            self.plugin_workspace_detail_x_scroll[workspace.workspace_id] = 0

    def _scroll_export_active_pane(self, delta: int) -> None:
        items = self._export_format_items()
        if self.active_pane == "export_detail":
            self.export_detail_scroll = max(0, self.export_detail_scroll + delta)
            return
        if not items:
            self.export_selected_index = 0
            return
        previous = self.export_selected_index
        self.export_selected_index = max(
            0, min(len(items) - 1, self.export_selected_index + delta)
        )
        if previous != self.export_selected_index:
            self.export_detail_scroll = 0
            self.export_detail_x_scroll = 0

    def _set_settings_active_scroll(self, value: int) -> None:
        if self.active_pane == "settings_detail":
            self.settings_detail_scroll = max(0, value)
            return
        self.settings_selected_index = max(0, value)

    def _set_scope_active_scroll(self, value: int) -> None:
        if self.active_pane == "scope_detail":
            self.scope_detail_scroll = max(0, value)
            return
        self.scope_selected_index = max(0, value)

    def _set_http_active_scroll(self, value: int, entry_count: int) -> None:
        if self.active_pane == "http_request":
            self.http_request_scroll = max(0, value)
            return
        if self.active_pane == "http_response":
            self.http_response_scroll = max(0, value)
            return
        self.selected_index = max(0, min(max(0, entry_count - 1), value))

    def _set_inspect_active_scroll(self, value: int) -> None:
        self.inspect_scroll = max(0, value)

    def _set_keybindings_active_scroll(self, value: int) -> None:
        if self.active_pane == "keybindings_detail":
            self.keybindings_detail_scroll = max(0, value)
            return
        self.keybindings_selected_index = max(0, value)

    def _set_filters_active_scroll(self, value: int) -> None:
        if self.active_pane == "filters_detail":
            self.filters_detail_scroll = max(0, value)
            return
        self.filters_selected_index = max(0, value)

    def _set_rule_builder_active_scroll(self, value: int) -> None:
        if self.active_pane == "rule_builder_detail":
            self.rule_builder_detail_scroll = max(0, value)
            return
        self.rule_builder_selected_index = max(0, value)

    def _set_theme_builder_active_scroll(self, value: int) -> None:
        if self.active_pane == "theme_builder_detail":
            self.theme_builder_detail_scroll = max(0, value)
            return
        self.theme_builder_selected_index = max(0, value)

    def _set_export_active_scroll(self, value: int) -> None:
        if self.active_pane == "export_detail":
            self.export_detail_scroll = max(0, value)
            return
        self.export_selected_index = max(0, value)

    def _set_plugin_workspace_active_scroll(self, value: int) -> None:
        workspace = self._current_plugin_workspace()
        if workspace is None:
            return
        if self.active_pane == "plugin_workspace_detail":
            self.plugin_workspace_detail_scroll[workspace.workspace_id] = max(0, value)
            return
        self.plugin_workspace_selected_index[workspace.workspace_id] = max(0, value)

    def _settings_page_rows(self, stdscr) -> int:
        height, _ = stdscr.getmaxyx()
        return max(1, height - 6)

    def _scope_page_rows(self, stdscr) -> int:
        height, _ = stdscr.getmaxyx()
        return max(1, height - 6)

    def _http_page_rows(self, stdscr) -> int:
        height, _ = stdscr.getmaxyx()
        pane_height = max(1, height - 5)
        return max(1, pane_height // 2)

    def _inspect_page_rows(self, stdscr) -> int:
        height, _ = stdscr.getmaxyx()
        return max(1, height - 5)

    def _export_page_rows(self, stdscr) -> int:
        height, _ = stdscr.getmaxyx()
        return max(1, height - 6)

    def _keybindings_page_rows(self, stdscr) -> int:
        height, _ = stdscr.getmaxyx()
        return max(1, height - 6)

    def _filters_page_rows(self, stdscr) -> int:
        height, _ = stdscr.getmaxyx()
        return max(1, height - 6)

    def _rule_builder_page_rows(self, stdscr) -> int:
        height, _ = stdscr.getmaxyx()
        return max(1, height - 6)

    def _theme_builder_page_rows(self, stdscr) -> int:
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
                self._set_status("Move with j/k to preview and apply themes automatically.")
                return
            self._apply_selected_theme()
            return
        if item.kind == "plugin_setting":
            self._activate_plugin_setting_field(stdscr, item)
            return
        if item.kind == "theme_builder":
            self._open_theme_builder_workspace()
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
        if item.kind == "about":
            self.active_pane = "settings_detail"
            self.settings_detail_scroll = 0
            self.settings_detail_x_scroll = 0
            self._set_status(f"Viewing {item.label}.")
            return
        if item.kind == "scope":
            self._open_scope_workspace()
            return
        if item.kind == "filters":
            self._open_filters_workspace()
            return
        if item.kind == "keybindings":
            self._open_keybindings_workspace()

    def _activate_plugin_setting_field(self, stdscr, item: SettingsItem) -> None:
        field = self._plugin_setting_field(item.plugin_id, item.field_id)
        if field is None:
            self._set_status("Plugin setting field is no longer available.")
            return
        current_value = self._plugin_setting_value(field)
        if field.kind == "toggle":
            new_value = not bool(current_value)
        elif field.kind == "choice":
            options = field.options or [str(field.default or "")]
            current_text = str(current_value if current_value is not None else field.default or "")
            try:
                position = options.index(current_text)
            except ValueError:
                position = -1
            new_value = options[(position + 1) % len(options)]
        elif field.kind == "text":
            prompt = f"{field.label}: "
            initial_text = str(current_value if current_value is not None else field.default or "")
            edited = self._prompt_inline_text(stdscr, prompt, initial_text)
            if edited is None:
                self._set_status("Plugin setting change cancelled.")
                return
            new_value = edited.strip() or field.default or ""
        else:
            new_value = current_value
        context = self._build_plugin_context(
            plugin_id=field.plugin_id,
            workspace_id="settings",
            tui=self,
        )
        if field.on_change is not None:
            candidate = field.on_change(context, new_value)
            if candidate is not None:
                new_value = candidate
        if field.kind != "action":
            self._set_plugin_setting_value(field, new_value)
            self._set_status(f"{field.label} updated.")
            return
        self._set_status(f"{field.label} executed.")

    def _move_theme_selection(self, delta: int) -> None:
        themes = self._available_themes()
        if not themes:
            self.theme_selected_index = 0
            return
        previous = self.theme_selected_index
        self.theme_selected_index = max(
            0, min(len(themes) - 1, self.theme_selected_index + delta)
        )
        selected_row = (
            self._theme_list_start_index(self._theme_detail_lines())
            + self.theme_selected_index
        )
        self.settings_detail_scroll = max(0, selected_row - 3)
        if self.theme_selected_index != previous:
            self._apply_selected_theme()

    @staticmethod
    def _theme_list_start_index(lines: list[str]) -> int:
        try:
            return lines.index("Available themes:") + 1
        except ValueError:
            return 0

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

    def _open_rule_builder_workspace(
        self,
        draft: MatchReplaceDraft | None = None,
        *,
        edit_index: int | None = None,
    ) -> None:
        self.active_tab = self._rule_builder_tab_index()
        self.active_pane = "rule_builder_menu"
        self.rule_builder_selected_index = 0
        self.rule_builder_detail_scroll = 0
        self.rule_builder_detail_x_scroll = 0
        self.rule_builder_draft = draft or MatchReplaceDraft()
        self.rule_builder_edit_index = edit_index
        self.rule_builder_error_message = ""
        self._set_status(
            "Rule editor opened." if edit_index is not None else "Rule builder opened."
        )

    def _open_filters_workspace(self) -> None:
        self.active_tab = self._filters_tab_index()
        self.active_pane = "filters_menu"
        self.filters_selected_index = 0
        self.filters_detail_scroll = 0
        self.filters_detail_x_scroll = 0
        self.filters_error_message = ""
        self._set_status("Filters workspace opened.")

    def _open_scope_workspace(self) -> None:
        self.active_tab = self._scope_tab_index()
        self.active_pane = "scope_menu"
        self.scope_selected_index = 0
        self.scope_detail_scroll = 0
        self.scope_detail_x_scroll = 0
        self.scope_error_message = ""
        self._set_status("Scope workspace opened.")

    def _save_scope_hosts(self, hosts: list[str], status: str) -> bool:
        try:
            self.store.set_scope_hosts(hosts)
        except Exception as exc:
            self.scope_error_message = str(exc)
            self._set_status(f"Invalid scope pattern: {exc}")
            return False
        self.scope_error_message = ""
        self._reset_visible_entry_navigation()
        self._set_status(status)
        return True

    def _normalize_scope_input(self, value: str, *, excluded: bool) -> str:
        candidate = value.strip()
        if excluded and not candidate.startswith("!"):
            candidate = f"!{candidate}"
        normalized = TrafficStore._normalize_scope_pattern(candidate)
        if not normalized:
            raise ValueError("pattern must contain a valid host or wildcard")
        return normalized

    def _edit_scope_pattern_inline(
        self,
        stdscr,
        prompt: str,
        *,
        initial_value: str = "",
        excluded: bool = False,
    ) -> str | None:
        edited = self._prompt_inline_text(stdscr, prompt, initial_value)
        if edited is None:
            self._set_status("Scope edit cancelled.")
            return None
        return self._normalize_scope_input(edited, excluded=excluded)

    def _save_view_filters(self, filters: ViewFilterSettings, status: str) -> None:
        try:
            self.store.set_view_filters(filters)
        except Exception as exc:
            self.filters_error_message = str(exc)
            self._set_status(f"Invalid filters: {exc}")
            return
        self.filters_error_message = ""
        self._reset_visible_entry_navigation()
        self._set_status(status)

    def _activate_scope_item(self, stdscr) -> None:
        items = self._scope_items()
        self._sync_scope_selection(items)
        if not items:
            return
        item = items[self.scope_selected_index]
        current = self.store.scope_hosts()
        self.scope_error_message = ""
        if item.kind == "add_include":
            normalized = self._edit_scope_pattern_inline(
                stdscr,
                "New in-scope pattern (Esc cancels): ",
                excluded=False,
            )
            if normalized is None:
                return
            if normalized in current:
                self._set_status(f"{normalized} is already in scope.")
                return
            self._save_scope_hosts(
                [*current, normalized], f"Added in-scope pattern: {normalized}."
            )
            return
        if item.kind == "add_exclude":
            normalized = self._edit_scope_pattern_inline(
                stdscr,
                "New out-of-scope pattern (Esc cancels): ",
                excluded=True,
            )
            if normalized is None:
                return
            if normalized in current:
                self._set_status(f"{normalized[1:]} is already excluded.")
                return
            self._save_scope_hosts(
                [*current, normalized], f"Added out-of-scope pattern: {normalized[1:]}."
            )
            return
        if item.kind == "include_pattern":
            normalized = self._edit_scope_pattern_inline(
                stdscr,
                "Edit in-scope pattern (Esc cancels): ",
                initial_value=item.value,
                excluded=False,
            )
            if normalized is None:
                return
            updated = [normalized if host == item.value else host for host in current]
            self._save_scope_hosts(updated, f"Updated in-scope pattern: {normalized}.")
            return
        if item.kind == "exclude_pattern":
            normalized = self._edit_scope_pattern_inline(
                stdscr,
                "Edit out-of-scope pattern (Esc cancels): ",
                initial_value=item.value,
                excluded=True,
            )
            if normalized is None:
                return
            original = f"!{item.value}"
            updated = [normalized if host == original else host for host in current]
            self._save_scope_hosts(
                updated, f"Updated out-of-scope pattern: {normalized[1:]}."
            )
            return
        if item.kind == "clear_scope":
            self._set_status(
                f"Press {self._binding_label('drop_item')} to clear the full scope."
            )

    def _activate_filter_item(self, stdscr) -> None:
        items = self._filter_items()
        self._sync_filter_selection(items)
        if not items:
            return
        item = items[self.filters_selected_index]
        filters = self.store.view_filters()
        self.filters_error_message = ""
        if item.kind == "show_out_of_scope":
            filters.show_out_of_scope = not filters.show_out_of_scope
            self._save_view_filters(
                filters,
                f"Scope visibility: {'all traffic' if filters.show_out_of_scope else 'in-scope only'}.",
            )
            return
        if item.kind == "query_mode":
            modes = ["all", "with_query", "without_query"]
            index = modes.index(filters.query_mode)
            filters.query_mode = modes[(index + 1) % len(modes)]
            self._save_view_filters(filters, f"Query filter: {filters.query_mode}.")
            return
        if item.kind == "body_mode":
            modes = ["all", "with_body", "without_body"]
            index = modes.index(filters.body_mode)
            filters.body_mode = modes[(index + 1) % len(modes)]
            self._save_view_filters(filters, f"Body filter: {filters.body_mode}.")
            return
        if item.kind == "failure_mode":
            modes = [
                "all",
                "failures",
                "hide_failures",
                "client_errors",
                "server_errors",
                "connection_errors",
            ]
            index = modes.index(filters.failure_mode)
            filters.failure_mode = modes[(index + 1) % len(modes)]
            self._save_view_filters(filters, f"Failure filter: {filters.failure_mode}.")
            return
        if item.kind.startswith("method:"):
            method = item.kind.split(":", 1)[1]
            if method in filters.methods:
                filters.methods = [
                    value for value in filters.methods if value != method
                ]
            else:
                filters.methods = [*filters.methods, method]
            label = ", ".join(filters.methods) if filters.methods else "all methods"
            self._save_view_filters(filters, f"Method filter: {label}.")
            return
        if item.kind.startswith("exclude_method:"):
            method = item.kind.split(":", 1)[1]
            if method in filters.hidden_methods:
                filters.hidden_methods = [
                    value for value in filters.hidden_methods if value != method
                ]
            else:
                filters.hidden_methods = [*filters.hidden_methods, method]
            label = (
                ", ".join(filters.hidden_methods) if filters.hidden_methods else "none"
            )
            self._save_view_filters(filters, f"Hidden methods: {label}.")
            return
        if item.kind == "clear_methods":
            filters.methods = []
            self._save_view_filters(filters, "Method filter cleared.")
            return
        if item.kind == "clear_hidden_methods":
            filters.hidden_methods = []
            self._save_view_filters(filters, "Hidden methods cleared.")
            return
        if item.kind == "edit_hidden_extensions":
            self._edit_hidden_extensions_inline(stdscr)
            return
        if item.kind == "clear_hidden_extensions":
            filters.hidden_extensions = []
            self._save_view_filters(filters, "Hidden file types cleared.")
            return
        if item.kind == "reset_filters":
            self._save_view_filters(ViewFilterSettings(), "View filters reset.")

    def _clear_selected_filter_item(self) -> None:
        items = self._filter_items()
        self._sync_filter_selection(items)
        if not items:
            return
        item = items[self.filters_selected_index]
        filters = self.store.view_filters()
        self.filters_error_message = ""
        if item.kind.startswith("method:"):
            method = item.kind.split(":", 1)[1]
            filters.methods = [value for value in filters.methods if value != method]
            self._save_view_filters(filters, f"Method removed: {method}.")
            return
        if item.kind.startswith("exclude_method:"):
            method = item.kind.split(":", 1)[1]
            filters.hidden_methods = [
                value for value in filters.hidden_methods if value != method
            ]
            self._save_view_filters(filters, f"Hidden method removed: {method}.")
            return
        if item.kind == "clear_methods":
            filters.methods = []
            self._save_view_filters(filters, "Method filter cleared.")
            return
        if item.kind == "clear_hidden_methods":
            filters.hidden_methods = []
            self._save_view_filters(filters, "Hidden methods cleared.")
            return
        if item.kind in {"edit_hidden_extensions", "clear_hidden_extensions"}:
            filters.hidden_extensions = []
            self._save_view_filters(filters, "Hidden file types cleared.")
            return
        if item.kind == "reset_filters":
            self._save_view_filters(ViewFilterSettings(), "View filters reset.")
            return
        self._set_status("Nothing to clear for this filter.")

    def _edit_hidden_extensions_inline(self, stdscr) -> None:
        filters = self.store.view_filters()
        initial = ", ".join(filters.hidden_extensions)
        edited = self._prompt_inline_text(
            stdscr,
            "Hidden file types (comma-separated, Esc cancels): ",
            initial,
        )
        if edited is None:
            self._set_status("Hidden file type edit cancelled.")
            return
        filters.hidden_extensions = [
            part.strip() for part in edited.split(",") if part.strip()
        ]
        self._save_view_filters(filters, "Hidden file types updated.")

    def _clear_selected_scope_item(self) -> None:
        items = self._scope_items()
        self._sync_scope_selection(items)
        if not items:
            return
        item = items[self.scope_selected_index]
        current = self.store.scope_hosts()
        self.scope_error_message = ""
        if item.kind == "include_pattern":
            updated = [host for host in current if host != item.value]
            self._save_scope_hosts(updated, f"Removed in-scope pattern: {item.value}.")
            return
        if item.kind == "exclude_pattern":
            original = f"!{item.value}"
            updated = [host for host in current if host != original]
            self._save_scope_hosts(
                updated, f"Removed out-of-scope pattern: {item.value}."
            )
            return
        if item.kind == "clear_scope":
            self._save_scope_hosts([], "Scope cleared. All hosts are now in scope.")
            return
        self._set_status("Nothing to delete for this scope item.")

    def _persist_rule_builder_edit(self, status: str) -> bool:
        if self.rule_builder_edit_index is None:
            self._set_status(status)
            return True
        rules = self.store.match_replace_rules()
        if self.rule_builder_edit_index < 0 or self.rule_builder_edit_index >= len(
            rules
        ):
            self.rule_builder_error_message = "Selected rule no longer exists."
            self._set_status(self.rule_builder_error_message)
            return False
        rules[self.rule_builder_edit_index] = self._draft_match_replace_rule()
        try:
            raw_document = self._render_match_replace_rules_document_from_rules(rules)
            parsed_rules = self._parse_match_replace_rules_document(raw_document)
            self.store.set_match_replace_rules(parsed_rules)
        except Exception as exc:
            self.rule_builder_error_message = str(exc)
            self._set_status(f"Invalid match/replace rule: {exc}")
            return False
        self.rule_builder_error_message = ""
        self._set_status(status)
        return True

    def _activate_rule_builder_item(self, stdscr) -> None:
        items = self._rule_builder_items()
        self._sync_rule_builder_selection(items)
        if not items:
            return
        item = items[self.rule_builder_selected_index]
        if item.kind == "enabled":
            self.rule_builder_draft.enabled = not self.rule_builder_draft.enabled
            self.rule_builder_error_message = ""
            self._persist_rule_builder_edit(
                f"Rule enabled: {self.rule_builder_draft.enabled}."
            )
            return
        if item.kind == "scope":
            modes = ["request", "response", "both"]
            index = modes.index(self.rule_builder_draft.scope)
            self.rule_builder_draft.scope = modes[(index + 1) % len(modes)]
            self.rule_builder_error_message = ""
            self._persist_rule_builder_edit(
                f"Rule scope: {self.rule_builder_draft.scope}."
            )
            return
        if item.kind == "mode":
            modes = ["literal", "regex"]
            index = modes.index(self.rule_builder_draft.mode)
            self.rule_builder_draft.mode = modes[(index + 1) % len(modes)]
            self.rule_builder_error_message = ""
            self._persist_rule_builder_edit(
                f"Rule mode: {self.rule_builder_draft.mode}."
            )
            return
        if item.kind == "description":
            self._edit_rule_builder_text_field(
                stdscr, "description", self.rule_builder_draft.description
            )
            return
        if item.kind == "match":
            self._edit_rule_builder_text_field(
                stdscr, "match", self.rule_builder_draft.match
            )
            return
        if item.kind == "replace":
            self._edit_rule_builder_text_field(
                stdscr, "replace", self.rule_builder_draft.replace
            )
            return
        if item.kind == "create":
            self._commit_rule_builder_draft()
            return
        if item.kind == "cancel":
            self._close_rule_builder_workspace("Rule builder cancelled.")

    def _edit_rule_builder_text_field(
        self, stdscr, field_name: str, initial_value: str
    ) -> None:
        edited = self._open_text_editor(
            stdscr, f"Edit Rule {field_name.title()}", initial_value
        )
        if edited is None:
            self._set_status(f"{field_name} edit cancelled.")
            return
        value = edited.rstrip("\n")
        setattr(self.rule_builder_draft, field_name, value)
        self.rule_builder_error_message = ""
        self._persist_rule_builder_edit(f"Updated rule {field_name}.")

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
        all_rules = self.store.match_replace_rules()
        if self.rule_builder_edit_index is None:
            all_rules = [*all_rules, rule]
        else:
            if self.rule_builder_edit_index < 0 or self.rule_builder_edit_index >= len(
                all_rules
            ):
                self.rule_builder_error_message = "Selected rule no longer exists."
                self._set_status(self.rule_builder_error_message)
                return
            all_rules[self.rule_builder_edit_index] = rule
        try:
            raw_document = self._render_match_replace_rules_document_from_rules(
                all_rules
            )
            parsed_rules = self._parse_match_replace_rules_document(raw_document)
            self.store.set_match_replace_rules(parsed_rules)
        except Exception as exc:
            self.rule_builder_error_message = str(exc)
            self._set_status(f"Invalid match/replace rule: {exc}")
            return
        self.rule_builder_error_message = ""
        if self.rule_builder_edit_index is None:
            self.match_replace_selected_index = max(0, len(all_rules) - 1)
            self._close_rule_builder_workspace("Match/Replace rule added.")
            return
        self.match_replace_selected_index = self.rule_builder_edit_index
        self._close_rule_builder_workspace("Match/Replace rule updated.")

    def _close_rule_builder_workspace(self, status: str) -> None:
        self.active_tab = 4
        self.active_pane = "detail"
        self.rule_builder_edit_index = None
        self.rule_builder_error_message = ""
        self.rule_builder_detail_scroll = 0
        self.rule_builder_detail_x_scroll = 0
        self._set_status(status)

    def _open_theme_builder_workspace(self) -> None:
        current = self._current_theme()
        self.active_tab = self._theme_builder_tab_index()
        self.active_pane = "theme_builder_menu"
        self.theme_builder_selected_index = 0
        self.theme_builder_menu_x_scroll = 0
        self.theme_builder_detail_scroll = 0
        self.theme_builder_detail_x_scroll = 0
        self.theme_builder_error_message = ""
        self.theme_builder_restore_name = self._theme_name
        self.theme_builder_draft = ThemeDraft(
            name=self._suggest_theme_name(current.name),
            description=f"Custom theme based on {current.name}",
            extends=current.name,
            colors=dict(current.colors),
        )
        self._apply_theme_builder_preview()
        self._set_status("Theme builder opened. Changes are previewed live.")

    def _activate_theme_builder_item(self, stdscr) -> None:
        items = self._theme_builder_items()
        self._sync_theme_builder_selection(items)
        if not items:
            return
        item = items[self.theme_builder_selected_index]
        if item.kind == "name":
            edited = self._prompt_inline_text(
                stdscr, "Theme name (Esc cancels): ", self.theme_builder_draft.name
            )
            if edited is None:
                self._set_status("Theme name edit cancelled.")
                return
            self.theme_builder_draft.name = edited.strip()
            self._apply_theme_builder_preview()
            return
        if item.kind == "description":
            edited = self._prompt_inline_text(
                stdscr,
                "Theme description (Esc cancels): ",
                self.theme_builder_draft.description,
            )
            if edited is None:
                self._set_status("Theme description edit cancelled.")
                return
            self.theme_builder_draft.description = edited.strip()
            self._apply_theme_builder_preview()
            return
        if item.kind == "extends":
            self._cycle_theme_builder_base()
            return
        if item.kind == "save":
            self._commit_theme_builder_draft()
            return
        if item.kind == "cancel":
            self._close_theme_builder_workspace(
                "Theme builder cancelled.", restore_preview=True
            )
            return
        role, axis = item.kind.split(":", 1)
        current_value = self.theme_builder_draft.colors[role][0 if axis == "fg" else 1]
        edited = self._prompt_inline_text(
            stdscr,
            f"{item.label} (named color or hex, Esc cancels): ",
            current_value,
        )
        if edited is None:
            self._set_status(f"{item.label} edit cancelled.")
            return
        self._set_theme_builder_color(role, axis, edited.strip().lower())

    def _cycle_theme_builder_base(self) -> None:
        themes = self._available_themes()
        if not themes:
            self.theme_builder_error_message = "No base themes are available."
            self._set_status(self.theme_builder_error_message)
            return
        names = [theme.name for theme in themes]
        try:
            index = names.index(self.theme_builder_draft.extends)
        except ValueError:
            index = -1
        self.theme_builder_draft.extends = names[(index + 1) % len(names)]
        base_theme = self.theme_manager.get(self.theme_builder_draft.extends)
        if base_theme is not None:
            self.theme_builder_draft.colors = dict(base_theme.colors)
        self._apply_theme_builder_preview()

    def _set_theme_builder_color(self, role: str, axis: str, value: str) -> None:
        if not self.theme_manager._is_supported_color(value):  # type: ignore[attr-defined]
            self.theme_builder_error_message = f"Unsupported color value: {value!r}"
            self._set_status(self.theme_builder_error_message)
            return
        fg, bg = self.theme_builder_draft.colors[role]
        self.theme_builder_draft.colors[role] = (value, bg) if axis == "fg" else (fg, value)
        self._apply_theme_builder_preview()

    def _apply_theme_builder_preview(self) -> bool:
        draft = self.theme_builder_draft
        if not draft.name.strip():
            self.theme_builder_error_message = "Theme name must not be empty."
            self._set_status(self.theme_builder_error_message)
            return False
        base_theme = self.theme_manager.get(draft.extends.strip() or "default")
        if base_theme is None:
            self.theme_builder_error_message = f"Unknown base theme {draft.extends!r}."
            self._set_status(self.theme_builder_error_message)
            return False
        try:
            preview = self.theme_manager._build_theme_definition(  # type: ignore[attr-defined]
                name=draft.name.strip(),
                description=draft.description.strip(),
                colors={
                    role: {"fg": fg, "bg": bg}
                    for role, (fg, bg) in draft.colors.items()
                },
                source="preview",
                base_theme=base_theme,
            )
        except Exception as exc:
            self.theme_builder_error_message = str(exc)
            self._set_status(f"Invalid theme draft: {exc}")
            return False
        self.theme_builder_error_message = ""
        self._theme_preview_override = preview
        self._apply_theme_definition(preview)
        self._set_status(f"Previewing theme draft: {preview.name}.")
        return True

    def _commit_theme_builder_draft(self) -> None:
        draft = self.theme_builder_draft
        if not self._apply_theme_builder_preview():
            return
        try:
            self.theme_manager.save_theme(
                name=draft.name.strip(),
                description=draft.description.strip(),
                extends=draft.extends.strip() or "default",
                colors=draft.colors,
            )
            self.theme_manager.load()
        except Exception as exc:
            self.theme_builder_error_message = str(exc)
            self._set_status(f"Could not save theme: {exc}")
            return
        self._theme_preview_override = None
        self._theme_name = draft.name.strip()
        self._sync_theme_selection(prefer_current=True)
        if self._colors_enabled():
            self._apply_theme_colors()
        if self._theme_saver is not None:
            self._theme_saver(self._theme_name)
        self._close_theme_builder_workspace(
            f"Theme saved: {self._theme_name}.",
            restore_preview=False,
        )

    def _close_theme_builder_workspace(
        self, status: str, *, restore_preview: bool
    ) -> None:
        if restore_preview and self.theme_builder_restore_name:
            self._theme_name = self.theme_builder_restore_name
        self._theme_preview_override = None
        if self._colors_enabled():
            self._apply_theme_colors()
        self.active_tab = self._settings_tab_index()
        self.active_pane = "settings_menu"
        self.settings_detail_scroll = 0
        self.settings_detail_x_scroll = 0
        self.theme_builder_selected_index = 0
        self.theme_builder_menu_x_scroll = 0
        self.theme_builder_detail_scroll = 0
        self.theme_builder_detail_x_scroll = 0
        self.theme_builder_error_message = ""
        self.theme_builder_restore_name = None
        self._sync_theme_selection(prefer_current=True)
        self._set_status(status)

    def _suggest_theme_name(self, base_name: str) -> str:
        existing = {theme.name for theme in self._available_themes()}
        candidate = f"{base_name}-custom"
        if candidate not in existing:
            return candidate
        suffix = 2
        while f"{candidate}-{suffix}" in existing:
            suffix += 1
        return f"{candidate}-{suffix}"

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
        self._set_status(
            f"Type one or two keys for {item.action}. Enter applies, Esc cancels."
        )

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
                self.keybinding_error_message = (
                    "Bindings must contain one or two visible characters."
                )
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
            self.keybinding_error_message = (
                "Only visible one or two-character bindings are allowed."
            )
            self._set_status(self.keybinding_error_message)
            return True
        if len(self.keybinding_capture_buffer) >= 2:
            self.keybinding_error_message = (
                "Bindings can contain at most two characters."
            )
            self._set_status(self.keybinding_error_message)
            return True
        self.keybinding_capture_buffer += key_name
        self.keybinding_error_message = ""
        self._set_status(
            f"Pending binding for {action}: {self.keybinding_capture_buffer}"
        )
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
            (
                name
                for name, value in bindings.items()
                if name != action and value == key_name
            ),
            None,
        )
        if duplicate_action is not None:
            self.keybinding_error_message = (
                f"{key_name!r} is already assigned to {duplicate_action}."
            )
            self._set_status(self.keybinding_error_message)
            return
        bindings[action] = key_name
        try:
            normalized = self._parse_active_keybindings_document(
                json.dumps({"bindings": bindings})
            )
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
        if self._is_inspect_tab():
            if self.active_pane != "inspect":
                self.active_pane = "inspect"
            return
        if self.active_tab == 2:
            if self.active_pane not in {
                "repeater_history",
                "repeater_request",
                "repeater_response",
            }:
                self.active_pane = "repeater_history"
            return
        if self.active_tab == 3:
            if self.active_pane not in {
                "sitemap_tree",
                "sitemap_request",
                "sitemap_response",
            }:
                self.active_pane = "sitemap_tree"
            return
        if self.active_tab == 5:
            if self.active_pane not in {"flows", "http_request", "http_response"}:
                self.active_pane = "flows"
            return
        if self._is_export_tab():
            if self.active_pane not in {"export_menu", "export_detail"}:
                self.active_pane = "export_menu"
            return
        if self._is_settings_tab():
            if self.active_pane not in {"settings_menu", "settings_detail"}:
                self.active_pane = "settings_menu"
            return
        if self._is_scope_tab():
            if self.active_pane not in {"scope_menu", "scope_detail"}:
                self.active_pane = "scope_menu"
            return
        if self._is_filters_tab():
            if self.active_pane not in {"filters_menu", "filters_detail"}:
                self.active_pane = "filters_menu"
            return
        if self._is_keybindings_tab():
            if self.active_pane not in {"keybindings_menu", "keybindings_detail"}:
                self.active_pane = "keybindings_menu"
            return
        if self._is_rule_builder_tab():
            if self.active_pane not in {"rule_builder_menu", "rule_builder_detail"}:
                self.active_pane = "rule_builder_menu"
            return
        if self._is_theme_builder_tab():
            if self.active_pane not in {"theme_builder_menu", "theme_builder_detail"}:
                self.active_pane = "theme_builder_menu"
            return
        if self._is_findings_tab():
            if self.active_pane not in {"findings_list", "findings_detail"}:
                self.active_pane = "findings_list"
            return
        if self._is_plugin_workspace_tab():
            if self.active_pane not in {"plugin_workspace_menu", "plugin_workspace_detail"}:
                self.active_pane = "plugin_workspace_menu"
            return
        if self.active_pane not in {"flows", "detail"}:
            self.active_pane = "flows"

    def _scroll_detail(self, delta: int) -> None:
        self.detail_scroll = max(0, self.detail_scroll + delta)

    def _move_active_pane(self, delta: int, entry_count: int) -> None:
        if self._is_inspect_tab():
            self._set_inspect_active_scroll(self.inspect_scroll + delta)
            return
        if self.active_tab == 5:
            self._scroll_http_active_pane(delta, entry_count)
            return
        if self.active_tab == 2:
            self._scroll_repeater_active_pane(delta)
            return
        if self.active_tab == 3:
            self._scroll_sitemap_active_pane(delta, self._entries_for_view())
            return
        if self._is_export_tab():
            self._scroll_export_active_pane(delta)
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
        if self._is_scope_tab():
            self._scroll_scope_active_pane(delta)
            return
        if self._is_filters_tab():
            self._scroll_filters_active_pane(delta)
            return
        if self._is_keybindings_tab():
            self._scroll_keybindings_active_pane(delta)
            return
        if self._is_rule_builder_tab():
            self._scroll_rule_builder_active_pane(delta)
            return
        if self._is_theme_builder_tab():
            self._scroll_theme_builder_active_pane(delta)
            return
        if self._is_findings_tab():
            self._scroll_findings_active_pane(delta)
            return
        if self._is_plugin_workspace_tab():
            self._scroll_plugin_workspace_active_pane(delta)
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
        if self._is_inspect_tab():
            self.inspect_x_scroll = max(0, self.inspect_x_scroll + delta)
            return
        if self.active_tab == 5:
            if self.active_pane == "http_request":
                self.http_request_x_scroll = max(0, self.http_request_x_scroll + delta)
                return
            if self.active_pane == "http_response":
                self.http_response_x_scroll = max(
                    0, self.http_response_x_scroll + delta
                )
                return
            self.flow_x_scroll = max(0, self.flow_x_scroll + delta)
            return
        if self.active_tab == 2:
            session = self._current_repeater_session()
            if session is None:
                return
            if self.active_pane == "repeater_history":
                session.history_x_scroll = max(0, session.history_x_scroll + delta)
                return
            if self.active_pane == "repeater_response":
                session.response_x_scroll = max(0, session.response_x_scroll + delta)
                return
            session.request_x_scroll = max(0, session.request_x_scroll + delta)
            return
        if self.active_tab == 3:
            if self.active_pane == "sitemap_request":
                self.sitemap_request_x_scroll = max(
                    0, self.sitemap_request_x_scroll + delta
                )
                return
            if self.active_pane == "sitemap_response":
                self.sitemap_response_x_scroll = max(
                    0, self.sitemap_response_x_scroll + delta
                )
                return
            self.sitemap_tree_x_scroll = max(0, self.sitemap_tree_x_scroll + delta)
            return
        if self._is_export_tab():
            if self.active_pane == "export_menu":
                self.export_menu_x_scroll = max(0, self.export_menu_x_scroll + delta)
                return
            if self.active_pane == "export_detail":
                self.export_detail_x_scroll = max(
                    0, self.export_detail_x_scroll + delta
                )
            return
        if self._is_settings_tab():
            if self.active_pane == "settings_menu":
                self.settings_menu_x_scroll = max(
                    0, self.settings_menu_x_scroll + delta
                )
                return
            if self.active_pane == "settings_detail":
                self.settings_detail_x_scroll = max(
                    0, self.settings_detail_x_scroll + delta
                )
            return
        if self._is_scope_tab():
            if self.active_pane == "scope_menu":
                self.scope_menu_x_scroll = max(0, self.scope_menu_x_scroll + delta)
                return
            if self.active_pane == "scope_detail":
                self.scope_detail_x_scroll = max(0, self.scope_detail_x_scroll + delta)
            return
        if self._is_filters_tab():
            if self.active_pane == "filters_menu":
                self.filters_menu_x_scroll = max(0, self.filters_menu_x_scroll + delta)
                return
            if self.active_pane == "filters_detail":
                self.filters_detail_x_scroll = max(
                    0, self.filters_detail_x_scroll + delta
                )
            return
        if self._is_keybindings_tab():
            if self.active_pane == "keybindings_menu":
                self.keybindings_menu_x_scroll = max(
                    0, self.keybindings_menu_x_scroll + delta
                )
                return
            if self.active_pane == "keybindings_detail":
                self.keybindings_detail_x_scroll = max(
                    0, self.keybindings_detail_x_scroll + delta
                )
            return
        if self._is_rule_builder_tab():
            if self.active_pane == "rule_builder_menu":
                self.rule_builder_menu_x_scroll = max(
                    0, self.rule_builder_menu_x_scroll + delta
                )
                return
            if self.active_pane == "rule_builder_detail":
                self.rule_builder_detail_x_scroll = max(
                    0, self.rule_builder_detail_x_scroll + delta
                )
            return
        if self._is_theme_builder_tab():
            if self.active_pane == "theme_builder_menu":
                self.theme_builder_menu_x_scroll = max(
                    0, self.theme_builder_menu_x_scroll + delta
                )
                return
            if self.active_pane == "theme_builder_detail":
                self.theme_builder_detail_x_scroll = max(
                    0, self.theme_builder_detail_x_scroll + delta
                )
            return
        if self._is_plugin_workspace_tab():
            workspace = self._current_plugin_workspace()
            if workspace is None:
                return
            if self.active_pane == "plugin_workspace_menu":
                self.plugin_workspace_menu_x_scroll[workspace.workspace_id] = max(
                    0,
                    self.plugin_workspace_menu_x_scroll.get(workspace.workspace_id, 0)
                    + delta,
                )
                return
            if self.active_pane == "plugin_workspace_detail":
                self.plugin_workspace_detail_x_scroll[workspace.workspace_id] = max(
                    0,
                    self.plugin_workspace_detail_x_scroll.get(workspace.workspace_id, 0)
                    + delta,
                )
            return
        if self.active_pane == "flows":
            self.flow_x_scroll = max(0, self.flow_x_scroll + delta)
            return
        if self.active_pane == "detail":
            self.detail_x_scroll = max(0, self.detail_x_scroll + delta)

    def _reset_horizontal_scrolls(self) -> None:
        self.flow_x_scroll = 0
        self.http_request_x_scroll = 0
        self.http_response_x_scroll = 0
        self.detail_x_scroll = 0
        self.inspect_x_scroll = 0
        self.sitemap_tree_x_scroll = 0
        self.sitemap_request_x_scroll = 0
        self.sitemap_response_x_scroll = 0
        self.export_menu_x_scroll = 0
        self.export_detail_x_scroll = 0
        self.settings_menu_x_scroll = 0
        self.settings_detail_x_scroll = 0
        self.scope_menu_x_scroll = 0
        self.scope_detail_x_scroll = 0
        self.filters_menu_x_scroll = 0
        self.filters_detail_x_scroll = 0
        self.keybindings_menu_x_scroll = 0
        self.keybindings_detail_x_scroll = 0
        self.rule_builder_menu_x_scroll = 0
        self.rule_builder_detail_x_scroll = 0
        self.theme_builder_menu_x_scroll = 0
        self.theme_builder_detail_x_scroll = 0
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
            stdscr.addnstr(
                y + height - 1, indicator_x, " v ", min(3, width), curses.A_BOLD
            )

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
            raw_value = stdscr.getstr(
                height - 1, len(prompt), max(1, width - len(prompt) - 1)
            )
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

    def _prompt_inline_text(
        self, stdscr, prompt: str, initial_text: str = ""
    ) -> str | None:
        buffer = list(initial_text)
        try:
            curses.curs_set(1)
        except curses.error:
            pass
        stdscr.keypad(True)
        stdscr.timeout(-1)
        try:
            while True:
                height, width = stdscr.getmaxyx()
                visible_prompt = self._sanitize_display_text(prompt)
                joined = "".join(buffer)
                available = max(0, width - len(visible_prompt) - 1)
                visible_value = joined[-available:] if available else ""
                stdscr.move(height - 1, 0)
                stdscr.clrtoeol()
                stdscr.addnstr(
                    height - 1, 0, visible_prompt, width - 1, self._chrome_attr()
                )
                stdscr.addnstr(
                    height - 1,
                    min(len(visible_prompt), width - 1),
                    visible_value,
                    max(0, width - len(visible_prompt) - 1),
                    self._chrome_attr(),
                )
                cursor_x = min(width - 1, len(visible_prompt) + len(visible_value))
                stdscr.move(height - 1, cursor_x)
                stdscr.refresh()

                key = stdscr.getch()
                if key == 27:
                    return None
                if key in (curses.KEY_ENTER, 10, 13):
                    return "".join(buffer)
                if key in (curses.KEY_BACKSPACE, 127, 8):
                    if buffer:
                        buffer.pop()
                    continue
                if 0 <= key <= 255:
                    character = chr(key)
                    if character.isprintable() and character not in {"\n", "\r"}:
                        buffer.append(character)
        finally:
            try:
                curses.curs_set(0)
            except curses.error:
                pass
            stdscr.keypad(True)
            stdscr.timeout(150)

    def _open_text_editor(self, stdscr, title: str, initial_text: str) -> str | None:
        lines = initial_text.split("\n")
        if not lines:
            lines = [""]
        cursor_row = 0
        cursor_col = 0
        row_scroll = 0
        col_scroll = 0
        try:
            curses.curs_set(1)
        except curses.error:
            pass
        stdscr.keypad(True)
        stdscr.timeout(-1)
        try:
            while True:
                height, width = stdscr.getmaxyx()
                body_top = 1
                body_height = max(1, height - 2)
                body_width = max(1, width)

                cursor_row = max(0, min(cursor_row, len(lines) - 1))
                cursor_col = max(0, min(cursor_col, len(lines[cursor_row])))

                if cursor_row < row_scroll:
                    row_scroll = cursor_row
                elif cursor_row >= row_scroll + body_height:
                    row_scroll = cursor_row - body_height + 1

                if cursor_col < col_scroll:
                    col_scroll = cursor_col
                elif cursor_col >= col_scroll + body_width:
                    col_scroll = cursor_col - body_width + 1

                stdscr.erase()
                header = self._trim(
                    f" {title} | F2/Ctrl+G save | Esc cancel ", max(1, width - 1)
                )
                stdscr.addnstr(
                    0,
                    0,
                    header.ljust(max(1, width - 1)),
                    max(1, width - 1),
                    self._chrome_attr(),
                )

                visible_lines = lines[row_scroll : row_scroll + body_height]
                for offset, line in enumerate(visible_lines):
                    self._draw_text_line(
                        stdscr,
                        body_top + offset,
                        0,
                        body_width,
                        line,
                        x_scroll=col_scroll,
                    )

                footer = self._trim(
                    f"Ln {cursor_row + 1}/{len(lines)}  Col {cursor_col + 1}  Tab inserts spaces  Del merges lines",
                    max(1, width - 1),
                )
                stdscr.addnstr(
                    height - 1,
                    0,
                    footer.ljust(max(1, width - 1)),
                    max(1, width - 1),
                    self._chrome_attr(),
                )

                cursor_y = min(height - 2, body_top + (cursor_row - row_scroll))
                cursor_x = min(body_width - 1, max(0, cursor_col - col_scroll))
                stdscr.move(cursor_y, cursor_x)
                stdscr.refresh()

                key = stdscr.getch()
                if key == 27:
                    return None
                if key in (curses.KEY_F2, 7):
                    return "\n".join(lines)
                if key in (curses.KEY_ENTER, 10, 13):
                    current = lines[cursor_row]
                    lines[cursor_row] = current[:cursor_col]
                    lines.insert(cursor_row + 1, current[cursor_col:])
                    cursor_row += 1
                    cursor_col = 0
                    continue
                if key in (curses.KEY_BACKSPACE, 127, 8):
                    if cursor_col > 0:
                        current = lines[cursor_row]
                        lines[cursor_row] = (
                            current[: cursor_col - 1] + current[cursor_col:]
                        )
                        cursor_col -= 1
                    elif cursor_row > 0:
                        previous = lines[cursor_row - 1]
                        current = lines.pop(cursor_row)
                        cursor_row -= 1
                        cursor_col = len(previous)
                        lines[cursor_row] = previous + current
                    continue
                if key == curses.KEY_DC:
                    current = lines[cursor_row]
                    if cursor_col < len(current):
                        lines[cursor_row] = (
                            current[:cursor_col] + current[cursor_col + 1 :]
                        )
                    elif cursor_row + 1 < len(lines):
                        lines[cursor_row] = current + lines.pop(cursor_row + 1)
                    continue
                if key == curses.KEY_LEFT:
                    if cursor_col > 0:
                        cursor_col -= 1
                    elif cursor_row > 0:
                        cursor_row -= 1
                        cursor_col = len(lines[cursor_row])
                    continue
                if key == curses.KEY_RIGHT:
                    if cursor_col < len(lines[cursor_row]):
                        cursor_col += 1
                    elif cursor_row + 1 < len(lines):
                        cursor_row += 1
                        cursor_col = 0
                    continue
                if key == curses.KEY_UP:
                    if cursor_row > 0:
                        cursor_row -= 1
                        cursor_col = min(cursor_col, len(lines[cursor_row]))
                    continue
                if key == curses.KEY_DOWN:
                    if cursor_row + 1 < len(lines):
                        cursor_row += 1
                        cursor_col = min(cursor_col, len(lines[cursor_row]))
                    continue
                if key == curses.KEY_HOME:
                    cursor_col = 0
                    continue
                if key == curses.KEY_END:
                    cursor_col = len(lines[cursor_row])
                    continue
                if key == curses.KEY_PPAGE:
                    cursor_row = max(0, cursor_row - body_height)
                    cursor_col = min(cursor_col, len(lines[cursor_row]))
                    continue
                if key == curses.KEY_NPAGE:
                    cursor_row = min(len(lines) - 1, cursor_row + body_height)
                    cursor_col = min(cursor_col, len(lines[cursor_row]))
                    continue
                if key == 9:
                    current = lines[cursor_row]
                    lines[cursor_row] = (
                        current[:cursor_col] + "    " + current[cursor_col:]
                    )
                    cursor_col += 4
                    continue
                if 0 <= key <= 255:
                    character = chr(key)
                    if character.isprintable() and character not in {"\n", "\r"}:
                        current = lines[cursor_row]
                        lines[cursor_row] = (
                            current[:cursor_col] + character + current[cursor_col:]
                        )
                        cursor_col += 1
        finally:
            try:
                curses.curs_set(0)
            except curses.error:
                pass
            stdscr.keypad(True)
            stdscr.timeout(150)

    def _render_match_replace_rules_document(self) -> str:
        return self._render_match_replace_rules_document_from_rules(
            self.store.match_replace_rules()
        )

    def _render_match_replace_rules_document_from_rules(
        self, rules: list[MatchReplaceRule]
    ) -> str:
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
        scope_hosts = self.store.scope_hosts()
        included = [host for host in scope_hosts if not host.startswith("!")]
        excluded = [host for host in scope_hosts if host.startswith("!")]
        lines = [
            "# One host per line.",
            "# In-scope patterns:",
            "#   example.com matches example.com and api.example.com.",
            "#   *.example.com matches only subdomains, not example.com itself.",
            "# Out-of-scope patterns:",
            "#   !test.example.com excludes that host even if a broader include matches it.",
            "# Leave both sections empty to intercept all hosts.",
            "",
            "# In scope",
        ]
        lines.extend(included)
        lines.extend(["", "# Out of scope"])
        lines.extend(excluded)
        return "\n".join(lines).rstrip() + "\n"

    def _render_view_filters_document(self) -> str:
        filters = self.store.view_filters()
        lines = [
            "# Filters applied to Flows and Sitemap.",
            "# query_mode: all | with_query | without_query",
            "# failure_mode: all | failures | hide_failures | client_errors | server_errors | connection_errors",
            "# body_mode: all | with_body | without_body",
            "# methods, hidden_methods and hidden_extensions accept comma-separated values and list items prefixed with '-'.",
            "",
            f"show_out_of_scope: {'true' if filters.show_out_of_scope else 'false'}",
            f"query_mode: {filters.query_mode}",
            f"failure_mode: {filters.failure_mode}",
            f"body_mode: {filters.body_mode}",
            f"methods: {', '.join(filters.methods)}",
            f"hidden_methods: {', '.join(filters.hidden_methods)}",
            "hidden_extensions:",
        ]
        if filters.hidden_extensions:
            lines.extend(f"  - {extension}" for extension in filters.hidden_extensions)
        return "\n".join(lines).rstrip() + "\n"

    def _render_keybindings_document(self) -> str:
        payload = {
            "bindings": self._current_keybindings(),
        }
        return json.dumps(payload, indent=2, ensure_ascii=True) + "\n"

    def _render_keybindings_lines(self) -> list[str]:
        bindings = self._current_keybindings()
        descriptions = self._all_keybinding_descriptions()
        lines: list[str] = []
        for action in sorted(descriptions):
            lines.append(
                f"{action}: {bindings[action]} | {descriptions[action]}"
            )
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
            normalized = TrafficStore._normalize_scope_pattern(candidate)
            if not normalized:
                continue
            if normalized in seen:
                continue
            hosts.append(normalized)
            seen.add(normalized)
        return hosts

    @staticmethod
    def _parse_filters_document(raw_text: str) -> ViewFilterSettings:
        scalar_values: dict[str, str] = {}
        list_values: dict[str, list[str]] = {
            "methods": [],
            "hidden_methods": [],
            "hidden_extensions": [],
        }
        active_list: str | None = None
        for raw_line in raw_text.splitlines():
            candidate = raw_line.strip()
            if not candidate or candidate.startswith("#"):
                continue
            if ":" in candidate and not candidate.startswith("-"):
                key, value = candidate.split(":", 1)
                key = key.strip()
                value = value.strip()
                if key in list_values:
                    active_list = key
                    if value:
                        list_values[key].extend(
                            part.strip() for part in value.split(",") if part.strip()
                        )
                    continue
                active_list = None
                scalar_values[key] = value
                continue
            if active_list in list_values:
                value = (
                    candidate[1:].strip() if candidate.startswith("-") else candidate
                )
                if value:
                    list_values[active_list].extend(
                        part.strip() for part in value.split(",") if part.strip()
                    )

        show_out_of_scope = (
            scalar_values.get("show_out_of_scope", "false").strip().lower()
        )
        if show_out_of_scope not in {
            "true",
            "false",
            "yes",
            "no",
            "on",
            "off",
            "1",
            "0",
        }:
            raise ValueError("show_out_of_scope must be true or false")
        return ViewFilterSettings(
            show_out_of_scope=show_out_of_scope in {"true", "yes", "on", "1"},
            query_mode=scalar_values.get("query_mode", "all"),
            failure_mode=scalar_values.get("failure_mode", "all"),
            body_mode=scalar_values.get("body_mode", "all"),
            methods=list_values["methods"],
            hidden_methods=list_values["hidden_methods"],
            hidden_extensions=list_values["hidden_extensions"],
        )

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
            if any(
                (not character.isprintable()) or character.isspace()
                for character in key_name
            ):
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
                    raise ValueError(
                        f"ambiguous keybinding between {action!r} and {other_action!r}"
                    )
        return normalized

    def _parse_active_keybindings_document(self, raw_text: str) -> dict[str, str]:
        payload = json.loads(raw_text or "{}")
        if not isinstance(payload, dict):
            raise ValueError("keybinding document must be a JSON object")
        bindings = payload.get("bindings", payload)
        if not isinstance(bindings, dict):
            raise ValueError("bindings must be a JSON object")
        bindings = {
            self.LEGACY_KEYBINDING_ACTIONS.get(str(action), str(action)): value
            for action, value in bindings.items()
        }

        normalized: dict[str, str] = {}
        seen: set[str] = set()
        descriptions = self._all_keybinding_descriptions()
        defaults = self._all_default_keybindings()
        for action in descriptions:
            key = bindings.get(action, defaults[action])
            key_name = str(key)
            if len(key_name) not in {1, 2}:
                raise ValueError(f"{action}: key must be one or two characters")
            if any(
                (not character.isprintable()) or character.isspace()
                for character in key_name
            ):
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
                    raise ValueError(
                        f"ambiguous keybinding between {action!r} and {other_action!r}"
                    )
        return normalized

    def _sync_selection(
        self, entries: list[TrafficEntry], pending: list[PendingInterceptionView]
    ) -> None:
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

    def _sync_intercept_selection(
        self, intercept_items: list[PendingInterceptionView]
    ) -> None:
        if not intercept_items:
            self.intercept_selected_index = 0
            return
        self.intercept_selected_index = max(
            0, min(self.intercept_selected_index, len(intercept_items) - 1)
        )

    def _move_intercept_selection(
        self, delta: int, intercept_items: list[PendingInterceptionView]
    ) -> None:
        if not intercept_items:
            self.intercept_selected_index = 0
            return
        self.intercept_selected_index = max(
            0, min(len(intercept_items) - 1, self.intercept_selected_index + delta)
        )

    def _selected_intercept_item(
        self,
        intercept_items: list[PendingInterceptionView],
    ) -> PendingInterceptionView | None:
        if not intercept_items:
            return None
        self._sync_intercept_selection(intercept_items)
        return intercept_items[self.intercept_selected_index]

    def _entry_for_pending(
        self,
        entries: list[TrafficEntry],
        pending: PendingInterceptionView | None,
    ) -> TrafficEntry | None:
        if pending is None:
            return None
        entry = next((entry for entry in entries if entry.id == pending.entry_id), None)
        if entry is not None:
            return entry
        return self.store.get(pending.entry_id)

    def _selected_pending_interception(
        self, entry_id: int | None
    ) -> PendingInterceptionView | None:
        if entry_id is None:
            return None
        return self.store.get_pending_interception(entry_id)

    def _current_repeater_session(self) -> RepeaterSession | None:
        if not self.repeater_sessions:
            return None
        self.repeater_index = max(
            0, min(self.repeater_index, len(self.repeater_sessions) - 1)
        )
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
        authority = (
            host
            if entry.request.port == default_port
            else f"{host}:{entry.request.port}"
        )
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
        if session is None:
            return ""
        exchange = self._selected_repeater_exchange(session)
        return session.request_text if exchange is None else exchange.request_text

    @property
    def repeater_response_text(self) -> str:
        session = self._current_repeater_session()
        if session is None:
            return ""
        exchange = self._selected_repeater_exchange(session)
        return session.response_text if exchange is None else exchange.response_text

    @property
    def repeater_source_entry_id(self) -> int | None:
        session = self._current_repeater_session()
        return session.source_entry_id if session is not None else None

    def _open_export_workspace(
        self,
        entries: list[TrafficEntry],
        selected: TrafficEntry | None,
        selected_intercept: PendingInterceptionView | None,
    ) -> None:
        entries = entries or []
        if self._is_findings_tab():
            findings = self._findings(entries)
            finding = self._selected_findings_finding(findings)
            if finding is None:
                self._set_status("Select a finding before exporting.")
                return
            entry = self.store.get(finding.entry_id)
            if entry is None:
                self._set_status("Flow for selected finding is not available.")
                return
            source = ExportRequestSource(
                label=f"Finding #{finding.entry_id}: {finding.title}",
                request_text=self._render_repeater_request(entry),
                response_text=self._render_entry_response(entry),
                entry_id=entry.id,
                host_hint=entry.request.host,
                port_hint=entry.request.port,
                finding=finding,
            )
        else:
            source = self._current_export_source(entries, selected, selected_intercept)
        if source is None:
            self._set_status("Select an HTTP request first.")
            return
        self.export_source = source
        self.active_tab = self._export_tab_index()
        self.active_pane = "export_menu"
        self.export_selected_index = 0
        self.export_menu_x_scroll = 0
        self.export_detail_scroll = 0
        self.export_detail_x_scroll = 0
        self._set_status(f"Loaded {source.label} into Export.")

    def _current_export_source(
        self,
        entries: list[TrafficEntry],
        selected: TrafficEntry | None,
        selected_intercept: PendingInterceptionView | None,
    ) -> ExportRequestSource | None:
        if self.active_tab == 2:
            session = self._current_repeater_session()
            if session is None or not session.request_text:
                return None
            entry = (
                self.store.get(session.source_entry_id)
                if session.source_entry_id is not None
                else None
            )
            host_hint = entry.request.host if entry is not None else ""
            port_hint = entry.request.port if entry is not None else 80
            exchange = self._selected_repeater_exchange(session)
            label = f"Repeater #{self.repeater_index + 1}"
            if session.source_entry_id is not None:
                label = f"{label} from flow #{session.source_entry_id}"
            if exchange is not None:
                label = f"{label} send #{session.selected_exchange_index}"
            return ExportRequestSource(
                label=label,
                request_text=session.request_text
                if exchange is None
                else exchange.request_text,
                response_text=session.response_text
                if exchange is None
                else exchange.response_text,
                entry_id=session.source_entry_id,
                host_hint=host_hint,
                port_hint=port_hint,
            )
        if self.active_tab == 3:
            entry = self._selected_sitemap_entry(entries)
            if entry is None:
                return None
            return ExportRequestSource(
                label=f"Sitemap flow #{entry.id}",
                request_text=self._render_repeater_request(entry),
                response_text=self._render_entry_response(entry),
                entry_id=entry.id,
                host_hint=entry.request.host,
                port_hint=entry.request.port,
            )
        if self.active_tab == 1:
            if selected_intercept is None:
                return None
            entry = self._entry_for_pending(entries, selected_intercept)
            if selected_intercept.phase == "request":
                request_text = selected_intercept.raw_text
            elif entry is not None:
                request_text = self._render_repeater_request(entry)
            else:
                return None
            host_hint = entry.request.host if entry is not None else ""
            port_hint = entry.request.port if entry is not None else 80
            return ExportRequestSource(
                label=f"Intercept {selected_intercept.phase} for flow #{selected_intercept.entry_id}",
                request_text=request_text,
                response_text=selected_intercept.raw_text
                if selected_intercept.phase == "response"
                else self._render_entry_response(entry),
                entry_id=selected_intercept.entry_id,
                host_hint=host_hint,
                port_hint=port_hint,
            )
        if selected is None:
            return None
        return ExportRequestSource(
            label=f"Flow #{selected.id}",
            request_text=self._render_repeater_request(selected),
            response_text=self._render_entry_response(selected),
            entry_id=selected.id,
            host_hint=selected.request.host,
            port_hint=selected.request.port,
        )

    def _render_entry_response(self, entry: TrafficEntry | None) -> str:
        if entry is None or not entry.response.version:
            return ""
        response = ParsedResponse(
            version=entry.response.version,
            status_code=entry.response.status_code,
            reason=entry.response.reason,
            headers=list(entry.response.headers),
            body=entry.response.body,
            raw=b"",
        )
        return render_response_text(response)

    def _render_export_text(self, kind: str, source: ExportRequestSource) -> str:
        request = parse_request_text(source.request_text)
        if request.method.upper() == "CONNECT":
            raise ValueError("CONNECT requests are not exportable yet")
        if kind.startswith("plugin:"):
            exporter_id = kind.split(":", 1)[1]
            contribution = next(
                (
                    item
                    for item in self.plugin_manager.exporter_contributions()
                    if item.exporter_id == exporter_id
                ),
                None,
            )
            if contribution is None:
                raise ValueError(f"unknown plugin exporter: {exporter_id}")
            response = None
            if source.response_text.strip():
                try:
                    response = parse_response_text(source.response_text)
                except Exception:
                    response = None
            context = self._build_plugin_context(
                plugin_id=contribution.plugin_id,
                request=request,
                response=response,
                export_source=source,
                workspace_id="export",
                tui=self,
            )
            return contribution.render(context)
        url = self._export_request_url(request, source)
        headers = self._export_headers(request.headers)
        if kind == "http_pair":
            return self._render_http_pair_export(source)
        if kind == "python_requests":
            return self._render_python_requests_export(request, url, headers)
        if kind == "curl_bash":
            return self._render_bash_curl_export(request, url, headers)
        if kind == "curl_windows":
            return self._render_windows_curl_export(request, url, headers)
        if kind == "node_fetch":
            return self._render_node_fetch_export(request, url, headers)
        if kind == "go_http":
            return self._render_go_http_export(request, url, headers)
        if kind == "php_curl":
            return self._render_php_curl_export(request, url, headers)
        if kind == "rust_reqwest":
            return self._render_rust_reqwest_export(request, url, headers)
        if kind in {
            "findings_text",
            "findings_json",
            "findings_html",
            "findings_xml",
        }:
            return self._render_findings_export(kind, source)
        raise ValueError(f"unknown export format: {kind}")
        # this point is unreachable

    def _render_findings_export(self, kind: str, source: ExportRequestSource) -> str:
        payload = self._findings_export_payload(source)
        if kind == "findings_text":
            return self._render_findings_text(payload)
        if kind == "findings_json":
            return json.dumps(
                {
                    "entry_id": payload["entry_id"],
                    "title": payload["title"],
                    "description": payload["description"],
                    "recommendation": payload["recommendation"],
                    "severity": payload["severity"],
                    "reported_severity": payload["reported_severity"],
                    "cvss_score": payload["cvss_score"],
                    "cvss_score_text": payload["cvss_score_text"],
                    "cvss_vector": payload["cvss_vector"],
                    "request": payload["request"],
                    "response": payload["response"],
                },
                indent=2,
                ensure_ascii=False,
            )
        if kind == "findings_html":
            return self._render_findings_html(payload)
        if kind == "findings_xml":
            return self._render_findings_xml(payload)
        raise ValueError(f"unknown findings export format: {kind}")

    def _findings_export_payload(self, source: ExportRequestSource) -> dict[str, str | float | None]:
        finding = source.finding
        if finding is None:
            raise ValueError("No finding loaded for export.")
        recommendation = finding.recommendation or "No recommendation provided."
        return {
            "entry_id": finding.entry_id,
            "title": finding.title,
            "description": finding.description,
            "recommendation": recommendation,
            "severity": finding.cvss_severity_label(),
            "reported_severity": finding.severity.capitalize(),
            "cvss_score": finding.cvss_score,
            "cvss_score_text": finding.cvss_score_display(),
            "cvss_vector": finding.cvss_vector or "unknown",
            "request": source.request_text or "",
            "response": source.response_text or "",
        }

    def _render_findings_text(self, payload: dict[str, str | float | None]) -> str:
        request = payload["request"] or "(empty request)"
        response = payload["response"] or "(empty response)"
        return "\n".join(
            [
                f"Finding: {payload['title']}",
                f"Severity (CVSS): {payload['severity']}",
                f"CVSS Vector: {payload['cvss_vector']}",
                f"Reported severity: {payload['reported_severity']}",
                f"CVSS Score: {payload['cvss_score_text']}",
                "",
                "Description:",
                payload["description"],
                "",
                "Recommendation:",
                payload["recommendation"],
                "",
                "Request:",
                request,
                "",
                "Response:",
                response,
            ]
        )

    def _render_findings_html(self, payload: dict[str, str | float | None]) -> str:
        title = html.escape(payload["title"])
        description = html.escape(payload["description"])
        recommendation = html.escape(payload["recommendation"])
        severity = html.escape(payload["severity"])
        reported = html.escape(str(payload["reported_severity"]))
        cvss_score = html.escape(str(payload["cvss_score_text"]))
        request = html.escape(payload["request"] or "(empty request)")
        response = html.escape(payload["response"] or "(empty response)")
        return "\n".join(
            [
                "<!DOCTYPE html>",
                "<html>",
                "<head>",
                '<meta charset="utf-8">',
                f"<title>Finding export – {title}</title>",
                "</head>",
                "<body>",
                f"<h1>Finding: {title}</h1>",
                f"<p><strong>Severity (CVSS):</strong> {severity}</p>",
                f"<p><strong>Reported severity:</strong> {reported}</p>",
                f"<p><strong>CVSS Score:</strong> {cvss_score}</p>",
                "<h2>Description</h2>",
                f"<p>{description}</p>",
                "<h2>Recommendation</h2>",
                f"<p>{recommendation}</p>",
                f"<p><strong>CVSS Vector:</strong> {html.escape(payload['cvss_vector'])}</p>",
                "<h2>Request</h2>",
                f"<pre><code>{request}</code></pre>",
                "<h2>Response</h2>",
                f"<pre><code>{response}</code></pre>",
                "</body>",
                "</html>",
            ]
        )

    def _render_findings_xml(self, payload: dict[str, str | float | None]) -> str:
        def wrap(text: str) -> str:
            return self._wrap_cdata(text or "")

        title = html.escape(payload["title"])
        description = html.escape(payload["description"])
        recommendation = html.escape(payload["recommendation"])
        severity = html.escape(payload["severity"])
        reported = html.escape(str(payload["reported_severity"]))
        cvss_score = html.escape(str(payload["cvss_score_text"]))
        request = wrap(payload["request"])
        response = wrap(payload["response"])
        cvss_vector = html.escape(str(payload["cvss_vector"]))
        return "\n".join(
            [
                "<finding>",
                f"  <title>{title}</title>",
                f"  <severity>{severity}</severity>",
                f"  <reportedSeverity>{reported}</reportedSeverity>",
                f"  <cvssScore>{cvss_score}</cvssScore>",
                f"  <cvssVector>{cvss_vector}</cvssVector>",
                "  <description>",
                f"    {description}",
                "  </description>",
                "  <recommendation>",
                f"    {recommendation}",
                "  </recommendation>",
                "  <request>",
                f"    {request}",
                "  </request>",
                "  <response>",
                f"    {response}",
                "  </response>",
                "</finding>",
            ]
        )

    @staticmethod
    def _wrap_cdata(text: str) -> str:
        safe = text.replace("]]>", "]]]]><![CDATA[>")
        return f"<![CDATA[{safe}]]>"

    def _copy_selected_export(self) -> None:
        if not self._is_export_tab():
            return
        source = self.export_source
        if source is None:
            self._set_status("No request loaded in Export.")
            return
        items = self._export_format_items()
        self._sync_export_selection(items)
        if not items:
            self._set_status("No export formats available.")
            return
        item = items[self.export_selected_index]
        try:
            export_text = self._render_export_text(item.kind, source)
            strategy = self._clipboard_copy(export_text)
        except Exception as exc:
            self._set_status(f"Clipboard copy failed: {exc}")
            return
        label = item.label
        if strategy:
            self._set_status(f"Copied {label} via {strategy}.")
            return
        self._set_status(f"Copied {label} to clipboard.")

    def _export_request_url(
        self, request: ParsedRequest, source: ExportRequestSource
    ) -> str:
        lowered = request.target.lower()
        if lowered.startswith(("http://", "https://", "ws://", "wss://")):
            return request.target
        host_header = (
            self._find_header_value(request.headers, "Host") or source.host_hint
        )
        if not host_header:
            raise ValueError("request is missing a Host header")
        host, port = self._split_host_port(host_header, source.port_hint)
        scheme = "https" if port == 443 or source.port_hint == 443 else "http"
        default_port = 443 if scheme == "https" else 80
        authority = host if port == default_port else f"{host}:{port}"
        path = request.target or "/"
        return f"{scheme}://{authority}{path}"

    @staticmethod
    def _find_header_value(headers: HeaderList, name: str) -> str:
        for header_name, value in headers:
            if header_name.lower() == name.lower():
                return value
        return ""

    @staticmethod
    def _split_host_port(host_header: str, default_port: int) -> tuple[str, int]:
        if host_header.startswith("[") and "]" in host_header:
            host, _, remainder = host_header.partition("]")
            host = f"{host}]"
            if remainder.startswith(":") and remainder[1:].isdigit():
                return host, int(remainder[1:])
            return host, default_port
        if host_header.count(":") == 1:
            host, port_text = host_header.rsplit(":", 1)
            if port_text.isdigit():
                return host, int(port_text)
        return host_header, default_port

    @staticmethod
    def _export_headers(headers: HeaderList) -> HeaderList:
        skipped = {"content-length", "proxy-connection"}
        return [(name, value) for name, value in headers if name.lower() not in skipped]

    def _render_python_requests_export(
        self, request: ParsedRequest, url: str, headers: HeaderList
    ) -> str:
        header_lines = ["headers = {"]
        for name, value in headers:
            header_lines.append(f"    {name!r}: {value!r},")
        header_lines.append("}")
        lines = [
            "import requests",
            "",
            *header_lines,
            "",
            f"response = requests.request({request.method!r}, {url!r},",
            "    headers=headers,",
        ]
        if request.body:
            lines.append(f"    data={request.body!r},")
        lines.extend(
            [
                "    timeout=30,",
                ")",
                "",
                "print(response.status_code)",
                "print(response.text)",
            ]
        )
        return "\n".join(lines)

    def _render_bash_curl_export(
        self, request: ParsedRequest, url: str, headers: HeaderList
    ) -> str:
        lines = [
            f"curl --request {shlex.quote(request.method)} \\",
            f"  --url {shlex.quote(url)} \\",
        ]
        for name, value in headers:
            lines.append(f"  --header {shlex.quote(f'{name}: {value}')} \\")
        if request.body:
            lines.append(f"  --data-binary {self._bash_ansi_c_quote(request.body)}")
        else:
            lines[-1] = lines[-1].removesuffix(" \\")
        return "\n".join(lines)

    def _render_windows_curl_export(
        self, request: ParsedRequest, url: str, headers: HeaderList
    ) -> str:
        lines = [
            f"curl.exe --request {self._powershell_quote(request.method)} `",
            f"  --url {self._powershell_quote(url)} `",
        ]
        for name, value in headers:
            lines.append(f"  --header {self._powershell_quote(f'{name}: {value}')} `")
        if request.body:
            lines.append(
                f"  --data-binary {self._powershell_quote(request.body.decode('iso-8859-1'))}"
            )
        else:
            lines[-1] = lines[-1].removesuffix(" `")
        return "\n".join(lines)

    def _render_node_fetch_export(
        self, request: ParsedRequest, url: str, headers: HeaderList
    ) -> str:
        body_prelude, body_option = self._render_javascript_body(request.body)
        lines = [
            "const headers = {",
            *(f"  {json.dumps(name)}: {json.dumps(value)}," for name, value in headers),
            "};",
            "",
            *body_prelude,
            *([""] if body_prelude else []),
            "const options = {",
            f"  method: {json.dumps(request.method)},",
            "  headers,",
        ]
        if body_option is not None:
            lines.append(body_option)
        lines.extend(
            [
                "};",
                "",
                f"const response = await fetch({json.dumps(url)}, options);",
                "const text = await response.text();",
                "console.log(response.status, text);",
            ]
        )
        return "\n".join(lines)

    def _render_go_http_export(
        self, request: ParsedRequest, url: str, headers: HeaderList
    ) -> str:
        body_setup, body_reader = self._render_go_body_setup(request.body)
        lines = [
            "package main",
            "",
            "import (",
            '    "fmt"',
            '    "io"',
            '    "net/http"',
            *body_setup["imports"],
            ")",
            "",
            "func main() {",
            *body_setup["lines"],
            f"    req, err := http.NewRequest({json.dumps(request.method)}, {json.dumps(url)}, {body_reader})",
            "    if err != nil {",
            "        panic(err)",
            "    }",
        ]
        for name, value in headers:
            lines.append(f"    req.Header.Set({json.dumps(name)}, {json.dumps(value)})")
        lines.extend(
            [
                "",
                "    resp, err := http.DefaultClient.Do(req)",
                "    if err != nil {",
                "        panic(err)",
                "    }",
                "    defer resp.Body.Close()",
                "",
                "    body, err := io.ReadAll(resp.Body)",
                "    if err != nil {",
                "        panic(err)",
                "    }",
                "    fmt.Println(resp.StatusCode, string(body))",
                "}",
            ]
        )
        return "\n".join(lines)

    def _render_php_curl_export(
        self, request: ParsedRequest, url: str, headers: HeaderList
    ) -> str:
        lines = [
            "<?php",
            "",
            f"$ch = curl_init({url!r});",
            "curl_setopt($ch, CURLOPT_CUSTOMREQUEST, " + repr(request.method) + ");",
            "curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);",
        ]
        if headers:
            lines.append("curl_setopt($ch, CURLOPT_HTTPHEADER, [")
            lines.extend(f"    {name!r} . ': ' . {value!r}," for name, value in headers)
            lines.append("]);")
        if request.body:
            body_expr = self._render_php_body_expression(request.body)
            lines.append(f"curl_setopt($ch, CURLOPT_POSTFIELDS, {body_expr});")
        lines.extend(
            [
                "",
                "$response = curl_exec($ch);",
                "if ($response === false) {",
                "    throw new RuntimeException(curl_error($ch));",
                "}",
                "",
                "$status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);",
                "curl_close($ch);",
                "echo $status . PHP_EOL . $response;",
            ]
        )
        return "\n".join(lines)

    def _render_rust_reqwest_export(
        self, request: ParsedRequest, url: str, headers: HeaderList
    ) -> str:
        body_setup, body_expr = self._render_rust_body_setup(request.body)
        lines = [
            "use reqwest::blocking::Client;",
            "use reqwest::header::HeaderMap;",
            *body_setup["imports"],
            "",
            "fn main() -> Result<(), Box<dyn std::error::Error>> {",
            "    let client = Client::new();",
            "    let mut headers = HeaderMap::new();",
        ]
        for name, value in headers:
            lines.append(
                f"    headers.insert({json.dumps(name)}, {json.dumps(value)}.parse()?);"
            )
        lines.extend(body_setup["lines"])
        lines.extend(
            [
                f"    let response = client.request(reqwest::Method::{request.method.upper()}, {json.dumps(url)})",
                "        .headers(headers)",
            ]
        )
        if request.body:
            lines.append(f"        .body({body_expr})")
        lines.extend(
            [
                "        .send()?;",
                "",
                '    println!("{}", response.status());',
                '    println!("{}", response.text()?);',
                "    Ok(())",
                "}",
            ]
        )
        return "\n".join(lines)

    def _render_http_pair_export(self, source: ExportRequestSource) -> str:
        request_text = source.request_text.strip("\n")
        response_text = source.response_text.strip("\n")
        if not response_text:
            return request_text
        return f"{request_text}\n\n{response_text}"

    def _render_javascript_body(self, body: bytes) -> tuple[list[str], str | None]:
        if not body:
            return [], None
        text_body = self._export_text_body(body)
        if text_body is not None:
            return [], f"  body: {json.dumps(text_body)},"
        encoded = self._base64_body(body)
        return [
            f'const body = Buffer.from({json.dumps(encoded)}, "base64");'
        ], "  body,"

    def _render_go_body_setup(self, body: bytes) -> tuple[dict[str, list[str]], str]:
        if not body:
            return {"imports": [], "lines": []}, "nil"
        text_body = self._export_text_body(body)
        if text_body is not None:
            return {
                "imports": ['    "strings"'],
                "lines": [f"    body := strings.NewReader({json.dumps(text_body)})"],
            }, "body"
        byte_values = ", ".join(str(byte) for byte in body)
        return {
            "imports": ['    "bytes"'],
            "lines": [f"    body := bytes.NewReader([]byte{{{byte_values}}})"],
        }, "body"

    def _render_php_body_expression(self, body: bytes) -> str:
        text_body = self._export_text_body(body)
        if text_body is not None:
            return repr(text_body)
        return f"base64_decode({self._base64_body(body)!r})"

    def _render_rust_body_setup(self, body: bytes) -> tuple[dict[str, list[str]], str]:
        if not body:
            return {"imports": [], "lines": []}, "String::new()"
        text_body = self._export_text_body(body)
        if text_body is not None:
            return {
                "imports": [],
                "lines": [f"    let body = {json.dumps(text_body)}.to_string();"],
            }, "body"
        byte_values = ", ".join(f"0x{byte:02x}" for byte in body)
        return {
            "imports": [],
            "lines": [f"    let body = vec![{byte_values}];"],
        }, "body"

    @staticmethod
    def _base64_body(body: bytes) -> str:
        return base64.b64encode(body).decode("ascii")

    @staticmethod
    def _export_text_body(body: bytes) -> str | None:
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            if not all(byte in {9, 10, 13} or 32 <= byte <= 126 for byte in body):
                return None
            text = body.decode("ascii")
        if any(ord(character) < 32 and character not in "\r\n\t" for character in text):
            return None
        return text

    @staticmethod
    def _bash_ansi_c_quote(data: bytes) -> str:
        parts = ["$'"]
        for byte in data:
            character = chr(byte)
            if character == "\\":
                parts.append("\\\\")
            elif character == "'":
                parts.append("\\'")
            elif character == "\n":
                parts.append("\\n")
            elif character == "\r":
                parts.append("\\r")
            elif character == "\t":
                parts.append("\\t")
            elif 32 <= byte <= 126:
                parts.append(character)
            else:
                parts.append(f"\\x{byte:02x}")
        parts.append("'")
        return "".join(parts)

    @staticmethod
    def _powershell_quote(text: str) -> str:
        return "'" + text.replace("'", "''") + "'"
