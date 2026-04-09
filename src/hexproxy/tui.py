from __future__ import annotations

import curses
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
from time import monotonic

from .bodyview import BodyDocument, build_body_document
from .certs import CertificateAuthority
from .extensions import PluginManager
from .models import HeaderList, MatchReplaceRule, TrafficEntry
from .proxy import parse_request_text
from .store import PendingInterceptionView, TrafficStore


class ProxyTUI:
    TABS = ["Overview", "Intercept", "Match/Replace", "Req Headers", "Req Body", "Res Headers", "Res Body"]

    def __init__(
        self,
        store: TrafficStore,
        listen_host: str,
        listen_port: int,
        certificate_authority: CertificateAuthority,
        plugin_manager: PluginManager | None = None,
    ) -> None:
        self.store = store
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.certificate_authority = certificate_authority
        self.plugin_manager = plugin_manager or PluginManager()
        self.selected_index = 0
        self.active_tab = 0
        self.status_message = ""
        self.status_until = 0.0
        self.request_body_view_mode = "pretty"
        self.response_body_view_mode = "pretty"

    def run(self) -> None:
        curses.wrapper(self._main)

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
            selected = entries[self.selected_index] if entries else None
            selected_pending = self._selected_pending_interception(selected.id if selected is not None else None)

            self._draw(stdscr, entries, selected, pending, selected_pending)

            key = stdscr.getch()
            selected_id = selected.id if selected is not None else None
            if key in (ord("q"), ord("Q")):
                return
            if key in (curses.KEY_UP, ord("k")):
                self.selected_index = max(0, self.selected_index - 1)
            elif key in (curses.KEY_DOWN, ord("j")):
                self.selected_index = min(max(0, len(entries) - 1), self.selected_index + 1)
            elif key in (9, curses.KEY_BTAB):
                self.active_tab = (self.active_tab + 1) % len(self.TABS)
            elif key in (ord("s"), ord("S")):
                self._save_project(stdscr)
            elif key in (ord("r"), ord("R")):
                self._edit_match_replace_rules(stdscr)
            elif key in (ord("p"), ord("P")):
                self._toggle_body_view_mode()
            elif key == ord("c"):
                self._ensure_certificate_authority()
            elif key == ord("C"):
                self._regenerate_certificate_authority()
            elif key in (ord("i"), ord("I")):
                self._toggle_intercept_mode()
            elif key in (ord("a"), ord("A")):
                self._forward_intercepted_request(selected_pending)
            elif key in (ord("x"), ord("X")):
                self._drop_intercepted_request(selected_pending)
            elif key in (ord("e"), ord("E")):
                self._edit_intercepted_request(stdscr, selected_pending)
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
        intercept_mode = "ON" if self.store.intercept_enabled() else "OFF"
        plugins_loaded = len(self.plugin_manager.loaded_plugins())
        header = (
            f" HexProxy HTTP | listening on {self.listen_host}:{self.listen_port} | captured: {len(entries)} "
            f"| intercept: {intercept_mode} | pending: {len(pending)} | plugins: {plugins_loaded} | project: {project_label} "
        )
        stdscr.addnstr(0, 0, header.ljust(width - 1), width - 1, curses.A_REVERSE)

        self._draw_box(stdscr, 1, 0, height - 3, left_width, "Flows")
        self._draw_box(stdscr, 1, right_x, height - 3, right_width, self.TABS[self.active_tab])
        stdscr.addnstr(
            height - 1,
            0,
            self._footer_text(width, selected_pending).ljust(width - 1),
            width - 1,
            curses.A_REVERSE,
        )

        self._draw_flow_list(stdscr, 2, 1, height - 5, left_width - 2, entries)
        self._draw_detail(stdscr, 2, right_x + 1, height - 5, right_width - 2, selected, pending)
        stdscr.refresh()

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
        if self.active_tab in {4, 6}:
            self._draw_body_detail(stdscr, y, x, height, width, entry)
            return
        lines = self._build_detail_lines(entry, pending, width)
        for offset, line in enumerate(lines[:height]):
            stdscr.addnstr(y + offset, x, line.ljust(width), width)

    def _build_detail_lines(
        self,
        entry: TrafficEntry | None,
        pending: list[PendingInterceptionView],
        width: int,
    ) -> list[str]:
        if self.active_tab == 1:
            return self._build_intercept_lines(entry, pending, width)
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
                    f"CA status: {cert_status}",
                    f"CA path: {cert_path}",
                    "CA download URL: http://hexproxy/",
                    "",
                    f"Error: {entry.error or '-'}",
                ]
            case 2:
                return self._build_match_replace_lines(width)
            case 3:
                return self._headers_to_lines(entry.request.headers, width)
            case 4:
                return []
            case 5:
                return self._headers_to_lines(entry.response.headers, width)
            case 6:
                return []
        return []

    def _build_intercept_lines(
        self,
        entry: TrafficEntry | None,
        pending: list[PendingInterceptionView],
        width: int,
    ) -> list[str]:
        intercept_enabled = self.store.intercept_enabled()
        enabled = "ON" if intercept_enabled else "OFF"
        lines = [
            f"Intercept mode: {enabled}",
            f"Pending queue: {len(pending)}",
            "",
            "Controls:",
            "i toggle mode",
            "",
        ]
        if current := self._selected_pending_interception(entry.id if entry is not None else None):
            lines.insert(5, "e edit request | a forward | x drop")
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
                f"Created: {created}",
                f"Updated: {updated}",
                "",
                "Raw request:",
                "",
            ]
        )
        raw_lines = current.raw_request.splitlines() or [current.raw_request]
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
        info_lines = [
            f"Detected: {document.display_name}",
            f"Media-Type: {document.media_type}",
            f"Mode: {mode}",
            "Controls: p toggle raw/pretty",
            "",
        ]

        row = y
        for line in info_lines[:height]:
            stdscr.addnstr(row, x, self._trim(line, width).ljust(width), width)
            row += 1
        if row >= y + height:
            return

        body_text = self._body_text_for_mode(document, mode)
        body_lines = body_text.splitlines() or [body_text]
        for raw_line in body_lines[: y + height - row]:
            safe_line = self._sanitize_display_text(raw_line)
            self._draw_styled_line(stdscr, row, x, width, self._style_body_line(safe_line, document.kind))
            row += 1

    def _current_body_document(self, entry: TrafficEntry) -> tuple[BodyDocument, str]:
        if self.active_tab == 4:
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
        if self.active_tab != 2:
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
        new_state = not self.store.intercept_enabled()
        self.store.set_intercept_enabled(new_state)
        self._set_status(f"Intercept mode {'enabled' if new_state else 'disabled'}.")

    def _forward_intercepted_request(self, pending: PendingInterceptionView | None) -> None:
        if pending is None:
            self._set_status("Select a paused intercepted flow first.")
            return
        try:
            self.store.forward_pending_interception(pending.entry_id)
        except KeyError:
            self._set_status("Selected flow is not intercepted.")
            return
        self._set_status(f"Forwarded intercepted flow #{pending.entry_id}.")

    def _drop_intercepted_request(self, pending: PendingInterceptionView | None) -> None:
        if pending is None:
            self._set_status("Select a paused intercepted flow first.")
            return
        try:
            self.store.drop_pending_interception(pending.entry_id)
        except KeyError:
            self._set_status("Selected flow is not intercepted.")
            return
        self._set_status(f"Dropped intercepted flow #{pending.entry_id}.")

    def _edit_intercepted_request(self, stdscr, pending: PendingInterceptionView | None) -> None:
        if pending is None:
            self._set_status("Select a paused intercepted flow first.")
            return

        edited = self._open_external_editor(stdscr, pending.raw_request)
        if edited is None:
            self._set_status("Edit cancelled.")
            return

        try:
            parse_request_text(edited)
        except Exception as exc:
            self._set_status(f"Invalid edited request: {exc}")
            return

        self.store.update_pending_interception(pending.entry_id, edited)
        self._set_status(f"Updated intercepted flow #{pending.entry_id}.")

    def _toggle_body_view_mode(self) -> None:
        if self.active_tab == 4:
            self.request_body_view_mode = "raw" if self.request_body_view_mode == "pretty" else "pretty"
            mode = self.request_body_view_mode
        elif self.active_tab == 6:
            self.response_body_view_mode = "raw" if self.response_body_view_mode == "pretty" else "pretty"
            mode = self.response_body_view_mode
        else:
            return
        self._set_status(f"Body view mode: {mode}.")

    def _footer_text(self, width: int, selected_pending: PendingInterceptionView | None) -> str:
        controls = " q quit | j/k move | tab switch | i intercept | s save | c cert | C regen cert "
        if self.active_tab == 2:
            controls = f"{controls}| r edit rules "
        elif self.active_tab in {4, 6}:
            controls = f"{controls}| p raw/pretty "
        elif selected_pending is not None:
            controls = f"{controls}| e edit | a send | x drop "
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
