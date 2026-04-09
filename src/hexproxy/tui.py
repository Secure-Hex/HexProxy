from __future__ import annotations

import curses
from datetime import datetime, timezone
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
from time import monotonic

from .models import HeaderList, TrafficEntry
from .proxy import parse_request_text
from .store import PendingInterceptionView, TrafficStore


class ProxyTUI:
    TABS = ["Overview", "Intercept", "Req Headers", "Req Body", "Res Headers", "Res Body"]

    def __init__(self, store: TrafficStore, listen_host: str, listen_port: int) -> None:
        self.store = store
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.selected_index = 0
        self.active_tab = 0
        self.status_message = ""
        self.status_until = 0.0

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

        while True:
            entries = self.store.snapshot()
            pending = self.store.pending_interceptions()
            self._sync_selection(entries, pending)
            selected = entries[self.selected_index] if entries else None

            self._draw(stdscr, entries, selected, pending)

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
            elif key in (ord("i"), ord("I")):
                self._toggle_intercept_mode()
            elif key in (ord("a"), ord("A")):
                self._forward_intercepted_request(selected_id)
            elif key in (ord("x"), ord("X")):
                self._drop_intercepted_request(selected_id)
            elif key in (ord("e"), ord("E")):
                self._edit_intercepted_request(stdscr, selected_id)
            elif key == curses.KEY_RESIZE:
                stdscr.erase()

    def _draw(
        self,
        stdscr,
        entries: list[TrafficEntry],
        selected: TrafficEntry | None,
        pending: list[PendingInterceptionView],
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
        header = (
            f" HexProxy HTTP | listening on {self.listen_host}:{self.listen_port} | captured: {len(entries)} "
            f"| intercept: {intercept_mode} | pending: {len(pending)} | project: {project_label} "
        )
        stdscr.addnstr(0, 0, header.ljust(width - 1), width - 1, curses.A_REVERSE)

        self._draw_box(stdscr, 1, 0, height - 3, left_width, "Flows")
        self._draw_box(stdscr, 1, right_x, height - 3, right_width, self.TABS[self.active_tab])
        stdscr.addnstr(height - 1, 0, self._footer_text(width).ljust(width - 1), width - 1, curses.A_REVERSE)

        self._draw_flow_list(stdscr, 2, 1, height - 5, left_width - 2, entries)
        self._draw_detail(stdscr, 2, right_x + 1, height - 5, right_width - 2, selected, pending)
        stdscr.refresh()

    def _draw_flow_list(self, stdscr, y: int, x: int, height: int, width: int, entries: list[TrafficEntry]) -> None:
        header = f"{'#':<4} {'M':<6} {'S':<5} {'Host':<18} Path"
        stdscr.addnstr(y, x, header.ljust(width), width, curses.A_BOLD)

        for index, entry in enumerate(entries[: max(0, height - 1)]):
            row_y = y + 1 + index
            status = self._status_label(entry)
            host = self._trim(entry.summary_host, 18)
            path = self._trim(entry.summary_path, max(1, width - 37))
            line = f"{entry.id:<4} {entry.request.method[:6]:<6} {status:<5} {host:<18} {path}"

            attr = curses.A_NORMAL
            if index == self.selected_index and curses.has_colors():
                attr = curses.color_pair(1)
            elif index == self.selected_index:
                attr = curses.A_REVERSE
            elif entry.state in {"error", "dropped"} and curses.has_colors():
                attr = curses.color_pair(3)
            elif entry.state == "intercepted" and curses.has_colors():
                attr = curses.color_pair(4)
            elif entry.response.status_code and curses.has_colors():
                attr = curses.color_pair(2)
            stdscr.addnstr(row_y, x, line.ljust(width), width, attr)

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
                    f"Last save: {saved}",
                    f"Save error: {last_save_error or '-'}",
                    "",
                    f"Error: {entry.error or '-'}",
                ]
            case 2:
                return self._headers_to_lines(entry.request.headers, width)
            case 3:
                return self._body_to_lines(entry.request.body, width)
            case 4:
                return self._headers_to_lines(entry.response.headers, width)
            case 5:
                return self._body_to_lines(entry.response.body, width)
        return []

    def _build_intercept_lines(
        self,
        entry: TrafficEntry | None,
        pending: list[PendingInterceptionView],
        width: int,
    ) -> list[str]:
        enabled = "ON" if self.store.intercept_enabled() else "OFF"
        lines = [
            f"Intercept mode: {enabled}",
            f"Pending queue: {len(pending)}",
            "",
            "Controls:",
            "i toggle mode | e edit request | a forward | x drop",
            "",
        ]
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

    def _toggle_intercept_mode(self) -> None:
        new_state = not self.store.intercept_enabled()
        self.store.set_intercept_enabled(new_state)
        self._set_status(f"Intercept mode {'enabled' if new_state else 'disabled'}.")

    def _forward_intercepted_request(self, entry_id: int | None) -> None:
        if entry_id is None:
            self._set_status("No flow selected.")
            return
        try:
            self.store.forward_pending_interception(entry_id)
        except KeyError:
            self._set_status("Selected flow is not intercepted.")
            return
        self._set_status(f"Forwarded intercepted flow #{entry_id}.")

    def _drop_intercepted_request(self, entry_id: int | None) -> None:
        if entry_id is None:
            self._set_status("No flow selected.")
            return
        try:
            self.store.drop_pending_interception(entry_id)
        except KeyError:
            self._set_status("Selected flow is not intercepted.")
            return
        self._set_status(f"Dropped intercepted flow #{entry_id}.")

    def _edit_intercepted_request(self, stdscr, entry_id: int | None) -> None:
        if entry_id is None:
            self._set_status("No flow selected.")
            return
        pending = self.store.get_pending_interception(entry_id)
        if pending is None:
            self._set_status("Selected flow is not intercepted.")
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

        self.store.update_pending_interception(entry_id, edited)
        self._set_status(f"Updated intercepted flow #{entry_id}.")

    def _footer_text(self, width: int) -> str:
        controls = " q quit | j/k move | tab switch | i intercept | e edit | a send | x drop | s save "
        if self.status_message and monotonic() < self.status_until:
            return self._trim(f"{controls}| {self.status_message}", max(1, width - 1))
        return controls

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
