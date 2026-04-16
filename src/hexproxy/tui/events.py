from __future__ import annotations

import curses

from ..models import TrafficEntry
from ..store import PendingInterceptionView


class EventLoopMixin:
    def _main(self, stdscr) -> None:
        curses.curs_set(0)
        stdscr.keypad(True)
        stdscr.timeout(150)
        try:
            curses.mouseinterval(0)
            motion_mask = getattr(curses, "REPORT_MOUSE_POSITION", 0)
            wheel_up = getattr(curses, "BUTTON4_PRESSED", 0)
            wheel_down = getattr(curses, "BUTTON5_PRESSED", 0)
            curses.mousemask(
                curses.BUTTON1_CLICKED
                | curses.BUTTON1_DOUBLE_CLICKED
                | curses.BUTTON1_TRIPLE_CLICKED
                | curses.BUTTON1_RELEASED
                | wheel_up
                | wheel_down
                | motion_mask
            )
        except curses.error:
            pass
        if curses.has_colors():
            curses.start_color()
            try:
                curses.use_default_colors()
            except curses.error:
                pass
            self._apply_theme_colors()

        while True:
            entries = self._entries_for_view()
            pending = self.store.pending_interceptions()
            intercept_items = self.store.interception_history()
            self._sync_selection(entries, pending)
            self._sync_active_pane()
            if self.active_tab == 1:
                self._sync_intercept_selection(intercept_items)
                selected_intercept = self._selected_intercept_item(intercept_items)
                selected_pending = (
                    selected_intercept
                    if selected_intercept is not None and selected_intercept.active
                    else None
                )
                selected = self._entry_for_pending(entries, selected_intercept)
                self._sync_detail_scroll(
                    selected_intercept.record_id
                    if selected_intercept is not None
                    else None
                )
            else:
                selected_intercept = None
                selected = entries[self.selected_index] if entries else None
                selected_pending = self._selected_pending_interception(
                    selected.id if selected is not None else None
                )
                self._sync_detail_scroll(selected.id if selected is not None else None)

            self._draw(
                stdscr,
                entries,
                selected,
                pending,
                selected_pending,
                intercept_items,
                selected_intercept,
            )

            key = stdscr.getch()
            if self._is_keybindings_tab() and self._handle_keybinding_capture(key):
                continue
            if key == curses.KEY_MOUSE:
                if self._handle_mouse_event(
                    stdscr,
                    entries,
                    selected,
                    selected_intercept,
                    selected_pending,
                    intercept_items,
                ):
                    return
                continue
            if key in (ord("q"), ord("Q")):
                self._pending_action_sequence = ""
                if self.execute_action(
                    stdscr,
                    "quit",
                    entries,
                    selected,
                    selected_intercept,
                    selected_pending,
                ):
                    return
                continue
            if key in (getattr(curses, "KEY_SLEFT", -1), ord("H")):
                self._pending_action_sequence = ""
                self.execute_action(
                    stdscr,
                    "pan_left",
                    entries,
                    selected,
                    selected_intercept,
                    selected_pending,
                )
                continue
            if key in (getattr(curses, "KEY_SRIGHT", -1), ord("L")):
                self._pending_action_sequence = ""
                self.execute_action(
                    stdscr,
                    "pan_right",
                    entries,
                    selected,
                    selected_intercept,
                    selected_pending,
                )
                continue
            action = self._consume_bound_action(key)
            if action is not None:
                if self.execute_action(
                    stdscr,
                    action,
                    entries,
                    selected,
                    selected_intercept,
                    selected_pending,
                ):
                    return
                continue
            if self._pending_action_sequence:
                continue
            if key in (curses.KEY_LEFT, ord("h")):
                self._pending_action_sequence = ""
                self.execute_action(
                    stdscr,
                    "pane_left",
                    entries,
                    selected,
                    selected_intercept,
                    selected_pending,
                )
            elif key in (curses.KEY_RIGHT, ord("l")):
                self._pending_action_sequence = ""
                self.execute_action(
                    stdscr,
                    "pane_right",
                    entries,
                    selected,
                    selected_intercept,
                    selected_pending,
                )
            elif key in (curses.KEY_UP, ord("k")):
                self._pending_action_sequence = ""
                self.execute_action(
                    stdscr,
                    "move_up",
                    entries,
                    selected,
                    selected_intercept,
                    selected_pending,
                )
            elif key in (curses.KEY_DOWN, ord("j")):
                self._pending_action_sequence = ""
                self.execute_action(
                    stdscr,
                    "move_down",
                    entries,
                    selected,
                    selected_intercept,
                    selected_pending,
                )
            elif key in (9, curses.KEY_BTAB):
                self._pending_action_sequence = ""
                self.execute_action(
                    stdscr,
                    "tab_switch",
                    entries,
                    selected,
                    selected_intercept,
                    selected_pending,
                )
            elif key in (ord("m"), ord("M")) and self._is_findings_tab():
                self._pending_action_sequence = ""
                self.execute_action(
                    stdscr,
                    "toggle_findings_flag",
                    entries,
                    selected,
                    selected_intercept,
                    selected_pending,
                )
            elif key == curses.KEY_NPAGE:
                self._pending_action_sequence = ""
                self.execute_action(
                    stdscr,
                    "page_down",
                    entries,
                    selected,
                    selected_intercept,
                    selected_pending,
                )
            elif key == curses.KEY_PPAGE:
                self._pending_action_sequence = ""
                self.execute_action(
                    stdscr,
                    "page_up",
                    entries,
                    selected,
                    selected_intercept,
                    selected_pending,
                )
            elif key == curses.KEY_HOME:
                self._pending_action_sequence = ""
                if self.active_tab == 5:
                    self._set_http_active_scroll(0, len(entries))
                elif self.active_tab == 2:
                    self._set_repeater_active_scroll(0)
                elif self.active_tab == 3:
                    self._set_sitemap_active_scroll(0)
                elif self._is_export_tab():
                    self._set_export_active_scroll(0)
                elif self._is_settings_tab():
                    self._set_settings_active_scroll(0)
                elif self._is_scope_tab():
                    self._set_scope_active_scroll(0)
                elif self._is_filters_tab():
                    self._set_filters_active_scroll(0)
                elif self._is_keybindings_tab():
                    self._set_keybindings_active_scroll(0)
                elif self._is_rule_builder_tab():
                    self._set_rule_builder_active_scroll(0)
                elif self._is_theme_builder_tab():
                    self._set_theme_builder_active_scroll(0)
                elif self._is_plugin_workspace_tab():
                    self._set_plugin_workspace_active_scroll(0)
                elif self._is_findings_tab():
                    self._set_findings_active_scroll(0)
                else:
                    self.detail_scroll = 0
            elif key == curses.KEY_END:
                self._pending_action_sequence = ""
                if self.active_tab == 5:
                    self._set_http_active_scroll(10**9, len(entries))
                elif self.active_tab == 2:
                    self._set_repeater_active_scroll(10**9)
                elif self.active_tab == 3:
                    self._set_sitemap_active_scroll(10**9)
                elif self._is_export_tab():
                    self._set_export_active_scroll(10**9)
                elif self._is_settings_tab():
                    self._set_settings_active_scroll(10**9)
                elif self._is_scope_tab():
                    self._set_scope_active_scroll(10**9)
                elif self._is_filters_tab():
                    self._set_filters_active_scroll(10**9)
                elif self._is_keybindings_tab():
                    self._set_keybindings_active_scroll(10**9)
                elif self._is_rule_builder_tab():
                    self._set_rule_builder_active_scroll(10**9)
                elif self._is_theme_builder_tab():
                    self._set_theme_builder_active_scroll(10**9)
                elif self._is_plugin_workspace_tab():
                    self._set_plugin_workspace_active_scroll(10**9)
                elif self._is_findings_tab():
                    self._set_findings_active_scroll(10**9)
                else:
                    self.detail_scroll = 10**9
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
                self.execute_action(
                    stdscr,
                    "activate",
                    entries,
                    selected,
                    selected_intercept,
                    selected_pending,
                )
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
        self._clickable_regions.clear()
        height, width = stdscr.getmaxyx()
        if height < 12 or width < 60:
            stdscr.addnstr(0, 0, "Terminal too small for HexProxy.", max(1, width - 1))
            stdscr.refresh()
            return

        layout_key = self._layout_key_for_tab() or "overview"
        left_width, right_width = self._split_horizontal(width, layout_key)
        right_x = left_width + 1

        project_path = self.store.project_path()
        project_label = str(project_path) if project_path is not None else "no project"
        intercept_mode = self.store.intercept_mode().upper()
        plugins_loaded = len(self.plugin_manager.loaded_plugins())
        repeater_count = len(self.repeater_sessions)
        visible_label = str(len(entries))
        total_entries = self.store.count()
        if len(entries) != total_entries:
            visible_label = f"{len(entries)}/{total_entries}"
        header = (
            f" HexProxy HTTP | listening on {self.listen_host}:{self.listen_port} | captured: {visible_label} "
            f"| intercept: {intercept_mode} | pending: {len(pending)} | plugins: {plugins_loaded} "
            f"| repeater: {repeater_count} | project: {project_label} "
        )
        stdscr.addnstr(0, 0, header.ljust(width - 1), width - 1, self._chrome_attr())

        if self.active_tab == 2:
            self._render_footer_line(stdscr, height, width, selected_pending)
            self._draw_repeater_workspace(stdscr, height, width)
            stdscr.refresh()
            return
        if self.active_tab == 3:
            self._render_footer_line(stdscr, height, width, selected_pending)
            self._draw_sitemap_workspace(stdscr, height, width, entries)
            stdscr.refresh()
            return
        if self.active_tab == 5:
            self._render_footer_line(stdscr, height, width, selected_pending)
            self._draw_http_workspace(stdscr, height, width, entries, selected)
            stdscr.refresh()
            return
        if self._is_settings_tab():
            self._render_footer_line(stdscr, height, width, selected_pending)
            self._draw_settings_workspace(stdscr, height, width)
            stdscr.refresh()
            return
        if self._is_scope_tab():
            self._render_footer_line(stdscr, height, width, selected_pending)
            self._draw_scope_workspace(stdscr, height, width)
            stdscr.refresh()
            return
        if self._is_filters_tab():
            self._render_footer_line(stdscr, height, width, selected_pending)
            self._draw_filters_workspace(stdscr, height, width)
            stdscr.refresh()
            return
        if self._is_export_tab():
            self._render_footer_line(stdscr, height, width, selected_pending)
            self._draw_export_workspace(stdscr, height, width)
            stdscr.refresh()
            return
        if self._is_keybindings_tab():
            self._render_footer_line(stdscr, height, width, selected_pending)
            self._draw_keybindings_workspace(stdscr, height, width)
            stdscr.refresh()
            return
        if self._is_rule_builder_tab():
            self._render_footer_line(stdscr, height, width, selected_pending)
            self._draw_rule_builder_workspace(stdscr, height, width)
            stdscr.refresh()
            return
        if self._is_theme_builder_tab():
            self._render_footer_line(stdscr, height, width, selected_pending)
            self._draw_theme_builder_workspace(stdscr, height, width)
            stdscr.refresh()
            return
        if self._is_plugin_workspace_tab():
            self._render_footer_line(stdscr, height, width, selected_pending)
            self._draw_plugin_workspace(stdscr, height, width, selected)
            stdscr.refresh()
            return
        if self._is_findings_tab():
            self._render_footer_line(stdscr, height, width, selected_pending)
            self._draw_findings_workspace(stdscr, height, width, entries)
            stdscr.refresh()
            return

        flows_label = "Pending" if self.active_tab == 1 else "Flows"
        flows_title = (
            f"{flows_label} [active]" if self.active_pane == "flows" else flows_label
        )
        tabs = self._workspace_tabs()
        current_label = tabs[self.active_tab] if 0 <= self.active_tab < len(tabs) else tabs[0]
        detail_title = (
            f"{current_label} [active]"
            if self.active_pane == "detail"
            else current_label
        )
        self._draw_box(stdscr, 1, 0, height - 3, left_width, flows_title)
        self._draw_box(stdscr, 1, right_x, height - 3, right_width, detail_title)
        self._render_footer_line(stdscr, height, width, selected_pending)

        self._register_clickable_region(
            "focus_pane",
            1,
            2,
            left_width - 2,
            height - 5,
            payload="flows",
        )
        self._register_clickable_region(
            "focus_pane",
            right_x + 1,
            2,
            right_width - 2,
            height - 5,
            payload="detail",
        )

        if self.active_tab == 1:
            self._draw_intercept_list(
                stdscr, 2, 1, height - 5, left_width - 2, entries, intercept_items
            )
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
