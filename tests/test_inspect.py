from __future__ import annotations

import tempfile
import unittest
from unittest import mock

from hexproxy.certs import CertificateAuthority
from hexproxy.models import RequestData, ResponseData
from hexproxy.store import TrafficStore
from hexproxy.tui import ProxyTUI
from hexproxy.tui.app import ClickableRegion


class InspectWorkspaceTests(unittest.TestCase):
    @staticmethod
    def _fill_long_entry(entry) -> None:
        request_body = "\n".join([f"line-{index}" for index in range(200)] + ["REQ_TAIL_MARKER"])
        response_body = "\n".join([f"row-{index}" for index in range(200)] + ["RESP_TAIL_MARKER"])
        entry.request = RequestData(
            method="POST",
            target="http://example.test/api",
            version="HTTP/1.1",
            headers=[("Host", "example.test"), ("Content-Type", "text/plain")],
            body=request_body.encode("utf-8"),
            host="example.test",
            port=80,
            path="/api",
        )
        entry.response = ResponseData(
            version="HTTP/1.1",
            status_code=200,
            reason="OK",
            headers=[("Content-Type", "text/plain")],
            body=response_body.encode("utf-8"),
        )

    @staticmethod
    def _flatten_inspect_lines(lines) -> str:
        rendered: list[str] = []
        for value, _kind in lines:
            if isinstance(value, list):
                rendered.append("".join(segment for segment, _attr in value))
            else:
                rendered.append(str(value))
        return "\n".join(rendered)

    def test_can_open_expanded_request_from_http_workspace(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.mutate(entry_id, self._fill_long_entry)
        entries = store.visible_entries()
        selected = entries[0]

        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui.active_tab = 5
            tui.active_pane = "http_request"
            tui.selected_index = 0

            tui.execute_action(mock.Mock(), "open_expand", entries, selected, None, None)

            self.assertEqual(tui.active_tab, tui._inspect_tab_index())
            self.assertEqual(tui.inspect_mode, "request")
            self.assertEqual(tui.inspect_source, "entry")
            self.assertEqual(tui.inspect_entry_id, selected.id)
            self.assertIn("REQ_TAIL_MARKER", self._flatten_inspect_lines(tui._inspect_message_lines()))

    def test_can_open_expanded_response_from_http_workspace(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.mutate(entry_id, self._fill_long_entry)
        entries = store.visible_entries()
        selected = entries[0]

        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui.active_tab = 5
            tui.active_pane = "http_response"
            tui.selected_index = 0

            tui.execute_action(mock.Mock(), "open_expand", entries, selected, None, None)

            self.assertEqual(tui.active_tab, tui._inspect_tab_index())
            self.assertEqual(tui.inspect_mode, "response")
            self.assertEqual(tui.inspect_source, "entry")
            self.assertEqual(tui.inspect_entry_id, selected.id)
            self.assertIn("RESP_TAIL_MARKER", self._flatten_inspect_lines(tui._inspect_message_lines()))

    def test_back_restores_workspace_and_selection_context(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.mutate(entry_id, self._fill_long_entry)
        entries = store.visible_entries()
        selected = entries[0]

        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui.active_tab = 5
            tui.active_pane = "http_request"
            tui.selected_index = 0

            tui.execute_action(mock.Mock(), "open_expand", entries, selected, None, None)
            tui.execute_action(mock.Mock(), "back", entries, selected, None, None)

            self.assertEqual(tui.active_tab, 5)
            self.assertEqual(tui.active_pane, "http_request")
            self.assertEqual(tui.selected_index, 0)

    def test_open_expand_toggles_between_request_and_response_inside_inspect(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.mutate(entry_id, self._fill_long_entry)
        entries = store.visible_entries()
        selected = entries[0]

        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui.active_tab = 5
            tui.active_pane = "http_request"
            tui.selected_index = 0

            tui.execute_action(mock.Mock(), "open_expand", entries, selected, None, None)
            self.assertEqual(tui.active_tab, tui._inspect_tab_index())
            self.assertEqual(tui.inspect_mode, "request")

            tui.execute_action(mock.Mock(), "open_expand", entries, selected, None, None)
            self.assertEqual(tui.inspect_mode, "response")

            tui.execute_action(mock.Mock(), "open_expand", entries, selected, None, None)
            self.assertEqual(tui.inspect_mode, "request")

    def test_double_click_on_request_pane_opens_inspect(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.mutate(entry_id, self._fill_long_entry)
        entries = store.visible_entries()
        selected = entries[0]

        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui.active_tab = 5
            tui.active_pane = "flows"

            region = ClickableRegion(action="focus_pane", x=0, y=0, width=10, payload="http_request")
            tui._activate_clickable_region(
                region,
                mock.Mock(),
                entries,
                selected,
                None,
                None,
                intercept_items=[],
                double_click=True,
            )

            self.assertEqual(tui.active_tab, tui._inspect_tab_index())
            self.assertEqual(tui.inspect_mode, "request")
