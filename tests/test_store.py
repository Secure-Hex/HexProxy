from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from hexproxy.certs import CertificateAuthority
from hexproxy.models import MatchReplaceRule, RequestData, ResponseData
from hexproxy.store import TrafficStore
from hexproxy.tui import ProxyTUI, RepeaterSession


class TrafficStorePersistenceTests(unittest.TestCase):
    def test_save_and_load_project_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_path = Path(tmpdir) / "session.hexproxy.json"

            store = TrafficStore(project_path=project_path)
            entry_id = store.create_entry("127.0.0.1:50000")
            store.set_match_replace_rules(
                [
                    MatchReplaceRule(
                        enabled=True,
                        scope="request",
                        mode="literal",
                        match="hello",
                        replace="goodbye",
                        description="demo",
                    )
                ]
            )
            store.mutate(entry_id, self._fill_entry)
            store.complete(entry_id)

            self.assertTrue(project_path.exists())

            restored = TrafficStore()
            restored.load(project_path)
            entries = restored.snapshot()

            self.assertEqual(len(entries), 1)
            entry = entries[0]
            self.assertEqual(entry.client_addr, "127.0.0.1:50000")
            self.assertEqual(entry.request.method, "POST")
            self.assertEqual(entry.request.body, b'{"hello":"world"}')
            self.assertEqual(entry.response.status_code, 201)
            self.assertEqual(entry.response.body, b"created")
            self.assertEqual(entry.state, "complete")
            self.assertEqual(len(restored.match_replace_rules()), 1)
            self.assertEqual(restored.match_replace_rules()[0].replace, "goodbye")

    def test_manual_save_writes_valid_project_document(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_path = Path(tmpdir) / "manual.hexproxy.json"

            store = TrafficStore()
            store.set_project_path(project_path)
            store.save()

            payload = json.loads(project_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["version"], 1)
            self.assertEqual(payload["entries"], [])

    def test_project_name_is_resolved_to_default_projects_directory(self) -> None:
        path = ProxyTUI._resolve_project_path("demo")
        self.assertEqual(path, Path("projects/demo.hexproxy.json"))

    def test_nested_project_name_gets_default_extension(self) -> None:
        path = ProxyTUI._resolve_project_path("captures/demo")
        self.assertEqual(path, Path("captures/demo.hexproxy.json"))

    def test_interception_forward_flow(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.set_intercept_mode("request")

        opened = store.begin_interception(entry_id, "request", "GET / HTTP/1.1\nHost: example.test\n\n")

        self.assertTrue(opened)
        pending = store.get_pending_interception(entry_id)
        self.assertIsNotNone(pending)
        self.assertEqual(pending.entry_id, entry_id)
        self.assertEqual(pending.phase, "request")

        store.update_pending_interception(entry_id, "GET /v2 HTTP/1.1\nHost: example.test\n\n")
        store.forward_pending_interception(entry_id)
        result = store.wait_for_interception(entry_id)

        self.assertEqual(result.decision, "forward")
        self.assertEqual(result.phase, "request")
        self.assertIn("/v2", result.raw_text)
        self.assertIsNone(store.get_pending_interception(entry_id))

    def test_interception_drop_marks_entry(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.set_intercept_mode("request")
        store.begin_interception(entry_id, "request", "GET / HTTP/1.1\nHost: example.test\n\n")

        store.drop_pending_interception(entry_id)
        result = store.wait_for_interception(entry_id)
        entry = store.get(entry_id)

        self.assertEqual(result.decision, "drop")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.state, "dropped")
        self.assertEqual(entry.error, "request dropped by interceptor")

    def test_response_interception_drop_marks_entry(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.set_intercept_mode("response")
        store.begin_interception(entry_id, "response", "HTTP/1.1 200 OK\nContent-Length: 0\n\n")

        store.drop_pending_interception(entry_id)
        result = store.wait_for_interception(entry_id)
        entry = store.get(entry_id)

        self.assertEqual(result.decision, "drop")
        self.assertEqual(result.phase, "response")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.state, "dropped")
        self.assertEqual(entry.error, "response dropped by interceptor")

    def test_store_should_intercept_respects_mode(self) -> None:
        store = TrafficStore()
        store.set_intercept_mode("response")

        self.assertFalse(store.should_intercept("request"))
        self.assertTrue(store.should_intercept("response"))

        store.set_intercept_mode("both")
        self.assertTrue(store.should_intercept("request"))
        self.assertTrue(store.should_intercept("response"))

    def test_release_pending_interceptions_unblocks_waiters(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.set_intercept_mode("request")
        store.begin_interception(entry_id, "request", "GET / HTTP/1.1\nHost: example.test\n\n")

        store.release_pending_interceptions("shutdown")
        result = store.wait_for_interception(entry_id)
        entry = store.get(entry_id)

        self.assertEqual(result.decision, "drop")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.state, "dropped")
        self.assertEqual(entry.error, "shutdown")

    def test_tui_footer_only_shows_intercept_actions_for_paused_flow(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            footer = tui._footer_text(200, None)
            self.assertNotIn("e edit", footer)
            self.assertNotIn("a send", footer)
            self.assertNotIn("x drop", footer)
            self.assertIn("c cert", footer)
            self.assertIn("C regen cert", footer)

            store.set_intercept_mode("request")
            store.begin_interception(entry_id, "request", "GET / HTTP/1.1\nHost: example.test\n\n")
            pending = tui._selected_pending_interception(entry_id)
            footer = tui._footer_text(200, pending)

            self.assertIn("e edit", footer)
            self.assertIn("a send", footer)
            self.assertIn("x drop", footer)

    def test_tui_toggle_intercept_mode_cycles_all_modes(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            self.assertEqual(store.intercept_mode(), "off")
            tui._toggle_intercept_mode()
            self.assertEqual(store.intercept_mode(), "request")
            tui._toggle_intercept_mode()
            self.assertEqual(store.intercept_mode(), "response")
            tui._toggle_intercept_mode()
            self.assertEqual(store.intercept_mode(), "both")
            tui._toggle_intercept_mode()
            self.assertEqual(store.intercept_mode(), "off")

    def test_tui_footer_shows_body_toggle_only_on_body_tabs(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            tui.active_tab = 4
            request_body_footer = tui._footer_text(200, None)
            self.assertNotIn("p raw/pretty", request_body_footer)

            tui.active_tab = 5
            request_body_footer = tui._footer_text(200, None)
            self.assertIn("p raw/pretty", request_body_footer)

            tui.active_tab = 7
            response_body_footer = tui._footer_text(200, None)
            self.assertIn("p raw/pretty", response_body_footer)

            tui.active_tab = 0
            overview_footer = tui._footer_text(200, None)
            self.assertNotIn("p raw/pretty", overview_footer)

    def test_tui_footer_shows_repeater_controls_on_repeater_tab(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            tui.active_tab = 2
            footer = tui._footer_text(200, None)

            self.assertIn("y new repeater", footer)
            self.assertIn("e edit req", footer)
            self.assertIn("a send", footer)
            self.assertIn("g send", footer)
            self.assertIn("[/] session", footer)
            self.assertNotIn("i intercept mode", footer)
            self.assertNotIn("c cert", footer)
            self.assertNotIn("C regen cert", footer)

    def test_tui_match_replace_document_parser_accepts_json_object(self) -> None:
        rules = ProxyTUI._parse_match_replace_rules_document(
            """
            {
              "rules": [
                {
                  "enabled": true,
                  "scope": "both",
                  "mode": "regex",
                  "match": "foo+",
                  "replace": "bar",
                  "description": "demo"
                }
              ]
            }
            """
        )

        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].scope, "both")
        self.assertEqual(rules[0].mode, "regex")

    def test_tui_can_generate_and_regenerate_certificate_authority(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            authority = CertificateAuthority(tmpdir)
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=authority,
            )

            tui._ensure_certificate_authority()
            self.assertTrue(authority.cert_path().exists())

            first_content = authority.cert_path().read_bytes()
            tui._regenerate_certificate_authority()
            self.assertTrue(authority.cert_path().exists())
            self.assertNotEqual(first_content, authority.cert_path().read_bytes())

    def test_tui_flow_list_window_scrolls_with_selection(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            entries = []
            for index in range(8):
                store.create_entry(f"127.0.0.1:{5000 + index}")
                entries = store.snapshot()

            tui.selected_index = 6
            start_index, visible_entries = tui._visible_flow_entries(entries, 4)

            self.assertEqual(start_index, 3)
            self.assertEqual([entry.id for entry in visible_entries], [4, 5, 6, 7])

    def test_tui_detail_window_scrolls_with_explicit_offset(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            tui.detail_scroll = 8
            start_index = tui._detail_window_start(total_lines=20, rows=5)

            self.assertEqual(start_index, 8)

    def test_tui_detail_scroll_resets_when_entry_changes(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            tui.detail_scroll = 9
            tui._sync_detail_scroll(1)
            tui.detail_scroll = 4
            tui._sync_detail_scroll(2)

            self.assertEqual(tui.detail_scroll, 0)

    def test_tui_move_active_pane_moves_flow_selection_by_default(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            for index in range(3):
                store.create_entry(f"127.0.0.1:{5000 + index}")

            tui._move_active_pane(1, len(store.snapshot()))

            self.assertEqual(tui.selected_index, 1)
            self.assertEqual(tui.detail_scroll, 0)

    def test_tui_move_active_pane_scrolls_detail_when_detail_is_active(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui.active_pane = "detail"

            tui._move_active_pane(3, 0)

            self.assertEqual(tui.detail_scroll, 3)
            self.assertEqual(tui.selected_index, 0)

    def test_tui_can_load_selected_flow_into_repeater(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.mutate(entry_id, self._fill_entry)
        entry = store.snapshot()[0]
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            tui._load_repeater_from_selected_flow(entry)

            self.assertEqual(tui.active_tab, 2)
            self.assertEqual(tui.repeater_source_entry_id, entry.id)
            self.assertIn("POST http://example.test/api HTTP/1.1", tui.repeater_request_text)
            self.assertEqual(len(tui.repeater_sessions), 1)

    def test_tui_can_keep_multiple_repeater_sessions(self) -> None:
        store = TrafficStore()
        first_id = store.create_entry("127.0.0.1:50000")
        second_id = store.create_entry("127.0.0.1:50001")
        store.mutate(first_id, self._fill_entry)
        store.mutate(second_id, self._fill_https_entry)
        entries = store.snapshot()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            tui._load_repeater_from_selected_flow(entries[0])
            tui._load_repeater_from_selected_flow(entries[1])

            self.assertEqual(len(tui.repeater_sessions), 2)
            self.assertEqual(tui.repeater_index, 1)
            self.assertEqual(tui.repeater_source_entry_id, entries[1].id)

            tui._switch_repeater_session(-1)

            self.assertEqual(tui.repeater_source_entry_id, entries[0].id)

    def test_tui_move_active_pane_scrolls_repeater_request_when_repeater_is_active(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui.repeater_sessions.append(RepeaterSession(request_text="GET / HTTP/1.1\nHost: example.test\n" * 4))
            tui.active_tab = 2
            tui.active_pane = "repeater_request"

            tui._move_active_pane(3, 0)

            self.assertEqual(tui.repeater_sessions[0].request_scroll, 3)

    def test_tui_sync_active_pane_uses_repeater_panes_on_repeater_tab(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui.active_tab = 2
            tui.active_pane = "flows"

            tui._sync_active_pane()

            self.assertEqual(tui.active_pane, "repeater_request")

    def test_tui_repeater_target_uses_https_for_port_443(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.mutate(entry_id, self._fill_https_entry)
        entry = store.snapshot()[0]
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            target = tui._repeater_target(entry)

            self.assertEqual(target, "https://secure.example.test/login")

    @staticmethod
    def _fill_entry(entry) -> None:
        entry.request = RequestData(
            method="POST",
            target="http://example.test/api",
            version="HTTP/1.1",
            headers=[("Host", "example.test"), ("Content-Type", "application/json")],
            body=b'{"hello":"world"}',
            host="example.test",
            port=80,
            path="/api",
        )
        entry.response = ResponseData(
            version="HTTP/1.1",
            status_code=201,
            reason="Created",
            headers=[("Content-Type", "text/plain")],
            body=b"created",
        )
        entry.upstream_addr = "example.test:80"
        entry.state = "complete"

    @staticmethod
    def _fill_https_entry(entry) -> None:
        entry.request = RequestData(
            method="POST",
            target="/login",
            version="HTTP/1.1",
            headers=[("Host", "secure.example.test"), ("Content-Type", "application/x-www-form-urlencoded")],
            body=b"user=demo",
            host="secure.example.test",
            port=443,
            path="/login",
        )
        entry.response = ResponseData(
            version="HTTP/1.1",
            status_code=200,
            reason="OK",
            headers=[("Content-Type", "text/html")],
            body=b"ok",
        )
        entry.upstream_addr = "secure.example.test:443"
        entry.state = "complete"
