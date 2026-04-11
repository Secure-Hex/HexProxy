from __future__ import annotations

import curses
import gzip
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from hexproxy.certs import CertificateAuthority
from hexproxy.extensions import PluginManager
from hexproxy.models import MatchReplaceRule, RequestData, ResponseData
from hexproxy.store import TrafficStore, ViewFilterSettings
from hexproxy.themes import ThemeManager
from hexproxy.tui import ProxyTUI, RepeaterExchange, RepeaterSession


class TrafficStorePersistenceTests(unittest.TestCase):
    def test_save_and_load_project_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_path = Path(tmpdir) / "session.hexproxy.json"

            store = TrafficStore(project_path=project_path)
            entry_id = store.create_entry("127.0.0.1:50000")
            store.set_scope_hosts(["example.test"])
            store.set_view_filters(
                ViewFilterSettings(
                    show_out_of_scope=True,
                    query_mode="with_query",
                    failure_mode="failures",
                    body_mode="with_body",
                    methods=["POST"],
                    hidden_methods=["GET"],
                    hidden_extensions=["png", "jpg"],
                )
            )
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
            store.set_plugin_value("demo", "enabled", True)
            store.mutate(entry_id, self._fill_entry)
            store.set_entry_plugin_metadata(entry_id, "demo", {"severity": "high"})
            store.set_entry_plugin_findings(entry_id, "demo", ["interesting response"])
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
            self.assertEqual(restored.scope_hosts(), ["example.test"])
            restored_filters = restored.view_filters()
            self.assertTrue(restored_filters.show_out_of_scope)
            self.assertEqual(restored_filters.query_mode, "with_query")
            self.assertEqual(restored_filters.failure_mode, "failures")
            self.assertEqual(restored_filters.body_mode, "with_body")
            self.assertEqual(restored_filters.methods, ["POST"])
            self.assertEqual(restored_filters.hidden_methods, ["GET"])
            self.assertEqual(restored_filters.hidden_extensions, ["png", "jpg"])
            self.assertEqual(len(restored.match_replace_rules()), 1)
            self.assertEqual(restored.match_replace_rules()[0].replace, "goodbye")
            self.assertTrue(restored.plugin_state("demo")["enabled"])
            self.assertEqual(entry.plugin_metadata["demo"]["severity"], "high")
            self.assertEqual(entry.plugin_findings["demo"], ["interesting response"])

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

        history = store.interception_history()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].decision, "forward")
        self.assertFalse(history[0].active)

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

    def test_interception_history_keeps_request_and_response_records(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.set_intercept_mode("both")
        store.begin_interception(entry_id, "request", "GET / HTTP/1.1\nHost: example.test\n\n")
        store.forward_pending_interception(entry_id)
        store.wait_for_interception(entry_id)

        store.begin_interception(entry_id, "response", "HTTP/1.1 200 OK\nContent-Length: 0\n\n")
        store.forward_pending_interception(entry_id)
        store.wait_for_interception(entry_id)

        history = store.interception_history()

        self.assertEqual(len(history), 2)
        self.assertEqual([item.phase for item in history], ["request", "response"])
        self.assertTrue(all(not item.active for item in history))

    def test_store_should_intercept_respects_mode(self) -> None:
        store = TrafficStore()
        store.set_intercept_mode("response")

        self.assertFalse(store.should_intercept("request"))
        self.assertTrue(store.should_intercept("response"))

        store.set_intercept_mode("both")
        self.assertTrue(store.should_intercept("request"))
        self.assertTrue(store.should_intercept("response"))

    def test_store_should_intercept_respects_scope_hosts(self) -> None:
        store = TrafficStore()
        store.set_intercept_mode("both")
        store.set_scope_hosts(["example.test"])

        self.assertTrue(store.should_intercept("request", "example.test"))
        self.assertTrue(store.should_intercept("response", "api.example.test"))
        self.assertFalse(store.should_intercept("request", "other.test"))

    def test_store_scope_supports_explicit_wildcard_subdomains(self) -> None:
        store = TrafficStore()
        store.set_intercept_mode("both")
        store.set_scope_hosts(["*.example.test"])

        self.assertFalse(store.should_intercept("request", "example.test"))
        self.assertTrue(store.should_intercept("request", "api.example.test"))
        self.assertTrue(store.should_intercept("response", "deep.api.example.test"))
        self.assertFalse(store.should_intercept("request", "other.test"))

    def test_store_scope_supports_explicit_exclusions(self) -> None:
        store = TrafficStore()
        store.set_intercept_mode("both")
        store.set_scope_hosts(["*.example.test", "!test.example.test"])

        self.assertTrue(store.should_intercept("request", "api.example.test"))
        self.assertTrue(store.should_intercept("response", "deep.api.example.test"))
        self.assertFalse(store.should_intercept("request", "test.example.test"))
        self.assertFalse(store.should_intercept("request", "other.test"))

    def test_store_scope_with_only_exclusions_allows_other_hosts(self) -> None:
        store = TrafficStore()
        store.set_intercept_mode("both")
        store.set_scope_hosts(["!test.example.test"])

        self.assertFalse(store.should_intercept("request", "test.example.test"))
        self.assertTrue(store.should_intercept("request", "api.example.test"))
        self.assertTrue(store.should_intercept("response", "other.test"))

    def test_scope_document_parser_preserves_explicit_wildcard(self) -> None:
        hosts = ProxyTUI._parse_scope_document(
            """
            *.example.test
            https://example.test/login
            """
        )

        self.assertEqual(hosts, ["*.example.test", "example.test"])

    def test_scope_document_parser_preserves_explicit_exclusions(self) -> None:
        hosts = ProxyTUI._parse_scope_document(
            """
            *.example.test
            !test.example.test
            !https://admin.example.test/panel
            """
        )

        self.assertEqual(hosts, ["*.example.test", "!test.example.test", "!admin.example.test"])

    def test_begin_interception_skips_out_of_scope_hosts(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.set_intercept_mode("request")
        store.set_scope_hosts(["example.test"])

        opened = store.begin_interception(entry_id, "request", "GET / HTTP/1.1\nHost: other.test\n\n", host="other.test")

        self.assertFalse(opened)
        self.assertIsNone(store.get_pending_interception(entry_id))

    def test_visible_entries_hide_out_of_scope_hosts(self) -> None:
        store = TrafficStore()
        first_id = store.create_entry("127.0.0.1:50000")
        second_id = store.create_entry("127.0.0.1:50001")
        store.mutate(first_id, self._fill_entry)
        store.mutate(second_id, self._fill_other_entry)
        store.set_scope_hosts(["example.test"])

        visible_entries = store.visible_entries()

        self.assertEqual(len(visible_entries), 1)
        self.assertEqual(visible_entries[0].request.host, "example.test")

    def test_visible_entries_hide_explicitly_excluded_hosts(self) -> None:
        store = TrafficStore()
        first_id = store.create_entry("127.0.0.1:50000")
        second_id = store.create_entry("127.0.0.1:50001")
        store.mutate(first_id, self._fill_api_subdomain_entry)
        store.mutate(second_id, self._fill_https_entry)
        store.set_scope_hosts(["*.example.test", "!secure.example.test"])

        visible_entries = store.visible_entries()

        self.assertEqual(len(visible_entries), 1)
        self.assertEqual(visible_entries[0].request.host, "api.example.test")

    def test_visible_entries_show_all_traffic_when_scope_is_empty(self) -> None:
        store = TrafficStore()
        first_id = store.create_entry("127.0.0.1:50000")
        second_id = store.create_entry("127.0.0.1:50001")
        store.mutate(first_id, self._fill_entry)
        store.mutate(second_id, self._fill_https_entry)

        visible_entries = store.visible_entries()

        self.assertEqual(len(visible_entries), 2)

    def test_visible_entries_can_include_out_of_scope_traffic_when_requested(self) -> None:
        store = TrafficStore()
        first_id = store.create_entry("127.0.0.1:50000")
        second_id = store.create_entry("127.0.0.1:50001")
        store.mutate(first_id, self._fill_entry)
        store.mutate(second_id, self._fill_other_entry)
        store.set_scope_hosts(["example.test"])

        visible_entries = store.visible_entries(scope_only=False)

        self.assertEqual(len(visible_entries), 2)

    def test_visible_entries_can_filter_requests_with_query_parameters(self) -> None:
        store = TrafficStore()
        first_id = store.create_entry("127.0.0.1:50000")
        second_id = store.create_entry("127.0.0.1:50001")
        store.mutate(first_id, self._fill_query_entry)
        store.mutate(second_id, self._fill_other_entry)
        store.set_view_filters(ViewFilterSettings(query_mode="with_query"))

        visible_entries = store.visible_entries()

        self.assertEqual(len(visible_entries), 1)
        self.assertEqual(visible_entries[0].request.host, "query.example.test")

    def test_visible_entries_can_filter_failures(self) -> None:
        store = TrafficStore()
        first_id = store.create_entry("127.0.0.1:50000")
        second_id = store.create_entry("127.0.0.1:50001")
        store.mutate(first_id, self._fill_error_entry)
        store.mutate(second_id, self._fill_entry)
        store.set_view_filters(ViewFilterSettings(failure_mode="failures"))

        visible_entries = store.visible_entries()

        self.assertEqual(len(visible_entries), 1)
        self.assertEqual(visible_entries[0].request.host, "broken.example.test")

    def test_visible_entries_can_hide_failures(self) -> None:
        store = TrafficStore()
        first_id = store.create_entry("127.0.0.1:50000")
        second_id = store.create_entry("127.0.0.1:50001")
        store.mutate(first_id, self._fill_error_entry)
        store.mutate(second_id, self._fill_entry)
        store.set_view_filters(ViewFilterSettings(failure_mode="hide_failures"))

        visible_entries = store.visible_entries()

        self.assertEqual(len(visible_entries), 1)
        self.assertEqual(visible_entries[0].request.host, "example.test")

    def test_visible_entries_can_hide_selected_file_extensions(self) -> None:
        store = TrafficStore()
        first_id = store.create_entry("127.0.0.1:50000")
        second_id = store.create_entry("127.0.0.1:50001")
        store.mutate(first_id, self._fill_asset_entry)
        store.mutate(second_id, self._fill_entry)
        store.set_view_filters(ViewFilterSettings(hidden_extensions=["png"]))

        visible_entries = store.visible_entries()

        self.assertEqual(len(visible_entries), 1)
        self.assertEqual(visible_entries[0].request.host, "example.test")

    def test_visible_entries_can_hide_selected_http_methods(self) -> None:
        store = TrafficStore()
        first_id = store.create_entry("127.0.0.1:50000")
        second_id = store.create_entry("127.0.0.1:50001")
        store.mutate(first_id, self._fill_entry)
        store.mutate(second_id, self._fill_other_entry)
        store.set_view_filters(ViewFilterSettings(hidden_methods=["GET"]))

        visible_entries = store.visible_entries()

        self.assertEqual(len(visible_entries), 1)
        self.assertEqual(visible_entries[0].request.method, "POST")

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
            self.assertNotIn("o edit scope", footer)
            self.assertNotIn("c cert", footer)
            self.assertNotIn("C regen cert", footer)

            store.set_intercept_mode("request")
            store.begin_interception(entry_id, "request", "GET / HTTP/1.1\nHost: example.test\n\n")
            pending = tui._selected_pending_interception(entry_id)
            tui.active_tab = 1
            footer = tui._footer_text(200, pending)

            self.assertIn("e edit", footer)
            self.assertIn("a send", footer)
            self.assertIn("x drop", footer)

    def test_tui_can_resolve_intercepted_items_out_of_arrival_order(self) -> None:
        store = TrafficStore()
        first_id = store.create_entry("127.0.0.1:50000")
        second_id = store.create_entry("127.0.0.1:50001")
        store.set_intercept_mode("request")
        store.begin_interception(first_id, "request", "GET /first HTTP/1.1\nHost: example.test\n\n")
        store.begin_interception(second_id, "request", "GET /second HTTP/1.1\nHost: example.test\n\n")

        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui.active_tab = 1
            pending = store.interception_history()
            tui.intercept_selected_index = 1
            selected_pending = tui._selected_intercept_item(pending)

            tui._forward_intercepted_request(selected_pending)

            result = store.wait_for_interception(second_id)

            self.assertEqual(result.entry_id, second_id)
            self.assertEqual(result.decision, "forward")
            self.assertIsNotNone(store.get_pending_interception(first_id))

    def test_tui_forwarded_intercept_item_remains_in_history(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.set_intercept_mode("request")
        store.begin_interception(entry_id, "request", "GET / HTTP/1.1\nHost: example.test\n\n")

        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui.active_tab = 1
            item = tui._selected_intercept_item(store.interception_history())

            tui._forward_intercepted_request(item)
            store.wait_for_interception(entry_id)

            history = store.interception_history()
            self.assertEqual(len(history), 1)
            self.assertEqual(history[0].decision, "forward")
            self.assertFalse(history[0].active)

    def test_tui_can_reach_history_items_beyond_active_pending_count(self) -> None:
        store = TrafficStore()
        store.set_intercept_mode("request")
        entry_ids = [store.create_entry(f"127.0.0.1:{50000 + index}") for index in range(10)]
        for index, entry_id in enumerate(entry_ids, start=1):
            store.begin_interception(entry_id, "request", f"GET /{index} HTTP/1.1\nHost: example.test\n\n")

        store.forward_pending_interception(entry_ids[4])
        store.wait_for_interception(entry_ids[4])
        store.forward_pending_interception(entry_ids[5])
        store.wait_for_interception(entry_ids[5])

        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui.active_tab = 1
            tui.active_pane = "flows"
            tui.intercept_selected_index = 7

            tui._move_active_pane(1, 0)
            self.assertEqual(tui.intercept_selected_index, 8)

            tui._move_active_pane(1, 0)
            self.assertEqual(tui.intercept_selected_index, 9)

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
            tui.active_tab = 1
            tui._toggle_intercept_mode()
            self.assertEqual(store.intercept_mode(), "request")
            tui._toggle_intercept_mode()
            self.assertEqual(store.intercept_mode(), "response")
            tui._toggle_intercept_mode()
            self.assertEqual(store.intercept_mode(), "both")
            tui._toggle_intercept_mode()
            self.assertEqual(store.intercept_mode(), "off")

    def test_tui_toggle_intercept_mode_is_ignored_outside_intercept_workspace(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            tui.active_tab = 0
            tui._toggle_intercept_mode()

            self.assertEqual(store.intercept_mode(), "off")

    def test_tui_footer_shows_body_toggle_only_on_http_workspace(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            tui.active_tab = 5
            request_body_footer = tui._footer_text(200, None)
            self.assertIn("p raw/pretty", request_body_footer)
            self.assertIn("z wrap:off", request_body_footer)

            tui.active_tab = 0
            overview_footer = tui._footer_text(200, None)
            self.assertNotIn("p raw/pretty", overview_footer)
            self.assertNotIn("i intercept mode", overview_footer)

    def test_tui_footer_shows_scope_toggle_when_scope_is_configured(self) -> None:
        store = TrafficStore()
        store.set_scope_hosts(["example.test"])
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            footer = tui._footer_text(200, None)

            self.assertIn("o scope:in", footer)
            self.assertIn("A add scope", footer)

    def test_tui_scope_toggle_switches_between_in_scope_and_all_traffic(self) -> None:
        store = TrafficStore()
        first_id = store.create_entry("127.0.0.1:50000")
        second_id = store.create_entry("127.0.0.1:50001")
        store.mutate(first_id, self._fill_entry)
        store.mutate(second_id, self._fill_other_entry)
        store.set_scope_hosts(["example.test"])
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            self.assertEqual(len(tui._entries_for_view()), 1)

            tui._toggle_scope_view()

            self.assertEqual(len(tui._entries_for_view()), 2)
            self.assertTrue(store.view_filters().show_out_of_scope)
            self.assertIn("all traffic", tui.status_message)

    def test_tui_can_add_selected_flow_host_to_scope(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.mutate(entry_id, self._fill_entry)
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            entry = store.snapshot()[0]

            tui._add_selected_host_to_scope(entry)

            self.assertEqual(store.scope_hosts(), ["example.test"])
            self.assertIn("Added example.test to scope.", tui.status_message)

    def test_tui_can_add_selected_sitemap_host_to_scope(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.mutate(entry_id, self._fill_https_entry)
        entries = store.snapshot()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui.active_tab = 3
            selected = tui._selected_sitemap_entry(entries)

            tui._add_selected_host_to_scope(selected)

            self.assertEqual(store.scope_hosts(), ["secure.example.test"])

    def test_tui_add_selected_host_to_scope_ignores_duplicates(self) -> None:
        store = TrafficStore()
        store.set_scope_hosts(["example.test"])
        entry_id = store.create_entry("127.0.0.1:50000")
        store.mutate(entry_id, self._fill_entry)
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            entry = store.snapshot()[0]

            tui._add_selected_host_to_scope(entry)

            self.assertEqual(store.scope_hosts(), ["example.test"])
            self.assertIn("already in scope", tui.status_message)

    def test_tui_footer_shows_export_binding_on_request_tabs(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            tui.active_tab = 5
            footer = tui._footer_text(200, None)

            self.assertIn("8 export", footer)

    def test_tui_open_response_workspace_focuses_response_pane(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            tui._open_workspace("open_response")

            self.assertEqual(tui.active_tab, 5)
            self.assertEqual(tui.active_pane, "http_response")

    def test_tui_open_request_workspace_focuses_request_pane(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            tui._open_workspace("open_request")

            self.assertEqual(tui.active_tab, 5)
            self.assertEqual(tui.active_pane, "http_request")

    def test_tui_footer_shows_intercept_mode_only_on_intercept_tab(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            tui.active_tab = 1
            intercept_footer = tui._footer_text(200, None)
            self.assertIn("i intercept mode", intercept_footer)

            tui.active_tab = 4
            match_replace_footer = tui._footer_text(200, None)
            self.assertNotIn("i intercept mode", match_replace_footer)

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
            self.assertIn("prev:[ next:/", footer)
            self.assertNotIn("i intercept mode", footer)
            self.assertNotIn("c cert", footer)
            self.assertNotIn("C regen cert", footer)

    def test_tui_footer_shows_sitemap_controls_on_sitemap_tab(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            tui.active_tab = 3
            footer = tui._footer_text(200, None)

            self.assertIn("y to repeater", footer)
            self.assertIn("PgUp/PgDn page", footer)
            self.assertNotIn("i intercept mode", footer)
            self.assertNotIn("c cert", footer)

    def test_settings_plugins_lines_show_installation_guidance(self) -> None:
        store = TrafficStore()
        manager = PluginManager()
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_dir = Path(tmpdir) / "plugins"
            manager.load_from_dirs([plugin_dir])
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
                plugin_manager=manager,
            )

            lines = tui._plugin_settings_lines()

            self.assertTrue(any("Loaded plugins:" in line for line in lines))
            self.assertTrue(any(str(plugin_dir) in line for line in lines))
            self.assertTrue(any("--plugin-dir" in line for line in lines))
            self.assertTrue(any("examples/add_header_plugin.py" in line for line in lines))

    def test_settings_plugin_docs_lines_include_api_reference(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            lines = tui._plugin_docs_lines()

            self.assertTrue(any("HookContext" in line for line in lines))
            self.assertTrue(any("before_request_forward" in line for line in lines))
            self.assertTrue(any("ParsedRequest" in line for line in lines))

    def test_tui_builds_sitemap_items_from_hosts_and_paths(self) -> None:
        store = TrafficStore()
        first_id = store.create_entry("127.0.0.1:50000")
        second_id = store.create_entry("127.0.0.1:50001")
        store.mutate(first_id, self._fill_entry)
        store.mutate(second_id, self._fill_https_entry)
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            items = tui._build_sitemap_items(store.snapshot())

            labels = [item.label for item in items]
            self.assertIn("example.test", labels)
            self.assertIn("secure.example.test", labels)
            self.assertTrue(any(label.endswith("[POST 201]") for label in labels))

    def test_tui_sitemap_tree_window_can_scroll_back_up(self) -> None:
        store = TrafficStore()
        for index in range(12):
            entry_id = store.create_entry(f"127.0.0.1:{50000 + index}")
            store.mutate(entry_id, lambda entry, i=index: self._fill_sitemap_entry(entry, i))

        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            items = tui._build_sitemap_items(store.snapshot())
            tui.sitemap_selected_index = min(len(items) - 1, 8)
            tui.sitemap_tree_scroll = 0
            tui._sync_sitemap_selection(items)

            tree_lines = [f"{'  ' * item.depth}{item.label}" for item in items]
            rows, _ = tui._prepare_plain_visual_rows(tree_lines, 30, 0)
            selected_row = next(index for index, (source_index, _) in enumerate(rows) if source_index == tui.sitemap_selected_index)
            start = tui._window_start(tui.sitemap_tree_scroll, len(rows), 5)
            if selected_row < start:
                start = selected_row
            elif selected_row >= start + 5:
                start = max(0, selected_row - 5 + 1)
            tui.sitemap_tree_scroll = start

            self.assertGreater(tui.sitemap_tree_scroll, 0)

            tui.sitemap_selected_index = 1
            selected_row = next(index for index, (source_index, _) in enumerate(rows) if source_index == tui.sitemap_selected_index)
            start = tui._window_start(tui.sitemap_tree_scroll, len(rows), 5)
            if selected_row < start:
                start = selected_row
            elif selected_row >= start + 5:
                start = max(0, selected_row - 5 + 1)
            tui.sitemap_tree_scroll = start

            self.assertEqual(tui.sitemap_tree_scroll, 1)

    def test_tui_selected_sitemap_entry_can_be_loaded_into_repeater(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.mutate(entry_id, self._fill_entry)
        entries = store.snapshot()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui.active_tab = 3

            entry = tui._selected_sitemap_entry(entries)
            tui._load_repeater_from_selected_flow(entry)

            self.assertEqual(tui.active_tab, 2)
            self.assertEqual(tui.repeater_source_entry_id, entry_id)

    def test_tui_can_open_export_from_selected_flow(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.mutate(entry_id, self._fill_entry)
        entries = store.snapshot()

        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            selected = entries[0]

            tui._open_workspace("open_export", entries, selected, None)

            self.assertEqual(tui.active_tab, tui._export_tab_index())
            self.assertIsNotNone(tui.export_source)
            self.assertEqual(tui.export_source.entry_id, entry_id)
            lines = tui._export_detail_lines(next(item for item in tui._export_format_items() if item.kind == "python_requests"))
            self.assertTrue(any("import requests" in line for line in lines))
            self.assertTrue(any("http://example.test/api" in line for line in lines))

    def test_tui_http_pair_export_contains_request_and_response_without_extra_noise(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.mutate(entry_id, self._fill_entry)
        entries = store.snapshot()

        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui._open_workspace("open_export", entries, entries[0], None)

            self.assertIsNotNone(tui.export_source)
            preview = tui._render_export_text("http_pair", tui.export_source)

            self.assertIn("POST http://example.test/api HTTP/1.1", preview)
            self.assertIn("HTTP/1.1 201 Created", preview)
            self.assertNotIn("Source:", preview)
            self.assertNotIn("Format:", preview)

    def test_tui_can_open_export_from_intercept_request_history(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.mutate(entry_id, self._fill_https_entry)
        store.set_intercept_mode("request")
        store.begin_interception(entry_id, "request", "POST /login HTTP/1.1\nHost: secure.example.test\n\nuser=demo")
        store.forward_pending_interception(entry_id)
        store.wait_for_interception(entry_id)
        entries = store.snapshot()

        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui.active_tab = 1
            selected_intercept = store.interception_history()[0]

            tui._open_workspace("open_export", entries, None, selected_intercept)

            self.assertEqual(tui.active_tab, tui._export_tab_index())
            self.assertIsNotNone(tui.export_source)
            preview = tui._render_export_text("curl_bash", tui.export_source)
            self.assertIn("https://secure.example.test/login", preview)
            self.assertIn("--request POST", preview)

    def test_tui_export_from_repeater_uses_current_request_text(self) -> None:
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
            tui.repeater_sessions[0].request_text = "GET http://example.test/custom HTTP/1.1\nHost: example.test\n\n"

            tui._open_workspace("open_export", store.snapshot(), entry, None)

            self.assertIsNotNone(tui.export_source)
            preview = tui._render_export_text("python_requests", tui.export_source)
            self.assertIn("'GET'", preview)
            self.assertIn("http://example.test/custom", preview)

    def test_tui_can_copy_selected_export_to_clipboard(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.mutate(entry_id, self._fill_entry)
        entries = store.snapshot()
        copied: list[str] = []

        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
                clipboard_copy=lambda text: copied.append(text) or "test-copy",
            )
            tui._open_workspace("open_export", entries, entries[0], None)
            tui.export_selected_index = next(
                index for index, item in enumerate(tui._export_format_items()) if item.kind == "python_requests"
            )

            tui._copy_selected_export()

            self.assertEqual(len(copied), 1)
            self.assertIn("import requests", copied[0])
            self.assertIn("Copied Python requests via test-copy.", tui.status_message)

    def test_tui_sitemap_response_lines_decode_compressed_body(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.mutate(entry_id, self._fill_gzip_entry)
        entry = store.snapshot()[0]
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            lines = tui._sitemap_response_lines(entry)

            self.assertTrue(any("gzip decoded" in line for line in lines))
            self.assertTrue(any("hello from gzip" in line for line in lines))

    def test_tui_repeater_request_lines_keep_long_untrimmed_content(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            long_value = "A" * 240
            session = RepeaterSession(request_text=f"GET / HTTP/1.1\nX-Long: {long_value}\n\n")

            lines = tui._repeater_request_lines(session)

            self.assertIn(f"X-Long: {long_value}", lines)

    def test_tui_flow_list_line_keeps_long_host_and_path(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.mutate(entry_id, self._fill_entry)
        entry = store.snapshot()[0]
        entry.request.host = "very-long-hostname.example.test.internal"
        entry.request.path = "/deep/path/" + ("segment-" * 12)

        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            line = tui._flow_list_line(entry)

            self.assertIn(entry.request.host, line)
            self.assertIn(entry.request.path, line)

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

    def test_tui_edit_match_replace_opens_rule_builder_workspace(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui.active_tab = 4

            tui._edit_match_replace_rules(None)

            self.assertEqual(tui.active_tab, tui._rule_builder_tab_index())
            self.assertEqual(tui.active_pane, "rule_builder_menu")

    def test_tui_rule_builder_commit_appends_rule(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui._open_rule_builder_workspace()
            tui.rule_builder_draft.scope = "both"
            tui.rule_builder_draft.mode = "literal"
            tui.rule_builder_draft.match = "hello"
            tui.rule_builder_draft.replace = "bye"
            tui.rule_builder_draft.description = "demo"

            tui._commit_rule_builder_draft()

            rules = store.match_replace_rules()
            self.assertEqual(len(rules), 1)
            self.assertEqual(rules[0].scope, "both")
            self.assertEqual(rules[0].match, "hello")
            self.assertEqual(tui.active_tab, 4)

    def test_tui_can_open_selected_match_replace_rule_for_editing(self) -> None:
        store = TrafficStore()
        store.set_match_replace_rules(
            [
                MatchReplaceRule(
                    enabled=True,
                    scope="response",
                    mode="regex",
                    match="Example Domain",
                    replace="Demo",
                    description="rewrite banner",
                )
            ]
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui.active_tab = 4
            tui.match_replace_selected_index = 0

            tui._edit_selected_match_replace_rule()

            self.assertEqual(tui.active_tab, tui._rule_builder_tab_index())
            self.assertEqual(tui.rule_builder_edit_index, 0)
            self.assertEqual(tui.rule_builder_draft.scope, "response")
            self.assertEqual(tui.rule_builder_draft.mode, "regex")
            self.assertEqual(tui.rule_builder_draft.match, "Example Domain")
            self.assertEqual(tui.rule_builder_draft.replace, "Demo")
            self.assertEqual(tui.rule_builder_draft.description, "rewrite banner")

    def test_tui_rule_builder_commit_updates_existing_rule(self) -> None:
        store = TrafficStore()
        store.set_match_replace_rules(
            [
                MatchReplaceRule(enabled=True, scope="request", mode="literal", match="one", replace="1", description="first"),
                MatchReplaceRule(enabled=True, scope="response", mode="literal", match="two", replace="2", description="second"),
            ]
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui.active_tab = 4
            tui.match_replace_selected_index = 1
            tui._edit_selected_match_replace_rule()
            tui.rule_builder_draft.match = "updated"
            tui.rule_builder_draft.replace = "22"
            tui.rule_builder_draft.description = "updated rule"

            tui._commit_rule_builder_draft()

            rules = store.match_replace_rules()
            self.assertEqual(len(rules), 2)
            self.assertEqual(rules[0].description, "first")
            self.assertEqual(rules[1].match, "updated")
            self.assertEqual(rules[1].replace, "22")
            self.assertEqual(rules[1].description, "updated rule")
            self.assertEqual(tui.match_replace_selected_index, 1)
            self.assertEqual(tui.active_tab, 4)

    def test_tui_editing_existing_rule_field_persists_immediately(self) -> None:
        store = TrafficStore()
        store.set_match_replace_rules(
            [
                MatchReplaceRule(enabled=True, scope="response", mode="literal", match="one", replace="1", description="first"),
            ]
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui.active_tab = 4
            tui.match_replace_selected_index = 0
            tui._edit_selected_match_replace_rule()

            with mock.patch.object(tui, "_open_text_editor", return_value="line1\nline2"):
                tui._edit_rule_builder_text_field(None, "replace", tui.rule_builder_draft.replace)

            rules = store.match_replace_rules()
            self.assertEqual(rules[0].replace, "line1\nline2")

    def test_tui_match_replace_lines_escape_multiline_fields(self) -> None:
        store = TrafficStore()
        store.set_match_replace_rules(
            [
                MatchReplaceRule(
                    enabled=True,
                    scope="response",
                    mode="literal",
                    match="hello\nworld",
                    replace="bye\nworld",
                    description="first\nrule",
                ),
            ]
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            lines = tui._build_match_replace_lines()

            self.assertTrue(any("first\\nrule" in line for line in lines))
            self.assertTrue(any("hello\\nworld" in line for line in lines))
            self.assertTrue(any("bye\\nworld" in line for line in lines))

    def test_tui_rule_builder_shows_error_for_invalid_rule(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui._open_rule_builder_workspace()
            tui.rule_builder_draft.mode = "regex"
            tui.rule_builder_draft.match = "["

            tui._commit_rule_builder_draft()

            self.assertEqual(store.match_replace_rules(), [])
            self.assertIn("invalid regex", tui.rule_builder_error_message)
            self.assertEqual(tui.active_tab, tui._rule_builder_tab_index())

    def test_tui_can_delete_selected_match_replace_rule(self) -> None:
        store = TrafficStore()
        store.set_match_replace_rules(
            [
                MatchReplaceRule(enabled=True, scope="request", mode="literal", match="one", replace="1", description="first"),
                MatchReplaceRule(enabled=True, scope="response", mode="literal", match="two", replace="2", description="second"),
            ]
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui.active_tab = 4
            tui.active_pane = "detail"
            tui.match_replace_selected_index = 1

            tui._delete_selected_match_replace_rule()

            rules = store.match_replace_rules()
            self.assertEqual(len(rules), 1)
            self.assertEqual(rules[0].description, "first")

    def test_tui_move_active_pane_moves_match_replace_selection(self) -> None:
        store = TrafficStore()
        store.set_match_replace_rules(
            [
                MatchReplaceRule(enabled=True, scope="request", mode="literal", match="one", replace="1", description="first"),
                MatchReplaceRule(enabled=True, scope="response", mode="literal", match="two", replace="2", description="second"),
            ]
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui.active_tab = 4
            tui.active_pane = "detail"

            tui._move_active_pane(1, 0)

            self.assertEqual(tui.match_replace_selected_index, 1)

    def test_tui_scope_document_parser_ignores_comments_and_duplicates(self) -> None:
        hosts = ProxyTUI._parse_scope_document(
            """
            # allowed hosts
            example.test
            api.example.test
            https://example.test/login
            example.test
            !https://test.example.test/debug
            !test.example.test
            """
        )

        self.assertEqual(hosts, ["example.test", "api.example.test", "!test.example.test"])

    def test_tui_filters_document_parser_accepts_lists_and_scalars(self) -> None:
        filters = ProxyTUI._parse_filters_document(
            """
            show_out_of_scope: true
            query_mode: with_query
            failure_mode: failures
            body_mode: with_body
            methods: GET, POST
            hidden_methods: DELETE, PATCH
            hidden_extensions:
              - jpg
              - png, js
            """
        )

        self.assertTrue(filters.show_out_of_scope)
        self.assertEqual(filters.query_mode, "with_query")
        self.assertEqual(filters.failure_mode, "failures")
        self.assertEqual(filters.body_mode, "with_body")
        self.assertEqual(filters.methods, ["GET", "POST"])
        self.assertEqual(filters.hidden_methods, ["DELETE", "PATCH"])
        self.assertEqual(filters.hidden_extensions, ["jpg", "png", "js"])

    def test_tui_keybindings_document_parser_accepts_custom_bindings(self) -> None:
        bindings = ProxyTUI._parse_keybindings_document(
            """
            {
              "bindings": {
                "open_overview": "1",
                "open_intercept": "2",
                "open_repeater": "3",
                "open_sitemap": "4",
                "open_match_replace": "5",
                "open_request": "6",
                "open_response": "7",
                "open_settings": "ws",
                "open_keybindings": "wk",
                "save_project": "v",
                "load_repeater": "u",
                "edit_match_replace": "m",
                "toggle_body_view": "b",
                "toggle_word_wrap": "q",
                "toggle_scope_view": "o",
                "toggle_intercept_mode": "t",
                "forward_send": "f",
                "drop_item": "d",
                "edit_item": "e",
                "repeater_send_alt": "n",
                "repeater_prev_session": ",",
                "repeater_next_session": "."
              }
            }
            """
        )

        self.assertEqual(bindings["open_settings"], "ws")
        self.assertEqual(bindings["open_keybindings"], "wk")
        self.assertEqual(bindings["forward_send"], "f")
        self.assertEqual(bindings["repeater_next_session"], ".")
        self.assertEqual(bindings["toggle_word_wrap"], "q")
        self.assertEqual(bindings["toggle_scope_view"], "o")

    def test_tui_keybindings_document_parser_migrates_legacy_request_response_actions(self) -> None:
        bindings = ProxyTUI._parse_keybindings_document(
            """
            {
              "bindings": {
                "open_request_body": "6",
                "open_response_headers": "7"
              }
            }
            """
        )

        self.assertEqual(bindings["open_request"], "6")
        self.assertEqual(bindings["open_response"], "7")

    def test_tui_keybindings_document_parser_rejects_ambiguous_bindings(self) -> None:
        with self.assertRaisesRegex(ValueError, "ambiguous keybinding"):
            ProxyTUI._parse_keybindings_document(
                """
                {
                  "bindings": {
                    "open_settings": "w",
                    "open_keybindings": "wk"
                  }
                }
                """
            )

    def test_tui_footer_uses_custom_keybindings(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
                initial_keybindings={"forward_send": "z"},
            )
            tui.active_tab = 2

            footer = tui._footer_text(200, None)

            self.assertIn("z send", footer)

    def test_tui_footer_uses_custom_word_wrap_binding(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
                initial_keybindings={"toggle_word_wrap": "wr"},
            )

            footer = tui._footer_text(200, None)

            self.assertIn("wr wrap:off", footer)

    def test_tui_settings_keybindings_item_opens_keybindings_workspace(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui.active_tab = tui._settings_tab_index()
            items = tui._settings_items()
            tui.settings_selected_index = next(index for index, item in enumerate(items) if item.kind == "keybindings")

            tui._activate_settings_item(None)

            self.assertEqual(tui.active_tab, tui._keybindings_tab_index())
            self.assertEqual(tui.active_pane, "keybindings_menu")

    def test_tui_settings_include_themes_item(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            items = tui._settings_items()

            self.assertTrue(any(item.kind == "themes" for item in items))
            self.assertTrue(any(item.kind == "theme_builder" for item in items))

    def test_tui_settings_include_filters_item(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            items = tui._settings_items()

            self.assertTrue(any(item.kind == "filters" for item in items))

    def test_tui_settings_items_are_grouped_into_sections(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            items = tui._settings_items()
            rows = tui._settings_menu_rows(items)

            self.assertEqual(items[0].section, "Appearance")
            self.assertTrue(any(row[2] == "[Appearance]" for row in rows))
            self.assertTrue(any(row[2] == "[Extensions]" for row in rows))
            self.assertTrue(any(row[2] == "[TLS]" for row in rows))
            self.assertTrue(any(row[2] == "[Traffic]" for row in rows))
            self.assertTrue(any(row[2] == "[Controls]" for row in rows))

    def test_tui_theme_detail_lines_document_hex_support(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            lines = tui._theme_detail_lines()

            self.assertTrue(any("#RRGGBB" in line or "#RGB" in line for line in lines))
            self.assertTrue(any("Theme JSON structure:" in line for line in lines))

    def test_tui_settings_filters_item_opens_filters_workspace(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui.active_tab = tui._settings_tab_index()
            items = tui._settings_items()
            tui.settings_selected_index = next(index for index, item in enumerate(items) if item.kind == "filters")

            tui._activate_settings_item(None)

            self.assertEqual(tui.active_tab, tui._filters_tab_index())
            self.assertEqual(tui.active_pane, "filters_menu")

    def test_tui_settings_scope_item_opens_scope_workspace(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui.active_tab = tui._settings_tab_index()
            items = tui._settings_items()
            tui.settings_selected_index = next(index for index, item in enumerate(items) if item.kind == "scope")

            tui._activate_settings_item(None)

            self.assertEqual(tui.active_tab, tui._scope_tab_index())
            self.assertEqual(tui.active_pane, "scope_menu")

    def test_tui_can_add_in_scope_pattern_in_scope_workspace(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui._open_scope_workspace()
            tui._prompt_inline_text = lambda stdscr, prompt, initial="": "*.example.test"

            tui._activate_scope_item(None)

            self.assertEqual(store.scope_hosts(), ["*.example.test"])

    def test_tui_can_add_out_of_scope_pattern_in_scope_workspace(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui._open_scope_workspace()
            items = tui._scope_items()
            tui.scope_selected_index = next(index for index, item in enumerate(items) if item.kind == "add_exclude")
            tui._prompt_inline_text = lambda stdscr, prompt, initial="": "test.example.test"

            tui._activate_scope_item(None)

            self.assertEqual(store.scope_hosts(), ["!test.example.test"])

    def test_tui_can_delete_scope_pattern_in_scope_workspace(self) -> None:
        store = TrafficStore()
        store.set_scope_hosts(["*.example.test", "!test.example.test"])
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui._open_scope_workspace()
            items = tui._scope_items()
            tui.scope_selected_index = next(
                index for index, item in enumerate(items) if item.kind == "exclude_pattern" and item.value == "test.example.test"
            )

            tui._clear_selected_scope_item()

            self.assertEqual(store.scope_hosts(), ["*.example.test"])

    def test_tui_can_toggle_scope_visibility_in_filters_workspace(self) -> None:
        store = TrafficStore()
        store.set_scope_hosts(["example.test"])
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui._open_filters_workspace()

            tui._activate_filter_item(None)

            self.assertTrue(store.view_filters().show_out_of_scope)
            self.assertIn("all traffic", tui.status_message)

    def test_tui_can_edit_hidden_extensions_in_filters_workspace(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui._open_filters_workspace()
            items = tui._filter_items()
            tui.filters_selected_index = next(
                index for index, item in enumerate(items) if item.kind == "edit_hidden_extensions"
            )
            tui._prompt_inline_text = lambda stdscr, prompt, initial="": "jpg, png, js"

            tui._activate_filter_item(None)

            self.assertEqual(store.view_filters().hidden_extensions, ["jpg", "png", "js"])

    def test_tui_can_toggle_hidden_http_methods_in_filters_workspace(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui._open_filters_workspace()
            items = tui._filter_items()
            tui.filters_selected_index = next(
                index for index, item in enumerate(items) if item.kind == "exclude_method:GET"
            )

            tui._activate_filter_item(None)

            self.assertEqual(store.view_filters().hidden_methods, ["GET"])

    def test_tui_can_apply_selected_theme_from_settings(self) -> None:
        store = TrafficStore()
        saved: list[str] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ThemeManager([Path(tmpdir) / "themes"])
            manager.load()
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
                theme_manager=manager,
                theme_saver=lambda name: saved.append(name),
            )
            tui.active_tab = tui._settings_tab_index()
            items = tui._settings_items()
            tui.settings_selected_index = next(index for index, item in enumerate(items) if item.kind == "themes")
            tui.active_pane = "settings_detail"
            tui.theme_selected_index = next(index for index, theme in enumerate(manager.available_themes()) if theme.name == "ocean")

            tui._activate_settings_item(None)

            self.assertEqual(tui.theme_name(), "ocean")
            self.assertEqual(saved[-1], "ocean")

    def test_tui_moving_theme_selection_applies_theme_automatically(self) -> None:
        store = TrafficStore()
        saved: list[str] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ThemeManager([Path(tmpdir) / "themes"])
            manager.load()
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
                theme_manager=manager,
                theme_saver=lambda name: saved.append(name),
            )
            items = tui._settings_items()
            tui.active_tab = tui._settings_tab_index()
            tui.active_pane = "settings_detail"
            tui.settings_selected_index = next(
                index for index, item in enumerate(items) if item.kind == "themes"
            )
            tui.theme_selected_index = next(
                index
                for index, theme in enumerate(manager.available_themes())
                if theme.name == "default"
            )

            tui._move_theme_selection(1)

            selected_theme = manager.available_themes()[tui.theme_selected_index]
            self.assertEqual(tui.theme_name(), selected_theme.name)
            self.assertEqual(saved[-1], selected_theme.name)

    def test_tui_theme_builder_preview_restores_previous_theme_on_cancel(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = ThemeManager([Path(tmpdir) / "themes"])
            manager.load()
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
                theme_manager=manager,
            )
            original = tui.theme_name()

            tui._open_theme_builder_workspace()
            tui._set_theme_builder_color("chrome", "fg", "red")

            self.assertEqual(tui._current_theme().colors["chrome"][0], "red")

            tui._close_theme_builder_workspace(
                "Theme builder cancelled.",
                restore_preview=True,
            )

            self.assertEqual(tui.theme_name(), original)
            self.assertEqual(tui._current_theme().name, original)

    def test_tui_theme_builder_can_save_new_theme(self) -> None:
        store = TrafficStore()
        saved: list[str] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            theme_dir = Path(tmpdir) / "themes"
            manager = ThemeManager([theme_dir])
            manager.load()
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
                theme_manager=manager,
                theme_saver=lambda name: saved.append(name),
            )

            tui._open_theme_builder_workspace()
            tui.theme_builder_draft.name = "sunrise"
            tui.theme_builder_draft.description = "Warm preview theme"
            tui._set_theme_builder_color("accent", "fg", "red")
            tui._commit_theme_builder_draft()

            self.assertEqual(tui.theme_name(), "sunrise")
            self.assertEqual(saved[-1], "sunrise")
            self.assertTrue((theme_dir / "sunrise.json").exists())
            self.assertIsNotNone(manager.get("sunrise"))

    def test_tui_theme_builder_returns_to_settings_menu_after_save(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            theme_dir = Path(tmpdir) / "themes"
            manager = ThemeManager([theme_dir])
            manager.load()
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
                theme_manager=manager,
            )

            items = tui._settings_items()
            tui.active_tab = tui._settings_tab_index()
            tui.active_pane = "settings_menu"
            tui.settings_selected_index = next(
                index for index, item in enumerate(items) if item.kind == "theme_builder"
            )
            tui._open_theme_builder_workspace()
            tui.theme_builder_draft.name = "sunrise"
            tui._commit_theme_builder_draft()

            self.assertEqual(tui.active_tab, tui._settings_tab_index())
            self.assertEqual(tui.active_pane, "settings_menu")

    def test_tui_keybinding_items_are_grouped_into_sections(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            items = tui._keybinding_items()
            rows = tui._keybinding_menu_rows(items)

            self.assertEqual(items[0].section, "Workspaces")
            self.assertTrue(any(row[2] == "[Workspaces]" for row in rows))
            self.assertTrue(any(row[2] == "[Flow Actions]" for row in rows))
            self.assertTrue(any(row[2] == "[Editing And Send]" for row in rows))
            self.assertTrue(any(row[2] == "[Repeater Sessions]" for row in rows))

    def test_tui_keybinding_detail_lines_include_section(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )

            item = next(item for item in tui._keybinding_items() if item.action == "forward_send")
            lines = tui._keybinding_detail_lines(item)

            self.assertIn("Section: Editing And Send", lines)

    def test_tui_duplicate_keybinding_is_rejected(self) -> None:
        store = TrafficStore()
        saved: list[dict[str, str]] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
                keybinding_saver=lambda bindings: saved.append(dict(bindings)),
            )
            tui.active_tab = tui._keybindings_tab_index()
            items = tui._keybinding_items()
            tui.keybindings_selected_index = next(index for index, item in enumerate(items) if item.action == "drop_item")

            tui._activate_keybinding_item()
            handled = tui._handle_keybinding_capture(ord("a"))
            self.assertTrue(handled)
            handled = tui._handle_keybinding_capture(curses.KEY_ENTER)

            self.assertTrue(handled)
            self.assertEqual(tui._binding_key("drop_item"), "x")
            self.assertIn("already assigned", tui.keybinding_error_message)
            self.assertEqual(saved, [])

    def test_tui_valid_keybinding_change_is_persisted(self) -> None:
        store = TrafficStore()
        saved: list[dict[str, str]] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
                keybinding_saver=lambda bindings: saved.append(dict(bindings)),
            )
            tui.active_tab = tui._keybindings_tab_index()
            items = tui._keybinding_items()
            tui.keybindings_selected_index = next(index for index, item in enumerate(items) if item.action == "drop_item")

            tui._activate_keybinding_item()
            handled = tui._handle_keybinding_capture(ord("d"))
            self.assertTrue(handled)
            handled = tui._handle_keybinding_capture(curses.KEY_ENTER)

            self.assertTrue(handled)
            self.assertEqual(tui._binding_key("drop_item"), "d")
            self.assertEqual(saved[-1]["drop_item"], "d")
            self.assertEqual(tui.keybinding_error_message, "")

    def test_tui_valid_two_key_binding_change_is_persisted(self) -> None:
        store = TrafficStore()
        saved: list[dict[str, str]] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
                keybinding_saver=lambda bindings: saved.append(dict(bindings)),
            )
            tui.active_tab = tui._keybindings_tab_index()
            items = tui._keybinding_items()
            tui.keybindings_selected_index = next(
                index for index, item in enumerate(items) if item.action == "open_settings"
            )

            tui._activate_keybinding_item()
            self.assertTrue(tui._handle_keybinding_capture(ord("w")))
            self.assertTrue(tui._handle_keybinding_capture(ord("s")))
            handled = tui._handle_keybinding_capture(curses.KEY_ENTER)

            self.assertTrue(handled)
            self.assertEqual(tui._binding_key("open_settings"), "ws")
            self.assertEqual(saved[-1]["open_settings"], "ws")

    def test_tui_consumes_two_key_workspace_binding(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
                initial_keybindings={"open_settings": "ws"},
            )

            self.assertIsNone(tui._consume_bound_action(ord("w")))
            self.assertEqual(tui._pending_action_sequence, "w")
            self.assertEqual(tui._consume_bound_action(ord("s")), "open_settings")
            self.assertEqual(tui._pending_action_sequence, "")

    def test_tui_consumes_two_key_binding_even_when_prefix_is_navigation_key(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
                initial_keybindings={"open_settings": "jw"},
            )

            self.assertIsNone(tui._consume_bound_action(ord("j")))
            self.assertEqual(tui._pending_action_sequence, "j")
            self.assertEqual(tui._consume_bound_action(ord("w")), "open_settings")
            self.assertEqual(tui._pending_action_sequence, "")

    def test_tui_footer_shows_settings_binding(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
                initial_keybindings={"open_settings": "z"},
            )

            footer = tui._footer_text(200, None)

            self.assertIn("z settings", footer)

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

    def test_tui_repeater_can_send_multiple_times_in_same_session(self) -> None:
        store = TrafficStore()
        responses = ["HTTP/1.1 200 OK\n\nfirst", "HTTP/1.1 200 OK\n\nsecond"]
        calls: list[str] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
                repeater_sender=lambda raw: (calls.append(raw), responses[len(calls) - 1])[1],
            )
            tui.repeater_sessions.append(
                RepeaterSession(request_text="GET http://example.test/ HTTP/1.1\nHost: example.test\n\n")
            )
            tui.active_tab = 2

            tui._send_repeater_request()
            tui._send_repeater_request()

            session = tui.repeater_sessions[0]
            self.assertEqual(len(calls), 2)
            self.assertEqual(len(session.exchanges), 2)
            self.assertEqual(session.response_text, "HTTP/1.1 200 OK\n\nsecond")
            self.assertEqual(session.selected_exchange_index, 2)

    def test_tui_repeater_history_exposes_old_request_response_pairs(self) -> None:
        store = TrafficStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            session = RepeaterSession(
                request_text="GET http://example.test/current HTTP/1.1\nHost: example.test\n\n",
                exchanges=[
                    RepeaterExchange(
                        request_text="GET http://example.test/old HTTP/1.1\nHost: example.test\n\n",
                        response_text="HTTP/1.1 200 OK\n\nold-response",
                    )
                ],
                selected_exchange_index=1,
            )
            tui = ProxyTUI(
                store=store,
                listen_host="127.0.0.1",
                listen_port=8080,
                certificate_authority=CertificateAuthority(tmpdir),
            )
            tui.repeater_sessions.append(session)
            tui.active_tab = 2

            self.assertIn("old HTTP/1.1", tui.repeater_request_text)
            self.assertIn("old-response", tui.repeater_response_text)
            self.assertEqual(tui._repeater_history_items(session), ["Draft", "Send #1"])

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

            self.assertEqual(tui.active_pane, "repeater_history")

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

    @staticmethod
    def _fill_other_entry(entry) -> None:
        entry.request = RequestData(
            method="GET",
            target="http://other.test/home",
            version="HTTP/1.1",
            headers=[("Host", "other.test")],
            body=b"",
            host="other.test",
            port=80,
            path="/home",
        )
        entry.response = ResponseData(
            version="HTTP/1.1",
            status_code=200,
            reason="OK",
            headers=[("Content-Type", "text/plain")],
            body=b"ok",
        )
        entry.upstream_addr = "other.test:80"
        entry.state = "complete"

    @staticmethod
    def _fill_api_subdomain_entry(entry) -> None:
        entry.request = RequestData(
            method="GET",
            target="http://api.example.test/home",
            version="HTTP/1.1",
            headers=[("Host", "api.example.test")],
            body=b"",
            host="api.example.test",
            port=80,
            path="/home",
        )
        entry.response = ResponseData(
            version="HTTP/1.1",
            status_code=200,
            reason="OK",
            headers=[("Content-Type", "text/plain")],
            body=b"ok",
        )
        entry.upstream_addr = "api.example.test:80"
        entry.state = "complete"

    @staticmethod
    def _fill_query_entry(entry) -> None:
        entry.request = RequestData(
            method="GET",
            target="http://query.example.test/search?q=demo",
            version="HTTP/1.1",
            headers=[("Host", "query.example.test")],
            body=b"",
            host="query.example.test",
            port=80,
            path="/search?q=demo",
        )
        entry.response = ResponseData(
            version="HTTP/1.1",
            status_code=200,
            reason="OK",
            headers=[("Content-Type", "text/html")],
            body=b"ok",
        )
        entry.upstream_addr = "query.example.test:80"
        entry.state = "complete"

    @staticmethod
    def _fill_error_entry(entry) -> None:
        entry.request = RequestData(
            method="GET",
            target="http://broken.example.test/fail",
            version="HTTP/1.1",
            headers=[("Host", "broken.example.test")],
            body=b"",
            host="broken.example.test",
            port=80,
            path="/fail",
        )
        entry.response = ResponseData(
            version="HTTP/1.1",
            status_code=502,
            reason="Bad Gateway",
            headers=[("Content-Type", "text/plain")],
            body=b"upstream failed",
        )
        entry.upstream_addr = "broken.example.test:80"
        entry.error = "upstream connection failed"
        entry.state = "error"

    @staticmethod
    def _fill_asset_entry(entry) -> None:
        entry.request = RequestData(
            method="GET",
            target="http://assets.example.test/logo.png",
            version="HTTP/1.1",
            headers=[("Host", "assets.example.test")],
            body=b"",
            host="assets.example.test",
            port=80,
            path="/logo.png",
        )
        entry.response = ResponseData(
            version="HTTP/1.1",
            status_code=200,
            reason="OK",
            headers=[("Content-Type", "image/png")],
            body=b"\x89PNG",
        )
        entry.upstream_addr = "assets.example.test:80"
        entry.state = "complete"

    @staticmethod
    def _fill_gzip_entry(entry) -> None:
        entry.request = RequestData(
            method="GET",
            target="http://example.test/gzip",
            version="HTTP/1.1",
            headers=[("Host", "example.test")],
            body=b"",
            host="example.test",
            port=80,
            path="/gzip",
        )
        entry.response = ResponseData(
            version="HTTP/1.1",
            status_code=200,
            reason="OK",
            headers=[("Content-Type", "text/plain; charset=utf-8"), ("Content-Encoding", "gzip")],
            body=gzip.compress(b"hello from gzip"),
        )
        entry.upstream_addr = "example.test:80"
        entry.state = "complete"

    @staticmethod
    def _fill_sitemap_entry(entry, index: int) -> None:
        path = f"/section-{index}/item-{index}"
        entry.request = RequestData(
            method="GET",
            target=f"http://example.test{path}",
            version="HTTP/1.1",
            headers=[("Host", "example.test")],
            body=b"",
            host="example.test",
            port=80,
            path=path,
        )
        entry.response = ResponseData(
            version="HTTP/1.1",
            status_code=200,
            reason="OK",
            headers=[("Content-Type", "text/plain")],
            body=b"ok",
        )
        entry.upstream_addr = "example.test:80"
        entry.state = "complete"
