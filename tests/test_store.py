from __future__ import annotations

import curses
import gzip
import json
from pathlib import Path
import tempfile
import unittest

from hexproxy.certs import CertificateAuthority
from hexproxy.extensions import PluginManager
from hexproxy.models import MatchReplaceRule, RequestData, ResponseData
from hexproxy.store import TrafficStore
from hexproxy.themes import ThemeManager
from hexproxy.tui import ProxyTUI, RepeaterSession


class TrafficStorePersistenceTests(unittest.TestCase):
    def test_save_and_load_project_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            project_path = Path(tmpdir) / "session.hexproxy.json"

            store = TrafficStore(project_path=project_path)
            entry_id = store.create_entry("127.0.0.1:50000")
            store.set_scope_hosts(["example.test"])
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
            self.assertEqual(restored.scope_hosts(), ["example.test"])
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

    def test_visible_entries_show_all_traffic_when_scope_is_empty(self) -> None:
        store = TrafficStore()
        first_id = store.create_entry("127.0.0.1:50000")
        second_id = store.create_entry("127.0.0.1:50001")
        store.mutate(first_id, self._fill_entry)
        store.mutate(second_id, self._fill_https_entry)

        visible_entries = store.visible_entries()

        self.assertEqual(len(visible_entries), 2)

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

    def test_tui_footer_shows_body_toggle_only_on_body_tabs(self) -> None:
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

            tui.active_tab = 6
            response_body_footer = tui._footer_text(200, None)
            self.assertIn("p raw/pretty", response_body_footer)
            self.assertIn("z wrap:off", response_body_footer)

            tui.active_tab = 0
            overview_footer = tui._footer_text(200, None)
            self.assertNotIn("p raw/pretty", overview_footer)
            self.assertNotIn("i intercept mode", overview_footer)

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
            """
        )

        self.assertEqual(hosts, ["example.test", "api.example.test"])

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
                "toggle_word_wrap": "o",
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
        self.assertEqual(bindings["toggle_word_wrap"], "o")

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
