from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from hexproxy.models import MatchReplaceRule, RequestData, ResponseData
from hexproxy.store import TrafficStore
from hexproxy.tui import ProxyTUI


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
        store.set_intercept_enabled(True)

        opened = store.begin_interception(entry_id, "GET / HTTP/1.1\nHost: example.test\n\n")

        self.assertTrue(opened)
        pending = store.get_pending_interception(entry_id)
        self.assertIsNotNone(pending)
        self.assertEqual(pending.entry_id, entry_id)

        store.update_pending_interception(entry_id, "GET /v2 HTTP/1.1\nHost: example.test\n\n")
        store.forward_pending_interception(entry_id)
        result = store.wait_for_interception(entry_id)

        self.assertEqual(result.decision, "forward")
        self.assertIn("/v2", result.raw_request)
        self.assertIsNone(store.get_pending_interception(entry_id))

    def test_interception_drop_marks_entry(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        store.set_intercept_enabled(True)
        store.begin_interception(entry_id, "GET / HTTP/1.1\nHost: example.test\n\n")

        store.drop_pending_interception(entry_id)
        result = store.wait_for_interception(entry_id)
        entry = store.get(entry_id)

        self.assertEqual(result.decision, "drop")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.state, "dropped")
        self.assertEqual(entry.error, "request dropped by interceptor")

    def test_tui_footer_only_shows_intercept_actions_for_paused_flow(self) -> None:
        store = TrafficStore()
        entry_id = store.create_entry("127.0.0.1:50000")
        tui = ProxyTUI(store=store, listen_host="127.0.0.1", listen_port=8080)

        footer = tui._footer_text(200, None)
        self.assertNotIn("e edit", footer)
        self.assertNotIn("a send", footer)
        self.assertNotIn("x drop", footer)

        store.set_intercept_enabled(True)
        store.begin_interception(entry_id, "GET / HTTP/1.1\nHost: example.test\n\n")
        pending = tui._selected_pending_interception(entry_id)
        footer = tui._footer_text(200, pending)

        self.assertIn("e edit", footer)
        self.assertIn("a send", footer)
        self.assertIn("x drop", footer)

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
