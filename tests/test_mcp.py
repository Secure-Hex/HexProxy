from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from hexproxy.extensions import PluginManager
from hexproxy.mcp import HexProxyMCPServer
from hexproxy.models import RequestData, ResponseData
from hexproxy.preferences import ApplicationPreferences
from hexproxy.store import TrafficStore
from hexproxy.themes import ThemeManager


class HexProxyMCPServerTests(unittest.TestCase):
    def _build_server(self, tmpdir: str) -> tuple[HexProxyMCPServer, TrafficStore, ApplicationPreferences]:
        store = TrafficStore()
        store.set_project_path(Path(tmpdir) / "project.hexproxy.json")
        preferences = ApplicationPreferences(Path(tmpdir) / "config.json")
        manager = PluginManager()
        themes = ThemeManager([Path(tmpdir) / "themes"])
        themes.load()
        manager.bind_runtime(store=store, preferences=preferences, theme_manager=themes)
        return (
            HexProxyMCPServer(
                store=store,
                plugin_manager=manager,
                preferences=preferences,
                theme_manager=themes,
            ),
            store,
            preferences,
        )

    @staticmethod
    def _tool_response_text(server: HexProxyMCPServer, name: str, arguments: dict[str, object]) -> str:
        result = server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": name,
                    "arguments": arguments,
                },
            }
        )
        assert result is not None
        return str(result["result"]["content"][0]["text"])

    def test_initialize_advertises_tools_and_resources(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            server, _, _ = self._build_server(tmpdir)

            result = server.handle_message(
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
            )

            self.assertIsNotNone(result)
            assert result is not None
            self.assertEqual(result["result"]["serverInfo"]["name"], "hexproxy-mcp")
            self.assertIn("tools", result["result"]["capabilities"])
            self.assertIn("resources", result["result"]["capabilities"])

    def test_get_flow_returns_decoded_request_and_response_details(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            server, store, _ = self._build_server(tmpdir)
            entry_id = store.create_entry("127.0.0.1:50000")
            store.mutate(
                entry_id,
                lambda entry: (
                    setattr(
                        entry,
                        "request",
                        RequestData(
                            method="POST",
                            target="https://example.com/api",
                            version="HTTP/1.1",
                            headers=[("Host", "example.com"), ("Content-Type", "application/json")],
                            body=b'{"hello":"world"}',
                            host="example.com",
                            port=443,
                            path="/api",
                        ),
                    ),
                    setattr(
                        entry,
                        "response",
                        ResponseData(
                            version="HTTP/1.1",
                            status_code=200,
                            reason="OK",
                            headers=[("Content-Type", "application/json")],
                            body=b'{"ok":true}',
                        ),
                    ),
                ),
            )

            payload = json.loads(
                self._tool_response_text(
                    server,
                    "get_flow",
                    {"entry_id": entry_id, "pretty": True},
                )
            )

            self.assertEqual(payload["summary"]["host"], "example.com")
            self.assertEqual(payload["request"]["body"]["kind"], "json")
            self.assertIn('"hello": "world"', payload["request"]["body"]["text"])
            self.assertIn('"ok": true', payload["response"]["body"]["text"])

    def test_set_scope_and_filters_update_store(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            server, store, _ = self._build_server(tmpdir)

            scope_payload = json.loads(
                self._tool_response_text(
                    server,
                    "set_scope",
                    {"patterns": ["*.example.com", "!test.example.com"]},
                )
            )
            filter_payload = json.loads(
                self._tool_response_text(
                    server,
                    "set_view_filters",
                    {"failure_mode": "hide_failures", "hidden_extensions": ["png", "jpg"]},
                )
            )

            self.assertEqual(scope_payload["scope_hosts"], ["*.example.com", "!test.example.com"])
            self.assertEqual(store.scope_hosts(), ["*.example.com", "!test.example.com"])
            self.assertEqual(filter_payload["failure_mode"], "hide_failures")
            self.assertEqual(store.view_filters().hidden_extensions, ["png", "jpg"])

    def test_match_replace_rules_can_be_created_and_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            server, store, _ = self._build_server(tmpdir)

            created = json.loads(
                self._tool_response_text(
                    server,
                    "upsert_match_replace_rule",
                    {
                        "enabled": True,
                        "scope": "response",
                        "mode": "literal",
                        "match": "Example Domain",
                        "replace": "Changed",
                        "description": "replace title",
                    },
                )
            )
            deleted = json.loads(
                self._tool_response_text(
                    server,
                    "delete_match_replace_rule",
                    {"index": 0},
                )
            )

            self.assertEqual(created["index"], 0)
            self.assertEqual(created["rule"]["scope"], "response")
            self.assertEqual(deleted["deleted"]["match"], "Example Domain")
            self.assertEqual(store.match_replace_rules(), [])

    def test_repeater_session_can_send_multiple_requests(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            server, _, _ = self._build_server(tmpdir)
            sent: list[str] = []
            server._send_repeater_text = lambda raw_request: (  # type: ignore[method-assign]
                sent.append(raw_request) or "HTTP/1.1 200 OK\nContent-Type: text/plain\n\npong"
            )
            request_text = (
                "GET https://example.com/ HTTP/1.1\n"
                "Host: example.com\n"
                "User-Agent: hexproxy-test\n\n"
            )

            created = json.loads(
                self._tool_response_text(
                    server,
                    "create_repeater_session",
                    {"request_text": request_text},
                )
            )
            first = json.loads(
                self._tool_response_text(
                    server,
                    "send_repeater_request",
                    {"session_id": created["session_id"]},
                )
            )
            second = json.loads(
                self._tool_response_text(
                    server,
                    "send_repeater_request",
                    {"session_id": created["session_id"]},
                )
            )

            self.assertEqual(len(sent), 2)
            self.assertEqual(len(first["history"]), 1)
            self.assertEqual(len(second["history"]), 2)
            self.assertIn("200 OK", second["response_text"])

    def test_interception_can_be_updated_and_resolved(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            server, store, _ = self._build_server(tmpdir)
            store.set_intercept_mode("request")
            store.set_scope_hosts(["*"])
            entry_id = store.create_entry("127.0.0.1:50000")
            created = store.begin_interception(
                entry_id,
                "request",
                "GET https://example.com/ HTTP/1.1\nHost: example.com\n\n",
                host="example.com",
            )
            self.assertTrue(created)
            record = store.interception_history()[0]

            updated = json.loads(
                self._tool_response_text(
                    server,
                    "update_interception",
                    {
                        "record_id": record.record_id,
                        "raw_text": "GET https://example.com/changed HTTP/1.1\nHost: example.com\n\n",
                    },
                )
            )
            resolved = json.loads(
                self._tool_response_text(
                    server,
                    "resolve_interception",
                    {"record_id": record.record_id, "decision": "forward"},
                )
            )

            self.assertTrue(updated["active"])
            self.assertEqual(resolved["decision"], "forward")
            self.assertEqual(store.interception_history()[0].decision, "forward")

    def test_keybindings_and_theme_can_be_changed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            server, _, preferences = self._build_server(tmpdir)

            keys = json.loads(
                self._tool_response_text(
                    server,
                    "set_keybinding",
                    {"action": "open_settings", "key": "jw"},
                )
            )
            theme = json.loads(
                self._tool_response_text(
                    server,
                    "set_theme",
                    {"theme": "default"},
                )
            )

            self.assertEqual(keys["keybindings"]["open_settings"], "jw")
            self.assertEqual(preferences.theme_name(), "default")
            self.assertEqual(theme["theme"], "default")


if __name__ == "__main__":
    unittest.main()
