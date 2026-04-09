from __future__ import annotations

from pathlib import Path
import tempfile
import textwrap
import unittest

from hexproxy.extensions import HookContext, PluginManager
from hexproxy.proxy import ParsedRequest
from hexproxy.store import TrafficStore


class PluginManagerTests(unittest.TestCase):
    def test_loads_plugin_and_modifies_request(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_path = Path(tmpdir) / "sample_plugin.py"
            plugin_path.write_text(
                textwrap.dedent(
                    """
                    from hexproxy.proxy import ParsedRequest

                    class SamplePlugin:
                        name = "sample"

                        def before_request_forward(self, context, request: ParsedRequest) -> ParsedRequest:
                            request.headers.append(("X-Test-Plugin", "sample"))
                            return request

                    def register():
                        return SamplePlugin()
                    """
                ),
                encoding="utf-8",
            )

            manager = PluginManager()
            manager.load_from_dirs([Path(tmpdir)])

            request = ParsedRequest(
                method="GET",
                target="http://example.test/",
                version="HTTP/1.1",
                headers=[("Host", "example.test")],
                body=b"",
            )
            context = HookContext(entry_id=1, client_addr="127.0.0.1:50000", store=TrafficStore())

            updated = manager.before_request_forward(context, request)

            self.assertEqual(len(manager.loaded_plugins()), 1)
            self.assertIn(("X-Test-Plugin", "sample"), updated.headers)

    def test_records_load_error_for_invalid_plugin(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_path = Path(tmpdir) / "broken_plugin.py"
            plugin_path.write_text("x = 1\n", encoding="utf-8")

            manager = PluginManager()
            manager.load_from_dirs([Path(tmpdir)])

            self.assertEqual(manager.loaded_plugins(), [])
            self.assertEqual(len(manager.load_errors()), 1)
