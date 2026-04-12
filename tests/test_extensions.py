from __future__ import annotations

from pathlib import Path
import tempfile
import textwrap
import unittest

from hexproxy.extensions import HookContext, PluginManager, ensure_config_plugin_dir
from hexproxy.proxy import ParsedRequest, ParsedResponse
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

    def test_tracks_configured_plugin_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = PluginManager()
            plugin_dir = Path(tmpdir)

            manager.load_from_dirs([plugin_dir])

            self.assertEqual(manager.plugin_dirs(), [plugin_dir])

    def test_ensures_config_plugin_dir_is_created_and_bundles_sample(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "config.json"

            plugin_dir = ensure_config_plugin_dir(config_file)

            self.assertEqual(plugin_dir, config_file.parent / "plugins")
            self.assertTrue(plugin_dir.exists())
            self.assertTrue((plugin_dir / "jwt_inspector.py").exists())

    def test_register_api_can_contribute_workspaces_panels_exporters_and_settings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_path = Path(tmpdir) / "v2_plugin.py"
            plugin_path.write_text(
                textwrap.dedent(
                    """
                    class DemoPlugin:
                        plugin_id = "demo"
                        name = "demo-plugin"

                    def register(api):
                        api.add_workspace("demo_workspace", "Demo Workspace", "plugin workspace", shortcut="dw")
                        api.add_panel(
                            "demo_workspace",
                            "demo_panel",
                            "Demo Panel",
                            render_lines=lambda context: ["hello", context.plugin_id],
                        )
                        api.add_panel(
                            "http_response",
                            "http_info",
                            "HTTP Info",
                            render_lines=lambda context: {"host": context.entry.summary_host if context.entry else "-"},
                        )
                        api.add_exporter(
                            "demo_export",
                            "Demo Export",
                            "plugin exporter",
                            render=lambda context: "exported",
                            style_kind="python",
                        )
                        api.add_keybinding(
                            "demo_action",
                            "dx",
                            "Run the demo action",
                            handler=lambda context: True,
                            section="Plugin Actions",
                        )
                        api.add_analyzer(
                            "demo_analyzer",
                            "Demo Analyzer",
                            analyze=lambda context: ["finding"],
                        )
                        api.add_metadata(
                            "demo_metadata",
                            "Demo Metadata",
                            collect=lambda context: {"plugin": context.plugin_id},
                        )
                        api.add_setting_field(
                            "demo_toggle",
                            "Demo",
                            "Enable Demo",
                            "Enable the demo plugin behavior.",
                            kind="toggle",
                            default=True,
                        )
                        return DemoPlugin()
                    """
                ),
                encoding="utf-8",
            )

            manager = PluginManager()
            manager.load_from_dirs([Path(tmpdir)])

            self.assertEqual(len(manager.loaded_plugins()), 1)
            self.assertEqual(manager.loaded_plugins()[0].plugin_id, "demo")
            self.assertEqual(
                [item.workspace_id for item in manager.workspace_contributions()],
                ["demo_workspace"],
            )
            self.assertEqual(
                [item.panel_id for item in manager.panel_contributions("demo_workspace")],
                ["demo_panel"],
            )
            self.assertEqual(
                [item.panel_id for item in manager.panel_contributions("http_response")],
                ["http_info"],
            )
            self.assertEqual(
                [item.exporter_id for item in manager.exporter_contributions()],
                ["demo_export"],
            )
            self.assertEqual(
                [item.action for item in manager.keybinding_contributions()],
                ["demo_action"],
            )
            self.assertEqual(
                [item.analyzer_id for item in manager.analyzer_contributions()],
                ["demo_analyzer"],
            )
            self.assertEqual(
                [item.metadata_id for item in manager.metadata_contributions()],
                ["demo_metadata"],
            )
            self.assertEqual(
                [item.field_id for item in manager.setting_field_contributions()],
                ["demo_toggle"],
            )

    def test_persist_hook_context_writes_metadata_and_findings_to_store(self) -> None:
        store = TrafficStore()
        manager = PluginManager()
        manager.bind_runtime(store=store)
        entry_id = store.create_entry("127.0.0.1:50000")
        context = HookContext(
            entry_id=entry_id,
            client_addr="127.0.0.1:50000",
            store=store,
            plugin_manager=manager,
        )
        context.set_metadata("demo", "severity", "high")
        context.add_finding("demo", "suspicious header")

        manager.persist_hook_context(context)
        entry = store.get(entry_id)

        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual(entry.plugin_metadata["demo"]["severity"], "high")
        self.assertEqual(entry.plugin_findings["demo"], ["suspicious header"])

    def test_hook_context_exposes_global_and_project_state_helpers(self) -> None:
        store = TrafficStore()
        manager = PluginManager()
        with tempfile.TemporaryDirectory() as tmpdir:
            from hexproxy.preferences import ApplicationPreferences

            preferences = ApplicationPreferences(Path(tmpdir) / "config.json")
            manager.bind_runtime(store=store, preferences=preferences)
            context = HookContext(
                entry_id=1,
                client_addr="127.0.0.1:50000",
                store=store,
                plugin_manager=manager,
            )

            context.set_global_value("demo", "enabled", True)
            context.set_project_value("demo", "mode", "strict")

            self.assertTrue(context.global_state("demo")["enabled"])
            self.assertEqual(context.project_state("demo")["mode"], "strict")
