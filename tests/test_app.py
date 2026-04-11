from __future__ import annotations

import asyncio
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from argparse import Namespace

from hexproxy.app import ProxyRuntime, build_parser, main
from hexproxy.certs import default_certificate_dir
from hexproxy.preferences import ApplicationPreferences, default_config_dir


class _FakeProxy:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.stopped = False

    async def start(self) -> None:
        self.started.set()

    async def stop(self) -> None:
        self.stopped = True


class ProxyRuntimeTests(unittest.TestCase):
    def test_runtime_stop_shuts_down_background_thread(self) -> None:
        proxy = _FakeProxy()
        runtime = ProxyRuntime(proxy)

        runtime.start()
        runtime.stop()

        self.assertTrue(proxy.stopped)
        self.assertFalse(runtime._thread.is_alive())

    def test_main_ignores_keyboard_interrupt_during_shutdown(self) -> None:
        parser = mock.Mock()
        parser.parse_args.return_value = Namespace(
            listen_host="127.0.0.1",
            listen_port=8080,
            project=None,
            plugin_dir=[],
            cert_dir=Path(".hexproxy/certs"),
            config_file=None,
        )
        mock_runtime = mock.Mock()
        mock_tui = mock.Mock()
        mock_tui.run.side_effect = KeyboardInterrupt()
        mock_tui.custom_keybindings.return_value = {}
        mock_tui.theme_name.return_value = "default"
        mock_runtime.stop.side_effect = KeyboardInterrupt()
        mock_proxy = mock.Mock()
        mock_proxy.listen_host = "127.0.0.1"
        mock_proxy.listen_port = 8080
        mock_proxy.startup_notice = ""

        with (
            mock.patch("hexproxy.app.build_parser", return_value=parser),
            mock.patch("hexproxy.app.TrafficStore"),
            mock.patch("hexproxy.app.ApplicationPreferences") as preferences_cls,
            mock.patch("hexproxy.app.PluginManager"),
            mock.patch("hexproxy.app.CertificateAuthority"),
            mock.patch("hexproxy.app.HttpProxyServer", return_value=mock_proxy),
            mock.patch("hexproxy.app.ProxyRuntime", return_value=mock_runtime),
            mock.patch("hexproxy.app.ProxyTUI", return_value=mock_tui),
        ):
            preferences = preferences_cls.return_value
            preferences.keybindings.return_value = {}
            preferences.theme_name.return_value = "default"
            result = main([])

        self.assertEqual(result, 0)

    def test_main_reports_missing_windows_curses_dependency(self) -> None:
        parser = mock.Mock()
        parser.parse_args.return_value = Namespace()

        with (
            mock.patch("hexproxy.app.build_parser", return_value=parser),
            mock.patch("hexproxy.app.ProxyTUI", None),
            mock.patch("hexproxy.app.sys.platform", "win32"),
            mock.patch("sys.stderr", new_callable=mock.MagicMock()) as stderr,
        ):
            result = main([])

        self.assertEqual(result, 1)
        written = "".join(call.args[0] for call in stderr.write.call_args_list if call.args)
        self.assertIn("windows-curses", written)


class ApplicationPreferencesTests(unittest.TestCase):
    def test_parser_uses_stable_default_certificate_directory(self) -> None:
        parser = build_parser()

        args = parser.parse_args([])

        self.assertEqual(args.cert_dir, default_certificate_dir())

    def test_preferences_round_trip_keybindings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.json"
            preferences = ApplicationPreferences(path)
            preferences.set_keybindings({"forward_send": "zz", "open_settings": "w"})
            preferences.set_theme_name("ocean")
            preferences.set_plugin_value("demo", "enabled", True)
            preferences.save()

            restored = ApplicationPreferences(path)
            restored.load()

            self.assertEqual(restored.keybindings()["forward_send"], "zz")
            self.assertEqual(restored.keybindings()["open_settings"], "w")
            self.assertEqual(restored.theme_name(), "ocean")
            self.assertTrue(restored.plugin_state("demo")["enabled"])

    def test_default_config_dir_uses_appdata_on_windows(self) -> None:
        with mock.patch("hexproxy.preferences.os.name", "nt"), mock.patch.dict(
            "hexproxy.preferences.os.environ",
            {"APPDATA": r"C:\Users\demo\AppData\Roaming"},
            clear=True,
        ):
            path = default_config_dir()

        self.assertEqual(str(path), r"C:\Users\demo\AppData\Roaming\hexproxy")
