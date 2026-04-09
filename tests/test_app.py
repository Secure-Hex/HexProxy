from __future__ import annotations

import asyncio
from pathlib import Path
import tempfile
import unittest

from hexproxy.app import ProxyRuntime
from hexproxy.preferences import ApplicationPreferences


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


class ApplicationPreferencesTests(unittest.TestCase):
    def test_preferences_round_trip_keybindings(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.json"
            preferences = ApplicationPreferences(path)
            preferences.set_keybindings({"forward_send": "z", "open_settings": "w"})
            preferences.save()

            restored = ApplicationPreferences(path)
            restored.load()

            self.assertEqual(restored.keybindings()["forward_send"], "z")
            self.assertEqual(restored.keybindings()["open_settings"], "w")
