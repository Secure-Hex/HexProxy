from __future__ import annotations

import asyncio
import unittest

from hexproxy.app import ProxyRuntime


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
