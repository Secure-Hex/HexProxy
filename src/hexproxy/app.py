from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
import threading

from .extensions import PluginManager
from .proxy import HttpProxyServer
from .store import TrafficStore
from .tui import ProxyTUI


class ProxyRuntime:
    def __init__(self, proxy: HttpProxyServer) -> None:
        self.proxy = proxy
        self._thread = threading.Thread(target=self._run, name="hexproxy-runtime", daemon=True)
        self._ready = threading.Event()
        self._stopped = threading.Event()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._shutdown_event: asyncio.Event | None = None
        self._error: Exception | None = None

    def start(self) -> None:
        self._thread.start()
        self._ready.wait()
        if self._error is not None:
            raise RuntimeError("failed to start proxy runtime") from self._error

    def stop(self) -> None:
        if self._loop is not None and self._shutdown_event is not None:
            self._loop.call_soon_threadsafe(self._shutdown_event.set)
        self._stopped.wait(timeout=5)
        self._thread.join(timeout=5)

    def _run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._shutdown_event = asyncio.Event()
        try:
            self._loop.run_until_complete(self._runner())
        except Exception as exc:
            self._error = exc
            self._ready.set()
        finally:
            self._loop.close()
            self._stopped.set()

    async def _runner(self) -> None:
        try:
            await self.proxy.start()
        finally:
            self._ready.set()
        assert self._shutdown_event is not None
        await self._shutdown_event.wait()
        await self.proxy.stop()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="HTTP interception proxy with a terminal UI.")
    parser.add_argument("--listen-host", default="127.0.0.1", help="Host interface to bind the proxy to.")
    parser.add_argument("--listen-port", default=8080, type=int, help="Port to bind the proxy to.")
    parser.add_argument(
        "--project",
        type=Path,
        help="Project file used to load and autosave captured traffic.",
    )
    parser.add_argument(
        "--plugin-dir",
        type=Path,
        action="append",
        default=[],
        help="Directory that contains HexProxy extension plugins.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    store = TrafficStore()
    plugin_manager = PluginManager()
    plugin_dirs = [Path("plugins"), *args.plugin_dir]
    plugin_manager.load_from_dirs(plugin_dirs)
    if args.project is not None:
        if args.project.exists():
            store.load(args.project)
        else:
            store.set_project_path(args.project)
            store.save()
    proxy = HttpProxyServer(
        store=store,
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        plugins=plugin_manager,
    )
    runtime = ProxyRuntime(proxy)
    runtime.start()

    tui = ProxyTUI(
        store=store,
        listen_host=proxy.listen_host,
        listen_port=proxy.listen_port,
        plugin_manager=plugin_manager,
    )
    try:
        tui.run()
    finally:
        runtime.stop()
        if args.project is not None:
            store.save()
    return 0
