from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path
import sys
import threading

from .certs import CertificateAuthority, default_certificate_dir
from .extensions import PluginManager, ensure_config_plugin_dir
from .preferences import ApplicationPreferences
from .proxy import HttpProxyServer
from .store import TrafficStore
from .themes import ThemeManager
from .update_checker import run_update_check

try:
    from .tui import ProxyTUI
    _TUI_IMPORT_ERROR: Exception | None = None
except ModuleNotFoundError as exc:
    if exc.name not in {"curses", "_curses"}:
        raise
    ProxyTUI = None  # type: ignore[assignment]
    _TUI_IMPORT_ERROR = exc


class ProxyRuntime:
    def __init__(self, proxy: HttpProxyServer) -> None:
        self.proxy = proxy
        self._thread = threading.Thread(target=self._run, name="hexproxy-runtime", daemon=True)
        self._ready = threading.Event()
        self._stopped = threading.Event()
        self._shutdown_requested = threading.Event()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._error: Exception | None = None

    def start(self) -> None:
        self._thread.start()
        self._ready.wait()
        if self._error is not None:
            raise RuntimeError("failed to start proxy runtime") from self._error

    def stop(self) -> None:
        self._shutdown_requested.set()
        self._thread.join(timeout=5)

    def run_coroutine(self, coro):
        if self._loop is None:
            raise RuntimeError("proxy runtime loop is not available")
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result()

    def _run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._runner())
        except Exception as exc:
            self._error = exc
            self._ready.set()
        finally:
            pending = [task for task in asyncio.all_tasks(self._loop) if not task.done()]
            for task in pending:
                task.cancel()
            if pending:
                self._loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            self._loop.run_until_complete(self._loop.shutdown_asyncgens())
            self._loop.run_until_complete(self._loop.shutdown_default_executor(timeout=1))
            self._loop.close()
            self._stopped.set()

    async def _runner(self) -> None:
        try:
            await self.proxy.start()
        finally:
            self._ready.set()
        while not self._shutdown_requested.is_set():
            await asyncio.sleep(0.1)
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
    parser.add_argument(
        "--cert-dir",
        type=Path,
        default=default_certificate_dir(),
        help="Directory used to store the generated local CA and leaf certificates.",
    )
    parser.add_argument(
        "--config-file",
        type=Path,
        help="Global configuration file used for persistent application preferences.",
    )
    parser.add_argument(
        "--cve-auto-update-days",
        type=int,
        default=0,
        help="Automatically refresh the CVE cache if the stored copy is at least this many days old.",
    )
    return parser


def _auto_update_interval(args: argparse.Namespace) -> int:
    value = getattr(args, "cve_auto_update_days", 0) or 0
    if value > 0:
        return value
    env_value = os.environ.get("HEXPROXY_CVE_AUTO_UPDATE_DAYS")
    if env_value:
        try:
            parsed = int(env_value)
        except ValueError:
            parsed = 0
        return parsed if parsed > 0 else 0
    return 0


def _maybe_auto_update_cve_db(interval_days: int) -> None:
    if interval_days <= 0:
        return
    try:
        from .security.cve_store import get_cache_path, should_auto_update
        from .security.cve_sync import synchronize_cve_database
    except Exception:  # pragma: no cover - sanity guard
        return
    cache_path = get_cache_path()
    if not should_auto_update(interval_days, cache_path=cache_path):
        return
    try:
        entries, path = synchronize_cve_database(output_path=cache_path, force=True)
        print(f"hexproxy: refreshed CVE cache ({entries} entries) at {path}", file=sys.stderr)
    except Exception as exc:
        print(f"hexproxy: failed to refresh CVE cache: {exc}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _maybe_auto_update_cve_db(_auto_update_interval(args))
    if run_update_check():
        return 0
    if ProxyTUI is None:
        if sys.platform.startswith("win"):
            print(
                "hexproxy: terminal UI is unavailable. Install the Windows TUI dependency with "
                "`pip install windows-curses` and try again.",
                file=sys.stderr,
            )
        else:
            print(f"hexproxy: failed to import curses support: {_TUI_IMPORT_ERROR}", file=sys.stderr)
        return 1
    store = TrafficStore()
    preferences = ApplicationPreferences(args.config_file)
    try:
        preferences.load()
    except Exception as exc:
        print(f"hexproxy: failed to load config: {exc}", file=sys.stderr)
    plugin_manager = PluginManager()
    default_plugin_dir = ensure_config_plugin_dir(preferences.path)
    plugin_dirs = [default_plugin_dir, *args.plugin_dir]
    plugin_manager.load_from_dirs(plugin_dirs)
    theme_manager = ThemeManager()
    theme_manager.load()
    certificate_authority = CertificateAuthority(args.cert_dir)
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
        certificate_authority=certificate_authority,
    )
    plugin_manager.bind_runtime(
        store=store,
        preferences=preferences,
        theme_manager=theme_manager,
    )
    runtime = ProxyRuntime(proxy)
    try:
        runtime.start()
    except Exception as exc:
        print(f"hexproxy: {exc}", file=sys.stderr)
        return 1

    tui = ProxyTUI(
        store=store,
        listen_host=proxy.listen_host,
        listen_port=proxy.listen_port,
        certificate_authority=certificate_authority,
        plugin_manager=plugin_manager,
        theme_manager=theme_manager,
        repeater_sender=lambda raw_request: runtime.run_coroutine(proxy.replay_request(raw_request)),
        initial_keybindings=preferences.keybindings(),
        keybinding_saver=lambda bindings: (preferences.set_keybindings(bindings), preferences.save()),
        initial_theme_name=preferences.theme_name(),
        theme_saver=lambda theme_name: (preferences.set_theme_name(theme_name), preferences.save()),
    )
    if proxy.startup_notice:
        tui._set_status(proxy.startup_notice)
    try:
        tui.run()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            runtime.stop()
        except KeyboardInterrupt:
            pass
        try:
            preferences.set_keybindings(tui.custom_keybindings())
            preferences.set_theme_name(tui.theme_name())
            preferences.save()
            if args.project is not None:
                store.save()
        except KeyboardInterrupt:
            pass
    return 0
