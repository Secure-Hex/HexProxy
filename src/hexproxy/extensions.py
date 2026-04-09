from __future__ import annotations

from dataclasses import dataclass, field
import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Protocol, TYPE_CHECKING

if TYPE_CHECKING:
    from .proxy import ParsedRequest, ParsedResponse
    from .store import TrafficStore


@dataclass(slots=True)
class HookContext:
    entry_id: int
    client_addr: str
    store: "TrafficStore"
    tags: dict[str, str] = field(default_factory=dict)


class HexProxyPlugin(Protocol):
    name: str

    def on_loaded(self) -> None: ...

    def before_request_forward(self, context: HookContext, request: "ParsedRequest") -> "ParsedRequest": ...

    def on_response_received(
        self,
        context: HookContext,
        request: "ParsedRequest",
        response: "ParsedResponse",
    ) -> None: ...

    def on_error(self, context: HookContext, error: Exception) -> None: ...


@dataclass(slots=True)
class LoadedPlugin:
    name: str
    path: Path
    instance: object


class PluginManager:
    def __init__(self) -> None:
        self._plugins: list[LoadedPlugin] = []
        self._load_errors: list[str] = []

    def load_from_dirs(self, directories: list[Path]) -> None:
        for directory in directories:
            if not directory.exists() or not directory.is_dir():
                continue
            for path in sorted(directory.glob("*.py")):
                if path.name.startswith("_"):
                    continue
                self._load_plugin(path)

    def loaded_plugins(self) -> list[LoadedPlugin]:
        return list(self._plugins)

    def load_errors(self) -> list[str]:
        return list(self._load_errors)

    def before_request_forward(self, context: HookContext, request: "ParsedRequest") -> "ParsedRequest":
        current = request
        for plugin in self._plugins:
            hook = getattr(plugin.instance, "before_request_forward", None)
            if hook is None:
                continue
            candidate = hook(context, current)
            if candidate is not None:
                current = candidate
        return current

    def on_response_received(
        self,
        context: HookContext,
        request: "ParsedRequest",
        response: "ParsedResponse",
    ) -> None:
        for plugin in self._plugins:
            hook = getattr(plugin.instance, "on_response_received", None)
            if hook is None:
                continue
            hook(context, request, response)

    def on_error(self, context: HookContext, error: Exception) -> None:
        for plugin in self._plugins:
            hook = getattr(plugin.instance, "on_error", None)
            if hook is None:
                continue
            hook(context, error)

    def _load_plugin(self, path: Path) -> None:
        try:
            module = self._load_module(path)
            plugin = self._instantiate_plugin(module)
            name = str(getattr(plugin, "name", path.stem))
            on_loaded = getattr(plugin, "on_loaded", None)
            if on_loaded is not None:
                on_loaded()
            self._plugins.append(LoadedPlugin(name=name, path=path, instance=plugin))
        except Exception as exc:
            self._load_errors.append(f"{path}: {exc}")

    @staticmethod
    def _load_module(path: Path) -> ModuleType:
        spec = importlib.util.spec_from_file_location(f"hexproxy_plugin_{path.stem}", path)
        if spec is None or spec.loader is None:
            raise RuntimeError("unable to create import spec")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    @staticmethod
    def _instantiate_plugin(module: ModuleType) -> object:
        register = getattr(module, "register", None)
        if callable(register):
            return register()
        plugin = getattr(module, "PLUGIN", None)
        if plugin is not None:
            return plugin
        raise RuntimeError("plugin module must export register() or PLUGIN")
