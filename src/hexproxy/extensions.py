from __future__ import annotations

from dataclasses import dataclass, field
import importlib.util
import inspect
import shutil
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Protocol, TYPE_CHECKING

from .preferences import default_config_dir

if TYPE_CHECKING:
    from .preferences import ApplicationPreferences
    from .proxy import ParsedRequest, ParsedResponse
    from .store import PendingInterceptionView, TrafficStore
    from .models import TrafficEntry
    from .themes import ThemeManager


BUILTIN_WORKSPACE_IDS = (
    "overview",
    "intercept",
    "repeater",
    "sitemap",
    "match_replace",
    "http",
    "export",
    "settings",
    "scope",
    "filters",
    "keybindings",
    "rule_builder",
    "theme_builder",
    "findings",
)
SETTING_FIELD_KINDS = ("toggle", "choice", "text", "action")


def _bundled_plugins_source() -> Path | None:
    candidates = [
        Path(__file__).resolve().parent / "plugins",
        Path(__file__).resolve().parents[2] / "plugins",
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return None


def ensure_config_plugin_dir(config_file: Path | None = None) -> Path:
    """
    Ensure the persistent configuration plugin directory exists with bundled samples.
    """
    config_file_path = (
        Path(config_file)
        if config_file is not None
        else default_config_dir() / "config.json"
    )
    target_dir = config_file_path.parent / "plugins"
    target_dir.mkdir(parents=True, exist_ok=True)
    _install_bundled_plugins(target_dir)
    return target_dir


def _install_bundled_plugins(target_dir: Path) -> None:
    source_dir = _bundled_plugins_source()
    if source_dir is None:
        return
    for candidate in source_dir.glob("*.py"):
        if candidate.name.startswith("_"):
            continue
        destination = target_dir / candidate.name
        if destination.exists():
            continue
        shutil.copy2(candidate, destination)


@dataclass(slots=True)
class HookContext:
    entry_id: int
    client_addr: str
    store: "TrafficStore"
    plugin_manager: "PluginManager | None" = None
    tags: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, dict[str, str]] = field(default_factory=dict)
    findings: dict[str, list[str]] = field(default_factory=dict)

    def set_metadata(self, plugin_id: str, key: str, value: object) -> None:
        plugin_name = str(plugin_id).strip()
        field_name = str(key).strip()
        if not plugin_name or not field_name:
            return
        bucket = dict(self.metadata.get(plugin_name, {}))
        bucket[field_name] = str(value)
        self.metadata[plugin_name] = bucket

    def add_finding(self, plugin_id: str, text: object) -> None:
        plugin_name = str(plugin_id).strip()
        message = str(text).strip()
        if not plugin_name or not message:
            return
        notes = list(self.findings.get(plugin_name, []))
        notes.append(message)
        self.findings[plugin_name] = notes

    def global_state(self, plugin_id: str) -> dict[str, object]:
        if self.plugin_manager is None:
            return {}
        return self.plugin_manager.global_state(plugin_id)

    def set_global_value(self, plugin_id: str, key: str, value: object) -> None:
        if self.plugin_manager is None:
            return
        self.plugin_manager.set_global_value(plugin_id, key, value)

    def project_state(self, plugin_id: str) -> dict[str, object]:
        if self.plugin_manager is None:
            return {}
        return self.plugin_manager.project_state(plugin_id)

    def set_project_value(self, plugin_id: str, key: str, value: object) -> None:
        if self.plugin_manager is None:
            return
        self.plugin_manager.set_project_value(plugin_id, key, value)


@dataclass(slots=True)
class PluginRenderContext:
    plugin_id: str
    plugin_manager: "PluginManager"
    store: "TrafficStore"
    entry: "TrafficEntry | None" = None
    request: "ParsedRequest | None" = None
    response: "ParsedResponse | None" = None
    intercept: "PendingInterceptionView | None" = None
    export_source: object | None = None
    tui: object | None = None
    workspace_id: str = ""
    panel_id: str = ""

    def set_status(self, message: str) -> None:
        if self.tui is None:
            return
        setter = getattr(self.tui, "_set_status", None)
        if callable(setter):
            setter(message)

    def open_workspace(self, workspace_id: str) -> None:
        if self.tui is None:
            return
        opener = getattr(self.tui, "open_workspace_by_id", None)
        if callable(opener):
            opener(workspace_id)

    def global_state(self, plugin_id: str | None = None) -> dict[str, object]:
        return self.plugin_manager.global_state(plugin_id or self.plugin_id)

    def set_global_value(self, key: str, value: object, plugin_id: str | None = None) -> None:
        self.plugin_manager.set_global_value(plugin_id or self.plugin_id, key, value)

    def project_state(self, plugin_id: str | None = None) -> dict[str, object]:
        return self.plugin_manager.project_state(plugin_id or self.plugin_id)

    def set_project_value(self, key: str, value: object, plugin_id: str | None = None) -> None:
        self.plugin_manager.set_project_value(plugin_id or self.plugin_id, key, value)

    def theme_manager(self) -> "ThemeManager | None":
        return self.plugin_manager.theme_manager()


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
    plugin_id: str
    name: str
    path: Path
    instance: object


@dataclass(slots=True)
class PluginWorkspaceContribution:
    plugin_id: str
    workspace_id: str
    label: str
    description: str = ""
    order: int = 100
    shortcut: str = ""


@dataclass(slots=True)
class PluginPanelContribution:
    plugin_id: str
    workspace_id: str
    panel_id: str
    title: str
    description: str = ""
    order: int = 100
    render_lines: Callable[[PluginRenderContext], str | list[str] | None] | None = None


@dataclass(slots=True)
class PluginExporterContribution:
    plugin_id: str
    exporter_id: str
    label: str
    description: str
    render: Callable[[PluginRenderContext], str]
    order: int = 100
    style_kind: str | None = None


@dataclass(slots=True)
class PluginKeybindingContribution:
    plugin_id: str
    action: str
    key: str
    description: str
    handler: Callable[[PluginRenderContext], bool | None]
    section: str = "Plugin Actions"


@dataclass(slots=True)
class PluginAnalyzerContribution:
    plugin_id: str
    analyzer_id: str
    label: str
    description: str = ""
    order: int = 100
    analyze: Callable[[PluginRenderContext], str | list[str] | None] | None = None


@dataclass(slots=True)
class PluginMetadataContribution:
    plugin_id: str
    metadata_id: str
    label: str
    description: str = ""
    order: int = 100
    collect: Callable[[PluginRenderContext], dict[str, object] | list[tuple[str, object]] | None] | None = None


@dataclass(slots=True)
class PluginSettingFieldContribution:
    plugin_id: str
    field_id: str
    section: str
    label: str
    description: str
    kind: str
    scope: str = "global"
    default: object = None
    options: list[str] = field(default_factory=list)
    placeholder: str = ""
    action_label: str = "Run"
    on_change: Callable[[PluginRenderContext, object], object | None] | None = None


class PluginAPI:
    def __init__(self, manager: "PluginManager", plugin_id: str) -> None:
        self._manager = manager
        self._plugin_id = plugin_id

    @property
    def plugin_id(self) -> str:
        return self._plugin_id

    def set_plugin_id(self, plugin_id: str) -> None:
        normalized = str(plugin_id).strip()
        if not normalized:
            raise ValueError("plugin id must not be empty")
        if normalized == self._plugin_id:
            return
        self._manager._reassign_plugin_id(self._plugin_id, normalized)
        self._plugin_id = normalized

    def add_workspace(
        self,
        workspace_id: str,
        label: str,
        description: str = "",
        *,
        order: int = 100,
        shortcut: str = "",
    ) -> None:
        self._manager.register_workspace(
            PluginWorkspaceContribution(
                plugin_id=self._plugin_id,
                workspace_id=str(workspace_id).strip(),
                label=str(label).strip(),
                description=str(description),
                order=int(order),
                shortcut=str(shortcut),
            )
        )

    def add_panel(
        self,
        workspace_id: str,
        panel_id: str,
        title: str,
        *,
        description: str = "",
        order: int = 100,
        render_lines: Callable[[PluginRenderContext], str | list[str] | None] | None = None,
    ) -> None:
        self._manager.register_panel(
            PluginPanelContribution(
                plugin_id=self._plugin_id,
                workspace_id=str(workspace_id).strip(),
                panel_id=str(panel_id).strip(),
                title=str(title).strip(),
                description=str(description),
                order=int(order),
                render_lines=render_lines,
            )
        )

    def add_exporter(
        self,
        exporter_id: str,
        label: str,
        description: str,
        *,
        render: Callable[[PluginRenderContext], str],
        order: int = 100,
        style_kind: str | None = None,
    ) -> None:
        self._manager.register_exporter(
            PluginExporterContribution(
                plugin_id=self._plugin_id,
                exporter_id=str(exporter_id).strip(),
                label=str(label).strip(),
                description=str(description),
                render=render,
                order=int(order),
                style_kind=style_kind,
            )
        )

    def add_keybinding(
        self,
        action: str,
        key: str,
        description: str,
        *,
        handler: Callable[[PluginRenderContext], bool | None],
        section: str = "Plugin Actions",
    ) -> None:
        self._manager.register_keybinding(
            PluginKeybindingContribution(
                plugin_id=self._plugin_id,
                action=str(action).strip(),
                key=str(key),
                description=str(description),
                handler=handler,
                section=str(section).strip() or "Plugin Actions",
            )
        )

    def add_analyzer(
        self,
        analyzer_id: str,
        label: str,
        *,
        description: str = "",
        order: int = 100,
        analyze: Callable[[PluginRenderContext], str | list[str] | None] | None = None,
    ) -> None:
        self._manager.register_analyzer(
            PluginAnalyzerContribution(
                plugin_id=self._plugin_id,
                analyzer_id=str(analyzer_id).strip(),
                label=str(label).strip(),
                description=str(description),
                order=int(order),
                analyze=analyze,
            )
        )

    def add_metadata(
        self,
        metadata_id: str,
        label: str,
        *,
        description: str = "",
        order: int = 100,
        collect: Callable[[PluginRenderContext], dict[str, object] | list[tuple[str, object]] | None] | None = None,
    ) -> None:
        self._manager.register_metadata(
            PluginMetadataContribution(
                plugin_id=self._plugin_id,
                metadata_id=str(metadata_id).strip(),
                label=str(label).strip(),
                description=str(description),
                order=int(order),
                collect=collect,
            )
        )

    def add_setting_field(
        self,
        field_id: str,
        section: str,
        label: str,
        description: str,
        *,
        kind: str,
        scope: str = "global",
        default: object = None,
        options: list[str] | None = None,
        placeholder: str = "",
        action_label: str = "Run",
        on_change: Callable[[PluginRenderContext, object], object | None] | None = None,
    ) -> None:
        kind_name = str(kind).strip()
        if kind_name not in SETTING_FIELD_KINDS:
            raise ValueError(f"unsupported setting field kind {kind_name!r}")
        scope_name = str(scope).strip().lower() or "global"
        if scope_name not in {"global", "project"}:
            raise ValueError("setting field scope must be 'global' or 'project'")
        self._manager.register_setting_field(
            PluginSettingFieldContribution(
                plugin_id=self._plugin_id,
                field_id=str(field_id).strip(),
                section=str(section).strip() or "Plugin Settings",
                label=str(label).strip(),
                description=str(description),
                kind=kind_name,
                scope=scope_name,
                default=default,
                options=list(options or []),
                placeholder=str(placeholder),
                action_label=str(action_label).strip() or "Run",
                on_change=on_change,
            )
        )


class PluginManager:
    def __init__(self) -> None:
        self._plugins: list[LoadedPlugin] = []
        self._load_errors: list[str] = []
        self._plugin_dirs: list[Path] = []
        self._workspaces: list[PluginWorkspaceContribution] = []
        self._panels: list[PluginPanelContribution] = []
        self._exporters: list[PluginExporterContribution] = []
        self._keybindings: list[PluginKeybindingContribution] = []
        self._analyzers: list[PluginAnalyzerContribution] = []
        self._metadata: list[PluginMetadataContribution] = []
        self._setting_fields: list[PluginSettingFieldContribution] = []
        self._store: TrafficStore | None = None
        self._preferences: ApplicationPreferences | None = None
        self._theme_manager: ThemeManager | None = None

    def bind_runtime(
        self,
        *,
        store: "TrafficStore | None" = None,
        preferences: "ApplicationPreferences | None" = None,
        theme_manager: "ThemeManager | None" = None,
    ) -> None:
        if store is not None:
            self._store = store
        if preferences is not None:
            self._preferences = preferences
        if theme_manager is not None:
            self._theme_manager = theme_manager

    def theme_manager(self) -> "ThemeManager | None":
        return self._theme_manager

    def global_state(self, plugin_id: str) -> dict[str, object]:
        if self._preferences is None:
            return {}
        state = self._preferences.plugin_state(str(plugin_id).strip())
        return state if isinstance(state, dict) else {}

    def set_global_state(self, plugin_id: str, values: dict[str, object]) -> None:
        if self._preferences is None:
            return
        self._preferences.set_plugin_state(plugin_id, values)
        self._preferences.save()

    def global_value(self, plugin_id: str, key: str, default: object = None) -> object:
        if self._preferences is None:
            return default
        return self._preferences.plugin_value(plugin_id, key, default)

    def set_global_value(self, plugin_id: str, key: str, value: object) -> None:
        if self._preferences is None:
            return
        self._preferences.set_plugin_value(plugin_id, key, value)
        self._preferences.save()

    def project_state(self, plugin_id: str) -> dict[str, object]:
        if self._store is None:
            return {}
        state = self._store.plugin_state(str(plugin_id).strip())
        return state if isinstance(state, dict) else {}

    def set_project_state(self, plugin_id: str, values: dict[str, object]) -> None:
        if self._store is None:
            return
        self._store.set_plugin_state(plugin_id, values)

    def project_value(self, plugin_id: str, key: str, default: object = None) -> object:
        if self._store is None:
            return default
        return self._store.plugin_value(plugin_id, key, default)

    def set_project_value(self, plugin_id: str, key: str, value: object) -> None:
        if self._store is None:
            return
        self._store.set_plugin_value(plugin_id, key, value)

    def load_from_dirs(self, directories: list[Path]) -> None:
        for directory in directories:
            if directory not in self._plugin_dirs:
                self._plugin_dirs.append(directory)
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

    def plugin_dirs(self) -> list[Path]:
        return list(self._plugin_dirs)

    def workspace_contributions(self) -> list[PluginWorkspaceContribution]:
        return sorted(self._workspaces, key=lambda item: (item.order, item.label.lower(), item.workspace_id))

    def panel_contributions(self, workspace_id: str | None = None) -> list[PluginPanelContribution]:
        items = self._panels
        if workspace_id is not None:
            items = [item for item in items if item.workspace_id == workspace_id]
        return sorted(items, key=lambda item: (item.order, item.title.lower(), item.panel_id))

    def exporter_contributions(self) -> list[PluginExporterContribution]:
        return sorted(self._exporters, key=lambda item: (item.order, item.label.lower(), item.exporter_id))

    def keybinding_contributions(self) -> list[PluginKeybindingContribution]:
        return sorted(self._keybindings, key=lambda item: (item.section.lower(), item.description.lower(), item.action))

    def analyzer_contributions(self) -> list[PluginAnalyzerContribution]:
        return sorted(self._analyzers, key=lambda item: (item.order, item.label.lower(), item.analyzer_id))

    def metadata_contributions(self) -> list[PluginMetadataContribution]:
        return sorted(self._metadata, key=lambda item: (item.order, item.label.lower(), item.metadata_id))

    def setting_field_contributions(self) -> list[PluginSettingFieldContribution]:
        return sorted(self._setting_fields, key=lambda item: (item.section.lower(), item.label.lower(), item.field_id))

    def register_workspace(self, contribution: PluginWorkspaceContribution) -> None:
        if not contribution.workspace_id:
            raise ValueError("workspace id must not be empty")
        if contribution.workspace_id in BUILTIN_WORKSPACE_IDS:
            raise ValueError(f"workspace id {contribution.workspace_id!r} collides with a built-in workspace")
        self._replace_or_append(
            self._workspaces,
            contribution,
            lambda item: item.workspace_id == contribution.workspace_id,
        )

    def register_panel(self, contribution: PluginPanelContribution) -> None:
        if not contribution.workspace_id or not contribution.panel_id:
            raise ValueError("workspace id and panel id must not be empty")
        self._replace_or_append(
            self._panels,
            contribution,
            lambda item: (
                item.workspace_id == contribution.workspace_id
                and item.panel_id == contribution.panel_id
            ),
        )

    def register_exporter(self, contribution: PluginExporterContribution) -> None:
        if not contribution.exporter_id:
            raise ValueError("exporter id must not be empty")
        self._replace_or_append(
            self._exporters,
            contribution,
            lambda item: item.exporter_id == contribution.exporter_id,
        )

    def register_keybinding(self, contribution: PluginKeybindingContribution) -> None:
        if not contribution.action:
            raise ValueError("keybinding action must not be empty")
        self._replace_or_append(
            self._keybindings,
            contribution,
            lambda item: item.action == contribution.action,
        )

    def register_analyzer(self, contribution: PluginAnalyzerContribution) -> None:
        if not contribution.analyzer_id:
            raise ValueError("analyzer id must not be empty")
        self._replace_or_append(
            self._analyzers,
            contribution,
            lambda item: item.analyzer_id == contribution.analyzer_id,
        )

    def register_metadata(self, contribution: PluginMetadataContribution) -> None:
        if not contribution.metadata_id:
            raise ValueError("metadata id must not be empty")
        self._replace_or_append(
            self._metadata,
            contribution,
            lambda item: item.metadata_id == contribution.metadata_id,
        )

    def register_setting_field(self, contribution: PluginSettingFieldContribution) -> None:
        if not contribution.field_id:
            raise ValueError("setting field id must not be empty")
        self._replace_or_append(
            self._setting_fields,
            contribution,
            lambda item: (
                item.plugin_id == contribution.plugin_id
                and item.field_id == contribution.field_id
            ),
        )

    def before_request_forward(self, context: HookContext, request: "ParsedRequest") -> "ParsedRequest":
        current = request
        context.plugin_manager = self
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
        context.plugin_manager = self
        for plugin in self._plugins:
            hook = getattr(plugin.instance, "on_response_received", None)
            if hook is None:
                continue
            hook(context, request, response)

    def on_error(self, context: HookContext, error: Exception) -> None:
        context.plugin_manager = self
        for plugin in self._plugins:
            hook = getattr(plugin.instance, "on_error", None)
            if hook is None:
                continue
            hook(context, error)

    def persist_hook_context(self, context: HookContext) -> None:
        if self._store is None:
            return
        for plugin_id, metadata in context.metadata.items():
            self._store.set_entry_plugin_metadata(context.entry_id, plugin_id, metadata)
        for plugin_id, findings in context.findings.items():
            self._store.set_entry_plugin_findings(context.entry_id, plugin_id, findings)

    def _load_plugin(self, path: Path) -> None:
        provisional_id = path.stem
        api = PluginAPI(self, provisional_id)
        try:
            module = self._load_module(path)
            plugin = self._instantiate_plugin(module, api)
            final_id = str(getattr(plugin, "plugin_id", provisional_id)).strip() or provisional_id
            if final_id != provisional_id:
                api.set_plugin_id(final_id)
            name = str(getattr(plugin, "name", final_id))
            module_contribute = getattr(module, "contribute", None)
            if callable(module_contribute):
                self._call_plugin_factory(module_contribute, api)
            contribute = getattr(plugin, "contribute", None)
            if callable(contribute):
                self._call_plugin_factory(contribute, api)
            on_loaded = getattr(plugin, "on_loaded", None)
            if callable(on_loaded):
                on_loaded()
            self._plugins.append(
                LoadedPlugin(plugin_id=api.plugin_id, name=name, path=path, instance=plugin)
            )
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

    def _instantiate_plugin(self, module: ModuleType, api: PluginAPI) -> object:
        register = getattr(module, "register", None)
        if callable(register):
            plugin = self._call_plugin_factory(register, api)
            return module if plugin is None else plugin
        plugin = getattr(module, "PLUGIN", None)
        if plugin is not None:
            return plugin
        contribute = getattr(module, "contribute", None)
        if callable(contribute):
            self._call_plugin_factory(contribute, api)
            return module
        raise RuntimeError("plugin module must export register(api) / register(), PLUGIN, or contribute(api)")

    @staticmethod
    def _call_plugin_factory(factory: Callable[..., object], api: PluginAPI) -> object:
        signature = inspect.signature(factory)
        positional = [
            parameter
            for parameter in signature.parameters.values()
            if parameter.kind in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
        ]
        required = [
            parameter
            for parameter in positional
            if parameter.default is inspect._empty
        ]
        if len(required) == 0:
            return factory()
        if len(required) == 1 and len(positional) == 1:
            return factory(api)
        raise RuntimeError("plugin factory must accept either zero arguments or a single PluginAPI")

    @staticmethod
    def _replace_or_append(items: list[Any], new_item: Any, matcher: Callable[[Any], bool]) -> None:
        for index, existing in enumerate(items):
            if matcher(existing):
                items[index] = new_item
                return
        items.append(new_item)

    def _reassign_plugin_id(self, old_id: str, new_id: str) -> None:
        if old_id == new_id:
            return
        for collection_name in (
            "_workspaces",
            "_panels",
            "_exporters",
            "_keybindings",
            "_analyzers",
            "_metadata",
            "_setting_fields",
        ):
            collection = getattr(self, collection_name)
            for item in collection:
                if getattr(item, "plugin_id", None) == old_id:
                    item.plugin_id = new_id
