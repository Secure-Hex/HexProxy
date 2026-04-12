from __future__ import annotations

from typing import Callable

from ..extensions import (
    BUILTIN_WORKSPACE_IDS,
    PluginPanelContribution,
    PluginRenderContext,
    PluginWorkspaceContribution,
)
from ..models import TrafficEntry
from ..proxy import ParsedRequest, ParsedResponse
from ..store import PendingInterceptionView
from .state import ExportRequestSource


class NavigationMixin:
    def _plugin_workspaces(self) -> list[PluginWorkspaceContribution]:
        return self.plugin_manager.workspace_contributions()

    def _workspace_tabs(self) -> list[str]:
        return [*self.TABS, *(item.label for item in self._plugin_workspaces())]

    def _plugin_workspace_by_id(
        self, workspace_id: str
    ) -> PluginWorkspaceContribution | None:
        for workspace in self._plugin_workspaces():
            if workspace.workspace_id == workspace_id:
                return workspace
        return None

    def _plugin_workspace_tab_index(self, workspace_id: str) -> int | None:
        for index, workspace in enumerate(self._plugin_workspaces(), start=len(self.TABS)):
            if workspace.workspace_id == workspace_id:
                return index
        return None

    def _workspace_id_for_tab(self, index: int) -> str:
        if index < len(BUILTIN_WORKSPACE_IDS):
            return BUILTIN_WORKSPACE_IDS[index]
        plugin_index = index - len(BUILTIN_WORKSPACE_IDS)
        workspaces = self._plugin_workspaces()
        if 0 <= plugin_index < len(workspaces):
            return workspaces[plugin_index].workspace_id
        return BUILTIN_WORKSPACE_IDS[0]

    def _is_plugin_workspace_tab(self) -> bool:
        return self.active_tab >= len(self.TABS)

    def _build_plugin_context(
        self,
        *,
        plugin_id: str,
        entry: TrafficEntry | None = None,
        request: ParsedRequest | None = None,
        response: ParsedResponse | None = None,
        intercept: PendingInterceptionView | None = None,
        export_source: ExportRequestSource | None = None,
        workspace_id: str = "",
        panel_id: str = "",
        tui: object | None = None,
    ) -> PluginRenderContext:
        return PluginRenderContext(
            plugin_id=plugin_id,
            plugin_manager=self.plugin_manager,
            store=self.store,
            entry=entry,
            request=request,
            response=response,
            intercept=intercept,
            export_source=export_source,
            tui=tui or self,
            workspace_id=workspace_id,
            panel_id=panel_id,
        )

    def _render_plugin_contribution_lines(
        self,
        plugin_id: str,
        callback: Callable[[PluginRenderContext], str | list[str] | None] | None,
        *,
        title: str,
        entry: TrafficEntry | None = None,
        request: ParsedRequest | None = None,
        response: ParsedResponse | None = None,
        intercept: PendingInterceptionView | None = None,
        export_source: ExportRequestSource | None = None,
        workspace_id: str = "",
        panel_id: str = "",
    ) -> list[str]:
        if callback is None:
            return [title, "", "This contribution does not provide a renderer."]
        context = self._build_plugin_context(
            plugin_id=plugin_id,
            entry=entry,
            request=request,
            response=response,
            intercept=intercept,
            export_source=export_source,
            workspace_id=workspace_id,
            panel_id=panel_id,
        )
        try:
            payload = callback(context)
        except Exception as exc:
            return [title, "", f"Plugin render error: {exc}"]
        if payload is None:
            body_lines = ["No content."]
        elif isinstance(payload, str):
            body_lines = payload.splitlines() or [payload]
        elif isinstance(payload, dict):
            body_lines = [f"{key}: {value}" for key, value in payload.items()]
        else:
            body_lines = []
            for line in payload:
                if isinstance(line, tuple) and len(line) == 2:
                    body_lines.append(f"{line[0]}: {line[1]}")
                else:
                    body_lines.append(str(line))
        return [title, "", *body_lines]

    def _plugin_panel_sections(
        self,
        workspace_id: str,
        *,
        entry: TrafficEntry | None = None,
        request: ParsedRequest | None = None,
        response: ParsedResponse | None = None,
        intercept: PendingInterceptionView | None = None,
        export_source: ExportRequestSource | None = None,
    ) -> list[str]:
        lines: list[str] = []
        for panel in self.plugin_manager.panel_contributions(workspace_id):
            lines.extend(
                self._render_plugin_contribution_lines(
                    panel.plugin_id,
                    panel.render_lines,
                    title=f"Plugin Panel: {panel.title}",
                    entry=entry,
                    request=request,
                    response=response,
                    intercept=intercept,
                    export_source=export_source,
                    workspace_id=workspace_id,
                    panel_id=panel.panel_id,
                )
            )
            lines.extend(["", ""])
        while lines[-2:] == ["", ""]:
            lines = lines[:-2]
            if len(lines) < 2:
                break
        return lines

    def _plugin_metadata_lines(self, entry: TrafficEntry | None) -> list[str]:
        if entry is None:
            return []
        lines: list[str] = []
        if entry.plugin_metadata:
            lines.extend(["", "Plugin Metadata"])
            for plugin_id, values in sorted(entry.plugin_metadata.items()):
                lines.append(f"[{plugin_id}]")
                for key, value in values.items():
                    lines.append(f"{key}: {value}")
        for contribution in self.plugin_manager.metadata_contributions():
            payload_lines = self._render_plugin_contribution_lines(
                contribution.plugin_id,
                contribution.collect,
                title=f"Plugin Metadata: {contribution.label}",
                entry=entry,
                workspace_id="http",
            )
            if payload_lines[-1:] == ["No content."]:
                continue
            lines.extend(["", *payload_lines])
        return lines

    def _settings_tab_index(self) -> int:
        return self.TABS.index("Settings")

    def _export_tab_index(self) -> int:
        return self.TABS.index("Export")

    def _scope_tab_index(self) -> int:
        return self.TABS.index("Scope")

    def _filters_tab_index(self) -> int:
        return self.TABS.index("Filters")

    def _keybindings_tab_index(self) -> int:
        return self.TABS.index("Keybindings")

    def _rule_builder_tab_index(self) -> int:
        return self.TABS.index("Rule Builder")

    def _theme_builder_tab_index(self) -> int:
        return self.TABS.index("Theme Builder")

    def _is_settings_tab(self) -> bool:
        return self.active_tab == self._settings_tab_index()

    def _is_export_tab(self) -> bool:
        return self.active_tab == self._export_tab_index()

    def _is_scope_tab(self) -> bool:
        return self.active_tab == self._scope_tab_index()

    def _is_filters_tab(self) -> bool:
        return self.active_tab == self._filters_tab_index()

    def _is_keybindings_tab(self) -> bool:
        return self.active_tab == self._keybindings_tab_index()

    def _is_rule_builder_tab(self) -> bool:
        return self.active_tab == self._rule_builder_tab_index()

    def _is_theme_builder_tab(self) -> bool:
        return self.active_tab == self._theme_builder_tab_index()

    def _security_tab_index(self) -> int:
        return self.TABS.index("Security")

    def _is_security_tab(self) -> bool:
        return self.active_tab == self._security_tab_index()
