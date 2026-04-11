from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import shlex
import sys
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from .bodyview import build_body_document
from .certs import CertificateAuthority, default_certificate_dir
from .extensions import PluginManager, PluginRenderContext
from .models import MatchReplaceRule
from .preferences import ApplicationPreferences
from .proxy import HttpProxyServer, ParsedRequest, ParsedResponse, parse_request_text, render_request_text, render_response_text
from .store import TrafficStore, ViewFilterSettings
from .themes import ThemeManager


JSONRPC_VERSION = "2.0"
MCP_PROTOCOL_VERSION = "2024-11-05"
SUSPICIOUS_RESPONSE_TERMS = (
    "traceback",
    "exception",
    "stack trace",
    "sql syntax",
    "internal server error",
    "access denied",
)


@dataclass(slots=True)
class ExportSource:
    """Stable MCP export contract passed to plugin exporters.

    This object is intentionally lightweight.

    It does not expose a resolved `.entry` object. Exporters should prefer
    `context.entry` and only fall back to `context.export_source.entry_id`
    when they need to resolve the flow through `context.store`.
    """

    label: str
    request_text: str
    response_text: str = ""
    entry_id: int | None = None
    host_hint: str = ""
    port_hint: int = 80
    response_parse_error: str = ""

    @property
    def has_response(self) -> bool:
        return bool(self.response_text.strip())

    @property
    def has_entry_reference(self) -> bool:
        return self.entry_id is not None

    def debug_dict(self) -> dict[str, object]:
        return {
            "label": self.label,
            "entry_id": self.entry_id,
            "host_hint": self.host_hint,
            "port_hint": self.port_hint,
            "has_response": self.has_response,
            "response_parse_error": self.response_parse_error,
        }


@dataclass(slots=True)
class MCPRepeaterExchange:
    request_text: str
    response_text: str = ""
    last_error: str = ""
    sent_at: datetime | None = None


@dataclass(slots=True)
class MCPRepeaterSession:
    session_id: int
    request_text: str
    source_entry_id: int | None = None
    response_text: str = ""
    last_error: str = ""
    last_sent_at: datetime | None = None
    exchanges: list[MCPRepeaterExchange] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.exchanges is None:
            self.exchanges = []


class MCPError(Exception):
    def __init__(self, code: int, message: str, data: object | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


class HexProxyMCPServer:
    def __init__(
        self,
        *,
        store: TrafficStore,
        plugin_manager: PluginManager,
        preferences: ApplicationPreferences,
        theme_manager: ThemeManager | None = None,
    ) -> None:
        self.store = store
        self.plugin_manager = plugin_manager
        self.preferences = preferences
        self.theme_manager = theme_manager
        self._repeater_proxy = HttpProxyServer(
            store=store,
            listen_host="127.0.0.1",
            listen_port=0,
            plugins=plugin_manager,
            certificate_authority=CertificateAuthority(default_certificate_dir()),
        )
        self._repeater_sessions: dict[int, MCPRepeaterSession] = {}
        self._next_repeater_session_id = 1

    def serve(self) -> int:
        input_stream = sys.stdin.buffer
        output_stream = sys.stdout.buffer
        while True:
            message = self._read_message(input_stream)
            if message is None:
                return 0
            response = self.handle_message(message)
            if response is not None:
                self._write_message(output_stream, response)

    def handle_message(self, message: dict[str, object]) -> dict[str, object] | None:
        method = str(message.get("method", ""))
        if not method:
            raise MCPError(-32600, "invalid request: missing method")
        if "id" not in message:
            self._handle_notification(method, message.get("params"))
            return None
        request_id = message.get("id")
        try:
            result = self._dispatch(method, message.get("params"))
        except MCPError as exc:
            return self._error_response(request_id, exc.code, exc.message, exc.data)
        except Exception as exc:
            return self._error_response(request_id, -32603, f"internal error: {exc}")
        return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": result}

    def _handle_notification(self, method: str, params: object) -> None:
        if method == "notifications/initialized":
            return
        if method == "notifications/cancelled":
            return

    def _dispatch(self, method: str, params: object) -> dict[str, object]:
        if method == "initialize":
            return self._initialize_result()
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": self._tool_definitions()}
        if method == "tools/call":
            return self._call_tool(self._require_dict(params))
        if method == "resources/list":
            return {"resources": self._resource_definitions()}
        if method == "resources/read":
            return self._read_resource(self._require_dict(params))
        if method == "prompts/list":
            return {"prompts": []}
        if method == "logging/setLevel":
            return {}
        raise MCPError(-32601, f"method not found: {method}")

    def _initialize_result(self) -> dict[str, object]:
        return {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {
                "tools": {},
                "resources": {},
            },
            "serverInfo": {
                "name": "hexproxy-mcp",
                "version": "0.1.0",
            },
        }

    def _tool_definitions(self) -> list[dict[str, object]]:
        return [
            {
                "name": "project_info",
                "description": "Return high-level information about the loaded HexProxy project, filters, scope, and plugin runtime.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
            {
                "name": "list_flows",
                "description": "List captured flows with optional filtering and pagination.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "offset": {"type": "integer", "minimum": 0},
                        "limit": {"type": "integer", "minimum": 1},
                        "only_visible": {"type": "boolean"},
                        "method": {"type": "string"},
                        "host_contains": {"type": "string"},
                        "text_contains": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
            },
            {
                "name": "search_flows",
                "description": "Search flows by free text across method, host, path, request text, and response text.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "limit": {"type": "integer", "minimum": 1},
                    },
                    "required": ["query"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "get_flow",
                "description": "Return a detailed HTTP view of a captured flow, including decoded request and response bodies.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "entry_id": {"type": "integer", "minimum": 1},
                        "pretty": {"type": "boolean"},
                        "max_body_chars": {"type": "integer", "minimum": 256},
                    },
                    "required": ["entry_id"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "list_exporters",
                "description": "List built-in and plugin-provided export formats.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
            {
                "name": "render_export",
                "description": "Render one export format for a captured flow. Supports built-in formats and plugin exporters.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "entry_id": {"type": "integer", "minimum": 1},
                        "format": {"type": "string"},
                    },
                    "required": ["entry_id", "format"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "list_plugins",
                "description": "Return loaded plugins, contribution counts, configured plugin directories, and load errors.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
            {
                "name": "set_intercept_mode",
                "description": "Set the active intercept mode.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"mode": {"type": "string", "enum": ["off", "request", "response", "both"]}},
                    "required": ["mode"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "list_interceptions",
                "description": "List interception history, including pending and resolved items.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
            {
                "name": "update_interception",
                "description": "Replace the raw HTTP text of a pending interception item.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "record_id": {"type": "integer", "minimum": 1},
                        "raw_text": {"type": "string"},
                    },
                    "required": ["record_id", "raw_text"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "resolve_interception",
                "description": "Resolve a pending interception by forwarding or dropping it.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "record_id": {"type": "integer", "minimum": 1},
                        "decision": {"type": "string", "enum": ["forward", "drop"]},
                    },
                    "required": ["record_id", "decision"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "list_match_replace_rules",
                "description": "Return the current Match/Replace rules.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
            {
                "name": "upsert_match_replace_rule",
                "description": "Create or replace a Match/Replace rule by index.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "index": {"type": "integer", "minimum": 0},
                        "enabled": {"type": "boolean"},
                        "scope": {"type": "string"},
                        "mode": {"type": "string"},
                        "match": {"type": "string"},
                        "replace": {"type": "string"},
                        "description": {"type": "string"},
                    },
                    "required": ["enabled", "scope", "mode", "match", "replace", "description"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "delete_match_replace_rule",
                "description": "Delete one Match/Replace rule by index.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"index": {"type": "integer", "minimum": 0}},
                    "required": ["index"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "list_repeater_sessions",
                "description": "List in-memory MCP repeater sessions and their send history.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
            {
                "name": "create_repeater_session",
                "description": "Create a repeater session from a flow or a raw HTTP request.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "entry_id": {"type": "integer", "minimum": 1},
                        "request_text": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
            },
            {
                "name": "get_repeater_session",
                "description": "Return one repeater session, including current draft and historical exchanges.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"session_id": {"type": "integer", "minimum": 1}},
                    "required": ["session_id"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "update_repeater_request",
                "description": "Replace the current draft request of a repeater session.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "integer", "minimum": 1},
                        "request_text": {"type": "string"},
                    },
                    "required": ["session_id", "request_text"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "send_repeater_request",
                "description": "Send the current repeater draft and append the result to the session history.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"session_id": {"type": "integer", "minimum": 1}},
                    "required": ["session_id"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "list_keybindings",
                "description": "Return global keybindings from the HexProxy configuration file.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
            {
                "name": "set_keybinding",
                "description": "Set or replace one global keybinding action.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {"type": "string"},
                        "key": {"type": "string"},
                    },
                    "required": ["action", "key"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "list_themes",
                "description": "Return available themes and the currently selected global theme.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
            {
                "name": "set_theme",
                "description": "Set the current global theme name.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"theme": {"type": "string"}},
                    "required": ["theme"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "get_plugin_state",
                "description": "Read plugin state from the global config or the current project.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "plugin_id": {"type": "string"},
                        "scope": {"type": "string", "enum": ["global", "project"]},
                    },
                    "required": ["plugin_id", "scope"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "set_plugin_state",
                "description": "Merge values into plugin state for the global config or the current project.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "plugin_id": {"type": "string"},
                        "scope": {"type": "string", "enum": ["global", "project"]},
                        "values": {"type": "object"},
                    },
                    "required": ["plugin_id", "scope", "values"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "set_scope",
                "description": "Replace the current scope pattern list.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "patterns": {
                            "type": "array",
                            "items": {"type": "string"},
                        }
                    },
                    "required": ["patterns"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "add_scope_patterns",
                "description": "Append one or more scope patterns, preserving existing entries and de-duplicating normalized patterns.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "patterns": {
                            "type": "array",
                            "items": {"type": "string"},
                        }
                    },
                    "required": ["patterns"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "remove_scope_patterns",
                "description": "Remove one or more scope patterns from the current scope.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "patterns": {
                            "type": "array",
                            "items": {"type": "string"},
                        }
                    },
                    "required": ["patterns"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "set_view_filters",
                "description": "Update view filters used by Flows and Sitemap. Omitted fields keep their current values.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "show_out_of_scope": {"type": "boolean"},
                        "query_mode": {"type": "string"},
                        "failure_mode": {"type": "string"},
                        "body_mode": {"type": "string"},
                        "methods": {"type": "array", "items": {"type": "string"}},
                        "hidden_methods": {"type": "array", "items": {"type": "string"}},
                        "hidden_extensions": {"type": "array", "items": {"type": "string"}},
                    },
                    "additionalProperties": False,
                },
            },
            {
                "name": "analyze_flow",
                "description": "Return a security-oriented structured analysis of one captured flow.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"entry_id": {"type": "integer", "minimum": 1}},
                    "required": ["entry_id"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "list_suspicious_flows",
                "description": "Return flows ranked by heuristic security interest.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "limit": {"type": "integer", "minimum": 1},
                        "only_visible": {"type": "boolean"},
                    },
                    "additionalProperties": False,
                },
            },
            {
                "name": "flow_evidence_bundle",
                "description": "Return a compact evidence bundle for one flow, suitable for LLM reasoning or reporting.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "entry_id": {"type": "integer", "minimum": 1},
                        "pretty": {"type": "boolean"},
                        "max_body_chars": {"type": "integer", "minimum": 256},
                    },
                    "required": ["entry_id"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "save_project",
                "description": "Write the current project file to disk.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
            },
        ]

    def _resource_definitions(self) -> list[dict[str, object]]:
        resources = [
            {
                "uri": "hexproxy://project/info",
                "name": "Project Info",
                "description": "Current project summary, scope, filters, and plugin counts.",
                "mimeType": "application/json",
            },
            {
                "uri": "hexproxy://plugins/summary",
                "name": "Plugin Summary",
                "description": "Loaded plugins, configured directories, and contribution inventory.",
                "mimeType": "application/json",
            },
            {
                "uri": "hexproxy://docs/mcp",
                "name": "MCP Guide",
                "description": "HexProxy MCP usage guide, tool contract, and runtime notes.",
                "mimeType": "text/markdown",
            },
        ]
        docs_path = self._plugin_docs_path()
        if docs_path is not None:
            resources.append(
                {
                    "uri": "hexproxy://docs/plugin-development",
                    "name": "Plugin Development Guide",
                    "description": "Runtime-accurate HexProxy plugin development documentation.",
                    "mimeType": "text/markdown",
                }
            )
        for entry in self.store.visible_entries():
            resources.append(
                {
                    "uri": f"hexproxy://flows/{entry.id}",
                    "name": f"Flow #{entry.id}",
                    "description": f"{entry.request.method or '-'} {entry.summary_host}{entry.summary_path}",
                    "mimeType": "application/json",
                }
            )
            resources.append(
                {
                    "uri": f"hexproxy://flows/{entry.id}/evidence",
                    "name": f"Flow #{entry.id} Evidence",
                    "description": f"Compact evidence bundle for flow #{entry.id}.",
                    "mimeType": "application/json",
                }
            )
        for plugin in self.plugin_manager.loaded_plugins():
            resources.append(
                {
                    "uri": f"hexproxy://plugins/{plugin.plugin_id}",
                    "name": f"Plugin {plugin.plugin_id}",
                    "description": f"Contribution and state summary for plugin {plugin.plugin_id}.",
                    "mimeType": "application/json",
                }
            )
        return resources

    def _call_tool(self, params: dict[str, object]) -> dict[str, object]:
        name = str(params.get("name", ""))
        arguments = self._require_dict(params.get("arguments", {}))
        handlers = {
            "project_info": self._tool_project_info,
            "list_flows": self._tool_list_flows,
            "search_flows": self._tool_search_flows,
            "get_flow": self._tool_get_flow,
            "list_exporters": self._tool_list_exporters,
            "render_export": self._tool_render_export,
            "list_plugins": self._tool_list_plugins,
            "set_intercept_mode": self._tool_set_intercept_mode,
            "list_interceptions": self._tool_list_interceptions,
            "update_interception": self._tool_update_interception,
            "resolve_interception": self._tool_resolve_interception,
            "list_match_replace_rules": self._tool_list_match_replace_rules,
            "upsert_match_replace_rule": self._tool_upsert_match_replace_rule,
            "delete_match_replace_rule": self._tool_delete_match_replace_rule,
            "list_repeater_sessions": self._tool_list_repeater_sessions,
            "create_repeater_session": self._tool_create_repeater_session,
            "get_repeater_session": self._tool_get_repeater_session,
            "update_repeater_request": self._tool_update_repeater_request,
            "send_repeater_request": self._tool_send_repeater_request,
            "list_keybindings": self._tool_list_keybindings,
            "set_keybinding": self._tool_set_keybinding,
            "list_themes": self._tool_list_themes,
            "set_theme": self._tool_set_theme,
            "get_plugin_state": self._tool_get_plugin_state,
            "set_plugin_state": self._tool_set_plugin_state,
            "set_scope": self._tool_set_scope,
            "add_scope_patterns": self._tool_add_scope_patterns,
            "remove_scope_patterns": self._tool_remove_scope_patterns,
            "set_view_filters": self._tool_set_view_filters,
            "analyze_flow": self._tool_analyze_flow,
            "list_suspicious_flows": self._tool_list_suspicious_flows,
            "flow_evidence_bundle": self._tool_flow_evidence_bundle,
            "save_project": self._tool_save_project,
        }
        handler = handlers.get(name)
        if handler is None:
            raise MCPError(-32601, f"unknown tool: {name}")
        payload = handler(arguments)
        return {
            "content": [
                {
                    "type": "text",
                    "text": self._json_text(payload),
                }
            ]
        }

    def _read_resource(self, params: dict[str, object]) -> dict[str, object]:
        uri = str(params.get("uri", ""))
        if uri == "hexproxy://project/info":
            text = self._json_text(self._project_info_payload())
            mime_type = "application/json"
        elif uri == "hexproxy://plugins/summary":
            text = self._json_text(self._plugins_payload())
            mime_type = "application/json"
        elif uri == "hexproxy://docs/mcp":
            docs_path = self._mcp_docs_path()
            if docs_path is None:
                raise MCPError(-32602, "MCP documentation resource is not available")
            text = docs_path.read_text(encoding="utf-8")
            mime_type = "text/markdown"
        elif uri == "hexproxy://docs/plugin-development":
            docs_path = self._plugin_docs_path()
            if docs_path is None:
                raise MCPError(-32602, "plugin documentation resource is not available")
            text = docs_path.read_text(encoding="utf-8")
            mime_type = "text/markdown"
        elif uri.startswith("hexproxy://plugins/"):
            plugin_id = uri.rsplit("/", 1)[1]
            text = self._json_text(self._plugin_detail_payload(plugin_id))
            mime_type = "application/json"
        elif uri.endswith("/evidence") and uri.startswith("hexproxy://flows/"):
            parts = uri.split("/")
            try:
                entry_id = int(parts[-2])
            except ValueError as exc:
                raise MCPError(-32602, f"invalid flow evidence resource URI: {uri}") from exc
            text = self._json_text(self._flow_evidence_payload(entry_id, pretty=True, max_body_chars=8000))
            mime_type = "application/json"
        elif uri.startswith("hexproxy://flows/"):
            try:
                entry_id = int(uri.rsplit("/", 1)[1])
            except ValueError as exc:
                raise MCPError(-32602, f"invalid flow resource URI: {uri}") from exc
            text = self._json_text(self._flow_payload(entry_id, pretty=True, max_body_chars=12000))
            mime_type = "application/json"
        else:
            raise MCPError(-32602, f"unknown resource URI: {uri}")
        return {
            "contents": [
                {
                    "uri": uri,
                    "mimeType": mime_type,
                    "text": text,
                }
            ]
        }

    def _tool_project_info(self, arguments: dict[str, object]) -> dict[str, object]:
        return self._project_info_payload()

    def _tool_list_flows(self, arguments: dict[str, object]) -> dict[str, object]:
        offset = max(0, int(arguments.get("offset", 0)))
        limit = max(1, min(500, int(arguments.get("limit", 50))))
        only_visible = bool(arguments.get("only_visible", True))
        method = str(arguments.get("method", "")).strip().upper()
        host_contains = str(arguments.get("host_contains", "")).strip().lower()
        text_contains = str(arguments.get("text_contains", "")).strip().lower()
        entries = self.store.visible_entries() if only_visible else self.store.snapshot()
        filtered = [entry for entry in entries if self._flow_matches(entry, method=method, host_contains=host_contains, text_contains=text_contains)]
        page = filtered[offset : offset + limit]
        return {
            "total": len(filtered),
            "offset": offset,
            "limit": limit,
            "items": [self._flow_summary(entry) for entry in page],
        }

    def _tool_search_flows(self, arguments: dict[str, object]) -> dict[str, object]:
        query = str(arguments.get("query", "")).strip().lower()
        if not query:
            raise MCPError(-32602, "query must not be empty")
        limit = max(1, min(200, int(arguments.get("limit", 20))))
        matches: list[dict[str, object]] = []
        for entry in self.store.snapshot():
            if self._flow_matches(entry, text_contains=query):
                matches.append(self._flow_summary(entry))
            if len(matches) >= limit:
                break
        return {"query": query, "total": len(matches), "items": matches}

    def _tool_get_flow(self, arguments: dict[str, object]) -> dict[str, object]:
        entry_id = int(arguments.get("entry_id", 0))
        pretty = bool(arguments.get("pretty", False))
        max_body_chars = max(256, min(200000, int(arguments.get("max_body_chars", 12000))))
        return self._flow_payload(entry_id, pretty=pretty, max_body_chars=max_body_chars)

    def _tool_list_exporters(self, arguments: dict[str, object]) -> dict[str, object]:
        builtin = [
            {"id": "http_pair", "label": "HTTP request + response", "style_kind": "http"},
            {"id": "python_requests", "label": "Python requests", "style_kind": "python"},
            {"id": "curl_bash", "label": "curl (bash)", "style_kind": "shell"},
            {"id": "curl_windows", "label": "curl (windows)", "style_kind": "shell"},
            {"id": "node_fetch", "label": "Node.js fetch", "style_kind": "javascript"},
            {"id": "go_http", "label": "Go net/http", "style_kind": "go"},
            {"id": "php_curl", "label": "PHP cURL", "style_kind": "php"},
            {"id": "rust_reqwest", "label": "Rust reqwest", "style_kind": "rust"},
        ]
        plugins = [
            {
                "id": f"plugin:{item.exporter_id}",
                "plugin_id": item.plugin_id,
                "label": item.label,
                "description": item.description,
                "style_kind": item.style_kind,
            }
            for item in self.plugin_manager.exporter_contributions()
        ]
        return {"builtin": builtin, "plugins": plugins}

    def _tool_render_export(self, arguments: dict[str, object]) -> dict[str, object]:
        entry_id = int(arguments.get("entry_id", 0))
        export_format = str(arguments.get("format", "")).strip()
        if not export_format:
            raise MCPError(-32602, "format must not be empty")
        entry = self._require_entry(entry_id)
        source = ExportSource(
            label=f"Flow #{entry.id}",
            request_text=self._render_request_for_entry(entry),
            response_text=self._render_response_for_entry(entry),
            entry_id=entry.id,
            host_hint=entry.request.host,
            port_hint=entry.request.port,
        )
        payload = self._render_export_payload(export_format, source)
        payload.update(
            {
            "entry_id": entry.id,
            "format": export_format,
            }
        )
        return payload

    def _tool_list_plugins(self, arguments: dict[str, object]) -> dict[str, object]:
        return self._plugins_payload()

    def _tool_set_intercept_mode(self, arguments: dict[str, object]) -> dict[str, object]:
        mode = str(arguments.get("mode", "")).strip().lower()
        try:
            self.store.set_intercept_mode(mode)
        except Exception as exc:
            raise MCPError(-32602, f"invalid intercept mode: {exc}") from exc
        return {"intercept_mode": self.store.intercept_mode()}

    def _tool_list_interceptions(self, arguments: dict[str, object]) -> dict[str, object]:
        history = self.store.interception_history()
        return {
            "items": [
                {
                    "record_id": item.record_id,
                    "entry_id": item.entry_id,
                    "phase": item.phase,
                    "decision": item.decision,
                    "active": item.active,
                    "created_at": item.created_at.isoformat(),
                    "updated_at": item.updated_at.isoformat(),
                    "raw_text": item.raw_text,
                }
                for item in history
            ]
        }

    def _tool_update_interception(self, arguments: dict[str, object]) -> dict[str, object]:
        record_id = int(arguments.get("record_id", 0))
        raw_text = str(arguments.get("raw_text", ""))
        record = self.store.get_pending_interception_record(record_id)
        if record is None or not record.active:
            raise MCPError(-32602, f"pending interception record {record_id} was not found")
        try:
            if record.phase == "request":
                parse_request_text(raw_text)
            else:
                from .proxy import parse_response_text

                parse_response_text(raw_text)
        except Exception as exc:
            raise MCPError(-32602, f"invalid edited {record.phase}: {exc}") from exc
        self.store.update_pending_interception_record(record_id, raw_text)
        updated = self.store.get_pending_interception_record(record_id)
        return {
            "record_id": record_id,
            "phase": record.phase,
            "active": updated.active if updated is not None else False,
        }

    def _tool_resolve_interception(self, arguments: dict[str, object]) -> dict[str, object]:
        record_id = int(arguments.get("record_id", 0))
        decision = str(arguments.get("decision", "")).strip().lower()
        if decision not in {"forward", "drop"}:
            raise MCPError(-32602, "decision must be 'forward' or 'drop'")
        record = self.store.get_pending_interception_record(record_id)
        if record is None or not record.active:
            raise MCPError(-32602, f"pending interception record {record_id} was not found")
        if decision == "forward":
            self.store.forward_pending_interception_record(record_id)
        else:
            self.store.drop_pending_interception_record(record_id)
        return {"record_id": record_id, "decision": decision}

    def _tool_list_match_replace_rules(self, arguments: dict[str, object]) -> dict[str, object]:
        rules = self.store.match_replace_rules()
        return {"items": [self._rule_to_dict(index, rule) for index, rule in enumerate(rules)]}

    def _tool_upsert_match_replace_rule(self, arguments: dict[str, object]) -> dict[str, object]:
        rules = self.store.match_replace_rules()
        rule = MatchReplaceRule(
            enabled=bool(arguments.get("enabled", True)),
            scope=str(arguments.get("scope", "request")),
            mode=str(arguments.get("mode", "literal")),
            match=str(arguments.get("match", "")),
            replace=str(arguments.get("replace", "")),
            description=str(arguments.get("description", "")),
        )
        if "index" in arguments and arguments.get("index") is not None:
            index = int(arguments.get("index", 0))
            if index < 0 or index >= len(rules):
                raise MCPError(-32602, f"rule index {index} is out of range")
            rules[index] = rule
        else:
            rules.append(rule)
            index = len(rules) - 1
        self.store.set_match_replace_rules(rules)
        return {"index": index, "rule": self._rule_to_dict(index, rule)}

    def _tool_delete_match_replace_rule(self, arguments: dict[str, object]) -> dict[str, object]:
        index = int(arguments.get("index", 0))
        rules = self.store.match_replace_rules()
        if index < 0 or index >= len(rules):
            raise MCPError(-32602, f"rule index {index} is out of range")
        removed = rules.pop(index)
        self.store.set_match_replace_rules(rules)
        return {"deleted": self._rule_to_dict(index, removed)}

    def _tool_list_repeater_sessions(self, arguments: dict[str, object]) -> dict[str, object]:
        return {
            "items": [self._repeater_session_payload(session) for session in self._repeater_sessions.values()]
        }

    def _tool_create_repeater_session(self, arguments: dict[str, object]) -> dict[str, object]:
        entry_id = arguments.get("entry_id")
        request_text = str(arguments.get("request_text", ""))
        source_entry_id: int | None = None
        if entry_id is not None:
            entry = self.store.get(int(entry_id))
            if entry is None:
                raise MCPError(-32602, f"flow {entry_id} was not found")
            request_text = self._render_request_for_entry(entry)
            source_entry_id = entry.id
        if not request_text.strip():
            raise MCPError(-32602, "entry_id or request_text is required")
        try:
            parse_request_text(request_text)
        except Exception as exc:
            raise MCPError(-32602, f"invalid repeater request: {exc}") from exc
        session = MCPRepeaterSession(
            session_id=self._next_repeater_session_id,
            request_text=request_text,
            source_entry_id=source_entry_id,
        )
        self._next_repeater_session_id += 1
        self._repeater_sessions[session.session_id] = session
        return self._repeater_session_payload(session)

    def _tool_get_repeater_session(self, arguments: dict[str, object]) -> dict[str, object]:
        session = self._require_repeater_session(int(arguments.get("session_id", 0)))
        return self._repeater_session_payload(session)

    def _tool_update_repeater_request(self, arguments: dict[str, object]) -> dict[str, object]:
        session = self._require_repeater_session(int(arguments.get("session_id", 0)))
        request_text = str(arguments.get("request_text", ""))
        try:
            parse_request_text(request_text)
        except Exception as exc:
            raise MCPError(-32602, f"invalid repeater request: {exc}") from exc
        session.request_text = request_text
        return self._repeater_session_payload(session)

    def _tool_send_repeater_request(self, arguments: dict[str, object]) -> dict[str, object]:
        session = self._require_repeater_session(int(arguments.get("session_id", 0)))
        sent_at = datetime.now(timezone.utc)
        try:
            response_text = self._send_repeater_text(session.request_text)
            session.response_text = response_text
            session.last_error = ""
            session.last_sent_at = sent_at
            session.exchanges.append(
                MCPRepeaterExchange(
                    request_text=session.request_text,
                    response_text=response_text,
                    sent_at=sent_at,
                )
            )
        except Exception as exc:
            session.response_text = ""
            session.last_error = str(exc)
            session.last_sent_at = sent_at
            session.exchanges.append(
                MCPRepeaterExchange(
                    request_text=session.request_text,
                    response_text="",
                    last_error=str(exc),
                    sent_at=sent_at,
                )
            )
            raise MCPError(-32603, f"repeater send failed: {exc}") from exc
        return self._repeater_session_payload(session)

    def _tool_list_keybindings(self, arguments: dict[str, object]) -> dict[str, object]:
        return {"keybindings": self.preferences.keybindings()}

    def _tool_set_keybinding(self, arguments: dict[str, object]) -> dict[str, object]:
        action = str(arguments.get("action", "")).strip()
        key = str(arguments.get("key", ""))
        if not action:
            raise MCPError(-32602, "action must not be empty")
        bindings = self.preferences.keybindings()
        bindings[action] = key
        try:
            self.preferences.set_keybindings(bindings)
            self.preferences.save()
        except Exception as exc:
            raise MCPError(-32602, f"invalid keybinding: {exc}") from exc
        return {"keybindings": self.preferences.keybindings()}

    def _tool_list_themes(self, arguments: dict[str, object]) -> dict[str, object]:
        themes = self.theme_manager.available_themes() if self.theme_manager is not None else []
        return {
            "current": self.preferences.theme_name(),
            "items": [
                {
                    "name": item.name,
                    "description": item.description,
                    "source": item.source,
                    "colors": item.colors,
                }
                for item in themes
            ],
        }

    def _tool_set_theme(self, arguments: dict[str, object]) -> dict[str, object]:
        if self.theme_manager is None:
            raise MCPError(-32603, "theme manager is not available")
        theme_name = str(arguments.get("theme", "")).strip()
        if not theme_name:
            raise MCPError(-32602, "theme must not be empty")
        if self.theme_manager.get(theme_name) is None:
            raise MCPError(-32602, f"unknown theme: {theme_name}")
        self.preferences.set_theme_name(theme_name)
        self.preferences.save()
        return {"theme": self.preferences.theme_name()}

    def _tool_get_plugin_state(self, arguments: dict[str, object]) -> dict[str, object]:
        plugin_id = str(arguments.get("plugin_id", "")).strip()
        scope = str(arguments.get("scope", "")).strip().lower()
        if not plugin_id:
            raise MCPError(-32602, "plugin_id must not be empty")
        if scope == "global":
            values = self.preferences.plugin_state(plugin_id)
        elif scope == "project":
            values = self.store.plugin_state(plugin_id)
        else:
            raise MCPError(-32602, "scope must be 'global' or 'project'")
        return {"plugin_id": plugin_id, "scope": scope, "values": values}

    def _tool_set_plugin_state(self, arguments: dict[str, object]) -> dict[str, object]:
        plugin_id = str(arguments.get("plugin_id", "")).strip()
        scope = str(arguments.get("scope", "")).strip().lower()
        values = arguments.get("values")
        if not plugin_id:
            raise MCPError(-32602, "plugin_id must not be empty")
        if not isinstance(values, dict):
            raise MCPError(-32602, "values must be a JSON object")
        if scope == "global":
            current = self.preferences.plugin_state(plugin_id)
            current.update(values)
            self.preferences.set_plugin_state(plugin_id, current)
            self.preferences.save()
            result = self.preferences.plugin_state(plugin_id)
        elif scope == "project":
            current = self.store.plugin_state(plugin_id)
            current.update(values)
            self.store.set_plugin_state(plugin_id, current)
            result = self.store.plugin_state(plugin_id)
        else:
            raise MCPError(-32602, "scope must be 'global' or 'project'")
        return {"plugin_id": plugin_id, "scope": scope, "values": result}

    def _tool_set_scope(self, arguments: dict[str, object]) -> dict[str, object]:
        patterns = arguments.get("patterns")
        if not isinstance(patterns, list):
            raise MCPError(-32602, "patterns must be an array of strings")
        normalized = [str(item) for item in patterns]
        self.store.set_scope_hosts(normalized)
        return {
            "scope_hosts": self.store.scope_hosts(),
            "count": len(self.store.scope_hosts()),
        }

    def _tool_add_scope_patterns(self, arguments: dict[str, object]) -> dict[str, object]:
        patterns = arguments.get("patterns")
        if not isinstance(patterns, list):
            raise MCPError(-32602, "patterns must be an array of strings")
        updated = [*self.store.scope_hosts(), *(str(item) for item in patterns)]
        self.store.set_scope_hosts(updated)
        return {
            "scope_hosts": self.store.scope_hosts(),
            "count": len(self.store.scope_hosts()),
        }

    def _tool_remove_scope_patterns(self, arguments: dict[str, object]) -> dict[str, object]:
        patterns = arguments.get("patterns")
        if not isinstance(patterns, list):
            raise MCPError(-32602, "patterns must be an array of strings")
        to_remove = {
            TrafficStore._normalize_scope_pattern(str(item))
            for item in patterns
            if TrafficStore._normalize_scope_pattern(str(item))
        }
        remaining = [pattern for pattern in self.store.scope_hosts() if pattern not in to_remove]
        self.store.set_scope_hosts(remaining)
        return {
            "scope_hosts": self.store.scope_hosts(),
            "count": len(self.store.scope_hosts()),
        }

    def _tool_set_view_filters(self, arguments: dict[str, object]) -> dict[str, object]:
        current = self.store.view_filters()
        updated = ViewFilterSettings(
            show_out_of_scope=bool(arguments.get("show_out_of_scope", current.show_out_of_scope)),
            query_mode=str(arguments.get("query_mode", current.query_mode)),
            failure_mode=str(arguments.get("failure_mode", current.failure_mode)),
            body_mode=str(arguments.get("body_mode", current.body_mode)),
            methods=[str(item).upper() for item in arguments.get("methods", current.methods)],
            hidden_methods=[str(item).upper() for item in arguments.get("hidden_methods", current.hidden_methods)],
            hidden_extensions=[str(item).lstrip(".").lower() for item in arguments.get("hidden_extensions", current.hidden_extensions)],
        )
        self.store.set_view_filters(updated)
        filters = self.store.view_filters()
        return {
            "show_out_of_scope": filters.show_out_of_scope,
            "query_mode": filters.query_mode,
            "failure_mode": filters.failure_mode,
            "body_mode": filters.body_mode,
            "methods": filters.methods,
            "hidden_methods": filters.hidden_methods,
            "hidden_extensions": filters.hidden_extensions,
        }

    def _tool_save_project(self, arguments: dict[str, object]) -> dict[str, object]:
        raw_path = str(arguments.get("path", "")).strip()
        try:
            saved_path = self.store.save(raw_path or None)
        except Exception as exc:
            raise MCPError(-32603, f"could not save project: {exc}") from exc
        return {"project_path": str(saved_path)}

    def _tool_analyze_flow(self, arguments: dict[str, object]) -> dict[str, object]:
        entry = self._require_entry(int(arguments.get("entry_id", 0)))
        return self._analyze_flow_payload(entry)

    def _tool_list_suspicious_flows(self, arguments: dict[str, object]) -> dict[str, object]:
        limit = max(1, min(200, int(arguments.get("limit", 20))))
        only_visible = bool(arguments.get("only_visible", True))
        entries = self.store.visible_entries() if only_visible else self.store.snapshot()
        ranked: list[dict[str, object]] = []
        for entry in entries:
            analysis = self._analyze_flow_payload(entry)
            score = int(analysis["heuristics"]["score"])
            if score <= 0:
                continue
            ranked.append(
                {
                    "summary": self._flow_summary(entry),
                    "heuristics": analysis["heuristics"],
                    "request": analysis["request"],
                    "response": analysis["response"],
                }
            )
        ranked.sort(key=lambda item: (-int(item["heuristics"]["score"]), int(item["summary"]["id"])))
        return {"total": len(ranked), "items": ranked[:limit]}

    def _tool_flow_evidence_bundle(self, arguments: dict[str, object]) -> dict[str, object]:
        entry_id = int(arguments.get("entry_id", 0))
        pretty = bool(arguments.get("pretty", True))
        max_body_chars = max(256, min(200000, int(arguments.get("max_body_chars", 12000))))
        return self._flow_evidence_payload(entry_id, pretty=pretty, max_body_chars=max_body_chars)

    def _project_info_payload(self) -> dict[str, object]:
        visible = self.store.visible_entries()
        all_entries = self.store.snapshot()
        return {
            "project_path": str(self.store.project_path()) if self.store.project_path() else None,
            "entry_count": len(all_entries),
            "visible_entry_count": len(visible),
            "scope_hosts": self.store.scope_hosts(),
            "view_filters": {
                "show_out_of_scope": self.store.view_filters().show_out_of_scope,
                "query_mode": self.store.view_filters().query_mode,
                "failure_mode": self.store.view_filters().failure_mode,
                "body_mode": self.store.view_filters().body_mode,
                "methods": self.store.view_filters().methods,
                "hidden_methods": self.store.view_filters().hidden_methods,
                "hidden_extensions": self.store.view_filters().hidden_extensions,
            },
            "intercept_mode": self.store.intercept_mode(),
            "plugin_count": len(self.plugin_manager.loaded_plugins()),
            "plugin_dirs": [str(path) for path in self.plugin_manager.plugin_dirs()],
            "theme": self.preferences.theme_name(),
            "repeater_session_count": len(self._repeater_sessions),
        }

    def _plugins_payload(self) -> dict[str, object]:
        loaded = self.plugin_manager.loaded_plugins()
        summaries = [self._plugin_detail_payload(item.plugin_id) for item in loaded]
        return {
            "loaded_plugins": [
                {
                    "plugin_id": item.plugin_id,
                    "name": item.name,
                    "path": str(item.path),
                }
                for item in loaded
            ],
            "plugin_dirs": [str(path) for path in self.plugin_manager.plugin_dirs()],
            "load_errors": self.plugin_manager.load_errors(),
            "plugin_summaries": summaries,
            "contributions": {
                "workspaces": [
                    {
                        "plugin_id": item.plugin_id,
                        "workspace_id": item.workspace_id,
                        "label": item.label,
                    }
                    for item in self.plugin_manager.workspace_contributions()
                ],
                "panels": [
                    {
                        "plugin_id": item.plugin_id,
                        "workspace_id": item.workspace_id,
                        "panel_id": item.panel_id,
                        "title": item.title,
                    }
                    for item in self.plugin_manager.panel_contributions()
                ],
                "exporters": [
                    {
                        "plugin_id": item.plugin_id,
                        "exporter_id": item.exporter_id,
                        "label": item.label,
                        "style_kind": item.style_kind,
                    }
                    for item in self.plugin_manager.exporter_contributions()
                ],
                "keybindings": [
                    {
                        "plugin_id": item.plugin_id,
                        "action": item.action,
                        "key": item.key,
                        "section": item.section,
                    }
                    for item in self.plugin_manager.keybinding_contributions()
                ],
                "analyzers": [
                    {
                        "plugin_id": item.plugin_id,
                        "analyzer_id": item.analyzer_id,
                        "label": item.label,
                    }
                    for item in self.plugin_manager.analyzer_contributions()
                ],
                "metadata": [
                    {
                        "plugin_id": item.plugin_id,
                        "metadata_id": item.metadata_id,
                        "label": item.label,
                    }
                    for item in self.plugin_manager.metadata_contributions()
                ],
                "settings": [
                    {
                        "plugin_id": item.plugin_id,
                        "field_id": item.field_id,
                        "label": item.label,
                        "section": item.section,
                        "scope": item.scope,
                        "kind": item.kind,
                    }
                    for item in self.plugin_manager.setting_field_contributions()
                ],
            },
        }

    def _plugin_detail_payload(self, plugin_id: str) -> dict[str, object]:
        plugin_id = str(plugin_id).strip()
        plugin = next((item for item in self.plugin_manager.loaded_plugins() if item.plugin_id == plugin_id), None)
        if plugin is None:
            raise MCPError(-32602, f"plugin {plugin_id!r} was not found")
        workspaces = [item for item in self.plugin_manager.workspace_contributions() if item.plugin_id == plugin_id]
        panels = [item for item in self.plugin_manager.panel_contributions() if item.plugin_id == plugin_id]
        exporters = [item for item in self.plugin_manager.exporter_contributions() if item.plugin_id == plugin_id]
        keybindings = [item for item in self.plugin_manager.keybinding_contributions() if item.plugin_id == plugin_id]
        analyzers = [item for item in self.plugin_manager.analyzer_contributions() if item.plugin_id == plugin_id]
        metadata = [item for item in self.plugin_manager.metadata_contributions() if item.plugin_id == plugin_id]
        settings = [item for item in self.plugin_manager.setting_field_contributions() if item.plugin_id == plugin_id]
        return {
            "plugin_id": plugin.plugin_id,
            "name": plugin.name,
            "path": str(plugin.path),
            "has_exporters": bool(exporters),
            "has_analyzers": bool(analyzers),
            "has_metadata_providers": bool(metadata),
            "has_settings": bool(settings),
            "counts": {
                "workspaces": len(workspaces),
                "panels": len(panels),
                "exporters": len(exporters),
                "keybindings": len(keybindings),
                "analyzers": len(analyzers),
                "metadata": len(metadata),
                "settings": len(settings),
            },
            "global_state": self.preferences.plugin_state(plugin_id),
            "project_state": self.store.plugin_state(plugin_id),
            "contributions": {
                "workspaces": [
                    {"workspace_id": item.workspace_id, "label": item.label}
                    for item in workspaces
                ],
                "panels": [
                    {
                        "workspace_id": item.workspace_id,
                        "panel_id": item.panel_id,
                        "title": item.title,
                    }
                    for item in panels
                ],
                "exporters": [
                    {
                        "exporter_id": item.exporter_id,
                        "label": item.label,
                        "style_kind": item.style_kind,
                    }
                    for item in exporters
                ],
                "keybindings": [
                    {"action": item.action, "key": item.key, "section": item.section}
                    for item in keybindings
                ],
                "analyzers": [
                    {"analyzer_id": item.analyzer_id, "label": item.label}
                    for item in analyzers
                ],
                "metadata": [
                    {"metadata_id": item.metadata_id, "label": item.label}
                    for item in metadata
                ],
                "settings": [
                    {
                        "field_id": item.field_id,
                        "label": item.label,
                        "section": item.section,
                        "scope": item.scope,
                        "kind": item.kind,
                    }
                    for item in settings
                ],
            },
        }

    def _flow_payload(self, entry_id: int, *, pretty: bool, max_body_chars: int) -> dict[str, object]:
        entry = self.store.get(entry_id)
        if entry is None:
            raise MCPError(-32602, f"flow {entry_id} was not found")
        request_doc = build_body_document(entry.request.headers, entry.request.body)
        response_doc = build_body_document(entry.response.headers, entry.response.body)
        request_body_text = self._document_text(request_doc, pretty=pretty, max_body_chars=max_body_chars)
        response_body_text = self._document_text(response_doc, pretty=pretty, max_body_chars=max_body_chars)
        return {
            "summary": self._flow_summary(entry),
            "request": {
                "method": entry.request.method,
                "target": entry.request.target,
                "version": entry.request.version,
                "headers": [{"name": name, "value": value} for name, value in entry.request.headers],
                "body": request_body_text,
                "http_text": self._render_request_for_entry(entry),
            },
            "response": {
                "version": entry.response.version,
                "status_code": entry.response.status_code,
                "reason": entry.response.reason,
                "headers": [{"name": name, "value": value} for name, value in entry.response.headers],
                "body": response_body_text,
                "http_text": self._render_response_for_entry(entry),
            },
            "plugin_metadata": entry.plugin_metadata,
            "plugin_findings": entry.plugin_findings,
        }

    def _flow_summary(self, entry) -> dict[str, object]:
        return {
            "id": entry.id,
            "client_addr": entry.client_addr,
            "state": entry.state,
            "method": entry.request.method,
            "host": entry.summary_host,
            "path": entry.summary_path,
            "status_code": entry.response.status_code,
            "reason": entry.response.reason,
            "error": entry.error,
            "request_size": entry.request_size,
            "response_size": entry.response_size,
            "started_at": entry.started_at.isoformat(),
            "finished_at": entry.finished_at.isoformat() if entry.finished_at else None,
            "duration_ms": entry.duration_ms,
            "in_scope": self._entry_in_scope(entry),
        }

    def _analyze_flow_payload(self, entry) -> dict[str, object]:
        request_header_map = self._header_map(entry.request.headers)
        response_header_map = self._header_map(entry.response.headers)
        request_doc = build_body_document(entry.request.headers, entry.request.body)
        response_doc = build_body_document(entry.response.headers, entry.response.body)
        request_query_count = self._query_param_count(entry.request.target or entry.request.path or "")
        request_cookies = self._cookie_names(request_header_map.get("cookie", ""))
        response_set_cookies = self._set_cookie_names(entry.response.headers)
        auth_header = request_header_map.get("authorization", "")
        auth_scheme = auth_header.split(" ", 1)[0] if auth_header else ""
        heuristics_reasons: list[str] = []
        score = 0
        if entry.error:
            heuristics_reasons.append(f"connection/runtime error: {entry.error}")
            score += 3
        if 500 <= (entry.response.status_code or 0) <= 599:
            heuristics_reasons.append(f"server error status {entry.response.status_code}")
            score += 3
        elif 400 <= (entry.response.status_code or 0) <= 499:
            heuristics_reasons.append(f"client error status {entry.response.status_code}")
            score += 1
        if auth_header:
            heuristics_reasons.append(f"authorization header present ({auth_scheme or 'unknown scheme'})")
            score += 2
        if request_cookies:
            heuristics_reasons.append(f"request cookies present ({len(request_cookies)})")
            score += 1
        if response_set_cookies:
            heuristics_reasons.append(f"response sets cookies ({len(response_set_cookies)})")
            score += 1
        finding_count = sum(len(values) for values in entry.plugin_findings.values())
        if finding_count:
            heuristics_reasons.append(f"plugin findings present ({finding_count})")
            score += min(4, finding_count)
        response_text = response_doc.raw_text.lower()
        matched_terms = [term for term in SUSPICIOUS_RESPONSE_TERMS if term in response_text]
        if matched_terms:
            heuristics_reasons.append(f"suspicious response text: {', '.join(matched_terms)}")
            score += min(3, len(matched_terms))
        return {
            "summary": self._flow_summary(entry),
            "request": {
                "content_type": self._content_type(entry.request.headers),
                "body_kind": request_doc.kind,
                "has_body": bool(entry.request.body),
                "has_authorization": bool(auth_header),
                "authorization_scheme": auth_scheme or None,
                "query_parameter_count": request_query_count,
                "cookie_names": request_cookies,
            },
            "response": {
                "status_code": entry.response.status_code,
                "content_type": self._content_type(entry.response.headers),
                "body_kind": response_doc.kind,
                "has_body": bool(entry.response.body),
                "set_cookie_names": response_set_cookies,
            },
            "plugins": {
                "metadata_plugins": sorted(entry.plugin_metadata.keys()),
                "finding_plugins": sorted(entry.plugin_findings.keys()),
                "finding_count": finding_count,
                "findings": entry.plugin_findings,
            },
            "heuristics": {
                "score": score,
                "reasons": heuristics_reasons,
            },
        }

    def _flow_evidence_payload(self, entry_id: int, *, pretty: bool, max_body_chars: int) -> dict[str, object]:
        entry = self._require_entry(entry_id)
        flow = self._flow_payload(entry_id, pretty=pretty, max_body_chars=max_body_chars)
        analysis = self._analyze_flow_payload(entry)
        return {
            "summary": flow["summary"],
            "analysis": analysis,
            "request": {
                "http_text": flow["request"]["http_text"],
                "body": flow["request"]["body"],
            },
            "response": {
                "http_text": flow["response"]["http_text"],
                "body": flow["response"]["body"],
            },
            "plugin_metadata": flow["plugin_metadata"],
            "plugin_findings": flow["plugin_findings"],
        }

    def _entry_in_scope(self, entry) -> bool:
        patterns = self.store.scope_hosts()
        if not patterns:
            return True
        host = TrafficStore._normalize_scope_host(entry.request.host or entry.summary_host)
        includes, excludes = TrafficStore._split_scope_patterns(patterns)
        if includes and not any(TrafficStore._scope_matches(pattern, host) for pattern in includes):
            return False
        if any(TrafficStore._scope_matches(pattern, host) for pattern in excludes):
            return False
        return True

    @staticmethod
    def _rule_to_dict(index: int, rule: MatchReplaceRule) -> dict[str, object]:
        return {
            "index": index,
            "enabled": rule.enabled,
            "scope": rule.scope,
            "mode": rule.mode,
            "match": rule.match,
            "replace": rule.replace,
            "description": rule.description,
        }

    def _require_repeater_session(self, session_id: int) -> MCPRepeaterSession:
        session = self._repeater_sessions.get(session_id)
        if session is None:
            raise MCPError(-32602, f"repeater session {session_id} was not found")
        return session

    def _repeater_session_payload(self, session: MCPRepeaterSession) -> dict[str, object]:
        return {
            "session_id": session.session_id,
            "source_entry_id": session.source_entry_id,
            "request_text": session.request_text,
            "response_text": session.response_text,
            "last_error": session.last_error,
            "last_sent_at": session.last_sent_at.isoformat() if session.last_sent_at else None,
            "history": [
                {
                    "request_text": item.request_text,
                    "response_text": item.response_text,
                    "last_error": item.last_error,
                    "sent_at": item.sent_at.isoformat() if item.sent_at else None,
                }
                for item in session.exchanges
            ],
        }

    def _send_repeater_text(self, raw_request: str) -> str:
        import asyncio

        return asyncio.run(self._repeater_proxy.replay_request(raw_request))

    def _document_text(self, document, *, pretty: bool, max_body_chars: int) -> dict[str, object]:
        chosen = document.pretty_text if pretty and document.pretty_available and document.pretty_text is not None else document.raw_text
        truncated = False
        if len(chosen) > max_body_chars:
            chosen = chosen[:max_body_chars]
            truncated = True
        return {
            "media_type": document.media_type,
            "kind": document.kind,
            "display_name": document.display_name,
            "encoding_summary": document.encoding_summary,
            "pretty_available": document.pretty_available,
            "truncated": truncated,
            "text": chosen,
        }

    def _flow_matches(
        self,
        entry,
        *,
        method: str = "",
        host_contains: str = "",
        text_contains: str = "",
    ) -> bool:
        if method and entry.request.method.upper() != method:
            return False
        if host_contains and host_contains not in entry.summary_host.lower():
            return False
        if text_contains:
            haystack = "\n".join(
                [
                    entry.request.method,
                    entry.summary_host,
                    entry.summary_path,
                    self._render_request_for_entry(entry),
                    self._render_response_for_entry(entry),
                ]
            ).lower()
            if text_contains not in haystack:
                return False
        return True

    def _render_request_for_entry(self, entry) -> str:
        request = ParsedRequest(
            method=entry.request.method,
            target=self._request_target(entry),
            version=entry.request.version,
            headers=list(entry.request.headers),
            body=entry.request.body,
        )
        return render_request_text(request)

    def _render_response_for_entry(self, entry) -> str:
        response = ParsedResponse(
            version=entry.response.version,
            status_code=entry.response.status_code,
            reason=entry.response.reason,
            headers=list(entry.response.headers),
            body=entry.response.body,
            raw=b"",
        )
        return render_response_text(response)

    def _request_target(self, entry) -> str:
        target = entry.request.target
        lowered = target.lower()
        if lowered.startswith(("http://", "https://", "ws://", "wss://")):
            return target
        scheme = "https" if entry.request.port == 443 else "http"
        host = entry.request.host or entry.summary_host
        default_port = 443 if scheme == "https" else 80
        authority = host if entry.request.port == default_port else f"{host}:{entry.request.port}"
        path = entry.request.path or entry.request.target or "/"
        return f"{scheme}://{authority}{path}"

    def _render_export_text(self, export_format: str, source: ExportSource) -> str:
        return self._render_export_payload(export_format, source)["text"]

    def _render_export_payload(self, export_format: str, source: ExportSource) -> dict[str, object]:
        try:
            request = parse_request_text(source.request_text)
        except Exception as exc:
            raise MCPError(
                -32602,
                f"invalid export source request: {exc}",
                {
                    "format": export_format,
                    "source": source.debug_dict(),
                },
            ) from exc
        if request.method.upper() == "CONNECT":
            raise MCPError(-32602, "CONNECT requests are not exportable yet")
        response, response_parse_error = self._parse_export_response(source)
        resolved_entry = self._resolve_entry_for_export_source(source)
        payload = {
            "format": export_format,
            "source": source.debug_dict(),
            "entry_resolved": resolved_entry is not None,
            "request_parsed": True,
            "response_parsed": response is not None,
            "response_parse_error": response_parse_error,
        }
        if export_format.startswith("plugin:"):
            exporter_id = export_format.split(":", 1)[1]
            contribution = next(
                (item for item in self.plugin_manager.exporter_contributions() if item.exporter_id == exporter_id),
                None,
            )
            if contribution is None:
                raise MCPError(-32602, f"unknown plugin exporter: {export_format}")
            context = PluginRenderContext(
                plugin_id=contribution.plugin_id,
                plugin_manager=self.plugin_manager,
                store=self.store,
                entry=resolved_entry,
                request=request,
                response=response,
                export_source=source,
                workspace_id="export",
                panel_id=contribution.exporter_id,
            )
            try:
                rendered = contribution.render(context)
            except Exception as exc:
                raise MCPError(
                    -32603,
                    f"plugin exporter failed: {contribution.plugin_id}:{contribution.exporter_id}: {exc}",
                    {
                        "plugin_id": contribution.plugin_id,
                        "exporter_id": contribution.exporter_id,
                        "entry_resolved": resolved_entry is not None,
                        "source": source.debug_dict(),
                        "response_parse_error": response_parse_error,
                        "mcp_safe_contract": {
                            "export_source_has_entry": False,
                            "recommended_entry_resolution": "Use context.entry first, then resolve context.export_source.entry_id via context.store.get(...).",
                        },
                    },
                ) from exc
            payload.update(
                {
                    "kind": "plugin",
                    "plugin_id": contribution.plugin_id,
                    "exporter_id": contribution.exporter_id,
                    "style_kind": contribution.style_kind,
                    "text": str(rendered),
                }
            )
            return payload
        url = self._export_request_url(request, source)
        headers = self._export_headers(request.headers)
        if export_format == "http_pair":
            payload.update({"kind": "builtin", "style_kind": "http", "text": self._render_http_pair_export(source)})
            return payload
        if export_format == "python_requests":
            payload.update({"kind": "builtin", "style_kind": "python", "text": self._render_python_requests_export(request, url, headers)})
            return payload
        if export_format == "curl_bash":
            payload.update({"kind": "builtin", "style_kind": "shell", "text": self._render_bash_curl_export(request, url, headers)})
            return payload
        if export_format == "curl_windows":
            payload.update({"kind": "builtin", "style_kind": "shell", "text": self._render_windows_curl_export(request, url, headers)})
            return payload
        if export_format == "node_fetch":
            payload.update({"kind": "builtin", "style_kind": "javascript", "text": self._render_node_fetch_export(request, url, headers)})
            return payload
        if export_format == "go_http":
            payload.update({"kind": "builtin", "style_kind": "go", "text": self._render_go_http_export(request, url, headers)})
            return payload
        if export_format == "php_curl":
            payload.update({"kind": "builtin", "style_kind": "php", "text": self._render_php_curl_export(request, url, headers)})
            return payload
        if export_format == "rust_reqwest":
            payload.update({"kind": "builtin", "style_kind": "rust", "text": self._render_rust_reqwest_export(request, url, headers)})
            return payload
        raise MCPError(-32602, f"unknown export format: {export_format}")

    def _render_http_pair_export(self, source: ExportSource) -> str:
        parts = [source.request_text.rstrip()]
        if source.response_text.strip():
            parts.extend(["", source.response_text.rstrip()])
        return "\n".join(parts) + "\n"

    @staticmethod
    def _export_request_url(request: ParsedRequest, source: ExportSource) -> str:
        lowered = request.target.lower()
        if lowered.startswith(("http://", "https://", "ws://", "wss://")):
            return request.target
        host_header = HexProxyMCPServer._find_header_value(request.headers, "Host") or source.host_hint
        if not host_header:
            raise MCPError(-32602, "request is missing a Host header and export source does not provide a host hint")
        host, port = HexProxyMCPServer._split_host_port(host_header, source.port_hint)
        scheme = "https" if port == 443 or source.port_hint == 443 else "http"
        default_port = 443 if scheme == "https" else 80
        authority = host if port == default_port else f"{host}:{port}"
        path = request.target or "/"
        return f"{scheme}://{authority}{path}"

    def _parse_export_response(self, source: ExportSource) -> tuple[ParsedResponse | None, str]:
        if not source.has_response:
            return None, ""
        try:
            return parse_response_text(source.response_text), ""
        except Exception as exc:
            return None, str(exc)

    def _resolve_entry_for_export_source(self, source: ExportSource | None):
        if source is None or source.entry_id is None:
            return None
        return self.store.get(source.entry_id)

    def _resolve_entry_for_context(self, context: PluginRenderContext):
        if context.entry is not None:
            return context.entry
        export_source = getattr(context, "export_source", None)
        if isinstance(export_source, ExportSource):
            return self._resolve_entry_for_export_source(export_source)
        entry_id = getattr(export_source, "entry_id", None)
        if entry_id is None:
            return None
        return context.store.get(int(entry_id))

    @staticmethod
    def _find_header_value(headers, name: str) -> str:
        for header_name, value in headers:
            if header_name.lower() == name.lower():
                return value
        return ""

    @staticmethod
    def _split_host_port(host_header: str, default_port: int) -> tuple[str, int]:
        if host_header.startswith("[") and "]" in host_header:
            host, _, remainder = host_header.partition("]")
            host = f"{host}]"
            if remainder.startswith(":") and remainder[1:].isdigit():
                return host, int(remainder[1:])
            return host, default_port
        if host_header.count(":") == 1:
            host, port_text = host_header.rsplit(":", 1)
            if port_text.isdigit():
                return host, int(port_text)
        return host_header, default_port

    @staticmethod
    def _export_headers(headers) -> list[tuple[str, str]]:
        skipped = {"content-length", "proxy-connection"}
        return [(name, value) for name, value in headers if name.lower() not in skipped]

    @staticmethod
    def _header_map(headers: list[tuple[str, str]]) -> dict[str, str]:
        result: dict[str, str] = {}
        for name, value in headers:
            result[name.lower()] = value
        return result

    @staticmethod
    def _content_type(headers: list[tuple[str, str]]) -> str:
        value = HexProxyMCPServer._find_header_value(headers, "Content-Type")
        return value.split(";", 1)[0].strip().lower()

    @staticmethod
    def _query_param_count(target: str) -> int:
        parsed = urlsplit(target if "://" in target else f"http://placeholder{target}")
        return len(parse_qsl(parsed.query, keep_blank_values=True))

    @staticmethod
    def _cookie_names(cookie_header: str) -> list[str]:
        if not cookie_header:
            return []
        names: list[str] = []
        for part in cookie_header.split(";"):
            if "=" not in part:
                continue
            name, _ = part.split("=", 1)
            normalized = name.strip()
            if normalized:
                names.append(normalized)
        return names

    @staticmethod
    def _set_cookie_names(headers: list[tuple[str, str]]) -> list[str]:
        names: list[str] = []
        for name, value in headers:
            if name.lower() != "set-cookie":
                continue
            cookie_name, _, _ = value.partition("=")
            normalized = cookie_name.strip()
            if normalized:
                names.append(normalized)
        return names

    def _require_entry(self, entry_id: int):
        entry = self.store.get(entry_id)
        if entry is None:
            raise MCPError(-32602, f"flow {entry_id} was not found")
        return entry

    def _render_python_requests_export(self, request: ParsedRequest, url: str, headers) -> str:
        header_lines = ["headers = {"]
        for name, value in headers:
            header_lines.append(f"    {name!r}: {value!r},")
        header_lines.append("}")
        lines = [
            "import requests",
            "",
            *header_lines,
            "",
            f"response = requests.request({request.method!r}, {url!r},",
            "    headers=headers,",
        ]
        if request.body:
            lines.append(f"    data={request.body!r},")
        lines.extend(["    timeout=30,", ")", "", "print(response.status_code)", "print(response.text)"])
        return "\n".join(lines)

    def _render_bash_curl_export(self, request: ParsedRequest, url: str, headers) -> str:
        lines = [f"curl --request {shlex.quote(request.method)} \\", f"  --url {shlex.quote(url)} \\"]
        for name, value in headers:
            lines.append(f"  --header {shlex.quote(f'{name}: {value}')} \\")
        if request.body:
            lines.append(f"  --data-binary {self._bash_ansi_c_quote(request.body)}")
        else:
            lines[-1] = lines[-1].removesuffix(" \\")
        return "\n".join(lines)

    def _render_windows_curl_export(self, request: ParsedRequest, url: str, headers) -> str:
        lines = [f"curl.exe --request {self._powershell_quote(request.method)} `", f"  --url {self._powershell_quote(url)} `"]
        for name, value in headers:
            lines.append(f"  --header {self._powershell_quote(f'{name}: {value}')} `")
        if request.body:
            lines.append(f"  --data-binary {self._powershell_quote(request.body.decode('iso-8859-1', errors='replace'))}")
        else:
            lines[-1] = lines[-1].removesuffix(" `")
        return "\n".join(lines)

    def _render_node_fetch_export(self, request: ParsedRequest, url: str, headers) -> str:
        lines = [
            "const headers = {",
            *(f"  {json.dumps(name)}: {json.dumps(value)}," for name, value in headers),
            "};",
            "",
            "const options = {",
            f"  method: {json.dumps(request.method)},",
            "  headers,",
        ]
        if request.body:
            lines.append(f"  body: {json.dumps(request.body.decode('iso-8859-1', errors='replace'))},")
        lines.extend(["};", "", f"const response = await fetch({json.dumps(url)}, options);", "const text = await response.text();", "console.log(response.status, text);"])
        return "\n".join(lines)

    def _render_go_http_export(self, request: ParsedRequest, url: str, headers) -> str:
        body_reader = "nil"
        body_setup: list[str] = []
        imports = ['    "fmt"', '    "io"', '    "net/http"']
        if request.body:
            imports.append('    "strings"')
            body_setup.append(f"    body := strings.NewReader({json.dumps(request.body.decode('iso-8859-1', errors='replace'))})")
            body_reader = "body"
        lines = [
            "package main",
            "",
            "import (",
            *imports,
            ")",
            "",
            "func main() {",
            *body_setup,
            f"    req, err := http.NewRequest({json.dumps(request.method)}, {json.dumps(url)}, {body_reader})",
            "    if err != nil {",
            '        panic(err)',
            "    }",
        ]
        for name, value in headers:
            lines.append(f"    req.Header.Set({json.dumps(name)}, {json.dumps(value)})")
        lines.extend(["", "    resp, err := http.DefaultClient.Do(req)", "    if err != nil {", "        panic(err)", "    }", "    defer resp.Body.Close()", "", "    payload, _ := io.ReadAll(resp.Body)", '    fmt.Println(resp.StatusCode, string(payload))', "}"])
        return "\n".join(lines)

    def _render_php_curl_export(self, request: ParsedRequest, url: str, headers) -> str:
        header_lines = [f"    {json.dumps(f'{name}: {value}')}" for name, value in headers]
        lines = ["<?php", "", f"$ch = curl_init({json.dumps(url)});", "curl_setopt_array($ch, [", f"    CURLOPT_CUSTOMREQUEST => {json.dumps(request.method)},", "    CURLOPT_RETURNTRANSFER => true,"]
        if header_lines:
            lines.append("    CURLOPT_HTTPHEADER => [")
            lines.extend(f"{line}," for line in header_lines)
            lines.append("    ],")
        if request.body:
            lines.append(f"    CURLOPT_POSTFIELDS => {json.dumps(request.body.decode('iso-8859-1', errors='replace'))},")
        lines.extend([']);', "", "$response = curl_exec($ch);", "echo curl_getinfo($ch, CURLINFO_RESPONSE_CODE), PHP_EOL;", "echo $response, PHP_EOL;", "curl_close($ch);"])
        return "\n".join(lines)

    def _render_rust_reqwest_export(self, request: ParsedRequest, url: str, headers) -> str:
        lines = [
            "use reqwest::Client;",
            "",
            "#[tokio::main]",
            "async fn main() -> Result<(), Box<dyn std::error::Error>> {",
            "    let client = Client::new();",
            f"    let mut request = client.request(reqwest::Method::{request.method.upper()}, {json.dumps(url)});",
        ]
        for name, value in headers:
            lines.append(f"    request = request.header({json.dumps(name)}, {json.dumps(value)});")
        if request.body:
            lines.append(f"    request = request.body({json.dumps(request.body.decode('iso-8859-1', errors='replace'))});")
        lines.extend(["    let response = request.send().await?;", "    let status = response.status();", "    let text = response.text().await?;", '    println!(\"{}\\n{}\", status, text);', "    Ok(())", "}"])
        return "\n".join(lines)

    @staticmethod
    def _bash_ansi_c_quote(body: bytes) -> str:
        escaped = body.decode("unicode_escape", errors="backslashreplace")
        escaped = escaped.replace("\\", "\\\\").replace("'", "\\'")
        return f"$'{escaped}'"

    @staticmethod
    def _powershell_quote(text: str) -> str:
        return "'" + text.replace("'", "''") + "'"

    @staticmethod
    def _json_text(payload: object) -> str:
        return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False)

    @staticmethod
    def _require_dict(value: object) -> dict[str, object]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise MCPError(-32602, "expected a JSON object for params")
        return value

    @staticmethod
    def _error_response(request_id: object, code: int, message: str, data: object | None = None) -> dict[str, object]:
        error: dict[str, object] = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "error": error}

    @staticmethod
    def _read_message(stream) -> dict[str, object] | None:
        content_length: int | None = None
        while True:
            line = stream.readline()
            if not line:
                return None
            if line in {b"\r\n", b"\n"}:
                break
            header = line.decode("ascii", errors="replace").strip()
            if not header:
                continue
            name, _, value = header.partition(":")
            if name.lower() == "content-length":
                content_length = int(value.strip())
        if content_length is None:
            raise MCPError(-32600, "missing Content-Length header")
        body = stream.read(content_length)
        if len(body) != content_length:
            return None
        payload = json.loads(body.decode("utf-8"))
        if not isinstance(payload, dict):
            raise MCPError(-32600, "message body must be a JSON object")
        return payload

    @staticmethod
    def _write_message(stream, payload: dict[str, object]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        stream.write(header)
        stream.write(body)
        stream.flush()

    @staticmethod
    def _plugin_docs_path() -> Path | None:
        docs_path = Path(__file__).resolve().parents[2] / "docs" / "plugin-development.md"
        if docs_path.exists():
            return docs_path
        return None

    @staticmethod
    def _mcp_docs_path() -> Path | None:
        docs_path = Path(__file__).resolve().parents[2] / "docs" / "mcp.md"
        if docs_path.exists():
            return docs_path
        return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Model Context Protocol server for HexProxy projects.")
    parser.add_argument("--project", type=Path, help="HexProxy project file to load.")
    parser.add_argument(
        "--plugin-dir",
        type=Path,
        action="append",
        default=[],
        help="Directory that contains HexProxy plugins.",
    )
    parser.add_argument(
        "--config-file",
        type=Path,
        help="Global configuration file used for persistent application preferences.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    store = TrafficStore()
    preferences = ApplicationPreferences(args.config_file)
    try:
        preferences.load()
    except Exception as exc:
        print(f"hexproxy-mcp: failed to load config: {exc}", file=sys.stderr)
    if args.project is not None:
        if args.project.exists():
            store.load(args.project)
        else:
            store.set_project_path(args.project)
    plugin_manager = PluginManager()
    plugin_manager.load_from_dirs([Path("plugins"), *args.plugin_dir])
    theme_manager = ThemeManager()
    theme_manager.load()
    plugin_manager.bind_runtime(
        store=store,
        preferences=preferences,
        theme_manager=theme_manager,
    )
    server = HexProxyMCPServer(
        store=store,
        plugin_manager=plugin_manager,
        preferences=preferences,
        theme_manager=theme_manager,
    )
    return server.serve()


if __name__ == "__main__":
    raise SystemExit(main())
