# HexProxy MCP

`hexproxy-mcp` exposes HexProxy projects and operational controls over the Model Context Protocol (MCP) using stdio transport.

It is designed so an LLM client can work with HexProxy data and state without going through the curses TUI.

## What It Can Control

The MCP covers the underlying operational state of HexProxy, including:

- project inspection
- flow listing, search and full flow retrieval
- export rendering, including plugin exporters
- scope management
- view filter management
- interception queue management
- Match/Replace rule management
- repeater session creation, editing and sending
- plugin inventory inspection
- plugin global and project state
- global keybindings
- global theme selection
- project saving

This is meant to let an MCP client operate HexProxy at roughly the same level as a user, but programmatically.

## Launch

Start it against a project file:

```bash
hexproxy-mcp --project projects/demo.hexproxy.json
```

Load extra plugins the same way as the main app:

```bash
hexproxy-mcp --project projects/demo.hexproxy.json --plugin-dir plugins
```

Options:

- `--project`: HexProxy project file to load
- `--plugin-dir`: additional plugin directory; repeatable
- `--config-file`: alternate global HexProxy config path

## Transport

The server uses stdio with MCP JSON-RPC framing via `Content-Length`.

Implemented protocol surface:

- `initialize`
- `ping`
- `tools/list`
- `tools/call`
- `resources/list`
- `resources/read`
- `prompts/list`
- `logging/setLevel`
- `notifications/initialized`

## Resources

Always available:

- `hexproxy://project/info`
- `hexproxy://plugins/summary`
- `hexproxy://docs/mcp`

Conditionally available:

- `hexproxy://docs/plugin-development`
  Only when the plugin guide exists on disk in the local checkout/package layout.

Per visible flow:

- `hexproxy://flows/<entry_id>`
- `hexproxy://flows/<entry_id>/evidence`

Per loaded plugin:

- `hexproxy://plugins/<plugin_id>`

## Tools

### `project_info`

Returns:

- project path
- total and visible flow counts
- current scope
- current view filters
- current intercept mode
- plugin count and plugin directories
- current global theme
- current MCP repeater session count

### `list_flows`

Arguments:

- `offset`
- `limit`
- `only_visible`
- `method`
- `host_contains`
- `text_contains`

Returns summarized flows with:

- id
- state
- method
- host
- path
- status
- error
- timestamps
- sizes
- `in_scope`

### `search_flows`

Arguments:

- `query`
- `limit`

Searches across:

- method
- host
- path
- rendered request text
- rendered response text

### `get_flow`

Arguments:

- `entry_id`
- `pretty`
- `max_body_chars`

Returns:

- flow summary
- request headers and rendered HTTP text
- response headers and rendered HTTP text
- decoded request body metadata and text
- decoded response body metadata and text
- plugin metadata
- plugin findings

Body rendering uses the same decoding path as the rest of HexProxy:

- chunked decoding
- content-encoding decoding when possible
- content-type detection
- optional pretty rendering when available

### `list_exporters`

Returns both built-in and plugin exporters.

Built-in formats currently exposed:

- `http_pair`
- `python_requests`
- `curl_bash`
- `curl_windows`
- `node_fetch`
- `go_http`
- `php_curl`
- `rust_reqwest`

### `render_export`

Arguments:

- `entry_id`
- `format`

Supports both built-in formats and plugin exporters using `plugin:<exporter_id>`.

The result now includes exporter metadata in addition to the rendered text, including:

- `kind`
- `style_kind`
- `entry_resolved`
- `request_parsed`
- `response_parsed`
- `response_parse_error`
- `source`

## Exporter Contract In MCP

Plugin exporters executed through MCP receive a normal `PluginRenderContext`, but with one important runtime caveat:

- `context.export_source` is lightweight
- it does not expose `.entry`
- it only provides stable export-source fields such as:
  - `label`
  - `request_text`
  - `response_text`
  - `entry_id`
  - `host_hint`
  - `port_hint`
  - `response_parse_error`

MCP-safe exporter pattern:

1. Prefer `context.entry` when available.
2. If `context.entry` is `None`, resolve the flow using `context.export_source.entry_id` and `context.store.get(...)`.
3. Do not assume `context.export_source.entry` exists.

Important:

- MCP does not render plugin workspaces or plugin panels.
- MCP executes plugin exporters and exposes plugin state/metadata, but not plugin UI.
- Exporters intended for MCP should be defensive about unresolved responses and unresolved flows.

If a plugin exporter fails during MCP execution, HexProxy returns a structured MCP error including:

- `plugin_id`
- `exporter_id`
- `entry_resolved`
- `source`
- `response_parse_error`
- an MCP-specific contract hint

### `list_plugins`

Returns:

- loaded plugins
- configured plugin directories
- load errors
- per-plugin summaries
- contributed workspaces
- panels
- exporters
- keybindings
- analyzers
- metadata providers
- settings fields

Each plugin summary also includes:

- contribution counts
- whether it has exporters
- whether it has analyzers
- whether it has metadata providers
- whether it has settings
- current global plugin state
- current project plugin state

### `set_intercept_mode`

Arguments:

- `mode`

Sets the current intercept mode to:

- `off`
- `request`
- `response`
- `both`

### `list_interceptions`

Returns interception history with:

- `record_id`
- `entry_id`
- `phase`
- `decision`
- `active`
- timestamps
- raw HTTP text

### `update_interception`

Arguments:

- `record_id`
- `raw_text`

Validates the edited request/response text before storing it back into the pending interception record.

### `resolve_interception`

Arguments:

- `record_id`
- `decision`: `forward` or `drop`

Important runtime note:

- this signals the waiting proxy flow
- a record is only marked inactive after the waiting runtime consumes it

### `list_match_replace_rules`

Returns every Match/Replace rule with its index.

### `upsert_match_replace_rule`

Arguments:

- optional `index`
- `enabled`
- `scope`
- `mode`
- `match`
- `replace`
- `description`

Behavior:

- without `index`, appends a new rule
- with `index`, replaces the existing rule at that position

### `delete_match_replace_rule`

Arguments:

- `index`

Deletes one rule by index.

### `list_repeater_sessions`

Returns all in-memory MCP repeater sessions and their send history.

### `create_repeater_session`

Arguments:

- `entry_id`
- or `request_text`

Behavior:

- if `entry_id` is provided, the request is built from the selected captured flow
- if `request_text` is provided, it is validated and stored as the new repeater draft

### `get_repeater_session`

Arguments:

- `session_id`

Returns:

- current request draft
- last response
- last error
- last sent timestamp
- full exchange history

### `update_repeater_request`

Arguments:

- `session_id`
- `request_text`

Validates and replaces the current repeater draft.

### `send_repeater_request`

Arguments:

- `session_id`

Behavior:

- sends the current draft using the same replay path used by HexProxy repeater logic
- appends the result to the session history
- preserves errors per exchange

Limitations:

- `CONNECT` is not supported
- WebSocket upgrade requests are not supported

### `list_keybindings`

Returns the current global keybindings.

### `set_keybinding`

Arguments:

- `action`
- `key`

Validation matches the application runtime:

- one or two visible characters
- no duplicate bindings
- no ambiguous prefixes

### `list_themes`

Returns:

- current theme
- all loaded themes
- theme description
- theme source
- resolved color roles

### `set_theme`

Arguments:

- `theme`

Sets the global theme in the HexProxy config.

### `get_plugin_state`

Arguments:

- `plugin_id`
- `scope`: `global` or `project`

Returns the stored plugin state bucket for that scope.

### `set_plugin_state`

Arguments:

- `plugin_id`
- `scope`: `global` or `project`
- `values`

Behavior:

- merges provided values into the existing bucket
- persists to the HexProxy config for `global`
- persists to the loaded project for `project`

### `set_scope`

Arguments:

- `patterns`

Replaces the current scope pattern list.

### `add_scope_patterns`

Arguments:

- `patterns`

Appends new patterns while preserving the current scope list.

### `remove_scope_patterns`

Arguments:

- `patterns`

Removes normalized patterns from the current scope.

Patterns follow the same rules as the TUI:

- `example.com`
- `*.example.com`
- `!test.example.com`
- `*`

### `set_view_filters`

Accepted fields:

- `show_out_of_scope`
- `query_mode`
- `failure_mode`
- `body_mode`
- `methods`
- `hidden_methods`
- `hidden_extensions`

Omitted fields preserve their current values.

### `analyze_flow`

Arguments:

- `entry_id`

Returns a structured analysis layer on top of a captured flow, including:

- request content type
- request body kind
- authorization presence and scheme
- cookie names
- query parameter count
- response content type
- response body kind
- response set-cookie names
- plugin metadata/findings summary
- heuristic score and reasons

This is intended for LLM-assisted triage, not as a definitive vulnerability engine.

### `list_suspicious_flows`

Arguments:

- `limit`
- `only_visible`

Returns flows ranked by heuristic interest using currently available runtime data such as:

- `4xx` / `5xx`
- connection/runtime errors
- authorization headers
- cookies or `Set-Cookie`
- plugin findings
- suspicious response text markers

### `flow_evidence_bundle`

Arguments:

- `entry_id`
- `pretty`
- `max_body_chars`

Returns a compact evidence-oriented bundle containing:

- flow summary
- request HTTP text
- response HTTP text
- decoded request body excerpt
- decoded response body excerpt
- plugin metadata
- plugin findings
- structured analysis

### `save_project`

Arguments:

- optional `path`

Writes the current project to disk.

## Practical Notes

- The MCP does not render or drive the curses UI directly. It drives the same underlying state and behaviors.
- Repeater sessions created through the MCP are separate from in-memory TUI repeater sessions.
- Plugin exporters are executed through the same contribution mechanism used by the main app.
- Plugin panels and workspace renderers are not directly rendered by the MCP, but their metadata and state remain available through flows, plugin state and exporter integration.
- If a plugin exporter assumes undocumented fields on `export_source`, it can still fail. The MCP passes a lightweight export source object and explicitly does not provide `export_source.entry`.
- `render_export` resolves `context.entry` when possible before calling plugin exporters. Exporters should still code defensively.
- `response_parse_error` can be populated when a source includes a response text that cannot be parsed as HTTP.

## Recommended Use Cases

- give an LLM structured access to captured traffic
- let an LLM search and summarize flows
- let an LLM build evidence from selected flows
- let an LLM operate repeater programmatically
- let an LLM manage scope and filtering before analysis
- let an LLM inspect plugin inventory and plugin state
