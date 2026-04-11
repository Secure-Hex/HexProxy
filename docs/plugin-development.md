# HexProxy Plugin Development

This document is a runtime-accurate reference for HexProxy plugins.

It is intentionally implementation-focused. Where the runtime has non-obvious behavior, that behavior is documented explicitly instead of being abstracted away.

## Scope

HexProxy plugins are trusted Python modules loaded in-process. They can:

- rewrite requests before they go upstream
- inspect or mutate responses in place
- persist per-flow metadata and findings
- define workspaces
- inject panels into plugin or built-in workspaces
- add exporters
- register keybindings
- add analyzers
- add metadata providers
- add fields to `Settings`
- store global or project-scoped plugin state

## Loading Model

HexProxy loads `*.py` files from:

- `plugins/` if it exists
- every directory passed with `--plugin-dir`

Loader rules:

- files that start with `_` are ignored
- there is no hot reload
- load order is directory order, then filename order inside each directory
- plugin code is trusted and runs in the HexProxy process

Supported entrypoints:

- `register(api)`
- `register()`
- `PLUGIN`
- `contribute(api)`

Behavioral details from the runtime:

- if `register(api)` or `register()` returns `None`, HexProxy keeps the module object as the plugin instance
- if both module-level `contribute(api)` and plugin-instance `contribute(api)` exist, both are called
- `plugin_id` defaults to the file stem until a plugin instance overrides it
- if a plugin changes `plugin_id`, previously registered contributions are reassigned to the final id

## Minimal Entrypoints

Recommended shape:

```python
def register(api):
    return MyPlugin()
```

Contribution-only module:

```python
def contribute(api):
    api.add_workspace("demo_workspace", "Demo", "Workspace provided by the module.")
```

Legacy-compatible style is still accepted:

```python
PLUGIN = MyPlugin()
```

## Core Runtime Types

## `HookContext`

`HookContext` is passed to traffic hooks.

Fields:

- `entry_id: int`
- `client_addr: str`
- `store: TrafficStore`
- `plugin_manager: PluginManager | None`
- `tags: dict[str, str]`
- `metadata: dict[str, dict[str, str]]`
- `findings: dict[str, list[str]]`

Important:

- `tags` is scratch state for the current hook chain. It is not persisted automatically.
- `metadata` is persisted, but only as strings.
- `findings` is persisted as lists of strings.

Helper methods:

- `set_metadata(plugin_id, key, value)`
- `add_finding(plugin_id, text)`
- `global_state(plugin_id)`
- `set_global_value(plugin_id, key, value)`
- `project_state(plugin_id)`
- `set_project_value(plugin_id, key, value)`

## `PluginRenderContext`

`PluginRenderContext` is passed to:

- workspace panels
- built-in panels
- exporters
- analyzers
- metadata providers
- keybinding handlers
- plugin settings callbacks

Fields:

- `plugin_id: str`
- `plugin_manager: PluginManager`
- `store: TrafficStore`
- `entry: TrafficEntry | None`
- `request: ParsedRequest | None`
- `response: ParsedResponse | None`
- `intercept: PendingInterceptionView | None`
- `export_source: object | None`
- `tui: object | None`
- `workspace_id: str`
- `panel_id: str`

Helper methods:

- `set_status(message)`
- `open_workspace(workspace_id)`
- `global_state(plugin_id=None)`
- `set_global_value(key, value, plugin_id=None)`
- `project_state(plugin_id=None)`
- `set_project_value(key, value, plugin_id=None)`
- `theme_manager()`

## Stable vs defensive fields

Use these as stable:

- `plugin_id`
- `plugin_manager`
- `store`
- `workspace_id`
- `panel_id`

Treat these as optional:

- `entry`
- `request`
- `response`
- `intercept`
- `tui`

Treat this as dynamic and loosely typed:

- `export_source`

`export_source` is typed as `object | None`. There is no strong public contract that guarantees attributes like `.entry`, `.request`, or `.response`.

Use this pattern:

1. Prefer `context.entry` if it exists.
2. If you must inspect `export_source`, treat it defensively with `getattr(...)`.
3. If `export_source` provides an `entry_id`, resolve the real flow through `context.store`.

Incorrect:

```python
entry = context.export_source.entry
```

Safer:

```python
entry = context.entry
if entry is None:
    export_source = getattr(context, "export_source", None)
    entry_id = getattr(export_source, "entry_id", None)
    if entry_id is not None:
        entry = context.store.get(entry_id)
```

## Request and Response Types

`ParsedRequest` fields:

- `method`
- `target`
- `version`
- `headers`
- `body`

`ParsedResponse` fields:

- `version`
- `status_code`
- `reason`
- `headers`
- `body`
- `raw`

Bodies are raw bytes. Decode explicitly if you need text.

## Traffic Hooks

Optional hooks on the plugin instance:

- `on_loaded()`
- `before_request_forward(context, request)`
- `on_response_received(context, request, response)`
- `on_error(context, error)`

## Hook behavior table

| Hook | Called when | Input | Return value | Can transform traffic | Notes |
| --- | --- | --- | --- | --- | --- |
| `on_loaded()` | after plugin load | none | ignored | no | startup-only |
| `before_request_forward(...)` | after request interception, before upstream | `HookContext`, `ParsedRequest` | `ParsedRequest` or `None` | yes | return a request to replace the current one; `None` leaves current request unchanged |
| `on_response_received(...)` | after upstream response is read, before response match/replace | `HookContext`, `ParsedRequest`, `ParsedResponse` | ignored | yes, in place | no returned response is consumed, but mutating the `response` object in place affects downstream processing |
| `on_error(...)` | when HexProxy catches a processing error for the flow | `HookContext`, `Exception` | ignored | no | useful for tagging, findings and diagnostics |

## Actual request/response pipeline

HTTP and HTTPS traffic follow this order:

1. request is parsed
2. request interceptor may pause and edit it
3. `before_request_forward(...)`
4. request-side Match/Replace
5. upstream request
6. upstream response
7. `on_response_received(...)`
8. plugin metadata/findings are persisted
9. response-side Match/Replace
10. response interceptor may pause and edit it
11. response is delivered to the client

Practical consequence:

- request hooks see the post-interceptor request
- response hooks run before response-side Match/Replace and before response interception

## Contribution API

`register(api)` receives a `PluginAPI`.

## `api.add_workspace(...)`

Registers a new top-level workspace.

Arguments:

- `workspace_id`
- `label`
- `description=""`
- `order=100`
- `shortcut=""`

Notes:

- `workspace_id` must be unique
- it must not collide with built-in workspace ids
- `shortcut` becomes the default keybinding for that workspace
- plugin workspaces are line-oriented: left panel menu, right panel detail

Built-in workspace ids reserved by HexProxy:

- `overview`
- `intercept`
- `repeater`
- `sitemap`
- `match_replace`
- `http`
- `export`
- `settings`
- `scope`
- `filters`
- `keybindings`
- `rule_builder`
- `theme_builder`

## `api.add_panel(...)`

Registers a panel either:

- inside a plugin workspace
- or against a built-in panel target

Arguments:

- `workspace_id`
- `panel_id`
- `title`
- `description=""`
- `order=100`
- `render_lines=context -> str | list[str] | dict | list[tuple[str, object]] | None`

Supported built-in panel targets today:

- `overview_detail`
- `http_request`
- `http_response`
- `sitemap_request`
- `sitemap_response`
- `repeater_request`
- `repeater_response`

If you target a built-in panel id that HexProxy does not render, registration still succeeds, but the panel will not appear anywhere.

## `api.add_exporter(...)`

Adds a format to the `Export` workspace.

Arguments:

- `exporter_id`
- `label`
- `description`
- `render=context -> str`
- `order=100`
- `style_kind=None`

Supported `style_kind` values used by the built-in renderer:

- `http`
- `python`
- `shell`
- `javascript`
- `php`
- `go`
- `rust`

## `api.add_keybinding(...)`

Adds a configurable action to the global keybinding set.

Arguments:

- `action`
- `key`
- `description`
- `handler=context -> bool | None`
- `section="Plugin Actions"`

Rules enforced by the runtime:

- keybindings must be one or two visible characters
- whitespace is rejected
- duplicate bindings are rejected
- ambiguous prefixes are rejected
  Example: `d` and `dw` cannot coexist

Two-key bindings are consumed before navigation if the first key matches a configured sequence prefix.

## `api.add_analyzer(...)`

Adds an analyzer contribution.

Arguments:

- `analyzer_id`
- `label`
- `description=""`
- `order=100`
- `analyze=context -> str | list[str] | None`

## `api.add_metadata(...)`

Adds a metadata provider.

Arguments:

- `metadata_id`
- `label`
- `description=""`
- `order=100`
- `collect=context -> dict | list[tuple[str, object]] | None`

## `api.add_setting_field(...)`

Adds a field to `Settings`.

Arguments:

- `field_id`
- `section`
- `label`
- `description`
- `kind`
- `scope="global"`
- `default=None`
- `options=None`
- `placeholder=""`
- `action_label="Run"`
- `on_change=context, value -> object | None`

Supported `kind` values:

- `toggle`
- `choice`
- `text`
- `action`

Supported `scope` values:

- `global`
- `project`

Actual behavior:

- `toggle` flips the stored boolean
- `choice` cycles through the configured options
- `text` prompts inside the TUI and stores the entered string
- `action` invokes the callback but does not auto-persist unless the callback writes state itself

## Metadata persistence

This is the most important runtime caveat in the plugin system.

`HookContext.metadata` is:

```python
dict[str, dict[str, str]]
```

And `HookContext.set_metadata(...)` does this:

```python
bucket[field_name] = str(value)
```

That means:

- every persisted metadata value becomes a string
- dicts do not stay dicts
- lists do not stay lists
- numbers and booleans also become strings

Incorrect:

```python
context.set_metadata(self.plugin_id, "summary", {"count": 2, "alg": "HS256"})
context.set_metadata(self.plugin_id, "details", [{"sub": "alice"}])
```

What gets stored is effectively:

```python
{
    "my_plugin": {
        "summary": "{'count': 2, 'alg': 'HS256'}",
        "details": "[{'sub': 'alice'}]",
    }
}
```

That is not safe to consume structurally.

Recommended pattern:

```python
import json

context.set_metadata(self.plugin_id, "summary", json.dumps(summary))
context.set_metadata(self.plugin_id, "details", json.dumps(details))
```

And when reading:

```python
import json

bucket = entry.plugin_metadata.get("my_plugin", {})
summary = json.loads(bucket.get("summary", "{}"))
details = json.loads(bucket.get("details", "[]"))
```

This is the official safe pattern for structured metadata.

## Structure of `entry.plugin_metadata`

Persisted metadata is grouped by `plugin_id`.

Shape:

```python
{
    "plugin_id": {
        "field_a": "value-as-string",
        "field_b": "value-as-string"
    }
}
```

Example:

```python
{
    "jwt_inspector": {
        "count": "2",
        "summary": "{\"count\": 2, \"issues\": 1}",
        "details": "[{\"source\": \"request\", \"payload\": {\"sub\": \"alice\"}}]"
    },
    "add_header": {
        "header": "X-HexProxy-Plugin"
    }
}
```

Multiple calls to `set_metadata(...)` for the same plugin merge into the same bucket by key:

```python
context.set_metadata("demo", "a", "1")
context.set_metadata("demo", "b", "2")
```

Final persisted shape:

```python
{
    "demo": {
        "a": "1",
        "b": "2"
    }
}
```

If the same key is written twice, the latest value wins.

## Findings persistence

`add_finding(...)` appends strings to a per-plugin list.

Shape:

```python
{
    "plugin_id": [
        "finding one",
        "finding two"
    ]
}
```

Findings are safer than metadata for human-readable diagnostics because they do not require further decoding.

## Reading and writing plugin settings

Declare a setting:

```python
def register(api):
    api.add_setting_field(
        "enabled",
        "JWT Inspector",
        "Enable JWT Inspector",
        "Toggle whether JWT inspection is active.",
        kind="toggle",
        scope="global",
        default=True,
    )
```

Read it in a hook:

```python
class JwtInspectorPlugin:
    plugin_id = "jwt_inspector"

    def before_request_forward(self, context, request):
        enabled = bool(context.global_state(self.plugin_id).get("enabled", True))
        if not enabled:
            return request
        ...
        return request
```

Read a single value directly:

```python
enabled = context.global_state(self.plugin_id).get("enabled", True)
```

Or through render context:

```python
enabled = context.global_state().get("enabled", True)
mode = context.project_state().get("analysis_mode", "strict")
```

Write a global value:

```python
context.set_global_value(self.plugin_id, "enabled", False)
```

Write a project-scoped value:

```python
context.set_project_value(self.plugin_id, "analysis_mode", "strict")
```

## Complete plugin example

This example combines:

- request hook
- response hook
- JSON-safe metadata
- findings
- workspace panel
- built-in panel
- exporter
- `enabled` setting
- safe metadata reads

```python
from __future__ import annotations

import json
from hexproxy.proxy import ParsedRequest


class ExampleInspector:
    plugin_id = "example_inspector"
    name = "example-inspector"

    def before_request_forward(self, context, request: ParsedRequest) -> ParsedRequest:
        enabled = bool(context.global_state(self.plugin_id).get("enabled", True))
        if not enabled:
            return request

        summary = {
            "host": self._header_value(request.headers, "host"),
            "method": request.method,
        }
        context.set_metadata(self.plugin_id, "summary", json.dumps(summary))
        context.add_finding(self.plugin_id, f"Observed request to {summary['host']}")
        return request

    def on_response_received(self, context, request, response) -> None:
        enabled = bool(context.global_state(self.plugin_id).get("enabled", True))
        if not enabled:
            return
        context.set_metadata(self.plugin_id, "status", response.status_code)

    @staticmethod
    def _header_value(headers, name):
        lowered = name.lower()
        for header_name, header_value in headers:
            if header_name.lower() == lowered:
                return header_value
        return ""


def render_workspace(context):
    entry = context.entry
    if entry is None:
        return ["Example Inspector", "", "No selected flow."]
    bucket = entry.plugin_metadata.get("example_inspector", {})
    summary = json.loads(bucket.get("summary", "{}"))
    return [
        "Example Inspector",
        "",
        f"Host: {summary.get('host', '-')}",
        f"Method: {summary.get('method', '-')}",
        f"Status: {bucket.get('status', '-')}",
    ]


def render_http_panel(context):
    entry = context.entry
    if entry is None:
        return ["No flow selected."]
    bucket = entry.plugin_metadata.get("example_inspector", {})
    if not bucket:
        return ["No Example Inspector metadata for this flow."]
    summary = json.loads(bucket.get("summary", "{}"))
    return [
        f"Observed host: {summary.get('host', '-')}",
        f"Observed method: {summary.get('method', '-')}",
    ]


def render_export(context):
    entry = context.entry
    if entry is None:
        export_source = getattr(context, "export_source", None)
        entry_id = getattr(export_source, "entry_id", None)
        if entry_id is not None:
            entry = context.store.get(entry_id)
    if entry is None:
        return "No flow available."
    bucket = entry.plugin_metadata.get("example_inspector", {})
    return json.dumps(bucket, indent=2, ensure_ascii=False)


def register(api):
    api.add_workspace(
        "example_inspector_workspace",
        "Example Inspector",
        "Example plugin workspace.",
        shortcut="ei",
    )
    api.add_panel(
        "example_inspector_workspace",
        "summary",
        "Summary",
        render_lines=render_workspace,
    )
    api.add_panel(
        "http_response",
        "example_inspector_http",
        "Example Inspector",
        render_lines=render_http_panel,
    )
    api.add_exporter(
        "example_inspector_json",
        "Example Inspector JSON",
        "Export persisted plugin metadata as JSON.",
        render=render_export,
    )
    api.add_setting_field(
        "enabled",
        "Example Inspector",
        "Enable Example Inspector",
        "Toggle inspection globally.",
        kind="toggle",
        scope="global",
        default=True,
    )
    return ExampleInspector()
```

## Common pitfalls

### `Plugin render error: 'str' object has no attribute 'get'`

Cause:

- structured metadata was written with `set_metadata(...)` without `json.dumps(...)`

Fix:

- serialize complex metadata explicitly with JSON
- deserialize with `json.loads(...)` on read

### Exporters fail because they assume `context.export_source.entry`

Cause:

- `export_source` is not a strongly typed contract

Fix:

- prefer `context.entry`
- fall back to `entry_id` + `context.store.get(...)`
- always use `getattr(...)` when touching `export_source`

### Metadata exists, but panel is empty

Cause:

- the selected flow has no data for that plugin
- or the panel assumes a shape that was never persisted

Fix:

- guard with `if not bucket: return ["No plugin metadata for this flow."]`

### Assuming store internals

Cause:

- a plugin reaches into private store attributes or undocumented helper names

Fix:

- prefer public helpers like `store.get(...)`, `project_state(...)`, `global_state(...)`
- treat anything private or inferred as unstable

### Assuming `on_response_received(...)` can return a replacement object

Cause:

- the hook returns a value expecting the runtime to consume it

Fix:

- do not rely on a returned response
- if you need changes to persist, mutate the `response` object in place

## Debugging patterns

Inspect persisted metadata in a renderer:

```python
def render_panel(context):
    entry = context.entry
    if entry is None:
        return ["No flow selected."]
    return [
        "Metadata debug",
        json.dumps(entry.plugin_metadata, indent=2, ensure_ascii=False),
    ]
```

Verify that a hook ran:

```python
def before_request_forward(self, context, request):
    context.add_finding(self.plugin_id, "before_request_forward executed")
    return request
```

Debug an exporter safely:

```python
def render_export(context):
    export_source = getattr(context, "export_source", None)
    return json.dumps(
        {
            "has_entry": context.entry is not None,
            "export_source_type": type(export_source).__name__ if export_source else None,
            "entry_id": getattr(export_source, "entry_id", None),
        },
        indent=2,
    )
```

Inspect the shape of the selected entry:

```python
def render_panel(context):
    entry = context.entry
    if entry is None:
        return ["No entry."]
    return [
        f"id={entry.id}",
        f"metadata_keys={list(entry.plugin_metadata.keys())}",
        f"finding_keys={list(entry.plugin_findings.keys())}",
    ]
```

## Behavioral Notes

- Plugin metadata persistence is string-only. This is the main trap in the current runtime.
- `export_source` is intentionally loose. Treat it defensively.
- There is no unload, no hot reload and no plugin sandbox.
- `register(api)` and `contribute(api)` can both run for the same module.
- If multiple contributions register the same id, the latest one replaces the earlier one.
- A panel can be registered successfully for a workspace target that HexProxy does not currently render. Registration does not imply visibility.
- Settings callbacks of kind `action` do not persist automatically unless they explicitly write through project/global state helpers.
- `on_response_received(...)` is not a pure observer in practice because in-place mutation of the response object affects later stages.

## References

- `src/hexproxy/extensions.py`
- `src/hexproxy/proxy.py`
- `src/hexproxy/store.py`
- `examples/add_header_plugin.py`
- `plugins/jwt_inspector.py`
