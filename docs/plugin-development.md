# HexProxy Plugin API v2

HexProxy plugins are trusted Python modules loaded from `plugins/` and from every directory passed with `--plugin-dir`.

This API is designed for deep integration. Plugins can:

- modify requests and responses
- persist global and project-scoped state
- create full workspaces
- inject panels into existing workspaces
- add exporters
- register keybindings
- add analyzers
- publish metadata visible in the TUI
- add custom fields to `Settings`

## Loading Model

HexProxy loads every `*.py` file in the configured plugin directories except files whose name starts with `_`.

Supported module entrypoints:

- `register(api)` returning a plugin instance
- `register()` returning a plugin instance
- `PLUGIN` with a plugin instance
- `contribute(api)` for contribution-only modules

Recommended model:

```python
def register(api):
    ...
    return MyPlugin()
```

## Minimal v2 Plugin

```python
from hexproxy.proxy import ParsedRequest


class DemoPlugin:
    plugin_id = "demo"
    name = "demo"

    def before_request_forward(self, context, request: ParsedRequest) -> ParsedRequest:
        request.headers.append(("X-Demo", "enabled"))
        context.set_metadata(self.plugin_id, "mode", "request-rewrite")
        return request


def register(api):
    api.add_workspace(
        "demo_workspace",
        "Demo",
        "Example workspace contributed by a plugin.",
        shortcut="dw",
    )
    api.add_panel(
        "demo_workspace",
        "summary",
        "Summary",
        render_lines=lambda context: [
            "Demo workspace",
            f"Selected flow: #{context.entry.id}" if context.entry else "No flow selected",
        ],
    )
    api.add_exporter(
        "demo_httpie",
        "HTTPie",
        "Generate an HTTPie command.",
        render=lambda context: "http GET https://example.test/",
        style_kind="shell",
    )
    api.add_keybinding(
        "demo_action",
        "dx",
        "Open the demo workspace",
        handler=lambda context: (context.open_workspace("demo_workspace") or True),
        section="Plugin Actions",
    )
    api.add_setting_field(
        "enabled",
        "Demo",
        "Enable Demo",
        "Toggle demo behavior globally.",
        kind="toggle",
        default=True,
    )
    api.add_metadata(
        "demo_meta",
        "Demo Metadata",
        collect=lambda context: {"host": context.entry.summary_host} if context.entry else {},
    )
    api.add_analyzer(
        "demo_analysis",
        "Demo Analyzer",
        analyze=lambda context: ["response body present"] if context.entry and context.entry.response.body else [],
    )
    return DemoPlugin()
```

## Core Types

## `HookContext`

Available inside traffic hooks.

Fields:

- `entry_id`
- `client_addr`
- `store`
- `plugin_manager`
- `tags`
- `metadata`
- `findings`

Useful helpers:

- `set_metadata(plugin_id, key, value)`
- `add_finding(plugin_id, text)`
- `global_state(plugin_id)`
- `set_global_value(plugin_id, key, value)`
- `project_state(plugin_id)`
- `set_project_value(plugin_id, key, value)`

`metadata` and `findings` are persisted into the captured flow and shown in the TUI.

## `PluginRenderContext`

Available inside workspace panels, exporters, analyzers, metadata providers, keybinding handlers and settings callbacks.

Fields:

- `plugin_id`
- `plugin_manager`
- `store`
- `entry`
- `request`
- `response`
- `intercept`
- `export_source`
- `tui`
- `workspace_id`
- `panel_id`

Useful helpers:

- `set_status(message)`
- `open_workspace(workspace_id)`
- `global_state(plugin_id=None)`
- `set_global_value(key, value, plugin_id=None)`
- `project_state(plugin_id=None)`
- `set_project_value(key, value, plugin_id=None)`
- `theme_manager()`

## Traffic Hooks

Optional hooks on the plugin instance:

- `on_loaded()`
- `before_request_forward(context, request)`
- `on_response_received(context, request, response)`
- `on_error(context, error)`

Request/response types come from `hexproxy.proxy`:

- `ParsedRequest`
- `ParsedResponse`

## Contribution API

The object passed to `register(api)` exposes the following methods.

### `api.add_workspace(...)`

Registers a new top-level workspace.

Arguments:

- `workspace_id`
- `label`
- `description=""`
- `order=100`
- `shortcut=""`

Notes:

- `workspace_id` must not collide with built-in workspace ids.
- `shortcut` creates a default keybinding for that workspace.
- A plugin workspace is rendered as a panel menu on the left and the selected panel content on the right.

### `api.add_panel(...)`

Registers a text panel inside a plugin workspace or inside a built-in panel target.

Arguments:

- `workspace_id`
- `panel_id`
- `title`
- `description=""`
- `order=100`
- `render_lines=context -> str | list[str] | dict | list[tuple[str, object]] | None`

Useful built-in panel targets currently supported:

- `overview_detail`
- `http_request`
- `http_response`
- `sitemap_request`
- `sitemap_response`
- `repeater_request`
- `repeater_response`

If `workspace_id` matches a plugin workspace id, the panel appears inside that workspace.

### `api.add_exporter(...)`

Adds a new export format to the `Export` workspace.

Arguments:

- `exporter_id`
- `label`
- `description`
- `render=context -> str`
- `order=100`
- `style_kind=None`

Useful `style_kind` values:

- `http`
- `python`
- `shell`
- `javascript`
- `php`
- `go`
- `rust`

### `api.add_keybinding(...)`

Adds a new configurable keybinding action.

Arguments:

- `action`
- `key`
- `description`
- `handler=context -> bool | None`
- `section="Plugin Actions"`

Rules:

- bindings must be one or two visible characters
- bindings are validated together with built-in bindings
- ambiguous prefixes such as `d` and `dw` are rejected

### `api.add_analyzer(...)`

Adds an analyzer that emits human-readable analysis lines for the selected flow.

Arguments:

- `analyzer_id`
- `label`
- `description=""`
- `order=100`
- `analyze=context -> str | list[str] | None`

Analyzers are currently rendered in the HTTP response workspace and in flow detail views through plugin findings sections.

### `api.add_metadata(...)`

Adds a metadata provider that publishes key/value pairs in the TUI.

Arguments:

- `metadata_id`
- `label`
- `description=""`
- `order=100`
- `collect=context -> dict | list[tuple[str, object]] | None`

Metadata providers are currently rendered in HTTP detail views.

### `api.add_setting_field(...)`

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

Supported kinds:

- `toggle`
- `choice`
- `text`
- `action`

Supported scopes:

- `global`
- `project`

Behavior:

- `toggle`: flips the stored boolean
- `choice`: cycles through `options`
- `text`: prompts inside the TUI
- `action`: executes `on_change` without automatic persistence unless the callback writes state itself

## Built-in Workspace Ids

These ids are reserved:

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

## State Persistence

Plugins have two built-in state stores.

Global state:

- stored in the global HexProxy config file
- use `context.global_state(...)` / `context.set_global_value(...)`
- use `PluginRenderContext` helpers or `HookContext` helpers

Project state:

- stored in the current HexProxy project file
- use `context.project_state(...)` / `context.set_project_value(...)`

## Practical Notes

- Plugins are trusted code. They run in-process and can break the app if they raise exceptions carelessly.
- Use stable ids. Renaming `plugin_id`, workspace ids, field ids or exporter ids changes persistence paths and references.
- Keep UI panels text-first. The current plugin workspace host is optimized for line-based content.
- `HookContext.metadata` and `HookContext.findings` are the cleanest path when you want something visible in the TUI for a captured flow.

## References

- `examples/add_header_plugin.py`
- `plugins/README.md`
- `src/hexproxy/extensions.py`
- `src/hexproxy/proxy.py`
