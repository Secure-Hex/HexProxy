# HexProxy Plugins

HexProxy loads Python plugins from:

- `plugins/`
- every extra directory passed with `--plugin-dir`

Loader rules:

- only `*.py` files are loaded
- files that start with `_` are ignored
- supported entrypoints are `register(api)`, `register()`, `PLUGIN`, or `contribute(api)`

Minimal startup example:

```bash
PYTHONPATH=src python3 -m hexproxy --plugin-dir plugins
```

What plugins can do in API v2:

- rewrite requests and responses
- create workspaces
- inject panels into built-in workspaces
- add exporters
- add configurable keybindings
- publish analyzers and metadata in the TUI
- add new fields to `Settings`
- persist global and project-scoped plugin state

Recommended starting point:

- copy `examples/add_header_plugin.py`
- adjust `plugin_id`
- add one workspace or one exporter first

Detailed reference:

- `docs/plugin-development.md`

Important runtime note:

- plugin metadata persisted through `HookContext.set_metadata(...)` is stored as strings
- if you need structured metadata, write it with `json.dumps(...)` and read it back with `json.loads(...)`
