# HexProxy Plugin Development

This guide is intended for HexProxy plugin authors.

## Loading Model

- HexProxy auto-loads `*.py` files from `plugins/` if that directory exists.
- You can add more plugin directories with `--plugin-dir path/to/plugins`.
- Files whose name starts with `_` are ignored.

## Minimal Plugin

```python
from hexproxy.proxy import ParsedRequest


class AddHeaderPlugin:
    name = "add-header"

    def before_request_forward(self, context, request: ParsedRequest) -> ParsedRequest:
        request.headers.append(("X-HexProxy-Plugin", self.name))
        return request


def register() -> AddHeaderPlugin:
    return AddHeaderPlugin()
```

HexProxy accepts either:

- `register()` returning a plugin instance
- `PLUGIN` exported as a plugin instance

## Available Hooks

### `on_loaded() -> None`

Optional startup hook called once after the plugin is instantiated.

### `before_request_forward(context, request) -> ParsedRequest`

Called before the request is sent upstream.

Use this hook to:

- add, remove or rewrite headers
- change the target or method
- modify the body

Return the request object you want HexProxy to forward.

### `on_response_received(context, request, response) -> None`

Called after the upstream response is received.

Use this hook to:

- inspect response metadata
- mutate response headers/body in place when needed
- attach information to `context.tags`

### `on_error(context, error) -> None`

Called when HexProxy catches a request-processing error for the active flow.

## Core Types

### `HookContext`

Defined in `src/hexproxy/extensions.py`.

Fields:

- `entry_id: int`
- `client_addr: str`
- `store: TrafficStore`
- `tags: dict[str, str]`

`tags` is a scratch space you can use to keep per-flow plugin state.

### `ParsedRequest`

Defined in `src/hexproxy/proxy.py`.

Fields:

- `method: str`
- `target: str`
- `version: str`
- `headers: list[tuple[str, str]]`
- `body: bytes`

### `ParsedResponse`

Defined in `src/hexproxy/proxy.py`.

Fields:

- `version: str`
- `status_code: int`
- `reason: str`
- `headers: list[tuple[str, str]]`
- `body: bytes`
- `raw: bytes`

## Practical Notes

- Bodies are raw bytes. Decode explicitly if you need text.
- If you rewrite a request body, keep related headers coherent.
- Keep plugins focused; a plugin should usually own one concern.
- Prefer request mutation in `before_request_forward` unless you specifically need response-time behavior.

## Local Development Workflow

1. Create a plugin file inside `plugins/` or another directory passed with `--plugin-dir`.
2. Start HexProxy:

```bash
PYTHONPATH=src python3 -m hexproxy --plugin-dir plugins
```

3. Check the `Settings` workspace inside HexProxy to confirm the plugin loaded or see load errors.

## References

- Example plugin: `examples/add_header_plugin.py`
- Short plugin README: `plugins/README.md`
- Hook protocol and loader: `src/hexproxy/extensions.py`
- Request/response models used by hooks: `src/hexproxy/proxy.py`
