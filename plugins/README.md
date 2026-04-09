# HexProxy Plugins

Cada archivo `*.py` dentro de esta carpeta se carga automaticamente al iniciar HexProxy.

Requisitos minimos:

- Exportar una funcion `register()` que devuelva una instancia de plugin
- Implementar `name`
- Opcionalmente implementar hooks como `before_request_forward`, `on_response_received` y `on_error`

Ejecutar:

```bash
PYTHONPATH=src python3 -m hexproxy --plugin-dir plugins
```

Hooks disponibles:

- `before_request_forward(context, request) -> request`
- `on_response_received(context, request, response) -> None`
- `on_error(context, error) -> None`

El hook mas util para extensiones iniciales es `before_request_forward`, porque permite modificar headers, path, body o metodos antes de salir al upstream.

Para una guia mas completa sobre la API de plugins, tipos disponibles y flujo de carga, revisa `docs/plugin-development.md` o abre `Settings` dentro de HexProxy.
