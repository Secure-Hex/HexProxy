# HexProxy

HexProxy es un proxy HTTP de interceptacion pensado para trabajar 100% en terminal. Esta primera version se enfoca en:

- Proxy HTTP funcional
- Captura de requests y responses
- Visualizacion en tiempo real en una TUI basada en `curses`
- Persistencia de proyecto para guardar sesiones y reabrirlas despues
- Interceptacion de requests con edicion antes de reenviar
- Sistema de extensiones en Python para terceros
- Sin dependencias externas

## Estado actual

El alcance de esta version inicial es deliberadamente acotado:

- Soporta trafico HTTP plano
- No implementa `CONNECT` ni HTTPS todavia
- Procesa una transaccion por conexion y fuerza `Connection: close` para simplificar el flujo

## Ejecutar

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
hexproxy --listen-port 8080
```

Tambien puedes ejecutar el modulo directamente:

```bash
PYTHONPATH=src python3 -m hexproxy --listen-port 8080
```

## Opciones CLI

- `--listen-host`: interfaz donde escucha el proxy
- `--listen-port`: puerto del proxy
- `--project`: archivo de proyecto para autosave y reapertura de sesiones
- `--plugin-dir`: directorio extra de plugins; puede repetirse varias veces

## Extensiones

HexProxy carga automaticamente extensiones Python desde la carpeta local `plugins/` si existe. Tambien puede cargar directorios extra usando `--plugin-dir`.

```bash
PYTHONPATH=src python3 -m hexproxy --plugin-dir plugins
```

Reglas:

- Cada extension es un archivo `*.py`
- Debe exportar `register()`
- `register()` debe devolver una instancia con `name`
- El hook principal es `before_request_forward(context, request)`

Ejemplo minimo:

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

Hay un ejemplo completo en [`examples/add_header_plugin.py`](/home/ifysec/hexproxy/examples/add_header_plugin.py) y una guia corta en [`plugins/README.md`](/home/ifysec/hexproxy/plugins/README.md).

## Guardar y reabrir proyectos

Si quieres que el trafico quede guardado en disco, inicia HexProxy con `--project`:

```bash
hexproxy --listen-port 8080 --project projects/demo.hexproxy.json
```

Comportamiento:

- Si el archivo existe, se carga al iniciar
- Si no existe, se crea un proyecto vacio
- Cada cambio en el trafico se guarda automaticamente
- Tambien puedes forzar guardado manual con `s` en la TUI
- Si presionas `s` sin haber iniciado con `--project`, la TUI pide un nombre o ruta y crea el proyecto en ese momento

## Interceptar y modificar requests

Desde la TUI puedes activar la interceptacion de requests:

- `i`: activar o desactivar `Intercept`
- `Tab`: cambiar a la pestaña `Intercept`
- `e`: editar el request crudo del flujo interceptado usando tu `$EDITOR`
- `a`: reenviar el request interceptado
- `x`: descartar el request interceptado

Notas:

- Si `EDITOR` no esta definido, HexProxy usa `vi`
- La edicion valida el request antes de liberarlo
- El proxy pausa el flujo hasta que lo reenvies o descartes
- `e`, `a` y `x` solo aplican cuando el flujo seleccionado esta pausado en el interceptor

## Probar con curl

```bash
curl -x http://127.0.0.1:8080 http://example.com/
```

## Controles TUI

- `↑` / `↓`: mover seleccion
- `j` / `k`: mover seleccion
- `Tab`: cambiar panel de detalle
- `i`: activar/desactivar interceptacion
- `e`: editar request interceptado cuando haya un flujo pausado
- `a`: reenviar request interceptado cuando haya un flujo pausado
- `x`: descartar request interceptado cuando haya un flujo pausado
- `s`: guardar proyecto manualmente
- `q`: salir

## Estructura

```text
src/hexproxy/
  app.py
  proxy.py
  store.py
  tui.py
  models.py
```

## Siguientes pasos

- Interceptacion editable de responses
- Filtros y busqueda
- Exportacion de trafico
- Soporte HTTPS via `CONNECT` + CA local
