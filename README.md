# HexProxy

HexProxy es un proxy HTTP de interceptacion pensado para trabajar 100% en terminal. Esta primera version se enfoca en:

- Proxy HTTP funcional
- Captura de requests y responses
- Visualizacion en tiempo real en una TUI basada en `curses`
- Persistencia de proyecto para guardar sesiones y reabrirlas despues
- Interceptacion de requests con edicion antes de reenviar
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

## Probar con curl

```bash
curl -x http://127.0.0.1:8080 http://example.com/
```

## Controles TUI

- `↑` / `↓`: mover seleccion
- `j` / `k`: mover seleccion
- `Tab`: cambiar panel de detalle
- `i`: activar/desactivar interceptacion
- `e`: editar request interceptado
- `a`: reenviar request interceptado
- `x`: descartar request interceptado
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
