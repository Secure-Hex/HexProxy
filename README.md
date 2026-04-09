# HexProxy

HexProxy es un proxy HTTP de interceptacion pensado para trabajar 100% en terminal. Esta primera version se enfoca en:

- Proxy HTTP funcional
- Captura de requests y responses
- Visualizacion en tiempo real en una TUI basada en `curses`
- Persistencia de proyecto para guardar sesiones y reabrirlas despues
- Interceptacion de requests con edicion antes de reenviar
- Reglas Match/Replace persistentes para requests y responses
- Intercepcion HTTPS con MITM local cuando la CA es confiada por el cliente
- Soporte basico para `WebSocket` despues del `101 Switching Protocols`
- Sistema de extensiones en Python para terceros
- Sin dependencias Python externas

## Estado actual

El alcance de esta version inicial es deliberadamente acotado:

- Soporta HTTP y HTTPS via `CONNECT`
- El trafico HTTPS puede inspeccionarse si el cliente confia la CA local de HexProxy
- Puede tunelar `WebSocket` despues del handshake HTTP
- Procesa una transaccion por conexion y fuerza `Connection: close` para simplificar el flujo
- Los requests y responses HTTPS quedan visibles dentro de la TUI cuando el MITM esta activo
- El trafico `WebSocket` se tunela, pero los frames aun no se muestran ni editan en la TUI

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
- `--cert-dir`: directorio donde se guardan la CA local y los certificados leaf generados

Nota:

- Si el puerto elegido ya esta ocupado, HexProxy prueba automaticamente con los siguientes puertos disponibles

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

## Visualizacion de body

Las pestañas `Req Body` y `Res Body` intentan identificar automaticamente el tipo de contenido usando `Content-Type` y una inspeccion simple del body.

- Detecta `JSON`, `XML`, `HTML`, `application/x-www-form-urlencoded`, `JavaScript`, `CSS`, texto y binarios
- Muestra el tipo detectado y el media type en el panel de detalle
- Intenta decodificar `Transfer-Encoding: chunked` y `Content-Encoding` comunes antes de renderizar el body
- `p`: alterna entre vista `raw` y `pretty` cuando existe una representacion legible mejor
- El modo `pretty` esta disponible actualmente para `JSON`, `XML`, `HTML` y formularios `x-www-form-urlencoded`
- Cuando el contenido es binario, HexProxy lo muestra como `hexdump`
- La TUI aplica resaltado sintactico basico para `JSON`, `XML/HTML`, formularios, `JavaScript`, `CSS` y `hexdump`
- `h` / `l` o `←` / `→`: cambian entre la lista de flows y el panel derecho
- `j` / `k` o `↑` / `↓`: mueven la lista o hacen scroll del panel derecho segun el pane activo
- `PgUp` y `PgDn`: hacen scroll por pagina en el panel derecho

## HTTPS

HexProxy soporta `HTTPS` usando `CONNECT` y puede interceptarlo con un MITM local.

Comportamiento:

- La primera vez genera una CA local en `.hexproxy/certs/`
- El certificado raiz queda en `.hexproxy/certs/hexproxy-ca.crt`
- Desde la TUI puedes generar la CA con `c` y regenerarla con `C`
- Tambien puedes descargarla desde el navegador entrando a `http://hexproxy/` o directamente `http://hexproxy/cert` cuando el navegador este configurado para usar HexProxy como proxy
- El navegador o cliente debe usar HexProxy como proxy HTTP explicito; si intenta hablar TLS directo con el proxy, HexProxy lo marcara como configuracion incorrecta
- Si prefieres no depender del host especial, tambien puedes abrir `http://127.0.0.1:PUERTO/` o `http://localhost:PUERTO/` directamente contra el puerto donde esta escuchando HexProxy
- La pagina local genera el link de descarga del certificado usando el host/origen real con el que accediste
- Una vez confiada la CA en el cliente, HexProxy puede ver request headers, request body, response headers y response body de HTTPS en la TUI
- Para el lado cliente del MITM, HexProxy anuncia `HTTP/1.1`; si pruebas con `curl`, usa `--http1.1`

Ejemplo con `curl`:

```bash
curl --proxy http://127.0.0.1:8080 --cacert .hexproxy/certs/hexproxy-ca.crt --http1.1 https://example.com/
```

## WebSocket

HexProxy soporta el handshake HTTP de `WebSocket` y luego tunela el trafico en ambas direcciones.

Alcance actual:

- Funciona para `ws://` y `wss://` a traves del proxy
- Se registra el request inicial y la response `101 Switching Protocols`
- Los frames `WebSocket` aun no se parsean ni se editan desde la TUI

## Probar con curl

```bash
curl -x http://127.0.0.1:8080 http://example.com/
```

## Controles TUI

- `↑` / `↓`: mover seleccion
- `j` / `k`: mover seleccion
- `←` / `→`: cambiar pane activo
- `h` / `l`: cambiar pane activo
- `Tab`: cambiar panel de detalle
- `i`: activar/desactivar interceptacion
- `r`: editar reglas de `Match/Replace` cuando esa pestaña este activa
- `c`: generar la CA local si aun no existe
- `C`: regenerar la CA local y descartar los certificados leaf previos
- `e`: editar request interceptado cuando haya un flujo pausado
- `a`: reenviar request interceptado cuando haya un flujo pausado
- `x`: descartar request interceptado cuando haya un flujo pausado
- `p`: alternar entre vista `raw` y `pretty` en `Req Body` y `Res Body`
- `PgUp` / `PgDn`: hacer scroll por pagina del panel derecho
- `s`: guardar proyecto manualmente
- `q`: salir

## Match/Replace

HexProxy incluye una pestaña `Match/Replace` con reglas persistentes que se guardan dentro del proyecto.

- `Tab`: cambia a `Match/Replace`
- `r`: abre un editor externo con el documento JSON de reglas
- Cada regla soporta `scope` en `request`, `response` o `both`
- Cada regla soporta `mode` en `literal` o `regex`
- Las reglas se aplican automaticamente antes de enviar el request al upstream y antes de entregar la response al cliente

Ejemplo:

```json
{
  "rules": [
    {
      "enabled": true,
      "scope": "request",
      "mode": "literal",
      "match": "User-Agent: curl/8.0.1",
      "replace": "User-Agent: HexProxy",
      "description": "rewrite curl user-agent"
    }
  ]
}
```

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
- Inspeccion y edicion de frames `WebSocket`
