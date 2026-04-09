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
- Repeater tipo Burp para reenviar requests manualmente
- Vista `Sitemap` para navegar hosts y rutas capturadas
- Workspace `Settings` para certificados, scope y keybindings
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

Hay un ejemplo completo en [`examples/add_header_plugin.py`](/home/ifysec/hexproxy/examples/add_header_plugin.py), una guia corta en [`plugins/README.md`](/home/ifysec/hexproxy/plugins/README.md) y una guia mas completa para desarrolladores en [`plugin-development.md`](/home/ifysec/hexproxy/docs/plugin-development.md). Esa misma documentacion tambien puede leerse desde `Settings` dentro de la TUI.

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

## Interceptar y modificar trafico

Desde la TUI puedes elegir que interceptar: `request`, `response` o `both`.

- `i`: cicla el modo `off -> request -> response -> both`
- `Tab`: cambiar a la pestaña `Intercept`
- `e`: editar el mensaje crudo interceptado usando tu `$EDITOR`
- `a`: reenviar el item interceptado
- `x`: descartar el item interceptado

Notas:

- Si `EDITOR` no esta definido, HexProxy usa `vi`
- La edicion valida `requests` y `responses` antes de liberarlos
- Si una `response` interceptada llega comprimida o `chunked`, HexProxy intenta decodificarla antes de abrirla en el editor
- El proxy pausa el flujo hasta que lo reenvies o descartes
- La pestaña `Intercept` muestra la fase actual pausada: `request` o `response`
- `e`, `a` y `x` solo aplican cuando el flujo seleccionado esta pausado en el interceptor

## Scope

HexProxy permite definir un `scope` opcional de dominios permitidos para la interceptacion.

- Si el `scope` esta vacio, la interceptacion aplica a cualquier host
- Si el `scope` tiene dominios, HexProxy solo pausa en el interceptor los hosts permitidos
- El trafico fuera de `scope` sigue pasando por el proxy, pero no aparece en `Flows` ni en vistas derivadas como `Sitemap`
- Se edita desde `Settings`
- El `scope` se guarda dentro del proyecto

Formato:

- un host por linea
- lineas vacias y lineas que empiezan con `#` se ignoran
- `example.com` tambien coincide con subdominios como `api.example.com`
- puedes pegar tambien URLs y HexProxy extraera el host

## Visualizacion de body

Las pestañas `Req Body` y `Res Body` intentan identificar automaticamente el tipo de contenido usando `Content-Type` y una inspeccion simple del body.

- Detecta `JSON`, `XML`, `HTML`, `application/x-www-form-urlencoded`, `JavaScript`, `CSS`, texto y binarios
- Muestra el tipo detectado y el media type en el panel de detalle
- Intenta decodificar `Transfer-Encoding: chunked` y `Content-Encoding` comunes antes de renderizar el body
- `p`: alterna entre vista `raw` y `pretty` cuando existe una representacion legible mejor
- El modo `pretty` esta disponible actualmente para `JSON`, `XML`, `HTML`, `JavaScript`, `CSS` y formularios `x-www-form-urlencoded`
- En `HTML`, HexProxy tambien intenta indentar `script` y `style` embebidos
- Cuando el contenido es binario, HexProxy lo muestra como `hexdump`
- La TUI aplica resaltado sintactico basico para `JSON`, `XML/HTML`, formularios, `JavaScript`, `CSS` y `hexdump`
- `h` / `l` o `←` / `→`: cambian entre la lista de flows y el panel derecho
- `j` / `k` o `↑` / `↓`: mueven la lista o hacen scroll del panel derecho segun el pane activo
- `PgUp` y `PgDn`: hacen scroll por pagina en el panel derecho

## Repeater

HexProxy incluye una pestaña `Repeater` para tomar un flow capturado, editarlo y reenviarlo manualmente.

- `y`: crea una nueva sesion de `Repeater` con el flow seleccionado y cambia a esa pestaña
- `e`: edita el request del repeater usando tu `$EDITOR`
- `a` o `g`: envia el request del repeater
- En la pestaña `Repeater` la lista global de flows se oculta y se reemplaza por dos paneles dedicados: `Request` y `Response`
- `h` / `l` o `←` / `→`: cambian entre el panel `Request` y `Response`
- `j` / `k` o `↑` / `↓`: hacen scroll del panel activo dentro de `Repeater`
- `[` y `]`: cambian entre sesiones de `Repeater`
- La response del repeater se muestra en su propio panel
- Si la response llega comprimida o `chunked`, HexProxy intenta decodificarla antes de mostrarla

Limitaciones actuales:

- `CONNECT` y upgrades `WebSocket` no se soportan desde repeater

## Sitemap

HexProxy incluye una pestaña `Sitemap` con workspace propio para navegar el trafico capturado por host y ruta.

- La lista global de `Flows` se oculta y se reemplaza por un arbol `Sitemap`
- A la derecha se muestran el `Request` y el `Response` del item seleccionado
- `h` / `l` o `←` / `→`: cambian entre `Sitemap`, `Request` y `Response`
- `j` / `k` o `↑` / `↓`: mueven la seleccion del arbol o hacen scroll del panel activo
- `PgUp` / `PgDn`: hacen scroll por pagina del panel activo
- `y`: carga el item seleccionado del sitemap en `Repeater`

## Settings

HexProxy incluye un workspace `Settings` que se abre con `w` por defecto.

- Desde ahi puedes ver los plugins cargados, sus rutas y errores de carga
- Desde ahi puedes ver como instalar mas plugins en `plugins/` o con `--plugin-dir`
- Desde ahi puedes leer una guia de desarrollo sobre plugins y la API de HexProxy
- Desde ahi puedes generar o regenerar la CA local
- Desde ahi puedes editar el `scope`
- Desde ahi puedes abrir un workspace dedicado de `Keybindings`
- `h` / `l` o `←` / `→`: cambian entre el menu y el panel de detalle
- `j` / `k` o `↑` / `↓`: mueven la seleccion o hacen scroll del detalle
- `e` o `Enter`: ejecutan o editan el item seleccionado

Notas sobre keybindings:

- Se guardan globalmente para toda la aplicacion
- Por defecto viven en `~/.config/hexproxy/config.json`
- Puedes cambiar la ruta con `--config-file` o `HEXPROXY_CONFIG`
- Se editan desde un workspace propio, no en JSON crudo
- Puedes usar bindings de una o dos teclas visibles
- Si intentas repetir una tecla o crear una secuencia ambigua, HexProxy rechaza el cambio y muestra el error en la TUI
- Cada workspace tiene una accion directa configurable para abrirlo sin recorrer tabs
- Las teclas especiales como `Tab`, flechas, `PgUp` y `PgDn` siguen fijas

## HTTPS

HexProxy soporta `HTTPS` usando `CONNECT` y puede interceptarlo con un MITM local.

Comportamiento:

- La primera vez genera una CA local en `.hexproxy/certs/`
- El certificado raiz queda en `.hexproxy/certs/hexproxy-ca.crt`
- Desde `Settings` puedes generar la CA y regenerarla
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
- `1`: abrir `Overview`
- `2`: abrir `Intercept`
- `3`: abrir `Repeater`
- `4`: abrir `Sitemap`
- `5`: abrir `Match/Replace`
- `6`: abrir `Req Headers`
- `7`: abrir `Req Body`
- `8`: abrir `Res Headers`
- `9`: abrir `Res Body`
- `0`: abrir `Keybindings`
- `i`: ciclar modo de interceptacion `off/request/response/both`
- `y`: cargar el flow seleccionado en `Repeater`
- `y`: desde `Sitemap`, cargar el item seleccionado en `Repeater`
- `r`: editar reglas de `Match/Replace` cuando esa pestaña este activa
- `w`: abrir `Settings`
- `e`: editar item interceptado cuando haya un flujo pausado
- `a`: reenviar item interceptado cuando haya un flujo pausado
- `x`: descartar item interceptado cuando haya un flujo pausado
- `a`: enviar tambien el request actual del `Repeater` cuando esa pestaña este activa
- `g`: alias para enviar el request actual del `Repeater`
- `p`: alternar entre vista `raw` y `pretty` en `Req Body` y `Res Body`
- `[` / `]`: cambiar entre sesiones del `Repeater`
- `PgUp` / `PgDn`: hacer scroll por pagina del panel derecho
- `s`: guardar proyecto manualmente
- `q`: salir

Los bindings anteriores son los defaults. Desde `Keybindings` puedes cambiarlos por secuencias de 1 o 2 teclas.

## Match/Replace

HexProxy incluye una pestaña `Match/Replace` con reglas persistentes que se guardan dentro del proyecto.

- `Tab`: cambia a `Match/Replace`
- `r`: abre un workspace guiado para crear una nueva regla
- El builder solicita `enabled`, `scope`, `mode`, `description`, `match` y `replace`
- El builder muestra el JSON generado antes de guardar
- `a`: valida y agrega la regla al conjunto persistente
- `x`: cancela el builder sin guardar
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

- Filtros y busqueda
- Exportacion de trafico
- Inspeccion y edicion de frames `WebSocket`
