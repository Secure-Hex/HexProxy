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
- Themes globales y cargables desde archivos JSON
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
- La pestaña `Intercept` muestra una lista dedicada con historial de items interceptados y su fase actual: `request` o `response`
- Puedes seleccionar y resolver cualquier item pendiente sin seguir el orden de llegada
- Los items reenviados o descartados no desaparecen de la lista; quedan visibles para analisis posterior
- `e`, `a` y `x` aplican solo al item actualmente seleccionado cuando sigue pendiente

## Scope

HexProxy permite definir un `scope` opcional de dominios permitidos para la interceptacion.

- Si el `scope` esta vacio, la interceptacion aplica a cualquier host
- Si el `scope` tiene dominios, HexProxy solo pausa en el interceptor los hosts permitidos
- El trafico fuera de `scope` sigue pasando por el proxy, pero puede ocultarse o mostrarse en `Flows` y `Sitemap`
- Puedes alternar entre ver solo trafico in-scope o todo el trafico con `o` cuando hay un `scope` configurado
- Desde `Flows`, `Sitemap` y las vistas de request/response del flow puedes agregar el host actual al `scope` con `A`
- Se edita desde `Settings`
- El `scope` se guarda dentro del proyecto

## Filters

HexProxy incluye filtros de visualizacion para `Flows` y `Sitemap`. Se configuran desde `Settings -> Filters` y se guardan dentro del proyecto.

- Puedes decidir si mostrar solo trafico `in-scope` o tambien lo que esta fuera de `scope`
- Puedes filtrar requests con parametros, sin parametros o ambos
- Puedes filtrar solo fallos, ocultar fallos, solo `4xx`, solo `5xx`, solo errores de conexion o dejar todo visible
- Puedes filtrar por presencia de body
- Puedes limitar la vista a ciertos metodos HTTP como `GET`, `POST` o `PUT`
- Puedes ocultar metodos HTTP concretos con una denylist separada, sin tener que construir una allowlist completa
- Puedes ocultar tipos de archivo por extension como `jpg`, `png`, `js`, `css`, `woff`
- El atajo `o` sigue alternando rapido la visibilidad de trafico fuera de `scope`
- `Settings -> Filters` abre un workspace dedicado dentro de la TUI con toggles, ciclos y listas
- Cada filtro explica en pantalla que significa y cual es su efecto real sobre `Flows` y `Sitemap`

Formato:

- un host por linea
- lineas vacias y lineas que empiezan con `#` se ignoran
- `example.com` tambien coincide con subdominios como `api.example.com`
- `*.example.com` coincide solo con subdominios como `api.example.com`, pero no con `example.com`
- `*` permite incluir todo el trafico explicitamente
- puedes pegar tambien URLs y HexProxy extraera el host

## Visualizacion de request/response

Las pestañas `Request` y `Response` muestran en el mismo workspace tanto los headers como el body.

- Detecta `JSON`, `XML`, `HTML`, `application/x-www-form-urlencoded`, `JavaScript`, `CSS`, texto y binarios
- Intenta decodificar `Transfer-Encoding: chunked` y `Content-Encoding` comunes antes de renderizar el body
- `p`: alterna entre vista `raw` y `pretty` cuando existe una representacion legible mejor
- `z`: alterna `word wrap` global para los paneles de texto
- El modo `pretty` esta disponible actualmente para `JSON`, `XML`, `HTML`, `JavaScript`, `CSS` y formularios `x-www-form-urlencoded`
- En `HTML`, HexProxy tambien intenta indentar `script` y `style` embebidos
- Cuando el contenido es binario, HexProxy lo muestra como `hexdump`
- La TUI aplica resaltado sintactico basico para `JSON`, `XML/HTML`, formularios, `JavaScript`, `CSS` y `hexdump`
- `h` / `l` o `←` / `→`: cambian entre la lista de flows y el panel derecho
- `j` / `k` o `↑` / `↓`: mueven la lista o hacen scroll del panel derecho segun el pane activo
- `H` / `L`: hacen scroll horizontal dentro del panel derecho cuando el contenido es muy ancho
- `PgUp` y `PgDn`: hacen scroll por pagina en el panel derecho

## Repeater

HexProxy incluye una pestaña `Repeater` para tomar un flow capturado, editarlo y reenviarlo manualmente.

- `y`: crea una nueva sesion de `Repeater` con el flow seleccionado y cambia a esa pestaña
- `e`: edita el request del repeater usando tu `$EDITOR`
- `a` o `g`: envia el request del repeater
- En la pestaña `Repeater` la lista global de flows se oculta y se reemplaza por dos paneles dedicados: `Request` y `Response`
- `h` / `l` o `←` / `→`: cambian entre el panel `Request` y `Response`
- `j` / `k` o `↑` / `↓`: hacen scroll del panel activo dentro de `Repeater`
- `H` / `L`: hacen scroll horizontal del panel activo dentro de `Repeater`
- `z`: alterna `word wrap` del panel activo
- `[` y `/`: cambian entre sesiones de `Repeater`
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
- `H` / `L`: hacen scroll horizontal del panel activo
- `z`: alterna `word wrap` del panel activo
- `PgUp` / `PgDn`: hacen scroll por pagina del panel activo
- `y`: carga el item seleccionado del sitemap en `Repeater`

## Export

HexProxy incluye una pestaña `Export` para convertir la request seleccionada a snippets reutilizables.

- Se puede abrir desde cualquier workspace que tenga una request HTTP seleccionable, como `Flows`, `Intercept`, `Repeater`, `Sitemap`, `Request` o `Response`
- Genera varios formatos: `HTTP request + response`, `Python requests`, `curl (bash)`, `curl (windows)`, `Node.js fetch`, `Go net/http`, `PHP cURL` y `Rust reqwest`
- El formato `HTTP request + response` exporta ambas mitades limpias, solo con el contenido HTTP, para usarlas como evidencia en reportes
- El panel derecho soporta `word wrap` con `z`
- El panel derecho soporta scroll horizontal con `H` / `L` cuando `word wrap` esta apagado
- El snippet usa resaltado sintactico basico para `HTTP`, `Python`, `curl`, `Node.js`, `PHP`, `Go` y `Rust`
- `a` o `Enter`: copian el formato seleccionado al clipboard
- La copia intenta usar `wl-copy`, `xclip`, `xsel`, `pbcopy` o `clip.exe` segun el sistema

## Settings

HexProxy incluye un workspace `Settings` que se abre con `w` por defecto.

- Desde ahi puedes ver los plugins cargados, sus rutas y errores de carga
- Desde ahi puedes ver como instalar mas plugins en `plugins/` o con `--plugin-dir`
- Desde ahi puedes leer una guia de desarrollo sobre plugins y la API de HexProxy
- Desde ahi puedes elegir el theme activo
- Desde ahi puedes generar o regenerar la CA local
- Desde ahi puedes editar el `scope`
- Desde ahi puedes abrir un workspace dedicado de `Filters` para cambiar la visibilidad de trafico sin usar un editor externo
- Desde ahi puedes abrir un workspace dedicado de `Keybindings`
- El workspace de `Keybindings` agrupa las acciones por secciones para que sea mas facil ubicarlas
- En los paneles de detalle tambien puedes usar `H` / `L` para scroll horizontal
- `z` alterna `word wrap` tambien dentro de `Settings` y workspaces auxiliares
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

## Themes

HexProxy incluye themes globales y persistentes para toda la aplicacion.

- Se seleccionan desde `Settings -> Themes`
- El cambio se aplica en vivo, sin reiniciar
- El theme elegido se guarda en `~/.config/hexproxy/config.json`
- Los themes custom se cargan desde `~/.config/hexproxy/themes/`
- Debes crear un archivo `.json` por theme

Ejemplo:

```json
{
  "name": "sunset",
  "description": "warm palette",
  "extends": "default",
  "colors": {
    "chrome": { "fg": "black", "bg": "yellow" },
    "selection": { "fg": "black", "bg": "magenta" },
    "accent": { "fg": "red", "bg": "default" }
  }
}
```

Roles disponibles:

- `chrome`
- `selection`
- `success`
- `error`
- `warning`
- `accent`
- `keyword`
- `info`

Colores soportados:

- `default`
- `black`
- `red`
- `green`
- `yellow`
- `blue`
- `magenta`
- `cyan`
- `white`

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
- `6`: abrir `Request`
- `7`: abrir `Response`
- `8`: abrir `Export`
- `0`: abrir `Keybindings`
- `i`: ciclar modo de interceptacion `off/request/response/both`
- `y`: cargar el flow seleccionado en `Repeater`
- `y`: desde `Sitemap`, cargar el item seleccionado en `Repeater`
- `r`: editar reglas de `Match/Replace` cuando esa pestaña este activa
- `w`: abrir `Settings`
- `o`: alternar entre mostrar solo trafico in-scope o todo el trafico cuando el `scope` existe
- `A`: agregar el host actual del flow o del item seleccionado en `Sitemap` al `scope`
- `e`: editar item interceptado cuando haya un flujo pausado
- `a`: reenviar item interceptado cuando haya un flujo pausado
- `x`: descartar item interceptado cuando haya un flujo pausado
- `a`: enviar tambien el request actual del `Repeater` cuando esa pestaña este activa
- `a`: copiar tambien el snippet actual del workspace `Export`
- `g`: alias para enviar el request actual del `Repeater`
- `p`: alternar entre vista `raw` y `pretty` en `Request` y `Response`
- `z`: alternar `word wrap` global para paneles de texto
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
- En la pestaña `Match/Replace`, `j` / `k` sobre el panel derecho seleccionan reglas y `x` elimina la regla actual
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
