# HexProxy

HexProxy es un proxy de interceptación orientado a terminal, escrito en Python y pensado para operar completamente desde una TUI. Combina captura de tráfico, edición en vivo, persistencia de sesiones, exportación de evidencia y extensibilidad mediante plugins, con un flujo de trabajo inspirado en herramientas como Burp Suite pero centrado en consola.

## Estado Del Proyecto

HexProxy está en una etapa temprana, pero ya cubre un flujo operativo real para análisis HTTP y HTTPS:

- Proxy HTTP funcional con captura de requests y responses
- Interceptación de `request`, `response` o ambas fases
- Inspección HTTPS mediante MITM local cuando el cliente confía la CA de HexProxy
- Túnel `CONNECT` funcional y soporte básico de `WebSocket` después del `101 Switching Protocols`
- Persistencia de proyectos para guardar y reabrir sesiones
- `Repeater`, `Sitemap`, `Match/Replace`, `Export`, `Filters`, `Settings` y `Keybindings`
- Snippets exportables y copia directa al portapapeles
- Themes globales y plugins cargables desde archivos Python
- Compatibilidad de instalación para Linux, macOS y Windows

## Características Principales

- `Flows` y vistas de detalle para navegar tráfico capturado en tiempo real
- Workspaces dedicados para `Intercept`, `Repeater`, `Sitemap`, `Match/Replace`, `Export`, `Settings`, `Filters` y `Keybindings`
- Visualización unificada de `Request` y `Response`, mostrando headers y body en el mismo workspace
- Detección de tipo de contenido, vista `raw`/`pretty`, `word wrap`, scroll horizontal y resaltado sintáctico básico
- Decodificación de `chunked`, `gzip`, `deflate` y `br` cuando es posible
- Scope configurable con soporte para patrones como `example.com`, `*.example.com` y `*`
- Filtros persistentes para ocultar ruido y trabajar con vistas limpias
- Reglas persistentes de `Match/Replace` para requests y responses
- Exportación a formatos de desarrollo y a transcript HTTP limpio para evidencia
- Plugins Python con hooks para request, response y errores
- Themes built-in y themes personalizados mediante archivos JSON

## Instalación

### Requisitos

- Python `3.12+`
- `openssl` en `PATH` para generar la CA local y los certificados leaf
- Terminal con soporte `curses`

Notas por plataforma:

- En Windows, `windows-curses` se instala automáticamente al hacer `pip install -e .`
- En Windows, para generar certificados necesitas tener `openssl.exe` disponible en `PATH`
- Para decodificar `brotli`, instala opcionalmente `brotli`

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
hexproxy --listen-port 8080
```

### Windows

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
hexproxy --listen-port 8080
```

También puedes ejecutar el módulo directamente:

```bash
PYTHONPATH=src python3 -m hexproxy --listen-port 8080
```

## Inicio Rápido

Levantar el proxy:

```bash
hexproxy --listen-port 8080
```

Levantar el proxy con proyecto persistente:

```bash
hexproxy --listen-port 8080 --project projects/demo.hexproxy.json
```

Cargar plugins adicionales:

```bash
hexproxy --plugin-dir plugins --plugin-dir /ruta/a/otros/plugins
```

Si el puerto solicitado está ocupado, HexProxy intenta puertos cercanos y deja visible el puerto final dentro de la TUI.

## Opciones CLI

- `--listen-host`: interfaz de escucha
- `--listen-port`: puerto del proxy
- `--project`: archivo de proyecto para cargar y autosalvar sesiones
- `--plugin-dir`: directorio extra de plugins; se puede repetir
- `--cert-dir`: directorio de certificados; si no se especifica, HexProxy usa una ruta global estable
- `--config-file`: archivo de configuración global para preferencias persistentes

## Flujo De Trabajo

### Overview / Flows

`Overview` es la vista principal. Desde ahí puedes:

- navegar requests capturadas
- abrir `Request` y `Response`
- mandar un flow a `Repeater`
- abrir `Export`
- añadir el host actual al `scope`

Cuando la lista supera la altura visible, HexProxy hace scroll vertical. Si una línea es más ancha que el panel y `word wrap` está desactivado, puedes usar scroll horizontal.

### Request Y Response

Las vistas `Request` y `Response` muestran en un mismo workspace:

- start line o status line
- headers
- body

HexProxy detecta el tipo de contenido y, cuando aplica, ofrece:

- `raw`
- `pretty`
- resaltado sintáctico básico
- `word wrap`
- scroll horizontal

Tipos soportados por el viewer:

- `JSON`
- `XML`
- `HTML`
- `application/x-www-form-urlencoded`
- `JavaScript`
- `CSS`
- texto plano
- binarios en `hexdump`

Para responses comprimidas o con `transfer-encoding`, HexProxy intenta normalizar el body antes de mostrarlo. Además, el proxy fuerza `Accept-Encoding: identity` para reducir respuestas comprimidas en el análisis normal.

### Intercept

HexProxy puede interceptar:

- `off`
- `request`
- `response`
- `both`

Comportamiento actual:

- la cola de interceptación permite resolver items fuera de orden
- los items interceptados permanecen visibles como historial después de reenviarlos o descartarlos
- si un flow fue interceptado en request y luego en response, ambos registros quedan visibles
- la edición valida requests y responses antes de liberarlas
- si la response interceptada llega comprimida, HexProxy intenta abrir una versión editable decodificada

### Repeater

`Repeater` permite tomar un request capturado, editarlo y reenviarlo manualmente.

Soporta:

- múltiples sesiones de repeater
- navegación entre sesiones
- panel `Request`
- panel `Response`
- edición del request
- reenvío y visualización del resultado
- body decodificado en la response cuando es posible

Limitación actual:

- no soporta `CONNECT`
- no soporta upgrades `WebSocket`

### Sitemap

`Sitemap` construye una vista por host y ruta usando el tráfico capturado.

Incluye:

- árbol por host, carpetas y hojas
- paneles dedicados para `Request` y `Response`
- integración con `Repeater`
- integración con `scope`
- aplicación de filtros globales de visualización

### Match/Replace

HexProxy soporta reglas persistentes de `Match/Replace` para requests y responses.

Características:

- scope de regla: `request`, `response` o `both`
- modo: `literal` o `regex`
- descripción opcional
- persistencia en el proyecto
- builder guiado dentro de la TUI
- eliminación de reglas desde la interfaz

Las reglas sobre responses se aplican sobre la representación decodificada/editable del mensaje cuando corresponde, para evitar fallos con contenido comprimido.

### Export

`Export` genera snippets reutilizables desde cualquier workspace que tenga una request HTTP seleccionable.

Formatos disponibles:

- `HTTP request + response`
- `Python requests`
- `curl (bash)`
- `curl (windows)`
- `Node.js fetch`
- `Go net/http`
- `PHP cURL`
- `Rust reqwest`

Casos de uso:

- reproducir requests rápidamente
- compartir snippets con otros equipos
- generar evidencia limpia para reportes
- copiar transcripts HTTP sin ruido adicional

`Export` soporta:

- copia al clipboard
- `word wrap`
- scroll horizontal
- resaltado sintáctico básico

## HTTPS, Certificados Y Navegadores

HexProxy puede inspeccionar HTTPS mediante MITM local.

Para eso:

1. HexProxy genera una CA local
2. el cliente debe confiar esa CA
3. el navegador o cliente debe usar HexProxy como proxy HTTP explícito

Puedes generar o regenerar la CA desde `Settings`.

También puedes descargarla desde la página local servida por el propio proxy:

- acceso directo: `http://127.0.0.1:PUERTO/`
- acceso directo: `http://localhost:PUERTO/`
- acceso vía proxy: `http://hexproxy/`
- descarga directa: `http://127.0.0.1:PUERTO/cert`

Archivos generados por defecto:

- Linux/macOS: `~/.config/hexproxy/certs/`
- Windows: `%APPDATA%\hexproxy\certs\`

Contenido esperado:

- `hexproxy-ca.crt`
- `hexproxy-ca.key`
- `hosts/` con certificados leaf por host

Notas importantes:

- si regeneras la CA, debes volver a importarla en el navegador o cliente
- Firefox debe configurarse usando `HTTP Proxy`, no `HTTPS Proxy`
- si el cliente no confía la CA, el MITM HTTPS fallará

## Scope

El `scope` define qué hosts quedan permitidos para interceptación.

Comportamiento:

- si el scope está vacío, la interceptación puede aplicarse a cualquier host
- si el scope tiene entradas, solo esos hosts entran al interceptor
- el tráfico fuera de scope puede ocultarse o mostrarse en `Flows` y `Sitemap`

Patrones soportados:

- `example.com`: coincide con `example.com` y subdominios
- `*.example.com`: coincide solo con subdominios
- `!test.example.com`: excluye un host concreto del scope
- `!*.internal.example.com`: excluye subdominios concretos de un patrón más amplio
- `*`: coincide con todo

También puedes:

- añadir hosts al scope directamente desde `Flows`, `Sitemap`, `Request` o `Response`
- abrir `Settings -> Scope` para gestionar patrones in-scope y out-of-scope desde la TUI
- alternar rápidamente si quieres ver solo tráfico in-scope o todo el tráfico

## Filters

`Settings -> Filters` abre un workspace dedicado para controlar qué aparece en `Flows` y `Sitemap`.

Filtros disponibles actualmente:

- mostrar u ocultar tráfico fuera de scope
- requests con query string, sin query string o ambos
- traffic con body, sin body o ambos
- todos los fallos, solo fallos, ocultar fallos, solo `4xx`, solo `5xx`, solo errores de conexión
- allowlist de métodos HTTP
- denylist de métodos HTTP
- ocultar extensiones como `jpg`, `png`, `js`, `css`, `woff`, etc.

Los filtros se guardan en el proyecto.

## Proyectos Y Persistencia

Si ejecutas HexProxy con `--project`, toda la información relevante se guarda en disco:

- flows capturados
- requests y responses
- reglas de `Match/Replace`
- scope
- filtros de visualización

Comportamiento:

- si el archivo existe, se carga
- si no existe, se crea un proyecto nuevo
- cada cambio se autosalva
- puedes forzar guardado manual
- si no iniciaste con `--project`, la TUI puede pedirte un nombre o ruta y crear el proyecto al guardar

## Keybindings

HexProxy mantiene `Tab` para rotar workspaces, pero además soporta atajos directos configurables.

Características:

- bindings globales persistentes para toda la aplicación
- bindings de uno o dos caracteres
- validación contra duplicados
- validación contra combinaciones ambiguas
- editor interactivo dentro de la TUI

Workspaces principales por defecto:

- `1`: `Overview`
- `2`: `Intercept`
- `3`: `Repeater`
- `4`: `Sitemap`
- `5`: `Match/Replace`
- `6`: `Request`
- `7`: `Response`
- `8`: `Export`
- `w`: `Settings`
- `0`: `Keybindings`

Acciones importantes por defecto:

- `a`: enviar en `Intercept` y `Repeater`, o copiar en `Export`
- `e`: editar item actual
- `x`: descartar item interceptado o cancelar donde aplique
- `y`: mandar el flow actual a `Repeater`
- `A`: agregar host actual al scope
- `p`: alternar `raw` / `pretty`
- `z`: alternar `word wrap`
- `o`: alternar visibilidad fuera de scope

Archivo global de preferencias:

- Linux/macOS: `~/.config/hexproxy/config.json`
- Windows: `%APPDATA%\hexproxy\config.json`

## Themes

HexProxy incluye themes built-in y permite themes personalizados.

Themes incorporados:

- `default`
- `amber`
- `ocean`
- `forest`
- `mono`

Los themes personalizados se cargan desde un archivo JSON por theme:

- Linux/macOS: `~/.config/hexproxy/themes/`
- Windows: `%APPDATA%\hexproxy\themes\`

Ejemplo:

```json
{
  "name": "sunset",
  "description": "Warm custom palette",
  "extends": "default",
  "colors": {
    "chrome": { "fg": "black", "bg": "yellow" },
    "accent": { "fg": "red", "bg": "default" }
  }
}
```

Roles soportados:

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

## Plugins

HexProxy carga plugins Python desde:

- `plugins/` si existe
- cualquier directorio indicado con `--plugin-dir`

Reglas del loader:

- se cargan archivos `*.py`
- archivos que empiezan con `_` se ignoran
- el módulo debe exportar `register()` o `PLUGIN`

Hooks soportados:

- `on_loaded()`
- `before_request_forward(context, request)`
- `on_response_received(context, request, response)`
- `on_error(context, error)`

Ejemplo mínimo:

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

Referencias:

- [Ejemplo de plugin](examples/add_header_plugin.py)
- [README de plugins](plugins/README.md)
- [Guía de desarrollo de plugins](docs/plugin-development.md)

Dentro de `Settings`, HexProxy también muestra:

- plugins cargados
- directorios de plugins configurados
- errores de carga
- guía para instalar más plugins
- documentación para desarrolladores

## Compatibilidad De Plataforma

HexProxy fue diseñado alrededor de `curses`, sockets y `openssl`, por lo que hay diferencias prácticas entre plataformas.

### Linux

Soporte principal y flujo más directo.

Clipboard:

- `wl-copy`
- `xclip`
- `xsel`

### macOS

Clipboard:

- `pbcopy`

### Windows

Soporte contemplado en el código actual:

- `windows-curses` como dependencia de instalación
- rutas globales en `%APPDATA%\hexproxy`
- clipboard con `clip.exe`, `pwsh.exe` o `powershell.exe`

Requisitos extra:

- `openssl.exe` en `PATH` para certificados MITM

## Rutas Importantes

Configuración global:

- Linux/macOS: `~/.config/hexproxy/config.json`
- Windows: `%APPDATA%\hexproxy\config.json`

Themes:

- Linux/macOS: `~/.config/hexproxy/themes/`
- Windows: `%APPDATA%\hexproxy\themes\`

Certificados:

- Linux/macOS: `~/.config/hexproxy/certs/`
- Windows: `%APPDATA%\hexproxy\certs\`

Proyecto:

- donde tú decidas al usar `--project`

## Limitaciones Actuales

- `WebSocket` se tunela, pero los frames no se inspeccionan ni editan en la TUI
- `Repeater` no soporta `CONNECT` ni upgrades `WebSocket`
- los plugins se cargan al inicio; no hay hot reload
- la decodificación `brotli` depende de que el paquete `brotli` esté instalado
- la inspección HTTPS depende de que el cliente confíe la CA local
- la generación de certificados depende de `openssl`
- el proyecto sigue en fase temprana y la superficie funcional aún está creciendo

## Desarrollo

Ejecutar tests:

```bash
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
```

Compilar rápidamente para verificar errores de sintaxis:

```bash
python3 -m compileall src tests
```

## Licencia

MIT
