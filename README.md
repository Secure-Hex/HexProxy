# HexProxy

HexProxy es un proxy HTTP/HTTPS orientado a terminal, escrito en Python y diseñado para trabajar completamente desde una TUI. Su objetivo es ofrecer un flujo de trabajo estilo Burp Suite, pero centrado en consola: captura, interceptación, edición, repetición, exportación de evidencia, persistencia de sesiones y extensibilidad mediante plugins.

## Resumen

HexProxy ya cubre un flujo operativo real para análisis de tráfico:

- proxy HTTP funcional con captura de requests y responses
- interceptación de `request`, `response` o ambas fases
- inspección HTTPS mediante MITM local cuando el cliente confía la CA de HexProxy
- `Repeater`, `Sitemap`, `Match/Replace`, `Export`, `Scope`, `Filters`, `Settings` y `Keybindings`
- workspace HTTP unificado con `Request` y `Response` visibles en la misma pantalla
- proyectos persistentes con autosave
- exportación a snippets de desarrollo y transcript HTTP limpio para evidencia
- plugins Python cargables desde archivos locales
- themes globales, incluyendo colores nombrados y colores hex

## Características Principales

- `Flows` en tiempo real con navegación por teclado
- visualización simultánea de `Request` y `Response` para el flow seleccionado
- detección de tipo de contenido, `raw` / `pretty`, syntax highlighting básico, `word wrap` y scroll horizontal
- decodificación de `chunked`, `gzip`, `deflate` y `br` cuando es posible
- `Intercept` con historial persistente en la sesión y resolución fuera de orden
- `Repeater` con múltiples sesiones y múltiples envíos por sesión
- `Sitemap` por host y ruta
- `Match/Replace` persistente con builder guiado dentro de la TUI
- `Scope` con inclusiones y exclusiones explícitas
- filtros para limpiar `Flows` y `Sitemap`
- copia al clipboard desde `Export`
- documentación de plugins y themes dentro de `Settings`

## Instalación

### Requisitos

- Python `3.12+`
- `openssl` en `PATH` para generar la CA local y certificados por host
- terminal compatible con `curses`

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

Notas de instalación:

- En Windows, `windows-curses` se instala como dependencia del proyecto.
- Para MITM HTTPS en Windows también necesitas `openssl.exe` accesible desde `PATH`.
- Para decodificar `brotli`, instala opcionalmente `brotli`.

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
hexproxy --plugin-dir plugins --plugin-dir /ruta/a/plugins-extra
```

Si el puerto solicitado está ocupado, HexProxy intenta puertos cercanos y muestra el puerto final dentro de la TUI.

## Opciones CLI

- `--listen-host`: interfaz de escucha
- `--listen-port`: puerto del proxy
- `--project`: archivo de proyecto para cargar y autosalvar sesiones
- `--plugin-dir`: directorio adicional de plugins; se puede repetir
- `--cert-dir`: directorio de certificados; por defecto usa una ruta global estable
- `--config-file`: archivo de configuración global

## Workspaces

### 1. Overview

Vista principal con la lista de `Flows` capturados y detalles generales del item seleccionado.

### 2. Intercept

Permite interceptar:

- `off`
- `request`
- `response`
- `both`

Características:

- cola de interceptación resoluble fuera de orden
- historial retenido después de reenviar o descartar
- edición validada de request y response

### 3. Repeater

Permite cargar un flow, editar el request y reenviarlo manualmente.

Incluye:

- múltiples sesiones
- múltiples envíos por sesión
- historial por sesión
- request editable
- response visible y reutilizable para export

Limitaciones actuales:

- no soporta `CONNECT`
- no soporta upgrades `WebSocket`

### 4. Sitemap

Construye un árbol por host y ruta usando el tráfico visible actualmente.

Incluye:

- árbol por host
- request y response del item seleccionado
- integración con `Repeater`
- integración con `Scope` y `Filters`

### 5. Match/Replace

Gestiona reglas persistentes para modificar requests y responses.

Incluye:

- builder guiado dentro de la TUI
- edición de reglas existentes
- eliminación de reglas
- soporte `literal` y `regex`
- scope de regla `request`, `response` o `both`

### 6 y 7. HTTP Workspace

Los atajos `6` y `7` abren el mismo workspace HTTP:

- `6`: abre el workspace con foco en `Request`
- `7`: abre el mismo workspace con foco en `Response`

La pantalla muestra al mismo tiempo:

- `Flows` a la izquierda
- `Request` arriba a la derecha
- `Response` abajo a la derecha

Cada panel soporta:

- scroll vertical
- scroll horizontal cuando `word wrap` está apagado
- `raw` / `pretty`
- syntax highlighting básico

Tipos soportados por el viewer:

- `JSON`
- `XML`
- `HTML`
- `application/x-www-form-urlencoded`
- `JavaScript`
- `CSS`
- texto plano
- binarios en `hexdump`

### 8. Export

Genera snippets y transcripts desde el flow, item interceptado o sesión de repeater actual.

Formatos disponibles:

- `HTTP request + response`
- `Python requests`
- `curl (bash)`
- `curl (windows)`
- `Node.js fetch`
- `Go net/http`
- `PHP cURL`
- `Rust reqwest`

También soporta:

- copia directa al clipboard
- `word wrap`
- scroll horizontal
- syntax highlighting básico

### 9. Findings

Workspace de análisis de seguridad en tiempo real. Escanea cada flow por:

- encabezados críticos ausentes (`X-Frame-Options`, `Content-Security-Policy`, `HSTS`)
- cookies sin `Secure`/`HttpOnly`
- cabeceras CORS permisivas (`Access-Control-Allow-Origin: *`)
- JSON con comentarios no estándar
- fingerprinting de librerías comunes y correlación con versiones detectadas

El panel izquierdo resume:

- conteos por severidad (critical/warning/info)
- indicación de flows marcados como riesgo crítico (asterisco `*`)
- atajos: `9` abre este workspace, `m` marca/desmarca un flow como riesgo crítico, `8` abre el panel de export para reportar rápidamente

El panel derecho muestra:

- descripción completa del hallazgo
- recomendaciones sugeridas
- identificación de versiones de librerías expuestas y hallazgos relacionados
- estado de marcado `Flagged as critical risk`

Todos los marcados se resaltan en la lista y permiten exportar/reportar en un solo click gracias a `open_export`.

### Settings

`Settings` está organizado por secciones:

- `Appearance`
- `Extensions`
- `TLS`
- `Traffic`
- `Controls`

Desde ahí puedes abrir o ejecutar:

- `Themes`
- `Plugins`
- `Plugin Developer Docs`
- generar o regenerar certificados
- `Scope`
- `Filters`
- `Keybindings`

### Scope

Workspace interactivo para gestionar:

- patrones in-scope
- patrones out-of-scope
- altas, edición y borrado sin salir de la TUI

### Filters

Workspace interactivo para controlar qué aparece en `Flows` y `Sitemap`.

Filtros actuales:

- mostrar u ocultar tráfico fuera de scope
- requests con query, sin query o ambos
- tráfico con body, sin body o ambos
- fallos: todos, solo fallos, ocultar fallos, `4xx`, `5xx`, errores de conexión
- allowlist de métodos HTTP
- denylist de métodos HTTP
- extensiones ocultas como `jpg`, `png`, `js`, `css`, `woff`, etc.

### Keybindings

Workspace interactivo para editar atajos globales.

Características:

- bindings persistentes para toda la aplicación
- secuencias de uno o dos caracteres
- validación contra duplicados
- validación contra combinaciones ambiguas

## HTTPS, Certificados Y Navegadores

HexProxy puede inspeccionar HTTPS mediante MITM local.

Flujo:

1. HexProxy genera una CA local
2. el cliente debe confiar esa CA
3. el navegador o cliente debe usar HexProxy como proxy HTTP explícito

La CA puede:

- generarse o regenerarse desde `Settings`
- descargarse desde la página local servida por HexProxy

Rutas útiles:

- `http://127.0.0.1:PUERTO/`
- `http://localhost:PUERTO/`
- `http://hexproxy/` cuando el navegador ya usa HexProxy como proxy
- `http://127.0.0.1:PUERTO/cert`

Ubicación por defecto de certificados:

- Linux/macOS: `~/.config/hexproxy/certs/`
- Windows: `%APPDATA%\hexproxy\certs\`

Notas importantes:

- si regeneras la CA, debes volver a importarla en el cliente
- Firefox debe configurarse como `HTTP Proxy`, no `HTTPS Proxy`
- si el cliente no confía la CA, el MITM HTTPS fallará

## Scope

El `scope` controla qué hosts quedan permitidos para interceptación.

Comportamiento:

- si el scope está vacío, toda la captura puede entrar al interceptor
- si el scope tiene entradas, solo los hosts permitidos se interceptan
- el tráfico fuera de scope puede seguir mostrándose o ocultarse desde `Filters`

Patrones soportados:

- `example.com`: coincide con `example.com` y subdominios
- `*.example.com`: coincide solo con subdominios
- `!test.example.com`: excluye un host concreto
- `!*.internal.example.com`: excluye subdominios concretos
- `*`: coincide con todo

También puedes añadir el host actual al scope desde:

- `Flows`
- `Sitemap`
- el workspace HTTP

## Proyectos Y Persistencia

Si usas `--project`, HexProxy persiste:

- flows capturados
- requests y responses
- reglas de `Match/Replace`
- scope
- filtros de vista

Comportamiento:

- si el archivo existe, se carga
- si no existe, se crea uno nuevo
- cada cambio importante se autosalva
- puedes forzar guardado manual
- si no iniciaste con `--project`, HexProxy puede pedir nombre o ruta al guardar

## Keybindings Por Defecto

Workspaces:

- `1`: `Overview`
- `2`: `Intercept`
- `3`: `Repeater`
- `4`: `Sitemap`
- `5`: `Match/Replace`
- `6`: `HTTP` con foco en request
- `7`: `HTTP` con foco en response
- `8`: `Export`
- `w`: `Settings`
- `0`: `Keybindings`

Acciones principales:

- `a`: enviar en `Intercept` y `Repeater`, o copiar en `Export`
- `e`: editar item actual
- `x`: descartar, borrar o cancelar según el workspace
- `y`: mandar el flow actual a `Repeater`
- `A`: agregar host actual al scope
- `p`: alternar `raw` / `pretty`
- `z`: alternar `word wrap`
- `o`: alternar visibilidad fuera de scope

Archivo global de configuración:

- Linux/macOS: `~/.config/hexproxy/config.json`
- Windows: `%APPDATA%\hexproxy\config.json`

## Themes

HexProxy incluye themes built-in y soporta themes personalizados.

Themes incorporados:

- `default`
- `amber`
- `ocean`
- `forest`
- `mono`

Ubicación de themes custom:

- Linux/macOS: `~/.config/hexproxy/themes/`
- Windows: `%APPDATA%\hexproxy\themes\`

Formato JSON:

```json
{
  "name": "sunset",
  "description": "Warm custom palette",
  "extends": "default",
  "colors": {
    "chrome": { "fg": "#1d3557", "bg": "#f1c40f" },
    "accent": { "fg": "red", "bg": "default" },
    "keyword": { "fg": "#ff8800", "bg": "default" }
  }
}
```

Claves soportadas:

- `name`: nombre único del theme
- `description`: descripción opcional
- `extends`: theme base, por defecto `default`
- `colors`: overrides por rol

Roles soportados:

- `chrome`
- `selection`
- `success`
- `error`
- `warning`
- `accent`
- `keyword`
- `info`

Valores de color soportados:

- `default`
- `black`
- `red`
- `green`
- `yellow`
- `blue`
- `magenta`
- `cyan`
- `white`
- `#RGB`
- `#RRGGBB`

Notas sobre hex:

- HexProxy acepta hex colors en el JSON.
- En runtime, la TUI los aproxima al color de terminal más cercano soportado por `curses`.
- Esto mantiene compatibilidad con terminales básicas sin perder expresividad en la definición del theme.

## Plugins

HexProxy carga plugins Python desde:

- la subcarpeta `plugins/` dentro del directorio de configuración global (por defecto `~/.config/hexproxy/plugins` en Linux/macOS o `%APPDATA%/hexproxy/plugins` / `%LOCALAPPDATA%/hexproxy/plugins` en Windows; el mismo directorio que contiene `--config-file` o la ruta indicada por `HEXPROXY_CONFIG`). HexProxy crea esta carpeta automáticamente y copia ahí el plugin `hexproxy/plugins/jwt_inspector.py` incluido.
- cualquier directorio indicado con `--plugin-dir`

Reglas del loader:

- se cargan archivos `*.py`
- archivos que comienzan con `_` se ignoran
- el módulo puede exportar `register(api)`, `register()`, `PLUGIN` o `contribute(api)`

Capacidades de la API v2:

- hooks de tráfico para request/response/error
- workspaces propios
- paneles dentro de workspaces propios y paneles en workspaces integrados
- exporters adicionales
- keybindings configurables
- analyzers
- metadata visible en la TUI
- campos en `Settings`
- estado global y por proyecto para plugins

Ejemplo:

```python
def register(api):
    api.add_workspace("demo_workspace", "Demo", "Workspace de plugin", shortcut="dw")
    api.add_panel(
        "demo_workspace",
        "summary",
        "Summary",
        render_lines=lambda context: ["Plugin workspace activo"],
    )
    return DemoPlugin()
```

Referencias:

- [Ejemplo de plugin](examples/add_header_plugin.py)
- [README de plugins](plugins/README.md)
- [Guía de desarrollo de plugins](src/hexproxy/docs/plugin-development.md)

Nota de runtime:

- la metadata de plugins persistida por flow se almacena como strings
- para guardar estructuras debes usar `json.dumps(...)` al escribir y `json.loads(...)` al leer

## Compatibilidad De Plataforma

HexProxy ya contempla:

- rutas globales por plataforma para config, themes y certificados
- instalación de `windows-curses` en Windows
- integración de clipboard para Linux, macOS y Windows

Aun así, el flujo más validado sigue siendo Unix-like. En Windows el soporte está presente en la base del proyecto, pero conviene validar terminal, `openssl` y clipboard en tu entorno real.

## Limitaciones Actuales

- soporte `WebSocket` limitado al túnel tras `101 Switching Protocols`
- `Repeater` no soporta `CONNECT`
- el rendering y clipboard dependen de lo que soporte tu terminal

## Desarrollo

Ejecutar tests:

```bash
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
```

Verificación rápida de sintaxis:

```bash
python3 -m compileall src tests
```
