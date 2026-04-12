# Changelog

All notable changes to this project will be documented in this file.

The format is based on Conventional Commits
and this project adheres to Semantic Versioning.

<!-- version list -->

## v0.3.0 (2026-04-12)

### Features

- Add startup update checker
  ([`fd6294d`](https://github.com/Secure-Hex/HexProxy/commit/fd6294dc9d9d96febe453c26039a603fabc0a272))


## v0.2.3 (2026-04-12)

### Bug Fixes

- Enable semantic release changelog updates
  ([`10f2092`](https://github.com/Secure-Hex/HexProxy/commit/10f209211979582468135d51d7d090568fa96e6d))


## [0.1.2] - 2026-04-11

### Features
- add license (41f8ecc)
- harden mcp exporter contracts and analysis tools (cb8abee)
- add mcp server for project automation (5f1add1)
- add plugin api v2 contributions (29fcbb6)
- add interactive theme builder workspace (1d39cf9)
- preview themes on selection (0a769e4)

### Fixes
- restore settings navigation after theme builder (9004ae0)
- support navigation-prefixed key sequences (4fb9f8a)
- honor two-key bindings and add jwt inspector plugin (2c26180)

### Documentation
- align plugin guide with runtime behavior (fec7605)

### Chores
- disable mcp server and docs (b631c78)

### Other
- Add MCP debugging instrumentation for OpenCode (a9f96d1)

## [0.1.1] - 2026-04-10

### Fixes
- stabilize theme selection navigation (476e732)

## [0.1.0] - 2026-04-10

### Features
- organize settings and support hex themes (aa1993a)
- add interactive scope workspace and exclusions (31274da)
- improve tui editing and repeater history (f1132d4)
- allow editing existing match replace rules (b776096)
- add interactive traffic filters workspace (3a075f0)
- add scope actions from flows and sitemap (b1965db)
- add scope visibility toggle (a3fa8d9)
- add export workspace and decoded response handling (d1862d9)
- retain intercept history after release (5084452)
- allow intercept queue items to be handled out of order (6c5a658)
- add toggleable word wrap for text panes (f027993)
- add configurable global themes (68af123)
- group keybindings by sections (0eef057)
- allow deleting match replace rules (920d0c7)
- add guided match replace builder (b502cfc)
- add direct workspace keybindings (23be0b3)
- hide out-of-scope traffic from views (3252267)
- add plugin settings and developer docs (c92984d)
- add interactive keybindings workspace (b886f47)
- persist keybindings globally (487c493)
- add settings workspace and keybindings (7fef7df)
- add intercept scope allowlist (7d61eb6)
- add sitemap workspace tab (f73c524)
- add multi-session repeater workspace (5fea4ba)
- add repeater tab (2a5d545)
- support request and response interception modes (032fb68)
- pretty print embedded script and style (26609e5)
- decode body views and add pane scrolling (3ae7a13)
- add typed body views with pretty formatting (9d90f27)
- reintroduce HTTPS MITM with dedicated tunnel worker (c4f1d57)
- add local CA management and download routes (cbed818)
- add HTTPS interception and websocket tunneling (dde655b)
- add persistent match and replace rules (b55fc17)
- add extension loading and tighten intercept actions (a3efea4)
- bootstrap terminal HTTP proxy with interception (c133f82)

### Fixes
- use a stable global certificate directory (9a00427)
- restore upward scrolling in sitemap tree (0d3c8ee)
- keep intercept history navigation reachable (201999c)
- limit intercept mode changes to intercept workspace (8c5c074)
- add horizontal scrolling to wide TUI panes (0b4b67d)
- apply response rules after decoding bodies (974a2c8)
- restore body decoding and shutdown handling (9ce4c46)
- show settings shortcut in footer (01b0bdf)
- shut down proxy runtime cleanly (a9e096c)
- streamline repeater footer controls (1a8e649)
- pretty print html bodies (6d98822)
- sanitize body rendering for curses (a5df1ae)
- fall back to stable HTTPS connect tunneling (75b3330)
- derive cert download url from browser origin (a9b2b0f)
- add direct local cert routes and auto-port fallback (acf6cc9)
- improve startup fallback and flow list scrolling (33a6271)

### Chores
- prepare v0.1.0 release (8d78e03)
