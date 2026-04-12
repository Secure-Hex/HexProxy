# CHANGELOG


## v0.4.0 (2026-04-12)

### Bug Fixes

- Retry trusted publishing
  ([`9fe7f7c`](https://github.com/Secure-Hex/HexProxy/commit/9fe7f7ce5b2b64a4cef01ae4a8cbb05e4bbadad1))

- **release**: Fix semantic-release configuration in pyproject.toml for changelog auto creation
  ([`60ad8c8`](https://github.com/Secure-Hex/HexProxy/commit/60ad8c86165962e87501d70612eb76feed5ce542))

- **release**: Fix semantic-release configuration in pyproject.toml for changelog auto creation
  ([`bd92642`](https://github.com/Secure-Hex/HexProxy/commit/bd926425fad44f5b1f5fb8e693fd1f2238d66623))

### Chores

- **release**: Enable changelog write mode and clean commit history for semantic-release
  ([`6f63d4a`](https://github.com/Secure-Hex/HexProxy/commit/6f63d4ad2cc69dc6949324a2146d276f961d1ec3))

### Features

- Trigger first automated release
  ([`554d680`](https://github.com/Secure-Hex/HexProxy/commit/554d6808e4d7533cd88848c690460408b4642d3b))


## v0.3.1 (2026-04-12)

### Bug Fixes

- **plugins**: Load from config directory
  ([`5afd2a9`](https://github.com/Secure-Hex/HexProxy/commit/5afd2a92f581cad6b891073ece4bb7d6ac20c48a))


## v0.3.0 (2026-04-12)

### Features

- Add startup update checker
  ([`8555caa`](https://github.com/Secure-Hex/HexProxy/commit/8555caa24a59cefa5199f98423c14c206851d3cc))


## v0.2.3 (2026-04-12)

### Bug Fixes

- Enable semantic release changelog updates
  ([`a91b615`](https://github.com/Secure-Hex/HexProxy/commit/a91b615858dd73f983aef23d7dafd88dec5ea717))


## v0.2.2 (2026-04-12)

### Bug Fixes

- Retry trusted publishing
  ([`eb73142`](https://github.com/Secure-Hex/HexProxy/commit/eb7314211442164fc834340c4bc6276122a29090))


## v0.2.1 (2026-04-12)

### Bug Fixes

- Configure semantic release github token
  ([`d0a457e`](https://github.com/Secure-Hex/HexProxy/commit/d0a457e5188a86de578b9e5324936d670ff56891))


## v0.2.0 (2026-04-12)

### Features

- Trigger first automated release
  ([`d7b0b66`](https://github.com/Secure-Hex/HexProxy/commit/d7b0b660bb64719eca6482e8dab0c7df3cdb516f))


## v0.1.0 (2026-04-12)

### Bug Fixes

- Add direct local cert routes and auto-port fallback
  ([`77e4562`](https://github.com/Secure-Hex/HexProxy/commit/77e45620dc94082c98ac19d63a95aea42dc193fb))

- Add horizontal scrolling to wide TUI panes
  ([`6b10581`](https://github.com/Secure-Hex/HexProxy/commit/6b1058189b86242f97313b60587d8617c20d83d8))

- Apply response rules after decoding bodies
  ([`d056b4c`](https://github.com/Secure-Hex/HexProxy/commit/d056b4c48bff0900c2da0f410bab736e2aa1c3fe))

- Derive cert download url from browser origin
  ([`dbb5d91`](https://github.com/Secure-Hex/HexProxy/commit/dbb5d91df4ddaac1bfd3c14058b92a4be93bc6c0))

- Fall back to stable HTTPS connect tunneling
  ([`6d5a1e0`](https://github.com/Secure-Hex/HexProxy/commit/6d5a1e0df9248e98a7c5bcb2b751795c58e2da3f))

- Hide intercept actions when interception is unavailable
  ([`a2ae8c0`](https://github.com/Secure-Hex/HexProxy/commit/a2ae8c0c5f34191ebe5d30532d2444634d72be2c))

- Honor two-key bindings and add jwt inspector plugin
  ([`1157a99`](https://github.com/Secure-Hex/HexProxy/commit/1157a99aa4da33a9c0c130b73cc142161943abd5))

- Improve startup fallback and flow list scrolling
  ([`4e9afb5`](https://github.com/Secure-Hex/HexProxy/commit/4e9afb50a283538b6ac3fc78eb383dbb3822a43a))

- Keep intercept history navigation reachable
  ([`791cb17`](https://github.com/Secure-Hex/HexProxy/commit/791cb177cfc6e4ddbe58078b458ab793f37450fd))

- Limit intercept mode changes to intercept workspace
  ([`b02f2fc`](https://github.com/Secure-Hex/HexProxy/commit/b02f2fc1d3c758894a11e7380057c9f82ed3d30e))

- Pretty print html bodies
  ([`a188fbb`](https://github.com/Secure-Hex/HexProxy/commit/a188fbbfb765fbcbdf8c34a1bcebabc77b8dcab5))

- Remove hardcoded version in mcp module and use package metadata
  ([`0a29621`](https://github.com/Secure-Hex/HexProxy/commit/0a29621bebc42624443f0e83365a8b42de57641b))

- Restore body decoding and shutdown handling
  ([`22cdf89`](https://github.com/Secure-Hex/HexProxy/commit/22cdf89e94bfb2ca197e37aa06944afc832689a7))

- Restore settings navigation after theme builder
  ([`ee6a6c2`](https://github.com/Secure-Hex/HexProxy/commit/ee6a6c2c5322797cc9b4c95a66f04463827be61e))

- Restore upward scrolling in sitemap tree
  ([`8da86d6`](https://github.com/Secure-Hex/HexProxy/commit/8da86d686fd1b2f81dc57726728e5f58ff7d60dc))

- Sanitize body rendering for curses
  ([`a12ecdc`](https://github.com/Secure-Hex/HexProxy/commit/a12ecdc56fc71e55062ea4d9a6315e06714f3493))

- Show settings shortcut in footer
  ([`ca35079`](https://github.com/Secure-Hex/HexProxy/commit/ca35079157db27be30ef328e6c0289c240384885))

- Shut down proxy runtime cleanly
  ([`c0e9714`](https://github.com/Secure-Hex/HexProxy/commit/c0e97145e96a85ce18c7825dade5767e4c65a50c))

- Stabilize theme selection navigation
  ([`420c7b1`](https://github.com/Secure-Hex/HexProxy/commit/420c7b1d21d8196802735abbe369573e252a8563))

- Streamline repeater footer controls
  ([`a4a1ebd`](https://github.com/Secure-Hex/HexProxy/commit/a4a1ebdaa139628303dbf9de1f7b2431e8a59ed1))

- Support navigation-prefixed key sequences
  ([`42077dc`](https://github.com/Secure-Hex/HexProxy/commit/42077dc00374339fca7289e629dbe9a2a762a927))

- Support wildcard scope hosts and clearer TLS errors
  ([`602fd49`](https://github.com/Secure-Hex/HexProxy/commit/602fd497ee6e72be6c4f47cc0a265533451f6f81))

- Use a stable global certificate directory
  ([`ff6328b`](https://github.com/Secure-Hex/HexProxy/commit/ff6328bb9db57c649200510e0c03219151d26ea2))

### Chores

- Disable mcp server and docs
  ([`4ab5d1f`](https://github.com/Secure-Hex/HexProxy/commit/4ab5d1f3311cb0580db0f032696c36dbd9239eee))

- Prepare v0.1.0 release
  ([`b66326b`](https://github.com/Secure-Hex/HexProxy/commit/b66326b2b15c9aa8373575b126a120d089c1a87a))

### Documentation

- Add changelog
  ([`c353e9d`](https://github.com/Secure-Hex/HexProxy/commit/c353e9d980d4eaebe697402ad2ac0bd174d1d2ed))

- Add changelog
  ([`3f8a194`](https://github.com/Secure-Hex/HexProxy/commit/3f8a194fd19de927ac457d0933fb0463568c4d42))

- Align plugin guide with runtime behavior
  ([`2cb5b06`](https://github.com/Secure-Hex/HexProxy/commit/2cb5b068bc6d00d834a2e21fb698be75a5e8c73a))

- Normalize changelog structure
  ([`cc2ae7d`](https://github.com/Secure-Hex/HexProxy/commit/cc2ae7d7078feb336a5b90dee95bd7e93768d94e))

### Features

- Add configurable global themes
  ([`c7c1ff5`](https://github.com/Secure-Hex/HexProxy/commit/c7c1ff5a9feca78b989d5523d2dac30f047a5e6b))

- Add direct workspace keybindings
  ([`931491e`](https://github.com/Secure-Hex/HexProxy/commit/931491e1ef3529400528616cd97289340104690c))

- Add export workspace and decoded response handling
  ([`16079a9`](https://github.com/Secure-Hex/HexProxy/commit/16079a9e4a0a5242526267d0b3c44331c4d6f77e))

- Add extension loading and tighten intercept actions
  ([`492d5ae`](https://github.com/Secure-Hex/HexProxy/commit/492d5ae8ba96fdb1831bf3b6509d1a464d146e70))

- Add guided match replace builder
  ([`4c1fb0e`](https://github.com/Secure-Hex/HexProxy/commit/4c1fb0e1e9c272a22dba61f16463ce11f083ace2))

- Add HTTPS interception and websocket tunneling
  ([`923cd2c`](https://github.com/Secure-Hex/HexProxy/commit/923cd2c00b678b1191f3675964eeeb09a0f8331b))

- Add interactive keybindings workspace
  ([`b396c1c`](https://github.com/Secure-Hex/HexProxy/commit/b396c1c49f330d9033c2fdedc00ef251f8921fb1))

- Add interactive scope workspace and exclusions
  ([`646cc7e`](https://github.com/Secure-Hex/HexProxy/commit/646cc7e21c3aa43963ed36419a63f1447f5ab7c2))

- Add interactive theme builder workspace
  ([`04fae6f`](https://github.com/Secure-Hex/HexProxy/commit/04fae6f941ff39075212e5a3102914ebc058d265))

- Add interactive traffic filters workspace
  ([`8ab20a6`](https://github.com/Secure-Hex/HexProxy/commit/8ab20a6f9528d6453afe1186a1400ff3d6074345))

- Add intercept scope allowlist
  ([`1fb073a`](https://github.com/Secure-Hex/HexProxy/commit/1fb073ab367c494c8ae5c5e2b5fff16450e91f4d))

- Add license
  ([`9389509`](https://github.com/Secure-Hex/HexProxy/commit/93895096207487a84f7991875167b1d0b9aa8646))

- Add local CA management and download routes
  ([`7dd0515`](https://github.com/Secure-Hex/HexProxy/commit/7dd0515cf5cdad9c808b10436f53116a3c92994e))

- Add mcp server for project automation
  ([`768faf1`](https://github.com/Secure-Hex/HexProxy/commit/768faf1e54213bdbbf3470bf93ddf73ecd0deccc))

- Add multi-session repeater workspace
  ([`4ee4613`](https://github.com/Secure-Hex/HexProxy/commit/4ee461354dad97d0080c74ae032135211bf5a3cd))

- Add persistent match and replace rules
  ([`c7ff724`](https://github.com/Secure-Hex/HexProxy/commit/c7ff72403927584677b3c6a13b9e931600424262))

- Add plugin api v2 contributions
  ([`891e1b0`](https://github.com/Secure-Hex/HexProxy/commit/891e1b0a12333db666743fc705e0bca0d9ffe80a))

- Add plugin settings and developer docs
  ([`945de11`](https://github.com/Secure-Hex/HexProxy/commit/945de11088c06644cf5da24c65b1cafcd061b056))

- Add repeater tab
  ([`528e50b`](https://github.com/Secure-Hex/HexProxy/commit/528e50baed13dd15d81dbe5db5d6e8516107df33))

- Add scope actions from flows and sitemap
  ([`6b0422e`](https://github.com/Secure-Hex/HexProxy/commit/6b0422ebfbb47804e7ac62d6b2eec77a7f0a3adc))

- Add scope visibility toggle
  ([`8451393`](https://github.com/Secure-Hex/HexProxy/commit/8451393c0abdb36e39b3ba7b89faa417d76969d0))

- Add settings workspace and keybindings
  ([`0dc0ee2`](https://github.com/Secure-Hex/HexProxy/commit/0dc0ee2113929e61a8dffdf59ee1d5d2cf946319))

- Add sitemap workspace tab
  ([`555bf7d`](https://github.com/Secure-Hex/HexProxy/commit/555bf7dde28aaff957425d2be614ce61f685c3b4))

- Add toggleable word wrap for text panes
  ([`9cc02fe`](https://github.com/Secure-Hex/HexProxy/commit/9cc02fe77ee292f0c852cbb431b40d3915982105))

- Add typed body views with pretty formatting
  ([`09033ff`](https://github.com/Secure-Hex/HexProxy/commit/09033ff2081c8d95ebd75a4690310dd220464fbb))

- Allow deleting match replace rules
  ([`d71b455`](https://github.com/Secure-Hex/HexProxy/commit/d71b45521316ebca6c339e65afc61010a3014710))

- Allow editing existing match replace rules
  ([`5eaced6`](https://github.com/Secure-Hex/HexProxy/commit/5eaced6ab1d5cff7a4b7828151c00964ce147415))

- Allow intercept queue items to be handled out of order
  ([`913eefb`](https://github.com/Secure-Hex/HexProxy/commit/913eefba166be9e4800b7c19d0e2cfc02b105dc2))

- Bootstrap terminal HTTP proxy with interception
  ([`216e360`](https://github.com/Secure-Hex/HexProxy/commit/216e360059f799b5936cdaad31200f7818b9bf44))

- Configure semantic release for package publishing
  ([`ac4128d`](https://github.com/Secure-Hex/HexProxy/commit/ac4128dcdf8b014d18b922f44a3db97a43eb5832))

- Decode body views and add pane scrolling
  ([`e9219a4`](https://github.com/Secure-Hex/HexProxy/commit/e9219a45254e6f85cc6cc6ad3affe9dd974c78c6))

- Group keybindings by sections
  ([`61b7a65`](https://github.com/Secure-Hex/HexProxy/commit/61b7a65ffd3e4c718dfee43e91e53c76b42b2668))

- Harden mcp exporter contracts and analysis tools
  ([`fbc4f22`](https://github.com/Secure-Hex/HexProxy/commit/fbc4f22188de03b57ff2149d6fa9b672642702ad))

- Hide out-of-scope traffic from views
  ([`aed93b5`](https://github.com/Secure-Hex/HexProxy/commit/aed93b5b198086723320801b4af3243a388d169d))

- Improve tui editing and repeater history
  ([`1a62bf7`](https://github.com/Secure-Hex/HexProxy/commit/1a62bf770325e86734225e769397be011237e7cc))

- Organize settings and support hex themes
  ([`4a3e0b7`](https://github.com/Secure-Hex/HexProxy/commit/4a3e0b7368359574e3350167331c154cdb664b0b))

- Persist keybindings globally
  ([`139fb0a`](https://github.com/Secure-Hex/HexProxy/commit/139fb0af0d0c66febbb5b44b89b7487e91bb5078))

- Pretty print embedded script and style
  ([`392fdb1`](https://github.com/Secure-Hex/HexProxy/commit/392fdb120b95907027381d4ba134a2cfcdcb5d40))

- Preview themes on selection
  ([`96edcfc`](https://github.com/Secure-Hex/HexProxy/commit/96edcfcb738ddac4f2cd4dfd26829cb7f09ef99d))

- Reintroduce HTTPS MITM with dedicated tunnel worker
  ([`ef8cef7`](https://github.com/Secure-Hex/HexProxy/commit/ef8cef7847d7fe400d37d45e685aa809d4071c64))

- Retain intercept history after release
  ([`13582d3`](https://github.com/Secure-Hex/HexProxy/commit/13582d37838ec2fc10fdbe52af130f1907230c8e))

- Setup semantic release pipeline
  ([`9fe14b4`](https://github.com/Secure-Hex/HexProxy/commit/9fe14b4d25f70421d432895ef371ea3232003dc2))

- Support request and response interception modes
  ([`c752865`](https://github.com/Secure-Hex/HexProxy/commit/c7528652aa3e598a6cc10ae3e4e4463c58edc915))
