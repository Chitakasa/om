# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`~/.om` is the install root (`$OM_HOME`) of **om**, a zero-daemon workspace orchestrator on Podman or Docker + Caddy, for Linux/macOS/Windows. Pure Python 3.10+ standard library (no dependencies, no build step). The repo is the program only. Machine state lives outside it (`gitops/core.py` header): settings in `$OM_CONFIG_DIR/om.env` (default `~/.config/om/om.env`, a folder other tools may share — om only ever touches `om.env`), everything generated in `$OM_STATE_DIR` (default `~/.local/state/om/`: `runtime.env`, `ports.yml`, `data/` with the Caddy root CA key and edge token, `routes/`, `auth/`, `registry/`, `firewall/`, `logs/`). Pre-split installs are migrated once by `ensure_state_migrated()` in `bin/om`. Never write state into `~/.om`.

## Commands

- Tests (no container engine needed): `cd tests && python3 -m unittest discover -s . -p 'test_*.py'`; one file: `python3 -m unittest test_routes`. They run against a temp `OM_HOME` with `OM_RUNTIME` pointing at a missing binary. Keep code Python 3.10-compatible (e.g. no backslashes inside f-string expressions); CI runs 3.10/3.12/3.13 on Linux, macOS, Windows with `-X warn_default_encoding` and `PYTHONWARNINGS=error::EncodingWarning`.
- Cross-platform rules (behavior must be identical on every OS): every text read/write passes `encoding="utf-8"` (writes also `newline="\n"`); `core.run()` decodes subprocess output as UTF-8; host paths handed to compose go through `core.compose_path()` (forward slashes); the engine socket comes from `engine_info()` (VM-side path for podman machine); line endings are pinned by `.gitattributes`. Run the strict suite locally: `cd tests && PYTHONWARNINGS=error::EncodingWarning python3 -X warn_default_encoding -m unittest discover -s . -p 'test_*.py'`.
- `om doctor` checks install + security perimeter (live attack probes) and prints fixes — run it after any network/core change.
- Core: `om core start|stop|restart|reload|update|heal|status` (`heal` is run by the `om boot enable` timer; `core_down` writes `<state>/data/stopped` so heal never revives a deliberately stopped core) — always via om (it generates `.runtime.env`/`ports.generated.yml` and passes them to compose); plain `podman compose up` in `core/` fails on the `${VAR:?}` guards by design.
- Dashboard code (`core/dashboard/app/`) is bind-mounted read-only: `podman restart om_dashboard` after edits.
- Workspace commands (`start`, `add`, `sync`, …) need a directory containing `.om/config.json`.
- Front-door host ports come from `core.edge_ports()` (`OM_HTTP_PORT`/`OM_HTTPS_PORT`, default 80/443); print URLs with `core.base_url()`, never a literal `http://localhost/`. Container-side ports (80/443/8080/8443) are fixed.
- Images are pinned to exact versions plus the multi-arch index digest (core: `tag@sha256:…`, from the registry, never a local platform digest) or major/minor (scaffolds); never introduce `latest` or bare-major tags.
- `om docs` reads `docs/*.md`, `README.md`, `CHANGELOG.md`; user-facing workflow docs go in `docs/DEVELOPER_GUIDE.md`.

## Architecture

Keyed on a **workspace id** (`.om/config.json` → `workspace_id`, default dir name; must match `SAFE_NAME_RE`, `core` reserved).

1. **CLI** — `bin/om` (argparse; `build_parser()`, `cmd_*` functions, dispatch in `main()`). Library `lib/gitops/`: `core.py` (settings resolution `auto/off/value`, engine detection, registry with cross-platform `file_lock`, core lifecycle `core_up`/`core_down`/`connect_router`, `VERSION`), `network.py` (workspace networks, validated edge reload that recreates the edge if its single-file Caddyfile mount is stale), `engine.py` (drift, `sync_workspace` with reconcile callback + health check + rollback), `secrets.py` (`om-v2` encrypt-then-MAC), `policy.py` (deploy gate on `compose config`), `egress.py` (om_egress config/credentials), `lock.py` (`.om/lock.json`, registry digests via the OCI API), `generations.py` (signature check against the trusted signer copy, hash-chained generation log), `access.py` (signed access-file chain), `door.py`, `gate.py`, `mirror.py` (off-host copy, never force-pushed), `omuser.py` (`om user setup`; `OM_RUN_AS` delegation via `sudo -u om` with the caller's process as signing broker — access.commit signs through it when `OM_SIGN_DIR` is set), `hostsetup.py` (firewall nft/pf/Windows, autosync systemd/launchd/schtasks, boot), `doctor.py`.
2. **Global core** (`core/docker-compose.yml`) — `om_wg` (the door: WireGuard, built from `core/door/`; owns the namespace and all host ports; peers rendered by `door.py` from the signed access file in `access.py`), `om_caddy` (edge; runs in `om_wg`'s namespace, so effectively **only** on `om_core_net`), `om_gate` (Authelia; config/users/rules rendered by `gate.py` from the access file + `om.access` labels; every `<ws>-<svc>.<OM_DOMAIN>` vhost uses `import gate`), `om_router` (on `om_core_net` + every `<ws>_net`), `om_egress` (Squid on `om_core_net` + every internal `<ws>_net`; config rendered by `lib/gitops/egress.py` into `<state>/egress/`), `om_sockguard` (no network; read-only filtered engine socket for the dashboard), `om_dashboard`, `portainer`.
3. **Dashboard** — `core/dashboard/app/server.py` (stdlib `http.server`; container listing via `om_sockguard`'s filtered socket, never the raw engine socket) + `index.html`.

### Routing is generated, not hand-written

`sync_caddy_routes` writes into `$OM_STATE_DIR/routes/` (mounted at `/etc/caddy/conf.d`) from each workspace's compose files (`parse_service_meta`: `dashboard.port` label > port lines > 8080; public only with `dashboard.scope=public`):
- `<ws>-<svc>.caddy` — `http://<ws>.<svc>.localhost`; `<ws>-<svc>.public_subpath` / `.private_subpath` — `/<svc>/` handlers.
- Change `render_vhost`/`render_subpath`, never the generated files. om's own hand-written routes (`00-info.caddy`, `portainer.*`) are program files in `core/caddy/conf.d/`, mounted at `/etc/caddy/core.d`.
- Routes of a workspace whose folder is gone are pruned by `prune_orphan_routes` (on `om start`, `om core start|restart|reload`) unless its containers may still run; `om doctor` reports them. The header `# Service: <svc> (<ws>)` records ownership; only owned files are written/pruned — keep that format.

### Security model (do not regress)

- Tiers: loopback/Tailscale → edge `:80/:443` (private: explicit host list + final `:80 { abort }`, optional `basic_auth` via `import private_auth`); LAN → edge `:8080/:8443` (public: only `*.public_subpath`, sets `X-Access-Scope: public`). `server.py` strips private data for public scope, enforces a Host allowlist and CSRF checks.
- Edge → workspace services **only** via `import to_workspace <ws>_<svc>:<port>`, which sets `X-Om-Edge-Token` (secret in `<state>/data/edge_token`) and `X-Om-Upstream`; `core/caddy/router/Caddyfile` aborts anything without the exact 64-hex token or with an `om_*` / malformed upstream. Never attach `om_caddy` to workspace networks and never `reverse_proxy <ws>_<svc>` directly from the edge.
- Services use `expose:`, never `ports:`. Core containers are `read_only`, `cap_drop: ALL` (+`NET_BIND_SERVICE`, required by the caddy binary's file capability under no-new-privileges).
- Firewall (`om firewall`) uses its own nft table `inet om_guard`; never `flush ruleset`.

### Compose conventions

`discover_compose_dirs` finds compose files at the workspace root and depth 1–2, ordered by a `# priority: N` line; a folder containing `.omignore` (and everything below it) is skipped. Labels drive the dashboard: `dashboard.name|icon|description|port|scope|hide|web|path|search|search_url`, `workspace.id`, `om.core`.
Labels also shape routes (`route_options`): `om.route.keep_prefix=true` (proxy `/<svc>/` unstripped, vhost `/` redirects there), `om.route.aliases=/a,/b` (redirect top-level paths into `/<svc>/`, `{uri}` kept), `om.route.dashboard_paths=/api/x*` (paths on the vhost served by the dashboard). Label paths are validated by `ROUTE_PATH_RE` before they reach Caddy. `om.access=shared|member|private` (missing = private) decides the gate rule for a service's `<ws>-<svc>.<OM_DOMAIN>` vhost. `om.egress=host,*.host|learn|internet` gives a service its own `om_egress` credential via an om-generated compose override (`<state>/egress/overrides/`). `om.policy.allow=<rule>,…` waives policy-gate rules (`lib/gitops/policy.py`: `WAIVABLE`; `privileged`/`ports` are laws) for that service only.

**om is generic, like git.** Never special-case a service or workspace name, a hostname or a user path in om's code: if a service needs different behavior, add or use a label and set it in the workspace's compose file. om touches the host only in the explicit opt-in commands (`om firewall`, `om boot`, `om autosync`); it never edits files like `/etc/hosts`. Workspace-specific docs live in the workspace, not in `docs/`. `get_workspace_env` injects `WORKSPACE_ID`, `COMPOSE_PROJECT_NAME`, `WORKSPACE_ROOT`, `DATA_DIR`, `WORKSPACE_DATA`, `WORKSPACE_NET`, `DOCKER_SOCK`. Machine-local workspace state (`.om/local.json` autosync switch, `.om/state.json`, `.om/trash/`) is hidden via `.git/info/exclude` so it never dirties the repo (a dirty tree blocks `om sync`).

## Token-saving rules

### Reading files
- Search for the function or keyword first (grep), then read only
  those lines, not the whole file
- Don't re-read a file already read in this session unless it changed
- Skip node_modules, dist, build, .git, lock files, and minified
  files unless I ask or you're debugging an error that points there
- Skip log files unless I ask or an error message references them

### Working
- Make the smallest change that fixes the problem; don't refactor
  or reformat code I didn't mention
- Don't create new files unless needed
- Run only the test file related to the change; run the full
  suite once at the end
- If a task touches more than 3 files, stop and show a plan first

### Answering
- Keep replies under 5 sentences unless I ask for detail
- Don't repeat my question back or summarize what you just did
- Show only the changed lines, not the whole file