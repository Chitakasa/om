# ⚡ om — Master Operations & Architectural Guide

**The Definitive Reference for the `om` Universal Workspace & GitOps Platform**

---

## 1. Core Architectural Philosophy & Mental Model

### The Git Mental Model
`om` is modeled directly after `git`:
* **Global CLI (`om`)**: A lightweight command-line engine available everywhere on your system (`~/.local/bin/om -> ~/.om/bin/om`).
* **Zero Resident Daemon**: Unlike Kubernetes, Nomad, or Portainer Agents that run persistent 200MB–1GB background processes, `om` executes on demand, completes tasks in milliseconds, and terminates immediately. It consumes **0 MB resident background RAM**.
* **Autonomous Workspace Capsules**: Every directory containing an `.om/config.json` is a self-contained, fully encapsulated environment with its own isolated network fabric, persistent data capsules, compose configs, and automation scripts.
* **Program, settings and state kept apart (like git)**: `~/.om/` holds only the program — reinstall or update it freely. Your machine settings live in `~/.config/om/om.env` (like `~/.gitconfig`) and everything om generates lives in `~/.local/state/om/` (on Windows both live in `%LOCALAPPDATA%\om`); each workspace's own state lives in its `.om/` folder (like `.git/`). The same layout is used on Linux, macOS and Windows, and `OM_CONFIG_DIR` / `OM_STATE_DIR` move it.
* **Zero External Dependencies**: Implemented strictly in **Python 3 Standard Library** (`pathlib`, `json`, `subprocess`, `socket`, `argparse`). Zero `pip` packages required, zero virtual environments to manage, zero supply-chain vulnerabilities.

```text
Host System (Linux / macOS / Windows)
  │
  ├── ~/.om/                                   ← The program only (reinstall/update freely)
  │    ├── bin/om                              ← CLI executable (symlinked to ~/.local/bin/om)
  │    ├── lib/gitops/                         ← Python engine (engine.py, network.py, secrets.py)
  │    ├── core/                               ← Core compose file, Caddyfiles, dashboard app
  │    └── docs/                               ← Platform specifications & architecture guides
  │
  ├── ~/.config/om/om.env                      ← Your machine settings (auto / off / value)
  ├── ~/.local/state/om/                       ← Generated state: CA, token, routes, registry, logs
  │
  └── Workspace: ~/my-workspace/               ← 100% User Work Territory
       ├── .om/config.json                     ← The ONLY requirement (workspace descriptor)
       ├── services/                           ← Web apps & system daemons (optional convention)
       ├── projects/                           ← Developer apps (optional convention)
       ├── scripts/                            ← Workspace automation utilities (optional)
       ├── data/                               ← Persistent capsule storage (git-ignored)
       └── vbox/                               ← Personal user sandboxes / Containerfiles
```

---

## 2. Dynamic Workspace Inspection & Directory Layout Freedom

### The Single Anchor Rule
There is **only one single requirement** that defines a directory as an `om` workspace:
* The existence of **`.om/config.json`** in the root of the directory.

This is identical to how `git` works: a directory is a Git repository because it contains `.git/`. What you put inside is 100% your choice.

### Complete Layout Freedom: Convention Over Configuration
Directories like `services/`, `projects/`, `scripts/`, and `data/` are **helpful conventions** scaffolded by `om init`, but they are **not mandatory constraints**.

`om`'s compose discovery engine is **fully layout-agnostic**:

```
                       WORKSPACE ROOT (.om/config.json)
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        ▼                              ▼                              ▼
  [FLAT LAYOUT]               [MODULAR CONVENTION]           [CUSTOM ARBITRARY]
  docker-compose.yml          ├── services/                  ├── apps/
  (Runs monolithic stack      │   ├── jellyfin/              │   ├── frontend/
   from workspace root)       │   └── searxng/               │   └── backend/
                              └── projects/                  ├── stack/
                                  └── my-site/               │   └── database/
                                                             └── vbox/
                                                                 └── Containerfile
```

1. **Flat / Monolithic Layout**:
   - You can place a single `docker-compose.yml` (or `compose.yaml`) right in the workspace root.
   - Running `om start` discovers and executes the root compose file.
2. **Modular Convention (`services/` & `projects/`)**:
   - Great for homelabs and multi-service repositories.
   - `om` scans subdirectories inside `services/` and `projects/` and boots them in priority order.
3. **Custom / Arbitrary Directory Structures**:
   - You can name your folders anything you want: `apps/`, `backend/`, `frontend/`, `stack/`, `vbox/`, `sandbox/`, or `infra/`.
   - `om` dynamically inspects:
     * **Depth 0**: The workspace root itself.
     * **Depth 1**: Any immediate subdirectory containing a compose file (e.g. `vbox/docker-compose.yml` or `apps/docker-compose.yml`).
     * **Depth 2**: Nested subdirectories (e.g. `apps/frontend/docker-compose.yml`, `stack/postgres/docker-compose.yml`).
   - Standard non-workload folders (`data`, `.om`, `.git`, `docs`, `scripts`, `overrides`, `__pycache__`) are automatically skipped.

### Supported Compose Filenames
The engine automatically detects any standard OCI compose filename:
* `docker-compose.yml`
* `docker-compose.yaml`
* `compose.yml`
* `compose.yaml`

### Priority-Based Boot Ordering
Inside any `docker-compose.yml`, you can specify a startup priority comment:
```yaml
# priority: 10
services:
  db:
    image: postgres:alpine
```
* **Lower numbers start first**: Priority 10 boots before Priority 50.
* Unspecified compose files default to priority 50.
* This ensures databases and infrastructure dependencies start before frontend services.

### What Are Custom Sandboxes (e.g., `vbox`)?
Directories like `vbox/` containing a `Containerfile` or `Dockerfile` are **user-defined sandbox environments**:
* `vbox/Containerfile` builds an isolated Arch Linux environment with `neovim`, `git`, `python`, etc.
* `vbox` is **not a platform requirement**, is not enforced on other workspaces, and `om` will never tamper with it.
* If you want `om` to start `vbox` as a persistent container service, simply add a `docker-compose.yml` inside `vbox/`, and `om` will automatically discover and run it!

---

## 3. Multi-Tenancy Without Port Collisions

Workspaces never bind host ports. Every service is reached through the single edge proxy on 80/443 by name (`http://<workspace>.<service>.localhost`), so any number of workspaces — even with identically named services — run side by side without conflicts. Each workspace has its own bridge network (`<workspace>_net`); workspaces cannot reach each other.

```bash
# View all registered workspaces across the machine
om list

# Show the host's port bindings (only the edge should appear) and flag any leaks
om ports
```

---

## 4. DNS Routing & Zero-Downtime Reverse Proxy

### The RFC 1123 & RFC 6761 Standard
All web services are exposed via standard subdomain routing:
```text
http://<workspace>.<service>.localhost
```
* **Examples**:
  * `http://containers.searxng.localhost/`
  * `http://containers.jellyfin.localhost/`
  * `http://core.portainer.localhost/`
  * `http://perso.pep.localhost/`
  * `http://containers.dashboard.localhost/` (or `http://localhost/`)

#### Why this is superior:
1. **RFC 1123 Hostname Compliant**: Uses only standard alphanumeric characters and dots. Resolves cleanly in all modern browsers (Firefox, Chrome, Zen, Safari) without underscore parsing failures.
2. **RFC 6761 Automatic Loopback**: Every subdomain ending in `.localhost` resolves natively to `127.0.0.1` and `::1` inside the operating system's resolver (glibc / systemd-resolved / macOS mDNSResponder) with **0ms latency** and **zero `/etc/hosts` editing**.
3. **No Collision Between Workspaces**: If you have two workspaces named `containers` and `perso`, both running a service named `web`, their URLs never conflict:
   * `http://containers.web.localhost/`
   * `http://perso.web.localhost/`

### Modular Reverse Proxy Architecture
Caddy manages traffic dynamically through decoupled, modular configuration files without hardcoding:
* Core configuration: `~/.om/core/caddy/Caddyfile`
* Modular virtual hosts: `~/.local/state/om/routes/<workspace>-<service>.caddy`
* Public subpaths (LAN + Tailscale): `~/.local/state/om/routes/<workspace>-<service>.public_subpath`
* Private subpaths (Tailscale only): `~/.local/state/om/routes/<workspace>-<service>.private_subpath`

### Dual-Tier Network Security & Zero-Knowledge Privacy
1. **Private Ingress (Ports 80 & 443)**: Bound strictly to Loopback (`127.0.0.1`, `[::1]`) and Tailscale (`100.x.x.x`). Serves all `.localhost` subdomains and private workloads. Answers only an explicit host list, and only to host-forwarded connections (containers cannot reach it — see [Network Architecture §3](NETWORK_ARCHITECTURE.md)).
2. **Public Ingress (Container Ports 8080 & 8443 / LAN)**: Bound strictly to Host LAN IP `192.168.1.5:80 -> 8080`. Only public services and dynamically imported `*.public_subpath` files exist in this route table.
3. **Zero-Knowledge API Privacy**: `/api/workspaces` strips all workspace names and paths for LAN visitors. `/api/system` and `/api/wallpapers` return HTTP 403 Forbidden.

### Rules for services (enforced or warned by `om`)
* **Public is opt-in**: a service is on the LAN only with the label `dashboard.scope=public` (`om add --public` / `om edit --scope public`). Everything else is private.
* **Never `ports:`** — use `expose:`. A published port bypasses Caddy and lands on every host interface. `om add` scaffolds `expose:`; `om start`, `om ports` and `om doctor` flag any workspace container publishing a host port. The host firewall (`om firewall apply`) drops such ports anyway.
* **Mount only what a service needs**: never `/home` wholesale (it contains `~/.ssh` and `~/.om`'s CA keys). Mount specific folders at their host paths.
* **Names**: workspace ids and service folder names must be lowercase letters, digits and `-` (they become hostnames and Caddy config). `core` is reserved.
* Remove services with `om remove <svc>` (stops it, prunes its routes, moves the folder to `.om/trash`). Deleting a folder by hand also drops its routes on the next `om start`/`om reload`.

When you add or modify a service, `om` writes isolated snippets into `conf.d/` and triggers a hot-reload. The reload executes in **< 50 milliseconds** with **zero dropped TCP connections**.

```bash
# Hot-reload routing table manually
om reload

# View active reverse-proxy routes and access policies
om routes

# Inspect visual ASCII bridge network channels
om network
```

---

## 5. Model A: Universal Platform Core & Pure User Territory

The platform establishes an absolute architectural separation between the **Global Platform Core Substrate** (`~/.om/core/`) and **User Work Territories** (`/home/cyber/Containers`, `/home/cyber/perso`):

### Why Model A (Universal Core) is Superior:
1. **100% Pure User Territory**: Workspaces contain only what the user creates. Platform reverse proxies, portal code, and CLI shims never pollute user repositories.
2. **Universal Dynamic Dashboard (`http://localhost/`)**:
   - The Universal Dashboard lives at `~/.om/core/dashboard` and runs at the host level.
   - It queries the container socket and discovers **all** running and stopped containers across **all** workspaces on the machine.
   - It features an interactive **Workspace Switcher** (`[ 🌐 All ] [ 📁 containers ] [ 📁 perso ] ...`).
   - Accessing `http://containers.dashboard.localhost` automatically filters the view to that specific workspace.
3. **Single Front Door**: One edge proxy (`om_caddy`) handles all routing on 80/443 and sits only on the core network. An internal router (`om_router`), attached to every workspace network, forwards only requests signed by the edge — see [Network Architecture §3](NETWORK_ARCHITECTURE.md).
4. **Resilient Visibility**: Stopping all services in a workspace leaves the Universal Dashboard and Ingress live at `http://localhost/`, clearly showing stopped container states.

```bash
# User Workloads (Preserves Global Ingress & Universal Dashboard):
om start               # Auto-ensures Global Core is up, then starts all user workloads
om start searxng       # Start specific user service
om stop                # Graceful stop of user workloads (Universal Dashboard remains active)
om stop jellyfin       # Stop specific service
om stop --all          # Full teardown of both user workloads and Global Core
om down                # Clean workspace shutdown (alias for om stop --all)
om restart             # Restart user workloads & hot-reload Caddy routes

# Dedicated Global Core Substrate Management:
om core status         # Check Global Caddy & Dashboard health
om core start          # Boot Global Core substrate only
om core stop           # Stop Global Core substrate only
om core restart        # Restart Global Core substrate
om core reload         # Hot-reload Caddy routes with zero downtime
```

---

## 6. Developer Mode (`om dev`)

When developing custom applications inside `projects/<name>` (or any project directory):
```bash
om dev <project-name>
```
1. Verifies the project's `docker-compose.yml` and network attachment.
2. Boots the container with live code volume mounts (`./src:/app/src:Z`).
3. Streams live hot-reload logs directly to your terminal.
4. Pressing `Ctrl+C` detaches from the log stream without stopping the container.

---

## 7. Script Execution Engine (`om scripts` & `om run`)

`om` includes a built-in automation runner that executes workspace scripts with pre-injected environment context:

```bash
# List all workspace automation scripts with type and descriptions
om scripts
```

```bash
# Execute any script by name (flat or nested)
om run system_info
om run RAM_and_Swap_clean
om run Git/git
om run UpdaterWithOption
```

### Automatic Environment Injection
Every script executed via `om run` automatically inherits:
* `WORKSPACE_ID`: Current workspace identifier (e.g. `containers`, `perso`)
* `WORKSPACE_ROOT`: Absolute path to workspace root
* `WORKSPACE_DATA`: Absolute path to `data/` capsule directory
* `WORKSPACE_NET`: Active bridge network name (e.g. `containers_net`, `perso_net`)

---

## 8. Data Capsule Pattern & State Separation

The platform enforces a strict separation between **Platform Internal State** and **User Application Data**:

### User Workload Capsules (`data/`)
All persistent container data for user applications and daemons is isolated in the root `data/` directory:
```text
data/
├── searxng/
├── jellyfin/
└── backup/
```
* **Git-Ignored**: Data never pollutes the repository.
* **One-Step Backups**: Backing up your entire user homelab state simply requires snapshotting the `data/` directory.
* **Clean Deletion**: Removing a service via `rm -rf services/<name>` preserves `data/<name>` until you explicitly choose to delete it.

### Core Platform Internal State (`~/.local/state/om/data/`)
Internal runtime caches and metadata for the core platform substrate are stored in `~/.local/state/om/data/` (set `OM_STATE_DIR` to move it), never inside `~/.om`:
```text
~/.local/state/om/data/
├── caddy/             # Auto-provisioned TLS certificates and OCSP cache
├── caddy_config/      # Auto-saved Caddy runtime configuration
└── dashboard/          # Dynamic dashboard wallpaper and settings
```
* Completely separated from user application capsules.
* Re-generated automatically if wiped (a wiped `caddy/` means a new local CA that browsers must trust again).
* **Git-ignored**: `caddy/pki/` holds the local root CA private key — whoever has it can impersonate any HTTPS site to a browser that trusts this CA.

---

## 9. GitOps Dual-Speed Engine (`om drift` & `om sync`)

`om` bridges local development and automated GitOps infrastructure:

### Interactive Drift Inspection (`om drift`)
Compares the live workspace configuration against remote Git tracking branches:
* Uncommitted local edits
* Divergent commits between local `main` and `origin/main`
* Stale container images

```bash
om drift
```

### Pull Reconciliation with Auto-Rollback (`om sync`)
```bash
om sync
```
1. **Refuses to run on a dirty tree** — commit or stash first (both `--force` and rollback use `git reset --hard`, which would destroy uncommitted work).
2. Fetches and pulls the workspace's `tracked_branch` from `.om/config.json` (default `main`) with `git pull --ff-only` (or `--rebase` / `--force`).
3. Reconciles: regenerates Caddy routes and runs `compose up -d` for every service (same as `om start`).
4. Probes every workspace vhost through the private ingress (`127.0.0.1:80` with each `Host`) for up to 60 seconds; a 5xx or no answer counts as unhealthy.
5. **Automated Rollback**: if unhealthy and `gitops.auto_rollback` is not `false`, resets to the previous commit and reconciles again.

```bash
# Force reset workspace state strictly to remote branch (still refuses on a dirty tree)
om sync --force

# Rebase local commits on top of remote
om sync --rebase
```

### Scheduled Auto-Sync (`om autosync`)
```bash
om autosync on --every 5     # this machine syncs this workspace every 5 minutes
om autosync status           # scheduler state, per-workspace last result
om autosync off
```
* Uses the OS scheduler: a systemd user timer (Linux), a launchd agent (macOS) or Task Scheduler (Windows).
* The on/off switch and sync state live in `.om/local.json` / `.om/state.json`, which om hides via `.git/info/exclude` — turning auto-sync on never dirties the repository.
* Skips a workspace with uncommitted changes (logged).
* **Quarantine:** if a pulled commit fails its health check, it is rolled back and that remote commit is skipped on later runs until a new commit is pushed — a broken push is deployed once, not every interval.
* Log: `~/.local/state/om/logs/autosync.log`.

---

## 10. Operational Command Cheat Sheet

| Task | Command |
| :--- | :--- |
| Status of core + workspace | `om` / `om status` |
| Start / stop / restart | `om start [svc] [--build]` · `om stop [svc]` · `om restart [svc] [--build]` |
| Stop workspace and core | `om down` |
| Scaffold a service | `om add <name> [--public] [--image I --port P] [--no-web]` |
| Scaffold a live-reload project | `om add <name> --project` then `om dev <name>` |
| Change scope/port/labels | `om edit <svc> --scope public` |
| Remove a service | `om remove <svc> [--data]` |
| Update images | `om update [svc]` · core: `om core update` |
| Logs / shell | `om logs <svc> -f` · `om shell <svc> [cmd…]` |
| URLs / network / ports | `om routes` · `om network` · `om ports` |
| Scripts | `om scripts` · `om run <script>` |
| GitOps | `om drift` · `om sync` · `om autosync on` |
| Core | `om core start\|stop\|restart\|reload\|update\|status` |
| Diagnose everything | `om doctor` |
| Security | `om firewall apply` · `om auth add <user>` (one login per person) |
| Reboot persistence | `om boot enable` |
| Secrets | `om secrets encrypt <file>` · `om secrets decrypt <file.enc> -o <file>` |
| Workspaces | `om list [--prune]` |
| Shell completion | `om completion bash\|zsh\|fish` |
| Read the docs | `om docs` · `om docs developer` |
