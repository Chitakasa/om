# Changelog

## Unreleased

### The door (phase 3, first part)
- New core container `om_wg`: WireGuard (kernel, or `wireguard-go` fallback) built locally from a pinned Alpine with the distribution's `wireguard-tools`. It owns the network namespace and host port bindings; `om_caddy` runs inside it (`network_mode: service:door`) so the edge sees each device's tunnel address. The door's UDP port (`OM_DOOR_PORT`, 51820) is published on the LAN address; `om firewall` opens it.
- The signed access file (`<state>/access/<n>.json` + `.sig`): each version names the previous one by SHA-256 and must be signed (`ssh-keygen -Y`, namespace `om-access`) by an owner listed in the previous version (`OM_OWNER_KEY`, default `~/.ssh/id_ed25519`; a hardware key later). `om access [show|verify]`.
- `om device add <name>` (QR code for the WireGuard app; or `--pubkey` for a key the device made itself), `om device list`, `om device revoke <name>`: each is one signed access version; peers reload without dropping tunnels. Enrolled devices reach the private tier at `http://10.77.0.1/` (today's tiers stay open alongside). `om doctor` checks the chain, the door's peers and that it stays silent to keyless packets (*Door*).

### Generations (phase 2)
- `.om/lock.json` pins every pulled image to its registry index digest; `om start`/`sync` apply it through an om-generated override, so a re-pushed tag changes nothing. `om lock` pins what runs now; `om update` moves to the newest digests, commits the lock and redeploys through the normal start path (policy gate and egress included).
- Signed deploys: a clean commit must be signed by a key in the workspace's `.om/allowed_signers`, checked against om's trusted copy from the last deployed generation (a commit cannot trust itself). `OM_SIGNED=warn|enforce`; `om sync` checks the incoming commit before pulling. A dirty tree runs as an unsigned *dev* generation. `om init` writes your git SSH signing key into `.om/allowed_signers`.
- Every deploy is a numbered generation in `<state>/generations/<ws>/`, hash-chained. `om log`, `om rollback [n]` (detached checkout of that commit; data is not rolled back), `om fsck` (chain, signature, running images vs lock); `om status` shows the current generation and any change since; `om doctor` checks every workspace (*Generations*).

### Workspaces
- A folder containing an `.omignore` file is not part of the workspace: `om start/stop/sync/policy` skip it (for a compose project you run some other way).

### Hardening (phase 1)
- Dashboard sends a strict Content-Security-Policy (only its own inline script, by hash); inline event handlers removed; `dashboard.url` must be http(s) or a relative path.
- New `om_sockguard` (no network) gives the dashboard a read-only engine API: `GET` container list and stats only, everything else 403. The dashboard no longer mounts the engine socket. `om doctor` probes it (*Engine filter*).
- Portainer is off by default (`OM_PORTAINER=off` in `om.env`): it holds the raw engine socket, and administration belongs at the console. Set `OM_PORTAINER=on` and run `om core restart` to bring it back; its data volume is kept.
- Policy gate: `om start`/`om sync` check each compose file (via `compose config`) for `privileged`, host namespaces, `ports:`, engine sockets and sensitive host mounts, capabilities beyond the engine default set, `devices`, and disabled seccomp/AppArmor/SELinux. `OM_POLICY=warn` (default) reports and starts anyway; `OM_POLICY=enforce` refuses the file. `om policy check [--all]` runs it alone. A service can waive a rule for itself with `om.policy.allow=host-namespace|caps|devices|unconfined|mounts` (comma-separated); waivers stay listed by `om policy check`. `privileged` and `ports` cannot be waived, and an unknown rule is itself a violation.
- Outbound access is per service (ADR 0002): new workspace networks are `internal` (no route out, no external DNS); `om network harden` converts an existing one. New core container `om_egress` (Squid, hardened, pinned) lets a service reach only the hosts in its `om.egress` label, with its own credential injected by om (`om.egress=internet` only without writable volumes or secrets; `om.egress=learn` temporarily allows any public host and records each one; `om doctor` warns while it is on). `om egress log` prints the hosts a learning service used, or the hosts a listed service was refused, with the label to set. `om doctor` probes each internal network (*Egress*).
- Core images pinned by multi-arch index digest as well as version (`caddy:2.11.6@sha256:…`), so a re-pushed tag cannot change what runs.

### Reproducible
- Core images pinned to exact versions (`caddy:2.11.6`, `python:3.14.8-alpine`, `portainer-ce:2.45.1`); `om add` scaffolds `nginx:1.31-alpine` / `node:24-alpine` instead of moving tags. The same om version now runs the same core everywhere.

### Builds
- `om start --build` / `om restart --build` rebuild images of services with a `build:` section; `om dev` and `om sync` (incl. autosync) always rebuild, so a pulled Dockerfile change is applied.
- `om update` rebuilds any service with `build:` (any Dockerfile/Containerfile name), not only a file named `Dockerfile`, and reports build failures.
- `om start` warns when a compose file doesn't join `<ws>_net` (its routes would return 502).

### Several people
- `om auth add|remove|list <user>`: one private-tier login per person (`set` still replaces all).
- `OM_HTTP_PORT` / `OM_HTTPS_PORT` in `om.env` (default 80/443) let a second OS user run om on the same machine; firewall, doctor, health checks, CLI URLs and dashboard links follow them.

### Docs
- `om docs [name] [--path]` lists the guides or reads one in a pager.
- New `docs/DEVELOPER_GUIDE.md`: creating containers, when to rebuild an image, debugging a workspace.

### Known limitations
- Flow-style `labels: [...]` are not read for routing (the route falls back to port 8080); write one label per line.
- Custom `OM_HTTP_PORT` / `OM_HTTPS_PORT` are unit-tested only, not yet with a real second OS user.
- Builds, sync and rebuilds were verified live on Linux (Podman); macOS and Windows are covered by CI tests only.
- Existing installs switch to the pinned core images on the next `om core update`.

## 1.0.0 — 2026-10-06

First release intended for use on any machine.

### Security
- **Edge/router split.** The edge proxy (`om_caddy`) is no longer attached to workspace networks; an internal router (`om_router`) is, and it forwards only requests carrying a 256-bit secret known to the edge. Containers can no longer reach the private tier, Portainer, or other workspaces. Works identically on Podman, Docker and Docker Desktop.
- Private tier answers only an explicit host list (DNS-rebinding safe); dashboard enforces a host allowlist and CSRF checks.
- Host firewall generator for Linux (nftables), macOS (pf) and Windows (`om firewall`).
- Optional login for the whole private tier (`om auth set <user>`).
- Services are scaffolded with `expose:` (never `ports:`); `om start`, `om ports` and `om doctor` flag published ports.
- Hardened core containers (read-only root, minimal capabilities, no-new-privileges); `trusted_proxies` removed at the edge.
- Dashboard: workspace ids validated (no path traversal), public scope pinned to core data, safe uploads, no SVG from the dashboard origin.
- Secrets vault `om-v2`: encrypt-then-MAC (HMAC-SHA256), PBKDF2 600k; `om-v1` still decrypts.
- Caddy CA keys, tokens and runtime state are git-ignored.

### Reliability
- Machine-specific values (LAN/Tailscale addresses, engine socket, wallpapers) are detected at `om core start` (`core/.env`: `auto`/`off`/value); no hard-coded user paths or IPs.
- `om core start/restart` reattaches the router to every workspace and verifies all core containers stay up.
- Self-heal (`om core heal`, scheduled by `om boot enable` at boot and every 2 minutes): recovers from a new LAN address, Tailscale coming up late, or a crashed core container; respects a deliberate `om core stop`.
- GitOps: refuses dirty trees, reconciles containers after a pull, health-checks every vhost, rolls back, and quarantines a failing remote commit for scheduled syncs.
- Route generator records ownership in each file, prunes stale routes (incl. on `om list --prune`), detects subpath collisions, validates names.
- Edge reload validates first and recreates the edge if its Caddyfile bind mount is stale.
- LAN HTTPS works (certificate for the LAN IP, used when clients send no SNI).

### New commands
`remove`, `logs`, `shell`, `update`, `doctor`, `auth`, `firewall`, `boot`, `autosync`, `secrets`, `completion`, `uninstall`, `version`/`--version`, `core update`, `list --prune`.

### Fixed
- `om add` produced services that answered 502 (nginx listens on 80) and projects that exited immediately.
- `om core start/restart` left workspaces unreachable.
- `om list` silently deleted registry entries for unplugged drives.
- Windows: no `fcntl`; scripts can be `.ps1`; colors via VT mode; installer `install.ps1`.
