# Changelog

## Unreleased

### Network: your VPN is the door (ADR 0003)
- `OM_VPN=auto|off|<list>` (replaces `OM_TAILSCALE_IP`/`OM_TAILSCALE_HOST`; `OM_TAILSCALE_IP=off` still means off): the private tier answers on loopback and on the addresses of the VPNs named — `auto` is Tailscale when it is up; WireGuard, ZeroTier, NetBird or Headscale interfaces and addresses are listed explicitly (a commercial VPN's tunnel is never trusted automatically). Tailscale's MagicDNS names are answered too, so `http://<machine>/<svc>/` works from every device on your tailnet.
- VPN addresses also serve the public tier on `:8080`/`:8443`, so a VPN's own access rules (e.g. a Tailscale ACL allowing only port 8080 to a shared user) give a guest exactly the `dashboard.scope=public` services. `om firewall` opens 8080/8443 for VPN addresses only.
- `om doctor` *VPN*: which VPN reaches the private tier, and with Tailscale whether Tailnet Lock guards who joins. *Admin surface* checks the edge's listeners. *Login* warns only when other people can log in to this machine.
- Removed, with everything they needed (ADR 0003 explains why): the WireGuard door (`om_wg`, dnsmasq, `om device`), the Authelia gate (`om_gate`, passkeys, `om invite/pending/approve/revoke`, `om grant/ungrant`), the signed access file (`om access`) and the `om.access` label, `OM_DOMAIN` and `.internal` names, `om tiers`, the off-host mirror (`om mirror`), the separate OS user (`om user`, `OM_RUN_AS`), `om host quiet`, and Portainer. `om core start` deletes their containers, their state and the gated sites in generated routes.

### Secrets
- Service secrets with age (GOALS G2): `om secrets init` (host key in `<state>/data/age.key`, recipients in `.om/age-recipients`: this host and your SSH key), `om secrets set <project>/<name>` (value from stdin; writes `<project>/secrets/<name>.age`), `om secrets list`. A service declares it with compose's own `secrets:` (`file: ./secrets/<name>`); `om start` decrypts into `$XDG_RUNTIME_DIR` (memory) and compose mounts it read-only at `/run/secrets/<name>` — never an environment variable. `om stop` wipes the decrypted copies. `age` runs in a locally built, pinned `om-tools` image, so the host needs nothing installed. A plaintext secret file in the workspace is refused by the policy gate. The built-in `om-v2` format is read-only (decrypt, for migration).

### Updates and new services
- `om update --dry-run` lists images whose tag now points at a newer digest; the heal timer checks every 6 hours and `om status` shows "updates N available".
- `om add` pins the new image in `.om/lock.json` right away.

### Generations (phase 2)
- `.om/lock.json` pins every pulled image to its registry index digest; `om start`/`sync` apply it through an om-generated override, so a re-pushed tag changes nothing. `om lock` pins what runs now; `om update` moves to the newest digests, commits the lock and redeploys through the normal start path (policy gate and egress included).
- Signed deploys: a clean commit must be signed by a key in the workspace's `.om/allowed_signers`, checked against om's trusted copy from the last deployed generation (a commit cannot trust itself). `OM_SIGNED=warn|enforce`; `om sync` checks the incoming commit before pulling. A dirty tree runs as an unsigned *dev* generation. `om init` writes your git SSH signing key into `.om/allowed_signers`.
- Every deploy is a numbered generation in `<state>/generations/<ws>/`, hash-chained. `om log`, `om rollback [n]` (detached checkout of that commit; data is not rolled back), `om fsck` (chain, signature, running images vs lock); `om status` shows the current generation and any change since; `om doctor` checks every workspace (*Generations*).

### Workspaces
- A folder containing an `.omignore` file is not part of the workspace: `om start/stop/sync/policy` skip it (for a compose project you run some other way).

### Hardening (phase 1)
- Dashboard sends a strict Content-Security-Policy (only its own inline script, by hash); inline event handlers removed; `dashboard.url` must be http(s) or a relative path.
- New `om_sockguard` (no network) gives the dashboard a read-only engine API: `GET` container list and stats only, everything else 403. The dashboard no longer mounts the engine socket. `om doctor` probes it (*Engine filter*).
- Policy gate: `om start`/`om sync` check each compose file (via `compose config`) for `privileged`, host namespaces, `ports:`, engine sockets and sensitive host mounts, capabilities beyond the engine default set, `devices`, and disabled seccomp/AppArmor/SELinux. `OM_POLICY=warn` (default) reports and starts anyway; `OM_POLICY=enforce` refuses the file. `om policy check [--all]` runs it alone. A service can waive a rule for itself with `om.policy.allow=host-namespace|caps|devices|unconfined|mounts` (comma-separated); waivers stay listed by `om policy check`. `privileged` and `ports` cannot be waived, and an unknown rule is itself a violation.
- Outbound access is per service (ADR 0002): new workspace networks are `internal` (no route out, no external DNS); `om network harden` converts an existing one. New core container `om_egress` (Squid, hardened, pinned) lets a service reach only the hosts in its `om.egress` label, with its own credential injected by om (`om.egress=internet` only without writable volumes or secrets; `om.egress=learn` temporarily allows any public host and records each one; `om doctor` warns while it is on). `om egress log` prints the hosts a learning service used, or the hosts a listed service was refused, with the label to set. `om doctor` probes each internal network (*Egress*).
- Core images pinned by multi-arch index digest as well as version (`caddy:2.11.6@sha256:…`), so a re-pushed tag cannot change what runs.

### Reproducible
- Core images pinned to exact versions (`caddy:2.11.6`, `python:3.14.8-alpine`); `om add` scaffolds `nginx:1.31-alpine` / `node:24-alpine` instead of moving tags. The same om version now runs the same core everywhere.

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
