# Changelog

## Unreleased

### Closer to absolute
- **The router listens on no network:** only on a unix socket shared with the edge, so no container can even connect to it; the edge token stays as a second lock. `om doctor` probes the socket (refused without the token) and that the router has no listener.
- **`om_egress` only where a service may go out:** networks without an `om.egress` service no longer reach the proxy at all.
- **Logs without content:** the firewall logs refused connections and new connections to om's ports with their real source (rate-limited); the edge logs site, method, status, size, time and login — never URLs, queries or headers. `om.log=off` on a service leaves no trace (no edge entry, no connection log, and the engine discards its own output: a search engine logs failed upstream URLs with the query). `om firewall log` shows who knocked, who got in, and per-site request and error counts.
- **Error logs no longer carry requests:** the edge's and router's error entries logged the full request — URL and headers, the edge token among them. Both loggers now keep only what happened; `om doctor` checks the token appears in no om log.
- **Rootful engines no longer bypass address rules:** Docker and rootful Podman publish ports by DNAT, so their connections are forwarded and never passed `om_guard`'s input chain — `om.net` rules silently did nothing there. Every address rule is now also rendered in a `forward` chain (matched on the original address and port; nothing else forwarded is touched), and "enforced" requires both.
- **`om vpn allow|disallow` update the firewall themselves** (one sudo prompt, where om's firewall is installed), before checking anything: the new list is in effect at once and no device loses access in between. Declined sudo, `--no-apply` or no installed firewall: fail closed as before (the VPN's private tier stays unbound until `om firewall apply`).
- **`om.net.allow=vpn`:** a service reachable by exactly the devices on the VPN allow-list, following it (expanded when the firewall renders; after a list change such services keep no own ports until `om firewall apply`). Mixes with addresses; refused without an allow-list.
- **CI checks the generated firewall with each OS's own parser:** `nft -c` (Linux), `pfctl -nf` (macOS), PowerShell parse plus `New-NetFirewallRule -WhatIf` (Windows), on rules with address lists, the VPN allow-list, logging and the forward chain (`tests/fw_render.py`). macOS VPN device discovery reads `netstat`'s interface column by its header and expands its abbreviated destinations (`100.64/10`).
- **`om vpn` lists every device on the trusted VPNs**, also ones that never contacted this machine: found in the kernel's routes through the VPN interface (a host route per peer for mesh VPNs; a subnet ≤ /24 whose DNS names its members for hub VPNs; neighbours for layer-2 VPNs), the allow-list and the firewall log; named through the VPN's own DNS (PTR), allowed or not, last seen, connected/refused counts. `om vpn devices` prints only that list; `--json`. No VPN product's tool is used.
- **VPN device allow-list:** `om vpn allow <device>` (address, range, or the VPN's own name for it) / `om vpn disallow`: only listed devices reach the private tier over the VPN; other VPN devices keep the public tier. Firewall-enforced; until it is, the VPN's private tier is not bound. `om vpn` and `om doctor` show it.
- **One network per service folder:** a compromised service can no longer reach another folder's services in the same workspace. om gives each folder its own internal network through a compose override (no compose edits), attaches the router and egress to each, and prunes networks of removed folders. `om.network=shared` opts a folder out; `om.link` connects two services within a workspace too. `om network` lists them; `om doctor` probes the isolation (by name and by address).
- **`om edit` recreates through `om start`'s path:** it used a bare `compose up`, which dropped the egress proxy settings, image pins, secrets — and would have dropped the project network.

### Who may reach a service, by address
- **`om.net.allow` / `om.net.deny` labels** (addresses or CIDR ranges, IPv4/IPv6; deny wins; this machine always allowed): the host firewall drops everyone else on that service's own ports — no answer at all. nft on Linux, pf on macOS (tables), Windows Firewall (block rules over the complement). Fail closed: an unreadable label leaves the service unrouted, and until `om firewall apply` carries its rules the service has no port of its own. `om routes` shows the rules; `om doctor` fails on rules missing from the firewall and warns on stale ones.
- **VPN devices no longer reach `*.localhost` sites:** VPN addresses land on their own edge ports (:81/:444; host ports unchanged), so `<ws>.<svc>.localhost` answers this machine only, whatever Host a VPN device sends. `om doctor` probes it. Needs `om core restart` once.
- **`om.caddy` refuses `remote_ip` / `client_ip`:** under rootless port forwarding the edge sees every client as one internal address, so such a rule matched everyone or no one.

### Self-heal sees dead containers
- **Podman containers whose process died unseen** (conmon killed, e.g. by systemd SIGKILLing `podman-restart.service` after a failed boot start) kept showing `Up` forever and were never restarted. `container_running` now checks the pid in `/proc` (local Podman) or asks the engine with `top` (Podman machine); Docker's daemon already supervises its containers; `om core heal` and `om core start` stop/start such containers, keeping their exact configuration.
- **`om core watch`** (a systemd user service, `om-watch`, installed by `om boot enable`): holds a pidfd per container, so a process that dies unseen is restarted within ~3 s instead of at the next 2-minute heal. Linux with a local Podman or Docker engine; `om core heal` stays the fallback elsewhere.
- **`om.heal=restart` label:** a service that stays unhealthy for 10 minutes is restarted by `om core heal`, at most once per hour.

### A developer engine
- **Cross-workspace links:** `om.link=<ws>/<svc>` on the user and `om.link.allow=<ws>/<svc>` (or `<ws>/*`) on the provider put exactly those two containers on a private network; the user reaches the provider as `<ws>-<svc>`, any protocol. `om links` lists them and what blocks a one-sided one; `om start` and the heal timer keep them attached; `om doctor` checks them.
- **Own Caddy rules:** `om.caddy` next to a service's compose file runs first on all its addresses — headers, redirects, rewrites, `basic_auth`, matchers — from an allow-list; anything that reads files, reaches another upstream or reads om's environment is refused, and a refused file leaves the service unrouted. Marked in `om routes` and `om doctor`.
- **Branch previews:** `om preview <branch>` runs a branch beside the workspace as `<ws>--<branch>` (git worktree; own network, data, ports); `om preview rm <branch>` removes all of it. `om add` writes `${WORKSPACE_ID}` / `${WORKSPACE_NET}` names so services can run twice.
- **`--json`** on `status`, `routes`, `log`, `doctor` (exit 1 on failure), `list`, `links`, `vpn`.
- **Clone to running on another machine:** `om secrets init` adds the machine to the recipients (never replaces them); `om secrets rekey` re-encrypts every secret for all of them; a failed decrypt says which steps to take. `om status` shows public services again.

### Any VPN, no product names
- om finds every VPN on the machine by itself — each tunnel the kernel reports (`tun`, `wireguard`), whatever its product or name — and trusts none without your yes: `om vpn` lists them, `om vpn trust|untrust <iface>` sets `OM_VPN` and restarts the core; the installer asks per VPN, `om doctor` reminds. `OM_VPN=auto` no longer trusts anything by itself.
- Discovery per OS: Linux by kernel kind, macOS every non-hardware interface with an address (finds ZeroTier's `feth`), Windows every non-hardware adapter (`Get-NetAdapter`); DNS servers from `resolv.conf`, `scutil --dns`, `Get-DnsClientServerAddress`.
- The names devices may use (e.g. `archlinux`, `archlinux.<tailnet>.ts.net`) come from the VPN's own DNS through a PTR query, plus the hostname. No Tailscale CLI, address range or port remains in om: the firewall's VPN transport rule is gone (conntrack answers peers), mDNS is accepted on Ethernet/Wi-Fi only (`iiftype ether`), and the dashboard trusts the VPN addresses you trusted.

### One origin per service (ADR 0004)
- Every web service gets a stable port of its own — `20000+n` (private: loopback and VPN) and, if public, `21000+n` (LAN and VPN) — so no service can read another, or the dashboard, through your browser. Each port aborts requests for unknown hosts (DNS rebinding). The ranges are published once: adding a service never restarts the edge. `om routes` and the dashboard show the ports.
- `/<svc>/` path routing over the VPN and the LAN is removed; `/<svc>` and `om.route.aliases` on the dashboard's address redirect to the service's port. `dashboard.path` now means the path on the service's own address (default `/`).
- `om firewall` opens 20000–20199 on VPN addresses and 21000–21199; `om doctor` checks that private service ports are closed on the LAN.

### Final setup and docs
- om refuses to run as root, with the reason: containers stay rootless under your user, and `sudo om` would create a second, root-owned om. Host steps ask for sudo themselves.
- The installer now also sets up SSH-signed git commits (then `OM_SIGNED=enforce`) and asks, for each VPN on the machine, whether to trust it; it refuses to run as root.
- `OM_POLICY=enforce` is the default; a mistyped `OM_POLICY` or `OM_SIGNED` enforces (fail closed). `om secrets encrypt` (old built-in format) is removed; `decrypt` stays to read old files. `om auth` accepts passwords of 4+ characters.
- Docs merged into three: `docs/GUIDE.md` (was DEVELOPER_GUIDE + PROJECT_GUIDE), `docs/ARCHITECTURE.md` (was NETWORK_ARCHITECTURE, now with outbound access and the policy gate), `docs/DESIGN.md` (was VISION + GOALS). `om docs guide|architecture|design`.

### Network: your VPN is the door (ADR 0003)
- `OM_VPN` (replaces `OM_TAILSCALE_IP`/`OM_TAILSCALE_HOST`): the private tier answers on loopback and on the addresses of the VPNs you trust (see *Any VPN, no product names* above), and on the names their DNS gives this machine, so `http://<machine>/` works from every device on that VPN.
- VPN addresses also serve the public tier (the public dashboard on `:8080`/`:8443`, public services on their own ports), so a VPN's own access rules (e.g. a Tailscale ACL allowing ports 8080 and 21000–21199 to a shared user) give a guest exactly the `dashboard.scope=public` services. `om firewall` opens 8080/8443 for VPN addresses only.
- `om doctor` *VPN*: which VPNs reach the private tier, and which tunnels are present but not trusted. *Admin surface* checks the edge's listeners. *Login* warns only when other people can log in to this machine.
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
- A developer guide (now part of `docs/GUIDE.md`): creating containers, when to rebuild an image, debugging a workspace.

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
