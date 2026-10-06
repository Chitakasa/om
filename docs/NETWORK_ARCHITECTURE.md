# Network Architecture & Security Specification

The definitive reference for om's network topology, access tiers, isolation model, firewall and verification. Applies to om 1.0+.

---

## 1. Philosophy: One Front Door, Fail-Closed

om separates two layers:

1. **Global Core (`~/.om/core/`)** — the edge proxy (`om_caddy`), the internal router (`om_router`), the dashboard (`om_dashboard`) and Portainer. The edge is the only thing that accepts traffic from outside the engine.
2. **Workspaces (any folder)** — your services and projects, each workspace on its own bridge network `<workspace>_net`. Service ports are never published to the host (`expose:`, never `ports:`).

Rule: **exactly one path leads in — the edge on ports 80/443 — and every layer behind it drops the connection when its check fails.**

The host ports 80/443 are `OM_HTTP_PORT` / `OM_HTTPS_PORT` in `om.env` (e.g. a second OS user on one machine runs om on 8081/8444). The firewall, `om doctor` and printed URLs follow them; container-side ports stay fixed.

```text
   This PC / Tailscale                                   LAN / Wi-Fi
         │                                                    │
   ┌─────┴────────────────────────────────────────────────────┴─────┐
   │ L0  HOST FIREWALL  inbound policy DROP; accept 80/443 (+system)  │
   └─────┬────────────────────────────────────────────────────┬─────┘
   ┌─────┴────────────────────────────────────────────────────┴─────┐
   │ L1  SOCKET SEPARATION                                            │
   │     127.0.0.1 · [::1] · Tailscale IP  :80/443 → edge :80/:443    │
   │     LAN IP                            :80/443 → edge :8080/:8443 │
   └─────┬───────────────────────────────────────────────────────────┘
   ┌─────┴───────────────────────────────────────────────────────────┐
   │ om_caddy (EDGE)     networks: om_core_net only                   │
   │ L2  route absence:  :8080/:8443 contain no private routes        │
   │ L3  private tier:   explicit host list, :80 { abort }, opt. login│
   └──┬───────────────────────┬───────────────────────────────────────┘
      │ om_core_net           │ X-Om-Edge-Token + X-Om-Upstream
      ▼                       ▼
   om_dashboard (L4)    ┌──────────────────────────────────┐
   portainer            │ om_router  networks: om_core_net + │
                        │            every <ws>_net          │
                        │ L3b no valid token → abort         │
                        └──────┬───────────────┬────────────┘
                               ▼               ▼
                         <ws1>_net         <ws2>_net        L5 container hardening
                         services          services         backup-host: no network
```

---

## 2. Access Tiers

### Tier 1 — Private (container ports 80/443)
* **Bound to:** `127.0.0.1`, `[::1]`, and the Tailscale IP (if Tailscale is up).
* **Answers only:** `localhost`, `127.0.0.1`, `[::1]`, `dashboard.localhost`, `*.dashboard.localhost`, the Tailscale IP, MagicDNS name and short name, and each generated `<workspace>.<service>.localhost`. Anything else → `:80 { abort }`.
* **Routes:** dashboard, all workspace vhosts, `/<service>/` subpaths (private and public), Portainer.
* **Optional login:** `om auth add <user>` puts HTTP Basic auth in front of the whole tier, one login per person (`list`, `remove`, `set` replaces all, `off`). Recommended on machines with several users.

### Tier 2 — Public (container ports 8080/8443)
* **Bound to:** the host's LAN address only.
* **Edge behavior:** sets `X-Access-Scope: public` (overwriting any client value); imports only `*.public_subpath`; everything else falls through to the sanitized public dashboard.
* **HTTPS:** a certificate for the LAN IP from the local CA, served also to clients that send no SNI.

### Who is public?
Only services labeled `dashboard.scope=public`. The route generator and the dashboard apply this single rule. No label, a typo or any other value means private.

### Machine-specific values
`~/.config/om/om.env` holds settings (`auto` / `off` / value):

```
OM_LAN_IP=auto            OM_TAILSCALE_IP=auto       OM_TAILSCALE_HOST=auto
OM_WALLPAPERS_DIR=auto    OM_FIREWALL_EXTRA_TCP=     OM_FIREWALL_EXTRA_UDP=
```

`om core start` resolves them into `~/.local/state/om/runtime.env` and `ports.yml`. A disabled or absent address is simply not bound (its Caddy host becomes a never-resolving `*.disabled.invalid` name). If addresses change (new DHCP lease or Wi-Fi, Tailscale up/down) or a core container dies, the self-heal job installed by `om boot enable` (`om core heal`, at boot and every 2 minutes) re-applies the configuration within ~2 minutes — no user action. It never restarts a core stopped on purpose (`om core stop` / `om down`). Without it, `om doctor` reports drift and `om core restart` applies it. Actions are logged to `~/.om/logs/heal.log`.

---

## 3. Isolation: Edge, Router and Token

### Why the edge must not share networks with workspaces
To proxy to `<ws>_<svc>`, something must be on each workspace network — and anything on a network is reachable by every container on it. Earlier versions attached the edge itself; a compromised LAN-public service could then call `http://om_caddy/portainer/` and reach Portainer (which holds the engine socket). That was confirmed live and is the reason for the split.

### The split
* **Edge (`om_caddy`)** — host ports, all access-control logic, attached only to `om_core_net`. No workspace container can open a connection to it.
* **Router (`om_router`)** — attached to `om_core_net` and every `<ws>_net` (by `om start` / `om core start`). It forwards a request only if **all** of these hold, otherwise it aborts the connection:
  * `X-Om-Edge-Token` equals the 256-bit secret in `~/.local/state/om/data/edge_token` (generated once, mode 0600, git-ignored), and that secret is exactly 64 hex characters — an empty or missing secret fails closed;
  * `X-Om-Upstream` matches `<workspace>_<service>:<port>` and does not start with `om_` (core containers are never targets).
* The edge **sets** both headers on every forwarded request (overwriting anything a client sent) and the router **strips** them before the upstream, so services never see the token.

```caddy
# edge
(to_workspace) {
    reverse_proxy om_router:8000 {
        header_up X-Om-Edge-Token {$OM_EDGE_TOKEN}
        header_up X-Om-Upstream {args[0]}
    }
}
# router
@from_edge expression `size("{$OM_EDGE_TOKEN}") == 64 && {http.request.header.X-Om-Edge-Token} == "{$OM_EDGE_TOKEN}" && ...`
```

**Result:** a workspace container can reach its own network and the router — nothing else. It cannot use the router (no token), cannot reach other workspaces (different networks), and cannot reach the edge, dashboard or Portainer (not on its network). This depends only on HTTP and container networking, so it behaves identically on Podman, Docker, Docker Desktop and Podman machine.

### DNS rebinding
A malicious website can point its domain at `127.0.0.1` and read the responses from your browser. The private tier therefore serves only the explicit host list; any other `Host` reaches `:80 { abort }`. The dashboard re-checks the host (`is_private_host_allowed`) and rejects cross-origin `POST`s (`Origin` / `Sec-Fetch-Site`).

### Forwarded headers
The edge has **no `trusted_proxies`**: client-supplied `X-Forwarded-*` headers are replaced, so a LAN client cannot claim to be `127.0.0.1` to Jellyfin or SearXNG. The router trusts only the edge's values (nothing else can get a request through it).

---

## 4. Defense in Depth

| Layer | Mechanism | Stops | Fails closed because |
| :--- | :--- | :--- | :--- |
| **L0 Host firewall** | `om firewall apply` — nftables / pf / Windows Firewall, inbound default-drop | Any other listening program; a published container port | Default policy is drop |
| **L1 Socket separation** | Host address → different edge port | LAN `Host`-header spoofing | LAN packets land on `:8080`, which has no private routes |
| **L2 Route absence** | Public tier imports only `*.public_subpath` | Private services addressable from LAN | Ungenerated routes don't exist |
| **L3 Private tier** | Explicit hosts + `:80 { abort }`, optional login | DNS rebinding; other local users (with login) | Non-matching hosts are aborted |
| **L3b Router token** | Edge-only secret, upstream allow-pattern | Container → private tier, container → other workspace, container → core | Missing/empty/wrong token → abort |
| **L4 Dashboard** | Host allowlist, CSRF, id validation, public sanitization | Leaks/forgery if a proxy rule were wrong | Unknown host → 403; unknown workspace → core data only |
| **L5 Containers** | `expose:` only, minimal mounts, no-new-privileges, read-only core, no network for backup | Escalation, host-file reads, lateral movement | Ungranted capabilities/mounts can't be used |

---

## 5. Zero-Knowledge Public Scope

When a request arrives on the public tier (`X-Access-Scope: public`, or a `.local`/`.home`/RFC 1918 `Host`), the dashboard API:

* `/api/workspaces` → `workspaces: []` (no names, paths or counts beyond public totals).
* `/api/services` → only `dashboard.scope=public` services; IDs, workspace ids, domains, memory and exit codes stripped; the `workspace` filter ignored.
* `/api/wallpaper/*` → core wallpaper/settings only (no workspace data, no workspace enumeration).
* `/api/system`, `/api/wallpapers`, `/api/wallpaper/preview_host`, all `POST` → **403**.
* The UI hides workspace tabs, the overview strip, the theme customizer and RAM badges.
* Files are served only if their magic bytes are a raster image (never SVG/HTML from the dashboard origin); uploads replace the current wallpaper only after validation.

---

## 6. Route Generation

`om start`, `om reload`, `om add`, `om edit`, `om remove` and `om sync` regenerate `~/.local/state/om/routes/` from each workspace's compose files:

| File | Content |
| :--- | :--- |
| `<ws>-<svc>.caddy` | `http://<ws>.<svc>.localhost` (private tier), via the router |
| `<ws>-<svc>.private_subpath` | `/<svc>/` on localhost/Tailscale |
| `<ws>-<svc>.public_subpath` | `/<svc>/` also on the LAN |

* Every file's header (`# Service: <svc> (<ws>)`) records its owner; a workspace only writes or deletes its own files — never another workspace's or core's (`portainer.*`).
* Routes of removed services, flipped tiers and pruned workspaces (`om list --prune`) are deleted — nothing lingers on the LAN.
* A subpath already claimed by another owner is skipped with a warning (the vhost still works).
* Workspace ids and service names must match `^[a-z0-9][a-z0-9-]{0,62}$` (they become hostnames and config); `core` is reserved.
* Reloads validate first; invalid config leaves live routes untouched. If the edge's single-file Caddyfile mount is stale (editor replaced the inode), the edge is recreated instead.

---

## 7. URLs per Tier

| Tier | Dashboard | Services |
| :--- | :--- | :--- |
| This PC | `http://localhost/`, `http://<ws>.dashboard.localhost/` | `http://<ws>.<svc>.localhost/`, `http://localhost/<svc>/` |
| Tailscale | `http://<tailscale-ip>/`, `http://<machine>.<tailnet>.ts.net/`, `http://<machine>/` | `http://<tailscale-ip>/<svc>/` |
| LAN | `http://<lan-ip>/`, `https://<lan-ip>/` | `http://<lan-ip>/<svc>/` (public services only) |

`om routes` prints the exact URLs for the current workspace.

---

## 8. Host Firewall (L0)

`om firewall apply` generates and installs a ruleset from `~/.config/om/om.env`:

| OS | Mechanism | Persistence |
| :--- | :--- | :--- |
| Linux | nftables table `inet om_guard` (never flushes other tables, so Tailscale's and the engine's rules are untouched) | `om-firewall.service` loading `/etc/om-firewall.nft` (root-owned copy) |
| macOS | pf anchor `om` (`/etc/pf.anchors/om`) | add the anchor to `/etc/pf.conf` (printed by the command) |
| Windows | Windows Firewall rules in group `om`; default inbound action Block | persistent (run the generated script elevated) |

Accepted inbound: loopback, established/related, TCP 80/443, UDP 443 (HTTP/3), UDP 41641 (Tailscale direct), UDP 5353 (mDNS, not over Tailscale), DHCP, essential ICMP/ICMPv6, plus `OM_FIREWALL_EXTRA_TCP/UDP`. `om firewall remove` undoes it.

---

## 9. Container Hardening

| Container | Networks | Hardening |
| :--- | :--- | :--- |
| `om_caddy` | `om_core_net` | read-only root, all caps dropped except `NET_BIND_SERVICE`, no-new-privileges |
| `om_router` | `om_core_net` + every `<ws>_net` | same; listens on 8000; admin API off |
| `om_sockguard` | none (`network_mode: none`) | same; the only holder of the engine socket besides Portainer; re-exposes `GET` container list/stats on a unix socket, everything else 403 |
| `om_dashboard` | `om_core_net` | same; no engine socket, only `om_sockguard`'s filtered one |
| `portainer` | `om_core_net` | no-new-privileges (holds the engine socket by design; private tier only) |
| services from `om add` | `<ws>_net` | `expose:` only, no-new-privileges |

Residual risk, stated plainly: Portainer uses the engine socket, so code execution in it equals control of the engine user; it is reachable only through the private tier. The dashboard no longer holds the socket: code execution in it can list containers and read their stats, nothing more (`om doctor` probes this as *Engine filter*).

---

## 10. Verification

`om doctor` runs all of the following and prints a fix for each failure: engine/compose/ports, core health, router attachment, edge isolation, published ports, address drift, private tier, DNS rebinding, router token, LAN scope, `.localhost` resolution, firewall, boot, login, git hygiene, registry.

Manual probes (attacks should print `000` = dropped or `403`; legitimate ones `200`/`302`):

```bash
c(){ curl -s -m4 -o /dev/null -w '%{http_code}\n' "$@"; }
X(){ podman exec <ws>_<svc> curl -s -m4 -o /dev/null -w '%{http_code}\n' "$@"; }   # from inside a service

c -H 'Host: attacker.example' http://127.0.0.1/api/workspaces        # DNS rebinding         → 000
X http://om_caddy/                                                    # container → edge     → 000
X -H 'X-Om-Upstream: other_svc:80' http://om_router:8000/             # router without token → 000
X http://<other-ws>_<svc>:80/                                         # cross-workspace      → 000
X http://portainer:9000/                                              # container → core     → 000
c http://<lan-ip>/api/system                                          # LAN telemetry        → 403
om ports                                                              # no other published ports

c http://localhost/ ; c http://<ws>.<svc>.localhost/ ; c http://<lan-ip>/<public-svc>/   # → 200
```

From **another device on the LAN** (the firewall doesn't filter the host's own traffic), every port except 80/443 should time out: `nc -vz -w3 <lan-ip> 9000`.
