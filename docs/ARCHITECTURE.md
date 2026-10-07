# om — Architecture

How om's network is built: tiers, isolation, outbound access, firewall, hardening and verification. Read it with `om docs architecture`; why it is built this way is in `om docs design` and `docs/adr/`.

---

## 1. Philosophy: One Front Door, Fail-Closed

om separates two layers:

1. **Global Core (`~/.om/core/`)** — the edge proxy (`om_caddy`), the internal router (`om_router`), the outbound proxy (`om_egress`), the engine filter (`om_sockguard`) and the dashboard (`om_dashboard`). The edge is the only thing that accepts traffic from outside the engine.
2. **Workspaces (any folder)** — your services and projects, each workspace on its own bridge network `<workspace>_net`. Service ports are never published to the host (`expose:`, never `ports:`).

Rule: **exactly one path leads in — the edge on ports 80/443 — and every layer behind it drops the connection when its check fails.**

The host ports 80/443 are `OM_HTTP_PORT` / `OM_HTTPS_PORT` in `om.env` (e.g. a second OS user on one machine runs om on 8081/8444). The firewall, `om doctor` and printed URLs follow them; container-side ports stay fixed.

```text
   This PC / your VPN                                    LAN / Wi-Fi
         │                                                    │
   ┌─────┴────────────────────────────────────────────────────┴─────┐
   │ L0  HOST FIREWALL  inbound policy DROP; accept 80/443 (+system)  │
   └─────┬────────────────────────────────────────────────────┬─────┘
   ┌─────┴────────────────────────────────────────────────────┴─────┐
   │ L1  SOCKET SEPARATION                                            │
   │     127.0.0.1 · [::1] · VPN address   :80/443 → edge :80/:443    │
   │     LAN IP :80/443, VPN address :8080/8443 → edge :8080/:8443    │
   └─────┬───────────────────────────────────────────────────────────┘
   ┌─────┴───────────────────────────────────────────────────────────┐
   │ om_caddy (EDGE)     networks: om_core_net only                   │
   │ L2  route absence:  :8080/:8443 contain no private routes        │
   │ L3  private tier:   explicit host list, :80 { abort }, opt. login│
   └──┬───────────────────────┬───────────────────────────────────────┘
      │ om_core_net           │ X-Om-Edge-Token + X-Om-Upstream
      ▼                       ▼
   om_dashboard (L4)    ┌──────────────────────────────────┐
                        │ om_router  networks: om_core_net + │
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
* **Bound to:** `127.0.0.1`, `[::1]`, and each VPN address (`OM_VPN`: `auto` = Tailscale when it is up; or named interfaces/addresses such as `wg0`, `10.8.0.1`). Other VPNs are never trusted automatically: a commercial VPN's tunnel would let its provider in.
* **Answers only:** `localhost`, `127.0.0.1`, `[::1]`, `dashboard.localhost`, `*.dashboard.localhost`, the VPN addresses, Tailscale's MagicDNS name and short name, and each generated `<workspace>.<service>.localhost`. Anything else → `:80 { abort }`.
* **Routes:** dashboard, all workspace vhosts, `/<service>/` subpaths (private and public).
* **Optional login:** `om auth add <user>` puts HTTP Basic auth in front of the whole tier, one login per person (`list`, `remove`, `set` replaces all, `off`). Recommended on machines with several users.

### Tier 2 — Public (container ports 8080/8443)
* **Bound to:** the host's LAN address (host ports 80/443), and each VPN address on host ports 8080/8443 — so a VPN's own access rules can give a guest the public tier only (e.g. a Tailscale ACL allowing port 8080 to a shared user). `om firewall` opens 8080/8443 for VPN addresses only.
* **Edge behavior:** sets `X-Access-Scope: public` (overwriting any client value); imports only `*.public_subpath`; everything else falls through to the sanitized public dashboard.
* **HTTPS:** a certificate for the LAN IP from the local CA, served also to clients that send no SNI.

### Who is public?
Only services labeled `dashboard.scope=public`. The route generator and the dashboard apply this single rule. No label, a typo or any other value means private.

### Machine-specific values
`~/.config/om/om.env` holds settings (`auto` / `off` / value):

```
OM_LAN_IP=auto            OM_VPN=auto
OM_WALLPAPERS_DIR=auto    OM_FIREWALL_EXTRA_TCP=     OM_FIREWALL_EXTRA_UDP=
```

`om core start` resolves them into `~/.local/state/om/runtime.env` and `ports.yml`. A disabled or absent address is simply not bound (its Caddy host becomes a never-resolving `*.disabled.invalid` name). If addresses change (new DHCP lease or Wi-Fi, VPN up/down) or a core container dies, the self-heal job installed by `om boot enable` (`om core heal`, at boot and every 2 minutes) re-applies the configuration within ~2 minutes — no user action. It never restarts a core stopped on purpose (`om core stop` / `om down`). Without it, `om doctor` reports drift and `om core restart` applies it. Actions are logged to `~/.om/logs/heal.log`.

---

## 3. Isolation: Edge, Router and Token

### Why the edge must not share networks with workspaces
To proxy to `<ws>_<svc>`, something must be on each workspace network — and anything on a network is reachable by every container on it. Earlier versions attached the edge itself; a compromised LAN-public service could then call the edge with any `Host` header and reach every private route, including admin tools holding the engine socket. That was confirmed live and is the reason for the split.

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

**Result:** a workspace container can reach its own network and the router — nothing else. It cannot use the router (no token), cannot reach other workspaces (different networks), and cannot reach the edge or the dashboard (not on its network). This depends only on HTTP and container networking, so it behaves identically on Podman, Docker, Docker Desktop and Podman machine.

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
| **L5 Containers** | `expose:` only, policy gate, internal networks with listed egress only, no-new-privileges, read-only core | Escalation, host-file reads, lateral movement | Ungranted capabilities/mounts can't be used |

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
| `<ws>-<svc>.private_subpath` | `/<svc>/` on localhost and the VPN |
| `<ws>-<svc>.public_subpath` | `/<svc>/` also on the LAN |

* Every file's header (`# Service: <svc> (<ws>)`) records its owner; a workspace only writes or deletes its own files — never another workspace's or core's (`00-info.caddy`).
* Routes of removed services, flipped tiers and pruned workspaces (`om list --prune`) are deleted — nothing lingers on the LAN.
* A subpath already claimed by another owner is skipped with a warning (the vhost still works).
* Workspace ids and service names must match `^[a-z0-9][a-z0-9-]{0,62}$` (they become hostnames and config); `core` is reserved.
* Reloads validate first; invalid config leaves live routes untouched. If the edge's single-file Caddyfile mount is stale (editor replaced the inode), the edge is recreated instead.

---

## 7. Outbound Access and the Policy Gate

* **Internal networks.** Every `<ws>_net` is created `--internal`: no route out and no external DNS. A container reaches its own workspace, the router and `om_egress` — nothing else.
* **`om_egress`** (Squid, see `docs/adr/0002-egress-proxy.md`) is attached to `om_core_net` and every `<ws>_net`. A service with an `om.egress` label gets, through an om-generated compose override, `HTTP(S)_PROXY` with its own credential (hashed in `<state>/egress/`); the proxy allows that credential exactly the listed names (`*.` for subdomains), never private or link-local addresses. `learn` allows any public host and records it; `om egress log` turns the record into the label. A service without the label has no credential and no way out.
* **Policy gate.** `om start` / `om sync` read each compose file through the engine's own `compose config` and refuse `privileged`, host namespaces, `ports:`, engine sockets and sensitive host mounts, capabilities beyond the engine's defaults, devices, unconfined security options, `om.egress=internet` on a service that writes or receives secrets, and plaintext secret files. `om.policy.allow=<rule>` waives one rule for one service (`privileged` and `ports` cannot be waived). `OM_POLICY=enforce` (default) refuses; `warn` only reports.
* **Images and deploys.** `.om/lock.json` pins every image to its registry index digest, applied through an override; a clean commit must be signed by a key the last deploy trusted (`OM_SIGNED`). Every deploy is a hash-chained generation in `<state>/generations/`.
* **Secrets** are age-encrypted in the repo and decrypted at start into `$XDG_RUNTIME_DIR` (memory), mounted read-only at `/run/secrets/<name>`, wiped on stop.

---

## 8. URLs per Tier

| Tier | Dashboard | Services |
| :--- | :--- | :--- |
| This PC | `http://localhost/`, `http://<ws>.dashboard.localhost/` | `http://<ws>.<svc>.localhost/`, `http://localhost/<svc>/` |
| Your VPN | `http://<vpn-ip>/`; with Tailscale also `http://<machine>/`, `http://<machine>.<tailnet>.ts.net/` | `http://<vpn-ip or machine>/<svc>/` |
| LAN | `http://<lan-ip>/`, `https://<lan-ip>/` | `http://<lan-ip>/<svc>/` (public services only) |
| VPN guests (public tier) | `http://<vpn-ip>:8080/` | `http://<vpn-ip>:8080/<svc>/` (public services only) |

`om routes` prints the exact URLs for the current workspace.

---

## 9. Host Firewall (L0)

`om firewall apply` generates and installs a ruleset from `~/.config/om/om.env`:

| OS | Mechanism | Persistence |
| :--- | :--- | :--- |
| Linux | nftables table `inet om_guard` (never flushes other tables, so Tailscale's and the engine's rules are untouched) | `om-firewall.service` loading `/etc/om-firewall.nft` (root-owned copy) |
| macOS | pf anchor `om` (`/etc/pf.anchors/om`) | add the anchor to `/etc/pf.conf` (printed by the command) |
| Windows | Windows Firewall rules in group `om`; default inbound action Block | persistent (run the generated script elevated) |

Accepted inbound: loopback, established/related, TCP 80/443, TCP 8080/8443 to VPN addresses only (public tier for VPN guests), UDP 443 (HTTP/3), UDP 41641 (Tailscale direct), UDP 5353 (mDNS, not over Tailscale), DHCP, essential ICMP/ICMPv6, plus `OM_FIREWALL_EXTRA_TCP/UDP`. `om firewall remove` undoes it.

---

## 10. Container Hardening

| Container | Networks | Hardening |
| :--- | :--- | :--- |
| `om_caddy` | `om_core_net` only (the only container with host ports) | read-only root, all caps dropped except `NET_BIND_SERVICE`, no-new-privileges |
| `om_router` | `om_core_net` + every `<ws>_net` | same; listens on 8000; admin API off |
| `om_egress` | `om_core_net` + every `<ws>_net` | read-only root, all caps dropped, user `proxy`; Squid allowing only per-service listed hosts (`om.egress`), never private ranges; see `docs/adr/0002-egress-proxy.md` |
| `om_sockguard` | none (`network_mode: none`) | same; the only holder of the engine socket; re-exposes `GET` container list/stats on a unix socket, everything else 403 |
| `om_dashboard` | `om_core_net` | same; no engine socket, only `om_sockguard`'s filtered one |
| services from `om add` | `<ws>_net` (internal: no route out, no external DNS) | `expose:` only, no-new-privileges; outbound only via `om_egress` with `om.egress` |

Residual risk, stated plainly: everyone who can join your VPN reaches the private tier, so the VPN account is the lock (Tailnet Lock with Tailscale; `om doctor` *VPN*). The dashboard does not hold the engine socket: code execution in it can list containers and read their stats, nothing more (`om doctor` probes this as *Engine filter*).

---

## 11. Verification

`om doctor` runs all of the following and prints a fix for each failure: engine/compose/ports, core health (and no leftover retired containers), router attachment, edge isolation, published ports, address drift, private tier, DNS rebinding, router token, engine filter (dashboard writes → 403), admin surface (edge listeners), running images = lock, egress (DNS, direct, host addresses blocked; proxy requires a credential), generations (signed, chained), LAN scope, VPN (Tailnet Lock), `.localhost` resolution, firewall, boot, login (only when other people can log in), state location, registry, orphan routes.

Manual probes (attacks should print `000` = dropped or `403`; legitimate ones `200`/`302`):

```bash
c(){ curl -s -m4 -o /dev/null -w '%{http_code}\n' "$@"; }
X(){ podman exec <ws>_<svc> curl -s -m4 -o /dev/null -w '%{http_code}\n' "$@"; }   # from inside a service

c -H 'Host: attacker.example' http://127.0.0.1/api/workspaces        # DNS rebinding         → 000
X http://om_caddy/                                                    # container → edge     → 000
X -H 'X-Om-Upstream: other_svc:80' http://om_router:8000/             # router without token → 000
X http://<other-ws>_<svc>:80/                                         # cross-workspace      → 000
X http://om_dashboard/                                                # container → core     → 000
c http://<lan-ip>/api/system                                          # LAN telemetry        → 403
om ports                                                              # no other published ports

c http://localhost/ ; c http://<ws>.<svc>.localhost/ ; c http://<lan-ip>/<public-svc>/   # → 200
```

From **another device on the LAN** (the firewall doesn't filter the host's own traffic), every port except 80/443 should time out: `nc -vz -w3 <lan-ip> 9000`.
