# om — Architecture

How om's network is built: tiers, isolation, outbound access, firewall, hardening and verification. Read it with `om docs architecture`; why it is built this way is in `om docs design` and `docs/adr/`.

---

## 1. Philosophy: One Front Door, Fail-Closed

om separates two layers:

1. **Global Core (`~/.om/core/`)** — the edge proxy (`om_caddy`), the internal router (`om_router`), the stream edge proxy (`om_stream_edge`), the stream internal router (`om_stream_router`), the outbound proxy (`om_egress`), the engine filter (`om_sockguard`) and the dashboard (`om_dashboard`). The edge proxies (`om_caddy` and `om_stream_edge`) are the only containers that accept traffic from outside the engine.
2. **Workspaces (any folder)** — your services and projects, each workspace on its own bridge network `<workspace>_net`. Service ports are never published to the host (`expose:`, never `ports:`).

Rule: **exactly one path leads in — the edge on ports 80/443 (HTTP) and the stream edge on stream ports (raw TCP) — and every layer behind it drops the connection when its check fails.**

The host ports 80/443 are `OM_HTTP_PORT` / `OM_HTTPS_PORT` in `om.env` (e.g. a second OS user on one machine runs om on 8081/8444). The firewall, `om doctor` and printed URLs follow them; container-side ports stay fixed.

```text
   This PC / your VPN                                    LAN / Wi-Fi
         │                                                    │
   ┌─────┴────────────────────────────────────────────────────┴─────┐
   │ L0  HOST FIREWALL  inbound policy DROP; accept 80/443 (+system)  │
   │     stream ports: default 22000-22199, explicit stream ports   │
   │     om.net.allow/deny: per-service source addresses, dropped     │
   └─────┬────────────────────────────────────────────────────┬─────┘
   ┌─────┴────────────────────────────────────────────────────┴─────┐
   │ L1  SOCKET SEPARATION                                            │
   │     127.0.0.1 · [::1]                 :80/443 → edge :80/:443    │
   │     VPN address                       :80/443 → edge :81/:444    │
   │     LAN IP :80/443, VPN address :8080/8443 → edge :8080/:8443    │
   │     loopback·VPN :20000+n → service n (private, own origin)      │
   │     LAN·VPN      :21000+n → public service n (own origin)        │
   │     stream :22000+n / explicit N → om_stream_edge :N             │
   └─────┬───────────────────────────────────────────────────────────┘
   ┌─────┴──────────────────────────────────┐ ┌─────────────────────┐
   │ om_caddy (EDGE) networks: om_core_net  │ │ om_stream_edge      │
   │ L2  route absence; L3 private tier     │ │ networks: core only │
   └──┬──────────────────┬──────────────────┘ └──────────┬──────────┘
      │ om_core_net      │ X-Om-Edge-Token               │ /run/om-stream/N.sock
      ▼                  ▼                               ▼
   om_dashboard (L4)  ┌────────────────────────┐  ┌──────────────────┐
                      │ om_router (HTTP)       │  │ om_stream_router │
                      │ networks: core+<ws>_net│  │ networks: <ws>_net│
                      │ L3b token check        │  │ L3c unix socket  │
                      └──────┬──────────────┬──┘  └───────┬──────────┘
                             ▼              ▼             ▼
                       <ws1>_net        <ws2>_net       <ws>_svc:cport
                       services         services        (raw TCP)
```

---

## 2. Access Tiers

### Tier 1 — Private (container ports 80/443 for this machine, 81/444 for VPN addresses)
* **Bound to:** `127.0.0.1`, `[::1]` (edge :80/:443), and each VPN address on host 80/443 (edge :81/:444) (`OM_VPN`, set by `om vpn trust <iface>`). om lists every interface that may be a VPN — Linux: tunnel devices by kernel kind (`tun`, `wireguard`); macOS: every non-hardware interface with an address (`utun*`, ZeroTier's `feth*`…); Windows: every non-hardware adapter — and trusts none by itself: a tunnel may be a commercial or company VPN or a public network, and telling them apart would need root.
* **Answers only:** `localhost`, `127.0.0.1`, `[::1]`, `dashboard.localhost`, `*.dashboard.localhost`, the VPN addresses, the names the VPN's DNS gives this machine (a PTR query to the system's DNS servers: `/etc/resolv.conf`, `scutil --dns`, `Get-DnsClientServerAddress`) and its hostname, and each generated `<workspace>.<service>.localhost`. Anything else → `:80 { abort }`.
* **This machine only:** the `<workspace>.<service>.localhost` sites listen on edge :80 alone. VPN addresses land on :81/:444, where only the dashboard's VPN names answer (anything else → `:81 { abort }`), so a VPN device sending such a Host reaches nothing; it uses each service's own port, which the firewall controls. `om doctor` probes this (VPN isolation).
* **Routes:** dashboard, all workspace vhosts, and redirects from `/<service>` (and `om.route.aliases`) to each service's own port.
* **Optional login:** `om auth add <user>` puts HTTP Basic auth in front of the whole tier, one login per person (`list`, `remove`, `set` replaces all, `off`). Recommended on machines with several users.

### Tier 2 — Public (container ports 8080/8443)
* **Bound to:** the host's LAN address (host ports 80/443), and each VPN address on host ports 8080/8443 — so a VPN's own access rules can give a guest the public tier only. `om firewall` opens 8080/8443 for VPN addresses only.
* **VPN devices outside `OM_VPN_ALLOW`** that open the private tier's address (host 80/443) are sent to 8080/8443 at that address by the firewall (`chain vpn_public`, nat prerouting `dnat`; pf `rdr`), so they see the public tier instead of no answer. New connections only: one opened while the device was allowed is still cut by the input chain. Windows Firewall cannot redirect: there such a device uses `:8080`.
* **Edge behavior:** sets `X-Access-Scope: public` (overwriting any client value); imports only `*.public_alias` (redirects to public services' ports); everything else falls through to the sanitized public dashboard.
* **HTTPS:** a certificate for the LAN IP from the local CA, served also to clients that send no SNI.

### Per-service ports: one origin per service
Browsers isolate origins (scheme, host, port). If services shared one address as paths, a script from one could read another's pages and the dashboard's API through your browser. So every web service gets a stable slot `n` (`<state>/registry/service_ports.json`):

* **20000+n** — private: bound on `127.0.0.1` and each VPN address; answers only `{$PRIVATE_NAMES}` (localhost and the VPN names/addresses), any other Host is aborted (DNS rebinding).
* **21000+n** — only for public services: bound on the LAN address and each VPN address; answers only `{$PUBLIC_NAMES}` (LAN address, `<hostname>.local`, VPN names); dashboard paths there are public-scoped.
* The ranges (200 slots each) are published once by `ports.yml`, so adding a service never recreates the edge; a port without a service has no listener.
* A VPN guest's access rule is therefore "ports 8080 and 21000–21199". On this machine, `<ws>.<svc>.localhost` remains each service's own origin as well.

### Raw TCP stream tier (`om.tcp` / `om.tcp.port`)
For services requiring raw TCP (e.g. Minecraft on TCP 25565, databases, Redis, custom TCP daemons) that cannot speak HTTP:

* **Labels:** `om.tcp=<container-port>`, optional `om.tcp.port=<host-port>`.
* **Scope:** Follows `dashboard.scope=public` (default is private). Private binds loopback and VPN addresses; public also binds the host's LAN IP. Rejects host ports < 1024 and clashes with 80, 443, 8080, 8443, 20000–21199, and the stream range.
* **Fragments:** each service has `<state>/stream/fragments/{edge,router}/<ws>.<svc>.cfg`; a fragment is owned by the workspace named in its `# Service: <svc> (<ws>)` header (never by file-name prefix: ids contain `-`), and a workspace's sync replaces only its own, including any left under the older `<ws>-<svc>.cfg` name.
* **Slots & Publishing:** Default slots `22000+n` (200 slots recorded in `<state>/registry/stream_ports.json`) are pre-published once in `ports.yml` on `om_stream_edge`, so adding or removing services never recreates the container. Explicit ports (e.g. 25565) are reserved on first use and update `ports.yml` (recreating `om_stream_edge`).
* **Zero-Network Router Lock (L3c):** `om_stream_edge` sits on `om_core_net` only; forwards host port N to `/run/om-stream/N.sock` in volume `om_stream_sock`. `om_stream_router` sits on workspace networks, but has **no network listener**: it binds `/run/om-stream/N.sock` and forwards to `<ws>_<svc>:<container-port>` using runtime DNS resolution (`resolvers docker`).
* **Source filtering & Fail-Closed:** `om.net.allow` and `om.net.deny` apply to stream ports at the host firewall (`om_guard`). While the applied firewall lacks a service's rules (`hostsetup.net_policy_enforced`), its stream port is not bound (fail closed).

### Per-service source addresses (`om.net.allow` / `om.net.deny`)
The edge cannot tell clients apart: rootless port forwarding hands it every connection from one internal address (verified: loopback, LAN and VPN connections all arrive from the edge network's own address). The host firewall sees the real source, and each service has ports of its own, so the rules live there: route generation writes `<state>/registry/net_policy.json` ({service: ports, allow, deny}), `om firewall` renders it ahead of every accept — nft `ip saddr != {…} drop` (plus an IPv6/IPv4 drop for a one-family allow-list), pf tables (`! { a b }` would expand into rules that block everyone), Windows block rules over the complement — and loopback stays allowed. Fail closed: a label that cannot be read leaves the service unrouted, and while the applied firewall lacks a service's rules (`hostsetup.net_policy_enforced`) its own ports are not routed at all; `om firewall apply` re-routes every workspace, `om doctor` fails on missing and warns on stale rules. A LAN address can be taken by anyone on the LAN; a VPN address belongs to a device key.

Address rules sit before the input chain's `established` accept, limited to the client side (`ct direction original`): a removed device's open connections are cut immediately, while replies to this machine's own outgoing connections pass whatever their local port. The same rules apply to engines that publish ports by DNAT (rootful Docker/Podman): those connections are forwarded to the container and never pass the input chain, so `om_guard` carries a `forward` chain (policy accept, touching nothing else) with each rule matched on `ct original` address, port and *initiator* (`ct original ip saddr`, so container replies to allowed clients pass). `hostsetup.net_policy_enforced` requires both copies.

### Logging without content
* **Firewall** (real source addresses): every address-rule drop is preceded by its own rate-limited `log` rule (`om-refused <rule>`; a `limit` on the drop itself would let packets over the rate fall through to the accepts), new connections to om's ports are logged (`om-in`) except the own ports of `om.log=off` services (`<state>/registry/no_log.json`), and unsolicited unicast reaching the default drop is logged (`om-refused`). Loopback is never logged. pf logs every block to `pflog0`; Windows Firewall logs dropped packets.
* **Edge** (`(access_log)`, imported by `(security_headers)` into every site): Caddy's filter encoder deletes `request>uri`, headers, TLS and client address fields — what remains is site, method, protocol, status, size, duration and login name. `om.log=off` adds `log_skip` to every site of the service.
* **Error logs too:** the edge's and the router's default loggers use the same filter. An unfiltered error entry carries the whole request — its URL and headers, the `X-Om-Edge-Token` among them (seen live: a router dial error logged the token). `om doctor` checks the token appears in no om log; the fix for a leak is a new token (`rm <state>/data/edge_token && om core restart`).
* **The service itself:** `om.log=off` also gives the service `logging: driver: none` (compose override in `<state>/nolog/overrides/`), so the engine stores none of its output.
* `om firewall log` reads the kernel log (Linux) and the edge's log, maps ports to services through `service_ports.json`.

### VPN device allow-list (`OM_VPN_ALLOW`)
`om vpn allow <device>` (address, range, or a name the VPN's DNS resolves) limits the private tier over the VPN — host 80/443 (edge :81/:444), HTTP/3, and every service's private port on the VPN addresses — to the listed devices; other VPN devices keep the public tier. It is one more address rule (`hostsetup.vpn_restriction`), rendered and checked like `om.net`. Fail closed: while the applied firewall lacks it, `omsettings.vpn_private_open()` is false and `ports.yml` does not bind the VPN's private tier at all; `om firewall apply` restarts the core so it is bound.

### Who is public?
Only services labeled `dashboard.scope=public`. The route generator and the dashboard apply this single rule. No label, a typo or any other value means private.

### Machine-specific values
`~/.config/om/om.env` holds settings (`auto` / `off` / value). It is written 0600 (it can carry `OM_NOTIFY_URL`, a bearer-like secret) and `om doctor` checks the mode:

```
OM_LAN_IP=auto            OM_VPN=tailscale0,wg0      (om vpn trust …)
OM_VPN_ALLOW=             (om vpn allow …)           OM_WALLPAPERS_DIR=auto
OM_HTTP_PORT=80           OM_HTTPS_PORT=443
OM_FIREWALL_EXTRA_TCP=    OM_FIREWALL_EXTRA_UDP=
OM_POLICY=enforce         OM_SIGNED=warn             (the installer sets enforce once signing works)
OM_NOTIFY=auto            OM_NOTIFY_URL=             (§12)
OM_TRUSTED_USERS=         (your own other accounts; `om doctor` Login does not count them)
```

`om core start` resolves them into `~/.local/state/om/runtime.env` and `ports.yml`. A disabled or absent address is simply not bound (its Caddy host becomes a never-resolving `*.disabled.invalid` name). If addresses change (new DHCP lease or Wi-Fi, VPN up/down) or a core container dies, the self-heal job installed by `om boot enable` (`om core heal`, at boot and every 2 minutes) re-applies the configuration within ~2 minutes — no user action; the first run that sees a changed address only notes it, the next one recreates the edge, so a flapping address does not restart it every time. It never restarts a core stopped on purpose (`om core stop` / `om down`). Without it, `om doctor` reports drift and `om core restart` applies it. On Linux with a local engine `om boot enable` also installs `om-watch` (`om core watch`), which restarts a container whose process died unseen within a few seconds. Actions are logged to `<state>/logs/heal.log` (`~/.local/state/om/logs/` by default).

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
    reverse_proxy unix//run/om-router/router.sock {
        header_up X-Om-Edge-Token {$OM_EDGE_TOKEN}
        header_up X-Om-Upstream {args[0]}
    }
}
# router: bind unix//run/om-router/router.sock (no network listener)
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
| **L0 Host firewall** | `om firewall apply` — nftables / pf / Windows Firewall, inbound default-drop; per-address rules (`om.net.*`, `OM_VPN_ALLOW`) on the inbound path and, for rootful engines (which publish ports by DNAT), the forward path | Any other listening program; a published container port; refused source addresses | Default policy is drop; rules not in the applied firewall leave the ports unrouted/unbound |
| **L1 Socket separation** | Host address → different edge port | LAN `Host`-header spoofing | LAN packets land on `:8080`, which has no private routes |
| **L2 Route absence** | Private service ports are bound to loopback and VPN only; the LAN gets only public services' ports | Private services addressable from LAN | An unbound port cannot answer |
| **L3 Private tier** | Explicit hosts + `:80 { abort }`, optional login | DNS rebinding; other local users (with login) | Non-matching hosts are aborted |
| **L3b Router socket + token** | The router listens on no network, only on a unix socket shared with the edge (`om_router_sock`); edge-only secret, upstream allow-pattern | Any container talking to the router at all; container → private tier, other workspace, core | No listener to reach; missing/empty/wrong token → abort |
| **L3c Stream router socket** | Static HAProxy configs over unix sockets (`/run/om-stream/N.sock`); router has no network listener, edge sits on `om_core_net` only | Container talking to stream router or edge; cross-workspace raw TCP access | No network listener on router; edge not on workspace network |
| **L4 Dashboard** | Host allowlist, CSRF, id validation, public sanitization | Leaks/forgery if a proxy rule were wrong | Unknown host → 403; unknown workspace → core data only |
| **L5 Containers** | `expose:` only, policy gate, internal networks with listed egress only, no-new-privileges, read-only core | Escalation, host-file reads, lateral movement | Ungranted capabilities/mounts can't be used |
| **L5a Egress placement** | `om_egress` is attached only to networks of projects with an `om.egress` service (`<state>/networks/egress.json`, `enginectl.connect_router`) | Services that may not go out probing the proxy | Unknown placement → attached as before, until the first `om start` records it |
| **L5b Project networks** | One internal network per service folder (compose override), router/egress attached to each; `om.link` between two | A compromised service reaching another folder's services | A network that cannot be made internal → the folder is not started |

---

## 5. Zero-Knowledge Public Scope

When a request arrives on the public tier (`X-Access-Scope: public`, or a `.local`/`.home`/RFC 1918 `Host`), the dashboard API:

* `/api/workspaces` → `workspaces: []` (no names, paths or counts beyond public totals).
* `/api/services` → only `dashboard.scope=public` services; IDs, workspace ids, domains, memory, update flags, private ports and exit codes stripped; the `workspace` filter ignored.
* `/opensearch.xml` → only a public service that marks itself `dashboard.search=true`, with its public port.
* `/api/wallpaper/*` → core wallpaper/settings only (no workspace data, no workspace enumeration).
* `/api/system`, `/api/wallpapers`, `/api/wallpaper/preview_host`, all `POST` → **403**.
* The UI hides workspace tabs, the overview strip, the theme customizer and RAM badges.
* Files are served only if their magic bytes are a raster image (never SVG/HTML from the dashboard origin); uploads replace the current wallpaper only after validation.

**Every route of the dashboard** (`DashboardHandler.GET_ROUTES` / `POST_ROUTES` in `core/dashboard/app/server.py`; each is one method):

| Route | Private tier | Public tier |
| :--- | :--- | :--- |
| `GET /healthz`, `/api/health` | `OK`; the only routes that skip the Host check | same |
| `GET /api/scope` | `{"is_public_scope": false}` | `true` |
| `GET /api/workspaces` | registered workspaces with service counts (no host paths) | public totals only |
| `GET /api/services` | every container that is not hidden (`dashboard.hide`); `?workspace=` and `?scope=public` filter | public services, sanitized |
| `GET /api/system` | platform and workload memory | 403 |
| `GET /api/wallpaper/settings`, `/api/wallpaper/current` | the workspace's own, else the core's | the core's |
| `GET /api/wallpapers`, `/api/wallpaper/preview_host` | host wallpapers (a file name only, looked up in the wallpaper and data folders) | 403 |
| `GET /opensearch.xml` | the service marked `dashboard.search=true` | only if it is public |
| `POST /api/wallpaper/upload` | image (magic bytes), at most 20 MB | 403 |
| `POST /api/wallpaper/set`, `/api/wallpaper/settings` | JSON, at most 1 MB | 403 |

Anything else under `/api/` is a 404 JSON answer; any other path is the page. State-changing requests are refused when the Host is foreign (DNS rebinding) or the `Origin` / `Sec-Fetch-Site` is cross-site, and a negative `Content-Length` counts as an empty body.

---

## 6. Route Generation

`om start`, `om reload`, `om add`, `om edit`, `om remove` and `om sync` regenerate `~/.local/state/om/routes/` from each workspace's compose files:

| File | Content |
| :--- | :--- |
| `<ws>-<svc>.caddy` | `http://<ws>.<svc>.localhost`, `http://:20000+n` and (public) `http://:21000+n`, all via the router |
| `<ws>-<svc>.private_alias` | `/<svc>` and alias paths on the private dashboard address → `http://{host}:20000+n` |
| `<ws>-<svc>.public_alias` | the same on the public dashboard → `http://{host}:21000+n` |

* A service's `om.caddy` (its own Caddy rules) is checked against an allow-list of directives and matcher types and refused if it contains `{$`, `{env.`, `{file.`, `import` or heredocs; it runs first inside a `route` on each of the service's sites. A refused file leaves the service unrouted (fail closed). The header then says `# custom:`.
* Every file's header (`# Service: <svc> (<ws>)`) records its owner; a workspace only writes or deletes its own files — never another workspace's or core's (`00-info.caddy`).
* Routes of removed services, flipped tiers and pruned workspaces (`om list --prune`) are deleted — nothing lingers on the LAN.
* A redirect path already claimed by another owner is skipped with a warning (the service's ports still work). A service's slot is freed when its routes are pruned.
* Workspace ids and service names must match `^[a-z0-9][a-z0-9-]{0,62}$` (they become hostnames and config); `core` is reserved.
* Reloads validate first; invalid config leaves live routes untouched. If the edge's single-file Caddyfile mount is stale (editor replaced the inode), the edge is recreated instead.

### Stream Routes & Registry
Services declaring raw TCP (`om.tcp=<port>`, optional `om.tcp.port=<host-port>`) are registered in `~/.local/state/om/registry/stream_ports.json`. HAProxy stream configurations (`edge.cfg` and `router.cfg`) are generated from active stream services:
* Default slots (`22000+n`) or explicit host ports are mapped to target containers `<ws>_<svc>:<cport>`.
* `om routes` and `om status` inspect both Caddy route files and the stream registry, presenting stream endpoints as `tcp://127.0.0.1:<port>` (and `tcp://<lan-ip>:<port>` for public services).

---

## 7. Outbound Access (Egress) and the Policy Gate

### What is Egress?
**Egress** refers to outbound network traffic initiated by your containers to destinations outside their own workspace network — such as public internet APIs, package registries (PyPI, npm), git repositories, or third-party identity/telemetry endpoints.

### Fail-Closed Internal Networks
In om, every workspace network (`<ws>_net`) is created with the `--internal` engine flag:
* **No Default Gateway:** Containers have no direct routing path to the host network or the internet.
* **No External DNS:** On internal networks, the engine's embedded DNS server (Aardvark on Podman, Docker embedded DNS) resolves only sibling container names within the workspace network and returns `NXDOMAIN` for all external domains.
* **Result:** Compromised containers or rogue dependencies cannot exfiltrate data, join botnets, or phone home by default.

### The `om_egress` Proxy
The only exit path for outbound traffic is through the hardened core proxy `om_egress` (Squid, see `docs/adr/0002-egress-proxy.md` and `docs/adr/0006-source-ip-egress.md`):
* `om_egress` connects to `om_core_net` (its only path to the outside world) and attaches to each workspace network.
* **Per-Service Source-IP Identity:** When a service specifies `om.egress=host1,host2...`, om deterministically assigns a static IP on its project internal network, persists it in `<state>/egress/ips/<ws>.json`, and injects plain `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` via a compose override (`<state>/egress/overrides/`). No credentials or passwords are used.
* **ACL Enforcement:** Squid inspects client source IP addresses and matches destination hostnames against that specific service's allowlist (`acl s_<id> src <ip>/32`). Unlisted hosts return `403 Forbidden`.
* **Anti-Spoofing:** Policy gate enforces `cap_drop: [NET_RAW]` (or `cap_drop: [ALL]`) and refuses `cap_add: [NET_RAW|NET_ADMIN]` on any service using `om.egress`, preventing raw packet construction and IP spoofing on the bridge network. Services within a compose project share a trust domain.
* **SSRF Prevention:** Private, loopback, and link-local ranges (RFC 1918, RFC 3927, 127.0.0.0/8) are hard-denied in Squid config, preventing containers from reaching host services or other core containers through the proxy.
* **Learn & Audit Modes:** Setting `om.egress=learn` allows outbound requests during discovery while recording every requested domain per service (`<state>/egress/learn/`). Learn mode auto-expires after a TTL (default 24h, configurable via `om.egress.learn_ttl`, e.g. `never`), falling back to deny-all with notification. Running `om egress log <svc> --apply` writes the exact allowlist to the compose file. For services that dynamically reach arbitrary external sources (e.g. scrapers, media indexers with extensions), `om.egress=audit` provides permanent non-expiring outbound access with continuous domain logging and fail-closed RFC 1918 private IP denial.

### Java / JVM Runtimes
Standard Linux tools (`curl`, Python `requests`/`urllib`, Node `fetch`, Go `net/http`) honor `HTTP_PROXY` and `HTTPS_PROXY` automatically with zero custom proxy-auth code. For Java/JVM runtimes, which ignore lowercase proxy environment variables by default, om automatically merges standard proxy system properties into `JAVA_TOOL_OPTIONS`:
`-Dhttp.proxyHost=om_egress -Dhttp.proxyPort=3128 -Dhttps.proxyHost=om_egress -Dhttps.proxyPort=3128 -Dhttp.nonProxyHosts="localhost|127.0.0.1|::1"`
Because identity is based on source IP, no proxy user or password tokens exist or need to be passed to JVM HTTP clients (avoiding authentication failures with OkHttp and modern HTTP libraries).

### Policy Gate & Deployments
* **Policy gate.** `om start` / `om sync` read each compose file through the engine's own `compose config` and refuse `privileged`, host namespaces, `ports:`, engine sockets and sensitive host mounts, capabilities beyond the engine's defaults, devices, unconfined security options, `om.egress=internet` on a service that writes or receives secrets, and plaintext secret files. `om.policy.allow=<rule>` waives one rule for one service (`privileged` and `ports` cannot be waived). `OM_POLICY=enforce` (default) refuses; `warn` only reports.
* **Images and deploys.** `.om/lock.json` pins every image to its registry index digest, applied through an override; a clean commit must be signed by a key the last deploy trusted (`OM_SIGNED`). Every deploy is a hash-chained generation in `<state>/generations/`.
* **Secrets** are age-encrypted in the repo and decrypted at start into `$XDG_RUNTIME_DIR` (memory), mounted read-only at `/run/secrets/<name>`, wiped on stop.
* **Cross-workspace links** (`lib/gitops/links.py`): when a service declares `om.link=<ws>/<svc>` and that service declares `om.link.allow` for it, om creates an internal network `omlink-<hash>` holding exactly those two containers, the provider aliased `<ws>-<svc>`. Declarations are read from the containers' labels, so start order doesn't matter; `om start` and the heal timer re-attach recreated containers, detach anything else found on a link network and remove links nobody declares.

---

## 8. URLs per Tier

| Tier | Dashboard | Services |
| :--- | :--- | :--- |
| This PC | `http://localhost/`, `http://<ws>.dashboard.localhost/` | `http://<ws>.<svc>.localhost/` |
| Your VPN | `http://<vpn-ip>/`; with Tailscale also `http://<machine>/`, `http://<machine>.<tailnet>.ts.net/` | `http://<vpn-ip or machine>:<20000+n>/` |
| LAN | `http://<lan-ip>/`, `https://<lan-ip>/` | `http://<lan-ip>:<21000+n>/` (public services only) |
| VPN guests (public tier) | `http://<vpn-ip>:8080/`; devices outside `OM_VPN_ALLOW` also `http://<vpn-ip>/` (Linux, macOS) | `http://<vpn-ip>:<21000+n>/` (public services only) |

`om routes` prints the exact URLs for the current workspace.

---

## 9. Host Firewall (L0)

`om firewall apply` generates and installs a ruleset from `~/.config/om/om.env`:

| OS | Mechanism | Persistence |
| :--- | :--- | :--- |
| Linux | nftables table `inet om_guard` (never flushes other tables, so Tailscale's and the engine's rules are untouched) | `om-firewall.service` loading `/etc/om-firewall.nft` (root-owned copy) |
| macOS | pf anchor `om` (`/etc/pf.anchors/om`) | add the anchor to `/etc/pf.conf` (printed by the command) |
| Windows | Windows Firewall rules in group `om`; default inbound action Block | persistent (run the generated script elevated) |

Accepted inbound: loopback, established/related (after the address rules), TCP 80/443, TCP 8080/8443 and 20000–20199 to VPN addresses only (public tier for VPN guests, private service ports), TCP 21000–21199 (public service ports, bound only on LAN and VPN addresses), TCP 22000–22199 to VPN addresses only (default stream ports), declared public stream ports (e.g. TCP 25565, bound on LAN and VPN addresses), UDP 443 (HTTP/3), UDP 5353 (mDNS, on Ethernet/Wi-Fi only, never over a tunnel), DHCP, essential ICMP/ICMPv6, plus `OM_FIREWALL_EXTRA_TCP/UDP`. A VPN's own transport needs no rule (its peers answer outgoing packets, conntrack lets the replies in). `om firewall remove` undoes it.

---

## 10. Container Hardening

| Container | Networks | Hardening |
| :--- | :--- | :--- |
| `om_caddy` | `om_core_net` only (the only container with host web ports) | read-only root, all caps dropped except `NET_BIND_SERVICE`, no-new-privileges |
| `om_router` | `om_core_net` + every `<ws>_net` and project network | same; listens on no network, only on a unix socket shared with the edge; admin API off |
| `om_stream_edge` | `om_core_net` only (the only container with host stream ports) | read-only root, all caps dropped except `NET_BIND_SERVICE`, no-new-privileges, 128m memory, 128 pids, HAProxy config validation healthcheck |
| `om_stream_router` | `om_core_net` + every `<ws>_net` and project network | same; listens on no network, only on unix sockets `/run/om-stream/N.sock` shared with stream edge |
| `om_egress` | `om_core_net` + every `<ws>_net` | read-only root, all caps dropped, user `squid`; Squid 7 on pinned Alpine (`core/egress/`), allowing only per-service listed hosts (`om.egress`), never private ranges; see `docs/adr/0002-egress-proxy.md` |
| `om_sockguard` | none (`network_mode: none`) | same; the only holder of the engine socket; re-exposes `GET` container list/stats on a unix socket, everything else 403 |
| `om_dashboard` | `om_core_net` | same; no engine socket, only `om_sockguard`'s filtered one |
| services from `om add` | `<ws>_net` (internal: no route out, no external DNS) | `expose:` only, no-new-privileges; outbound only via `om_egress` with `om.egress` |

Every core container has a memory limit (`om_caddy` 256 MB, the others 128 MB) and a `pids_limit` (256 / 128), about 2 to 4 times the peaks measured on a running core, and a healthcheck: `caddy validate` for the Caddy containers (config only, so they carry no `om.heal` label: a restart would not fix a bad config), `haproxy -c` for the stream containers, a TCP connect for `om_egress`, `/healthz` for `om_dashboard`. `om_egress` and `om_dashboard` carry `om.heal=restart`, so `om core heal` restarts them after 10 minutes unhealthy. There is no CPU limit: throttling the edge adds latency. The dashboard's *Core RAM* tile shows anonymous memory from `<state>/registry/core_memory.json`, which `om core heal` rewrites from the cgroups (Linux, local engine); without a fresh snapshot it shows the engine's figure, which includes shared file cache. The stats worker polls the engine only while a dashboard request has asked for stats in the last 30 seconds.

Residual risk, stated plainly: everyone who can join your VPN reaches the private tier, so the VPN account is the lock (Tailnet Lock with Tailscale; `om doctor` *VPN*). The dashboard does not hold the engine socket: code execution in it can list containers and read their stats, nothing more (`om doctor` probes this as *Engine filter*).

---

## 11. Verification

`om doctor` runs all of the following (38 checks) and prints a fix for each failure: Python, engine/compose/ports, core health (and no leftover retired containers), router attachment, edge isolation, published ports, address drift, private tier, DNS rebinding, router token (no network listener; refused without the token), the edge token in no log, engine filter (dashboard writes → 403), admin surface (edge listeners), running images = lock, egress (DNS, direct, host addresses blocked; proxy requires a credential), folder isolation (no name, no route between two folders' networks), generations (signed, chained), LAN scope, VPN (trusted and untrusted tunnels), VPN isolation (`*.localhost` refused on VPN addresses), address rules (`om.net`, `OM_VPN_ALLOW` in the firewall), links (two-sided, attached), custom routes (om.caddy), healthchecks (a warning for running workspace containers without one), stream ports (only declared stream ports published), stream firewall (rule exists for each stream port), stream isolation (stream router and edge unreachable from workspace containers), `.localhost` resolution, firewall, boot, login (a failure when another account that is not in `OM_TRUSTED_USERS` can log in and the private tier has none), private reach (a warning when a trusted VPN has neither a device allow-list nor a login), secret file modes, state location, registry, orphan routes.

Manual probes (attacks should print `000` = dropped or `403`; legitimate ones `200`/`302`):

```bash
c(){ curl -s -m4 -o /dev/null -w '%{http_code}\n' "$@"; }
X(){ podman exec <ws>_<svc> curl -s -m4 -o /dev/null -w '%{http_code}\n' "$@"; }   # from inside a service

c -H 'Host: attacker.example' http://127.0.0.1/api/workspaces        # DNS rebinding         → 000
X http://om_caddy/                                                    # container → edge     → 000
X -H 'X-Om-Upstream: other_svc:80' http://om_router:8000/             # router without token → 000
X http://<other-ws>_<svc>:80/                                         # cross-workspace      → 000
X http://om_dashboard/                                                # container → core     → 000
podman exec <ws>_<svc> nc -vz -w3 om_stream_router 1                  # container → stream router → refused
podman exec <ws>_<svc> nc -vz -w3 om_stream_edge 22000                # container → stream edge   → timeout
c http://<lan-ip>/api/system                                          # LAN telemetry        → 403
om ports                                                              # no other published ports

c http://localhost/ ; c http://<ws>.<svc>.localhost/ ; c http://<lan-ip>/<public-svc>/   # → 200
```

From **another device on the LAN** (the firewall doesn't filter the host's own traffic), every port except 80/443 should time out: `nc -vz -w3 <lan-ip> 9000`.

---

## 12. Updates, limits and notifications

* **Pins.** `.om/lock.json` maps each pulled image to its registry index digest (OCI distribution API, anonymous token; `lib/gitops/lock.py`). A moving tag changes nothing until a pin moves.
* **Moving a pin.** `om update` re-resolves the tags, commits the lock and redeploys through `start_workspace`; `--image REF` / `-i` move only some. Labels per service: `om.update=hold` keeps the image's pin (a ref is held when *any* service using it says so), `om.update=auto` lets the scheduled sync move it (only when *every* service using the image says so). An unknown value counts as `manual` and is reported. `--dry-run` also prints the registry's build date and compressed size of both digests.
* **Auto-update** (`auto_update` in `bin/om`, run by `om sync --scheduled` after a successful sync, at most every 6 hours per workspace): move the pins, commit the lock, redeploy, health-check. If the lock cannot be committed the pins are restored. If the health check fails, `git revert` undoes the lock commit, the previous images are redeployed and the failing digest is remembered in `.om/state.json` so it is not retried; a newer digest is.
* **Seeing it.** The heal timer looks for newer digests every 6 hours and writes `<state>/registry/updates/<ws>.json` (images and services); `om status` lists them and the dashboard, which mounts that folder read-only, shows `⬆ update` on a card (hidden on the public tier). `om scan` counts critical and high findings with `trivy` or `grype` when one is installed; om ships neither. `om prune` lists images no container uses and no workspace lock pins (plain `rmi` with `--yes`, never forced).
* **Service tools.** `om.cli=<path>` names a tool a service ships; `om cli <service>` (`lib/gitops/clicmd.py`) runs it as the user from the service's folder, with the workspace environment. The path must resolve to a file inside that folder (no absolute path, `..`, variable or symlink out), like the guard `om run` applies to `scripts/`; the label comes from the committed compose file, so it has the trust of any other script in the workspace.
* **Limits.** `om.mem`, `om.pids` and `om.cpus` become a compose override (`<state>/limits/overrides/`, `lib/gitops/limits.py`) passed with the egress, lock, secret, network and no-log overrides. A value that does not parse is reported and ignored. The core's own limits are in §10.
* **Notifications** (`lib/gitops/notify.py`). Every message is appended to `<state>/logs/notify.log`; `OM_NOTIFY` adds channels: `auto` (the default) is desktop (`notify-send`, `osascript`, a PowerShell toast), `webhook` POSTs the text to `OM_NOTIFY_URL`, `off` is none. The webhook is never automatic because it leaves the machine. A message with a key is sent once per key (`<state>/notify/seen.json`): an update per new digest, a failed sync per failing commit, a heal action per hour. Sources: `om core heal` (updates found, what it fixed) and `om sync --scheduled` (auto-updates, failed syncs). Desktop toasts need a graphical session, so a timer on a headless machine may not reach one.
