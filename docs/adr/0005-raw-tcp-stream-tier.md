# ADR 0005 — Raw TCP stream tier (unix socket bridge and HAProxy)

- **Status:** accepted
- **Update (2026-11-24):** om no longer supports Docker; it runs on Podman only. The Docker analysis below is kept as the record of why the design looks as it does.
- **Date:** 2026-11-11
- **Amends:** ADR 0003, ADR 0004

## Context

om enforces a strict fail-closed network perimeter: user compose files cannot declare `ports:` (unwaivable policy gate), and every workspace network `<ws>_net` is created `--internal` (no route out, no external DNS). Up to now, all inbound access passed through Caddy HTTP reverse proxy tiers (L1/L2/L3).

Services requiring raw TCP protocols (such as Minecraft game servers on TCP 25565, database protocols, Redis, MQTT, or custom stream daemons) could not be routed through om. These protocols lack HTTP headers: there is no `Host` header for virtual hosting, no `X-Om-Edge-Token` to prove origin from the edge proxy, and no `X-Om-Upstream` header to declare the destination container.

Attaching an edge proxy directly to workspace networks would violate the fundamental isolation guarantee (a compromised workspace container could reach the edge or other workspaces). Publishing ports directly from workspace containers would bypass om's firewalling, logging, and access tiers entirely.

## Decision

We introduce a raw TCP stream tier based on a dual-proxy architecture connected by private unix domain sockets:

```text
player -> host port N -> om_stream_edge (om_core_net only)
       -> unix socket /run/om-stream/N.sock (om_stream_sock volume)
       -> om_stream_router (attached to <ws>_net networks, no network listener)
       -> <ws>_<svc>:<container-port>
```

### 1. Zero-Network Router Lock
Because raw TCP cannot carry a security token, the isolation lock is structural:
- **`om_stream_router`** has no TCP or UDP network listeners. It listens exclusively on filesystem unix domain sockets `/run/om-stream/N.sock` located in a private Docker volume (`om_stream_sock`).
- **`om_stream_edge`** is attached only to `om_core_net`. It is the only container publishing stream ports to the host. No workspace container can connect to it.
- Sockets are created with permissions `mode 660` owned by `haproxy:haproxy` (uid 99 / gid 99) in Alpine HAProxy.

### 2. Static Configuration Generation
Routing is strictly static:
- Route generation validates and renders fragments into `<state>/stream/fragments/{edge,router}/`.
- For each service, the edge maps host port `N` directly to `/run/om-stream/N.sock`.
- The router maps `/run/om-stream/N.sock` to exactly one upstream target `<ws>_<svc>:<container_port>`.
- A workspace container cannot reach the router over the network, cannot inject traffic into sockets, and cannot select an upstream target.

### 3. HAProxy in TCP Mode
Both `om_stream_edge` and `om_stream_router` use pinned Alpine HAProxy (`docker.io/library/haproxy:3.0-alpine@sha256:35114f41284747c8b460babd0c082d5d8e0268218b167240f47d15d0474b718b`):
- Operates in `mode tcp`.
- Supports zero-downtime reloads via master-worker process model (`-W`) and `SIGUSR2`.
- `om_stream_router` dynamically resolves `<ws>_<svc>` container names at runtime using Docker/Podman internal DNS (`resolvers docker`, `parse-resolv-conf`, `init-addr libc,none`).
- Configs are validated before reloads (`haproxy -c`); invalid configurations fail closed, leaving the active configuration untouched.

### 4. Port Allocation & Publishing
- **Default slots (`22000+n`)**: 200 default stream slots (`22000–22199`) recorded in `<state>/registry/stream_ports.json`. These ports are pre-published once in `ports.yml` so adding or removing default stream services never recreates `om_stream_edge`.
- **Explicit ports (`om.tcp.port=<port>`)**: Specific ports (e.g. 25565) are reserved in `stream_ports.json`. Adding an explicit port updates `ports.yml` and recreates `om_stream_edge` (active connections on other stream ports are dropped during recreate).
- **Scope**: Tier follows `dashboard.scope=public` (public binds LAN and VPN addresses; private binds loopback and VPN only).
- Ports below 1024 and collisions with HTTP tiers (80, 443, 8080, 8443, 20000–21199, 22000–22199) are rejected.

### 5. Host Firewall Integration (Fail-Closed)
- Public stream ports are accepted on LAN and VPN interfaces (`tcp dport { ... } accept`).
- Private stream ports and the default range (22000–22199) are accepted only on VPN addresses (`ip daddr { <vpn_ips> }`).
- `om.net.allow` and `om.net.deny` apply to stream ports.
- `OM_VPN_ALLOW` restricts private stream ports on VPN interfaces.
- If the active host firewall lacks a service's `om.net` rules (`hostsetup.net_policy_enforced`), the service's stream port is not bound (fail closed).

## Consequences & Limits

1. **Rootless Port Forwarding & Client IPs**:
   Rootless Podman and Docker forward packets through a userland proxy, presenting a single internal bridge IP to `om_stream_edge`. Per-client IP allow/deny rules must therefore be enforced at the host firewall (`om_guard`). In-application client controls (such as Minecraft's `WHITELIST=TRUE`, `ENFORCE_WHITELIST=TRUE`, and `ONLINE_MODE=TRUE`) remain essential.
2. **Explicit Port Recreation**:
   Declaring an explicit host port (e.g. 25565) recreates `om_stream_edge`, momentarily terminating active connections on other stream services. Using default slots (22000–22199) avoids this recreate.
3. **Java/Egress Proxy Requirements**:
   Java runtimes ignore standard `HTTP_PROXY` and `HTTPS_PROXY` environment variables. Java applications (such as Minecraft downloading server jars and authenticating against Mojang APIs) must be provided proxy properties via `JAVA_TOOL_OPTIONS`:
   `-Dhttp.proxyHost=om_egress -Dhttp.proxyPort=3128 -Dhttps.proxyHost=om_egress -Dhttps.proxyPort=3128 -Djdk.http.auth.tunneling.disabledSchemes=""` along with Basic auth credentials.
