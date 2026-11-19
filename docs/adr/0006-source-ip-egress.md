# ADR 0006 — Outbound Egress: Source-IP Identity and Zero-Credential Proxy

- **Status:** accepted
- **Date:** 2026-11-18
- **Supersedes:** ADR 0002 (proxy authentication credential mechanism)
- **Amends:** ADR 0003, ADR 0004

## Context

In ADR 0002, `om` implemented outbound egress filtering using Squid (`om_egress`) on `--internal` workspace networks. Under ADR 0002, per-service identity was established using proxy basic authentication: `om` generated a random credential per service (`http://<ws>.<svc>:<token>@om_egress:3128`), hashed it into a Squid `passwd` file, and injected it into container environment variables (`HTTP_PROXY`, `HTTPS_PROXY`).

### The Root Flaw
Client-credential identity depends on every application's HTTP client stack correctly parsing proxy credentials from environment variables and answering Squid's `HTTP 407 Proxy Authentication Required` challenge.

In production workloads (specifically JVM services using OkHttp, such as Suwayomi-Server), this assumption failed completely:
1. OkHttp ignores credentials embedded in `HTTPS_PROXY` URL userinfo for HTTPS CONNECT tunnels.
2. Standard JVM system properties (`-Dhttp.proxyUser` / `-Dhttp.proxyPassword`) are ignored by modern HTTP client libraries (including OkHttp) unless the application explicitly installs a custom `proxyAuthenticator`.
3. Consequently, requests fail with:
   `java.io.IOException: Failed to authenticate with proxy at okhttp3...ConnectPlan.createTunnel`

Requiring application-specific code modifications or runtime-specific workarounds violates `om`'s dual core principles: **MOST SECURE** and **MOST GENERIC**. A feature that requires per-app workarounds is a bug in `om`.

## Gate Verification

We empirically investigated network traffic on rootless Podman (netavark/aardvark) and Docker user-defined bridge networks:
- In container-to-container communication on user-defined internal networks (`<ws>_<folder>_net`), the real source IP address of the originating container is fully preserved in the IP packet headers seen by `om_egress` (e.g. `10.89.12.50`). Rootless port-forwarding NAT collapses source addresses only at the host ingress edge, **not** on container-to-container internal bridge networks.
- Squid access logs confirmed exact client source IP logging without source NAT:
  `1794951973.641 42 10.89.12.50 TCP_TUNNEL/200 5544 CONNECT raw.githubusercontent.com:443 - HIER_DIRECT/185.199.111.133 -`

## Alternatives Evaluated

| Option | Isolation & Security | Generality | Resource Cost | Ranking |
| :--- | :--- | :--- | :--- | :--- |
| **Source-IP Identity (Deterministic Static IP + Anti-Spoofing)** | **High**: Pinned IP per service + anti-spoofing via `cap_drop: [NET_RAW]` enforced by policy gate. Squid ACLs match `src <ip>/32`. | **Universal**: Standard plain `HTTP_PROXY=http://om_egress:3128` without credentials. Works with all runtimes (curl, Go, Python, Node, OkHttp/JVM). | **Zero**: No additional sidecars or background processes. | **#1 (Chosen)** |
| **Per-Service Egress Proxy Sidecar** | **High**: Each service talks to a dedicated local loopback proxy sidecar that forwards to Squid. | **High**: Plain loopback proxy. | **Heavy**: Adds 1 container/process per service, multiplying memory overhead across projects. | **#2** |
| **Per-Service Squid Port** | **Weak**: Squid opens a distinct TCP port for each service. | **High**: Port-based proxy without credentials. | **Low**: Single proxy instance, but any container on the project network can route through any port. | **#3 (Rejected)** |
| **Transparent Interception (TPROXY / REDIRECT)** | **Medium**: No client proxy config needed. | **Broken**: Incompatible with rootless netavark namespaces, unprivileged containers, and `--internal` networks without default gateways. | **High complexity** | **#4 (Rejected)** |

## Decision

1. **Identity via Pinned Source IP:**
   - Each service declaring `om.egress` is deterministically assigned a static `ipv4_address` on its project network (`<ws>_<folder>_net`).
   - Mappings are persisted in `$OM_STATE_DIR/egress/ips/{ws}.json`.
   - `om` injects `networks: { <project_net>: { ipv4_address: <ip> } }` into the generated compose override.
   - Pinned addresses eliminate IP recycling windows across container recreations.

2. **Per-Service Squid Source-IP ACLs:**
   - Squid configuration is generated deterministically in `$OM_STATE_DIR/egress/acl/{ws}.conf`.
   - Rules pair the container's source IP with its allowed hostnames:
     ```text
     acl s_<id> src <ip>/32
     acl d_<id> dstdomain host1 .host2
     http_access allow s_<id> d_<id>
     ```
   - Destinations in RFC 1918, RFC 3927 (link-local), loopback, host addresses, and core containers are denied before any service rules (`http_access deny to_private`).
   - The configuration ends with a strict `http_access deny all`.
   - Squid reconfigures dynamically via `squid -k reconfigure`.

3. **Zero-Credential Environment Injection:**
   - `om` injects plain `HTTP_PROXY=http://om_egress:3128`, `HTTPS_PROXY=http://om_egress:3128`, and `NO_PROXY=...` (plus lowercase equivalents) with **no** embedded credentials.
   - For Java/JVM services (detected via image heuristics or `om.egress.jvm=true`), `om` merges `-Dhttp.proxyHost=om_egress -Dhttp.proxyPort=3128 -Dhttps.proxyHost=om_egress -Dhttps.proxyPort=3128 -Dhttp.nonProxyHosts=...` into `JAVA_TOOL_OPTIONS` without overwriting existing options. Zero secrets are exposed in process tables or environment variables.

4. **Anti-Spoofing and Policy Gate Enforcement:**
   - To prevent container IP spoofing on the internal bridge, `om policy check` strictly requires `cap_drop: [NET_RAW]` (or `cap_drop: [ALL]`) and refuses `cap_add: [NET_RAW|NET_ADMIN]` on any service using `om.egress`.
   - Without `NET_RAW`, the Linux kernel prevents unprivileged raw packet construction (`PermissionError: [Errno 1] Operation not permitted`).
   - Services within the same compose file share a trust domain.

5. **First-Class Learn & Audit Modes:**
   - `om.egress=learn` allows outbound traffic to public destinations while recording every accessed host per service (`host`, `first_seen`, `count`) in `$OM_STATE_DIR/egress/learn/{ws}/{svc}.json`.
   - Learn mode automatically expires after a configurable TTL (`om.egress.learn_ttl`, default `24h`, or `never` to disable expiry), falling back to deny-all with desktop/webhook notifications (`notify.notify`).
   - `om.egress=audit` provides permanent non-expiring egress with continuous host recording in `$OM_STATE_DIR/egress/learn/` for services that require dynamic access (e.g. extension managers, scrapers) while keeping RFC 1918 hard-blocked.
   - `om egress log <svc> --apply` updates the compose file with the exact discovered host allowlist.
   - `om doctor` warns on services in learn or audit mode and fails if `learn`, `audit`, or `internet` is combined with writable volumes or secrets without explicit `om.policy.allow=egress`.

6. **Live Verification via `om doctor`:**
   - `om doctor` runs active live probes on each network verifying:
     - DNS queries return NXDOMAIN (blocked).
     - Direct outbound TCP is blocked.
     - Host ports are unreachable.
     - Cross-service allowlist reuse is denied (HTTP 403).
     - Raw packet forging is blocked by capability dropping.

## Migration Note

The basic authentication mechanism (`auth_param basic`, `basic_ncsa_auth`, `passwd` file) is deprecated and removed.

- **Automatic Migration:** Running `om start` re-renders all ACLs to the source-IP format and injects credential-free proxy variables into compose overrides.
- **Compose Files:** If user compose files contained manual `JAVA_TOOL_OPTIONS` or application-specific proxy environment variables carrying credentials (`proxyUser`/`proxyPassword`), those credentials should be removed. `om` handles JVM system property injection automatically.
