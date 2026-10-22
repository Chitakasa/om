# ADR 0002 — Egress: internal networks and an allow-list proxy

- **Status:** accepted (spike passed on rootless Podman, 2026-10-07; Docker and podman machine still to verify)
- **Date:** 2026-10-07
- **Context documents:** `docs/DESIGN.md` ideas 5 and 6

## Context

G5: a service cannot reach the host, the edge, another workspace or the internet, except the exact
hosts it lists in `om.egress`. Today every `<ws>_net` is an ordinary bridge with full outbound
access, so a hostile dependency can phone home. G7: this must not make development painful, so a
blocked call has to say what to add.

Two mechanisms are needed: something that **cuts** outbound traffic, and something that **lets
through** only the listed names.

### Requirements

| # | Requirement |
| :-- | :-- |
| E1 | Default: no outbound packets and no external DNS from a workspace container. |
| E2 | Per-**service** allow-list by hostname (wildcards like `*.example.com`), for HTTPS (`CONNECT`) and plain HTTP. |
| E3 | The proxy must know *which service* is asking, in a way another container cannot forge. |
| E4 | Refuses private, loopback and link-local destinations, so it cannot be used to reach the host, the core or another workspace. |
| E5 | Logs denials with the service and hostname, so `om` can print the `om.egress` line to add (G7). |
| E6 | Reused, maintained, pinned multi-arch image, runnable hardened; same on Linux, macOS, Windows engines. |
| E7 | No TLS interception: om never sees service traffic in clear. |

## Research pass (October 2026)

### Cutting outbound traffic

| Option | Finding |
| :-- | :-- |
| **`internal` networks** (`network create --internal`) | No route out on both engines. **Podman** (netavark/aardvark-dns): on an internal network aardvark resolves only container names and answers NXDOMAIN for everything else, so DNS cannot be used as a side channel. **Docker** ≥ 26.0 (CVE-2024-29018 fix) no longer forwards DNS from internal networks; 26.1 fixed a regression. Same flag on every OS. **Chosen.** |
| Host firewall per container (nftables/pf) | Host-specific, not identical across OSes, and fights the engine's own rules. Rejected. |

### Letting listed names through

| Candidate | E2 per-service names | E3 who is asking | E4 private ranges | E6 image | Notes |
| :-- | :-- | :-- | :-- | :-- | :-- |
| **Squid** (`ubuntu/squid`, Canonical) | `dstdomain` ACLs for `CONNECT` and HTTP | **proxy auth**: one credential per service, `proxy_auth` ACLs | `dst` ACLs deny RFC1918, loopback, link-local | Canonical rock, multi-arch. Registry tags (Docker Hub page is inaccurate): `6.6-24.04_beta` (LTS to 05/2029, **ships Squid 6.13** with Ubuntu security updates) and only `7.2-26.04_edge` for Squid 7 | The 2021 audit found 55 issues; all fixed as of Squid 7.0, and ESI is removed in 7. Large C++ codebase: we enable only forwarding (no cache, no ssl-bump). |
| **Smokescreen** (Stripe) | yes, YAML ACL with wildcards, report/enforce modes | **mTLS client certs only**; anything else needs a custom build (`RoleFromRequest`) | yes, by default | no official image (third-party `pretix/smokescreen`) | Designed for exactly this job, but per-service identity means om minting client certificates or forking. Rejected for now; revisit if it ships an image and header/basic-auth roles. |
| **tinyproxy** | filter list is **global**, not per user | `BasicAuth` exists but cannot select a filter | no built-in | only third-party images | Fails E2/E3 per service. Rejected. |
| **Caddy `forward_proxy`** | yes | basic auth | partial | needs a custom Caddy build | Breaks the pinned upstream image (same reason AuthCrunch was rejected). Rejected. |
| **Envoy** | yes (RBAC + SNI) | via headers/mTLS | yes | official | Heavy configuration for one host; nothing it adds is needed. Rejected. |
| Source-IP rules (any proxy) | — | container IP | — | — | IPs change on restart and can be reused by another container before om re-renders. Rejected for identity. |

## Decision

1. **Every `<ws>_net` becomes `internal`.** Existing networks are recreated by an explicit command
   (`om network harden`), never silently; new workspaces get internal networks from the start.
2. **`om_egress`: Squid built from `core/egress/Containerfile` (Squid 7.6 on pinned Alpine 3.24; first written against `ubuntu/squid:6.6-24.04_beta`)**, attached to
   `om_core_net` (its only route out) and, like `om_router`, to every `<ws>_net`. om renders its
   whole configuration into `$OM_STATE_DIR/egress/`:
   - per service with `om.egress`: a random credential (hashed with `caddy hash-password`, bcrypt,
     which Squid's `basic_ncsa_auth` reads through libxcrypt), an ACL `user <ws>.<svc>` +
     `dstdomain` list, `http_access allow` only for that pair;
   - `deny` for private, loopback and link-local destinations, `CONNECT` only to port 443,
     no cache, no ssl-bump, `http_access deny all` last.
3. **Services get their credential through an om-generated compose override**
   (`HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` for that service only). Services without `om.egress` get
   nothing, so they have no way out at all.
4. **Labels.** `om.egress=api.example.com,*.cdn.example.com` or `om.egress=internet`. The policy
   gate validates names, and enforces the law: `internet` only for a service with no writable
   mount and no secrets.
5. **Learn mode (G7).** `om egress log` reads `om_egress`'s denials and prints, per service, the
   exact `om.egress=…` line that would allow them.

### Spike results (rootless Podman 5, 2026-10-07)

| Check | Result |
| :-- | :-- |
| `7.2-26.04_edge` on rootless Podman | **fails to unpack**: a file owned by UID 584792 exceeds the default 65536 subuid range. Not usable without host changes; revisit when a 26.04 tag fixes it. |
| `6.6-24.04_beta` hardened | runs `--read-only`, `--cap-drop ALL`, `no-new-privileges`, `--user proxy`, tmpfs `/tmp /run /var/log/squid /var/spool/squid`; needs `pinger_enable off`, `shutdown_lifetime 1 seconds` |
| bcrypt from `caddy hash-password` | accepted by `basic_ncsa_auth`; cost 14 makes the first request per credential TTL take ~1.5 s, cached afterwards |
| internal network | external DNS: NXDOMAIN; direct HTTPS by name and by IP (`1.1.1.1:443`): unreachable |
| through the proxy | listed host (HTTPS and HTTP): 200; unlisted: 403; wrong or missing credential: 407; private IP and a container on the same internal network: 403 |
| denial log | `TCP_DENIED/403 … CONNECT github.com:443 ws.web` — service and host present for learn mode |

### Still to verify

- Docker and podman machine (rootless Podman done above): a container on an internal network gets NXDOMAIN for
  external names and no route out; through `om_egress` it reaches a listed host and gets 403 for an
  unlisted one, for a private IP, and for another workspace's container.

**Fallback if Squid fails a check:** Smokescreen with om-minted client certificates (one per
service, from om's existing root CA, created inside a pinned container), or per-workspace instead of
per-service allow-lists as an interim step.

## Consequences

- **Good:** a hostile dependency without a listed host has no way out, not even DNS; a listed host
  is reachable only by the service that listed it; every denial is visible and explained.
- **Bad:** applications that ignore `HTTP(S)_PROXY` fail closed until configured; Squid is a large
  C++ program in the egress path (mitigated: forwarding only, pinned, reachable only from workspace
  networks, cannot reach private ranges); another core container to keep updated.
- **Neutral:** routes, the edge and the router are unchanged; inbound traffic still flows edge →
  router → service on the same (now internal) networks.

## Sources

- Podman internal networks and aardvark-dns: https://docs.podman.io/en/stable/markdown/podman-network.unit.5.html , CVE-2025-8283: https://access.redhat.com/security/cve/CVE-2025-8283
- Docker internal-network DNS (CVE-2024-29018): https://security-tracker.debian.org/tracker/CVE-2024-29018 , https://docs.docker.com/engine/release-notes/26.1.md
- `ubuntu/squid` image and tags: https://hub.docker.com/r/ubuntu/squid
- Squid audit status: https://joshua.hu/squid-security-audit-35-0days-45-exploits
- Squid egress allow-listing: https://www.qovery.com/docs/getting-started/guides/advanced-tutorials/egress-filtering-squid-proxy
- `basic_ncsa_auth` hash formats: https://www.mankier.com/8/basic_ncsa_auth
- Smokescreen: https://github.com/stripe/smokescreen
- tinyproxy filter options: https://hub.docker.com/r/owncloudops/tinyproxy
