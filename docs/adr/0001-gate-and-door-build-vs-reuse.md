# ADR 0001 — Gate and door: build or reuse

- **Status:** superseded by ADR 0003 (2026-10-07): the door and the gate were built, used, and removed; the developer's VPN is the boundary
- **Date:** 2026-10-07
- **Context documents:** `VISION.md` ("Orchestrate, don't reinvent"), `GOALS.md`

## Context

`VISION.md` fills five parts with proven projects and keeps om as the glue: it verifies
signatures, renders the signed access file and compose labels into each part's configuration,
switches generations and proves the result. It also says *om writes no cryptography and no
authentication protocol of its own*.

The previous `GOALS.md` contradicted this for the gate: it planned `om_auth`, a Python service doing
WebAuthn, sessions and signature checks itself. This ADR settles, for the two parts that keep
attackers out — the **door** (which device?) and the **gate** (which person, and may they?) —
whether om builds or reuses, and which candidate it starts with.

### Requirements that decide the choice

A candidate is acceptable only if all of these hold. They come straight from `VISION.md`.

| # | Requirement | Why |
| :-- | :-- | :-- |
| R1 | **No second write path.** Who-may-reach-what comes only from files om renders from the signed access file. The part has no admin UI or API that can change access, or it can be disabled. | "Requests read; signatures write." |
| R2 | **Passkey-first.** A person signs in with a passkey alone; no password exists. | "No password database." |
| R3 | **Standard forward-auth** with Caddy, returning the verified user in a response header. | Edge = Caddy; gate = "spoken to through the standard forward-auth protocol". |
| R4 | **Device-aware rules.** A rule can require that the request comes from a given device address. | `shared` / `member` / `private`. |
| R5 | **Freshness.** A rule can require a sign-in in the last few minutes. | `private`. |
| R6 | **Small, rootless, hardened container**, pinned by digest, runnable `read_only` with `cap_drop: ALL`, on Linux, macOS and Windows engines. | Core container rules. |
| R7 | **Maintained**, with a public security-advisory history. | "Proven parts still have bugs." |
| D1 | **Door: key-bound peer address** visible to the edge, silent UDP port without a key. | Device proof. |
| D2 | **Door: no control plane om does not own.** | One source of truth (the access file). |

## Research pass (October 2026)

### Gate candidates

| Candidate | R1 no 2nd write path | R2 passkey-first | R3 forward-auth | R4 device rule | R5 freshness | Notes |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| **Build `om_auth`** (Python + vetted crypto lib) | yes, by design | yes | yes | yes | yes | Fits every rule because we write it — and therefore writes WebAuthn verification and session handling: the one thing the vision forbids. Unaudited by anyone but us. |
| **Authelia** 4.39+ | **mostly**: rules, users and sessions are YAML files; passkeys are stored in its SQL storage and self-registered through the portal (see gaps) | yes since 4.39.0 (passwordless passkey login); counting as `two_factor` needs an *experimental* user-verification option | native, made for it; returns `Remote-User`, `Remote-Groups`, `Remote-Email`, `Remote-Name` | yes: `networks:` per rule (CIDR, matched on first `X-Forwarded-For`, which our edge sets) combined with `subject: user:/group:` | partial: per-cookie-domain inactivity/expiration, no per-rule "signed in within N minutes" | ~20 MB image, ~30 MB RAM, no external DB required (SQLite, in-memory sessions). Four CVEs total, the auth-bypass one (2021) was nginx-specific; the 2026 XSS one is blocked by the default CSP. Cookie domain must have a dot and not be special-use; `.internal` must be tested. |
| **Pocket ID** (+ oauth2-proxy or tinyauth for forward-auth) | **no**: SQLite + web admin UI | yes, passkey-only, no password field anywhere | only via a second component | no (authentication only, no policy engine) | no | Excellent WebAuthn core, but two components and a UI that is a second write path. Good fallback *IdP*. |
| **tinyauth** | partial: env/labels | no (password + optional TOTP; passkeys only through an OIDC IdP) | yes | per-app user allow/block labels, no network rule | no | Simple, but would still need Pocket ID for passkeys. |
| **VoidAuth** | no: DB + admin UI | yes, passkey-only users since 1.1 | yes (ForwardAuth) | not documented | not documented | Young project (1.x). |
| **Kanidm** (+ oauth2-proxy) | no: DB + admin CLI/API of its own | yes, passkey-first | only via oauth2-proxy | no | partial | Strong security culture, but a full IdM with its own state. |
| **Authentik** | no: Postgres + admin UI and flows | yes, passkey-only flows | yes (outposts) | via policies | via flows | Heavy footprint; its policy engine *is* a second write path. |
| **caddy-security / AuthCrunch** | yes (Caddyfile) | partial | in-process | yes | — | Needs a custom Caddy build (breaks the pinned upstream image); no releases since March 2025. Rejected. |

### Door candidates

| Candidate | D1 key-bound address | D2 no foreign control plane | Rootless / cross-OS | Notes |
| :-- | :-- | :-- | :-- | :-- |
| **WireGuard, kernel module** (Linux) | yes (cryptokey routing) | yes | needs `NET_ADMIN` in a rootful namespace or host setup | Fastest, most reviewed. Host setup only through the opt-in `om door` / `om firewall`. |
| **WireGuard, `wireguard-go` in a container** | yes | yes | needs `/dev/net/tun`; reported **failing on Podman** in wg-easy (works on Docker) | The cross-OS path; must be proven on rootless Podman, Docker and podman machine. |
| **WireGuard userspace without TUN** (gVisor netstack) | yes in principle | yes | no device needed | No maintained, pinned *server* image does this today; building one is building a door. Kept as a spike option, not a plan. |
| **wg-easy** | yes | yes | as above | Ships a web UI that adds peers: a second write path (R1). Only its image layout is useful as reference. |
| **Headscale / NetBird** (self-hosted control plane) | yes | **no**: their ACLs and enrollment become a second source of truth | yes | Mesh features om does not need for one host. |
| **Tailscale** (`vpn:` door) | yes, with Tailnet Lock | no (third-party control plane) | userspace mode exists for containers | In userspace mode the service is reached through a proxy, so the edge may not see the true peer address: must pass the `vpn:` qualification test. |

### Supporting facts that change the design

- **Caddy `forward_auth` `copy_headers` did not strip client-supplied headers** in 2.10.0–2.11.1
  (CVE-2026-30851, fixed in 2.11.2). om pins Caddy 2.11.6, but the edge must still delete every
  identity header *before* `forward_auth`, and `om doctor` keeps its spoofed-header probe.
- Authelia matches `networks:` on the first `X-Forwarded-For` address, so the edge must overwrite
  (not append to) `X-Forwarded-For` with the WireGuard peer address. That makes the device rule a
  property of the edge configuration om renders — testable by a probe.
- Authelia's cookie covers a parent domain, so every service host receives it. The edge must strip
  it before the request leaves for the router, as it already strips `om_*` cookies.

## Decision

**Reuse for everything that authenticates; build only the glue.**

1. **Door: WireGuard, reused as-is.** Default implementation is the official one (kernel module on
   Linux, `wireguard-go` elsewhere) in a pinned, hardened container; om renders `wg0.conf` peers
   from the signed access file and nothing else adds peers. The spike picks the container layout
   per engine. Headscale, NetBird and wg-easy are rejected as defaults (second write path or
   control plane). Any other VPN stays possible as a `vpn:<ip>` door that must pass the
   qualification probe.
2. **Gate: Authelia, as the first candidate**, configured only from files om renders:
   `access_control` (one rule per service, `networks:` = the person's device addresses for
   `member`/`private`, `subject:` = granted users), `users_database.yml` with unusable password
   hashes (passkey-only in practice), sessions in memory, default policy `deny`. Its portal is the
   only thing it serves; it has no admin UI.
3. **om builds only:** the access-file signer/verifier (via `ssh-keygen -Y sign|verify`), the
   renderer (access file + labels → WireGuard peers, Authelia rules, Caddy routes), the generation
   switch, and the `om doctor` probes. No WebAuthn, no session code, no crypto.
4. **`om_auth` is not built.** Its earlier responsibilities map as follows:

| Earlier `om_auth` job | Now done by |
| :-- | :-- |
| WebAuthn, sessions, cookies | Authelia |
| `device` proof | WireGuard address → edge sets `X-Forwarded-For` → Authelia `networks:` |
| `grant` / `user` | Authelia `subject:` rendered from the access file |
| Verify identity signatures | om on the host, before rendering (data plane never verifies, it only reads) |
| Token to the router | edge, after `forward_auth` returns 2xx (existing `to_workspace` snippet) |

### Known gaps, and what happens to each

| Gap | Handling |
| :-- | :-- |
| Passkey self-registration in the portal is a request-plane write (R1). | Spike must show either (a) registration can be disabled and credentials imported with Authelia's storage CLI from the approved enrollment, or (b) registration requires an identity-verification step om controls (one-time code shown by `om approve`). If neither works, Authelia fails R1. |
| `passkey.fresh` (R5) has no per-rule equivalent. | Render `private` services under their own session cookie domain with a short expiration; if Authelia cannot do that, `private` becomes "device-bound + passkey" and freshness is listed as an honest limit. |
| `passkey.bound` (credential tied to a device). | Approximated by `networks:` = that person's own device addresses; documented as "person on one of their devices", not credential binding. |
| Passkey as `two_factor` relies on an experimental option. | Rules use `one_factor` (a passkey with user verification *is* the only factor that exists), so the experimental flag is not needed. |
| `.internal` cookie domain. | Spike tests it; if refused, local mode uses `<host>.home.arpa` or a sub-domain of an owned name. |

### Qualification (go / no-go, in the phase-3 spike)

Authelia is adopted only if `om doctor`-style probes pass on rootless Podman, Docker and podman
machine: no write path except rendered files; passkey-only sign-in; spoofed `Remote-*` /
`X-Forwarded-For` / `X-Om-*` headers ignored; a revoked user refused on the next request after a
re-render; container runs `read_only`, `cap_drop: ALL`, no engine socket.

### Gate spike results (Authelia 4.39.28, rootless Podman, 2026-10-07)

| Check | Result |
| :-- | :-- |
| Hardened run | works with `--read-only`, `cap_drop: ALL`, `no-new-privileges`, given two adjustments: a writable bind mount for `/app/.healthcheck.env` (Authelia writes it at start; read-only root otherwise fails the opaque "startup checks"), and `ntp.disable_startup_check` (no internet on purpose) |
| Cookie domain | `<host>.internal` accepted; `home.arpa` refused (public suffix list), single-label names refused |
| `shared` (bypass + door subnet) | enrolled device address → 200; LAN address → 403 |
| `member` (one_factor + user + device address) | no session → 401 + redirect to portal; session from the person's own device → 200 with `Remote-User`; same session from another device or the LAN → 403 |
| Unknown host | 403 (`default_policy: deny`) |
| Registration lock (R1) | registering a WebAuthn credential without an elevated session → 403 `elevation: true`; the elevation one-time code is written to the filesystem notifier, i.e. a file only om reads — so `om pending` can show it and the owner decides |
| `private` freshness (R5) | a second cookie domain may not be a subdomain of the first (shares cookie scope), but a sibling (`<host>-p.internal`) validates: private services can live there with a 5-minute inactivity session |
| Passkey-only sign-in in a browser | **not yet tested** (needs a real authenticator on an enrolled device) |

**Fallback order if it fails:** Pocket ID (passkeys) + oauth2-proxy (forward-auth) with om-rendered
allow-lists and the admin UI unreachable from any door; then Kanidm + oauth2-proxy. Building
`om_auth` is the last resort and needs a new ADR that explains why every reuse option failed.

## Consequences

- **Good:** om's security-critical code shrinks to signing, rendering and probing; the WebAuthn
  and session code is maintained and attacked by a much larger community; parts stay swappable
  (`OM_GATE=authelia`, `OM_DOOR=wireguard`).
- **Bad:** om depends on Authelia's configuration format and release cadence; two of the vision's
  proofs (`fresh`, `bound`) may weaken to approximations; Authelia's SQL storage is service data
  that must be backed up.
- **Neutral:** the router stays exactly as today; the edge gains `forward_auth` and header hygiene.

## Sources

- Authelia passkeys (passwordless since 4.39.0; experimental UV option): https://www.authelia.com/overview/authentication/security-key/
- Authelia access control (`networks`, `subject`, `default_policy`): https://www.authelia.com/configuration/security/access-control/
- Authelia session cookie rules: https://www.authelia.com/configuration/session/introduction/
- Authelia CVEs: https://releasealert.dev/cve/CVE-2026-33525 , https://github.com/advisories/GHSA-68wm-pfjf-wqp6
- Authelia vs Pocket ID as forward-auth: https://bex.co/blog/2026/07/28/authelia-pocket-id-forward-auth-admin-dashboard
- tinyauth vs Pocket ID vs Authelia: https://sumguy.com/tinyauth-vs-pocket-id-vs-authelia/
- Pocket ID with proxies: https://pocket-id.org/docs/guides/proxy-services
- Authelia vs Authentik 2026: https://www.cerbos.dev/blog/authelia-vs-authentik-2026-idp
- Kanidm: https://www.kanidm.com/ ; VoidAuth passkey-only users: https://peachpie.theatl.social/post/49741
- AuthCrunch activity: https://opencollective.ecosyste.ms/projects/75559
- Caddy `forward_auth`: https://caddyserver.com/docs/caddyfile/directives/forward_auth ; CVE-2026-30851: https://api.osv.dev/v1/vulns/GO-2026-4639
- wireguard-go on Podman: https://github.com/wg-easy/wg-easy/issues/2435 , https://github.com/containers/podman/discussions/20302
- Tailscale userspace networking: https://tailscale.com/docs/concepts/userspace-networking
- Self-hosted VPN comparison: https://meshwg.com/compare/netbird-vs-headscale/
