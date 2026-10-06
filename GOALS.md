## Networking architecture update — identity-based access

Redesign access control so the same rules work unchanged on LAN (mDNS `archlinux.local` or
`<dynamic_name>.local`), Tailscale (or any private VPN), and the public internet (a cheap or free
domain, no heavy hosting) — without giving up anything in `docs/NETWORK_ARCHITECTURE.md`.

### CURRENT (om 1.0)
- Access = **network position**. The edge binds loopback + Tailscale IP → container `:80/:443`
  (private tier: everything), LAN IP → `:8080/:8443` (public tier: only `*.public_subpath`).
- Only identity: optional HTTP Basic auth on the whole private tier (`om auth add`).
- Per-service scope is a label: `dashboard.scope=public`, anything else = private.
- The dashboard also *guesses* scope from the `Host` header (`.local`, `.home`, RFC 1918 →
  public) in `server.py:_is_public_scope` — a heuristic, not a decision.
- Gaps: no per-person access, nothing between "LAN sees public" and "Tailscale sees all",
  no internet listener, any local OS user is "private" unless Basic auth is on.

---

## GOALS
1. **Access depends on WHO the client is, not where it sits.** Network position becomes one
   *proof* among others, never the only one (except for `public`). No MAC addresses (spoofable,
   randomized, invisible past a router).
2. **Anonymous** visitors see a dashboard with only public items.
3. **Logged-in** users see public items plus the items granted to them — nothing else, not even names.
4. **Enforced on EVERY request, at the edge** (dashboard, `<ws>.<svc>` vhosts, `/<svc>/` subpaths,
   WebSockets), never only in the dashboard UI. Default deny.
5. **Config, not code.** Adding a hostname, a domain, a tunnel, a listener or an identity method
   is an `om.env` / label change. om stays generic (no service, host or user names in code).
6. **Zero-daemon and stdlib-only stay true.** No om process on the host; new pieces are pinned,
   hardened core containers; Python stays stdlib.
7. **Defense in depth is kept, not replaced.** Socket separation, route absence, the router token
   and the host firewall remain; identity is a new layer on top (L3 becomes "L3 identity gate").
8. **Same behavior on Linux/macOS/Windows**, rootful/rootless, Podman/Docker — or a clearly
   reported, tested degradation (`om doctor`).

### NON-GOALS (for now)
- Being an OIDC/SAML provider for other apps (possible later as a provider, not a rewrite).
- Syncing users between several om hosts (each host keeps its own DB; link via API later).
- Replacing an app's own login (Jellyfin, Home Assistant keep theirs; om gates in front).

---

## ACCESS LEVELS (each service declares the minimum it needs)

Declared by label in the workspace's compose file (portable, versioned). Who is granted what is
machine state (DB). Unknown/typo/missing label = `private` (same fail-closed rule as today).

| Level     | Who gets through                                                                 |
| :-------- | :------------------------------------------------------------------------------- |
| `public`  | Anyone. No login.                                                                |
| `user`    | Signed-in user (passkey session or API token) **and** a grant for this resource. |
| `private` | `user` **plus a device proof bound to the same user**: a mapped VPN/Tailscale peer or an enrolled mTLS device. |
| `admin`   | Users with role `admin`, with a device proof. Portainer, om settings, user management. |

- Label: `om.access=public|user|private|admin`. `dashboard.scope=public` keeps working as an alias
  for `om.access=public` (back-compat); a service with neither is `private`.
- Resources are `<ws>/<svc>`. Grants may target `<ws>/*` (whole workspace) or `*` (everything a
  level allows). A grant never raises a resource above its declared level's proof requirement —
  a `private` service always needs the device proof, whatever the grant says.
- Portainer and anything holding the engine socket are `admin` (it equals root on the engine user).
- Optional per-label tightening: `om.access.listeners=lan,tailscale` (resource is never served on
  the internet listener even to granted users).

---

## ARCHITECTURE

### One pipeline for every request
```
client ─► listener (host socket → its own container port) ─► edge (om_caddy)
          strip all client X-Om-* headers
          forward_auth ─► om_auth  (resource, level, listener, client IP, cert fingerprint)
                          proofs → identity → grants → allow | 401/redirect-to-login | 403
          on allow: set X-Om-User / X-Om-Roles ─► om_router (edge token) ─► <ws>_<svc>
```
- This *is* "request → identity → grants → allow/deny", implemented with what om already has
  (Caddy `forward_auth` + the generated routes), so every route gets it for free.

### New core container: `om_auth`
- Pure-stdlib Python, same hardening as the dashboard (`read_only`, `cap_drop: ALL`,
  no-new-privileges), on `om_core_net` **only**, **no engine socket** (the dashboard holds the
  socket; the identity DB must not live in the same process).
- "om must only accept requests from the proxy" is satisfied by topology, like the router today:
  workspace containers cannot reach `om_core_net`; additionally every edge → `om_auth` call carries
  the edge token (`X-Om-Edge-Token`), and `om_auth` rejects anything without it.
- Serves: `/verify` (forward_auth target, must be fast: one indexed SQLite read, small in-memory
  cache keyed by session id ≤ 5 s), login/enroll pages, and an admin API used by the dashboard.

### Edge changes (generated, never hand-written)
- `render_vhost` / `render_subpath` emit `import gate <ws>/<svc> <level>` before `import to_workspace`.
  `public` emits nothing extra (no auth hop for public traffic).
- `(gate)` snippet: `request_header -X-Om-*` then `forward_auth om_auth:80 { uri /verify?... ;
  copy_headers X-Om-User X-Om-Roles }`. The edge sets the context headers (`X-Om-Listener`,
  `X-Om-Client-IP`, `X-Om-Client-Cert` = `{http.request.tls.client.fingerprint}`), overwriting
  client values — same pattern as `to_workspace`.
- The router keeps stripping the token; it **forwards** `X-Om-User`/`X-Om-Roles`, so apps can do
  SSO by trusting those headers. Caveat to document: they are trustworthy only on requests coming
  through the router — a container on the same `<ws>_net` can call a sibling with forged headers.
- Core routes (`00-info.caddy`, `portainer.*`) use the same gate (`admin`).

### Listeners (config-driven, each on its own container port)
Today loopback and Tailscale share container `:80`, so the edge can't tell them apart except by
`Host`. Each listener gets its own container port pair; the edge stamps `X-Om-Listener` from the
port, never from `Host` or source IP guesses.

| Listener    | Host bind              | Container ports | Allowed proofs                     | Max level by default |
| :---------- | :--------------------- | :-------------- | :--------------------------------- | :------------------- |
| `loopback`  | 127.0.0.1, [::1]       | 80/443          | passkey, token, (optional `OM_LOOPBACK_TRUST`) | admin |
| `tailscale` | Tailscale IP           | 9080/9443       | passkey, token, tailscale peer     | admin                |
| `lan`       | LAN IP                 | 8080/8443       | passkey, token, mTLS               | private              |
| `internet`  | port-forward / tunnel target | 10080/10443 | passkey, token, mTLS             | user                 |

```ini
# om.env
OM_LISTENERS=loopback,tailscale,lan            # add ,internet to go public
OM_DOMAIN=om.example.com                       # empty = no domain, IP/.local/.localhost only
OM_HOSTNAMES=archlinux.local                   # extra names (mDNS etc.)
OM_LOOPBACK_TRUST=none                         # none | admin  (admin only on single-user machines)
OM_INTERNET_MAX_LEVEL=user
```
- `render_ports` / the Caddyfile become generated from `OM_LISTENERS` (same `auto/off/value` rules).
- A listener that is off is simply not bound (today's `*.disabled.invalid` trick).
- **Tunnels must target the `internet` listener port, never `127.0.0.1:80`.** cloudflared and
  Tailscale Funnel deliver to a local port; pointing them at loopback today would hand the
  internet the *private* tier. `om doctor` must probe for this.
- Remove the `Host`-based scope guess from the dashboard; it reads `X-Om-Listener` / `X-Om-User`
  set by the edge only.

### Identity providers ("proofs"), each returns a user or nothing
| Provider   | Proves                    | How                                                                 |
| :--------- | :------------------------ | :------------------------------------------------------------------ |
| `passkey`  | user                      | WebAuthn login → server-side session (see SESSIONS)                 |
| `token`    | user (non-browser)        | `Authorization: Bearer om_…` personal access token, scoped to resources, hashed at rest |
| `vpn_peer` | user + device             | source IP on the `tailscale` listener → peer → user. Tailscale/WireGuard peer IPs are authenticated by the tunnel and stable, so the mapping is IP → peer. `om auth peers sync` (host CLI) refreshes it from `tailscale status --json` — no tailscaled socket inside a container. Works for plain WireGuard too (static peer IPs in config). |
| `mtls`     | device (→ user)           | Caddy `client_auth { mode verify_if_given; trust_pool file … }` on `lan`/`internet`; `om_auth` maps the SHA-256 fingerprint to a device and checks `revoked_at` on every request (Caddy has no client-cert CRL; the DB *is* the revocation list). |
| `loopback` | user (opt-in)             | `OM_LOOPBACK_TRUST=admin`: requests on the loopback listener are the owner. Off by default on multi-user machines; `om doctor` warns if other human accounts exist. |
| `basic`    | user (legacy)             | Current `om auth add` users keep working during migration, then removed. |

Enabled per listener in config; adding a provider = new module + config entry, routes untouched.

---

## HOSTNAMES, TLS AND PASSKEYS — the part that decides whether "works unchanged" is true

Facts that constrain the design:
- WebAuthn needs a **secure context** (HTTPS with a *trusted* cert, or `localhost`) and binds each
  passkey to an **RP ID** (a domain; never an IP). A passkey made on `archlinux.local` does not work
  on `machine.tailnet.ts.net` or `om.example.com`.
- `__Host-`/`Secure` cookies need HTTPS. Plain `http://<lan-ip>/` can only ever be `public`.
- mDNS resolves single names (`archlinux.local`), not `proj.archlinux.local` (would need om to
  publish avahi aliases = touching the host). On `.local`, project routing stays path-based (`/<svc>/`).
- Every Let's Encrypt cert is logged publicly (Certificate Transparency): per-project certs leak
  project names. A **wildcard** hides them but needs DNS-01, which the official Caddy image can't do
  (DNS plugins = custom build, conflicts with pinned official images).

**Decision: one domain, one wildcard cert, one RP ID, every listener.**
- `OM_DOMAIN=om.example.com`, RP ID = `om.example.com` → one passkey works on all its subdomains.
- Per-listener zones in public DNS, all under the RP ID:
  `*.lan.om.example.com → 192.168.x.y`, `*.ts.om.example.com → 100.x.y.z`, `*.om.example.com → public IP`.
  Project hosts: `<svc>.<ws>.lan.om.example.com` etc. (vhost routing everywhere, not only on localhost).
- Certificates: `*.om.example.com` + `*.lan.…` + `*.ts.…` via DNS-01 by a pinned `lego` container run
  by `om cert renew` (on the existing heal timer), files mounted read-only into the edge. Provider and
  API token in `om.env` (`OM_DNS_PROVIDER=desec|cloudflare|…`, token in `$OM_STATE_DIR/data/`, 0600).
- DDNS for the public record: same provider API, updated by the heal timer when the IP changes.
- Cheap options: deSEC (`*.dedyn.io`, free, API, DNS-01) or a ~$10–15/yr domain on Cloudflare DNS
  (**DNS-only / grey cloud** — orange-cloud proxying terminates TLS at Cloudflare).
- Known caveat: some routers block public DNS answers pointing to private IPs (DNS-rebind
  protection); `om doctor` detects it, fix = whitelist the domain on the router or use `.local`.
- **No domain configured** = today's model: loopback (passkeys on `localhost` work), `.local`/IP
  on LAN = public only, Tailscale via `machine.tailnet.ts.net` (Caddy's built-in Tailscale cert
  getter, optional). Users needing `user`/`private` remotely without a domain register one passkey
  per origin family (`localhost`, `ts.net`); om shows which origins each passkey covers.

### Internet exposure
- Port-forward **only** 443 (and 80 for redirects) to the `internet` listener; DDNS keeps the record.
- Behind CGNAT: Tailscale Funnel or cloudflared, **targeting the internet listener port**.
  Both terminate TLS before Caddy → mTLS is impossible there (Cloudflare additionally sees plaintext).
  Passkeys still work (origin is the hostname). `private` resources are therefore never served via
  a tunnel: users reach them over Tailscale instead (`OM_INTERNET_MAX_LEVEL=user`).
- Client IP behind a tunnel: trust `CF-Connecting-IP`/`X-Forwarded-For` **only** on that listener and
  only from the tunnel's source, for rate limiting and audit.

---

## SESSIONS AND COOKIES
- Login happens on one origin: `auth.<zone>` (e.g. `auth.lan.om.example.com`). Session cookie
  `__Host-om_s` lives there only: `Secure; HttpOnly; SameSite=Lax`, random 256-bit id, stored hashed.
- Project hosts never see the session cookie (otherwise every backend receives it and a compromised
  service could replay it against others). After login, `auth.` redirects to the project host with a
  one-time, 60 s ticket; `om_auth` exchanges it for a **host-bound** cookie (`__Host-om_h`, valid for
  that host only). The edge strips every `om_*` cookie before proxying upstream.
- Idle timeout (e.g. 12 h) + absolute lifetime (e.g. 30 d) + revoke-all on credential loss.
  Step-up (fresh passkey assertion ≤ 5 min) for admin actions: grants, invites, revocations.
- CSRF: existing `Origin`/`Sec-Fetch-Site` checks stay; all state changes are `POST` to `om_auth`.

---

## ENROLLMENT (private keys never leave the device)
- **Root of trust = shell access to the host.** `om auth init` (host CLI) creates the first admin
  and prints a one-time link (`http://localhost/…` works for passkeys without a cert). The same
  command later is the **break-glass recovery** if all admin passkeys are lost.
- **New user:** admin creates a one-time, 24 h invite (`om auth invite <name> [--grant ws/*]` or
  dashboard). User opens it on the domain origin, `navigator.credentials.create()` with
  `userVerification: required`, `attestation: none`, resident key. om stores only credential id,
  public key, sign count, transports, AAGUID label.
- **More devices / lost device:** users add passkeys from a signed-in session; synced passkeys
  (iCloud/Google/password manager) make this rare. Lost device → admin revokes credential(s) and
  sessions, issues a new invite.
- **mTLS device (optional, phase 5):** browsers can no longer generate CSRs, so enrollment is
  `om auth device-csr` on the device (or `openssl req`), uploaded with an invite; admin approves the
  shown fingerprint; signing runs in a pinned `step-cli` container (stdlib cannot sign X.509).
  Client CA key in `$OM_STATE_DIR/data/`, separate from Caddy's root CA. Mobile installation of
  client certs is painful — this is why `private` also accepts a VPN peer.
- **VPN peer:** the client has its own node key; admin maps peer → user (`om auth peers map`).

---

## STORAGE
- One SQLite file, WAL, `$OM_STATE_DIR/identity/om.db`, **opened only by `om_auth`** (single writer).
  The host CLI never opens it: on podman machine / Docker Desktop the state dir is a VM mount where
  WAL's shared memory is unsafe. CLI commands run through the container
  (`<engine> exec om_auth python3 -m omauth …`), identical on every OS.
- `om auth export|import` for backups (JSON, includes no secrets that can log in: hashes and
  public keys only).
- Resources and their levels are **not** stored — the labels are the source of truth; grants to
  resources that no longer exist are inert and listed by `om doctor`.

```
users(id, name, role[admin|user], created_at, disabled_at)
passkeys(id, user_id, credential_id, public_key_cose, sign_count, label, created_at, last_used_at, revoked_at)
devices(id, user_id, cert_fingerprint, label, created_at, approved_at, revoked_at)
vpn_peers(peer_ip, node_id, user_id, label)
grants(id, user_id, resource_pattern, created_by, created_at)      -- "ws/svc", "ws/*", "*"
invites(token_hash, role, grants_json, expires_at, used_at, created_by)
sessions(id_hash, user_id, host, created_at, last_seen_at, expires_at, revoked_at)
api_tokens(token_hash, user_id, label, resource_pattern, expires_at, last_used_at, revoked_at)
audit(ts, actor, action, target, listener, client_ip, result)      -- append-only
```

---

## STDLIB CONSTRAINTS (and how to meet them)
- WebAuthn needs CBOR + signature verification; stdlib has neither. Implement **verify-only**
  ES256 (P-256 ECDSA), Ed25519 and RS256 in pure Python (~200 lines; verification handles only
  public data, so constant-time is not a concern), plus a minimal CBOR decoder. Covered by official
  test vectors and recorded real authenticator responses.
- Checks: challenge (single-use, 5 min), origin ∈ configured origins, rpIdHash, UP+UV flags,
  sign-count regression → flag credential, credential belongs to user.
- Rate limiting: in-memory token buckets in `om_auth` (Caddy's official image has none), per IP
  and per account on login/enroll/invite endpoints; exponential lockout; logged.

---

## SECURITY REQUIREMENTS (all tested)
- Default deny: unknown resource, missing label, unknown listener, `om_auth` down → **deny**
  (fail closed; public routes don't call `om_auth` so they stay up).
- Client-supplied `X-Om-*` headers and `om_*` cookies never reach `om_auth`'s decision or an upstream.
- Invite tokens, session ids and API tokens stored only as SHA-256 hashes; single-use invites; short expiry.
- Revocation (passkey, device, peer, token, session, user) takes effect on the next request.
- Audit log of logins, failures, enrollments, grant/role changes, revocations; `om auth log`.
- Public scope stays zero-knowledge (current §5); `user` scope reveals only granted items.
- No secret ever in a label, route file, or log line.

### `om doctor` probes to add
- Forged `X-Om-User: admin` from a client → stripped (request treated as anonymous).
- `user`/`private` resource without session → 302 to login (browser) / 401 (API); with session but
  no grant → 403; private resource with passkey but no device proof → 403.
- Revoked passkey/device/token → 403 on the next request.
- Internet listener cannot reach `private`/`admin`; tunnel targets loopback → **fail**.
- Workspace container → `om_auth` → `000` (not reachable).
- Source IP preserved on the `tailscale` listener (rootless slirp4netns / Docker userland proxy /
  podman machine can rewrite it) — if not, `vpn_peer` is disabled with a printed fix.
- DNS for each configured zone resolves to the right address; cert covers every listener host.

---

## MIGRATION AND PHASES
Each phase ships alone, keeps all existing doctor probes green, and updates
`docs/NETWORK_ARCHITECTURE.md` + `CHANGELOG.md`.

0. **Split listeners**: own container ports per listener, `X-Om-Listener`, drop the dashboard's
   `Host` heuristic. No behavior change for users.
1. **`om_auth` + passkeys + `(gate)`** on loopback/LAN/Tailscale; `om auth init|invite|list|revoke`;
   Basic auth kept as `basic` provider. Dashboard filters by identity.
2. **Grants + `om.access` labels** (`user`/`private`/`admin`), dashboard admin UI for grants/invites.
3. **Domain**: `OM_DOMAIN`, wildcard certs via `lego`, per-listener zones, DDNS, `internet` listener.
4. **VPN peers**: `vpn_peer` provider, `om auth peers sync|map`.
5. **mTLS** devices (optional), client CA, `step-cli` signing.
6. **API tokens** for non-browser clients; remove the legacy `basic` provider.

---

## OPEN DECISIONS (mine to make)
1. `private` via Tailscale: peer alone, or peer **+** passkey? (Draft said peer alone; Tailscale
   login is already an SSO + device key. Proposed: configurable, default peer alone.)
2. `OM_LOOPBACK_TRUST` default on a single-user laptop: `admin` (convenient) or `none` (strict)?
3. Domain provider: deSEC (free, `dedyn.io`) or own domain on Cloudflare DNS-only?
4. Is mTLS worth phase 5 at all, given passkeys + Tailscale already cover device proof?
