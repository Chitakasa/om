## Networking architecture update — one door, identity by device

om is a **personal workspace orchestrator**: it runs your projects and services and lets you and a
few trusted people (family, collaborators) use them. Serving strangers is not its job — a project
meant for the world is deployed elsewhere. So om needs no public access at all: **a private VPN that
om owns is the only way in**, everywhere (LAN, travel, mobile), and **administration happens only at
the host's physical console**.

### CURRENT (om 1.0)
- Access = **network position**: loopback + Tailscale IP → private tier (everything); LAN IP →
  public tier (`dashboard.scope=public` services, anyone on the Wi-Fi).
- Only identity: optional HTTP Basic auth on the private tier (`om auth add`).
- Web ports 80/443 are open on the LAN; the host announces itself (`archlinux.local` via mDNS).
- The dashboard guesses scope from the `Host` header (`server.py:_is_public_scope`).
- Known holes: dashboard renders workspace labels with `innerHTML` and has no CSP; dashboard and
  Portainer hold the raw engine socket; `om sync` deploys unsigned commits and nothing rejects
  `privileged`, host networking or socket mounts; workspace containers have unrestricted egress.

---

## GOALS
1. **One way in.** The only open inbound port on the host is one UDP port for WireGuard. No web
   ports on any interface. A port scan finds nothing: WireGuard never answers unauthenticated packets.
2. **Identity = device key.** Every request arrives from a WireGuard peer whose key is enrolled to one
   user. Cryptokey routing makes the peer address unforgeable. No IPs guessed, no MACs, no passwords.
3. **Same rules everywhere.** On the home LAN, abroad or on mobile data, a device uses the same tunnel
   and gets exactly the same access.
4. **Default deny, on every request, at the edge** — dashboard, every service, every WebSocket.
   A user sees only what they are granted; ungranted services do not exist for them (not even names).
5. **Administration only at the console.** Users, devices, grants and Portainer exist only on the
   host's loopback listener, confirmed by a touch on the admin hardware key, which the admin carries (never stored with the host).
   No remote admin path exists, so there is no admin device to find or attack.
6. **Physical enrollment.** Devices join by scanning a QR code shown at the console. No invite links.
7. **A quiet host.** Nothing advertises it: no mDNS name, no DHCP hostname, no ping replies,
   randomized MAC (opt-in host command).
8. **om stays om.** Zero-daemon on the host, stdlib Python, pinned hardened containers, generic
   (no service/host/user names in code), identical on Linux/macOS/Windows.

### REMOVED compared with 1.0 and earlier drafts
Public tier, LAN tier, internet listener, Tailscale dependency, Basic auth, mTLS and a client CA,
invite links, API tokens, multi-VPN adapters, time-locks and two-device approvals (admin is physical).

---

## ACCESS LEVELS
Declared per service by label in the workspace's compose file; who is granted what is machine state.
Missing or unknown label = `private` (fail closed).

| Level     | Who gets through                                                            |
| :-------- | :-------------------------------------------------------------------------- |
| `shared`  | Any enrolled device (household services: media, search).                    |
| `user`    | An enrolled device **plus** a passkey of that device's user, who holds a grant (stolen unlocked device ≠ access). |
| `private` | `user` with a **device-bound** passkey (`BS=0`, not synced to a cloud account) and a fresh assertion (≤ 5 min). |
| `admin`   | Console only: loopback listener + touch on the admin hardware key. Portainer, om settings. |

- Label: `om.access=shared|user|private`. `dashboard.scope=public` from 1.0 maps to `shared`.
- Resources are `<ws>/<svc>`; grants may target `<ws>/*` or `*`.
- Anything holding the engine socket (Portainer) is `admin`, never reachable through the tunnel.

---

## ARCHITECTURE

```
 device ──WireGuard (UDP 51820, the only open port)──► om_wg ┐ shared network namespace
                                                      om_caddy (edge) ┘ sees the real peer IP 10.77.0.N
                                                         │ strip client X-Om-* headers
                                                         │ forward_auth ─► om_auth: peer → device → user → grants
                                                         ▼ allow: X-Om-User set
                                                      om_router (edge token) ─► <ws>_<svc>
 host keyboard ── http://localhost (console listener) ─► om_caddy ─► om_auth admin UI (hardware-key touch)
```

### `om_wg` — the door
- A pinned, hardened container running userspace WireGuard (`wireguard-go`; `/dev/net/tun`,
  `NET_ADMIN` only inside its own namespace). Works the same on rootless Podman, Docker and podman
  machine; never touches the host network configuration.
- Publishes **only** `51820/udp`. Tunnel subnet `10.77.0.0/24` (configurable `OM_WG_SUBNET`);
  each device gets one `/32`, enforced by WireGuard's cryptokey routing.
- `AllowedIPs` on clients = the tunnel subnet only (split tunnel): om is not an internet exit, and
  devices' other traffic never touches the host.
- The edge runs **in `om_wg`'s network namespace** (`network_mode: service:wg`), so it receives the
  real peer address — no NAT, no port-forward rewriting — and binds `10.77.0.1:443`.
  `om_wg` is also on `om_core_net`, so the edge still reaches `om_router`, `om_auth`, the dashboard.
- Revoking a device removes its peer live (`wg set … peer … remove`) and denies it in `om_auth`.

### `om_auth` — the decision
- Pure-stdlib Python, hardened like the dashboard, on `om_core_net` only, **no engine socket**.
  Every edge → `om_auth` call carries the edge token; anything else is rejected.
- `/verify` (forward_auth): `X-Om-Peer` (set by the edge from the TCP source) → device → user →
  level/grant check → `200` + `X-Om-User` | `302` to passkey login (`user`/`private`) | `403`.
- Console admin UI: users, devices (QR enrollment), grants, audit log. Every write needs a fresh
  assertion from the admin hardware key (device-bound, `BS=0`, user presence + verification).
- Passkey verification in pure Python (verify-only ES256/Ed25519 + minimal CBOR), tested against
  official vectors and recorded authenticator responses.
- Owns the SQLite DB (single writer); the host CLI goes through `<engine> exec om_auth …`.

### Edge and routes (generated, never hand-written)
- Tunnel listener: `https://<ws>-<svc>.<OM_DOMAIN>` and `https://<OM_DOMAIN>` (dashboard). One label
  per service host so one wildcard certificate `*.<OM_DOMAIN>` covers everything.
- `render_vhost` emits `import gate <ws>/<svc> <level>` before `import to_workspace`; subpath routes
  are dropped (hosts are cheap and isolate cookies better).
- Console listener: `127.0.0.1`/`[::1]` host ports → container `:8080`; serves the dashboard with
  admin UI, Portainer and every service (still gated: the console is a place, not an identity).
- Router token isolation, `security_headers` and abort catch-alls stay as they are.
- The dashboard reads `X-Om-User`/`X-Om-Listener` set by the edge; the `Host` heuristic is removed.

### Names and certificates (needed for passkeys on `user`/`private`)
- `OM_DOMAIN=om.<name>.dedyn.io` — a free deSEC name. Public DNS holds exactly one wildcard record:
  `*.om.<name>.dedyn.io → 10.77.0.1`, a tunnel-internal address that reveals nothing about the host.
- Certificate: wildcard via DNS-01 (pinned `lego` container, run by the heal timer), short-lived
  profile; CAA restricted to Let's Encrypt + om's `accounturi`; DNSSEC (deSEC default).
- Passkey RP ID = `OM_DOMAIN`, valid on every service host.
- Client WireGuard configs set a public resolver (`DNS = 9.9.9.9`) so home routers' DNS-rebind
  filters never block the private-address answer.
- The admin key's passkey is registered for `localhost` (secure context on the console, no cert needed).

### Reaching the door from outside
- Endpoint in client configs: the LAN address at home, and a **separate** DDNS name (another
  random deSEC name, updated by the heal timer) away from home; one router port-forward of UDP 51820.
- Without a public IPv4 (CGNAT): an IPv6 endpoint; if neither exists, a minimal relay that forwards
  the encrypted UDP only (it holds no keys and sees no content).

### Sessions (`user` and `private`)
- Login at `auth.<OM_DOMAIN>`; host-bound ticket → `__Host-` cookie per service host; the edge strips
  `om_*` cookies before upstream. Session bound to the device's peer address: a copied cookie fails
  from any other device. `user`: idle 8 h, absolute 7 d; `private`: idle 1 h, absolute 12 h.
- State changes on `auth.` and the dashboard require `Sec-Fetch-Site: same-origin` and an exact
  `Origin` (sibling service hosts are same-site).

---

## ENROLLMENT
- **First run:** `om init-admin` at the host registers the admin hardware key at `http://localhost`.
  It registers **two** keys: the daily key (carried by the admin) and a **backup key** kept in a separate
  safe place. Console access alone never grants admin: recovery (`om admin recover`) requires a touch on
  a still-registered key, and revokes the lost one. Losing both keys means re-initialising identity
  (`om init-admin --reset`): all users, devices, grants and sessions are wiped and re-enrolled, so a thief
  with the host gains nothing but an empty system.
- **New user:** created in the console UI.
- **New device:** console UI shows a QR code containing a WireGuard config with a fresh key pair;
  the device scans it. om stores only the public key and the `/32`; the private key is never written
  to disk and disappears with the QR. (Strict variant: the device generates its key and the admin
  enters only its public key.)
- **Passkey (needed for `user`/`private`):** the user registers it from an enrolled device, confirmed at the console.
- **Lost device:** revoke at the console; it is dropped from WireGuard instantly.

---

## STORAGE
One SQLite file (WAL) in `$OM_STATE_DIR/identity/om.db`, opened only by `om_auth`.
```
users(id, name, created_at, disabled_at)
devices(id, user_id, wg_public_key, peer_ip, label, created_at, last_seen_at, revoked_at)
passkeys(id, user_id, credential_id, public_key_cose, sign_count, rp_id, is_admin, created_at, revoked_at)
grants(id, user_id, resource_pattern, created_at)                    -- "ws/svc", "ws/*", "*"
sessions(id_hash, user_id, device_id, host, created_at, last_seen_at, expires_at, revoked_at)
audit(ts, prev_hash, hash, actor, action, target, listener, peer, result)   -- hash-chained
```
Labels remain the source of truth for levels; grants to vanished services are inert and listed by `om doctor`.

---

## SECURITY — closing everything that remains

### Today's holes (fixed first, independent of the new door)
- **A1** Dashboard: strict CSP (`script-src 'self'`, no inline, `frame-ancestors 'none'`),
  `textContent` rendering, label value validation.
- **A2** Dashboard engine access through a read-only socket filter (`GET` allowlist); Portainer
  off by default and console-only (`om core portainer on`, auto-off after 30 min).
- **A3** Compose policy gate on `om start|sync|add`: reject `privileged`, host network/pid/ipc,
  `ports:`, socket and sensitive host mounts, added caps/devices unless an `om.allow.*` label is
  confirmed at the console.
- **A4** `om sync`/autosync require signed commits (`.om/allowed_signers`, `git verify-commit`).
- **A5** Core images pinned by digest; doctor flags tag-only workspace images.
- **A6** Workspace networks `internal` by default (no egress); `om.egress=internet` opt-in;
  firewall drops container → host except the router path.

### The host
- om runs under a **dedicated non-login user** `om` (rootless engine): the desktop account, where
  the browser lives, has no access to its socket, state or keys.
- Host firewall (`om firewall`): inbound drop everything except `51820/udp` (+ DHCP, essential ICMPv6).
- `om host quiet` (opt-in, host-touching like `om firewall`): disable mDNS/LLMNR announcements,
  send no DHCP hostname, randomize MAC, ignore ping.
- Physical: full-disk encryption with TPM2 **+ PIN**, Secure Boot, firmware password, USB boot off;
  the admin keys are never stored with the host (daily key carried, backup in a separate safe).
  The DB holds public keys and hashes only.
- Audit entries hash-chained and pushed off-host the moment they are written (`OM_ALERT_URL`, e.g. ntfy).

### `om doctor` probes
- From another LAN device: every TCP port and every UDP port except 51820 closed; 51820 silent to
  unauthenticated probes; no mDNS answer for the host.
- Through the tunnel: ungranted service → 403 (and absent from the dashboard); `private` without
  passkey → login (`user` too); forged `X-Om-User`/`X-Om-Peer` → ignored; revoked device → no handshake.
- Console-only routes (admin UI, Portainer) unreachable through the tunnel.
- Workspace container → `om_auth`, edge, host, internet (unless opted in) → `000`.
- The edge sees real peer addresses (not a NAT gateway).
- DNS record, certificate expiry, CAA, DDNS freshness.

---

## PHASES
Each phase ships alone, keeps existing probes green, updates `docs/NETWORK_ARCHITECTURE.md` + `CHANGELOG.md`.

**Verify first:** `wireguard-go` in rootless Podman, Docker and podman machine; the edge in
`om_wg`'s namespace receives peer addresses; Caddy can filter the engine socket; `lego` supports the
short-lived profile with deSEC.

- **A1–A6** — close today's holes.
1. **Dedicated `om` user** (`om install --system-user`, migration from the desktop user).
2. **`om_wg` + firewall to 51820/udp only + console listener.** LAN tier and Tailscale binding
   removed; `dashboard.scope=public` → `shared`. QR enrollment, revocation.
3. **`om_auth`**: devices → users, grants, `om.access` levels, gate in every generated route,
   dashboard shows only granted services, admin console with hardware key, audit + alerts.
4. **Domain + passkeys for `user`/`private`**: deSEC wildcard, `lego`, CAA, sessions, `auth.` origin.
5. **`om host quiet`** and the full doctor probe set.

### What is left
Breaking in beyond `shared` requires the enrolled device **and** its user's passkey, or physical
access to a locked, encrypted host **and** one of the admin's hardware keys, which are never kept with it. Everything else is closed by design;
what remains is an unknown flaw in WireGuard, Caddy, the kernel or the browser, kept short by updates.
