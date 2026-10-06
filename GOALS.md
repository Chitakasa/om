## om — git for what projects use: one door, keys, signed history

om is to running software what git is to source: git versions what a project **is**, om runs what
a project **uses** (its services, networks, routes, access). Like git, om is small, generic and
decentralised: a few primitives, plain files, signed history, no server, no knowledge of what it runs.
Deploying and access follow the same shape.

### Principles (git's, applied to the runtime)
1. **Few primitives, everything else derived.** Repo, Lock, Deploy log, Identity log for state;
   Door, Keys, Policy for access — nothing more.
2. **Generic.** om knows protocols, never products: no service, host, user, vendor or provider name
   in code. Every choice is a label (in the repo) or a setting (`om.env`).
3. **What lives in the repo, who lives on the machine.** Labels say what a service needs and can do;
   the signed log says who may use it. Neither ever contains a secret.
4. **History is signed and append-only.** Every change of who-may-do-what is an entry signed by an
   admin hardware key, chained by hash. State is the replay of the log, like a checkout of commits.
5. **Default deny, fail closed, on every request.** Anything unlabeled, unknown, unsigned or
   unverifiable is refused.
6. **Same everywhere.** One transport, one set of rules, on any network and any OS.
7. **Runs on your daily computer.** om is a project manager; it isolates itself from your desktop
   instead of requiring a server.
8. **Nothing runs that isn't signed.** Code, images (by digest) and access changes all reach the
   host only as signed history.

---

## om is git for the runtime

Four objects, all content-addressed, all verifiable offline — the same shape as git's:

| Object | Where | git equivalent | Answers |
| :-- | :-- | :-- | :-- |
| **Repo** | the workspace's git repository (compose files, labels, `.om/config.json`) | the tree | *what* the project uses |
| **Lock** | `.om/lock.json`, committed: every image resolved to its digest | a lockfile / blob ids | *exactly which bits* run |
| **Deploy log** | `$OM_STATE_DIR/deploys/<ws>/`, hash-chained entries `{commit, lock hash, time, result}` | reflog | *what ran here, when* |
| **Identity log** | `$OM_STATE_DIR/identity/` — a real git repo (see Log below) | a git repo | *who* may use it |

- **Deploy = checkout.** Running state is a pure function of `(signed commit, lock)`: the same commit
  gives the same services, routes, access and egress on any host. Compose tags stay readable; om
  runs only the digests in the lock.
- **Only signed commits deploy** (`.om/allowed_signers`, `git verify-commit`), whoever pushed them.
- **Uncommitted changes never deploy**, except `om dev`, which runs the working tree and marks the
  workspace *dirty* in `om status` and the dashboard until a signed commit is deployed.
- **Data is not history.** Volumes and `data/` are never rewritten by a checkout; rolling back code
  never rolls back data.
- **Config levels like git's:** machine `om.env` (`--system`), repo `.om/config.json` (versioned),
  `.om/local.json` (this machine only, never committed).
- **Plumbing and porcelain.** Small stable commands with `--porcelain` output (`om plumbing
  policy-check|render-routes|verify|lock-resolve`) under the friendly ones; scripts use plumbing only.

### Commands, read as git
| git | om | Does |
| :-- | :-- | :-- |
| `git init` / `clone` | `om init` / `om clone <url>` | create or fetch a workspace; `clone` verifies signatures before registering it |
| `git status` | `om status` | running vs deployed commit (drift), dirty `om dev`, pending update proposals |
| `git diff` | `om diff [<rev>]` | what a deploy would change: images, routes, access, egress, write rights |
| `git log` | `om log` / `om identity log` | deploy history / access history |
| `git pull` + `checkout` | `om sync` (autosync on a timer) | fetch, verify signature, policy gate, deploy lock, health check, roll back on failure |
| `git checkout <rev>` | `om checkout <rev>` | deploy an earlier signed commit (rollback is just this) |
| `git fsck` | `om fsck` | verify locks, deploy log and identity log end to end |

### Updates are commits (no silent auto-update)
- The heal timer runs `om lock --check`: for each image it looks for newer versions within the pinned
  range (exact or major/minor, never `latest`), resolves digests, and writes the result as a commit on
  a branch `om/updates` (unsigned), then alerts. Core images follow the same path in `$OM_HOME`.
- You review `om diff om/updates`, merge and sign. Autosync deploys it; a failed health check rolls
  back to the previous deploy-log entry automatically.
- `om update` becomes `om lock --check` + this flow; pulling a tag in place (a re-pushed tag runs
  unreviewed code) is removed.

---

## Access primitives

### 1. Door — one transport at a time, your choice (like git's ssh/https)
```ini
OM_DOOR=wireguard            # default: om's own WireGuard (om_wg), free, om owns every key
OM_DOOR=vpn:<interface-ip>   # a VPN you already run: Tailscale, Headscale, NetBird, ZeroTier, plain WireGuard…
```
- A `vpn:` door qualifies only if the VPN authenticates each peer cryptographically and gives it a
  stable address that reaches the edge unchanged; `om doctor` proves both, else the door stays closed.
  The edge binds only that interface address; om manages no keys of that VPN.
- Everything after the door is identical: peer address → device → user → grants, same labels, same log.
- **The default door** runs in an om container (`om_wg`): one UDP port, silent to anything
  without an enrolled key. No web port on any interface. LAN, travel and mobile use the same door.
- Each device holds one key and one `/32`; cryptokey routing makes the address unforgeable.
  Clients route only the tunnel subnet (om is never an exit node).
- The edge (`om_caddy`) runs in `om_wg`'s network namespace, so it sees the true peer address.
- The **console** (host loopback) is the second listener: it is a place, not an identity.

### 2. Keys — identity
- **Device key** (WireGuard, or the chosen VPN's node key): proves the device, on every packet.
- **Passkey** (WebAuthn): proves the person. Private keys never leave their device; om keeps public keys.
- **Admin hardware keys** (two: one carried, one backup in a separate place; never kept with the host),
  used as **SSH security keys** (`ed25519-sk`). **One key signs everything:** workspace commits and
  update merges (git's SSH signing) and every identity commit. They are the only entries in
  `.om/allowed_signers` and in the identity repo's root of trust. The console alone is never admin.
- No passwords, tokens, invite links or certificates of om's own.

### 3. Policy — labels in the repo
Three labels per service, validated by the policy gate; missing or unknown = strictest value.

| Label | Values | Meaning |
| :-- | :-- | :-- |
| `om.access` | `shared` \| `user` \| `private` (default) | `shared`: any enrolled device. `user`: device + its user's passkey + a grant. `private`: `user` with a device-bound passkey (`BS=0`) asserted ≤ 5 min ago. |
| `om.writes` | `false` \| `true` (default when any host mount lacks `:ro`) | The service's own features change data or run code (file manager, IDE, terminal, wiki, delete rights). |
| `om.egress` | `none` (default) \| `internet` | Outbound internet. |

Fixed rules (no override exists):
- `om.writes=true` ⇒ never `shared`, never `om.egress=internet`. What can write cannot talk out.
- Anything holding the engine socket is console-only.
- Grants target `<ws>/<svc>`, `<ws>/*` or `*`. Admin actions exist only on the console.

### 4. Log — the identity repo: a git repository of who may do what
- `$OM_STATE_DIR/identity/` is an ordinary git repo of plain files: `users/<name>`,
  `devices/<id>` (public key or peer address, owner), `passkeys/<id>` (public key), `grants/<user>`
  (resource patterns), `admin_signers` (the two admin keys). Every change is one commit signed by an
  admin key; there is no other way to change it, and no custom format to maintain.
- **The root commit** adds `admin_signers` — the root of trust. A commit is valid only if it is signed
  by a key in `admin_signers` *as of its parent*; changing that file needs a signature from a key
  already in it.
- `om_auth` verifies the history from the root commit (SSH signature verification in stdlib Python:
  the same Ed25519/ECDSA code passkeys need) and serves the newest valid commit; an invalid commit
  stops at its parent (fail closed) and alerts. Root on the host can't forge a commit; it could only
  rewind, and every new `HEAD` is pushed off-host (`OM_ALERT_URL`), so rewinding is visible.
- `git log` is the audit log, `git verify-commit` and `om fsck` check it, backup is `git clone`.
  Sessions are never stored on disk; they live in `om_auth`'s memory.
- Lost one admin key: the other signs a commit replacing it in `admin_signers`. Lost both:
  `om identity reset` starts a new repo — every user and device re-enrolls; nothing carries over.

---

## Request path
```
device ─WireGuard─► om_wg ═ om_caddy (edge) ─forward_auth─► om_auth (replayed log)
                              │ strips client X-Om-* headers and om_* cookies
                              ▼ allow → X-Om-User
                           om_router (edge token) ─► <ws>_<svc>
console ─localhost─► om_caddy ─► same gate (no admin web UI exists)
console ─terminal──► om user|device|grant …  → signed commit (key touch) → om_auth reloads
```
- `om_auth`: stdlib Python, hardened, `om_core_net` only, no engine socket, accepts only edge-token calls.
- Routes are generated (`render_vhost` emits `import gate <ws>/<svc> <access>`); one host per service,
  `<ws>-<svc>.<OM_DOMAIN>`; subpath routes removed.
- Sessions (`user`/`private`): login at `auth.<OM_DOMAIN>`, host-bound `__Host-` cookie per service
  host, bound to the device's peer address, stripped before upstream; state changes require
  `Sec-Fetch-Site: same-origin`. `user`: 8 h idle / 7 d; `private`: 1 h / 12 h.

### Names (only because passkeys need HTTPS on a domain)
- `OM_DOMAIN` = any name you control with ACME DNS-01 support (a free dynamic-DNS name is enough).
  Its only record: `*.<OM_DOMAIN> → <tunnel address>` — reveals nothing about the host.
- Wildcard certificate by DNS-01 (`OM_ACME_DNS=<provider>`, run by the heal timer), renewed at one
  third of its lifetime, alert on failure; CAA pinned to the CA and om's ACME account.
- Door endpoint for roaming devices: `OM_WG_ENDPOINT` (address or a separate dynamic name).

### Enrollment (physical, at the console)
- **Admin is CLI-only at the console.** No admin web page, so no admin session, CSRF or web attack
  surface: `om user add`, `om device add`, `om grant`, `om … revoke` each write one commit signed with
  a touch on the admin key.
- `om identity init`: generates the two `ed25519-sk` keys on the hardware keys and makes the root commit.
- Device: `om device add` prints a one-time QR (WireGuard config) in the terminal; only its public key
  is committed.
  With a `vpn:` door, the device is the VPN's peer address, recorded by a signed `device.add` entry.
- Passkey: registered from an enrolled device; it stays pending until the admin approves it at the
  console (`om passkey approve`, a signed commit).
- Revocation is one signed entry; the device leaves WireGuard instantly.

---

## Hardening of what exists today (first, independent of the door)
- **A1** Dashboard: strict CSP, no inline script, `textContent` rendering, label validation.
- **A2** Dashboard reaches the engine through a read-only `GET` allowlist; Portainer off by default,
  console-only.
- **A3** Policy gate on `om start|sync|add`: rejects `privileged`, host namespaces, `ports:`, socket
  and sensitive host mounts, added caps/devices, and every combination the fixed rules forbid;
  exceptions (`om.allow.*`) only via a signed identity commit.
- **A4** `om sync`/autosync deploy only commits signed by `.om/allowed_signers` — collaborators reach
  the host only through code you reviewed and signed.
- **A5** Core images pinned by digest; workspaces get `.om/lock.json` (digests) and updates arrive
  only as `om/updates` commits.
- **A6** Workspace networks `internal` unless `om.egress=internet`; containers can't reach the host.

## Host
- om runs as a dedicated non-login user (rootless engine), unreachable from the desktop account.
- `om firewall`: inbound only the WireGuard port. `om host quiet` (opt-in): no mDNS/LLMNR, no DHCP
  hostname, randomized MAC, no ping replies.
- `om doctor` checks what it can see of the rest: disk encryption, LSM enforcing, pending kernel
  updates, hibernate-not-suspend.

---

## Invariants (`om doctor` proves each one; any failure is reported with its fix)
1. From any other machine, every port is closed except the WireGuard port, which stays silent
   without an enrolled key.
2. Every generated route passes the gate; no route reaches a service without `om_auth` allowing it.
3. Client-supplied `X-Om-*` headers and `om_*` cookies never reach `om_auth`'s decision or an upstream.
4. A device or passkey revoked in the log is refused on its next request.
5. Nothing console-only answers through the tunnel.
6. No container reaches the host, the edge, `om_auth`, another workspace, or — without
   `om.egress=internet` — the internet; no `om.writes=true` service has egress or `shared` access.
7. The identity repo verifies from its root commit to `HEAD`, and `HEAD` matches the last one pushed off-host.
   Every running workspace matches a signed commit and its lock (or is flagged dirty by `om dev`).
8. The edge sees real peer addresses.
9. With a `vpn:` door: peers are authenticated and their addresses stable; for VPNs with a third-party
   coordination server, node-signing protection (e.g. Tailnet Lock) is on. A node such a server slips
   in reaches at most `shared` (read-only): `user`/`private` still need a passkey.

## Phases
**Verify first:** `wireguard-go` on rootless Podman, Docker and podman machine; peer addresses in
the shared namespace; engine-socket filtering in Caddy.
- **A1–A6.**
- **G** git model: `.om/lock.json` + `om lock --check`, deploy log, `om status|diff|log|checkout|fsck|clone`,
  `--porcelain` plumbing; `om update` replaced by update commits.
1. Dedicated `om` user.
2. `OM_DOOR`: `om_wg` (default) or `vpn:<ip>`; console listener; `OM_TAILSCALE_*` become
   `OM_DOOR=vpn:…`. **Migration without lockout:** the door opens *alongside* today's tiers; every
   device that uses om today is enrolled; `om doctor` lists anyone who would lose access; only when
   that list is empty (or you confirm) are the LAN tier and other bindings closed and the firewall
   reduced to the door (`dashboard.scope=public` → `om.access=shared`).
3. `om_auth` + identity repo + gate in every route + admin CLI.
4. `OM_DOMAIN`, certificates, passkeys, sessions.
5. `om host quiet`; all invariants in `om doctor`.

## Every known risk and its answer
| Risk | Answer |
| :--- | :--- |
| Remote attacker | One silent door; nothing to scan. |
| Third-party VPN control plane (`vpn:` door) | A slipped-in node gets at most read-only `shared`; node-signing checked by doctor. |
| Stolen unlocked device | `shared` read-only services only. |
| Malware on an enrolled device | Its user's grants while a session is open; device-bound sessions; never admin; writers can't talk out. |
| Collaborator | Git only; only your signed commits deploy; the gate still applies. |
| Hijacked image publisher / re-pushed tag | Digests in the lock; new versions only as commits you review and sign. |
| Bad update | `om diff` before merge; health check + automatic rollback to the previous deploy. |
| Misuse of a write feature | Writers are never `shared`; granted per person. |
| Poisoned dependency / hostile container | No egress, no host, no socket, own network, gate. |
| Exploit in your desktop browser | om runs as another user. |
| Root on the host | Can't forge a signed commit; rewinding is visible off-host. |
| Admin web interface attacked | None exists: admin is CLI at the console, signed by a key touch. |
| Stolen host | Encrypted disk, keys elsewhere, console is never admin. |
| Lost admin key(s) | Backup key; both lost → reset, never a takeover. |
| DNS / CA provider | 2FA, CAA, early renewal; the record reveals only a tunnel address. |
| Bug in om, WireGuard, Caddy, kernel or browser | Fail closed, tests and fuzzing for om's crypto, auto-updates; layered, so one bug alone opens nothing. |
