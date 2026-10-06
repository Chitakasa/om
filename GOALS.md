# om — the core

git versions what a project **is**; om runs what a project **uses** (services, routes, access).
Like git, om has a small core that never changes. New ideas plug into it; they never reshape it.

## One rule

```
request → door → proofs → rule → allow | deny
```

1. **Door** — a transport that cryptographically identifies the device. It is the only way in;
   nothing else listens. Default: om's own WireGuard. Pluggable: any VPN with authenticated, stable
   peer addresses (`OM_DOOR=wireguard | vpn:<ip>`). The host's loopback listener is a second, local
   door: it proves only `device` (the host is one enrolled device), never `console`.
2. **Proofs** — facts established about a request, each from a pluggable provider:
   `device` (door key) · `user` (owner of that device) · `passkey` · `passkey.bound` (device-bound) ·
   `passkey.fresh` (≤ 5 min) · `console` (an interactive terminal running as the om user, proven by
   the OS, never by a network listener) · `admin` (touch on an admin hardware key).
3. **Rule** — each service declares the proofs it requires, in its compose labels:
   ```yaml
   om.require: device,passkey,grant     # grant = the user holds a grant for this service
   ```
   Shortcuts: `shared` = `device` · `user` = `device,passkey,grant` ·
   `private` = `device,passkey.bound,passkey.fresh,grant`. Missing or unknown → `private`.
4. **Signed history** — everything that can change what runs or who gets in is a commit signed by
   your admin hardware key (an SSH security key): workspace code, image updates (digests in
   `.om/lock.json`), and the identity repo (users, devices, passkeys, grants, signers). Nothing
   unsigned takes effect. Deploying is checking out a signed commit.
5. **Fixed laws** — hold whatever the configuration; nothing can override them:
   - Unknown, unlabeled, unsigned or unverifiable → deny (fail closed, on every request).
   - A service that can write (`om.writes`, or any host mount without `:ro`) never needs fewer
     proofs than `user`, and never has open internet egress: only the hosts it lists
     (`om.egress=api.example.com,…`).
   - Containers reach only their workspace network: never the host, the edge, another workspace,
     or the internet unless `om.egress` allows it (`internet` for read-only services only).
   - Admin requires `console` + `admin`. The engine socket is never reachable through a door.
   - Labels and the identity repo never contain a secret; private keys never leave their device.

## How new ideas fit

| New idea | Goes in as | Core changes |
| :-- | :-- | :-- |
| Another VPN or transport | a door type | none |
| Another login method (NFC card, new biometrics, …) | a proof provider | none |
| A new access combination | a value of `om.require` | none |
| A new kind of resource or limit | a label + a law check in the policy gate | none |
| Another host | a clone of the repos; its own identity repo | none |

## Principles
Generic (protocols, never products or names in code) · plain files · signed history · no daemon on
the host · stdlib Python on the host, never hand-written crypto · identical on every OS · runs on
your daily computer, isolated in its own user · every guarantee is an invariant that `om doctor` proves.

## Scope
**For:** one owner running their own services on their own computer, giving a few people (family,
collaborators) access through grants. Only the owner holds admin keys.
**Not goals:** multi-tenant hosting, clusters or high availability, anonymous public websites,
managing other machines, replacing the container engine or Caddy.

---
---

# Appendix A — How the core is built

### Door
- `om_wg`: userspace WireGuard in a pinned, hardened container; publishes one UDP port, silent to
  anything without an enrolled key. One `/32` per device (cryptokey routing makes it unforgeable);
  clients route only the tunnel subnet. The edge (`om_caddy`) shares `om_wg`'s network namespace so
  it sees true peer addresses. `vpn:` doors qualify only after `om doctor` proves authenticated,
  stable peer addresses (and node-signing, e.g. Tailnet Lock, for third-party control planes).
- Roaming endpoint: `OM_WG_ENDPOINT`. Without public IPv4: IPv6, else a relay that forwards
  encrypted UDP only.

### Request path
```
device ─door─► om_caddy ─forward_auth─► om_auth ─► allow → om_router (edge token) ─► <ws>_<svc>
host ─loopback─► om_caddy ─► same gate (`device`)   console ─terminal─► om <admin cmd> → signed commit
```
- The edge strips client `X-Om-*` headers and `om_*` cookies, then asks `om_auth` with the proofs it
  can see (peer address, listener). `om_auth` adds the rest (user, passkey session), checks the
  service's `om.require` and the grants, and answers allow / login / deny.
- `om_auth`: Python, hardened, on `om_core_net` only, no engine socket, edge-token calls only.
  It verifies the identity repo from its root commit. Signature checks (SSH and passkey) use one
  pinned, vetted crypto library inside the container, never hand-written crypto; the host CLI stays
  stdlib and verifies SSH signatures with `ssh-keygen -Y verify`.
- Egress: a writer's `om.egress` hosts are reachable only through `om_egress`, a pinned forward
  proxy on that workspace's network that allows exactly the listed names (CONNECT by SNI/host).
- Routes are generated: `render_vhost` emits `import gate <ws>/<svc> <require>`; one host per
  service, `<ws>-<svc>.<OM_DOMAIN>`.

### Proof providers
- `device`/`user`: peer address → `devices/<id>` → owner.
- `passkey*`: WebAuthn at `auth.<OM_DOMAIN>`; session in memory only, host-bound `__Host-` cookie per
  service host, bound to the peer address, stripped before upstream; state changes need
  `Sec-Fetch-Site: same-origin`. Lifetimes follow the strongest proof required (8 h / 7 d for
  `passkey`, 1 h / 12 h for `passkey.bound`).
- `console`: the om CLI run in an interactive terminal as the om user (OS-checked: process uid,
  TTY); no listener ever yields it. `admin`: an `ed25519-sk` signature by a key in `admin_signers`.

### Names
Passkeys need a real name and a trusted certificate, so `OM_DOMAIN` is part of the core. Two modes:
- **local** (default, no outside service): `<host>.internal`, certificates from om's own root CA,
  which each device trusts once at enrollment (`om device add` hands it over with the door key).
- **public** (opt-in, no CA to install): any name with ACME DNS-01 (a free dynamic-DNS name works);
  its only record points at the tunnel address. Wildcard certificate (`OM_ACME_DNS=<provider>`),
  renewed at a third of its lifetime with an alert on failure; CAA pinned to the CA and om's account.

### Signed history
| Object | Where | Like |
| :-- | :-- | :-- |
| Workspace repo | the project's git repo + `.om/lock.json` (image digests) | tree + lockfile |
| Deploy log | `$OM_STATE_DIR/deploys/<ws>/`, hash-chained `{commit, lock, time, result}` | reflog |
| Identity repo | `$OM_STATE_DIR/identity/`: `users/ devices/ passkeys/ grants/ admin_signers` | signed repo |

- Only commits signed by `.om/allowed_signers` (workspaces) or by a key in `admin_signers` as of the
  parent (identity) take effect. Every new identity `HEAD` is pushed to an off-host clone
  (`OM_ALERT_URL`); `om fsck --remote`, run from another enrolled machine, compares the host's `HEAD`
  with it and alerts on a rewind or fork. Backup = `git clone`; audit = `git log`.
- Updates: the heal timer proposes newer images (same pin range, never `latest`) as commits on
  `om/updates`; you review `om diff`, merge and sign; autosync deploys, health-checks, rolls back.
- Two admin keys: one carried, one backup elsewhere; never kept with the host. Lost one: the other
  replaces it. Lost both: `om identity reset` starts a new identity repo; everyone re-enrolls.

### Secrets
Service secrets live in the workspace repo, encrypted with age (via sops) to the host's key in
`$OM_STATE_DIR/data/`, which is never in a repo. They are decrypted only at container start, as
read-only files under `/run/secrets/`, never env vars or labels. The built-in `om-v2` format is
read-only, kept to migrate existing files.

### Commands, read as git
`om init|clone` · `om status` (drift, dirty `om dev`, pending updates) · `om diff [<rev>]` ·
`om log` · `om sync` · `om checkout <rev>` (rollback) · `om fsck` · admin at the console:
`om identity init`, `om user|device|grant|passkey … [add|approve|revoke]` (one signed commit each;
`om device add` prints a one-time QR) · stable `--porcelain` plumbing for scripts.

### Host
om runs as a dedicated non-login user (rootless engine). `om firewall`: inbound only the door.
Dev loop: you keep editing your repo as yourself; the om user only reads it (shared group, no
write access). `om dev` runs your working tree unsigned, mounted read-only, and flags the workspace
dirty; `om sync` fetches and deploys a signed commit and clears the flag. One key touch per deploy,
not per edit.
`om host quiet` (opt-in): no mDNS/LLMNR, no DHCP hostname, randomized MAC, no ping replies.
`om doctor` also reports disk encryption, LSM, pending kernel updates, hibernate-not-suspend.

---

# Appendix B — Invariants (`om doctor` proves each)
1. From any other machine every port is closed except the door, which is silent without a key.
2. No route reaches a service unless `om_auth` allowed it under that service's `om.require`.
3. Client `X-Om-*` headers and `om_*` cookies never reach a decision or an upstream.
4. Anything revoked in the identity repo is refused on its next request.
5. Nothing that requires `console` answers through a door, including the loopback one.
6. The container laws hold (no host, edge, `om_auth`, other workspace; egress only when labeled;
   writers reach only their listed hosts and never need less than `user`).
7. The identity repo verifies from its root commit to a `HEAD` matching the last one pushed off-host;
   every running workspace matches a signed commit and its lock (or is flagged dirty by `om dev`).
8. The edge sees real peer addresses; a `vpn:` door meets its qualification.

---

# Appendix C — Phases
**Verify first:** `wireguard-go` on rootless Podman, Docker and podman machine (incl. UDP forwarding);
peer addresses in the shared namespace; engine-socket filtering in Caddy.

- **A — close today's holes:** dashboard CSP and `textContent` rendering; read-only engine-socket
  filter, Portainer off by default (admin is CLI-only); policy gate (rejects `privileged`, host
  namespaces, `ports:`, socket/sensitive mounts, added caps/devices, any law violation); signed
  commits for `om sync`; core images by digest; workspace networks `internal` by default.
- **G — git model:** `.om/lock.json`, update commits, deploy log, `om status|diff|log|checkout|fsck|clone`.
1. Dedicated `om` user.
2. Door (`om_wg` / `vpn:`) and console listener, opened **alongside** today's tiers. Every current
   device is enrolled; `om doctor` lists anyone who would lose access; then the LAN tier and old
   bindings close and the firewall is reduced to the door (`dashboard.scope=public` → `shared`).
3. `om_auth`, identity repo, `om.require` in every route, admin CLI.
4. `OM_DOMAIN` (local mode first, public opt-in), certificates, passkeys.
5. `om host quiet`; every invariant in `om doctor`.

---

# Appendix D — Risks and answers
| Risk | Answer |
| :--- | :--- |
| Remote attacker | One silent door; nothing to scan. |
| Third-party VPN control plane | A slipped-in node has only `device`; anything above `shared` needs a passkey. |
| Stolen unlocked device | Only services requiring nothing more than `device`. |
| Malware on an enrolled device | Its user's grants while a session is open; device-bound sessions; never admin; writers reach only their listed hosts. |
| Collaborator | Git only; only your signed commits deploy; the laws still apply. |
| Hijacked image / re-pushed tag | Digests in the lock; new versions only as commits you sign. |
| Bad update | `om diff` before merging; health check and automatic rollback. |
| Poisoned dependency / hostile container | No host, no socket, no egress unless labeled (writers: listed hosts only), own network. |
| Exploit in your desktop browser | om runs as another user; loopback gives only `device`, never `console`. |
| Root on the host | Not prevented: root can replace om or any container. Root can't forge a signed commit, and a rewind or fork shows up in `om fsck --remote` from another machine; recover by reinstalling from signed history. |
| Stolen host | Encrypted disk; admin keys elsewhere; the console alone is never admin. |
| Lost admin key(s) | The backup replaces it; both lost → reset, never a takeover. |
| DNS / CA provider | 2FA, CAA, early renewal; the record reveals only a tunnel address. |
| Bug in om, WireGuard, Caddy, kernel or browser | Fail closed; tested crypto; auto-updates; layered, so one bug alone opens nothing. |
