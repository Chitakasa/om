# om — goals and plan

`VISION.md` says what om is meant to become and why. This document turns it into goals that can be
checked, the parts om reuses or builds, and the order of work. The build-or-reuse choice for the
door and the gate is recorded in [ADR 0001](docs/adr/0001-gate-and-door-build-vs-reuse.md).

A goal is finished only when `om doctor` proves it with a live probe. Anything that cannot be
probed is not a goal, it is a hope.

## Where we start

om today protects services with network tiers: loopback and Tailscale reach the private edge
(`:80/:443`), the LAN reaches the public edge (`:8080/:8443`), and the router admits only requests
carrying the edge token. Deploys come from the workspace's git tree, but nothing pins image
digests, requires signatures, or keeps generations. Access is granted by **location**; the goal is
to grant it by **keys, history and proof**, without losing plain files, no host daemon, and
identical behaviour on every OS.

---

## Goals

One goal per idea in `VISION.md`.

### G1 — Every deploy is a generation

- A workspace commit plus `.om/lock.json` (image digests) fully describes what runs; a re-pushed
  tag changes nothing.
- `om sync` builds a numbered **generation**, health-checks it, and either keeps it or switches back
  to the previous one as a whole.
- `om rollback` returns to the previous generation instantly; `om log` lists every generation with
  commit, lock, time and result, hash-chained.
- `om status` shows drift between the current generation and what is running (today's `om drift`
  folds into it). `om dev` runs the working tree unsigned and marks the workspace dirty.
- Commits are signed with the key the owner already uses for git, listed in `.om/allowed_signers`;
  an unsigned commit cannot become a generation.
- `om update` proposes newer digests within the pinned range (never `latest`) as a commit to
  review; nothing updates itself.

**Done when:** an unsigned commit is refused; a failing health check rolls back automatically;
running digests always match a generation or the workspace is marked dirty.

### G2 — The host is a cache

- Everything on the host is rendered from four inputs: workspace repositories, the signed access
  file, the host key, and service data. Routes, certificates, WireGuard peers, gate rules,
  networks and containers are generated and disposable.
- Secrets live encrypted in the workspace repo (age via sops) to the host key in
  `$OM_STATE_DIR/data/`, decrypted only at container start into `/run/secrets/`, never into
  environment variables or labels. The built-in `om-v2` format becomes read-only, for migration.
- The access-file chain and generation logs are mirrored off-host (`OM_MIRROR`).

**Done when:** a fresh machine with a clone, the host key, the mirror and the data reaches the same
state with `om sync`, and `om doctor` reports no difference.

### G3 — Keys, not networks

- Three keys only: **device key** (WireGuard, per laptop/phone), **passkey** (per person),
  **owner key** (hardware key plus a backup, owner only).
- Nothing is granted by location: the LAN tier and the "loopback is private" rule are removed.
  Loopback counts as one enrolled device, never as the owner.
- Identity comes only from the passkey, never from the device; a device alone opens only `shared`.

**Done when:** a scan from any other machine finds only one silent UDP port, and a stolen device
reaches nothing above `shared`.

### G4 — Requests read; signatures write

- **Data plane** (door, edge, gate, router) reads rendered configuration and answers allow, sign
  in, or deny. None of its parts has an admin UI or API that can change access (ADR 0001, R1).
- **Control plane** is signatures only: a signed commit changes what runs; a new version of the
  **access file**, signed with the owner key at the console (`ssh-keygen -Y sign`, verified on the
  host with `ssh-keygen -Y verify`), changes who gets in.
- Each access-file version records the hash of the previous one; om keeps them all. A rewind or
  fork against the off-host mirror is reported by `om fsck --remote`.
- Requests can only *ask*: an enrolling phone lands in `om pending`; a newer image lands as an
  update proposal. Both wait for `om approve` at the console with a touch of the owner key.

**Done when:** no request, from any door including loopback, can change access or what runs; the
access chain verifies from its first version to the mirrored head.

### G5 — Every app is sandboxed, and gets sign-in for free

- Each workspace network is `internal`: no host, no edge, no other workspace, no internet.
  Outbound only to hosts a service lists in `om.egress`, through a pinned forward proxy that allows
  exactly those names.
- A service that can write (`om.writes=true`, or any mount without `:ro`) requires at least
  `member`. Open internet (`om.egress=internet`) only for services that neither write nor receive
  secrets.
- After the gate allows a request, the edge passes the verified user to the service in an
  `X-Om-User` header that it first deletes from the client request, so only om can set it.

**Done when:** in-container probes cannot reach the host, the edge, another workspace or an unlisted
host; a spoofed `X-Om-User` never reaches a service.

### G6 — Proven, not promised

- `om doctor` probes every invariant below from outside and inside: port scan, keyless handshake,
  spoofed headers, revoked-key replay, container escape attempts.
- Each phase ships only when its rows pass.

---

## Parts: reuse vs build

Decided in [ADR 0001](docs/adr/0001-gate-and-door-build-vs-reuse.md). Each part is a setting, so a
better one can replace it without changing om.

| Part | Job | Filled by | om's code |
| :-- | :-- | :-- | :-- |
| **Door** (`OM_DOOR`) | authenticate the device | WireGuard (kernel on Linux, `wireguard-go` elsewhere), or a qualified `vpn:<ip>` | renders peers from the access file |
| **Edge** | TLS, routing, header hygiene, `forward_auth` | Caddy (≥ 2.11.2, see CVE-2026-30851) | `render_vhost` / `render_subpath` |
| **Gate** (`OM_GATE`) | passkeys, sessions, allow/deny | Authelia (first candidate; fallback Pocket ID + oauth2-proxy) | renders `access_control` and users from the access file |
| **Router** | admit only gate-approved requests | Caddy, edge token | unchanged |
| **Engine** | run containers, rootless | Podman or Docker | unchanged |
| **Egress proxy** | allow listed outbound names | a pinned forward proxy (chosen in phase 1) | renders the allow-list |

**om builds only:** signature verification (via `ssh-keygen`), rendering, the generation switch, and
the probes. It writes no cryptography, no WebAuthn, no session handling. `om_auth` from the earlier
plan is dropped.

### How a request flows

```
device ─WireGuard─► edge: strip client X-Om-*, Remote-*, X-Forwarded-For, gate cookies
                          set X-Forwarded-For = peer address
                    ─forward_auth─► gate: rule for <ws>-<svc>: networks + subject + policy
                    ◄─ 2xx + Remote-User ─ edge: set X-Om-User, X-Om-Edge-Token
                    ─► router (token check) ─► <ws>_<svc>
console ─terminal + owner key─► om approve | invite | revoke ─► new signed access-file version
                                                              ─► re-render door, gate, routes
```

## Access levels

One label per service, `om.access`:

| Level | Requires | Gate rule rendered |
| :-- | :-- | :-- |
| `shared` | an enrolled device | `networks:` all device addresses, `policy: bypass` at the gate (device is proven by the door) |
| `member` | device, passkey, grant | `networks:` the grantee's devices, `subject:` granted users, `policy: one_factor` (passkey is the only factor) |
| `private` | as `member`, plus a recent sign-in | as `member`, under a short-lived session cookie domain (spike; see open questions) |

No label means `private`. A label om cannot read stops the deploy. `dashboard.scope=public` is
rewritten to `om.access=shared` by a migration commit the owner reviews and signs.

## People

- `om invite <name> --grant <svc> [--until <date>]` prints a one-time QR code with the device key,
  the host's CA (local mode) and an enrollment code.
- The enrolling device appears in `om pending`; `om approve <name>` (owner-key touch) writes a new
  access-file version and re-renders door and gate.
- Grants may expire; `om revoke <name>` removes devices, passkeys and grants in one version,
  effective on the next request.
- `om access <svc>` explains who can reach a service and why.
- The dashboard becomes a viewer: what runs, what drifted, who has access. Portainer is off by
  default. Administration happens only at the console.

## Names

Passkeys need a real hostname and a trusted certificate, so `OM_DOMAIN` becomes a core setting.

- **Local** (default): a private name with certificates from om's root CA, which each device trusts
  once at enrollment. The exact suffix (`.internal` or `.home.arpa`) is chosen by the spike, since
  the gate's cookie rules must accept it.
- **Public** (opt-in): a name with ACME DNS-01 whose only record points at the tunnel address;
  wildcard certificate, CAA pinned to the CA and om's account.

## Fixed laws

No configuration can override these.

- **Fail closed:** unknown, unlabelled, unsigned or unverifiable means deny.
- **Writers need people:** any service that can write requires at least `member`.
- **No open internet for anything with something to lose.**
- **Containers stay in their workspace** unless `om.egress` lists a host.
- **Admin is local:** console plus owner key; the engine socket is never reachable through a door.
- **No secrets in configuration;** private keys never leave the device holding them.
- **No second write path:** a reused part that can change access by itself is not allowed.

## Principles

Unchanged from `VISION.md`: generic (labels, never special cases), compose don't rebuild, no host
daemon, plain files, fail closed, stdlib Python on the host, identical on every OS, runs on the daily
computer in its own user.

---

## Phases

Each phase adds to the previous without breaking it and ships when `om doctor` proves its exit
test. Changes to existing workspaces arrive as commits the owner reviews and signs.

| Phase | Adds | Ships when |
| :-- | :-- | :-- |
| **1 — Close today's holes** | dashboard CSP and `textContent` rendering; read-only engine-socket filter; Portainer off by default; policy gate at deploy (rejects `privileged`, host namespaces, `ports:`, socket and sensitive mounts, added capabilities or devices, law violations); core images by digest; `internal` workspace networks; egress proxy chosen and pinned | the policy gate passes on every workspace |
| **2 — Generations** | `.om/lock.json`, signed commits, numbered generations, `om status / log / rollback / update / dev / fsck` | an unsigned commit cannot deploy; rollback is proven |
| **Spike** (ADR 0001 qualification) | WireGuard container on rootless Podman, Docker and podman machine (UDP forwarding, `/dev/net/tun`); true peer address at the edge; Authelia: passkey-only, registration locked to approved enrollments, short-lived cookie domain for `private`, cookie domain suffix | written go / no-go per part, with the fallback if no-go |
| **3 — The door** | dedicated `om` user; signed access file and chain; WireGuard opened **alongside** today's tiers; every current device enrolled; then the LAN tier closes and the firewall allows only the door | `om doctor` lists nobody who would lose access |
| **4 — The gate** | `OM_DOMAIN`, certificates, gate container, `forward_auth` on every route, `om invite / pending / approve / revoke / access`, `X-Om-User` | every route is gated; the revoke test passes |
| **5 — Hardening and proof** | `om host quiet`; every invariant probed; off-host mirror and `om fsck --remote` | every row below is proven |

Door and gate ship separately, but enforcement waits: before phase 4 turns the gate on, om writes an
explicit `om.access` for every existing service as one signed migration commit, so no service
silently becomes `private` and unreachable.

## Invariants

| Invariant | Enforced by | How `om doctor` proves it |
| :-- | :-- | :-- |
| From another machine, only the door's UDP port exists, and it is silent without a key. | door, firewall | external scan; keyless handshake |
| No route reaches a service unless the gate allowed it under the service's level. | generated routes, `forward_auth` | unauthenticated probe of every route |
| Client identity headers and gate cookies never reach a decision or a service. | edge stripping | spoofed `X-Om-*`, `Remote-*`, `X-Forwarded-For` probe |
| Anything revoked is refused on its next request. | re-render on every access-file version | revoke a test identity, then probe |
| No door, loopback included, can change access or what runs. | no admin surface in the data plane | probe admin endpoints of every part |
| Containers keep to their network; writers need `member`; open internet only without data or secrets. | policy gate, internal networks, egress proxy | reachability probes from inside containers |
| Every running workspace matches a signed generation, or is marked dirty. | signed deploys | compare running digests with the lock |
| The access chain verifies to a head matching the off-host mirror. | signed, hash-chained access file | `om fsck --remote` |
| A `vpn:` door gives authenticated, stable peer addresses. | door qualification | peer-address echo |

## Risks and answers

| Risk | Answer |
| :-- | :-- |
| Remote attacker | One silent door; nothing to scan. |
| Third-party VPN control plane (`vpn:` door) | A slipped-in node gets only `shared`; anything else needs a passkey. |
| Stolen unlocked device | Only `shared`; identity comes from the passkey. |
| Malware on an enrolled device | Its user's grants while a session is open; never admin. |
| Bug in the reused gate | Default deny, router still demands the edge token, pinned digest with reviewed updates, spoofed-header probes; swappable via `OM_GATE`. |
| Reused part grows an admin surface | Law "no second write path"; probed by `om doctor`; the part is disabled or replaced. |
| Hijacked image or re-pushed tag | Digests in the lock; updates arrive as commits you sign. |
| Bad update | Health check and automatic rollback to the previous generation. |
| Hostile container | No host, no socket, internal network, listed egress only. |
| Exploit in the desktop browser | om runs as another user; loopback is only a device. |
| Root on the host | Not prevented. Signed history and the mirrored access chain make a rewrite visible; recovery is a rebuild, because the host is a cache. |
| Lost owner key | The backup replaces it; both lost means a new access chain and everyone enrolls again — never a takeover. |
| DNS or CA provider (public mode) | 2FA, CAA, early renewal; the record reveals only a tunnel address. |

## Open questions (answered by the spike)

- Does `wireguard-go` run in a rootless Podman container, and does podman machine forward its UDP
  port? If not, which door layout does each engine get?
- Can Authelia's passkey registration be limited to enrollments `om approve` created?
- Can `private` get a short-lived session through a separate cookie domain, or is freshness an
  honest limit?
- Which local suffix (`.internal`, `.home.arpa`) do browsers and the gate accept for passkeys and
  cookies?
- Which egress proxy satisfies "exact names only" with the fewest moving parts?

## How we will know it worked

From `VISION.md`, unchanged: a scan finds nothing to talk to; sharing a service takes under ten
minutes and creates no password; `om status`, `om log`, `om access` each answer their question in
one command; a lost host costs an afternoon and leaks nothing; `om doctor` proves every promise,
every time.
