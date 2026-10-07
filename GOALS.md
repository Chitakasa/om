# om — goals and plan

`VISION.md` says what om is meant to become and why. This document turns it into goals that can be
checked, the parts om reuses, and what is done. Network and identity are decided in
[ADR 0003](docs/adr/0003-simplify-network-and-identity.md) (it supersedes ADR 0001); outbound access
in [ADR 0002](docs/adr/0002-egress-proxy.md).

A goal is finished only when `om doctor` proves it with a live probe. Anything that cannot be
probed is not a goal, it is a hope.

## The rule behind every goal

om runs containers safely, routes them, and deploys them from signed commits. It reuses what
already does a job well — the container engine, Caddy, git, age, and **the developer's VPN** — and
writes only the glue. om builds no VPN, no login system and no certificate authority for devices.

---

## Goals

### G1 — Every deploy is a generation

- A workspace commit plus `.om/lock.json` (image index digests) fully describes what runs; a
  re-pushed tag changes nothing.
- Every `om start`, `sync`, `update` and `rollback` is a numbered **generation** with commit, lock,
  signer, time and result, hash-chained in `<state>/generations/<ws>/`. Git does not record what was
  deployed when; this log does.
- A clean commit must be signed by a key in `.om/allowed_signers`, checked against om's trusted
  copy from the last deploy (a commit cannot trust itself). `OM_SIGNED=enforce` refuses the rest.
  Uncommitted work still runs, as a dirty, unsigned dev generation.
- `om rollback [n]`, `om log`, `om fsck` (chain, signature, running images = lock).
- `om update [--dry-run]` moves pins to newer digests within the pinned tag, commits the lock and
  redeploys; nothing updates itself. `om status` shows updates found by the heal timer.

**Done:** an unsigned commit is refused under enforce; `om fsck` and *Running = lock* prove the
running digests match the lock.

### G2 — The host is a cache

- Routes, certificates, networks, egress rules and containers are rendered from the workspace
  repositories, `om.env`, and two keys in `<state>/data/` (edge token, age host key).
- Secrets live encrypted in the workspace repo with age, to this host's key and the owner's SSH
  key; `om start` decrypts them into memory (`$XDG_RUNTIME_DIR`) and mounts them read-only at
  `/run/secrets/<name>` — never environment variables or labels. A plaintext secret file in a
  workspace is refused. Back up `<state>/data/age.key` off the machine.

**Done:** a fresh machine with the clones, `om.env`, the age key and the service data reaches the
same state with `om start`.

### G3 — The VPN is the network boundary

- The private tier answers on loopback and on the VPN addresses in `OM_VPN` (`auto` = Tailscale
  when it is up; WireGuard, ZeroTier, NetBird or Headscale by interface or address). A commercial
  VPN's tunnel is never trusted automatically.
- Nothing is reachable from the internet. The LAN reaches only `dashboard.scope=public` services.
- Who may join the VPN is the VPN's job: with Tailscale, Tailnet Lock means a device joins only when
  one of your devices signs it. `om doctor` reports whether it is on.

**Done:** a scan from the LAN finds only the public tier; the private tier answers only on loopback
and VPN addresses; *VPN* passes.

### G4 — Signatures change what runs

- What runs changes only through a signed commit (G1). No request through the edge can change it:
  the edge, router and dashboard have no write path to the engine, and Caddy's admin API listens on
  loopback inside its container only.

**Done:** *Admin surface*, *Engine filter* and *Router token* pass.

### G5 — Every app is sandboxed

- Each workspace network is `internal`: no host, no edge, no other workspace, no internet.
  Outbound only to hosts a service lists in `om.egress`, through `om_egress`, with its own
  credential. `om.egress=learn` allows any public host and records what was used.
- A policy gate at every deploy refuses `privileged`, host namespaces, `ports:`, the engine socket
  and sensitive mounts, added capabilities and devices; `om.policy.allow` waives a rule for one
  service, never `privileged` or `ports`.
- Open internet (`om.egress=internet`) only for services that neither write nor receive secrets.

**Done:** in-container probes cannot reach DNS, the internet, the host addresses or the proxy
without a credential (*Egress*).

### G6 — Proven, not promised

- `om doctor` probes every invariant below and prints a fix for each failure.

### G7 — Development is no slower than plain compose

- **Nothing network-related is hand-written.** Routes, hostnames, networks and egress rules are
  generated. A service needs at most two labels: `dashboard.scope=public` to share it, and
  `om.egress` if it calls out.
- **No device setup.** A phone or laptop reaches om by joining the developer's VPN; no QR code,
  certificate or one-time code.
- **Every refusal names its fix.** A refused deploy, connection or commit says which label, command
  or signature is missing (`om egress log` prints the exact `om.egress=…` line).
- **`om init`, `om add`** scaffold the workspace, labels and lock, so a new project runs in minutes.

**Done:** a new project goes from `om init` to running with zero hand-written network
configuration; a new device needs only the VPN app.

---

## Parts

| Part | Job | Filled by | om's code |
| :-- | :-- | :-- | :-- |
| **VPN** | who may reach the machine | Tailscale (Tailnet Lock), or any VPN named in `OM_VPN` | detects addresses; binds the private tier to them |
| **Edge** (`om_caddy`) | routing, header hygiene, tiers | Caddy | `render_vhost` / `render_subpath`, the Caddyfile |
| **Router** (`om_router`) | admit only requests carrying the edge token | Caddy | the router Caddyfile |
| **Egress proxy** (`om_egress`) | allow listed outbound names | Squid | renders rules and per-service credentials |
| **Engine filter** (`om_sockguard`) | read-only engine API for the dashboard | Caddy on a unix socket | its Caddyfile |
| **Engine** | run containers, rootless | Podman or Docker | unchanged |
| **Signatures, secrets** | trust commits; encrypt secrets | `git verify-commit`, `ssh-keygen`; age | verification, rendering |

The edge and the router stay two containers: the edge never joins a workspace network, and the
router refuses anything without the edge's token, so a service cannot use the edge to reach another
workspace by sending a different `Host` header.

### How a request flows

```
device on your VPN ─► VPN address :80 ─► edge (explicit host list, optional login)
LAN guest          ─► LAN address :80 ─► edge public tier (public routes only)
VPN guest          ─► VPN address :8080 ─► edge public tier
edge ─ X-Om-Edge-Token ─► router (token check) ─► <ws>_<svc> on its internal network
service ─ om_egress credential ─► om_egress ─► only the hosts in its om.egress label
```

## Exposure

| Label | Reached by |
| :-- | :-- |
| none (default) | this machine and your VPN devices |
| `dashboard.scope=public` | also anyone on the LAN, and VPN guests on port 8080 |

Sharing with someone outside the household is the VPN's job: share the machine with their account
and allow them port 8080 only in the VPN's access rules.

## Fixed laws

- **Fail closed:** unknown, unlabelled, unsigned or unverifiable means private, refused, or denied.
- **No open internet for anything with something to lose.**
- **Containers stay in their workspace** unless `om.egress` lists a host.
- **Admin is local:** the console; the engine socket is never reachable through the edge.
- **No secrets in configuration.**
- **om builds no VPN, login system or device CA.**

## Principles

Unchanged from `VISION.md`: generic (labels, never special cases), compose don't rebuild, no host
daemon, plain files, fail closed, stdlib Python on the host, identical on every OS.

---

## What is done

| Phase | Shipped |
| :-- | :-- |
| **1 — Close the holes** | dashboard CSP; `om_sockguard`; policy gate (`OM_POLICY=enforce`); core images by digest; internal workspace networks; `om_egress` with learn mode |
| **2 — Generations** | `.om/lock.json`, signed deploys, generations, `om log / rollback / fsck / update [--dry-run]` |
| **3 — Secrets** | age secrets in the repo, mounted read-only from memory |
| **4 — Simplify (ADR 0003)** | the VPN as the boundary (`OM_VPN`); door, gate, access file, tiers, mirror, om user, host quiet and Portainer removed |

## Invariants

| Invariant | Enforced by | `om doctor` row |
| :-- | :-- | :-- |
| The private tier answers only on loopback and VPN addresses, and only to listed host names. | port bindings, explicit hosts, `:80 { abort }` | *Private tier*, *DNS rebinding*, *Address drift* |
| The LAN reaches only public routes and a sanitized dashboard. | separate container ports, route absence | *LAN tier* |
| Nothing listens in the edge but its web ports; Caddy admin on loopback only. | edge config | *Admin surface* |
| A request without the edge token never reaches a service. | router | *Router token*, *Edge isolation* |
| The dashboard cannot change the engine. | `om_sockguard` | *Engine filter* |
| Containers keep to their network and listed hosts. | internal networks, egress proxy, policy gate | *Egress*, *Published ports* |
| Every running workspace matches a signed generation and its lock, or is marked dirty. | signed deploys, lock | *Generations*, *Running = lock* |
| Joining the VPN needs your signature. | Tailnet Lock | *VPN* |

## Risks and answers

| Risk | Answer |
| :-- | :-- |
| Remote attacker | Nothing listens on the internet. |
| Someone on the LAN | Public tier only; private routes do not exist there. |
| A device slipped into your VPN | Tailnet Lock (Tailscale) or keys only you hold; `om doctor` warns when it is off. |
| Another person with a login on this machine | `om doctor` *Login* warns; `om auth add` puts a password on the private tier. |
| Hijacked image or re-pushed tag | Digests in the lock; updates arrive as commits you sign. |
| Bad update | Health check and rollback to the previous generation. |
| Hostile container | No host, no socket, internal network, listed egress only. |
| Root on the host | Not prevented. Signed commits and the generation log make a change visible; the host is a cache, so recovery is a rebuild. |

## How we will know it worked

A new device needs only the VPN app; a new service needs no hand-written network configuration;
`om status`, `om log`, `om egress log` each answer their question in one command; a lost host costs
an afternoon and leaks nothing; `om doctor` proves every promise, every time.
