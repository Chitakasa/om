# om — Design

> **git made code trustworthy, portable and easy to reason about. om does the same for the services
> that code runs — on your own computer, for you and the few people you choose.**

Why om is built the way it is, what it promises, and how each promise is checked. Read it with
`om docs design`. The decisions behind it are recorded in `docs/adr/` (0002: outbound access;
0003: the VPN as the network boundary; 0004: one origin per service).

---

## The problem

Self-hosting is easy to start and hard to trust. A few containers and a reverse proxy run in an
afternoon. Then the questions begin. Who can reach this, and from where? What exactly is running,
and who changed it? What happens when an image is re-pushed, an update breaks, a container is
compromised, or the machine dies?

Most setups answer with an open port and a login page, or by trusting the whole home network. om
answers with **keys** (only devices you approved reach it), **history** (every deploy is a signed,
numbered generation) and **proof** (`om doctor` probes every promise live).

## Role models

| Role model | What om takes from it |
| :-- | :-- |
| **git** | What should run lives in a repository: pinned by hash, history kept, commits signed; status and log answer every question. |
| **NixOS** | Deploys are numbered generations; rolling back means returning to the previous one. |
| **Sandstorm** | Every app is sandboxed by default and has no internet unless granted. |
| **WireGuard / Tailscale** | A network where every device is bound to a key you approve — used as it is, not rebuilt. |
| **Unix** | Small tools, plain text files, composing proven parts. |

Two lessons from where they struggled: Sandstorm required apps to be repackaged — **om runs ordinary
compose files** unchanged. And building your own network identity (om tried: a WireGuard door, a
passkey gate, its own certificate authority) made every new device a chore — **om uses the VPN you
already have** (ADR 0003).

---

## Six ideas, each with its check

A goal is finished only when `om doctor` proves it with a live probe. Anything that cannot be probed
is not a goal, it is a hope.

### 1. Every deploy is a generation

A workspace is a git repository. A commit plus `.om/lock.json` (image index digests) fully describes
what runs; a re-pushed tag changes nothing. Every `om start`, `sync`, `update` and `rollback` is a
numbered generation — commit, lock, signer, time, result — hash-chained, because git does not record
what was deployed when. A clean commit must be signed by a key in `.om/allowed_signers`, checked
against om's copy from the last deploy, so a commit cannot trust itself. Uncommitted work still runs,
as a dirty, unsigned dev generation. Updates arrive as commits (`om update`); nothing updates itself
unless a service opts in with `om.update=auto`: then the scheduled sync commits the new digest,
health-checks it and reverts the commit if it fails. `om.update=hold` pins a service where it is.

**Checked by:** *Generations*, *Running = lock*; `om fsck`.

### 2. The host is a cache

Everything on the host is derived from three things: the **workspace repositories**, the **host
key** (`<state>/data/age.key`, decrypts the age secrets kept in the repositories), and the **service
data**. Routes, certificates, networks and containers are generated and disposable. Recovery is a
new machine, the clones, the key, the data, and `om start`. Secrets reach a service only in memory,
read-only at `/run/secrets/`, never as environment variables.

**Checked by:** the policy gate refuses plaintext secret files; *State* (no machine state in the
program folder).

### 3. Your VPN is the door

Nothing om serves is on the internet. The private tier answers on loopback and on the VPN addresses
you trust (`om vpn trust <iface>`): om finds every VPN by itself, with no product names, but trusts
none without your yes — a tunnel may also be a commercial or company VPN, which would let its
provider or your coworkers in. The VPN does what it is good at: keys,
NAT traversal, device approval. With Tailscale's Tailnet Lock a device joins only when one of *your*
devices signs it. A new phone needs the VPN app and nothing more.

Every web service gets its own port — its own browser origin — so a compromised service's scripts
can never read another service or the dashboard through your browser (ADR 0004). The LAN reaches
only services marked `dashboard.scope=public`, on their public ports (21000+n). Someone elsewhere
sees exactly those when your VPN shares the machine with them on the public ports only.

**Checked by:** *Private tier*, *DNS rebinding*, *LAN tier*, *VPN*, *Firewall*.

### 4. Signatures change what runs

A signed commit changes what runs; nothing else can. The edge, the router and the dashboard read and
answer — none can start, stop or change a container. Caddy's admin API listens only on loopback
inside its container; the dashboard sees the engine only through `om_sockguard`'s read-only filter.

**Checked by:** *Admin surface*, *Engine filter*, *Router token*.

### 5. Every app is sandboxed

Each workspace runs on its own internal network: no host, no edge, no other workspace, no internet —
unless its labels list the exact hosts it needs (`om.egress`), reached through `om_egress` with the
service's own credential. A policy gate at every deploy refuses `privileged`, host namespaces,
published ports, the engine socket and sensitive mounts, extra capabilities and devices; a service
may waive a rule for itself only by a visible label (`om.policy.allow`), never `privileged` or `ports`.
Open internet only for services that neither write nor receive secrets.

**Checked by:** *Egress* (DNS, direct and host addresses blocked from inside; the proxy demands a
credential), *Published ports*, *Edge isolation*.

### 6. Development is no slower than plain compose

Security that slows the edit loop gets switched off, so: nothing network-related is hand-written
(routes, hostnames, networks, egress rules are generated from at most two labels); a new device
needs only the VPN app; every refusal names its fix (`om egress log` prints the exact label line);
`om init` / `om add` scaffold a working service in minutes; uncommitted work runs unsigned.
Services compose across workspaces (`om.link`, consented by both sides); a service may carry its own
proxy rules (`om.caddy`, from an allow-list); any branch runs beside the original as a throw-away
workspace (`om preview`); every status answer is also JSON (`--json`) for scripts and editors; and a
clone on another machine runs with `om start` (`om secrets rekey` for its secrets).

**Checked by:** the test suite (every refusal carries a fix); a new project runs from `om init`
with zero hand-written network configuration.

---

## Parts: orchestrate, don't reinvent

om's own code is the glue, never the lock. The parts that keep attackers out are proven projects,
pinned by digest and hardened (read-only, all capabilities dropped).

| Part | Job | Filled by |
| :-- | :-- | :-- |
| **VPN** | which devices reach the machine | the one you use (Tailscale with Tailnet Lock by default) |
| **Edge** `om_caddy` | tiers, routing, header hygiene | Caddy |
| **Router** `om_router` | admit only requests carrying the edge's token | Caddy |
| **Egress proxy** `om_egress` | let each service reach only its listed hosts | Squid |
| **Engine filter** `om_sockguard` | read-only engine API for the dashboard | Caddy on a unix socket |
| **Engine** | run containers, rootless | Podman or Docker |
| **Signatures, secrets** | trust commits, encrypt secrets | git + SSH keys, age |

om itself verifies signatures, renders labels into each part's configuration, records generations
and proves the result. It writes no cryptography, no VPN, no login system, no certificate authority
for devices. The edge and the router stay two containers: the edge never joins a workspace network,
so a service cannot use it to reach another workspace by sending a different `Host` header.

```
            your devices (VPN)                      guests on your Wi-Fi
                    │                                        │
  ┌─ 1. SILENCE ────┴────────────────────────────────────────┴───────────┐
  │  Firewall: only om's web ports. Nothing listens on the internet.     │
  └─────────────────┬────────────────────────────────────────┬───────────┘
  ┌─ 2. TIERS ──────┴────────────────────────────────────────┴───────────┐
  │  Loopback and VPN addresses → private tier (every route).            │
  │  LAN address → public tier: public routes only, whatever Host sent.  │
  └─────────────────┬────────────────────────────────────────────────────┘
  ┌─ 3. ROUTER ─────┴─── forwards only requests carrying the edge token ─┐
  └─────────────────┬────────────────────────────────────────────────────┘
  ┌─ 4. SANDBOX ────┴─── internal network; outbound only to listed hosts ┐
  └──────────────────────────────────────────────────────────────────────┘
```

## Fixed laws

No setting overrides these.

- **Fail closed:** unknown, unlabelled, unsigned or unverifiable means private, refused or denied —
  including a mistyped `OM_POLICY` / `OM_SIGNED`.
- **No open internet for anything with something to lose.**
- **Containers stay in their workspace** unless `om.egress` lists a host.
- **Admin is local:** the console; the engine socket is never reachable through the edge.
- **No secrets in configuration.**
- **om never runs as root;** containers run rootless under your user.
- **om builds no VPN, login system or device CA.**

## Principles

- **Generic.** om knows protocols, never products: behaviour comes from labels, never from special
  cases in om's code.
- **No daemon on the host.** om runs when invoked; long-lived parts are hardened containers.
- **Plain files.** Everything can be read, diffed and backed up with ordinary tools.
- **Standard-library Python,** no dependencies to install.
- **The same on Linux, macOS and Windows.**
- **Runs on your daily computer;** no dedicated server required.

## What om is not

Not Kubernetes (one machine, no cluster). Not a hosting platform (no tenants, no anonymous public
websites). Not a VPN, identity provider or certificate authority — it uses yours. Not a replacement
for the container engine or Caddy — it orchestrates them.

---

## Risks and answers

| Risk | Answer |
| :-- | :-- |
| Remote attacker | Nothing listens on the internet. |
| Someone on the LAN | Public tier only; private routes do not exist there. |
| A device slipped into your VPN | Your VPN's device approval (with Tailscale: Tailnet Lock) or keys only you hold; `om doctor` reminds you. |
| Another person with a login on this machine | `om doctor` *Login* warns; `om auth add` puts a password on the private tier. |
| Hijacked image or re-pushed tag | Digests in the lock; updates arrive as commits you sign. |
| Bad update | Health check and rollback to the previous generation. |
| Hostile container | No host, no socket, internal network, listed egress only. |

## Honest limits

- **Root on the host wins.** om makes a change visible (signed commits, the generation log) and
  recovery routine, because the host is a cache.
- **The VPN account is the lock.** Whoever can add a device to your VPN reaches the private tier.
- **Plain HTTP on other devices.** The VPN encrypts the traffic, but browsers keep HTTPS-only
  features (app install, offline mode, camera and clipboard) off; trusted certificates per service
  would need a domain or a CA installed on every device.
- **Data is not code.** The host is truly disposable only when its data is backed up.
- **Proven parts still have bugs.** Layering means one bug alone opens nothing; pinned digests with
  reviewed updates keep them current. A pin never gets a security fix until it moves: `om status` and
  the dashboard say when a newer digest exists, `om scan` (with trivy or grype) says which pins have
  findings, and `om.update=auto` moves the ones you trust it with.
- **Notifications are best effort.** Desktop toasts need a graphical session; a webhook leaves the
  machine, so it is never switched on for you. Nothing depends on being notified.

## Horizons

- **Data snapshots:** `om data snapshot | restore`, encrypted, to an off-host remote.
- **Publishing one service to the internet** through a relay that terminates TLS on this machine
  (e.g. Tailscale Funnel), opt-in per service, never touching the private path.

## How we will know it worked

From the internet nothing answers; from the LAN only the public services. A new device needs the VPN
app and nothing else; a new service needs no hand-written network configuration. `om status`,
`om log` and `om egress log` each answer their question in one command. A lost host costs an
afternoon and leaks nothing. `om doctor` proves every promise, every time.
