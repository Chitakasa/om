# om — vision

> **git made code trustworthy, portable and easy to reason about. om does the same for the services
> that code runs — on your own computer, for you and the few people you choose.**

This document describes what om is meant to become and why. It is not a task list; `GOALS.md` turns
it into one.

---

## The problem

Self-hosting is easy to start and hard to trust. A few containers and a reverse proxy are running
in an afternoon. Then the questions begin. Who can reach this, and from where? What exactly is
running, and who changed it? What happens when an image is re-pushed, an update breaks, a laptop is
stolen, or the machine dies?

Most setups answer with **location**: whoever is on the home network, or inside the VPN, is
trusted. That is the weakest answer there is. om answers instead with **keys, history and proof**.

## Role models

om borrows the best idea from each of several systems rather than copying any one of them.

| Role model | What om takes from it |
| :-- | :-- |
| **git** | What should run lives in a repository. Content is pinned by hash; history is kept; commits are signed; status, diff and log answer every question. |
| **NixOS** | Deploys are numbered **generations**: the switch is all-or-nothing, and rolling back means returning to the previous generation. |
| **Sandstorm** | Every app is sandboxed by default and has no internet access unless granted. |
| **WireGuard / Tailscale** | A network where every device is bound to a key you approve, silent to anyone else — used as it is, not rebuilt. |
| **Unix** | Small tools, plain text files, and composing proven parts instead of rebuilding them. |

Two lessons from where these projects struggled shape om as much as their successes:

- Sandstorm required every app to be repackaged, and too few were. **om runs ordinary compose
  files**; anything published as a container can run, unchanged.
- git has no access control of its own; that came later, from servers. **om does not force access
  into git's shape.** git shapes how what runs is *changed*. Who may *reach* it follows security
  practice, on its own terms.

---

## Six ideas

### 1. Every deploy is a generation

A workspace is a git repository. A commit in it, together with its lock file of image digests,
fully describes what should run. `om sync` builds that commit into a new **generation** and switches
to it as a whole: health-checked, then kept, or abandoned for the previous generation. Generations
are numbered and kept, so `om rollback` is instant and `om log` is the complete history.

`om status` shows any drift between the current generation and what is actually running. During
development, `om dev` runs the working tree unsigned and marks the workspace dirty, as git marks
uncommitted changes.

Commits are signed with the key you already use for git; deploying needs no extra ceremony.

### 2. The host is a cache

Everything on the host is derived from three things:

1. the **workspace repositories** — what runs;
2. the **host key** — decrypts the secrets kept, encrypted, in the repositories;
3. the **service data** — volumes, the only thing that is not code.

Routes, certificates, networks and containers are generated from these and can be thrown away. If
the host is lost or compromised, recovery is a new machine, a clone, the key, the data, and
`om sync`. A machine you can rebuild in an afternoon is a machine you can afford to distrust.

### 3. Your VPN is the door

A device reaches om the way it reaches everything else you own: by joining your VPN. Tailscale,
Headscale, WireGuard, ZeroTier — om answers on the VPN addresses you name and on nothing else from
outside the machine. The VPN does what it is good at (keys, NAT traversal, device approval;
Tailscale's Tailnet Lock means a device joins only when one of *your* devices signs it), and om does
not rebuild it. A new phone needs the VPN app and nothing more.

Guests on your Wi-Fi see only what you mark public. Someone outside your home sees exactly the
public services when your VPN shares the machine with them on its public port.

### 4. Signatures change what runs

A signed commit changes what runs; nothing else can. The edge, the router and the dashboard read and
answer — none of them can start, stop or change a container. A flaw in the web layer therefore can
never become control of the machine.

### 5. Every app is sandboxed

Each workspace runs on its own internal network. A service cannot reach the host, the edge, another
workspace, or the internet — unless its labels list the exact hosts it needs. Most supply-chain
attacks need to phone home; a service that cannot reach the internet cannot leak what it holds, even
when its code is hostile.

### 6. Proven, not promised

Every guarantee in this document is an invariant that `om doctor` checks with a live probe: it
spoofs hosts, sends requests without the edge's token, and tries to reach the host and the internet
from inside a container. A guarantee that cannot be probed is not written down as a guarantee.

---

## Orchestrate, don't reinvent

om's own code is the glue, never the lock. The parts that keep attackers out are proven projects,
pinned by digest and hardened:

| Part | Job | Filled by |
| :-- | :-- | :-- |
| **VPN** | decide which devices reach the machine | the one you already use (Tailscale with Tailnet Lock by default) |
| **Edge** | route, separate tiers, strip forged headers | Caddy |
| **Router** | admit only what the edge sent | Caddy, checking the edge's secret token |
| **Egress proxy** | let a service reach only the hosts it lists | Squid |
| **Engine** | run the containers, rootless | Podman or Docker |
| **Signatures and secrets** | trust commits, encrypt secrets | git + SSH keys, age |

om itself verifies signatures, renders the compose labels into each part's configuration, records
generations, and proves the result. It writes no cryptography, no VPN, no login system.

## Network architecture

A series of locked doors, each of which assumes the one before it has already failed.

```
            your devices (VPN)                      guests on your Wi-Fi
                    │                                        │
  ┌─ 1. SILENCE ────┴────────────────────────────────────────┴───────────┐
  │  Firewall: only om's web ports. Nothing listens on the internet.     │
  └─────────────────┬────────────────────────────────────────┬───────────┘
                    ▼                                        ▼
  ┌─ 2. TIERS ──────────────────────────────────────────────────────────┐
  │  Loopback and VPN addresses → private tier (every route).           │
  │  LAN address → public tier: public routes only, no private route    │
  │  exists there, whatever Host header is sent.                        │
  └─────────────────┬───────────────────────────────────────────────────┘
                    ▼
  ┌─ 3. ROUTER — did the edge really send this? ────────────────────────┐
  │  The only component on the workspace networks. Forwards only        │
  │  requests carrying the edge's secret token; drops everything else.  │
  └─────────────────┬───────────────────────────────────────────────────┘
                    ▼
  ┌─ 4. SANDBOX — what can the service itself reach? ───────────────────┐
  │  An internal network per workspace: no host, no edge, no other      │
  │  workspace, no internet. Outbound only to hosts the service lists.  │
  └─────────────────────────────────────────────────────────────────────┘
```

**Why these choices**

- **A VPN, not open HTTPS.** An open web port can be scanned and attacked before any login runs.
  Nothing om serves is on the internet.
- **The developer's VPN, not om's own.** Building a second VPN, a login system and a certificate
  authority for every device made om harder to use and added a worse secret to keep (a CA every
  device trusts for every website). ADR 0003 records the decision.
- **An edge and a router, not one proxy.** The edge never joins a workspace network, so a service
  cannot use it to reach another workspace. Each layer is simple enough to verify on its own.
- **No outbound by default.** It turns most supply-chain attacks into dead ends.

## Rules on services

A service is private unless its labels say `dashboard.scope=public`. A missing label, a typo or any
other value means private: forgetting a label can never open a service.

## People

om is for **one owner** and the few people they share with.

- **Your devices** join your VPN and see everything.
- **Guests at home** use your Wi-Fi and see the public services.
- **People elsewhere** get your machine shared through the VPN, limited by its access rules to the
  public port.
- **Several people on one machine** each get a login with `om auth add`.
- **The dashboard is a viewer, not a control panel.** It shows what runs and changes nothing.

## How it feels

```
$ om status
photos   generation 14   clean    3 services healthy
notes    dev             dirty    working tree, unsigned
updates  1 available              om update --dry-run

$ om update                    # pins the new digest, commits, redeploys
$ om log
15  a41c9e2  running   2026-10-07 09:12
14  77b0d1c  running   2026-10-01 21:40
$ om rollback 14
$ om egress log                # what a service tried to reach, and the label that allows it
```

It should feel like git: few commands, each doing one obvious thing, and nothing happening that you
did not ask for.

## Principles

- **Generic.** om knows protocols, never products. Behaviour comes from labels in the workspace,
  never from special cases in om's code.
- **Compose, don't rebuild.** Proven parts do the security-critical work; om is the glue.
- **No daemon on the host.** om runs when invoked; the long-lived parts are hardened containers.
- **Plain files.** Everything can be read, diffed and backed up with ordinary tools.
- **Fail closed.** Anything unknown, unlabelled, unsigned or unverifiable is private or refused.
- **Standard-library Python on the host,** with no dependencies to install.
- **The same on every OS.** Linux, macOS and Windows behave identically.
- **Runs on your daily computer;** no dedicated server required.

## What om is not

- Not Kubernetes: one machine, no cluster, no high availability.
- Not a hosting platform: no tenants, no anonymous public websites.
- Not a VPN, an identity provider or a certificate authority: it uses the ones you have.
- Not a replacement for the container engine or Caddy: it orchestrates them.

## Honest limits

- **Root on the host wins.** om cannot stop an attacker with root. Signed commits and the
  generation log make a change visible, and recovery is routine, because the host is a cache.
- **The VPN account is the lock.** Whoever can add a device to your VPN reaches the private tier;
  turn on Tailnet Lock (or hold the keys yourself).
- **Data is not code.** Volumes cannot live in git, so the host is only truly disposable when its
  data is backed up.
- **Proven parts still have bugs.** Layering means one bug alone opens nothing, and pinned digests
  with reviewed updates keep them current.

## Horizons

Ideas that fit this model and come later, each without changing the core:

- **Data snapshots:** `om data snapshot | restore`, encrypted, to an off-host remote — making "the
  host is a cache" fully true.
- **Publishing one service to the internet** through a relay that terminates TLS on this machine
  (e.g. Tailscale Funnel), opt-in per service, never touching the private path.

## How we will know it worked

- From the internet, nothing answers; from the LAN, only the public services.
- A new device needs the VPN app and nothing else.
- What runs, who changed it, and what a service reaches are each answered by one command:
  `om status`, `om log`, `om egress log`.
- A lost or stolen host costs an afternoon to replace and leaks nothing.
- `om doctor` proves every promise in this document, every time it runs.
