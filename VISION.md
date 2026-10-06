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
| **Sandstorm** | Every app is sandboxed by default, has no internet access unless granted, and receives the user's identity from the platform instead of running its own login. |
| **BeyondCorp** (zero-trust access) | Access depends on who you are and what device you hold, never on which network you are on. |
| **WireGuard** | A door that stays silent to anyone without a key, where every peer address is bound to a key. |
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

Everything on the host is derived from four things:

1. the **workspace repositories** — what runs;
2. the **access file** — who may reach it: one plain file, signed by the owner key;
3. the **host key** — decrypts the secrets kept, encrypted, in the repositories;
4. the **service data** — volumes, the only thing that is not code.

Routes, certificates, networks and containers are generated from these and can be thrown away. If
the host is lost or compromised, recovery is a new machine, a clone, the key, the data, and
`om sync`. A machine you can rebuild in an afternoon is a machine you can afford to distrust.

### 3. Keys, not networks

om recognises exactly three kinds of key:

| Key | Held by | Proves |
| :-- | :-- | :-- |
| **Device key** (WireGuard) | each enrolled laptop or phone | this request comes from a known device |
| **Passkey** | each person, in their device's secure hardware | this is a known person, present now |
| **Owner key** (a hardware security key, plus a backup) | the owner only | this change to access is authorised |

A device alone opens only what is explicitly `shared`. Anything personal needs a person, and the
person comes from their passkey, never from the device — so a family member can sign in on your
laptop as themselves, and a stolen device yields almost nothing. Nothing is granted by location:
not the LAN, not loopback, not "inside the VPN".

### 4. Requests read; signatures write

There are two planes, and they never mix.

- The **data plane** answers requests. It reads the current configuration and decides: allow, ask
  to sign in, or deny. It can never change who is allowed or what runs.
- The **control plane** is signatures. A signed commit changes what runs; a new version of the
  access file, signed with the owner key at the console, changes who gets in. Nothing else can.

A request may *ask* for a change — a new phone wanting to enroll — and om may *notice* one — a newer
image is available. Both wait until the owner runs `om approve`. A flaw in the web layer therefore
can never become control of the machine.

Each version of the access file records the hash of the one before it, and om keeps them all. That
short chain is the audit trail and makes a silent rollback detectable: git's history guarantee,
without a repository for a file of a few dozen lines.

### 5. Every app is sandboxed, and gets sign-in for free

Each workspace runs on its own internal network. A service cannot reach the host, the edge, another
workspace, or the internet — unless its labels list the exact hosts it needs. A service that can
write data must require a signed-in person. Most supply-chain attacks need to phone home; a service
that cannot reach the internet cannot leak what it holds, even when its code is hostile.

After the gate allows a request, it passes the verified user to the service in a header that only
om can set. A family photo app needs no login screen and no password database of its own.

### 6. Proven, not promised

Every guarantee in this document is an invariant that `om doctor` checks with a live probe: it scans
from outside, spoofs headers, replays revoked keys, and tries to reach the host from inside a
container. A guarantee that cannot be probed is not written down as a guarantee.

---

## Orchestrate, don't reinvent

om's own code is the glue, never the lock. The parts that keep attackers out are proven projects,
pinned by digest and hardened:

| Part | Job | Filled by |
| :-- | :-- | :-- |
| **Door** | authenticate the device | WireGuard, or any VPN with key-bound peer addresses |
| **Edge** | terminate TLS, route, strip forged headers | Caddy |
| **Gate** | passkeys, sessions, allow or deny | a vetted identity-aware auth server, spoken to through the standard forward-auth protocol |
| **Router** | admit only what the gate allowed | Caddy, checking the gate's secret token |
| **Engine** | run the containers, rootless | Podman or Docker |

om itself does what no off-the-shelf part does: it verifies signatures, renders the signed access
file and the compose labels into each part's configuration, switches generations, and proves the
result. Each part is chosen by a setting, not hard-coded, so a better one can replace it without
changing om's design. om writes no cryptography and no authentication protocol of its own.

## Network architecture

A series of locked doors, each of which assumes the one before it has already failed.

```
                     anyone on the internet or the LAN
                                   │
                                   ▼
  ┌─ 1. SILENCE ─────────────────────────────────────────────────────────┐
  │  Firewall: nothing answers except one UDP port, and that port says   │
  │  nothing to a sender without an enrolled device key.                 │
  └──────────────────────────────────┬───────────────────────────────────┘
                                     ▼
  ┌─ 2. DOOR — which device? ────────────────────────────────────────────┐
  │  WireGuard. Each device has a fixed tunnel address bound to its key, │
  │  so the address itself is proof.                                     │
  └──────────────────────────────────┬───────────────────────────────────┘
                                     ▼
  ┌─ 3. GATE — which person, and may they? ──────────────────────────────┐
  │  The edge discards identity claims sent by the client; the gate adds │
  │  passkey and grant, and compares them with the service's rule.       │
  │  Allow, ask to sign in, or deny. Unknown or unlabelled: deny.        │
  └──────────────────────────────────┬───────────────────────────────────┘
                                     ▼
  ┌─ 4. ROUTER — did the gate really say yes? ───────────────────────────┐
  │  The only component on the workspace networks. Forwards only         │
  │  requests that carry the gate's secret token; drops everything else. │
  └──────────────────────────────────┬───────────────────────────────────┘
                                     ▼
  ┌─ 5. SANDBOX — what can the service itself reach? ────────────────────┐
  │  An internal network per workspace: no host, no edge, no other       │
  │  workspace, no internet. Outbound only to hosts the service lists.   │
  └──────────────────────────────────────────────────────────────────────┘

  Beside all of this, never reachable through it:
  CONSOLE (owner at a terminal, as the om user) + OWNER KEY → signed access file
```

**Why these choices**

- **WireGuard, not open HTTPS.** An open web port can be scanned and attacked before any login
  runs. A WireGuard port is silent without a key.
- **Passkeys, not passwords.** They cannot be phished, reused or guessed, and they live in hardware
  people already own.
- **A gate and a router, not one proxy.** If the edge is ever misconfigured to forward something
  directly, the router still refuses it. Each layer is simple enough to verify on its own.
- **Loopback is not trust.** Every program on the host can reach loopback, including a compromised
  browser. It proves "this machine", never "the owner".
- **No outbound by default.** It turns most supply-chain attacks into dead ends.

**Considered and rejected:** client TLS certificates (poor browser support, painful on phones); a
third-party VPN's account as the only identity (one compromised account would open everything); a
public reverse proxy with a login page (the login page becomes the target).

## Rules on services

Each service says who may reach it in one label:

| Level | Requires | Typical use |
| :-- | :-- | :-- |
| `shared` | an enrolled device | a status page for the household |
| `member` | device, passkey, and a grant for this service | a service for specific people |
| `private` | device, a passkey bound to that device and used in the last few minutes, and a grant | anything sensitive |

A service without the label is `private`; a label om cannot read stops the deploy. Forgetting a
label can never open a service, and a typo can never silently change one.

## People

om is for **one owner** and the few people they share with: family, friends, collaborators.

- **Inviting** is one command: `om invite alice --grant photos`. It prints a one-time QR code. Alice
  scans it; her phone receives its device key and learns to trust the host; she creates a passkey.
  Her request waits in `om pending` until the owner runs `om approve alice` and touches the key.
- **Grants** link a person to a service and may expire (`--until 2026-12-31`), so a guest's access
  ends without anyone having to remember.
- **Revoking** a person removes their devices, passkeys and grants in one signed change, effective
  on their next request.
- **The dashboard is a viewer, not a control panel.** It shows what runs, what drifted and who has
  access, and changes nothing. Administration happens only at the console.

## How it feels

```
$ om status
photos   generation 14   clean    3 services healthy
notes    dev             dirty    working tree, unsigned
updates  1 available              om update --dry-run

$ om update photos             # shows the change, pins the new digest, commits
photos/immich   1.118.2 → 1.119.0   sha256:9f3e…
$ om sync                      # builds generation 15, health-checks, keeps or rolls back

$ om log photos
15  a41c9e2  healthy       2026-10-07 09:12
14  77b0d1c  rolled back   2026-10-01 21:40

$ om invite alice --grant photos --until 2026-12-31
$ om pending                   # alice's phone wants to enroll
$ om approve alice             # touch key
$ om access photos             # who can reach photos, and why
```

It should feel like git: few commands, each doing one obvious thing, and nothing happening that you
did not ask for.

## Principles

- **Generic.** om knows protocols, never products. Behaviour comes from labels in the workspace,
  never from special cases in om's code.
- **Compose, don't rebuild.** Proven parts do the security-critical work; om is the glue.
- **No daemon on the host.** om runs when invoked; the long-lived parts are hardened containers.
- **Plain files.** Everything can be read, diffed and backed up with ordinary tools.
- **Fail closed.** Anything unknown, unlabelled, unsigned or unverifiable is denied.
- **Standard-library Python on the host,** with no dependencies to install.
- **The same on every OS.** Linux, macOS and Windows behave identically.
- **Runs on your daily computer,** isolated in its own user; no dedicated server required.

## What om is not

- Not Kubernetes: one machine, no cluster, no high availability.
- Not a hosting platform: no tenants, no anonymous public websites.
- Not a VPN or an identity provider: it configures proven ones to guard its own door.
- Not a replacement for the container engine or Caddy: it orchestrates them.

## Honest limits

- **Root on the host wins.** om cannot stop an attacker with root. It makes the attack visible —
  git history and the access-file chain, mirrored off-host, show any rewrite — and makes recovery
  routine, because the host is a cache.
- **Some setup is unavoidable.** Each device installs WireGuard once and trusts the host once; the
  owner buys two hardware keys.
- **Data is not code.** Volumes cannot live in git, so the host is only truly disposable when its
  data is backed up.
- **Proven parts still have bugs.** Layering means one bug alone opens nothing, and pinned digests
  with reviewed updates keep them current.

## Horizons

Ideas that fit this model and come later, each without changing the core:

- **Data snapshots:** `om data snapshot | restore`, encrypted, to an off-host remote — making "the
  host is a cache" fully true.
- **Several hosts, one access file:** a home server and a laptop sharing it, so a device enrolled
  once can reach both.
- **Groups:** grant a service to `family` instead of to each person.
- **A publish door:** a separate door for genuinely public, read-only, secret-free services, which
  never touches the private path.

## How we will know it worked

- From any other machine, a scan of the host finds nothing to talk to.
- Sharing a service with a family member takes under ten minutes and creates no password.
- What runs, who changed it, and who can reach it are each answered by one command:
  `om status`, `om log`, `om access`.
- A lost or stolen host costs an afternoon to replace and leaks nothing.
- `om doctor` proves every promise in this document, every time it runs.
