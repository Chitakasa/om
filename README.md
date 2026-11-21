# ⚡ om — Universal Workspace & GitOps Platform

<div align="center">

[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue?style=for-the-badge&logo=linux)](#-supported-platforms)
[![Python](https://img.shields.io/badge/Python-3.10%2B%20Standard%20Library-green?style=for-the-badge&logo=python)](https://python.org)
[![Runtime](https://img.shields.io/badge/Runtime-Podman%20%7C%20Docker-purple?style=for-the-badge&logo=podman)](https://podman.io)
[![Ingress](https://img.shields.io/badge/Ingress-Caddy%20v2%20(QUIC%2FHTTP3)-black?style=for-the-badge&logo=caddy)](https://caddyserver.com)
[![CI](https://img.shields.io/github/actions/workflow/status/Chitakasa/om/ci.yml?branch=main&style=for-the-badge&label=CI)](https://github.com/Chitakasa/om/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT-amber?style=for-the-badge)](LICENSE)

**Run, publish and GitOps everything you build on your own machine — behind one front door.**

[What is om](#-what-is-om) • [Install](#-install) • [Quickstart](#-quickstart) • [Security](#%EF%B8%8F-security-model) • [Commands](#-command-reference) • [Platforms](#-supported-platforms) • [Docs](#-documentation)

</div>

---

## 💡 What is `om`?

`om` turns any folder or Git repository into a **workspace**: a set of containerized services and projects that get clean URLs, a dashboard, and Git-driven deployment — with no port juggling and no hand-written proxy config.

- **One front door.** Only the edge proxy listens on the network (80/443). Every service is reached through it; nothing else is exposed.
- **Private by default.** Services are visible on this machine (and your devices on your VPN, e.g. Tailscale). Add `--public` to share one with your LAN.
- **No daemon.** The `om` CLI runs and exits; the core is a few small containers. With `om boot enable`, a self-heal check runs every 2 minutes (~1 s CPU) and only acts when something changed. With `om autosync on`, a timer syncs workspaces from git and applies `om.update=auto` image updates.
- **Zero dependencies.** Python 3.10+ standard library and a container engine (Podman or Docker).
- **Built in the open, with AI.** Written by Chitakasa with Claude, and checked by 377 tests (including attack tests), a [threat model](docs/DESIGN.md#threat-model) that states its limits, and `om doctor`. Don't trust the claims: read the code and run the tests. [Who did what](#-authorship).

---

## ✨ Key Features

- 🔒 **Fail-closed networking** — host firewall, separate private/public tiers, an edge proxy no container can reach, and an internal router that only accepts requests signed by the edge. Workspaces cannot reach each other.
- 🧱 **Sandboxed services** — internal networks; outbound only to the hosts a service lists (`om.egress`, with learn and audit modes); a policy gate refuses privileged containers, published ports and the engine socket.
- ✍️ **Signed deploys** — images pinned by digest, only signed commits deploy, every deploy is a numbered generation you can roll back; secrets live age-encrypted in the repo.
- 📱 **Your devices, via your VPN** — any VPN of your own devices (Tailscale, WireGuard, ZeroTier…), found automatically and trusted with one yes; nothing is on the internet.
- 🌐 **One origin per service** — `http://<workspace>.<service>.localhost` on this machine (RFC 6761, no `/etc/hosts`), and a stable port of its own over your VPN and the LAN, so no service can read another through your browser.
- 🎨 **Dashboard** — every service across all workspaces with live state and RAM, a command palette (`Ctrl+K`), and a public view for LAN guests that reveals nothing private.
- 🔄 **GitOps** — `om drift`, `om sync` (pull → reconcile → health-check → automatic rollback), and scheduled auto-sync that quarantines a bad commit instead of redeploying it in a loop.
- ⬆️ **Updates you control** — images pinned by digest; `om update` shows what changed (services, build date, size) and moves all, some (`--image`, `-i`) or none (`om.update=hold`); `om.update=auto` lets the scheduled sync update a service and revert it if its health check fails. The dashboard marks cards with a newer image; `om scan` (trivy/grype) counts known vulnerabilities; `om prune` lists the images left behind.
- 🔔 **Told when it matters** — desktop notifications (and, if you add one, a webhook such as ntfy) for new image updates, auto-updates applied or rolled back, failed scheduled syncs and the core healing itself.
- 🩺 **`om doctor`** — checks the install, the engine and the security perimeter (including live attack probes) and prints the fix for anything wrong.
- 🖥️ **Any OS** — Linux, macOS and Windows; Podman (rootless or rootful, incl. Podman machine) or Docker (incl. Docker Desktop).

---

## 🏗️ Architecture

```text
   This PC / your VPN devices                      LAN / Wi-Fi guests
   localhost, *.localhost, VPN address/name         192.168.x.y
              │                                            │
   ┌──────────┴────────────────────────────────────────────┴──────────┐
   │ HOST FIREWALL (om firewall): inbound default-drop, only 80/443   │
   └──────────┬────────────────────────────────────────────┬──────────┘
              │ :80/:443                                    │ :80/:443
              ▼ → container :80/:443 (private tier)         ▼ → container :8080/:8443 (public tier)
   ┌──────────────────────────────────────────────────────────────────┐
   │ om_caddy — EDGE PROXY             network: om_core_net ONLY       │
   │  private tier: explicit hosts, optional login, all routes        │
   │  public tier:  public routes only, sanitized dashboard           │
   └───────┬───────────────────────┬──────────────────────┬───────────┘
           │ dashboard             │ + secret token        │
           ▼                       ▼                       │
   om_dashboard              ┌───────────────────────────┐ │
   (om_core_net)             │ om_router — INTERNAL ROUTER│◄┘
                             │ on every workspace network │
                             │ no valid token → dropped   │
                             └─────┬─────────────┬────────┘
                                   ▼             ▼
                          <ws1>_net services   <ws2>_net services
```

Workspace containers can reach only their own network and the router — and the router refuses anything not signed by the edge. Details: **[Architecture](docs/ARCHITECTURE.md)**.

---

## 🛡️ Security Model

**Who reaches what**

| From | Gets |
| :--- | :--- |
| The internet | nothing: no port is opened to it |
| This machine | every service (`<ws>.<svc>.localhost`), the dashboard |
| Your devices on your VPN | the private tier — optionally only the devices you list (`om vpn allow`) |
| Other VPN devices | the public tier only (`:8080`, and at the same address when you list yours) |
| Your LAN | public services and the public dashboard only |
| A compromised service | its own folder's network; the internet only to the hosts it lists |

**The checkpoints**

| Layer | Stops |
| :--- | :--- |
| **Host firewall** (`om firewall apply`) — default drop, per-device and per-service address rules ahead of open connections, logs of refusals | Everything else on the machine; removed devices, at once; port scans |
| **Ports exist only where they belong** — LAN and VPN land on different edge ports | Private services being addressable from the LAN or by a forged `Host` |
| **Edge** — explicit host list, `abort` for anything else, content-free logs | DNS rebinding; request content ending up in logs |
| **Router on a socket** — no network listener, edge token required | Any container talking to the router, the dashboard, or another workspace |
| **One internal network per folder**, egress proxy only where a service may go out | A compromised service reaching other services, the LAN or the internet |
| **Policy gate** — no `ports:`, privileged mode, host namespaces, sensitive mounts or foreign networks | Escalation through a compose file |
| **Least privilege** — rootless, `expose:` only, read-only core, scaffolds without capabilities | Escalation from inside a container |
| **Signed deploys + image digests** (`OM_SIGNED`, `.om/lock.json`) | Running code or images you did not approve |

`om doctor` attacks these properties on your install (38 checks). Residual trust, documented rather than
hidden: your VPN decides which devices exist (use Tailnet Lock with Tailscale); each service's own login;
other accounts on the same machine unless you set `om auth`. Why om uses your VPN as the identity layer
instead of building its own: **[ADR 0003](docs/adr/0003-simplify-network-and-identity.md)**. Open items:
**[docs/REMAINING.md](docs/REMAINING.md)**; reporting a vulnerability: **[SECURITY.md](SECURITY.md)**.


---

## 🚀 Install

**Requirements:** Python 3.10+, Podman or Docker (with compose), Git.

**Linux / macOS**
```bash
git clone https://github.com/<you>/om.git ~/.om
~/.om/install.sh
```

**Windows** (PowerShell)
```powershell
git clone https://github.com/<you>/om.git $HOME\.om
powershell -ExecutionPolicy Bypass -File $HOME\.om\install.ps1
```

The installer walks through every one-time step and asks before each: rootless ports 80/443,
signed git commits, which VPNs to trust, starting the core, start at boot, and the host
firewall. Run it as yourself — om never runs as root and asks for sudo only where needed.
Then `om doctor` verifies everything and prints a fix for anything missing.

---

## ⚡ Quickstart

```bash
cd ~/Projects/homelab
om init                       # workspace id = folder name (or: om init <id>)
om add web                    # nginx service → http://homelab.web.localhost
om add api --project          # live-reload Node project (edit server.js, it restarts)
om add search --image docker.io/searxng/searxng:<version> --port 8080 --public   # also on the LAN
om start                      # starts everything (and the core if needed)
om routes                     # every URL for this workspace
```

---

## ⚡ Command Reference

| Command | What it does |
| :--- | :--- |
| **Workspace** | *(run inside a workspace folder)* |
| `om init [id]` | Create a workspace in the current folder |
| `om start [svc] [--build]` / `om stop [svc]` / `om restart [svc] [--build]` | Start / stop / restart services (starts the core if needed); `--build` rebuilds images after Dockerfile changes |
| `om down` | Stop the workspace **and** the core |
| `om add <name> [--project] [--public] [--image I --port P] [--no-web]` | Scaffold a service or live-reload project with routes |
| `om edit <svc> [--scope public\|private] [--port P] [--name/--icon/--desc]` | Change a service's settings and routes in place |
| `om remove <svc> [--data] [-y]` | Stop and remove a service (moved to `.om/trash`, recoverable) |
| `om disable <svc>` · `om enable <svc>` | Stop a service and keep it off (an `.omignore` marker) · undo it |
| `om update [folder] [--dry-run] [--image REF]… [-i]` | Move pinned images to the newest digests, commit the lock, recreate, health-check. `--dry-run` lists what is newer (services, build date, size); `--image` / `-i` move only some. Labels: `om.update=hold\|auto` |
| `om scan` | Count critical/high vulnerabilities in the pinned images (needs trivy or grype installed) |
| `om prune [--yes]` | List (or remove) images no container uses and no workspace lock pins |
| `om notify test` | Send a test message on every notification channel (`OM_NOTIFY`, `OM_NOTIFY_URL`) |
| `om logs <svc> [-f] [-n N]` · `om shell <svc> [cmd…]` · `om dev <project>` | Logs, a shell/command inside, dev mode with live logs |
| `om status` · `om routes` · `om network` | State, URLs, network membership |
| `om network harden` | Make this workspace's network internal (outbound only through `om_egress`, per `om.egress` label) |
| `om egress log [svc] [--apply] [--all] [--since 24h]` | Refused or learned outbound calls per service, with the `om.egress=…` line to allow them (or `--apply` to write it) |
| `om scripts` · `om run <script> [args…]` | List / run `scripts/` (`.sh`, `.py`, `.ps1`) with workspace env |
| Labels `om.mem=256m` · `om.pids=200` · `om.cpus=0.5` | Per-service memory, process and CPU limits, applied at the next `om start` / `om update` |
| `om reload` | Regenerate routes and hot-reload the proxy |
| **GitOps** | |
| `om drift` | Compare with the remote (ahead/behind/dirty) |
| `om secrets init\|set <project>/<name>\|list\|rekey` | Service secrets: age-encrypted in the repo, read-only at `/run/secrets/<name>`; `rekey` after adding a machine |
| `om links` | Cross-workspace links (`om.link` / `om.link.allow`): a private network of exactly two services |
| `om preview <branch>` · `om preview rm <branch>` | Run a branch beside the workspace as a throw-away workspace (own network, data, ports) |
| `--json` on `status`, `routes`, `log`, `doctor`, `list`, `links`, `vpn` | Machine-readable output for scripts, editors and CI |
| `om lock` · `om update` | Pin images to registry digests in `.om/lock.json` · move pins to the newest digests, commit the lock, redeploy |
| `om log` · `om rollback [n]` · `om fsck` | Generations (numbered, signed, hash-chained deploys) · deploy an earlier generation's commit · verify chain, signature and running images |
| `om policy check [--all]` | Check compose files against the policy gate (privileged, host namespaces, `ports:`, sockets, sensitive mounts, extra capabilities, devices) |
| `om sync [--rebase\|--force]` | Pull → reconcile → health-check → roll back on failure (refuses a dirty tree) |
| `om autosync on [--every MIN]` · `off` · `status` | Scheduled sync on this machine; a failing commit is quarantined |
| **Platform** | *(run anywhere)* |
| `om core [start\|stop\|restart [names]\|reload\|update\|heal\|watch\|status]` | Manage the edge proxy, router, egress proxy, engine filter and dashboard. `restart` with names (`om core restart dashboard`) restarts only those; `heal` is what the self-heal timer runs; `watch` (Linux, local engine) restarts a container the moment its process dies unseen |
| `om config [show\|get <KEY>\|set KEY=value\|unset <KEY>] [--reveal] [--json]` | Read and change `om.env` without an editor: every value is checked, the file stays 0600, `OM_NOTIFY_URL` is shown as `***` unless `--reveal` (`OM_VPN` / `OM_VPN_ALLOW` keep `om vpn`) |
| `om doctor` | Diagnose install + security perimeter, with fixes |
| `om exposure [--json]` | Who can reach what: this machine, the VPN's devices, the LAN; per service its tier, address rules (and whether the firewall carries them), own login and outbound access |
| `om vpn [trust\|untrust <iface>\|allow\|disallow <device>\|devices]` | Every VPN on this machine, found automatically; the ones you trust reach the private tier, optionally only the devices you allow |
| `om firewall [show\|apply\|remove\|status\|log]` | Host firewall (nftables / pf / Windows Firewall); `log` shows who was refused and who connected |
| `om auth [add\|remove\|set <user>\|list\|off]` | Logins for the whole private tier (one per person) |
| `om boot [enable\|disable\|status]` | Restart containers at boot and self-heal the core every 2 min |
| `om secrets decrypt <file> [-o out]` · `om secrets migrate <file> <project>/<name>` | Read a file from om's old built-in secret format · move it to age (`--allow-unauthenticated` for an old om-v1 file) |
| `om list [--prune]` · `om ports` | Registered workspaces · host port bindings (and leaks) |
| `om docs [name] [--path]` | List the guides or read one in the terminal (`om docs guide`) |
| `om completion bash\|zsh\|fish` · `om version` · `om uninstall [--purge]` | Shell completion, version, removal |

---

## 🖥️ Supported Platforms

| | Podman | Docker |
| :--- | :--- | :--- |
| **Linux** | ✅ rootless — verified end-to-end · 🧪 rootful | 🧪 rootful & rootless |
| **macOS** | 🧪 Podman machine | 🧪 Docker Desktop |
| **Windows** | 🧪 Podman Desktop | 🧪 Docker Desktop |

✅ verified live (full probe suite) · 🧪 designed for, not yet verified on a real machine. The CI workflow
runs the unit tests and checks the generated firewall with each OS's own parser on Linux, macOS and
Windows — run `om doctor` and please report results.

Linux only by design: `om core watch` (instant restart via pidfd), connection logging and
`om firewall log` (macOS and Windows log refusals only), and the firewall's forward path for rootful
engines. VPN device discovery is complete for mesh VPNs that route each device (Tailscale, Headscale on
Linux) and partial elsewhere (see docs/REMAINING.md).

- VPN discovery and names are verified on Linux; the macOS (`ifconfig`, `scutil`) and Windows (`Get-NetAdapter`) paths are unit-tested only. Per-service port ranges are verified with rootless Podman; on Docker Desktop and Podman machine they are untested.
- Linux rootless engines must be allowed to bind 80/443 (`net.ipv4.ip_unprivileged_port_start=80`); the installer and `om doctor` handle it.
- `*.localhost` names resolve natively in all major browsers; on some OSes CLI tools need `curl --resolve` (see `om doctor`).
- Several people: share a workspace through git (each runs om on their machine), give each person a login with `om auth add` (`om doctor` fails while another account can log in here and the private tier has no login; list accounts that are yours in `OM_TRUSTED_USERS`), and let a second OS user on the same machine use other front-door ports (`OM_HTTP_PORT` / `OM_HTTPS_PORT` in `om.env`).
- A VPN is optional: any VPN of your own devices works (Tailscale, Headscale, NetBird, WireGuard, ZeroTier…); om finds it and `om vpn trust <iface>` lets it in. Without one, the private tier is this machine only. Machine settings live in `~/.config/om/om.env` (`auto` / `off` / value); generated state in `~/.local/state/om/`, so `~/.om` is only the program.

---

## 📊 Resource Use

Measured on Arch Linux, rootless Podman (idle, anonymous memory — what the dashboard's *Core RAM* tile shows; the engine's own figure adds up to ~60 MB of shared file cache that varies with recreates):

| Container | RAM | Limit |
| :--- | :--- | :--- |
| `om_caddy` (edge) | ~21 MB | 256 MB |
| `om_sockguard` (engine filter) | ~19 MB | 128 MB |
| `om_dashboard` | ~18 MB | 128 MB |
| `om_router` | ~13 MB | 128 MB |
| `om_egress` (Squid) | ~9 MB | 128 MB |
| **Core** | **~80 MB** | |
| `om` CLI | 0 MB (runs and exits) | |

---

## 📚 Documentation

- 🛠️ **[Guide](docs/GUIDE.md)** — install, workspaces, services, deploys, egress, secrets, devices and sharing, debugging (`om docs guide`).
- 📄 **[Architecture](docs/ARCHITECTURE.md)** — tiers, router, outbound access, firewall, hardening, verification (`om docs architecture`).
- 🧭 **[Design](docs/DESIGN.md)** — why om is built this way, its laws, risks and limits (`om docs design`).
- 🗂️ **[Decisions](docs/adr/)** — ADR 0002 (outbound proxy), ADR 0003 (your VPN as the boundary), ADR 0004 (one origin per service).
- 📝 **[Changelog](CHANGELOG.md)**

**Development:** `cd tests && python -m unittest discover -s . -p "test_*.py"` (no container engine needed); `ruff check` for the lint rules in `pyproject.toml`. CI runs the lint and the suite on Linux, macOS and Windows; `tests/test_docs_match_code.py` fails when these docs and the code disagree (commands, settings, doctor checks, dashboard routes, modules).

---

## 🤝 Authorship

om is built by **Chitakasa** together with AI assistants (Claude, and another AI in earlier versions). The split:

- **Chitakasa:** the idea and the requirements (a private-by-default home server that one person can run and trust), every design decision (VPN as the boundary, per-service and per-device rules, what to harden and in what order), the review of each change, running it on a real machine, and the final say on what was merged.
- **AI assistants:** most of the code, tests and docs, written to that direction.

The git history shows it: commits with a `Co-Authored-By: Claude` line were written with Claude; the tests (`tests/`) are what keep both honest.

---

## 📜 License

[MIT](LICENSE).
