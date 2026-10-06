# ⚡ om — Universal Workspace & GitOps Platform

<div align="center">

[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue?style=for-the-badge&logo=linux)](#-supported-platforms)
[![Python](https://img.shields.io/badge/Python-3.10%2B%20Standard%20Library-green?style=for-the-badge&logo=python)](https://python.org)
[![Runtime](https://img.shields.io/badge/Runtime-Podman%20%7C%20Docker-purple?style=for-the-badge&logo=podman)](https://podman.io)
[![Ingress](https://img.shields.io/badge/Ingress-Caddy%20v2%20(QUIC%2FHTTP3)-black?style=for-the-badge&logo=caddy)](https://caddyserver.com)
[![License](https://img.shields.io/badge/License-MIT-amber?style=for-the-badge)](LICENSE)

**Run, publish and GitOps everything you build on your own machine — behind one front door.**

[What is om](#-what-is-om) • [Install](#-install) • [Quickstart](#-quickstart) • [Security](#%EF%B8%8F-security-model) • [Commands](#-command-reference) • [Platforms](#-supported-platforms) • [Docs](#-documentation)

</div>

---

## 💡 What is `om`?

`om` turns any folder or Git repository into a **workspace**: a set of containerized services and projects that get clean URLs, a dashboard, and Git-driven deployment — with no port juggling and no hand-written proxy config.

- **One front door.** Only the edge proxy listens on the network (80/443). Every service is reached through it; nothing else is exposed.
- **Private by default.** Services are visible on this machine (and your Tailscale devices). Add `--public` to share one with your LAN.
- **No daemon.** The `om` CLI runs and exits; the core is a few small containers. With `om boot enable`, a self-heal check runs every 2 minutes (~1 s CPU) and only acts when something changed.
- **Zero dependencies.** Python 3.10+ standard library and a container engine (Podman or Docker).

---

## ✨ Key Features

- 🔒 **Fail-closed networking** — host firewall (only 80/443), separate private/public tiers, an edge proxy no container can reach, and an internal router that only accepts requests signed by the edge. Workspaces cannot reach each other.
- 🌐 **Clean URLs** — `http://<workspace>.<service>.localhost` (RFC 6761, no `/etc/hosts`), `/<service>/` subpaths over Tailscale and LAN, HTTPS with a local CA.
- 🎨 **Dashboard** — every service across all workspaces with live state and RAM, a command palette (`Ctrl+K`), and a public view for LAN guests that reveals nothing private.
- 🔄 **GitOps** — `om drift`, `om sync` (pull → reconcile → health-check → automatic rollback), and scheduled auto-sync that quarantines a bad commit instead of redeploying it in a loop.
- 🩺 **`om doctor`** — checks the install, the engine and the security perimeter (including live attack probes) and prints the fix for anything wrong.
- 🖥️ **Any OS** — Linux, macOS and Windows; Podman (rootless or rootful, incl. Podman machine) or Docker (incl. Docker Desktop).

---

## 🏗️ Architecture

```text
   This PC / Tailscale devices                     LAN / Wi-Fi guests
   localhost, *.localhost, 100.x.y.z               192.168.x.y
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
           │ dashboard / portainer │ + secret token        │
           ▼                       ▼                       │
   om_dashboard, portainer   ┌───────────────────────────┐ │
   (om_core_net)             │ om_router — INTERNAL ROUTER│◄┘
                             │ on every workspace network │
                             │ no valid token → dropped   │
                             └─────┬─────────────┬────────┘
                                   ▼             ▼
                          <ws1>_net services   <ws2>_net services
```

Workspace containers can reach only their own network and the router — and the router refuses anything not signed by the edge. Details: **[Network Architecture](docs/NETWORK_ARCHITECTURE.md)**.

---

## 🛡️ Security Model

| Layer | Stops |
| :--- | :--- |
| **Host firewall** (`om firewall apply`) | Anything else listening on the machine; a container that accidentally publishes a port |
| **Tier separation** — LAN traffic lands on a different proxy port | LAN guests reaching private routes, even with forged `Host` headers |
| **Route absence** — the public tier has no private routes | Private services being addressable from the LAN at all |
| **Explicit hosts + `:80 { abort }`** | DNS-rebinding attacks from malicious websites |
| **Edge on the core network only + token-gated router** | A compromised container reaching the private tier, Portainer, or another workspace |
| **Dashboard checks** — host allowlist, CSRF, input validation, public sanitization | Data leaks and request forgery even if a proxy rule were wrong |
| **Container hardening** — `expose:` only, minimal mounts, no-new-privileges, read-only core | Escalation and host-file access from a compromised service |
| **Optional login** (`om auth add <user>`, one per person) | Other local users/processes on a shared machine |

Residual trust (documented, not hidden): Portainer, if you turn it on (`OM_PORTAINER=on`), talks to the container engine socket (the dashboard gets a read-only filtered copy); each service's own login; your Tailscale account.

> 📄 Case study: **[Solving the Rootless Container Ingress Flaw](docs/architecture-case-study/ENGINEERING_CASE_STUDY.md)**

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

Then, once:
```bash
om core start        # edge proxy, router, dashboard  → http://localhost/
om doctor            # verifies everything and prints fixes
om firewall apply    # recommended: only 80/443 reachable from the network
om boot enable       # containers come back after a reboot + self-heal (new Wi-Fi/IP, Tailscale, crashes)
```

---

## ⚡ Quickstart

```bash
cd ~/Projects/homelab
om init                       # workspace id = folder name (or: om init <id>)
om add web                    # nginx service → http://homelab.web.localhost
om add api --project          # live-reload Node project (edit server.js, it restarts)
om add search --image docker.io/searxng/searxng --port 8080 --public   # also on the LAN
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
| `om update [svc]` | Pull newer images, recreate, health-check |
| `om logs <svc> [-f] [-n N]` · `om shell <svc> [cmd…]` · `om dev <project>` | Logs, a shell/command inside, dev mode with live logs |
| `om status` · `om routes` · `om network` | State, URLs, network membership |
| `om network harden` | Make this workspace's network internal (outbound only through `om_egress`, per `om.egress` label) |
| `om egress log [--all] [--since 24h]` | Refused outbound calls per service, with the `om.egress=…` line that would allow them |
| `om scripts` · `om run <script> [args…]` | List / run `scripts/` (`.sh`, `.py`, `.ps1`) with workspace env |
| `om reload` | Regenerate routes and hot-reload the proxy |
| **GitOps** | |
| `om drift` | Compare with the remote (ahead/behind/dirty) |
| `om policy check [--all]` | Check compose files against the policy gate (privileged, host namespaces, `ports:`, sockets, sensitive mounts, extra capabilities, devices) |
| `om sync [--rebase\|--force]` | Pull → reconcile → health-check → roll back on failure (refuses a dirty tree) |
| `om autosync on [--every MIN]` · `off` · `status` | Scheduled sync on this machine; a failing commit is quarantined |
| **Platform** | *(run anywhere)* |
| `om core [start\|stop\|restart\|reload\|update\|status]` | Manage the edge proxy, router, dashboard, Portainer |
| `om doctor` | Diagnose install + security perimeter, with fixes |
| `om firewall [show\|apply\|remove\|status]` | Host firewall (nftables / pf / Windows Firewall) |
| `om auth [add\|remove\|set <user>\|list\|off]` | Logins for the whole private tier (one per person) |
| `om boot [enable\|disable\|status]` | Restart containers at boot and self-heal the core every 2 min |
| `om secrets encrypt\|decrypt <file> [-o out]` | File encryption (SOPS if installed, else built-in authenticated vault) |
| `om list [--prune]` · `om ports` | Registered workspaces · host port bindings (and leaks) |
| `om docs [name] [--path]` | List the guides or read one in the terminal (`om docs developer`) |
| `om completion bash\|zsh\|fish` · `om version` · `om uninstall [--purge]` | Shell completion, version, removal |

---

## 🖥️ Supported Platforms

| | Podman | Docker |
| :--- | :--- | :--- |
| **Linux** | ✅ rootless — verified end-to-end · 🧪 rootful | 🧪 rootful & rootless |
| **macOS** | 🧪 Podman machine | 🧪 Docker Desktop |
| **Windows** | 🧪 Podman Desktop | 🧪 Docker Desktop |

✅ verified live (full probe suite) · 🧪 designed for and covered by the cross-platform unit tests in CI, not yet verified on a real machine — run `om doctor` and please report results.

- Linux rootless engines must be allowed to bind 80/443 (`net.ipv4.ip_unprivileged_port_start=80`); the installer and `om doctor` handle it.
- `*.localhost` names resolve natively in all major browsers; on some OSes CLI tools need `curl --resolve` (see `om doctor`).
- Several people: share a workspace through git (each runs om on their machine), give each person a login with `om auth add`, and let a second OS user on the same machine use other front-door ports (`OM_HTTP_PORT` / `OM_HTTPS_PORT` in `om.env`).
- Tailscale is optional: detected automatically, ignored if absent. Machine settings live in `~/.config/om/om.env` (`auto` / `off` / value); generated state in `~/.local/state/om/`, so `~/.om` is only the program.

---

## 📊 Resource Use

Measured on Arch Linux, rootless Podman (idle):

| Container | RAM |
| :--- | :--- |
| `om_caddy` (edge) | ~21 MB |
| `om_router` | ~10 MB |
| `om_dashboard` | ~9 MB |
| `portainer` (optional UI, off by default: `OM_PORTAINER=on`) | ~27 MB |
| `om` CLI | 0 MB (runs and exits) |

---

## 📚 Documentation

- 📄 **[Network Architecture](docs/NETWORK_ARCHITECTURE.md)** — tiers, router, firewall, hardening, verification suite.
- 🛠️ **[Developer Guide](docs/DEVELOPER_GUIDE.md)** — create containers, when to rebuild an image, debugging a workspace.
- 📘 **[Project Guide](docs/PROJECT_GUIDE.md)** — workspaces, services, GitOps, scripts, data.
- 🛡️ **[Engineering Case Study](docs/architecture-case-study/ENGINEERING_CASE_STUDY.md)** — threat model and the audit that shaped 1.0.
- 📝 **[Changelog](CHANGELOG.md)**

**Development:** `cd tests && python -m unittest discover -s . -p "test_*.py"` (no container engine needed). CI runs the suite on Linux, macOS and Windows.

---

## 📜 License

[MIT](LICENSE).
