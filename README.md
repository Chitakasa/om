# ⚡ om — self-host anything, privately and safely

<div align="center">

[![Platform](https://img.shields.io/badge/Platform-Linux%20verified%20%7C%20macOS%20%26%20Windows%20untested-blue?style=for-the-badge&logo=linux)](#%EF%B8%8F-supported-platforms)
[![Go](https://img.shields.io/badge/Go-Standard%20Library%20Only-00ADD8?style=for-the-badge&logo=go)](https://go.dev)
[![Runtime](https://img.shields.io/badge/Runtime-Podman-purple?style=for-the-badge&logo=podman)](https://podman.io)
[![Ingress](https://img.shields.io/badge/Ingress-Caddy%20v2%20(QUIC%2FHTTP3)-black?style=for-the-badge&logo=caddy)](https://caddyserver.com)
[![CI](https://img.shields.io/github/actions/workflow/status/Chitakasa/om/ci.yml?branch=main&style=for-the-badge&label=CI)](https://github.com/Chitakasa/om/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT-amber?style=for-the-badge)](LICENSE)

**Self-host anything, privately and safely: clean URLs, sandboxed services, signed deploys and rollbacks on Podman. No daemon, one static binary.**

[What is om](#-what-is-om) • [Install](#-install) • [Quickstart](#-quickstart) • [Security](#%EF%B8%8F-security-at-a-glance) • [Platforms](#%EF%B8%8F-supported-platforms) • [Docs](#-documentation)

</div>

> om is written in Go. The original Python implementation, which the Go program's tests were recorded from, lives in its own repository: [Chitakasa/om-python](https://github.com/Chitakasa/om-python).

---

## 💡 What is `om`?

Self-hosting is easy to start and hard to trust. A few containers and a reverse proxy run in an afternoon; then come
the questions. Who can reach this? What exactly is running, and who changed it? What can a compromised container
reach?

`om` turns a folder of compose files into a **workspace** and generates everything around it (addresses, proxy,
networks, firewall rules, outbound allow-lists, a dashboard) from labels in the compose files you already write. Then
`om doctor` attacks the result, live, to prove it. It is one static Go binary with no dependencies and no daemon, and it
runs rootless on Podman.

**What is different**

- **Keys, not open ports.** Nothing is on the internet. Services answer on this machine and on a VPN of your own devices (om finds the VPN by itself and trusts none without your yes); `--public` shares one service with your LAN, and only that one.
- **The compose file is the policy.** Who may reach a service, which hosts it may call, how much memory it gets, whether anything is logged: each is a label (`om.net.allow`, `om.egress`, `om.mem`, `om.log=off`, and over thirty more), and nothing is written by hand for the proxy, the networks or the firewall. [Every label](docs/LABELS.md).
- **Fail closed, and proven.** Every compose folder gets its own internal network with no route out. The edge reaches a service only through a router that has no network listener and checks a secret token. Privileged containers, published ports and the engine socket are refused at deploy. `om doctor` probes each of these from inside.
- **Every deploy is history.** A signed commit plus digest-pinned images is a numbered, hash-chained generation you can roll back; a re-pushed image tag changes nothing; updates are commits you review, unless a service opts in to automatic ones that revert on a failed health check.
- **The host is a cache.** Everything om generates is disposable. A new machine needs your repositories, one key and your data, then `om start`.

**How far the customization goes.** Anything that runs from a compose file runs in om: any image, any build, any number
of services. On top of that, each service can carry its own Caddy rules (`om.caddy`), its own outbound allow-list,
address rules for its ports, limits, raw TCP ports, links to services in other workspaces, a throw-away copy of any git
branch (`om preview`), and your own scripts. It is not unlimited, and that is on purpose: privileged containers,
published host ports and the engine socket are laws, not options.

**What om is not:** Kubernetes (it is one machine), a hosting platform, a VPN or an identity provider. It orchestrates the
engine and Caddy and uses your VPN. The [honest limits](docs/DESIGN.md#honest-limits) are written down.

**Built in the open, with AI.** Written by Chitakasa with Claude, and checked by hundreds of tests (attack tests included),
a [threat model](docs/DESIGN.md#threat-model) that states its limits, and `om doctor`. Don't trust the claims: read the code
and run the tests. [Who did what](#-authorship).

---

## 🚀 Install

**Requirements:** Podman (with a compose provider: docker-compose v2 or podman-compose), Git, and either Go (the installer builds om) or internet access (it downloads the release binary and checks its SHA-256).

**Podman only, no Docker needed.** om does not support Docker: rootful Docker is refused, and rootless Docker could not publish the same port on loopback and on the LAN address ([why](docs/DESIGN.md#why-podman-and-not-docker)). The standalone `docker-compose` binary is fine as the compose provider, because it only talks to Podman's socket.

```bash
git clone https://github.com/Chitakasa/om.git ~/.om
~/.om/install.sh            # Windows: powershell -ExecutionPolicy Bypass -File $HOME\.om\install.ps1
om doctor                   # in a new terminal: no FAIL means you are ready
```

The installer asks before each step (rootless ports 80/443, signed git commits, which VPNs to trust, starting the
core, start at boot, the host firewall) and never runs om as root. Re-running it is safe.

---

## ⚡ Quickstart

```bash
mkdir ~/apps && cd ~/apps
om init                       # this folder becomes a workspace
om add web                    # a hardened nginx → http://apps.web.localhost
om start                      # starts it (and the core, the first time)
om routes                     # prints every address
```

That is the whole loop. Or run `om add` with no name and answer a few questions: it asks what you are adding, shows what it will write, and tells you which label each choice sets. Already have a compose file or a `docker run` command? `om add --from <folder or file>` or `om add --run '…'` brings it in, editing only what om needs and proving with the compose engine that nothing else changed; `om check` looks without touching anything, and `om edit <service>` asks instead of making you remember labels. The ten-minute walkthrough, with what each step does, is **[docs/START.md](docs/START.md)**.

| Everyday | |
| :--- | :--- |
| `om status` | What runs and where; ends with what to do next if something is missing |
| `om logs <service> -f` | Follow a service's output |
| `om stop <service>` · `om restart <service>` | Stop or restart one service |
| `om edit <service> --scope public` | Share one with your local network |
| `om doctor` | Check everything, with a fix for each problem |
| `om log` · `om rollback` | What was deployed, and going back |

Every command, with every argument, is in **[docs/COMMANDS.md](docs/COMMANDS.md)** (`om --help` groups them).

---

## 🛡️ Security at a glance

**Who reaches what**

| From | Gets |
| :--- | :--- |
| The internet | nothing: no port is opened to it |
| This machine | every service (`<ws>.<svc>.localhost`), the dashboard |
| Your devices on your VPN | the private tier — optionally only the devices you list (`om vpn allow`) |
| Other VPN devices | the public tier only (`:8080`, and at the same address when you list yours) |
| Your LAN | public services and the public dashboard only |
| A compromised service | its own folder's network; the internet only to the hosts it lists |

`om doctor` attacks these properties on your install (37 checks). The checkpoints behind them, and what each stops,
are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#the-checkpoints-at-a-glance); the limits, stated plainly, in
[docs/DESIGN.md](docs/DESIGN.md); open items in [docs/REMAINING.md](docs/REMAINING.md); reporting a vulnerability in
**[SECURITY.md](SECURITY.md)**.

---

## 🖥️ Supported Platforms

| | Podman |
| :--- | :--- |
| **Linux** | ✅ rootless — verified end-to-end · ❌ rootful (om stops: see below) |
| **macOS** | 🧪 Podman machine |
| **Windows** | 🧪 Podman Desktop |

✅ verified live (full probe suite) · 🧪 designed for, not yet verified on a real machine · ❌ not supported on Linux: a rootful engine (it runs as root: om's core containers drop every capability and could not write your state folders; `om core start` refuses it and `om doctor` fails it). Use rootless Podman. **Docker is not supported:** om runs on Podman only.

Using om on a system marked 🧪? A short [platform report](https://github.com/Chitakasa/om/issues/new?template=platform_report.yml) (what you ran and the output of `om doctor`) is the most useful thing you can send, whether it works or not.
runs the unit tests and checks the generated firewall with each OS's own parser on Linux, macOS and
Windows — run `om doctor` and please report results.

Platform-specific notes (Linux-only features, VPN discovery, ports) are in [docs/GUIDE.md](docs/GUIDE.md#platform-notes).

---

## 📚 Documentation

- 🚀 **[Start here](docs/START.md)**: install, your first service and a rollback, in ten minutes (`om docs start`).
- 🛠️ **[Guide](docs/GUIDE.md)**: every task, from secrets and sharing to updates, egress and previews (`om docs guide`).
- 📖 **Reference, generated from the code so it is never stale:** [Commands](docs/COMMANDS.md), [Settings](docs/SETTINGS.md), [Labels](docs/LABELS.md), [Doctor](docs/DOCTOR.md). Plus the [Glossary](docs/GLOSSARY.md) and [Troubleshooting](docs/TROUBLESHOOTING.md).
- 📄 **How it works:** [Architecture](docs/ARCHITECTURE.md) (tiers, router, outbound access, firewall, hardening), [Design](docs/DESIGN.md) (why, its laws, risks and limits), [Decisions](docs/adr/) (ADRs).
- 📝 **Project:** [Changelog](CHANGELOG.md), [Remaining](docs/REMAINING.md), [Contributing](CONTRIBUTING.md), [Code of conduct](CODE_OF_CONDUCT.md), [Security](SECURITY.md).

Read any of them in the terminal with `om docs <name>`. **Development:** `go test ./...` (no container engine needed), `gofmt -l .` and `go vet ./...`. CI runs them on Linux, macOS and Windows; `internal/repocheck` fails when these docs and the code disagree.

---

## 🤝 Authorship

om is built by **Chitakasa** together with AI assistants (Claude, and another AI in earlier versions). The split:

- **Chitakasa:** the idea and the requirements (a private-by-default home server that one person can run and trust), every design decision (VPN as the boundary, per-service and per-device rules, what to harden and in what order), the review of each change, running it on a real machine, and the final say on what was merged.
- **AI assistants:** most of the code, tests and docs, written to that direction.

The git history shows it: commits with a `Co-Authored-By: Claude` line were written with Claude; the tests (`go test ./...`) are what keep both honest.

---

## 📜 License

[MIT](LICENSE).
