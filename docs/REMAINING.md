# om — Remaining before a public release

State on 2026-10-22: om 1.0.0, `main` at `1041c91`. On the author's machine (Arch Linux, rootless
Podman 5 with pasta, nftables, systemd, Tailscale) `om doctor` passes 31 of 32 checks and 161 tests
pass. Everything below is either unverified elsewhere, an open decision, or a known limit that users
must be told about. Items are ordered by how much they block a release.

---

## 1. Release blockers

1. **CI has never run.** The repository has no remote, so `.github/workflows/ci.yml` (3 OS ×
   Python 3.10/3.12/3.13, `caddy-config`, `firewall-syntax`) has never executed. Push to a remote
   and get it green before claiming Linux/macOS/Windows support.
2. **No run on a real macOS or Windows host.** Unit tests need no engine, so these are unverified
   with Docker Desktop and Podman machine: the router's unix socket shared between two containers
   inside the VM, per-folder networks, `logging: driver: none`, whether pf / Windows Firewall see
   the *real* source address at the engine's port forwarder (address rules depend on it), and VPN
   device discovery (the route shapes Tailscale uses there). Minimum: `om core start`, a sample
   workspace with `om start`, `om doctor` on each.
3. **Linux beyond Arch + rootless Podman is unverified.**
   - Rootful Docker and rootful Podman: the forward-chain address rules (DNAT path) have only passed
     `nft -c`; Docker's own chains (`DOCKER-USER`), its userland proxy, and the input default-drop
     need a live test.
   - SELinux (Fedora/RHEL): the named volume `om_router_sock` is shared by two containers with
     different MCS labels; the socket may be denied. AppArmor (Ubuntu) likewise.
   - Coexistence with firewalld / ufw; iptables-only systems (no `nft`).
   - Non-systemd distros: `om boot` timers, `om core heal`, `om firewall log` (reads the journal) and
     the OOM-score lookup (`systemd-run`) have no equivalent there.
4. **Personal data in tracked files.** Replace with documentation addresses (RFC 5737, `100.64.0.x`)
   and neutral names before publishing:
   - real tailnet/LAN addresses `100.78.88.56`, `100.107.6.118`, `100.122.24.92`, `100.117.253.5`,
     `192.168.1.5` in `tests/test_core.py`, `tests/test_routes.py`, `tests/fw_render.py`,
     `tests/test_cli.py`, `tests/test_dashboard.py`, `.github/workflows/ci.yml`;
   - host name `archlinux` in `docs/GUIDE.md`, `tests/test_dashboard.py`, `CHANGELOG.md`.
5. **Git history carries a personal e-mail** (all 89 commits). Decide before the first push: publish
   as is, or rewrite authorship to a no-reply address. A rewrite is only possible before anyone clones.
6. **The egress proxy's image channel:** `docker.io/ubuntu/squid:6.6-24.04_beta` (Squid 6.13 inside,
   newest build pinned). Ubuntu publishes Squid only as "beta" and "edge" — no stable channel — so for
   a release decide: keep Ubuntu's 24.04 LTS beta, or build om's own Squid image from a pinned Alpine
   (like `om-tools`), maintained by Alpine's security updates.
7. **Version and upgrade notes.** Still `1.0.0` after changes that need action on upgrade. Bump
   (e.g. 2.0.0) and document the steps:
   - `om core restart` — router on a unix socket, VPN on edge :81/:444, filtered logs;
   - `om start` in every workspace — per-folder networks recreate containers;
   - `om firewall apply` — logging, the forward chain;
   - rotate the edge token (`rm <state>/data/edge_token && om core restart`): error logs of earlier
     versions could contain it.

## 2. Security — open decisions

1. **Local accounts.** The private tier's only identity is optional HTTP Basic auth, and some
   browsers never show its prompt (Zen, including new-tab extension pages). Options: keep Basic auth
   and document the browser limits; add a minimal session login (conflicts with ADR 0003: om builds
   no login system); or rely on OS-user separation (one om per user, `OM_HTTP_PORT`).
2. **Accounts in `wheel` / `adm` / `systemd-journal` read every journal.** om's own logs are now
   content-free, but a service's own output is not unless it carries `om.log=off`. Document it.
3. **The LAN tier is plain HTTP, and LAN source addresses can be borrowed**, so `om.net` rules on LAN
   addresses are weak. Options: HTTPS on public ports with the local CA, LAN tier off by default, or
   documentation only.
4. **The edge cannot see client addresses** (rootless port forwarding hands it one internal address):
   no per-client rate limiting or Basic-auth brute-force throttling at the edge; only the firewall
   sees sources. Investigate source-preserving forwarding, or per-source rate limits in the firewall.
5. **`om_egress` (Squid) is the one hub with a reachable parser** — for every service allowed out.
   Keep it pinned and updated; consider one egress proxy per workspace.
6. **Legacy secrets reader** (`om-v1`/`om-v2`, a hand-rolled keystream) is still there for old
   files. Set a deprecation date, then remove it.
7. **Supply chain:** images are pinned by digest, but upstream signatures (cosign/sigstore) are not
   verified and there is no SBOM; `om-tools` is built locally from a pinned Alpine.
8. **Signed deploys trust a workspace's `.om/allowed_signers` on first use** (TOFU). Say so plainly.
9. **Old logs:** entries written before the log filters (request URLs, a service's own output, the
   edge token in error logs) stay in the system journal until it rotates.

## 3. Known limits to document for users

1. **VPN device discovery** is generic in method (kernel routes + the VPN's own DNS, no product
   tool), not in coverage:

   | VPN | Online devices | Offline devices |
   |---|---|---|
   | Tailscale / Headscale on Linux | yes (one route each) | yes |
   | Tailscale on macOS / Windows | unverified (likely one route for the whole range) | unverified |
   | NetBird | no (routes its whole /16) | no |
   | Plain WireGuard / OpenVPN | only if its DNS has reverse names | same |
   | ZeroTier | recently active only (neighbour cache) | no |
   | Nebula | no (no DNS by default) | no |
   | Tailscale userspace-networking mode | not detected as a VPN (no interface) | — |

2. **Platform matrix.** Linux only: `om core watch`; connection logging and reading it in
   `om firewall log` (macOS logs refusals to `pflog0`, Windows to `pfirewall.log`); the OOM-score fix
   and the forward chain (only needed on Linux). On macOS the pf anchor needs a manual `pf.conf` entry
   to survive reboots.
3. **IPv6:** the VPN and LAN tiers bind IPv4 addresses only.
4. **`om logs` shows nothing for `om.log=off` services** (by design).
5. **A dashboard tab fills the edge access log** (about 1,000 entries a day per open tab, from its
   polling). Consider `log_skip` for the dashboard's own API calls.

## 4. Code health

1. `bin/om` is still about 2,600 lines; route generation (`lib/gitops/routes.py`) and script
   discovery (`lib/gitops/scripts.py`) are split out, the rest is not.
2. Two lint findings predate this work: unused variables in `cmd_core` (restart fallback) and `cmd_dev`.
3. No integration test with a real engine in CI. GitHub's Linux runners have Podman: add a job that
   runs `om core start`, `om start` on a sample workspace and `om doctor`.
4. Compose parsing falls back to regex when the engine is unavailable.
5. The dashboard front end (`core/dashboard/app/index.html`, ~1,900 lines) was not reviewed in this
   hardening pass. Unlabelled services now get a generic card (the product preset table is gone).
6. The installers (`install.sh`, `install.ps1`) were not re-checked after these changes and don't
   mention `om vpn allow` or `om firewall log`.

## 5. Open-source readiness

1. **License:** MIT, copyright "Chitakasa" — confirm the holder's name.
2. **Missing project files:** `SECURITY.md` (how to report vulnerabilities, supported versions),
   `CONTRIBUTING.md` (tests, the cross-platform rules now in `CLAUDE.md`), a code of conduct, issue and
   pull-request templates.
3. **`CLAUDE.md`** is a guide for AI coding agents: keep it for contributors who use one, or rename it.
4. **Distribution and updates:** today it is `git clone` + `install.sh`. Consider packages (AUR,
   Homebrew, Scoop/winget), signed release tags, a documented upgrade path or `om self-update`.
5. **README:** put the platform support matrix and a one-screen threat model up front.
