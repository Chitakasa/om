# om — Remaining before a public release

State on 2026-11-21: om 1.0.0, the repository is public but no release is tagged. On the author's machine (Arch Linux, rootless Podman 5 with pasta,
nftables, systemd, Tailscale) `om doctor` runs 38 checks with no failure and one warning (a service in permanent
egress audit mode), all 377 tests pass (also under the strict-encoding run) and `ruff check` is clean. Everything below is either unverified elsewhere, an open decision, or a known limit that users
must be told about. Items are ordered by how much they block a release.

---

## 1. Release blockers

1. ~~CI has never run~~ — done 2026-11-21: `.github/workflows/ci.yml` (lint, 3 OS × Python 3.10/3.12/3.13,
   `caddy-config`, `firewall-syntax`, and the Podman `integration` job with `om doctor`) is green on `main`.
   Windows needed real fixes (UTF-8 console output) plus POSIX-only tests skipped there. One Windows
   dashboard test (`test_public_scope_restrictions`) was seen failing once on a socket abort and passed on rerun:
   if it recurs, make its socket handling retry.
2. **No run on a real macOS or Windows host.** Unit tests need no engine, so these are unverified
   with Docker Desktop and Podman machine: the router's unix socket shared between two containers
   inside the VM, per-folder networks, `logging: driver: none`, whether pf / Windows Firewall see
   the *real* source address at the engine's port forwarder (address rules depend on it), and VPN
   device discovery (the route shapes Tailscale uses there). Minimum: `om core start`, a sample
   workspace with `om start`, `om doctor` on each. The full steps are in "Live test plan" below.
3. **Linux beyond Arch + rootless Podman is unverified.**
   - Rootful Docker and rootful Podman: the forward-chain address rules (DNAT path) have only passed
     `nft -c`; Docker's own chains (`DOCKER-USER`), its userland proxy, and the input default-drop
     need a live test. The VPN fallback (`chain vpn_public`, a `dnat` before the engine's) then hands
     8080 to the engine's userland proxy; without it (`userland-proxy: false`) it finds no listener.
   - SELinux (Fedora/RHEL): the named volume `om_router_sock` is shared by two containers with
     different MCS labels; the socket may be denied. AppArmor (Ubuntu) likewise.
   - Coexistence with firewalld / ufw; iptables-only systems (no `nft`).
   - Non-systemd distros: `om boot` timers, `om core heal`, `om firewall log` (reads the journal) and
     the OOM-score lookup (`systemd-run`) have no equivalent there.
4. ~~Personal data in tracked files~~ — done: real addresses and names replaced by example
   values (`100.64.0.x`, `192.168.1.10`, `myhost`). Re-check before each release:
   `git grep -nE '<your real addresses or host name>'`.
5. ~~Git history carries personal data~~ — audited 2026-11-21, accepted: the repository is already public.
   History has the author e-mail on all 172 commits (none in file contents) and a `/home/cyber/` path in two
   old doc commits; addresses and tailnet names in history are placeholders. A regex scan of every added line
   (cloud and chat tokens, private-key headers, age keys, JWTs, `password=` forms) and of every file name ever
   tracked found no secrets; the 64-hex strings are image digests and test vectors. New commits should use the
   GitHub no-reply address. `gitleaks git` over all 178 commits (2026-11-21) found no leaks.
6. ~~The egress proxy's image channel~~ — done: `core/egress/Containerfile` builds Squid 7.6 on the
   pinned Alpine 3.24 (`squid=7.6-r0`), like `om-tools`; `om core start` builds it, the tag is a hash of
   the file. Bump the package pin when Alpine publishes a security update.
7. **Version stays 1.0.0 until the first public release.** At release, fold `CHANGELOG.md`'s
   "Unreleased" into the 1.0.0 entry and date it; upgrade notes start with the first published version.
8. **Multi-machine sync has never run end to end.** `om sync` / `om autosync` (pull, redeploy, 60 s route
   probe, rollback), cloning a workspace on a second machine with `om start`, adding its key to
   `.om/allowed_signers`, and `om secrets init` + `rekey` for a second recipient are covered by unit tests
   and mocks only. Run it once with two real machines (or a second user) and one shared remote.

### Live test plan for macOS and Windows (item 2)

Use a clean machine or user. Engine: Docker Desktop, or Podman (macOS: a running `podman machine`; Windows:
Podman Desktop with compose). Record the OS, engine and Python versions and `om version`. Run the steps in
order on each platform; a VM does everything except step 8 (it needs a second device on a real LAN).

1. **Install.** macOS: `git clone https://github.com/Chitakasa/om.git ~/.om && ~/.om/install.sh`. Windows
   (PowerShell): clone to `$HOME\.om`, then `powershell -ExecutionPolicy Bypass -File $HOME\.om\install.ps1`
   and open a new terminal. Pass: no traceback, `om version` prints.
2. **Core.** `om core start`, `om core status`. Pass: `om_caddy`, `om_router`, `om_egress`, `om_sockguard`
   and `om_dashboard` run (this exercises the router's unix socket shared by two containers in the VM).
3. **Sample workspace.** `mkdir om-live-test; cd om-live-test; om init; om add web; om start; om routes`.
   Pass: the URL answers with the nginx page (if `*.localhost` does not resolve for `curl`, use
   `curl --resolve <host>:80:127.0.0.1 http://<host>/`).
4. **Per-folder networks.** `om add api --project`, `om start`, `om network`. Pass: each folder has its own
   network and the services do not share one.
5. **No-log services.** Put the label `om.log=off` on a service, `om start`, `om logs <svc>`. Pass: it shows
   nothing (`logging: driver: none` works on the VM engines).
6. **Doctor.** `om doctor --json > doctor.json`. Pass: no FAIL; list the warnings and keep the file.
7. **Exposure.** `om exposure`. Pass: it matches reality (private on this machine, nothing on the LAN unless
   a service is public).
8. **Firewall and the real source address** (the riskiest claim: do pf and Windows Firewall see the client's
   address behind the engine's port forwarder?). Make a service public (`om edit web --scope public`) and open
   `http://<LAN address>:8080/` from a second device on the LAN. macOS: `om firewall show`, then
   `om firewall apply` (sudo). Windows: `om firewall show`, then run the generated script from an elevated
   PowerShell (the installer says to; whether `om firewall apply` works there directly is unconfirmed). Add
   `om.net.deny=<second device's address>` to a service, apply again and retry. Pass: that device is blocked
   and this machine is not, and the refusal shows the real source address (macOS: the pf log shown by
   `om firewall log`; Windows: `pfirewall.log`). If every client looks like one internal address, record that:
   address rules cannot work on that engine.
9. **VPN discovery** (if you use one). `om vpn`, `om vpn devices`. Pass: the VPN's interface is listed and
   your other devices appear with names.
10. **Teardown.** `om down`, `om uninstall` (`--purge` to remove state), delete `om-live-test`. Pass: no
    containers left (`docker ps -a` / `podman ps -a`).

Report each step as pass, fail or skipped with the exact output of any failure, plus `doctor.json`; redact
addresses, host names and tokens first. A step that fails goes back into this list as a bug, and the platform
stays marked "not yet verified" in the README until steps 1-8 pass on it.

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
   to survive reboots (plus `rdr-anchor "om"` for the VPN fallback). Windows Firewall cannot redirect:
   VPN devices outside `OM_VPN_ALLOW` get no answer at the private address there and use `:8080`.
3. **IPv6:** the VPN and LAN tiers bind IPv4 addresses only.
4. **`om logs` shows nothing for `om.log=off` services** (by design).
5. **A dashboard tab fills the edge access log** (about 1,000 entries a day per open tab, from its
   polling). Consider `log_skip` for the dashboard's own API calls.
6. **`om prune` covers the whole engine**, not only om's images: it lists everything no container uses
   and no workspace lock pins, so read the list before `--yes`.
7. **Auto-updates and failed syncs are only noticed through notifications or the log** — no
   dashboard panel shows them yet.

## 4. Code health

0. **Written 2026-10-24, covered by unit tests with mocks but not yet run live:**
   - `om.update=auto` was run live on 2026-10-28 on a throw-away workspace: signed lock commit, redeploy, failed health check, `git revert`, redeploy of the old image all worked. The success path (health check passes) was not run.
   - The webhook channel (only a mocked POST), the macOS (`osascript`) and Windows (PowerShell toast) desktop channels; on Linux `notify-send` works from a shell, not yet from the timer on a headless machine.
   - `om scan` with a real `trivy` or `grype` (only the parsing of their JSON is tested).
   - `om.mem` / `om.pids` were checked live (the engine reports 64 MB and 50 pids on the running container). `om prune --yes` was not run: it lists every unused image on the engine, other projects' included.
   - The RAM tile's cache-free figure on Docker and on macOS/Windows: there the engine's figure, which includes file cache, is shown.
1. `bin/om` is 1,807 lines (was 2,700). Split out: route generation (`routesync.py`), the argparse definitions
   (`cliparser.py`), the VPN / firewall / boot and the auth / links / secrets commands (`hostcmds.py`,
   `securitycmds.py`), the `om add` scaffolding (`scaffold.py`), scripts, workspace helpers (`workspace.py`),
   `cli.py`, `firewalllog.py`, `vpndevices.py`, `docscmd.py`, `routesview.py`, `previews.py`. Still in `bin/om`:
   `start_workspace` (seven steps now) and the `cmd_*` that call it; the tests patch those functions' globals.
   `core.py` is split by job (1,493 → 366 lines): `omstate.py`, `wsregistry.py`, `enginectl.py`, `vpndetect.py`,
   `omsettings.py`, `migration.py`, and the core's lifecycle left in `core.py`. A function is patched in the module
   that calls it, so tests name that module.
2. ~~Lint~~ — `pyproject.toml` configures ruff (errors, imports, bugbear, pyupgrade, comprehensions, simplify,
   pie, pylint warnings); `ruff check` is clean and runs as the CI `lint` job.
3. ~~The `integration` job~~ — ran 2026-11-21 and is green: Podman, `om core start`, a sample workspace, `om doctor`.
   Its first run failed on the *Login* check (the runner's other account); the job now sets `OM_TRUSTED_USERS`.
4. Compose parsing falls back to regex when the engine is unavailable.
5. The dashboard server (`core/dashboard/app/server.py`) is a route table of small handlers, with every endpoint
   pinned by `tests/test_dashboard_endpoints.py`. The front end (`core/dashboard/app/index.html`, ~1,900 lines)
   was not reviewed in this hardening pass. Unlabelled services now get a generic card (the product preset table is gone).
6. The installers (`install.sh`, `install.ps1`) were not re-checked after these changes and don't
   mention `om vpn allow` or `om firewall log`. They are checked only for the library calls they make
   (`tests/test_installers.py`); nothing runs them. A behavioural test needs a sandbox: `install.sh` looks for an
   engine and can reach `sudo` (only when a terminal answers), so run it by hand on a throwaway user or VM.
7. Reviewed 2026-11-21 and left as they are: the `functools.cache` in `enginectl.py` (engine kind and the systemd
   `oom_score_adj` do not change under a running process in practice; revisit only if `om core watch` is seen
   with a stale value) and `vpn_peers()`'s DNS scan (only `om vpn` / `om vpn devices` call it, not `om doctor`
   or `om exposure`; a hub VPN with no answering DNS costs about 8 s there).
8. Parser coverage: the kernel-log, VPN-device and edge-log parsers are tested in `tests/test_routes.py`
   (`TestFirewallLog`, `TestVpnDevices`, `TestVpnDeviceLogEdges`), including truncated and hostile lines.

## 5. Open-source readiness

1. **License:** MIT, copyright "Chitakasa" — confirm the holder's name.
2. **Project files:** `SECURITY.md` and `CONTRIBUTING.md` are in place. Issue forms and a pull-request template are in `.github/`. `CODE_OF_CONDUCT.md` is in place (reports go through GitHub's private reporting). `SECURITY.md` points reporters to GitHub's private
   vulnerability reporting, switched on in the repository's settings on 2026-11-21 (`gh api repos/Chitakasa/om/private-vulnerability-reporting` reads `enabled: true`).
3. **`CLAUDE.md`** is a guide for AI coding agents: keep it for contributors who use one, or rename it.
4. **Distribution and updates:** today it is `git clone` + `install.sh`; the upgrade path is documented
   in `CHANGELOG.md` from the first published version on. Consider packages (AUR, Homebrew, Scoop/winget), signed release tags, or
   `om self-update`.
5. ~~README~~ — done: "who reaches what", the checkpoints, and the platform matrix with the Linux-only
   features.
