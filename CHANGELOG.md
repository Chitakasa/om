# Changelog

## Unreleased

### om is a Go program (2026-11-22)
- **om was rewritten in Go**: one static binary (standard library only, no cgo) replaces the Python program (kept in the tree, unused, as the reference). Commands, options, output, exit codes and every generated file (Caddy routes, nftables/pf/Windows rules, compose overrides, Squid ACLs, HAProxy fragments) are the same as before: each library package replays outputs recorded from the Python version (`testdata/`), and `internal/cli/e2e_test.go` runs about 60 commands through both programs and compares them.
- **Install:** `install.sh` / `install.ps1` build the binary with Go when it is installed, else download the release binary for your system and check its SHA-256 (`OM_RELEASE_URL` overrides the source). Python is not needed to install or run om. A signed tag `vX.Y.Z` now builds and publishes the binaries for Linux, macOS and Windows (amd64, arm64) with `SHA256SUMS`.
- **The dashboard is `om dashboard`:** the container runs the same binary (copied to `<state>/bin/om-dashboard` by `om core start`, mounted at `/om`) on the pinned Alpine image; the page is embedded in the binary. On macOS and Windows the installer also builds `bin/om-linux-<arch>` for it. `om doctor`'s in-container probes became `om probe …` (no Python in any container). `om doctor` runs 37 checks (the Python-version check is gone).
- **Fixed on the way** (found by comparing the Go port with the Python version, command by command): `om uninstall --help` named the folders of the machine the help was recorded on; a job with stdin or stdout on /dev/null (cron, a systemd unit) counted as interactive, so `om shell` asked for a tty there; the autosync switch was read wrongly, so scheduled sync never ran; `rm` was missing from the shell completions.
- **A rootful engine is refused:** found by the first live run on Docker (CI): with an engine that runs as root the core's containers (no capabilities) cannot write your state folders, so the edge restarted in a loop and every request hung. `om core start` now stops with the reason and the fix (rootless Podman, or rootless Docker), and `om doctor` fails the *Engine* row. Rootless engines and VM engines (macOS, Windows) are unchanged.
- **Tests and CI** are Go's: `go vet` on three OSes, `go test -race`, a coverage floor for the library and one for the whole program, static cross-builds of every target, the Caddy and firewall syntax checks (now rendered by Go tests), and the Podman integration job. The attack, fuzz, perimeter-consistency, registry and id-collision suites were ported to `internal/attacks` and `internal/cli`; `internal/repocheck` keeps the docs, the workflows' pinning and the package layering honest. The generated reference docs (`docs/COMMANDS.md`, `SETTINGS.md`, `LABELS.md`, `DOCTOR.md`) now come from `go test ./internal/cli -run TestReferenceDocs -update`.
- **Upgrade:** nothing to do for state or settings. Re-run `install.sh` (it replaces the Python wrapper with one for the binary), then `om core restart` once so the dashboard container runs the Go build.


### Logins, links and secrets are tested (2026-11-21)
- **`securitycmds` went from 39% to 100% line coverage** (`tests/test_securitycmds.py`, 20 tests, engine, Caddy and age replaced): the login file's format and its bcrypt-only parsing; adding, setting, removing and switching off logins; a password that is too short, mismatched or hashed without the edge is refused and nothing is written; the password reaches only `caddy hash-password` and appears in no file or output; secrets are stored encrypted and never as plaintext, an empty value or a bad target is refused, and `decrypt -o` writes a 0600 file.
- The tests were checked by breaking the code on purpose, seven ways (a leaked password, a plaintext line counted as a login, each password check removed, `set` no longer replacing, a bad login name accepted, an empty secret stored): every one failed the suite.
- The CI coverage floor rose to 70% (the library is at 73%).

### Coverage floor, releases and flaky tests (2026-11-21)
- **CI measures the library's line coverage** (Linux, Python 3.12, `coverage` pinned) and fails below a floor of 68%; it is about 71% today. `docs/REMAINING.md` names the thinnest modules.
- **A release process** is written down (`CONTRIBUTING.md`: semantic versioning, changelog fold, signed tag, release notes, a fresh-clone check) and a test fails when the changelog has no entry for the current `VERSION`.
- **The recorded `om status` outputs no longer hard-code the version**, so a release does not touch tests; and a policy for tests that fail sometimes is written down.

### Fuzzing found two bugs (2026-11-21)
- **A setting could write a second line into `om.env`.** `om config set OM_WALLPAPERS_DIR='a<newline>OM_POLICY=warn'` was accepted (and so was a webhook URL with a newline), which added a setting nobody asked for. Every value with a control character is now refused, and `set_setting` refuses it too.
- **An IPv6 scope id (`fe80::1%eth0`) passed as an address rule** (`om.net.allow` / `om.net.deny`, `OM_VPN_ALLOW`, `om vpn allow`) and would have reached the firewall as `…%eth0/128`, which `nft` cannot parse: one bad label could make `om firewall apply` fail. Scoped addresses are now refused.
- **`tests/test_fuzz.py`** feeds thousands of seeded hostile inputs to the name, host, route-label, `om.caddy`, address-rule, limit and setting validators: nothing may raise, nothing refused may reach a generated config, and a forbidden token anywhere makes a Caddy snippet fail. It runs in under a second and reproduces from its seed.

### CI hardening (2026-11-21)
- **Every GitHub Action is pinned to a full commit SHA** (version in a comment) and **Dependabot** opens a weekly pull request for each update; the workflow token is read-only (`permissions: contents: read`), checkouts keep no credentials, every job has a timeout, and a newer push supersedes a branch's running checks (`main` always finishes).
- **A `secrets` job runs `gitleaks` over the whole history** on every push.
- `tests/test_ci_hygiene.py` fails if an action is unpinned, a job loses its timeout, the token gains write access, or the secret scan or Dependabot goes missing.

### Docs for newcomers (2026-11-21)
- **`docs/START.md`** is a ten-minute path from install to a running service, a rollback and a VPN pointer; **`docs/GLOSSARY.md`** explains every om term in a line; **`docs/TROUBLESHOOTING.md`** holds the debugging path and every common symptom with its cause and fix (moved out of the Guide's section 13, plus the first-run problems: engine, compose, ports, signing, the policy gate, `.omignore`).
- **The README is a front page of about 130 lines** (was 267): what om is, install, a five-command quickstart, who reaches what, platforms, and a map of the docs. The architecture diagram and the checkpoints table moved to `ARCHITECTURE.md`, the platform notes to the Guide, and the full command list is the generated `COMMANDS.md`. The platform badge now says what is verified (Linux) and what is not.
- **A test checks every relative link and `#heading` anchor** in the README and docs; it found a README anchor that never matched its heading.
- `om --help` points newcomers to `om docs start`.

### Reference docs generated from the code (2026-11-21)
- **`docs/COMMANDS.md`, `SETTINGS.md`, `LABELS.md` and `DOCTOR.md`** list every command and argument, every `om.env` key (default, accepted values, what it does, how to change it), every label a service can carry, and what each of the 38 doctor checks verifies. `tests/gen_reference.py` writes them from the code and a test fails while they are stale, so they cannot drift. Read them with `om docs commands|settings|labels|doctor`.
- **Every argument now has help text** (`om <command> --help` was missing 45 descriptions), and every doctor check has a docstring.

### Easier first steps (2026-11-21)
- **`om --help` groups the commands** (Everyday, Services, Deploy and GitOps, Network and security, Platform and upkeep) and points newcomers to `om docs guide`. Same commands, no new ones; a test keeps every command in exactly one group.
- **`om status` ends with a `Next` block** when something obvious is missing (the core is not running; you are outside a workspace), says what `—` means in the URL column, and three error messages (`not in a workspace`, `no such login`, `not a trusted VPN`) now say what to run.

### Bug sweep (2026-11-21)
- **`om --help`** no longer prints a `==SUPPRESS==` line for the hidden `script` alias, and its title no longer says "Universal" (README and `bin/om` too): *self-host anything, privately and safely*.
- **`om status`** names the folders om skips because they hold an `.omignore` ("not managed by om"), and `om status --json` lists them under `workspace.ignored`. A folder with a compose file used to vanish from the list without a word.
- **Tests:** every command must answer `--help` cleanly, and the backticked `om <command>` names in the docs must exist (ideas sections excepted).

### `om add` offers every label (2026-11-21)
- **The compose file `om add` writes now lists every user label** as a commented, grouped menu (routing, access, outbound traffic, resources and updates, logging and policy, dashboard) with an example and one line each, generated from one table (`scaffold.LABEL_MENU`). A test fails if a label om documents is missing from the scaffold, or a menu label is missing from the docs.

### Public-readiness (2026-11-21)
- **README:** the install commands clone `https://github.com/Chitakasa/om.git` instead of a `<you>` placeholder.
- **`CODE_OF_CONDUCT.md`:** short rules for behaviour in the project's spaces; conduct reports go through GitHub's private reporting.
- **GitHub templates:** bug-report and feature-request issue forms (the bug form asks for `om version`, OS and engine, and `om doctor` output), an issue chooser that sends security reports to private reporting, and a pull-request checklist that mirrors `CONTRIBUTING.md`.

### `om config` (2026-11-21)
- **`om config show|get|set|unset`** reads and changes `om.env` without an editor (`lib/gitops/settingscmd.py`): unknown keys are refused with a "did you mean", every value is checked (ports, `OM_POLICY`, `OM_SIGNED`, `OM_NOTIFY`, `OM_NOTIFY_URL`, extra firewall ports, trusted users), the file is written 0600, `OM_NOTIFY_URL` is masked unless `--reveal`, and the command says what to run next. `OM_VPN` / `OM_VPN_ALLOW` keep `om vpn`, which also updates the firewall.

### Review fixes (2026-11-21)
- **`om.env` is written 0600** (`write_private`, also its first write by `om core start`): `OM_NOTIFY_URL` is a bearer-like secret. `om doctor`'s secret-file check now includes it; an existing 0644 file is fixed by the next `om` settings change or `chmod 600`.
- **`om uninstall`** leaves an unreadable launcher in place with a warning instead of crashing half way; **`om docs`** starts `$PAGER` without a shell.

### CI green on Linux, macOS and Windows (2026-11-21)
- **Windows console:** `bin/om` writes UTF-8 to stdout/stderr (`errors="replace"`), so the ✓ ✗ ⚠ marks no longer raise `UnicodeEncodeError` under the cp1252 console.
- **Policy gate:** `secret_findings` treats a declared secret path it may not stat (e.g. `/run/podman/podman.sock`) as no plaintext secret, instead of crashing the gate.
- **Tests:** a git identity for the sync `--rebase` test; POSIX-only tests are skipped on Windows (file modes, `select.poll`, kernel interface kinds, newline folder names, host firewall); recorded scenarios compare paths with forward slashes via `_env.scrub_paths`; `arm64` in the platform map.
- **CI:** the `integration` job's `om doctor` trusts the runner's own accounts through `OM_TRUSTED_USERS`.

### Code audit: fixes, tests and a smaller `bin/om`
- **Stream fragments are named `<workspace>.<service>.cfg`** and found by the owner in their header, not by file-name prefix. Workspace ids contain `-`, so syncing workspace `a` used to delete the stream routes of `a-b`, and `a`+`b-web` and `a-b`+`web` shared one file. Old `<ws>-<svc>.cfg` files are replaced at the workspace's next stream sync (`om start` / `om reload`).
- **A route file owned by another workspace is never overwritten.** The same `<ws>-<svc>` ambiguity made two workspaces flip `<ws>-<svc>.caddy` between them on every sync; the second one now gets an error and no route until one is renamed. Long preview branch names no longer truncate to one id (a hash of the branch is kept).
- **Egress:** `om.egress.learn_ttl` now takes effect (the first start stored the 24 h default and the label was ignored); reading the proxy log records learned hosts only for services in `learn` / `audit` mode and no longer counts a log line twice; an unreadable subnet falls back instead of crashing.
- **`om.link` networks are kept when the engine lists no containers** (a failed `ps` used to look like "no link declared" and removed every link network).
- **Dashboard:** a negative `Content-Length` on the wallpaper endpoints is treated as empty instead of blocking until the client disconnects.
- **Smaller fixes:** generation numbers are taken under a lock; a keyed notification that no channel delivered is retried; decrypted secrets go to `XDG_RUNTIME_DIR` or `/dev/shm`, never a symlinked or foreign folder; `om secrets decrypt -o` writes 0600 from the start; `om firewall remove` reports whether the firewall is really gone; `om status` lists all seven core containers.
- **`om doctor` *Login* is a failure**, not a warning, when another account can log in on this machine and the private tier has no login. `OM_TRUSTED_USERS=<user>,…` in `om.env` lists accounts that are yours.
- **Code and tests:** route generation, the VPN / firewall / boot commands and the auth / links / secrets commands moved out of `bin/om` into `lib/gitops/routesync.py`, `hostcmds.py` and `securitycmds.py`, text unchanged. New `tests/test_id_collisions.py` (colliding id pairs through routes, pruning, stream fragments and previews) and `tests/test_audit_fixes.py`.

### Security hardening
- **Attack suite** (`tests/test_attacks.py`) feeds hostile input to every place untrusted text becomes configuration; each hole it found is closed: a trailing newline passed every name, domain, host, path, digest and limit check (`$` → `\Z`); an `om.caddy` snippet could hide `{$OM_EDGE_TOKEN}` in a multi-line string on a `#` line (every line is scanned now); the policy gate now refuses a named volume binding a sensitive host path, `configs:` from sensitive paths, `volumes_from` a foreign container, `no-new-privileges:false` and `container_name: om_*`; `om.route.aliases=/` redirected the whole dashboard and a service named `api` broke `/api` (reserved paths); the workspace id `om` is reserved; `om.tcp=²` crashed the route sync (`is_number`); `om preview` validates branch names.
- **Fail-open fixed:** a service with unreadable `om.net.*` labels or a refused `om.caddy` was still published on its TCP port; it now gets no route of any kind. Found by `tests/test_perimeter_consistency.py`, which builds random workspaces and checks that routes, registries, published ports, the firewall and `om exposure` agree.
- **`om exposure`** shows who can reach what (this machine, the VPN's devices, the LAN; per service its address rules and whether the firewall carries them, own login, outbound access); the doctor gains *Private reach* (38 checks).
- **`OM_SIGNED=auto`** (the default) enforces signed deploys whenever git signs with an SSH key; the installer offers a private-tier login.
- **Safer secrets, webhook and first deploy:** `om-v1` secrets (no integrity check) are refused unless `--allow-unauthenticated`, and `om secrets migrate <file> <project>/<name>` moves an old file to age; `OM_NOTIFY_URL` must be `https://` (plain `http://` only to localhost or a private address); the first deploy of a workspace shows the fingerprints of the signers it will trust and, under `enforce`, asks you to confirm them (no terminal: refused); the generation log's head is signed with the git SSH key when that needs no prompt, and `om fsck` checks the signature against the trusted signers.
- **Threat model** in `docs/DESIGN.md`: assets, who is trusted, and per actor what they can do, what stops them and where it stops.
- **Installers fixed:** `install.sh` / `install.ps1` still called `core.set_setting` and `core.vpn_*` after `core.py` was split; `tests/test_installers.py` checks every library call they make.

### Code quality
- **Lint:** `pyproject.toml` configures ruff (errors, imports, bugbear, pyupgrade, comprehensions, simplify, pie, pylint warnings); the whole tree, `bin/om` included, is clean, and CI runs it as a `lint` job with the version it was checked with.
- **Long functions are short steps** (behaviour unchanged, each pinned by tests that ran on the old code first): the dashboard's `_handle_request` (266 lines), `do_POST` (179) and `_load_running_services` (150) became route tables and small handlers; `_sync_caddy_routes` (156) became eight functions; `start_workspace` (129) seven steps; `cmd_add` (113) 25 lines on a pure `scaffold.py`; `cmd_core` one function per action; `sync_workspace` `_pull` / `_workspace_id` / `_roll_back`; `main()` two dispatch tables; the parser lives in `cliparser.py` in five groups; the doctor's check list is data (`BASIC_CHECKS`, `PERIMETER_CHECKS`, `HOST_CHECKS`). `bin/om` is 1,807 lines (was 2,550).
- **Tests: 273** (was 222): every dashboard endpoint (35 recorded requests, both tiers, refusals and errors), `service_entry`, ten `start_workspace` scenarios, `sync_workspace` against real git repositories, `om add` output and refusals, the parser/handler parity, and `tests/test_docs_match_code.py`, which fails when the docs and the code disagree on commands, settings, the number of doctor checks, dashboard routes, modules, label names or unpinned core images.
- **Docs re-derived from the code:** the doctor runs 37 checks (the README said 34), `ARCHITECTURE.md` has the dashboard's route table, `CLAUDE.md` lists every module and the lint command, `GUIDE.md` lists `dashboard.url`, `dashboard.search_url`, `workspace.category` and `om.jvm`, and the stale `ports.generated.yml` / `.runtime.env` names in `core/compose.yml`, the edge Caddyfile and `CLAUDE.md` now say `<state>/ports.yml` / `runtime.env`.
- `om core status` lists the stream edge and router like `om status` does.
- **The remaining long functions are short steps** (the logic-heavy ones; tables and templates under 60 lines are left): `cmd_status`, `cmd_edit` (label editing is pure functions in `scaffold.py`), `cmd_egress`, `cmd_preview`, `scheduled_sync`, `cmd_vpn`, `core_up`, `watch` (a `_ContainerWatcher` in its own `corewatch.py`), `render_ports`, `validate_haproxy_syntax`, `assign_stream_slots`, the doctor's `check_egress` and `egress.write_override`. Each was recorded first (output, calls, return value, exit code, written files) and the split code reproduces the recording; the recordings are tests now (`test_status`, `test_edit_labels`, `test_egress_log`, `test_preview_command`, `test_scheduled_sync`, `test_vpn_command`, `test_core_up`, `test_core_watch`, `test_render_ports`, `test_haproxy_validation`, `test_registry_invariants`, `test_doctor_egress`, `test_egress_override`). The label-normalizing snippet that existed in six places is `svclabels.service_labels`; the registry's four atomic JSON writes share `_write_sorted_json`.
- **`om egress log` no longer suggests allowing the proxy itself.** An HTTP/3 client probing its proxy for MASQUE support (`GET http://om_egress:3128/.well-known/masque/...`, refused with 403) showed up as a refused host `om_egress`, and `--apply` would have written it into the compose file; requests aimed at the proxy are now ignored when reading its log.
- **`core.py` is split by job** (1,493 lines → 366 for the core's lifecycle): `omstate.py` (paths, constants, `file_lock`, `run`, atomic and private writes), `wsregistry.py` (workspace registry, port slots, address policies), `enginectl.py` (engine detection, networks, `connect_router`, reviving dead containers), `vpndetect.py` (LAN address, tunnels, PTR names), `omsettings.py` (`om.env`, the VPN as configured, `render_ports`, `write_runtime_files`) and `migration.py`. Moved verbatim, every caller and test points at the new home (625 module references resolve; none of the 141 old names is missing), and the modules are named so they never collide with the local variables `state`, `registry`, `runtime`, `vpn` and `settings`. `tests/test_layering.py` keeps the imports one-directional (`omstate` ← `wsregistry` / `vpndetect` / `migration` ← `enginectl` ← `omsettings` ← `core`), and `tests/test_docs_match_code.py` also fails on a doc that names a module attribute that does not exist (it found a stale `core.reserve_stream_port`).

### Egress audit mode & auto-apply fixes
- **Permanent egress audit mode (`om.egress=audit`):** Allows public egress permanently while continuously logging and tracking all contacted domains to disk (`<state>/egress/learn/`) for dynamic applications (scrapers, extensions, indexers) where static allowlists are too brittle. RFC 1918 private ranges remain hard-denied.
- **Configurable learn TTL (`om.egress.learn_ttl`):** Supports `never` (or `off`, `0`) to disable expiry on `om.egress=learn`.
- **Compose-aware `om egress log --apply`:** Resolves compose files accurately across all workspace project folders; safely targets only the service being modified without altering other services' labels; preserves indentation and quote styles.

### Updates you control, and told when it matters
- **Pick what to update:** `om update --image REF` (repeatable) and `om update -i` (asks per image); `--dry-run` now lists the services using each image and the registry's build date and compressed size of both digests.
- **`om.update=hold|auto`:** `hold` keeps an image's pin (`om update` skips it, `om status` stops listing it); `auto` lets the scheduled sync (`om autosync`) move it at most every 6 hours — commit the lock, redeploy, health-check, and on failure revert the lock commit, redeploy the previous images and do not retry that digest.
- **Dashboard badge:** `⬆ update` on a card when its image has a newer digest (private tier only). The list now lives in `<state>/registry/updates/<ws>.json`, which the dashboard mounts read-only.
- **Notifications** (`OM_NOTIFY`, default `auto` = desktop; `webhook` with `OM_NOTIFY_URL` is opt-in; `om notify test`): a new image update, an auto-update applied or rolled back, a failed scheduled sync (once per failing commit), the core healing itself (once an hour per message). Every message is also in `<state>/logs/notify.log`.
- **`om scan`** counts critical/high vulnerabilities in the pinned images with `trivy` or `grype` if installed. **`om prune`** lists (`--yes` removes) images no container uses and no workspace lock pins. **`om doctor`** warns about running workspace containers without a healthcheck (34 checks).
- **Per-service limits:** labels `om.mem`, `om.pids`, `om.cpus` become a compose override applied by `om start` / `om update`.

### The core's footprint
- **Memory and process limits on every core container** (`om_caddy` 256 MB / 256 pids, the others 128 MB / 128), a healthcheck on `om_egress` and `om_sockguard` too, and `om.heal=restart` on `om_egress` and `om_dashboard` (the Caddy containers' check validates configuration only, so a restart would not help them).
- **The dashboard's *Core RAM* tile** shows anonymous memory from `<state>/registry/core_memory.json`, written by `om core heal` from the cgroups (Linux, local engine), instead of the engine's figure, which includes shared file cache and swung between ~80 and ~150 MB for the same core. Elsewhere, or when the file is older than 10 minutes, it falls back to the engine's figure.
- The dashboard's stats worker polls the engine only while a request asked for stats in the last 30 seconds.

### Docs refreshed against the code
- ARCHITECTURE: the router listens on a unix socket only (the edge snippet and the container table still said port 8000); no UDP 41641 rule; the heal log lives in the state directory; the full settings list; all 34 doctor checks; a new section on updates, limits and notifications.
- GUIDE: what `om init` creates, which folders are skipped, `om disable|enable`, the `om add` flags and that `--project` is Node.js only; README: every command, the 34 checks, current RAM figures; DESIGN: opt-in auto-updates and the limits of pins and notifications; REMAINING: what is untested live.

### Review fixes
- **Secret files are 0600 from the first byte** (edge token, age host key, egress credentials): written through `core.write_private_bytes`, not written and then chmod'ed. `om doctor` checks the modes ("Secret files").
- **Route and lock files are replaced atomically** (`core.write_atomic`), so Caddy never reads half a file.
- **Generation log head:** `generations/<ws>/head` names the newest generation and its digest, so dropped or rewritten tail entries are noticed by `om fsck` / `om doctor` (the hash chain alone could not see them).
- **`om_egress` runs Squid 7.6 on a pinned Alpine** built by `om core start` from `core/egress/`, replacing the Ubuntu beta image; its private-range blocklist now also covers special-use IPv4/IPv6 ranges (benchmarking, documentation, reserved, NAT64, 6to4, unspecified, multicast).
- systemd units quote their paths; the launchd plist is XML-escaped; `restart_unhealthy` restarts through `engine_lifecycle`; the post-sync health check uses a preview's own id; route generation says when it skips a service.
- `bin/om` split into modules (2,700 → 2,200 lines); CI gets an `integration` job on Podman.

### Closer to absolute
- **Isolation for any compose file:** om no longer relies on a folder joining `${WORKSPACE_NET}`. The implicit `default` network becomes the folder's own network, networks a file defines itself become internal with a per-folder name (compose named them after the workspace, so two folders' `backend` networks were one), and every service joins the folder's network so the edge reaches it. New policy rule `networks`: joining another stack's external network (waivable).
- **Least-privileged scaffolds:** `om add` uses a non-root nginx (`nginx-unprivileged:1.31-alpine`, port 8080) and runs it and the Node project with `cap_drop: [ALL]`, `read_only`, tmpfs `/tmp`; `--image` keeps only CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID. Opt-in labels are listed as comments.
- **Core images:** Caddy 2.11.7, Python 3.14.9-alpine (dashboard), Alpine 3.24 (om-tools), pinned by multi-arch digest; `om core update` applies them. (Squid stayed on Ubuntu's `6.6-24.04_beta` at this point; the review fixes below replace it with Squid 7.6 on Alpine.)
- **The router listens on no network:** only on a unix socket shared with the edge, so no container can even connect to it; the edge token stays as a second lock. `om doctor` probes the socket (refused without the token) and that the router has no listener.
- **Disallowed VPN devices see the public tier at the same address:** a device outside `OM_VPN_ALLOW` that opens `http://<machine>/` is sent to the public tier by the firewall instead of getting no answer (Linux, macOS; Windows: `:8080` as before). Run `om firewall apply` once (or any `om vpn allow|disallow`); on macOS also add `rdr-anchor "om"` to `/etc/pf.conf`.
- **`om_egress` only where a service may go out:** networks without an `om.egress` service no longer reach the proxy at all.
- **Logs without content:** the firewall logs refused connections and new connections to om's ports with their real source (rate-limited); the edge logs site, method, status, size, time and login — never URLs, queries or headers. `om.log=off` on a service leaves no trace (no edge entry, no connection log, and the engine discards its own output: a search engine logs failed upstream URLs with the query). `om firewall log` shows who knocked, who got in, and per-site request and error counts.
- **Error logs no longer carry requests:** the edge's and router's error entries logged the full request — URL and headers, the edge token among them. Both loggers now keep only what happened; `om doctor` checks the token appears in no om log.
- **Rootful engines no longer bypass address rules:** Docker and rootful Podman publish ports by DNAT, so their connections are forwarded and never passed `om_guard`'s input chain — `om.net` rules silently did nothing there. Every address rule is now also rendered in a `forward` chain (matched on the original address and port; nothing else forwarded is touched), and "enforced" requires both.
- **A removed device loses connections it already had:** address rules (`om.net.*`, `OM_VPN_ALLOW`) now come before the firewall's `established` accept, scoped to the client side (`ct direction original`), so a disallowed device's open keep-alive connections (a dashboard tab polls forever) are cut at once; replies to this machine's own connections are untouched. On the forward path (rootful engines) the rules match the connection's initiator (`ct original ip saddr`): they used to drop the container's replies even to allowed clients.
- **`om vpn allow|disallow` update the firewall themselves** (one sudo prompt, where om's firewall is installed), before checking anything: the new list is in effect at once and no device loses access in between. Declined sudo, `--no-apply` or no installed firewall: fail closed as before (the VPN's private tier stays unbound until `om firewall apply`).
- **`om.net.allow=vpn`:** a service reachable by exactly the devices on the VPN allow-list, following it (expanded when the firewall renders; after a list change such services keep no own ports until `om firewall apply`). Mixes with addresses; refused without an allow-list.
- **CI checks the generated firewall with each OS's own parser:** `nft -c` (Linux), `pfctl -nf` (macOS), PowerShell parse plus `New-NetFirewallRule -WhatIf` (Windows), on rules with address lists, the VPN allow-list, logging and the forward chain (`tests/fw_render.py`). macOS VPN device discovery reads `netstat`'s interface column by its header and expands its abbreviated destinations (`100.64/10`).
- **`om vpn` lists every device on the trusted VPNs**, also ones that never contacted this machine: found in the kernel's routes through the VPN interface (a host route per peer for mesh VPNs; a subnet ≤ /24 whose DNS names its members for hub VPNs; neighbours for layer-2 VPNs), the allow-list and the firewall log; named through the VPN's own DNS (PTR), allowed or not, last seen, connected/refused counts. `om vpn devices` prints only that list; `--json`. No VPN product's tool is used.
- **VPN device allow-list:** `om vpn allow <device>` (address, range, or the VPN's own name for it) / `om vpn disallow`: only listed devices reach the private tier over the VPN; other VPN devices keep the public tier. Firewall-enforced; until it is, the VPN's private tier is not bound. `om vpn` and `om doctor` show it.
- **One network per service folder:** a compromised service can no longer reach another folder's services in the same workspace. om gives each folder its own internal network through a compose override (no compose edits), attaches the router and egress to each, and prunes networks of removed folders. `om.network=shared` opts a folder out; `om.link` connects two services within a workspace too. `om network` lists them; `om doctor` probes the isolation (by name and by address).
- **`om edit` recreates through `om start`'s path:** it used a bare `compose up`, which dropped the egress proxy settings, image pins, secrets — and would have dropped the project network.

### Who may reach a service, by address
- **`om.net.allow` / `om.net.deny` labels** (addresses or CIDR ranges, IPv4/IPv6; deny wins; this machine always allowed): the host firewall drops everyone else on that service's own ports — no answer at all. nft on Linux, pf on macOS (tables), Windows Firewall (block rules over the complement). Fail closed: an unreadable label leaves the service unrouted, and until `om firewall apply` carries its rules the service has no port of its own. `om routes` shows the rules; `om doctor` fails on rules missing from the firewall and warns on stale ones.
- **VPN devices no longer reach `*.localhost` sites:** VPN addresses land on their own edge ports (:81/:444; host ports unchanged), so `<ws>.<svc>.localhost` answers this machine only, whatever Host a VPN device sends. `om doctor` probes it. Needs `om core restart` once.
- **`om.caddy` refuses `remote_ip` / `client_ip`:** under rootless port forwarding the edge sees every client as one internal address, so such a rule matched everyone or no one.

### Self-heal sees dead containers
- **Podman containers whose process died unseen** (conmon killed, e.g. by systemd SIGKILLing `podman-restart.service` after a failed boot start) kept showing `Up` forever and were never restarted. `container_running` now checks the pid in `/proc` (local Podman) or asks the engine with `top` (Podman machine); Docker's daemon already supervises its containers; `om core heal` and `om core start` stop/start such containers, keeping their exact configuration.
- **`om core watch`** (a systemd user service, `om-watch`, installed by `om boot enable`): holds a pidfd per container, so a process that dies unseen is restarted within ~3 s instead of at the next 2-minute heal. Linux with a local Podman or Docker engine; `om core heal` stays the fallback elsewhere.
- **`om.heal=restart` label:** a service that stays unhealthy for 10 minutes is restarted by `om core heal`, at most once per hour.

### A developer engine
- **Cross-workspace links:** `om.link=<ws>/<svc>` on the user and `om.link.allow=<ws>/<svc>` (or `<ws>/*`) on the provider put exactly those two containers on a private network; the user reaches the provider as `<ws>-<svc>`, any protocol. `om links` lists them and what blocks a one-sided one; `om start` and the heal timer keep them attached; `om doctor` checks them.
- **Own Caddy rules:** `om.caddy` next to a service's compose file runs first on all its addresses — headers, redirects, rewrites, `basic_auth`, matchers — from an allow-list; anything that reads files, reaches another upstream or reads om's environment is refused, and a refused file leaves the service unrouted. Marked in `om routes` and `om doctor`.
- **Branch previews:** `om preview <branch>` runs a branch beside the workspace as `<ws>--<branch>` (git worktree; own network, data, ports); `om preview rm <branch>` removes all of it. `om add` writes `${WORKSPACE_ID}` / `${WORKSPACE_NET}` names so services can run twice.
- **`--json`** on `status`, `routes`, `log`, `doctor` (exit 1 on failure), `list`, `links`, `vpn`.
- **Clone to running on another machine:** `om secrets init` adds the machine to the recipients (never replaces them); `om secrets rekey` re-encrypts every secret for all of them; a failed decrypt says which steps to take. `om status` shows public services again.

### Any VPN, no product names
- om finds every VPN on the machine by itself — each tunnel the kernel reports (`tun`, `wireguard`), whatever its product or name — and trusts none without your yes: `om vpn` lists them, `om vpn trust|untrust <iface>` sets `OM_VPN` and restarts the core; the installer asks per VPN, `om doctor` reminds. `OM_VPN=auto` no longer trusts anything by itself.
- Discovery per OS: Linux by kernel kind, macOS every non-hardware interface with an address (finds ZeroTier's `feth`), Windows every non-hardware adapter (`Get-NetAdapter`); DNS servers from `resolv.conf`, `scutil --dns`, `Get-DnsClientServerAddress`.
- The names devices may use (e.g. `myhost`, `myhost.<tailnet>.ts.net`) come from the VPN's own DNS through a PTR query, plus the hostname. No Tailscale CLI, address range or port remains in om: the firewall's VPN transport rule is gone (conntrack answers peers), mDNS is accepted on Ethernet/Wi-Fi only (`iiftype ether`), and the dashboard trusts the VPN addresses you trusted.

### One origin per service (ADR 0004)
- Every web service gets a stable port of its own — `20000+n` (private: loopback and VPN) and, if public, `21000+n` (LAN and VPN) — so no service can read another, or the dashboard, through your browser. Each port aborts requests for unknown hosts (DNS rebinding). The ranges are published once: adding a service never restarts the edge. `om routes` and the dashboard show the ports.
- `/<svc>/` path routing over the VPN and the LAN is removed; `/<svc>` and `om.route.aliases` on the dashboard's address redirect to the service's port. `dashboard.path` now means the path on the service's own address (default `/`).
- `om firewall` opens 20000–20199 on VPN addresses and 21000–21199; `om doctor` checks that private service ports are closed on the LAN.

### Final setup and docs
- om refuses to run as root, with the reason: containers stay rootless under your user, and `sudo om` would create a second, root-owned om. Host steps ask for sudo themselves.
- The installer now also sets up SSH-signed git commits (then `OM_SIGNED=enforce`) and asks, for each VPN on the machine, whether to trust it; it refuses to run as root.
- `OM_POLICY=enforce` is the default; a mistyped `OM_POLICY` or `OM_SIGNED` enforces (fail closed). `om secrets encrypt` (old built-in format) is removed; `decrypt` stays to read old files. `om auth` accepts passwords of 4+ characters.
- Docs merged into three: `docs/GUIDE.md` (was DEVELOPER_GUIDE + PROJECT_GUIDE), `docs/ARCHITECTURE.md` (was NETWORK_ARCHITECTURE, now with outbound access and the policy gate), `docs/DESIGN.md` (was VISION + GOALS). `om docs guide|architecture|design`.

### Network: your VPN is the door (ADR 0003)
- `OM_VPN` (replaces `OM_TAILSCALE_IP`/`OM_TAILSCALE_HOST`): the private tier answers on loopback and on the addresses of the VPNs you trust (see *Any VPN, no product names* above), and on the names their DNS gives this machine, so `http://<machine>/` works from every device on that VPN.
- VPN addresses also serve the public tier (the public dashboard on `:8080`/`:8443`, public services on their own ports), so a VPN's own access rules (e.g. a Tailscale ACL allowing ports 8080 and 21000–21199 to a shared user) give a guest exactly the `dashboard.scope=public` services. `om firewall` opens 8080/8443 for VPN addresses only.
- `om doctor` *VPN*: which VPNs reach the private tier, and which tunnels are present but not trusted. *Admin surface* checks the edge's listeners. *Login* warns only when other people can log in to this machine.
- Removed, with everything they needed (ADR 0003 explains why): the WireGuard door (`om_wg`, dnsmasq, `om device`), the Authelia gate (`om_gate`, passkeys, `om invite/pending/approve/revoke`, `om grant/ungrant`), the signed access file (`om access`) and the `om.access` label, `OM_DOMAIN` and `.internal` names, `om tiers`, the off-host mirror (`om mirror`), the separate OS user (`om user`, `OM_RUN_AS`), `om host quiet`, and Portainer. `om core start` deletes their containers, their state and the gated sites in generated routes.

### Secrets
- Service secrets with age (GOALS G2): `om secrets init` (host key in `<state>/data/age.key`, recipients in `.om/age-recipients`: this host and your SSH key), `om secrets set <project>/<name>` (value from stdin; writes `<project>/secrets/<name>.age`), `om secrets list`. A service declares it with compose's own `secrets:` (`file: ./secrets/<name>`); `om start` decrypts into `$XDG_RUNTIME_DIR` (memory) and compose mounts it read-only at `/run/secrets/<name>` — never an environment variable. `om stop` wipes the decrypted copies. `age` runs in a locally built, pinned `om-tools` image, so the host needs nothing installed. A plaintext secret file in the workspace is refused by the policy gate. The built-in `om-v2` format is read-only (decrypt, for migration).

### Updates and new services
- `om update --dry-run` lists images whose tag now points at a newer digest; the heal timer checks every 6 hours and `om status` shows "updates N available".
- `om add` pins the new image in `.om/lock.json` right away.

### Generations (phase 2)
- `.om/lock.json` pins every pulled image to its registry index digest; `om start`/`sync` apply it through an om-generated override, so a re-pushed tag changes nothing. `om lock` pins what runs now; `om update` moves to the newest digests, commits the lock and redeploys through the normal start path (policy gate and egress included).
- Signed deploys: a clean commit must be signed by a key in the workspace's `.om/allowed_signers`, checked against om's trusted copy from the last deployed generation (a commit cannot trust itself). `OM_SIGNED=warn|enforce`; `om sync` checks the incoming commit before pulling. A dirty tree runs as an unsigned *dev* generation. `om init` writes your git SSH signing key into `.om/allowed_signers`.
- Every deploy is a numbered generation in `<state>/generations/<ws>/`, hash-chained. `om log`, `om rollback [n]` (detached checkout of that commit; data is not rolled back), `om fsck` (chain, signature, running images vs lock); `om status` shows the current generation and any change since; `om doctor` checks every workspace (*Generations*).

### Workspaces
- A folder containing an `.omignore` file is not part of the workspace: `om start/stop/sync/policy` skip it (for a compose project you run some other way).

### Hardening (phase 1)
- Dashboard sends a strict Content-Security-Policy (only its own inline script, by hash); inline event handlers removed; `dashboard.url` must be http(s) or a relative path.
- New `om_sockguard` (no network) gives the dashboard a read-only engine API: `GET` container list and stats only, everything else 403. The dashboard no longer mounts the engine socket. `om doctor` probes it (*Engine filter*).
- Policy gate: `om start`/`om sync` check each compose file (via `compose config`) for `privileged`, host namespaces, `ports:`, engine sockets and sensitive host mounts, capabilities beyond the engine default set, `devices`, and disabled seccomp/AppArmor/SELinux. `OM_POLICY=warn` (the default at the time; `enforce` since, see *Final setup and docs*) reports and starts anyway; `OM_POLICY=enforce` refuses the file. `om policy check [--all]` runs it alone. A service can waive a rule for itself with `om.policy.allow=host-namespace|caps|devices|unconfined|mounts` (comma-separated); waivers stay listed by `om policy check`. `privileged` and `ports` cannot be waived, and an unknown rule is itself a violation.
- Outbound access is per service (ADR 0002): new workspace networks are `internal` (no route out, no external DNS); `om network harden` converts an existing one. New core container `om_egress` (Squid, hardened, pinned) lets a service reach only the hosts in its `om.egress` label, with its own credential injected by om (`om.egress=internet` only without writable volumes or secrets; `om.egress=learn` temporarily allows any public host and records each one; `om doctor` warns while it is on). `om egress log` prints the hosts a learning service used, or the hosts a listed service was refused, with the label to set. `om doctor` probes each internal network (*Egress*).
- Core images pinned by multi-arch index digest as well as version (`caddy:2.11.6@sha256:…`), so a re-pushed tag cannot change what runs.

### Reproducible
- Core images pinned to exact versions (`caddy:2.11.6`, `python:3.14.8-alpine`); `om add` scaffolds `nginx:1.31-alpine` / `node:24-alpine` instead of moving tags. The same om version now runs the same core everywhere.

### Builds
- `om start --build` / `om restart --build` rebuild images of services with a `build:` section; `om dev` and `om sync` (incl. autosync) always rebuild, so a pulled Dockerfile change is applied.
- `om update` rebuilds any service with `build:` (any Dockerfile/Containerfile name), not only a file named `Dockerfile`, and reports build failures.
- `om start` warns when a compose file doesn't join `<ws>_net` (its routes would return 502).

### Several people
- `om auth add|remove|list <user>`: one private-tier login per person (`set` still replaces all).
- `OM_HTTP_PORT` / `OM_HTTPS_PORT` in `om.env` (default 80/443) let a second OS user run om on the same machine; firewall, doctor, health checks, CLI URLs and dashboard links follow them.

### Docs
- `om docs [name] [--path]` lists the guides or reads one in a pager.
- A developer guide (now part of `docs/GUIDE.md`): creating containers, when to rebuild an image, debugging a workspace.

### Known limitations
- Without a running engine, routes come from a line-based reader of the compose file that does not
  understand flow-style `labels: [...]`; with the engine (the normal case) any style works.
- Custom `OM_HTTP_PORT` / `OM_HTTPS_PORT` are unit-tested only, not yet with a real second OS user.
- Verified live on Arch Linux with rootless Podman only. macOS, Windows and other Linux setups are covered
  by the CI workflow, which has not run yet (see docs/REMAINING.md).
- Existing installs switch to the pinned core images on the next `om core update`.

## 1.0.0 — 2026-10-06

First release intended for use on any machine.

### Security
- **Edge/router split.** The edge proxy (`om_caddy`) is no longer attached to workspace networks; an internal router (`om_router`) is, and it forwards only requests carrying a 256-bit secret known to the edge. Containers can no longer reach the private tier, Portainer, or other workspaces. Works identically on Podman, Docker and Docker Desktop.
- Private tier answers only an explicit host list (DNS-rebinding safe); dashboard enforces a host allowlist and CSRF checks.
- Host firewall generator for Linux (nftables), macOS (pf) and Windows (`om firewall`).
- Optional login for the whole private tier (`om auth set <user>`).
- Services are scaffolded with `expose:` (never `ports:`); `om start`, `om ports` and `om doctor` flag published ports.
- Hardened core containers (read-only root, minimal capabilities, no-new-privileges); `trusted_proxies` removed at the edge.
- Dashboard: workspace ids validated (no path traversal), public scope pinned to core data, safe uploads, no SVG from the dashboard origin.
- Secrets vault `om-v2`: encrypt-then-MAC (HMAC-SHA256), PBKDF2 600k; `om-v1` still decrypts.
- Caddy CA keys, tokens and runtime state are git-ignored.

### Reliability
- Machine-specific values (LAN/Tailscale addresses, engine socket, wallpapers) are detected at `om core start` (`core/.env`: `auto`/`off`/value); no hard-coded user paths or IPs.
- `om core start/restart` reattaches the router to every workspace and verifies all core containers stay up.
- Self-heal (`om core heal`, scheduled by `om boot enable` at boot and every 2 minutes): recovers from a new LAN address, Tailscale coming up late, or a crashed core container; respects a deliberate `om core stop`.
- GitOps: refuses dirty trees, reconciles containers after a pull, health-checks every vhost, rolls back, and quarantines a failing remote commit for scheduled syncs.
- Route generator records ownership in each file, prunes stale routes (incl. on `om list --prune`), detects subpath collisions, validates names.
- Edge reload validates first and recreates the edge if its Caddyfile bind mount is stale.
- LAN HTTPS works (certificate for the LAN IP, used when clients send no SNI).

### New commands
`remove`, `logs`, `shell`, `update`, `doctor`, `auth`, `firewall`, `boot`, `autosync`, `secrets`, `completion`, `uninstall`, `version`/`--version`, `core update`, `list --prune`.

### Fixed
- `om add` produced services that answered 502 (nginx listens on 80) and projects that exited immediately.
- `om core start/restart` left workspaces unreachable.
- `om list` silently deleted registry entries for unplugged drives.
- Windows: no `fcntl`; scripts can be `.ps1`; colors via VT mode; installer `install.ps1`.
