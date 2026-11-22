# Go rewrite: parity checklist

Generated from the Python om (`testdata/cli_spec.json`, golden help in `testdata/golden/help/`; that program is no longer in the tree: its last commit on `main` is `9b19235`, and the file names below are its files at that commit). Tick a row only when the Go version matches the Python behavior and has a ported test. `[x]` = verified against Python (golden or end-to-end: `testdata/e2e/basic.sh`); `[~]` = ported, but needs a running engine to compare (e.g. `start`, `stop`, `update`, `core`) and is not yet differentially verified. The engine-dependent commands are `[x]` when `testdata/e2e/engine.sh` (a scenario against a fake engine, `internal/cli/e2e_test.go`) prints and calls the engine exactly as the Python version did; `om core watch`, `om uninstall --purge` and `om update` against newer registry digests are not in that scenario.

## Commands (51)

| Done | Command | Flags/args | Phase |
|---|---|---|---|
| [x] | `om add` | name, --project, --port, --image, --public, --domain, --icon, --desc, --no-web | 3 |
| [x] | `om auth` | action, user | 3 |
| [x] | `om autosync` | action, --every | 3 |
| [x] | `om boot` | action | 3 |
| [x] | `om completion` | shell | 3 |
| [x] | `om config` | action, arg, --reveal, --json | 1 |
| [x] | `om core` | action, services | 3 |
| [x] | `om dev` | project | 3 |
| [x] | `om disable` | service | 3 |
| [x] | `om docs` | name, --path | 3 |
| [~] | `om doctor` | --json | 4 |
| [x] | `om down` | - | 3 |
| [x] | `om drift` | - | 3 |
| [x] | `om edit` | service, --scope, --port, --icon, --desc, --name | 3 |
| [x] | `om egress` | target, --apply, --since, --all | 2 |
| [x] | `om enable` | service | 3 |
| [x] | `om exposure` | --json | 2 |
| [x] | `om firewall` | action, --since | 3 |
| [x] | `om fsck` | - | 3 |
| [x] | `om init` | name | 3 |
| [x] | `om links` | --json | 2 |
| [x] | `om list` | --json, --prune | 3 |
| [x] | `om lock` | - | 3 |
| [x] | `om log` | -n, --json | 3 |
| [x] | `om logs` | service, --follow, --tail | 3 |
| [x] | `om network` | action | 2 |
| [x] | `om notify` | action | 3 |
| [x] | `om policy` | action, --all | 2 |
| [x] | `om ports` | - | 3 |
| [x] | `om preview` | action, branch | 2 |
| [x] | `om prune` | --yes | 3 |
| [x] | `om reload` | - | 3 |
| [x] | `om remove` | service, --data, --yes | 3 |
| [x] | `om restart` | target, --build | 3 |
| [x] | `om rm` | service, --data, --yes | 3 |
| [x] | `om rollback` | generation | 3 |
| [x] | `om routes` | --json | 2 |
| [x] | `om run` | script, args | 3 |
| [x] | `om scan` | - | 3 |
| [x] | `om script` | - | 3 |
| [x] | `om scripts` | - | 3 |
| [x] | `om secrets` | action, file, destination, --output, --allow-unauthenticated | 3 |
| [x] | `om shell` | service, cmd | 3 |
| [x] | `om start` | target, --build | 3 |
| [x] | `om status` | --json | 3 |
| [x] | `om stop` | target, --all | 3 |
| [x] | `om sync` | --force, --rebase, --scheduled | 3 |
| [x] | `om uninstall` | --purge, --yes | 3 |
| [x] | `om update` | target, --dry-run, --image, --choose | 3 |
| [x] | `om version` | - | 1 |
| [x] | `om vpn` | action, name, --json, --no-apply | 3 |

## Python modules → Go packages (9064 lines in lib/gitops)

| Done | Module | Lines | Go package | Phase |
|---|---|---|---|---|
| [x] | `agesecrets.py` | 179 | `internal/secrets` | 3 |
| [x] | `cli.py` | 23 | `cmd/om` | 3 |
| [x] | `cliparser.py` | 284 | `cmd/om` | 3 |
| [x] | `core.py` | 320 | `internal/sys` | 1 |
| [x] | `corewatch.py` | 93 | `internal/engine` | 3 |
| [x] | `docscmd.py` | 62 | `cmd/om` | 3 |
| [~] | `doctor.py` | 884 | `internal/cli/doctor.go` | 4 |
| [x] | `egress.py` | 630 | `internal/egress` | 2 |
| [x] | `engine.py` | 261 | `internal/engine` | 3 |
| [x] | `enginectl.py` | 285 | `internal/engine` | 1 |
| [x] | `exposure.py` | 159 | CLI layer (`om exposure`; needs hostsetup, routesview, securitycmds) | 3 |
| [x] | `firewalllog.py` | 92 | `internal/host` | 3 |
| [x] | `generations.py` | 285 | `internal/deploy` | 3 |
| [x] | `hostcmds.py` | 225 | `internal/host` | 3 |
| [x] | `hostsetup.py` | 752 | `internal/firewall` + `internal/sched` | 3 |
| [x] | `limits.py` | 68 | `internal/labels` | 1 |
| [x] | `links.py` | 121 | `internal/links` | 2 |
| [x] | `lock.py` | 228 | `internal/deploy` | 3 |
| [x] | `migration.py` | 85 | `internal/state` | 1 |
| [x] | `network.py` | 156 | `internal/network` + `internal/core` (`reload_caddy`) | 2 |
| [x] | `notify.py` | 129 | `internal/notify` | 3 |
| [x] | `omsettings.py` | 395 | `internal/settings` + `internal/core` (`write_runtime_files`) | 1 |
| [x] | `omstate.py` | 244 | `internal/state` | 1 |
| [x] | `policy.py` | 283 | `internal/policy` | 2 |
| [x] | `previews.py` | 44 | `internal/previews` | 2 |
| [x] | `prune.py` | 67 | `internal/workspace` | 3 |
| [x] | `routes.py` | 303 | `internal/routes` | 2 |
| [x] | `routesview.py` | 126 | CLI layer (`om routes`, `om ports`; needs hostsetup + emit_json) | 3 |
| [x] | `routesync.py` | 315 | `internal/routesync` | 2 |
| [x] | `scaffold.py` | 266 | `internal/scaffold` | 3 |
| [x] | `scan.py` | 35 | `internal/deploy` | 3 |
| [x] | `scripts.py` | 41 | `internal/workspace` | 3 |
| [x] | `secrets.py` | 87 | `internal/secrets` | 3 |
| [x] | `securitycmds.py` | 201 | `internal/secrets` | 3 |
| [x] | `settingscmd.py` | 189 | `internal/settings` | 1 |
| [x] | `stream.py` | 393 | `internal/stream` | 2 |
| [x] | `svclabels.py` | 11 | `internal/labels` | 1 |
| [x] | `vpndetect.py` | 204 | `internal/netdetect` | 1 |
| [x] | `vpndevices.py` | 92 | `internal/host` | 3 |
| [x] | `workspace.py` | 230 | `internal/workspace` (engine socket is a parameter; `engine()` cache arrives with enginectl) | 1 |
| [x] | `wsregistry.py` | 217 | `internal/workspace` | 1 |
| [x] | `bin/om` (cmd_* functions) | 1841 | `cmd/om` (every command compared with Python, 17 against a fake engine; `om doctor` has its own row) | 3 |
| [x] | `core/dashboard/app/server.py` + `index.html` | 1058 | `internal/dashboard` (go:embed) | 5 |
| [x] | `install.sh` / `install.ps1` | 231 | build with Go or download + SHA-256 check into `build/`; run on a Linux, a macOS and a Windows runner in CI (build, verified download, a wrong checksum refused); the real release URL is untested (no release yet) | 6 |

## Other surfaces

- [x] Settings/env: `OM_*` (28 names in code; documented in docs/SETTINGS.md)
- [x] Service labels `om.*` (docs/LABELS.md)
- [~] `om doctor` checks (docs/DOCTOR.md): Basics and Perimeter ran live on rootless Podman in CI (31 PASS, 6 expected WARN, 0 FAIL, the live attack probes included); the Python-version check is replaced; Docker, SELinux, macOS and Windows are unverified
- [x] Generated artifacts byte-identical: Caddy routes, nft rules, compose output
- [~] Cross-platform: UTF-8, `\n` writes, Windows paths — `go vet` and the unit tests on Linux, macOS and Windows runners, the installers on all three; no container engine has run on macOS or Windows
- [~] Tests: 54 Python test files ported to Go `_test.go` (attack, fuzz, perimeter included) — replayed goldens for the library packages; attacks, fuzz, perimeter consistency, registry, id collisions, audit fixes and the repo guards ported by hand; securitycmds, settingscmd, exposure wording and test_cli unit cases rely on the e2e scenario (REMAINING.md section 0)
- [~] CI: replace ruff/unittest with `go vet`, `go test -race`, coverage floor — runs green on GitHub (go vet on three OSes, -race, coverage floors, cross-builds, Caddy and firewall syntax, installers on three OSes, the real-Podman integration job, gitleaks); the release workflow has not run (no tag yet)
- [x] Docs: update Python mentions (README badge, START, CONTRIBUTING, CLAUDE.md)
