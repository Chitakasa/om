# Go rewrite: parity checklist

Generated from the Python om (`testdata/cli_spec.json`, golden help in `testdata/golden/help/`). Tick a row only when the Go version matches the Python behavior and has a ported test.

## Commands (51)

| Done | Command | Flags/args | Phase |
|---|---|---|---|
| [ ] | `om add` | name, --project, --port, --image, --public, --domain, --icon, --desc, --no-web | 3 |
| [ ] | `om auth` | action, user | 3 |
| [ ] | `om autosync` | action, --every | 3 |
| [ ] | `om boot` | action | 3 |
| [ ] | `om completion` | shell | 3 |
| [ ] | `om config` | action, arg, --reveal, --json | 1 |
| [ ] | `om core` | action, services | 3 |
| [ ] | `om dev` | project | 3 |
| [ ] | `om disable` | service | 3 |
| [ ] | `om docs` | name, --path | 3 |
| [ ] | `om doctor` | --json | 4 |
| [ ] | `om down` | - | 3 |
| [ ] | `om drift` | - | 3 |
| [ ] | `om edit` | service, --scope, --port, --icon, --desc, --name | 3 |
| [ ] | `om egress` | target, --apply, --since, --all | 2 |
| [ ] | `om enable` | service | 3 |
| [ ] | `om exposure` | --json | 2 |
| [ ] | `om firewall` | action, --since | 3 |
| [ ] | `om fsck` | - | 3 |
| [ ] | `om init` | name | 3 |
| [ ] | `om links` | --json | 2 |
| [ ] | `om list` | --json, --prune | 3 |
| [ ] | `om lock` | - | 3 |
| [ ] | `om log` | -n, --json | 3 |
| [ ] | `om logs` | service, --follow, --tail | 3 |
| [ ] | `om network` | action | 2 |
| [ ] | `om notify` | action | 3 |
| [ ] | `om policy` | action, --all | 2 |
| [ ] | `om ports` | - | 3 |
| [ ] | `om preview` | action, branch | 2 |
| [ ] | `om prune` | --yes | 3 |
| [ ] | `om reload` | - | 3 |
| [ ] | `om remove` | service, --data, --yes | 3 |
| [ ] | `om restart` | target, --build | 3 |
| [ ] | `om rm` | service, --data, --yes | 3 |
| [ ] | `om rollback` | generation | 3 |
| [ ] | `om routes` | --json | 2 |
| [ ] | `om run` | script, args | 3 |
| [ ] | `om scan` | - | 3 |
| [ ] | `om script` | - | 3 |
| [ ] | `om scripts` | - | 3 |
| [ ] | `om secrets` | action, file, destination, --output, --allow-unauthenticated | 3 |
| [ ] | `om shell` | service, cmd | 3 |
| [ ] | `om start` | target, --build | 3 |
| [ ] | `om status` | --json | 3 |
| [ ] | `om stop` | target, --all | 3 |
| [ ] | `om sync` | --force, --rebase, --scheduled | 3 |
| [ ] | `om uninstall` | --purge, --yes | 3 |
| [ ] | `om update` | target, --dry-run, --image, --choose | 3 |
| [ ] | `om version` | - | 1 |
| [ ] | `om vpn` | action, name, --json, --no-apply | 3 |

## Python modules → Go packages (9064 lines in lib/gitops)

| Done | Module | Lines | Go package | Phase |
|---|---|---|---|---|
| [ ] | `agesecrets.py` | 179 | `internal/secrets` | 3 |
| [ ] | `cli.py` | 23 | `cmd/om` | 3 |
| [ ] | `cliparser.py` | 284 | `cmd/om` | 3 |
| [ ] | `core.py` | 320 | `internal/sys` | 1 |
| [ ] | `corewatch.py` | 93 | `internal/engine` | 3 |
| [ ] | `docscmd.py` | 62 | `cmd/om` | 3 |
| [ ] | `doctor.py` | 884 | `internal/doctor` | 4 |
| [x] | `egress.py` | 630 | `internal/egress` | 2 |
| [ ] | `engine.py` | 261 | `internal/engine` | 3 |
| [x] | `enginectl.py` | 285 | `internal/engine` | 1 |
| [ ] | `exposure.py` | 159 | CLI layer (`om exposure`; needs hostsetup, routesview, securitycmds) | 3 |
| [ ] | `firewalllog.py` | 92 | `internal/host` | 3 |
| [ ] | `generations.py` | 285 | `internal/deploy` | 3 |
| [ ] | `hostcmds.py` | 225 | `internal/host` | 3 |
| [ ] | `hostsetup.py` | 752 | `internal/host` | 3 |
| [x] | `limits.py` | 68 | `internal/labels` | 1 |
| [x] | `links.py` | 121 | `internal/links` | 2 |
| [ ] | `lock.py` | 228 | `internal/deploy` | 3 |
| [ ] | `migration.py` | 85 | `internal/state` | 1 |
| [~] | `network.py` | 156 | `internal/network` (all but `reload_caddy`, which needs `core_compose`+`write_runtime_files`: lands with `core.py`) | 2 |
| [ ] | `notify.py` | 129 | `internal/notify` | 3 |
| [~] | `omsettings.py` | 395 | `internal/settings` (all but `write_runtime_files`, which composes stream, hostsetup and egress hooks: lands with `core.py`) | 1 |
| [x] | `omstate.py` | 244 | `internal/state` | 1 |
| [x] | `policy.py` | 283 | `internal/policy` | 2 |
| [x] | `previews.py` | 44 | `internal/previews` | 2 |
| [ ] | `prune.py` | 67 | `internal/workspace` | 3 |
| [x] | `routes.py` | 303 | `internal/routes` | 2 |
| [ ] | `routesview.py` | 126 | CLI layer (`om routes`, `om ports`; needs hostsetup + emit_json) | 3 |
| [x] | `routesync.py` | 315 | `internal/routesync` | 2 |
| [ ] | `scaffold.py` | 266 | `internal/scaffold` | 3 |
| [ ] | `scan.py` | 35 | `internal/deploy` | 3 |
| [ ] | `scripts.py` | 41 | `internal/workspace` | 3 |
| [ ] | `secrets.py` | 87 | `internal/secrets` | 3 |
| [ ] | `securitycmds.py` | 201 | `internal/secrets` | 3 |
| [ ] | `settingscmd.py` | 189 | `internal/settings` | 1 |
| [x] | `stream.py` | 393 | `internal/stream` | 2 |
| [x] | `svclabels.py` | 11 | `internal/labels` | 1 |
| [x] | `vpndetect.py` | 204 | `internal/netdetect` | 1 |
| [ ] | `vpndevices.py` | 92 | `internal/host` | 3 |
| [x] | `workspace.py` | 230 | `internal/workspace` (engine socket is a parameter; `engine()` cache arrives with enginectl) | 1 |
| [x] | `wsregistry.py` | 217 | `internal/workspace` | 1 |
| [ ] | `bin/om` (cmd_* functions) | 1841 | `cmd/om` | 3 |
| [ ] | `core/dashboard/app/server.py` + `index.html` | 1058 | `internal/dashboard` (go:embed) | 5 |
| [ ] | `install.sh` / `install.ps1` | 231 | fetch/build binary | 6 |

## Other surfaces

- [ ] Settings/env: `OM_*` (28 names in code; documented in docs/SETTINGS.md)
- [ ] Service labels `om.*` (docs/LABELS.md)
- [ ] `om doctor` checks (docs/DOCTOR.md): Basics, Perimeter, Python→Go replaced
- [ ] Generated artifacts byte-identical: Caddy routes, nft rules, compose output
- [ ] Cross-platform: UTF-8, `\n` writes, Windows paths
- [ ] Tests: 54 Python test files ported to Go `_test.go` (attack, fuzz, perimeter included)
- [ ] CI: replace ruff/unittest with `go vet`, `go test -race`, coverage floor
- [ ] Docs: update Python mentions (README badge, START, CONTRIBUTING, CLAUDE.md)
