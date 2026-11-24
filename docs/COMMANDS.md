<!-- Generated from the code (internal/cli/refdocs.go): do not edit. Run `go test ./internal/cli -run TestReferenceDocs -update` after a change. -->
# Commands

Every `om` command, grouped as in `om --help`. A workspace command needs a folder with `.om/config.json` (`om init` makes one); the others work anywhere. New to om? Start with [START.md](START.md); for how to do a task, see [GUIDE.md](GUIDE.md).

## Everyday

### `om init`

Initialize a workspace in the current directory

```text
om init [name]
```

| Argument | Meaning |
| :--- | :--- |
| `name` | Workspace id (default: directory name) |

### `om add`

Scaffold a service or project

```text
om add [name] [--interactive] [--project] [--port PORT] [--image IMAGE] [--public] [--domain DOMAIN] [--icon ICON] [--desc DESC] [--no-web]
```

| Argument | Meaning |
| :--- | :--- |
| `name` | Service name: lowercase letters, digits, - (left out: asked) |
| `-i, --interactive` | Ask the questions (also what `om add` alone does on a terminal) |
| `--project` | Live-reload dev project in projects/ |
| `--port PORT` | Port the container listens on |
| `--image IMAGE` | Container image (requires --port) |
| `--public` | Also expose on the LAN (public tier) |
| `--domain DOMAIN` | Informational domain label |
| `--icon ICON` | Emoji for the dashboard card |
| `--desc DESC` | Description for the dashboard card |
| `--no-web` | Background daemon without web UI |

### `om start`

Start services (and the core if needed)

```text
om start [target] [--build]
```

| Argument | Meaning |
| :--- | :--- |
| `target` | One service or project (default: all of them) |
| `--build` | Rebuild images of services with a build: section |

### `om stop`

Stop services (core stays up)

```text
om stop [target] [--all]
```

| Argument | Meaning |
| :--- | :--- |
| `target` | One service or project (default: all of them) |
| `--all` | Also stop the Global Core |

### `om restart`

Restart services

```text
om restart [target] [--build]
```

| Argument | Meaning |
| :--- | :--- |
| `target` | One service or project (default: all of them) |
| `--build` | Rebuild images of services with a build: section |

### `om status`

Show core and workspace status

```text
om status [--json]
```

| Argument | Meaning |
| :--- | :--- |
| `--json` | Machine-readable output |

### `om logs`

Show a service's logs

```text
om logs <service> [--follow] [--tail TAIL]
```

| Argument | Meaning |
| :--- | :--- |
| `service` | The service whose logs to show |
| `-f, --follow` | Keep following new lines |
| `-n, --tail TAIL` | How many recent lines to show first Default: 100. |

### `om doctor`

Diagnose the installation and security perimeter

```text
om doctor [--json]
```

| Argument | Meaning |
| :--- | :--- |
| `--json` | Machine-readable output (exit code 1 on any failure) |

## Services

### `om edit`

Edit a service's labels (scope, port, icon, ...)

```text
om edit <service> [--scope SCOPE] [--port PORT] [--icon ICON] [--desc DESC] [--name NAME]
```

| Argument | Meaning |
| :--- | :--- |
| `service` | The service to change |
| `--scope SCOPE` | private (this machine and your VPN) or public (the LAN too) One of: public, private. |
| `--port PORT` | The container port om routes to |
| `--icon ICON` | Emoji for the dashboard card |
| `--desc DESC` | Description for the dashboard card |
| `--name NAME` | Title of the dashboard card |

### `om remove`

Remove a service (moved to .om/trash) (alias: `om rm`)

```text
om remove <service> [--data] [--yes]
```

| Argument | Meaning |
| :--- | :--- |
| `service` | The service to remove |
| `--data` | Also move data/<service> to the trash |
| `-y, --yes` | Do not ask for confirmation |

### `om disable`

Stop a service and keep it off (reversible with `om enable`)

```text
om disable <service>
```

| Argument | Meaning |
| :--- | :--- |
| `service` | The service to stop and keep off |

### `om enable`

Undo `om disable`

```text
om enable <service>
```

| Argument | Meaning |
| :--- | :--- |
| `service` | The service to switch back on |

### `om shell`

Open a shell (or run a command) in a service

```text
om shell <service> [cmd…]
```

| Argument | Meaning |
| :--- | :--- |
| `service` | The service to open a shell in |
| `cmd` | A command to run there instead of a shell |

### `om dev`

Start a project and follow its logs

```text
om dev <project>
```

| Argument | Meaning |
| :--- | :--- |
| `project` | The project to start (a folder in projects/) |

### `om update`

Move pinned images to the newest digests, commit the lock, redeploy

```text
om update [target] [--dry-run] [--image REF] [--choose]
```

| Argument | Meaning |
| :--- | :--- |
| `target` | Only this service's folder (default: the whole workspace) |
| `--dry-run` | Only show which images have newer digests |
| `--image REF` | Only update this image (as `--dry-run` prints it); repeatable |
| `-i, --choose` | Ask for each image with a newer digest |

### `om scripts`

List workspace scripts

```text
om scripts
```

### `om run`

Run a workspace script

```text
om run <script> [args…]
```

| Argument | Meaning |
| :--- | :--- |
| `script` | The script's name, without extension, from scripts/ |
| `args` | Arguments passed on to the script |

### `om routes`

Show this workspace's URLs

```text
om routes [--json]
```

| Argument | Meaning |
| :--- | :--- |
| `--json` | Machine-readable output |

### `om preview`

Run a branch as its own throw-away workspace: om preview <branch> \| rm <branch> \| list

```text
om preview [action] [branch]
```

| Argument | Meaning |
| :--- | :--- |
| `action` | <branch> to start it, rm <branch>, or list |
| `branch` | The branch to run (with rm: the preview to remove) |

## Deploy and GitOps

### `om sync`

Pull from git, reconcile, health-check, roll back on failure

```text
om sync [--force] [--rebase] [--scheduled]
```

| Argument | Meaning |
| :--- | :--- |
| `--force` | Reset to the remote branch |
| `--rebase` | Rebase local commits onto the remote |
| `--scheduled` | (used by the scheduler) sync all auto-sync workspaces |

### `om autosync`

Scheduled GitOps sync for this workspace

```text
om autosync <action> [--every EVERY]
```

| Argument | Meaning |
| :--- | :--- |
| `action` | on, off or status One of: on, off, status. |
| `--every EVERY` | Minutes between syncs (with 'on') |

### `om drift`

Compare the workspace with its git remote

```text
om drift
```

### `om lock`

Pin images missing from .om/lock.json to their registry digest

```text
om lock
```

### `om log`

Generations of this workspace (deploy history)

```text
om log [-n N] [--json]
```

| Argument | Meaning |
| :--- | :--- |
| `-n N` | Show only the last N |
| `--json` | Machine-readable output |

### `om rollback`

Deploy an earlier generation's commit (default: the previous one)

```text
om rollback [generation]
```

| Argument | Meaning |
| :--- | :--- |
| `generation` | The generation number (default: the previous clean one) |

### `om fsck`

Verify generation chain, signature, and running images against the lock

```text
om fsck
```

### `om secrets`

Service secrets (age): init, set <project>/<name>, list, rekey; decrypt / migrate <file> <project>/<name> read and move old om-v2 files

```text
om secrets <action> [file] [destination] [--output OUTPUT] [--allow-unauthenticated]
```

| Argument | Meaning |
| :--- | :--- |
| `action` | init, set, list, rekey, decrypt or migrate One of: init, set, list, rekey, decrypt, migrate. |
| `file` | decrypt / migrate: the old secret file |
| `destination` | migrate: <project>/<name> to store the secret under (age) |
| `-o, --output OUTPUT` | decrypt: write the plain text to this file instead of printing it |
| `--allow-unauthenticated` | read an old om-v1 file, which has no integrity check |

### `om policy`

Check compose files against the policy gate

```text
om policy [action] [--all]
```

| Argument | Meaning |
| :--- | :--- |
| `action` | check (the only action) One of: check. |
| `--all` | Check every registered workspace |

## Network and security

### `om exposure`

Who can reach what: this machine, the VPN's devices, the LAN; per service, its address rules and outbound access

```text
om exposure [--json]
```

| Argument | Meaning |
| :--- | :--- |
| `--json` | Machine-readable output |

### `om vpn`

VPNs whose devices reach the private tier: list, trust\|untrust <iface>, allow\|disallow <device>, devices

```text
om vpn [action] [name] [--json] [--no-apply]
```

| Argument | Meaning |
| :--- | :--- |
| `action` | list (default), trust, untrust, allow, disallow or devices One of: list, trust, untrust, allow, disallow, devices. |
| `name` | trust/untrust: interface (wg0, zt…) or address; allow/disallow: device address, range or VPN name |
| `--json` | Machine-readable output (list) |
| `--no-apply` | allow/disallow: leave the host firewall alone (the VPN's private tier closes until `om firewall apply`) |

### `om firewall`

Host firewall: only om's ingress reachable; `log`: who was refused, who connected

```text
om firewall [action] [--since SINCE]
```

| Argument | Meaning |
| :--- | :--- |
| `action` | show, apply or remove the rules; status (default); or log One of: show, apply, remove, status, log. |
| `--since SINCE` | With log: how far back (default 24h) Default: 24h. |

### `om auth`

Require a login for the private tier

```text
om auth <action> [user]
```

| Argument | Meaning |
| :--- | :--- |
| `action` | set, add or remove a login; list them; off; or status One of: set, add, remove, list, off, status. |
| `user` | The login name (letters, digits, . _ -) |

### `om links`

Cross-workspace links (om.link / om.link.allow)

```text
om links [--json]
```

| Argument | Meaning |
| :--- | :--- |
| `--json` | Machine-readable output |

### `om network`

Show this workspace's network, or harden it (internal)

```text
om network [action]
```

| Argument | Meaning |
| :--- | :--- |
| `action` | show (default) or harden One of: show, harden. |

### `om egress`

Show refused outbound calls and the om.egress line to allow them

```text
om egress [target] [--apply] [--since SINCE] [--all]
```

| Argument | Meaning |
| :--- | :--- |
| `target` | Optional service name or 'log' |
| `--apply` | Write suggested om.egress line into the compose file |
| `--since SINCE` | How far back to read the proxy log (default 24h) Default: 24h. |
| `--all` | Every workspace, not only this one |

### `om ports`

Show host port bindings and any leaks

```text
om ports
```

## Platform and upkeep

### `om core`

Manage the Global Core (edge, router, dashboard)

```text
om core [action] [services]
```

```text
actions:
  status    core containers and the addresses they answer on (default)
  start     start the core: resolve om.env (LAN, VPN, ports), write its config, create the containers
  stop      stop the core; the self-heal timer leaves it stopped until `om core start`
  restart   whole core: re-detect LAN/VPN addresses, rewrite its config, recreate every container
            and re-attach them to the workspace networks (a few seconds of downtime)
  restart <names>
            only those containers, as they are (no re-detection), e.g. `om core restart router dashboard`
  reload    drop routes of deleted workspaces and hot-reload the edge's routes (no downtime)
  update    pull the core's pinned images and recreate what changed
  heal      what the self-heal timer runs: revive dead containers, restart on address changes
  watch     Linux, local engine: restart a container the moment its process dies unseen
```

| Argument | Meaning |
| :--- | :--- |
| `action` | What to do with the core (default: status) One of: start, stop, restart, reload, update, heal, watch, status. |
| `services` | with restart: only these core containers (caddy, router, egress, sockguard, dashboard) |

### `om config`

Settings in om.env: show, get <KEY>, set KEY=value (checked, file kept 0600), unset <KEY>

```text
om config [action] [arg] [--reveal] [--json]
```

| Argument | Meaning |
| :--- | :--- |
| `action` | show (default), get, set or unset One of: show, get, set, unset. |
| `arg` | get/unset: the setting (OM_POLICY); set: KEY=value |
| `--reveal` | show/get: print secret values (OM_NOTIFY_URL) instead of *** |
| `--json` | Machine-readable output (show) |

### `om boot`

Start containers automatically at boot

```text
om boot [action]
```

| Argument | Meaning |
| :--- | :--- |
| `action` | enable, disable or status (default) One of: enable, disable, status. |

### `om notify`

Notifications about image updates: `om notify test` sends one on every channel

```text
om notify [action]
```

| Argument | Meaning |
| :--- | :--- |
| `action` | test (the only action) One of: test. |

### `om list`

List registered workspaces

```text
om list [--json] [--prune]
```

| Argument | Meaning |
| :--- | :--- |
| `--json` | Machine-readable output |
| `--prune` | Forget workspaces whose folder no longer exists |

### `om prune`

List images nothing uses and no lock pins; --yes removes them

```text
om prune [--yes]
```

| Argument | Meaning |
| :--- | :--- |
| `-y, --yes` | Remove the images, not only list them |

### `om scan`

Count critical/high vulnerabilities in the pinned images (needs trivy or grype)

```text
om scan
```

### `om reload`

Regenerate routes and hot-reload the proxy

```text
om reload
```

### `om down`

Stop the workspace and the Global Core

```text
om down
```

### `om docs`

List om's docs, or read one (om docs guide \| architecture \| design)

```text
om docs [name] [--path]
```

| Argument | Meaning |
| :--- | :--- |
| `name` | guide, architecture, design, … (none lists them all) |
| `--path` | Print the file path instead (open it in an editor or browser) |

### `om completion`

Print a shell completion script

```text
om completion <shell>
```

| Argument | Meaning |
| :--- | :--- |
| `shell` | bash, zsh or fish One of: bash, zsh, fish. |

### `om version`

Print the version

```text
om version
```

### `om upgrade`

Upgrade om itself: pull the new code, rebuild, restart what runs the old build

```text
om upgrade [--core]
```

| Argument | Meaning |
| :--- | :--- |
| `--core` | Also restart the whole core (`om core restart`), needed when the changelog says its configuration changed |

### `om uninstall`

Stop om and remove its command

```text
om uninstall [--purge] [--yes]
```

| Argument | Meaning |
| :--- | :--- |
| `--purge` | Also delete ~/.om, ~/.local/state/om and ~/.config/om/om.env |
| `-y, --yes` | Do not ask for confirmation |
