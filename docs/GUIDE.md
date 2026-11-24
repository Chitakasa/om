# om — Guide

Everything you do with om, task by task. Read it in the terminal with `om docs guide`.

- **New to om?** Read [START.md](START.md) first: ten minutes from install to a running service.
- **Looking something up?** [COMMANDS.md](COMMANDS.md), [SETTINGS.md](SETTINGS.md), [LABELS.md](LABELS.md) and [GLOSSARY.md](GLOSSARY.md).
- **Something broken?** [TROUBLESHOOTING.md](TROUBLESHOOTING.md), then `om doctor` ([DOCTOR.md](DOCTOR.md)).
- **How it is built, and why:** `om docs architecture` and `om docs design`.

---

## 1. om in one page

om works like git, for the containers your code runs.

| git | om | What it is |
| :--- | :--- | :--- |
| `/usr/bin/git` | `~/.om/` | The program only. Reinstall or update it freely. |
| `~/.gitconfig` | `~/.config/om/om.env` | Your machine settings (`auto` / `off` / value). Mode 0600: `OM_NOTIFY_URL` (a webhook or ntfy topic) is a bearer-like secret; `om doctor` warns if the file is readable by others. |
| `.git/` | `.om/` in a workspace | Marks a folder as a workspace; `.om/config.json` is the only required file. |
| — | `~/.local/state/om/` | Generated state: routes, keys, registry, logs. Never edit by hand. |
| `git init` / `status` / `log` | `om init` / `om status` / `om log` | Create a workspace, see what runs, see what was deployed. |
| `git pull` | `om sync` | Pull, apply, health-check, roll back if unhealthy. |
| `git fsck` | `om doctor` | Check the install and every security promise, with a fix for each problem. |

On Windows, settings and state both live in `%LOCALAPPDATA%\om`; `OM_CONFIG_DIR` / `OM_STATE_DIR`
move them on any OS.

A **workspace** is a git repository of compose files. A **service** is one compose project in it:
its container is `<workspace>_<service>`, it sits on the sealed network `<workspace>_net`, and you
open it at `http://<workspace>.<service>.localhost`. om runs as your own user — never with `sudo`;
it asks for sudo itself for the few host steps that need it.

```text
browser ─► om_caddy (edge) ─► om_router (token check) ─► <ws>_net ─► <ws>_<svc>:<port>
                         routes are generated from your compose labels
```

---

## 2. Install

```bash
git clone <repo> ~/.om && ~/.om/install.sh        # Windows: install.ps1
```

The installer builds (or downloads and verifies) the `om` binary; checks Podman and a compose provider; allows rootless engines to bind
80/443 (one sudo step); installs the `om` command; sets up SSH-signed git commits (then refuses
unsigned deploys); asks which VPNs on the machine to trust; and offers to start the core, start it at boot,
and apply the host firewall. Re-running it is safe. Afterwards, `om doctor` must show no `FAIL`.

An existing workspace on another machine: `git clone <repo> && cd <repo> && om start` — om registers
it, starts the core and pins nothing new (the lock comes with the repo). Secrets: see §8.

### Platform notes

Linux only by design: `om core watch` (instant restart via pidfd), connection logging and
`om firewall log` (macOS and Windows log refusals only), and the firewall's forward path for rootful
engines. VPN device discovery is complete for mesh VPNs that route each device (Tailscale, Headscale on
Linux) and partial elsewhere (see docs/REMAINING.md).

- VPN discovery and names are verified on Linux; the macOS (`ifconfig`, `scutil`) and Windows (`Get-NetAdapter`) paths are unit-tested only. Per-service port ranges are verified with rootless Podman; on Podman machine they are untested.
- Linux rootless engines must be allowed to bind 80/443 (`net.ipv4.ip_unprivileged_port_start=80`); the installer and `om doctor` handle it.
- `*.localhost` names resolve natively in all major browsers; on some OSes CLI tools need `curl --resolve` (see `om doctor`).
- Several people: share a workspace through git (each runs om on their machine), give each person a login with `om auth add` (`om doctor` fails while another account can log in here and the private tier has no login; list accounts that are yours in `OM_TRUSTED_USERS`), and let a second OS user on the same machine use other front-door ports (`OM_HTTP_PORT` / `OM_HTTPS_PORT` in `om.env`).
- A VPN is optional: any VPN of your own devices works (Tailscale, Headscale, NetBird, WireGuard, ZeroTier…); om finds it and `om vpn trust <iface>` lets it in. Without one, the private tier is this machine only. Machine settings live in `~/.config/om/om.env` (`auto` / `off` / value); generated state in `~/.local/state/om/`, so `~/.om` is only the program.

---

## 3. Workspaces

`om init [id]` turns the current folder into a workspace (id = folder name: lowercase letters,
digits, `-`; `core` is reserved). It creates `services/`, `projects/`, `scripts/`, `data/`, `docs/`
and `.om/`, writes `.om/config.json` and `.om/allowed_signers` (your signing key), and a `.gitignore`
if there is none. Machine-local files (`.om/local.json`, `.om/state.json`, `.om/trash/`) are kept out of
git through `.git/info/exclude`, so they never dirty the tree.

om finds compose files (`compose.yml|yaml`, `docker-compose.yml|yaml`) at the workspace root and
one or two folders down — `services/`, `projects/` and any names you like. Folders such as `data`,
`.om`, `.git`, `docs`, `scripts`, `overrides`, `node_modules` and any starting with `.` are skipped, and
so is any folder containing an `.omignore` file (with everything below it; `om disable <svc>` writes
one, `om enable <svc>` removes it). A skipped folder that has a compose file is named in `om status` ("not managed
by om"), so a service that seems to be missing is easy to find; to hand it to om, delete its `.omignore`.

```yaml
# priority: 10          # optional first line: lower starts first (default 50)
```

Workspaces never bind host ports, so any number of them — even with identically named services —
run side by side: `http://containers.web.localhost` and `http://perso.web.localhost`.
`om list` shows every workspace on the machine.

---

## 4. Create a service

### a. Scaffold it
```bash
om add web                                # nginx → http://<ws>.web.localhost
om add api --project                      # Node app with live reload, in projects/api
om add search --image docker.io/searxng/searxng:<version> --port 8080 [--public]
om start                                  # starts everything (and the core if needed)
om routes                                 # prints every URL
```
`om add` writes the compose file with labels, network and hardening already set, and pins the image
in `.om/lock.json`. Every other label om reads is in the file too, commented and grouped (routing, access,
outbound traffic, resources, logging, dashboard) with an example and one line on what it does: uncomment what you need. Edit the file freely afterwards; `om edit <svc> --scope public|private --port P`
(also `--name`, `--icon`, `--desc`) changes labels for you and recreates the service. More `om add`
flags: `--icon`, `--desc`, `--domain` (informational), `--no-web` (a background daemon without a web
page). `--project` scaffolds a **Node.js** server (`node:24-alpine`, port 3000, `node --watch`); there is
no other language template: for anything else give your own `build:` (below) or an image with
`--image` and `--port`.

`om disable <svc>` stops a service and keeps it off (it also drops its routes); `om enable <svc>`
brings it back; `om remove <svc>` moves it to the trash. `om restart` is a stop followed by a start.

### b. Your own image
```yaml
# services/hello/compose.yml
services:
  hello:
    build:
      context: .
      dockerfile: Containerfile     # any name; Dockerfile is the default
    container_name: myws_hello      # <workspace>_<service>
    restart: unless-stopped
    security_opt: [no-new-privileges:true]
    labels:                         # one label per line
      - "workspace.id=myws"
      - "dashboard.port=8000"       # the port the app listens on INSIDE the container
      - "dashboard.scope=private"   # or public (see §9)
    expose: ["8000"]                # never `ports:`
networks:
  default:
    name: ${WORKSPACE_NET}          # required, or the route returns 502
    external: true
```
Then `om start --build`.

### c. Rules that save debugging time
- **`expose:`, never `ports:`.** A published port bypasses the edge; the policy gate refuses it.
- **Labels one per line** (`- "key=value"`): flow-style `labels: [...]` are not read for routing.
- **Pin image versions** (`nginx:1.31-alpine`, never `latest`); `om lock` pins the digest.
- **Mount only what a service needs**, never `/home` wholesale. Data goes in `data/<service>/`
  (`${WORKSPACE_DATA}`, git-ignored).
- The **policy gate** refuses `privileged`, host namespaces, the engine socket, sensitive mounts,
  added capabilities and devices, and says why. If a service truly needs one,
  `om.policy.allow=<rule>` waives it for that service (`privileged` and `ports` cannot be waived).
  `om policy check` lists everything.

Other labels: `dashboard.name|icon|description|hide|web|path` (dashboard card), `dashboard.url` (open this address instead of the service's own port; `http(s)://` or a path), `dashboard.search=true` with `dashboard.search_url=/search?q={searchTerms}` (the service is the browser's search engine, `/opensearch.xml`), `workspace.category` (reported by `/api/services`; the page does not group by it),
`dashboard.path=/x/` (where the dashboard link opens on the service's address),
`om.route.keep_prefix=true` (the app serves under `/<svc>/`; its root redirects there),
`om.route.aliases=/a,/b` (paths on the dashboard's address that redirect to the service),
`om.route.dashboard_paths=/api/x*` (paths on the service's address answered by the dashboard),
`om.tcp=<container-port>` (publishes raw TCP stream port, assigning default slot in 22000–22199),
`om.tcp.port=<host-port>` (publishes an explicit host port like 25565, scoped via `dashboard.scope`).

### d. Your own Caddy rules
Put an `om.caddy` file next to the service's compose file. om adds it to all of the service's
addresses and runs it before passing the request on:

```caddy
header Strict-Transport-Security "max-age=31536000"
@old path /legacy/*
redir @old /new{uri}
@admin path /admin*
basic_auth @admin {
    me $2a$14$...                   # caddy hash-password
}
```

### e. Raw TCP services (game servers, databases)
Non-HTTP services (like Minecraft, SSH or Redis) cannot use Caddy virtual hosts. Instead, declare `om.tcp`:
```yaml
services:
  mc:
    image: docker.io/itzg/minecraft-server:latest
    container_name: ${WORKSPACE_ID}_mc
    labels:
      - "om.tcp=25565"                 # container port
      - "om.tcp.port=25565"            # explicit host port (or omit for slot 22000+n)
      - "dashboard.scope=public"       # public binds LAN; private binds loopback + VPN
    expose: ["25565"]                  # never ports:
```
`om` publishes the host port on `om_stream_edge`, routes it over private Unix sockets to `om_stream_router`, and enforces firewall filtering without compromising workspace isolation. For Java services needing outbound downloads through `om_egress`, provide proxy settings via `JAVA_TOOL_OPTIONS` (see ADR 0005).

Allowed: `header`, `request_header`, `redir`, `rewrite`, `uri`, `respond`, `encode`, `basic_auth`,
`request_body`, `error`, `abort`, `vars`, `map`, `method`, the blocks `handle`, `handle_path`,
`route`, and named matchers (`@x path|host|method|header|query|remote_ip|expression|not…`). Refused:
anything that reads files, reaches another upstream or reads om's environment (`file_server`, `root`,
`reverse_proxy`, `import`, `{$…}`, `{env.…}`, `{file.…}`). A refused file leaves the service
**without a route** until it is fixed — the rules may be what protects it. `om routes` and
`om doctor` mark services that carry one.

---

## 5. Change, rebuild, update

om never rebuilds an image unless you ask, or `om sync` pulls new commits.

| You changed… | Do this |
| :--- | :--- |
| Code in a `--project` (bind-mounted) | nothing — the dev server reloads it (`om dev <svc>` shows live logs) |
| Code `COPY`'d into an image, the Dockerfile, dependencies | `om restart <svc> --build` |
| The compose file (image tag, env, volumes, labels) | `om start <svc>` |
| Only routing/dashboard labels | `om reload` |
| Nothing, but it is in a bad state | `om restart <svc>` |
| Cap a service's memory, processes or CPU | Labels on the service: `om.mem=256m`, `om.pids=200`, `om.cpus=0.5`. om passes them as a compose override at the next `om start`/`om update`; a value that does not parse is reported and ignored. They replace a limit the compose file sets itself |
| Free disk after updates | `om prune` lists images no container uses and no workspace lock pins (old digests, build leftovers); `om prune --yes` removes them with a plain `rmi`, never forced. It covers every project on this engine, so read the list first |
| Change a machine setting (ports, policy, notifications, extra firewall ports) | `om config show`, then `om config set OM_POLICY=warn`; `om config unset <KEY>` restores the default. Values are checked (a port must be 1-65535, `OM_NOTIFY_URL` https), the file stays 0600 and secrets print as `***` (`--reveal` shows them). The command says what to run next (`om core restart`, `om firewall apply`). `OM_VPN` / `OM_VPN_ALLOW` are set with `om vpn`. |
| Get told when something needs you | An image update, an auto-update applied or rolled back, a scheduled sync that failed (once per failing commit) and the core healing itself (a container restarted, the core recreated; at most once an hour per message) are announced. The dashboard card shows `⬆ update`. Messages go to `<state>/logs/notify.log`; desktop toasts are on by default (`OM_NOTIFY=auto`; `off` disables them); add `webhook` with `OM_NOTIFY_URL=https://ntfy.sh/<topic>` in `om.env` to get them on a phone too. Each new digest is announced once. `om notify test` tries every channel. The webhook leaves the machine and carries only the workspace and image names; desktop toasts need a graphical session, so a timer on a headless box may not reach them |
| See which pinned images have known vulnerabilities | `om scan` (needs trivy or grype on the machine; om ships neither). `om doctor` also warns about running services without a healthcheck, which updates and rollbacks cannot judge |
| Want newer images | `om update --dry-run` (per image: services using it, build date, size), then `om update` (pins new digests, commits the lock, redeploys). `om update --image REF` (repeatable) or `om update -i` (asks per image) moves only some. Label `om.update=hold` on a service keeps its image's pin where it is; `om update` skips it and `om status` stops listing it. Label `om.update=auto` (every service using the image must have it) lets the scheduled sync (`om autosync`) move that image at most every 6 hours: it commits the lock, redeploys and health-checks; if that fails it reverts the lock commit, redeploys the previous images and does not retry that digest (see `<state>/logs/autosync.log`) |
| Upgrade om itself | `om upgrade` (fast-forwards the checkout in `~/.om`, rebuilds through `install.sh`, refreshes the scheduled jobs, restarts the watcher and the dashboard; it refuses a checkout with uncommitted changes and never discards anything). The core's other containers keep running: `om upgrade --core` also restarts the whole core, which the changelog tells you when it is needed. Not `om update`, which moves service images. On Windows it pulls, then tells you to run `install.ps1` (a running `om.exe` cannot replace itself). |

`om status` shows "updates N available" when the heal timer found newer digests (it looks every 6
hours; `om update --dry-run` looks right now). The self-heal timer needs `om boot enable`, the
scheduled sync `om autosync on`.
`om remove <svc> [--data]` stops a service and moves its folder to `.om/trash`.

---

## 6. Deploy: signed commits and generations

Every `om start`, `sync`, `update` and `rollback` is a numbered **generation**: commit, dirty flag,
signer, lock and result. `om log` lists them; `om rollback [n]` deploys an earlier commit (volumes are
not rolled back); `om fsck` checks the log, the signature and that running images match the lock.

- A clean commit must be signed by a key in `.om/allowed_signers`. om checks it against its own copy
  from the last deploy, so a commit cannot add its own key; changing the list takes a commit signed
  by a key that is already trusted. With `OM_SIGNED=enforce` (set by the installer once signing
  works) unsigned or untrusted commits are refused.
- Uncommitted edits still run (`om start`, `om dev`), as a dirty, unsigned generation.

**Several machines:** push the workspace to a git remote; on each machine `om sync` pulls
(`--ff-only`, or `--rebase` / `--force`), redeploys, probes every route for 60 s and rolls back to the
previous commit if anything answers 5xx. It refuses a dirty tree. `om drift` shows ahead/behind/dirty.
`om autosync on --every 5` does it on a schedule (systemd timer, launchd or Task Scheduler); a commit
that fails its health check is rolled back once and skipped until a new one is pushed. The timer
fires every minute; each workspace's own interval (`--every`, kept in its machine-local
`.om/local.json`) decides whether it syncs. After a successful sync the same job also applies
`om.update=auto` image updates (§5). Log: `~/.local/state/om/logs/autosync.log`.

---

## 7. Let a service call the internet (Egress)

### What is Egress?
**Egress** is outbound network traffic that containers initiate towards the outside world — for example, fetching container assets, calling cloud APIs, downloading packages (npm/pip), syncing git repositories, or looking up external accounts/identities.

### Fail-Closed by Default
Workspace networks are created `--internal`:
- No route out to the internet or host network.
- No external DNS: external queries return `NXDOMAIN` to prevent data exfiltration.
- Containers can communicate only within their workspace network, with the router, and with `om_egress`.

### Granting Egress (`om.egress`)
To allow a service outbound access, declare `om.egress` in its labels:

```yaml
labels:
  - "om.egress=api.example.com,*.githubusercontent.com"   # *. covers subdomains
  # - "om.egress=audit"      # permanent: all public egress allowed & logged, no expiry (ideal for dynamic tools/extensions)
  # - "om.egress=learn"      # discovery: all public egress allowed & logged, expires after TTL (default 24h)
  # - "om.egress=internet"   # unlogged: any public destination (requires no writable volume/secrets or om.policy.allow=egress)
```

### Source-IP Identity (Zero Credentials)
`om` establishes container identity using deterministic **source-IP pinning**:
1. Each service with `om.egress` is automatically assigned a static IP on its internal network via an auto-generated compose override.
2. `om` renders Squid ACLs pairing each container's source IP with its declared destinations (`acl s_<id> src <ip>/32`).
3. Standard plain environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`) pointing to `http://om_egress:3128` are injected with **no credentials**.
4. Squid allows requests matching the source IP and destination allowlist; unlisted destinations return `403 Forbidden`. Private and link-local destination ranges are strictly blocked.

### Anti-Spoofing Requirement
To guarantee that one container cannot spoof another container's IP address on the shared bridge network, `om policy check` requires services with `om.egress` to drop `NET_RAW`:
```yaml
cap_drop:
  - NET_RAW # or ALL
```
Services keeping `cap_add: [NET_RAW]` or `NET_ADMIN` are refused by policy check. Services in one compose file share a trust domain.

### Java / JVM Runtimes
Most Linux runtimes (`curl`, Python, Node.js, Go) automatically use `HTTP_PROXY` and `HTTPS_PROXY`.
While the **Java Virtual Machine (JVM)** ignores lowercase environment variables by default, `om` automatically detects JVM services (or explicit `om.egress.jvm=true`, or its short form `om.jvm=true`) and merges standard proxy system properties into `JAVA_TOOL_OPTIONS`:
`-Dhttp.proxyHost=om_egress -Dhttp.proxyPort=3128 -Dhttps.proxyHost=om_egress -Dhttps.proxyPort=3128 -Dhttp.nonProxyHosts="localhost|127.0.0.1|::1"`

No manual proxy credentials or passwords (`proxyUser`, `proxyPassword`) are needed, preventing authentication failures in modern HTTP libraries such as OkHttp.

### The `learn` Workflow vs Permanent `audit` Mode
Don't know which hosts your application needs to reach?
1. **Discovery with `learn`:**
   Set `om.egress=learn`. In learn mode, outbound calls to any public destination are allowed, and every destination is recorded per service (`host`, `first_seen`, `count`).
2. Run `om egress log`: it displays all accessed hosts and prints the exact `om.egress=...` line to add.
3. Automatically apply the discovered hosts to your compose file:
   ```sh
   om egress log <svc> --apply
   ```
4. **Why Learn Mode Auto-Expires:**
   In secure production architectures, discovery is a transitional onboarding phase, not a permanent steady-state. Leaving open outbound access indefinitely creates a silent data-exfiltration risk. `learn` mode defaults to a 24-hour TTL (`DEFAULT_LEARN_TTL`) so that administrators review and pin the required domains into Git. If you want learn mode to run longer or never expire, set `om.egress.learn_ttl=7d` or `om.egress.learn_ttl=never`.
5. **Permanent Mode (`om.egress=audit`):**
   For applications that dynamically fetch external content (such as manga readers, scrapers, package managers, or apps with user-installable extensions like Suwayomi), static allowlists become brittle.
   `om.egress=audit` is the permanent, non-expiring mode:
   - Outbound traffic to any public destination is permanently permitted.
   - All contacted domains are continuously tracked and visible in `om egress log`.
   - Private networks (RFC 1918, loopback, link-local) remain strictly blocked by Squid.
   - Like `internet` and `learn`, services with writable volumes or secrets require `om.policy.allow=egress` to ensure deliberate operator waiver.
6. **Safety:** `om doctor` warns on any service in `learn` or `audit` mode, and fails if combined with writable volumes or secrets without explicit `om.policy.allow=egress`.

### Migration Note
Legacy basic authentication (`http://user:pass@om_egress:3128`) has been removed in favor of source-IP identity. Existing workspaces migrate automatically on `om start`. If your compose files have manual `JAVA_TOOL_OPTIONS` with `proxyUser` or `proxyPassword`, you can safely remove those credentials.

---

## 8. Secrets

```sh
om secrets init                       # once per workspace; commit .om/age-recipients
printf '%s' "$TOKEN" | om secrets set app/api_token
```
```yaml
services:
  app:
    secrets: [api_token]              # the service reads /run/secrets/api_token
secrets:
  api_token:
    file: ./secrets/api_token         # om decrypts ./secrets/api_token.age for it
```
Commit the `.age` file. It is decrypted only while the workspace runs, into memory, read-only, never
into environment variables. A plaintext secret file in the workspace is refused. Back up
`~/.local/state/om/data/age.key` off the machine; your SSH key can always decrypt as well.
`om secrets decrypt <file>` still reads files from the old built-in format.

**A second machine:** clone the workspace there and run `om secrets init` (it *adds* that machine to
`.om/age-recipients`); commit. Then, on a machine that can already decrypt — or there, if your SSH
key has no passphrase — `om secrets rekey` re-encrypts every secret for all recipients; commit.
`om start` then works on both.

---

## 9. Reach your services from other devices, and share them

| Who | URL | Sees |
| :--- | :--- | :--- |
| This machine | `http://<ws>.<svc>.localhost` | everything |
| Your devices on your VPN | `http://<machine>:<20000+n>/` (Tailscale name or VPN address) | everything |
| Anyone on your Wi-Fi | `http://<lan-ip>:<21000+n>/` | public services only |
| Guests your VPN lets in | `http://<vpn-ip>:<21000+n>/` | public services only |
| The internet | — | nothing |

Every web service gets its own port `n` (stable; `om routes` prints them, the dashboard links to
them), so each service is its own browser origin: one service's scripts can never read another's
pages or the dashboard's. The dashboard stays at `http://<machine>/` (public view on
`http://<lan-ip>/` or `http://<machine>.local/`), and `/<svc>` there redirects to the service's port.
Per-service *names* on other devices would need a DNS server every device is told to use, so om
doesn't do it; ports work with any VPN and no setup. Pages on other devices are plain HTTP — the VPN
encrypts the traffic, but browsers keep HTTPS-only features (installing as an app, offline mode,
camera/clipboard access) off there.

- **Your devices:** use any VPN whose members are only your devices (Tailscale, Headscale, NetBird,
  Nebula, ZeroTier, WireGuard, OpenVPN…). om finds every VPN on this machine by itself — the kernel
  reports each tunnel — but trusts none without your yes, because a tunnel can also be a commercial
  or company VPN or a public network: `om vpn` lists them, `om vpn trust <iface>` trusts one (the
  installer asks, `om doctor` reminds), `om vpn untrust <iface>` stops. Then `om firewall apply`.
  Devices use this machine's address on that VPN, or the name the VPN's own DNS gives it (om looks it
  up): `http://myhost:20001/`, `http://10.8.0.1:20001/`. Keep joining the VPN to devices you
  approve (with Tailscale: Tailnet Lock — `tailscale lock sign nodekey:…` for each new device).
- **Only your devices, not everything on the VPN:** `om vpn allow <device>` (an address, a range, or
  the name the VPN's DNS gives it, e.g. `om vpn allow my-tablet`). Only listed devices reach the
  private tier over the VPN; every other VPN device gets the public tier only — at the same address
  (`http://myhost/` shows it the public dashboard; Linux and macOS: the firewall sends it to the public
  tier) and at `http://myhost:8080/` (the only way on Windows). Where om's firewall is
  installed, `allow` and `disallow` update it right away (one sudo prompt), so the change is in
  effect at once and nobody loses access in between. If that is not possible (declined, no sudo,
  `--no-apply`, firewall not installed yet), the VPN's private tier is not bound at all until
  `om firewall apply` carries the list — a removed device never keeps access (this machine is
  unaffected); `om vpn` shows the list, `om vpn disallow <device>` removes one, `om doctor` checks.
  `om vpn` lists every device on the trusted VPNs — found in the kernel's routes through the VPN (any
  VPN: a route per peer, or a small subnet whose DNS names its members), on the allow-list, or in the
  firewall log — named through the VPN's own DNS, allowed or not, last seen, connected/refused.
- **Make a service public:** `dashboard.scope=public` (or `om add --public`, `om edit --scope public`).
- **Share with someone elsewhere:** share this machine with their VPN account (Tailscale: *Share*)
  and allow them only ports 8080 (the public dashboard) and 21000–21199 (public services) in your
  VPN's access rules.
- **Several people on one machine:** `om auth add <user>` puts a login on the private tier (one per
  person; `om auth list|remove|off`). `om doctor` fails when other accounts can log in here and there
  is none; accounts that are yours go in `OM_TRUSTED_USERS` in `om.env`. A second OS user can run their own om with `OM_HTTP_PORT` / `OM_HTTPS_PORT` (e.g. 8081/8444).
- **Only some devices, or not some devices:** label the service with the addresses (or ranges, IPv4
  or IPv6) that may reach it, or that never may; deny wins, and this machine is always allowed:

  ```yaml
  labels:
    - "om.net.allow=100.101.0.7,192.168.1.0/24"   # only these
    - "om.net.deny=192.168.1.66"                   # never these
    # - "om.net.allow=vpn"                         # exactly the devices on your VPN allow-list
  ```

  `vpn` stands for the VPN allow-list (`om vpn allow`) and follows it: change the list, run
  `om firewall apply`, and every service with `om.net.allow=vpn` has the new devices. Useful for a
  public service your own devices should reach but not the LAN. It mixes with addresses
  (`vpn,192.168.1.20`) and needs an allow-list (without one the service is refused).

  The host firewall enforces it on the service's own ports (`om firewall apply`): a refused address
  gets no answer at all, as if nothing were there. Until the firewall carries the rules the service
  has no port of its own (reachable on this machine only), and `om doctor` fails; `om routes` shows
  the rules. The edge cannot do this itself: rootless port forwarding hands it every connection from
  one internal address, so `om.caddy` refuses `remote_ip`/`client_ip`. Prefer VPN addresses: on a
  VPN an address belongs to a device's key, while anyone on your Wi-Fi can take a LAN address.
- **Logs, without your content:** the firewall logs refused connections and new connections to om's
  ports with their real source address (rate-limited; this machine's own connections never), and the
  edge logs what happened per request — site, method, status, size, time, login name — never the
  URL, query or headers — error entries included. `om firewall log` shows both. A service labelled
  `om.log=off` (e.g. a search engine) leaves no trace at all: no edge entry, no connection log, and
  the engine discards its own output (a search engine logs failed upstream URLs, query included), so
  `om logs` shows nothing for it; refusals are still logged, since a refused connection never used it.

---

## 10. Connect services across workspaces

A service in one workspace may use one service of another — a shared database, a cache, an API, any
protocol — when **both** say so:

```yaml
# app/services/web/compose.yml (the user)          # data/services/db/compose.yml (the provider)
labels:                                             labels:
  - "om.link=data/db"                                 - "om.link.allow=app/web"     # or app/*
```

om puts exactly those two containers on a private network of their own (no route out, nothing else
on it) and the user reaches the provider as `data-db` (e.g. `postgres://data-db:5432`). Nothing else
in either workspace becomes reachable. `om links` lists links and what blocks a one-sided one;
`om start` and the heal timer keep them attached when a container is recreated.

Inside one workspace the same holds between folders: each service folder runs on its own internal
network (`<ws>_<folder>_net`, `om network` lists them), so a compromised service cannot reach the
services of another folder. Services in one compose file share theirs (an app and its database).
Two folders that must talk use `om.link` (it works within a workspace too: `om.link=<ws>/<svc>`), or
`om.network=shared` on a service puts its folder back on the workspace-wide network.

This holds however the compose file is written: the workspace network and the implicit `default`
network become the folder's own network, networks the file defines itself become internal with a
per-folder name (so two folders' `backend` networks never meet), and every service joins the folder's
network so the edge can reach it. Joining another stack's network is refused by the policy gate
(rule `networks`, waivable with `om.policy.allow=networks`).

`om add` scaffolds start least-privileged: the default service is a non-root nginx
(`nginx-unprivileged`, port 8080) and the Node project run with no capabilities and a read-only
filesystem; an image of your choice keeps only the five capabilities most images need to start.
The scaffold lists the opt-in labels as comments: `om.egress`, `om.net.allow`, `om.log=off`.

---

## 11. Try a branch next to your workspace

```bash
om preview feature-x          # git worktree of the branch (created from here if new), started
                              # as workspace <ws>--feature-x: own network, data, ports
om preview                    # list previews
om preview rm feature-x       # stop it and delete its containers, data, routes, ports, worktree
```

The preview runs beside the original — open both at once — and never touches the original's data.
It needs container and network names written with the variables om sets
(`${WORKSPACE_ID:-…}_<svc>`, `${WORKSPACE_NET}`, as `om add` writes them); om says which line to change.

---

## 12. Scripts, data and scripting om

`om scripts` lists the workspace's `scripts/` (`.sh`, `.py`, `.ps1`); `om run <script> [args…]` runs
one with `WORKSPACE_ID`, `WORKSPACE_ROOT`, `WORKSPACE_DATA` and `WORKSPACE_NET` set.

A service that ships its own admin script next to its compose file is reached with a small wrapper *file* in
`scripts/` (`om run` refuses any script that resolves outside `scripts/`, so a symlink does not work), for example
`scripts/mytool/mytool.sh`: `#!/usr/bin/env bash` then `exec "$WORKSPACE_ROOT/services/mytool/admin" "$@"`, run as
`om run mytool status`. A tool that lives inside the container is `om shell <service> <command>`.

Service data lives in the workspace's `data/` (git-ignored): back it up and the workspace can be
rebuilt anywhere. om's own state lives in `~/.local/state/om/`; `data/caddy/pki/` there holds the
local CA key for `https://*.localhost` — keep it private.

Scripts, editors and CI can read om: `om status|routes|log|doctor|list|links|vpn --json` print JSON
(`om doctor --json` exits 1 on any failure).

---

## 13. Debugging

Run `om doctor`, then follow the path a request takes: [TROUBLESHOOTING.md](TROUBLESHOOTING.md) has the step-by-step
table, every common symptom with its cause and fix, and what not to do.

---

## 14. Everyday loop

```bash
cd ~/my-workspace
om start                       # bring it up
om dev api                     # live logs while you code (Ctrl+C detaches, keeps running)
om restart api --build         # after changing the Dockerfile or dependencies
git commit -am "…" && om start # a signed generation
om log                         # what ran when; om rollback if needed
```

Every command: `om --help`, or the table in `README.md`.
