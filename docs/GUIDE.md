# om — Guide

Everything you do with om, from install to debugging. Read it in the terminal with `om docs guide`.
How the network is built: `om docs architecture`. Why om is built this way: `om docs design`.

---

## 1. om in one page

om works like git, for the containers your code runs.

| git | om | What it is |
| :--- | :--- | :--- |
| `/usr/bin/git` | `~/.om/` | The program only. Reinstall or update it freely. |
| `~/.gitconfig` | `~/.config/om/om.env` | Your machine settings (`auto` / `off` / value). |
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

The installer checks Python 3.10+, Podman (or Docker) and compose; allows rootless engines to bind
80/443 (one sudo step); installs the `om` command; sets up SSH-signed git commits (then refuses
unsigned deploys); asks which VPNs on the machine to trust; and offers to start the core, start it at boot,
and apply the host firewall. Re-running it is safe. Afterwards, `om doctor` must show no `FAIL`.

An existing workspace on another machine: `git clone <repo> && cd <repo> && om start` — om registers
it, starts the core and pins nothing new (the lock comes with the repo). Secrets: see §8.

---

## 3. Workspaces

`om init [id]` turns the current folder into a workspace (id = folder name: lowercase letters,
digits, `-`; `core` is reserved). It writes `.om/config.json` and `.om/allowed_signers` (your
signing key).

om finds compose files (`docker-compose.yml|yaml`, `compose.yml|yaml`) at the workspace root and
one or two folders down — `services/`, `projects/` and any names you like. Folders such as `data`,
`.om`, `.git`, `docs` and `scripts` are skipped, and so is any folder containing an `.omignore`
file (with everything below it).

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
in `.om/lock.json`. Edit the file freely afterwards; `om edit <svc> --scope public|private --port P`
changes labels for you.

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

Other labels: `dashboard.name|icon|description|hide|web|path` (dashboard card),
`dashboard.path=/x/` (where the dashboard link opens on the service's address),
`om.route.keep_prefix=true` (the app serves under `/<svc>/`; its root redirects there),
`om.route.aliases=/a,/b` (paths on the dashboard's address that redirect to the service),
`om.route.dashboard_paths=/api/x*` (paths on the service's address answered by the dashboard).

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
| Want newer images | `om update --dry-run`, then `om update` (pins new digests, commits the lock, redeploys) |

`om status` shows "updates N available" when the heal timer found newer digests.
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
that fails its health check is rolled back once and skipped until a new one is pushed. Log:
`~/.local/state/om/logs/autosync.log`.

---

## 7. Let a service call the internet

Workspace networks are internal: a container cannot resolve or reach anything outside its
workspace unless its labels say so. om then gives that service (and only it) `HTTP(S)_PROXY`
settings with its own credential for `om_egress`, which allows exactly the listed hosts.

```yaml
labels:
  - "om.egress=api.example.com,*.githubusercontent.com"   # *. covers subdomains
  # - "om.egress=learn"      # temporarily: any public host, each one recorded
  # - "om.egress=internet"   # anything public — only for services with no writable volume and no secrets
```

Don't know the hosts? Set `om.egress=learn`, use the service normally, then `om egress log`: it
lists what was used and the exact `om.egress=…` line to paste. Private addresses are never allowed.
Apps that ignore `HTTP(S)_PROXY` have no way out; configure their proxy setting. A workspace whose
network predates this is open until `om network harden` (`om doctor` lists them).

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
  up): `http://archlinux:20001/`, `http://10.8.0.1:20001/`. Keep joining the VPN to devices you
  approve (with Tailscale: Tailnet Lock — `tailscale lock sign nodekey:…` for each new device).
- **Only your devices, not everything on the VPN:** `om vpn allow <device>` (an address, a range, or
  the name the VPN's DNS gives it, e.g. `om vpn allow my-tablet`). Only listed devices reach the
  private tier over the VPN; every other VPN device gets the public tier only. Where om's firewall is
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
  person; `om auth list|remove|off`). `om doctor` warns when other accounts can log in here and there
  is none. A second OS user can run their own om with `OM_HTTP_PORT` / `OM_HTTPS_PORT` (e.g. 8081/8444).
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

Service data lives in the workspace's `data/` (git-ignored): back it up and the workspace can be
rebuilt anywhere. om's own state lives in `~/.local/state/om/`; `data/caddy/pki/` there holds the
local CA key for `https://*.localhost` — keep it private.

Scripts, editors and CI can read om: `om status|routes|log|doctor|list|links|vpn --json` print JSON
(`om doctor --json` exits 1 on any failure).

---

## 13. Debugging

Work from the outside in, the path a request takes:

| Step | Command | Look for |
| :--- | :--- | :--- |
| 1. Is om healthy? | `om doctor` | Any `FAIL` / `WARN`; each prints its fix. |
| 2. Is the core up? | `om core status` | Fix: `om core restart`. |
| 3. Is my container running? | `om status` | A stopped or restarting service. |
| 4. What did it say? | `om logs <svc> -f` | Crashes, wrong port, missing env. |
| 5. Does om route to it? | `om routes` | The `→ <ws>_<svc>:<port>` target must be the app's port inside the container. |
| 6. Right network? | `om network` | The container must be on `<ws>_net`. |
| 7. Does it answer inside? | `om shell <svc> wget -qO- localhost:<port>` | Whether the app answers at all. |
| 8. Blocked outbound? | `om egress log` | Hosts refused, with the line that allows them. |
| 9. Who knocked, who got in? | `om firewall log` | Refused connections and connections to om's ports with their real source, mapped to services; the edge's request counts per site (no URLs). |

| Symptom | Usual cause | Fix |
| :--- | :--- | :--- |
| **502** | Container down, wrong `dashboard.port`, not on `<ws>_net`, flow-style labels | Steps 3–6. |
| **404 / refused on the URL** | No route yet | `om start <svc>` or `om reload`. |
| **401** | Private-tier login is on | Log in; `om auth list`. |
| **403 from the LAN** | The service is private | `om edit <svc> --scope public`. |
| Old code still served | Image not rebuilt | `om restart <svc> --build`. |
| Deploy refused | Policy gate, or an unsigned commit | The message names the rule or the signing step. |
| `om sync` refuses / rolled back | Dirty tree / failed health check | Commit or stash / read `om logs <svc>`. |
| Port 80/443 in use | Another web server or another user's om | Stop it, or set `OM_HTTP_PORT` / `OM_HTTPS_PORT`, then `om core restart`. |
| `*.localhost` fails in curl | Some OSes resolve it only in browsers | `curl -H 'Host: <ws>.<svc>.localhost' http://127.0.0.1/`. |

Don't: edit `~/.local/state/om/routes/` (regenerated), run `podman compose up` in `~/.om/core/`
(use `om core …`), attach services to `om_core_net`, or add `ports:`.

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
