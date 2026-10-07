# om — Developer Guide

How to build and debug your own work with om: create containers, know when an image must be
rebuilt, and find what is wrong when something breaks. Read it in the terminal with `om docs developer`.

---

## 1. Think of om like git

| git | om | What it is |
| :--- | :--- | :--- |
| `/usr/bin/git` (the program) | `~/.om/` | The program only. Reinstall or update it freely. |
| `~/.gitconfig` | `~/.config/om/om.env` | Your machine settings (`auto` / `off` / value). |
| `.git/` in a repo | `.om/` in a workspace | Marks a folder as a workspace. `.om/config.json` is the only required file. |
| — | `~/.local/state/om/` | Generated state: routes, CA, edge token, registry, logs. Never edit by hand. |
| `git init` | `om init [id]` | Turn the current folder into a workspace. |
| `git status` | `om status` / `om` | What is running here, and the core's health. |
| `git fetch && git status` | `om drift` | How this workspace differs from its git remote. |
| `git pull` | `om sync` | Pull, apply, health-check, roll back if unhealthy. |
| `git fsck` | `om doctor` | Check the install and security perimeter, and print a fix for each problem. |

On Windows, settings and state both live in `%LOCALAPPDATA%\om`. `OM_CONFIG_DIR` / `OM_STATE_DIR` move them on any OS.

A **workspace** is a git repo (or any folder) of compose files. A **service** is one compose
project inside it. Its container is named `<workspace>_<service>`, sits on the network
`<workspace>_net`, and is reached at `http://<workspace>.<service>.localhost`. Nothing else is
exposed: requests go edge proxy → router → your container.

```text
browser ─► om_caddy (edge) ─► om_router ─► <ws>_net ─► <ws>_<svc>:<port>
              ▲ routes are generated from your compose labels by `om start` / `om reload`
```

Teams work through git: everyone clones the workspace repo and runs om on their own machine
(`om sync`, or `om autosync on`). On a shared machine, give each person a login with
`om auth add <user>`. A second OS user can run their own om by setting `OM_HTTP_PORT` /
`OM_HTTPS_PORT` in their `om.env` (e.g. 8081/8444). The host firewall is machine-wide, so add
those ports to `OM_FIREWALL_EXTRA_TCP` of whoever runs `om firewall apply`.

---

## 2. Create a new container

### a. Quickest: scaffold it
```bash
om init                                   # once per workspace (id = folder name)
om add web                                # nginx → http://<ws>.web.localhost
om add api --project                      # Node app with live reload, in projects/api
om add search --image docker.io/searxng/searxng:<version> --port 8080 [--public]
om start                                  # starts everything (and the core if needed)
om routes                                 # prints every URL
```
`om add` writes `services/<name>/docker-compose.yml` (or `projects/<name>/`) with the labels,
network and hardening already set. Edit that file freely afterwards.

### b. Your own image (Dockerfile / Containerfile)
Put the build file next to a compose file anywhere up to two folders below the workspace root:

```yaml
# services/hello/compose.yml
# priority: 50                      # optional: lower numbers start first
services:
  hello:
    build:
      context: .
      dockerfile: Containerfile     # any name; Dockerfile is the default
    container_name: myws_hello      # <workspace>_<service>
    restart: unless-stopped
    security_opt: [no-new-privileges:true]
    labels:                         # one label per line: om reads labels line by line
      - "workspace.id=myws"
      - "dashboard.port=8000"       # the port your app listens on INSIDE the container
      - "dashboard.scope=private"   # or public (LAN can see it)
    expose: ["8000"]                # never `ports:` — that bypasses the proxy
networks:
  default:
    name: ${WORKSPACE_NET}          # required: without it the route returns 502
    external: true
```
Then `om start --build`. `om start` warns if a compose file doesn't join the workspace network.

Rules that save debugging time:
- **`expose:`, never `ports:`.** Published ports bypass the edge and are flagged by `om start` and `om doctor`.
- **Labels go one per line** (`- "key=value"`). om doesn't read flow-style `labels: [...]` for routing, so the route falls back to port 8080.
- **Pin image versions** (`nginx:1.31-alpine`, not `nginx:latest`). Then the same commit runs the same thing on every machine and every day.
- Persistent data goes in `data/<service>/` (`${WORKSPACE_DATA}`), which is git-ignored.

### c. Change a service's settings
`om edit <svc> --scope public|private --port P --name/--icon/--desc` rewrites the labels,
recreates the container and regenerates its routes.

### d. Deploys are generations
Each `om start` / `om sync` / `om update` / `om rollback` is a numbered **generation**: the commit,
whether the tree was dirty, who signed it, and the lock. `om log` lists them, `om rollback [n]`
deploys an earlier one (git checks out that commit, detached; volumes are not rolled back), and
`om fsck` checks the log, the signature and that running images match `.om/lock.json`.

- Commit with an SSH signing key (`git config --global gpg.format ssh`, `user.signingkey`,
  `commit.gpgsign true`) and list it in `.om/allowed_signers` (`om init` does this for you).
  Changing that list takes a commit signed by a key that is already trusted.
- Uncommitted edits still run (`om start`, `om dev`): the generation is marked dirty and unsigned.
- `om lock` pins images to digests; `om update` moves them forward and commits the new lock.
- `OM_SIGNED=enforce` in `om.env` refuses unsigned or untrusted commits for `om start`/`om sync`.

### e. Reach your services from a phone or another computer
Use a VPN; om answers on it. With Tailscale (the default, `OM_VPN=auto`): install it on the phone
or laptop, sign in to the same account, and open `http://<this machine's name>/<service>/`
(for example `http://archlinux/searxng/`). Any other VPN works when you name its interface or
address in `om.env` (`OM_VPN=wg0` or `OM_VPN=tailscale,10.8.0.1`), then `om core restart`.

Everyone who can join your VPN reaches the private tier, so the VPN account is the lock:
turn on Tailnet Lock (`tailscale lock init`), so a new device joins only when one of yours signs it.
`om doctor` (*VPN*) reports it. Run `om firewall apply` once (it asks for sudo).

### f. Share some services with other people
Mark a service public: `dashboard.scope=public` in its labels (or `om add <svc> --public`).
- Anyone on your Wi-Fi then opens `http://<LAN address>/<service>/`. Nothing private is served there.
- Someone outside your home: share this machine with their VPN account (Tailscale: *Share*),
  and let your VPN's access rules allow them port 8080 only. They open
  `http://<this machine's VPN address>:8080/<service>/` and see the public services, nothing else.

### g. Keep a folder out of om
Put an empty `.omignore` file in a folder (for example a compose project you run with plain
`podman compose`): om skips it and everything below it.

### h. Give a service a secret
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
Commit the `.age` file. It is decrypted only while the workspace runs, into memory, read-only.
Back up `~/.local/state/om/data/age.key` off-host; your SSH key can always decrypt as well.

### i. Let a service call the internet
Workspace networks are internal: a container cannot resolve or reach anything outside the
workspace unless its labels say so. om then gives that service (and only it) `HTTP(S)_PROXY`
settings with its own credential for `om_egress`, which allows exactly the listed hosts.

```yaml
labels:
  - "om.egress=api.example.com,*.githubusercontent.com"   # exact hosts; *. covers subdomains
  # - "om.egress=learn"      # temporarily: any public host, each one recorded (find out what it needs)
  # - "om.egress=internet"   # anything public — only for services with no writable volume and no secrets
```

Don't know the hosts? Set `om.egress=learn`, use the service normally (it keeps working: any
public host is allowed, private ranges never), then run `om egress log`: it lists the hosts it used
and the exact `om.egress=…` line to paste instead. `om doctor` warns while any service is learning,
and the "no internet for writers" law is suspended for it until you replace `learn`. Apps that ignore `HTTP(S)_PROXY`
have no way out; configure their proxy setting or file an issue upstream. An older workspace whose
network was created before this change is still open until you run `om network harden`
(`om doctor` lists them).

---

## 3. When to recreate the image

om never rebuilds an image unless you ask, or unless `om sync` pulls new commits.

| You changed… | Do this | Why |
| :--- | :--- | :--- |
| Code in a `--project` (bind-mounted source) | nothing | `node --watch` (or your dev server) reloads it live. |
| Code that is `COPY`'d into an image | `om restart <svc> --build` | The old image still contains the old code. |
| `Dockerfile` / `Containerfile`, dependencies (`package.json`, `requirements.txt`, …) | `om restart <svc> --build` | Only a build bakes them in. |
| The base image should get security updates | `om update <svc>` | Pulls newer base images (`build --pull`), rebuilds, recreates and health-checks. |
| A pulled image's tag (`image:`) | `om start <svc>` | Compose sees the new image and recreates the container. |
| Labels, `expose`, env vars, volumes in compose | `om start <svc>` | Compose recreates the container when its config changed. Routes are regenerated. |
| Only labels for routing/dashboard | `om reload` | Regenerates routes and hot-reloads the proxy without touching containers. |
| Nothing, but the container is in a bad state | `om restart <svc>` | Stop + start, same image. |
| Pulled commits from git | `om sync` | Pulls, rebuilds services that have `build:`, starts, health-checks, rolls back if unhealthy. |

Rule of thumb: **anything baked into the image needs `--build`; anything in the compose file
needs `om start`; route labels only need `om reload`.**

---

## 4. Debugging your workspace

Work from the outside in, the same path a request takes:

| Step | Command | Look for |
| :--- | :--- | :--- |
| 1. Is om itself healthy? | `om doctor` | Any `FAIL` / `WARN`. Each one prints its fix. |
| 2. Is the core up? | `om core status` | `om_caddy`, `om_router`, `om_dashboard` running. Fix: `om core restart`. |
| 3. Is my container running? | `om status` | A stopped or restarting service. |
| 4. What did it say? | `om logs <svc> -f` | Crashes, wrong port, missing env. |
| 5. Does om route to it? | `om routes` | URL and the `→ <ws>_<svc>:<port>` target. The port must be the port the app listens on inside the container. |
| 6. Is it on the right network? | `om network` | The container must be on `<ws>_net`. |
| 7. Poke it from inside | `om shell <svc>` · `om shell <svc> wget -qO- localhost:<port>` | Whether the app answers at all. |
| 8. Am I in sync with git? | `om drift` | Ahead/behind/dirty. `om sync` refuses a dirty tree. |

What the HTTP status tells you:

| Symptom | Usual cause | Fix |
| :--- | :--- | :--- |
| **502** | Container down, wrong `dashboard.port`, not on `<ws>_net`, or flow-style labels | Steps 3–6 above. |
| **404 / connection refused on the URL** | No route: the service wasn't started, or its routes weren't generated | `om start <svc>` or `om reload`. |
| **401** | Private-tier login is on | Log in, or check `om auth list`. |
| **403 from the LAN** | The service is private | `om edit <svc> --scope public`. |
| Old code still served | Image not rebuilt | `om restart <svc> --build` (see §3). |
| `om sync` refuses | Uncommitted changes | Commit or stash. Machine-local files in `.om/` are already ignored. |
| `om sync` rolled back | The new commit failed the health check | Read `om logs <svc>`, fix, commit again. |
| Port 80/443 in use | Another web server, or another user's om | Stop it, or set `OM_HTTP_PORT` / `OM_HTTPS_PORT`. Then `om core restart`. |
| `*.localhost` doesn't resolve in curl | Some OSes resolve it only in browsers | `curl -H 'Host: <ws>.<svc>.localhost' http://127.0.0.1/`. |

What **not** to do: don't edit files in `~/.local/state/om/routes/` (they are regenerated).
Don't run `podman compose up` in `~/.om/core/` (use `om core …`). Don't attach your services
to `om_core_net`. And don't add `ports:`.

---

## 5. Everyday loop

```bash
cd ~/my-workspace
om start                       # bring it up
om dev api                     # live logs while you code (Ctrl+C detaches, keeps running)
om restart api --build         # after changing the Dockerfile or dependencies
git commit -am "…" && git push
om sync                        # on another machine: pull, rebuild, verify, roll back if bad
```

More: `om docs` lists every guide, `om docs project` covers architecture and layout, and
`om docs network` covers the security model.
