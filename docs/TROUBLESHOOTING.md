# Troubleshooting

When something does not work: run `om doctor` first. It checks the install and every security promise (see
[DOCTOR.md](DOCTOR.md)) and prints a fix for each problem. If it is clean, work from the outside in, along the path
a request takes. `om status` also ends with a `Next` block when the obvious thing is missing.

## The path a request takes

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

## Symptom, cause, fix
| Symptom | Usual cause | Fix |
| :--- | :--- | :--- |
| **502** | Container down, wrong `dashboard.port`, not on `<ws>_net`, flow-style labels | Steps 3–6. |
| Every request hangs; `om_caddy` restarts in a loop; `om core start` says the engine runs as root | A rootful engine (Docker's default install): the core's containers drop every capability and cannot write your state folders | Use a rootless engine: Podman as a normal user, or Docker after `dockerd-rootless-setuptool.sh install`. `om doctor` checks it (*Engine*). |
| **404 / refused on the URL** | No route yet | `om start <svc>` or `om reload`. |
| **401** | Private-tier login is on | Log in; `om auth list`. |
| **403 from the LAN** | The service is private | `om edit <svc> --scope public`. |
| Old code still served | Image not rebuilt | `om restart <svc> --build`. |
| Deploy refused | Policy gate, or an unsigned commit | The message names the rule or the signing step. |
| No notification arrived | No desktop session for the timer, `OM_NOTIFY=off`, or a missing `notify-send` | `om notify test`; every message is also in `<state>/logs/notify.log`. |
| `⬆ update` badge never clears | The update list refreshes every 6 hours | `om update --dry-run` refreshes it at once. |
| `om sync` refuses / rolled back | Dirty tree / failed health check | Commit or stash / read `om logs <svc>`. |
| Port 80/443 in use | Another web server or another user's om | Stop it, or set `OM_HTTP_PORT` / `OM_HTTPS_PORT`, then `om core restart`. |
| `*.localhost` fails in curl | Some OSes resolve it only in browsers | `curl -H 'Host: <ws>.<svc>.localhost' http://127.0.0.1/`. |
| A service is missing from `om status` | Its folder has an `.omignore` (om skips it, and `om status` names it under "not managed") | Delete the `.omignore` to hand the folder to om; `om disable` writes one on purpose. |
| `om doctor`: **Engine not responding** | The container engine is not running | Start it (`podman machine start`, Docker Desktop, or the system service). |
| `om doctor`: **compose missing** | No `compose` command for the engine | Install docker-compose v2 or podman-compose. |
| `om doctor`: **unprivileged ports start at N** | A rootless engine may not bind 80/443 yet | Run the `sysctl` line `om doctor` prints (once, with sudo), or set `OM_HTTP_PORT` / `OM_HTTPS_PORT` (`om config set`). |
| Deploy refused: **unsigned commit** | `OM_SIGNED` enforces and git is not signing | Set up SSH signing (the installer shows how), or `om config set OM_SIGNED=warn`. |
| Deploy refused by the **policy gate** | The compose file asks for something om will not run (`privileged`, `ports:`, host namespaces, an engine socket, a sensitive mount…) | The message names the rule. Fix the file; for the rules that can be waived, add `om.policy.allow=<rule>` to that service (`privileged` and `ports` cannot be waived). `om policy check` lists everything. |
| `om doctor`: **secret files readable by other users** | `om.env` or a key file is group- or world-readable | `chmod 600` the file named, or change a setting with `om config set` (it rewrites `om.env` privately). |
| `om doctor`: **Login** fails | Another account on this machine can log in and the private tier has no login | `om auth add <user>`, or list accounts that are yours: `om config set OM_TRUSTED_USERS=<user>`. |
| The core will not start | An engine problem, a busy port, or a stale container | `om doctor`, then `om core status`; `om core restart` rebuilds the core's containers. |
| `om: command not found` right after installing | The shell has not re-read your PATH | Open a new terminal; the installer adds `om` to your PATH (on Windows too). |

Don't: edit `~/.local/state/om/routes/` (regenerated), run `podman compose up` in `~/.om/core/`
(use `om core …`), attach services to `om_core_net`, or add `ports:`.

Not covered here? The full task list is in [GUIDE.md](GUIDE.md), and what each `om` command takes is in
[COMMANDS.md](COMMANDS.md). If it looks like a bug, [open an issue](https://github.com/Chitakasa/om/issues) with `om version`
and the (redacted) output of `om doctor`; a security problem goes through the private report in [SECURITY.md](../SECURITY.md).
