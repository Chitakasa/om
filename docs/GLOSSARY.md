# Glossary

Every word om uses for its own ideas, in alphabetical order. The links go to where it is explained.

**Address rule.** A restriction on who may reach a service's own ports, written with the labels `om.net.allow` and
`om.net.deny` and enforced by the host firewall. See [LABELS.md](LABELS.md).

**Audit.** An outbound-access mode (`om.egress=audit`) that allows every public destination and logs it. Compare
*learn*. See [GUIDE.md](GUIDE.md), section 7.

**Core.** The few containers om runs for every workspace: the edge, the router, the outbound proxy, the engine
filter and the dashboard. `om core start` brings it up.

**Dashboard.** The web page at `http://localhost/` that lists every service with its state and address. The core
runs it, and a public view for guests reveals nothing private.

**Drift.** The difference between the workspace and its git remote (ahead, behind, or changed). `om drift` shows it.

**Edge.** The one proxy that listens on the network. Every request to a service goes through it, and it reaches
only the dashboard and the router. See [ARCHITECTURE.md](ARCHITECTURE.md).

**Egress.** Outbound traffic from a service to the internet. Services have none by default; `om.egress` grants
exactly the hosts a service needs, through om's outbound proxy.

**Generation.** A numbered, signed record of one deploy (the commit, the lock and the result). `om log` lists them
and `om rollback` redeploys an earlier one.

**Label.** A line under `labels:` in a service's compose file that tells om what the service needs, such as
`om.log=off` or `dashboard.scope=public`. Everything om reads is in [LABELS.md](LABELS.md).

**Learn.** An outbound-access mode (`om.egress=learn`) that records what a service connects to, so
`om egress log --apply` can write the exact allow-list. It expires on its own.

**Lock.** `.om/lock.json`, which pins each image to an exact registry digest. `om update` moves the pins on purpose.

**`om.env`.** Your machine's settings file, `~/.config/om/om.env`, kept readable by you only. Read and change it
with `om config`; every key is in [SETTINGS.md](SETTINGS.md).

**Policy gate.** The check om runs on every compose file before it starts anything. It refuses privileged
containers, published `ports:`, host namespaces, engine sockets and sensitive mounts. `om policy check` runs it by
hand.

**Preview.** A branch run next to your workspace as a throw-away copy with its own network, data and ports
(`om preview <branch>`).

**Private tier.** The side of om that this machine, and the devices of a VPN you trust, can reach: every service.
Compare *public tier*.

**Project.** A service you are developing (a folder in `projects/`, with live reload), as opposed to one that runs a
ready-made image.

**Public tier.** The side your local network can reach: only the services you marked `public`, and a dashboard that
shows nothing private.

**Router.** The internal proxy between the edge and the services. It has no network listener and refuses any
request that does not carry the edge's secret token.

**Secret.** A value a service needs but the repository must not contain, stored encrypted (age) in the repo and
mounted read-only into the container. See [GUIDE.md](GUIDE.md), section 8.

**Service.** One compose project in a workspace: one app, one container (or a few), one address.

**Signed deploy.** om starts a clean commit only when it is signed by a key listed in the workspace's
`.om/allowed_signers`. `OM_SIGNED` decides whether an unsigned commit is refused or only reported.

**State directory.** `~/.local/state/om/`, where om keeps what it generates: routes, keys, the registry and logs.
Never edit it by hand.

**Stream route.** A raw TCP port published for a service (a game server, a database) with `om.tcp`, kept off the
HTTP edge. See [LABELS.md](LABELS.md).

**Trust (a VPN).** `om vpn trust <interface>` tells om that every member of that VPN is your own device, so it
may reach the private tier. Nothing is trusted by default.

**Workspace.** A folder of compose files that om manages as one unit, marked by `.om/config.json`. Its id (the
folder name unless you choose another) names its containers and its addresses.
