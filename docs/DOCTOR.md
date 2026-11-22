<!-- Generated from the code (internal/cli/refdocs.go): do not edit. Run `go test ./internal/cli -run TestReferenceDocs -update` after a change. -->
# What `om doctor` checks

`om doctor` runs 37 checks and prints one line each: **PASS**, **WARN** (works, but look at it) or **FAIL** (fix it; the line says how). It exits 1 when any check fails, and `om doctor --json` prints the same results for scripts. Run it after any change to the network or the core. For symptoms and their fixes, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## Basics

Always run. If these fail, the perimeter checks are skipped.

### Engine

The container engine (Podman or Docker) answers, and whether it runs rootless, rootful or in a VM.

### Compose

The engine's `compose` command is available (docker compose v2, or podman-compose).

### Ports

A rootless engine on Linux is allowed to bind the front door's ports (80 and 443 by default).

### Core

Every core container is running, and no part left over from an older om is still there.

## Perimeter

Need a running core; they attack the setup the way an outsider or a compromised container would.

### Router

The internal router is attached to every workspace and folder network, so it can reach their services.

### Edge isolation

The edge proxy is on `om_core_net` only: containers on workspace networks cannot reach the private tier.

### Published ports

No workspace container publishes a host port (`ports:`): everything goes through the edge.

### Address drift

The addresses the core was started with (LAN, VPN) still match this machine's network.

### Private tier

The private tier answers on this machine's front door.

### DNS rebinding

A request with a foreign Host header is refused on the private tier (DNS-rebinding protection).

### Router token

The router listens on no network (only the edge's socket), and refuses a request without the edge token.

### Token not logged

The edge token never appears in om's own container logs (an unfiltered error log would carry it).

### Engine filter

The dashboard must see the engine only through om_sockguard: list allowed, writes refused, no raw socket.

### Admin surface

Nothing administrative listens where the network can reach it: only the edge ports; Caddy's admin API on loopback inside the container.

### Running = lock

Every workspace runs what its signed generation and lock say (`om fsck` in each).

### Egress

Each workspace network: internal (no DNS, no route out) and om_egress enforces source-IP ACLs; cross-service reuse & IP forging blocked.

### Project isolation

A container on one folder's network cannot reach another folder's service (by name or address).

### Generations

Each workspace: generation log chains, and what runs is a clean, signed commit.

### LAN tier

The LAN address serves the public tier only: private service ports are closed there and the dashboard is public-scoped.

### VPN

Which VPNs reach the private tier; tunnels present but not trusted.

### VPN isolation

A VPN device that sends a *.localhost Host gets nothing: those sites answer this machine only.

### Address rules

Services restricted by address (om.net.allow / om.net.deny): their rules are in the applied firewall.

### Links

Cross-workspace links: both sides declared, attached, nothing else on their networks.

### Custom routes

Services carrying their own Caddy rules (om.caddy): allowed, but always visible.

### Healthchecks

Running workspace containers without a healthcheck: `om update`, auto-updates and the heal timer can only judge a service by its health.

### Stream ports

Only declared stream ports (default range 22000-22199 and explicit ports from stream_ports.json) are published on om_stream_edge, and no other container publishes stream ports.

### Stream firewall

A host firewall rule exists for each declared stream port.

### Stream isolation

From inside a workspace container, om_stream_router and om_stream_edge are unreachable (expect refused/timeout), and a different workspace's stream target is unreachable.

## This machine

Always run.

### .localhost DNS

`*.localhost` names resolve on this OS (browsers always resolve them; some command-line tools need a hosts entry).

### Firewall

The host firewall (`om firewall`) is active and logs refusals and connections.

### Boot

Containers restart at boot and the core heals itself (`om boot`).

### Login

The private tier requires a login, or you are the only person who can log in on this machine.

### Private reach

Who the private tier answers: this machine, and the VPN's devices (all of them, or the allow-list).

### Secret files

Files that hold secrets are readable by their owner only (POSIX; Windows follows the profile's ACLs).

### State

om's program folder must hold no machine state (CA key, edge token, registry).

### Registry

Every registered workspace's folder still exists.

### Orphan routes

Routes of workspaces whose folder is gone (deleted without `om remove`).
