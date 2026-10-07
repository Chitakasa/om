# ADR 0003 — Use the VPN you have; keep om to containers, routes and deploys

- **Status:** accepted
- **Date:** 2026-10-07
- **Supersedes:** ADR 0001 (gate and door). Amends `VISION.md` ideas 3–4 and `GOALS.md` G3–G5.

## Context

Phases 3–5 gave om its own network identity: a WireGuard door (`om_wg`), its own DNS
(dnsmasq), an Authelia gate with passkeys, a signed access-file chain of people, devices and
grants, `.internal` names with om's own CA trusted on every device, closable tiers, an off-host
mirror, and a separate OS user with a signing broker.

Trying to use it showed the cost. Enrolling one laptop took a QR code that a laptop can't scan,
a hand-written WireGuard file, a one-time password, a code read from a notifier file and a CA
installed on the device. That breaks G7 (development no slower than plain compose). It also
added risk: a CA trusted by a device for *every* website is a worse secret to keep than anything
om protects. The gate's passkeys could not work at all without that CA, or without a domain
the developer would have to buy.

What the door actually provides — only enrolled keys reach the machine, traffic encrypted end
to end — is exactly what the developer's VPN (Tailscale, Headscale, WireGuard, ZeroTier, NetBird)
already provides, done better: key handling, NAT traversal and device approval
(Tailscale's Tailnet Lock: a new device joins only when one of *your* devices signs it).

## Decision

om runs containers safely, routes them, and deploys them from signed commits. **The VPN is the
network boundary; om builds no VPN, no login system and no certificate authority for devices.**

### Who reaches what

| Who | URL | Listener |
| :-- | :-- | :-- |
| This machine | `http://<ws>.<svc>.localhost`, `http://localhost/<svc>/` | `127.0.0.1:80/443` |
| Your devices on any VPN | `http://<vpn-ip or vpn name>/<svc>/` | each VPN address `:80/:443` |
| Anyone on the LAN | `http://<lan-ip>/<svc>/`, only services with `dashboard.scope=public` | LAN address, host `:80/:443` → edge `:8080/:8443` |
| Guests your VPN lets in on its public port | `http://<vpn-ip>:8080/<svc>/`, the same public services | VPN addresses, host `:8080/:8443` |
| The internet | nothing | — |

`OM_VPN=auto` (default) finds VPN interfaces — `tailscale0`, `wg*`, `zt*`, `nb*` — and their
addresses; `OM_VPN=off` disables them; `OM_VPN=<iface>,<iface>` names them. Tailscale's
MagicDNS names are added to the allowed Host list when Tailscale is present.

Sharing with someone outside the household is the VPN's job: share the machine with their
account and let the VPN's access rules (Tailscale ACL) allow port 8080 only. They then see
exactly the `public` services. om does not keep a list of people.

The opt-in password on the private tier (`om auth`, Caddy `basic_auth`) stays as it was.

### Kept

| Part | Why |
| :-- | :-- |
| Edge (`om_caddy`) and router (`om_router`) as two containers | The edge never joins workspace networks; the router accepts only requests carrying the edge's 64-hex token. A service can therefore not use the edge to reach another workspace by sending a different Host header. Merging them would remove that wall. |
| `*.localhost` names, `/<svc>/` subpaths, local CA for `https://*.localhost` on this machine only | Clean URLs with no DNS and no device setup. |
| Internal workspace networks, `om_egress` allow-list, learn mode | A service cannot phone home except to hosts it lists. |
| Policy gate, `om.policy.allow` waivers | Refuses `privileged`, host namespaces, the engine socket, published ports. |
| `om_sockguard`, dashboard CSP | The dashboard never holds the raw engine socket. |
| `.om/lock.json` digests, `om update [--dry-run]`, updates in `om status` | Every image is exact and reviewable. |
| age secrets | Secrets in git, encrypted; in memory only at run time. |
| Signed deploys, generations, `om log`, `om rollback`, `om fsck` | Git does not record *what was deployed when*; the generation log does, and pins the trusted signer list. |
| Firewall (`om firewall`), `om boot`, `om autosync`, `om doctor` | Unchanged in purpose; rules follow the table above. |

### Removed

| Part | Replaced by |
| :-- | :-- |
| WireGuard door (`om_wg`, `core/door/`, dnsmasq), `om device` | Your VPN |
| Authelia gate (`om_gate`), `om invite/pending/approve/revoke/grant/ungrant`, passkeys | Your VPN's sharing and access rules; `om auth` for a password on the private tier |
| Signed access-file chain (`om access`), `om.access` label | `dashboard.scope=public` (the one exposure label) |
| `OM_DOMAIN`, `.internal` names, om's CA on devices | VPN addresses and names |
| `om tiers close/open` | The firewall always allows exactly the table above |
| Mirror (`om mirror`) | Push the workspace repository anywhere; the generation log is machine-local history |
| Separate OS user (`om user`, `OM_RUN_AS`, signing broker) | Rootless Podman under your user |
| Portainer | It needs the raw engine socket — the one thing the dashboard was rebuilt to avoid |
| `om host quiet`, host-facts checks | Hardening the operating system is outside om's job |

## Consequences

- Adding a device: install the VPN app, sign in, open `http://<machine>/`. Nothing else.
- Anyone who can join your VPN reaches the private tier. The VPN account is the lock: use
  Tailnet Lock (Tailscale) or keys only you hold (Headscale, WireGuard). `om doctor` reports
  whether Tailnet Lock is on when Tailscale is the VPN.
- Plain HTTP over the VPN is encrypted by the VPN itself; HTTPS on VPN addresses still uses the
  local CA and is optional.
- Existing state from the removed parts (`<state>/access`, `gate`, `door`, `mirror`) and their
  containers and images are deleted by `om core start` on the first run after the upgrade.
