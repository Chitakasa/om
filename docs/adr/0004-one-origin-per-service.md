# ADR 0004 — One browser origin per service

- **Status:** accepted
- **Date:** 2026-10-07
- **Amends:** ADR 0003 (the URLs over the VPN and the LAN)

## Context

On this machine every service already had its own origin (`<ws>.<svc>.localhost`). Over the VPN
and the LAN, services were paths of one address (`http://<machine>/<svc>/`), shared with the
dashboard: VPN names give one name per machine, not per service. Browsers isolate origins, not
paths, so a compromised service's scripts could read every other service and the dashboard's API
through the owner's browser.

Per-service names would need DNS (a bought domain, or a public wildcard resolver such as sslip.io
that some routers block) and were rejected in ADR 0003's discussion.

## Decision

Each web service gets a stable slot `n` and two ports, so its own origin everywhere:

- **20000+n** — private: loopback and VPN addresses; Host must be a known local or VPN name.
- **21000+n** — public services only: LAN and VPN addresses; Host must be the LAN or a VPN name.

The two ranges are published once; adding a service only adds a Caddy site. Path routing over the
VPN and the LAN is removed; `/<svc>` and `om.route.aliases` on the dashboard's address redirect to
the service's port. A VPN guest's access rule is "ports 8080 and 21000–21199".

## Consequences

- No service can read another service, or the dashboard, through the browser. Cookies are not
  isolated by port; services set their own cookie names, and om's own cookies are not involved.
- URLs carry a port number; the dashboard and `om routes` show them, and they never change.
- The per-service ports serve plain HTTP; the VPN encrypts its traffic, and public services carry
  nothing private.
