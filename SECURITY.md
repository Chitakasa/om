# Security

om sits in front of everything it runs, so security reports matter more than any other kind.

## Reporting a vulnerability

Report it **privately** with GitHub's *Report a vulnerability* button on this repository
(Security → Advisories). Please do not open a public issue or pull request for it.

Include what you can: the om version (`om --version`), OS and container engine, the steps or a proof
of concept, and what an attacker gains. You will get an acknowledgement, and a fix or a decision is
discussed with you before anything is made public. Credit is given unless you prefer otherwise.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x (latest) | yes |

## Scope

In scope: everything in this repository — the CLI (`cmd/om`, `internal/`), the edge, router,
socket filter and egress configuration (`core/`), the dashboard, the generated firewall rules and
compose overrides, and the installers.

Out of scope: vulnerabilities in the services you run with om, in the container engine, in your VPN,
or in the upstream images om pins (report those upstream; tell us if om should pin a fixed version).

## What om promises, and what it does not

The layers and what each one stops are described in `docs/ARCHITECTURE.md` (Defense in Depth) and the
reasoning in `docs/DESIGN.md`. In short: nothing is reachable from the internet; only om's edge has host
ports; services run rootless, on internal networks of their own, reachable only through an edge-signed
router; outbound traffic only to listed hosts; logs never keep request content. Known limits — what om
does **not** protect against — are listed in `docs/REMAINING.md`.

`om doctor` probes these properties on a running install; please include its output (`om doctor --json`)
when a report concerns a deployment.
