# Contributing

Thanks for helping. om is small on purpose: one Python program using only the standard library, a few
pinned container images, and generated configuration. Contributions that keep it that way are the
easiest to accept.

## Setup and tests

- Python 3.10 or newer; no dependencies, no build step.
- Lint (`pip install ruff`; the rules are in `pyproject.toml`, CI pins the version): `ruff check` from the repo root.
- Tests need no container engine:

  ```
  cd tests
  PYTHONWARNINGS=error::EncodingWarning python3 -X warn_default_encoding -m unittest discover -s . -p 'test_*.py'
  ```

  CI runs them on Linux, macOS and Windows with Python 3.10, 3.12 and 3.13, checks the Caddy
  configuration, and checks the generated firewall with each OS's own parser (`nft`, `pfctl`,
  PowerShell).
- A change to networking, the core or the firewall also needs a real run: `om core restart`,
  `om start` in a workspace, then `om doctor` — it attacks the setup and must pass.

## Rules that keep om portable

- Every text read and write passes `encoding="utf-8"` (writes also `newline="\n"`); subprocess output goes
  through `core.run()`. Host paths handed to compose go through `core.compose_path()`.
- Behaviour must be the same on every OS. Where it cannot be (a Linux-only kernel feature), say so in
  the code, the docs and `om doctor`.
- om is generic: never special-case a service, workspace, host name or VPN product. If something needs
  different behaviour, add a label and set it in the workspace's compose file.

## Rules that keep om secure

- Services use `expose:`, never `ports:`. Only the edge has host ports.
- The edge never joins a workspace or project network; it reaches services only through the router's
  socket with the edge token.
- Anything that creates or recreates containers goes through `start_workspace` (it applies the policy
  gate and the egress, lock, secret, network, no-log and limits overrides) — never a bare `compose up`.
- Decisions about client addresses live in the host firewall (the edge cannot see them under rootless
  port forwarding). Logs never keep request content.
- Fail closed: when om cannot verify that a protection is in place, it closes the door and says how to
  open it, rather than leaving it open.
- Images are pinned to an exact version plus the multi-arch digest (core) or major/minor (scaffolds).

## Where things go

- `docs/GUIDE.md` — how to use it; `docs/ARCHITECTURE.md` — how it works; `docs/DESIGN.md` — why;
  `docs/adr/` — decisions; `docs/REMAINING.md` — open items before and after a release.
- `CHANGELOG.md` — every user-visible change, with upgrade steps when users must act.
- `CLAUDE.md` holds the same rules for AI coding agents.

## Pull requests

Small and focused, with tests for new behaviour and the docs updated in the same change. Commits are
signed (om itself deploys signed commits). For security issues, see `SECURITY.md` instead.
