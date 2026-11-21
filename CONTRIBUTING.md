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
  PowerShell). Tests must pass on all three: skip POSIX-only ones with `unittest.skipIf(os.name == "nt", …)`,
  and compare paths in recorded output through `_env.scrub_paths` (Windows prints backslashes).
- A change to networking, the core or the firewall also needs a real run: `om core restart`,
  `om start` in a workspace, then `om doctor` — it attacks the setup and must pass.

## Rules that keep om portable

- `docs/COMMANDS.md`, `SETTINGS.md`, `LABELS.md` and `DOCTOR.md` are generated from the code: after changing a command,
  argument, setting, label or doctor check, run `python3 tests/gen_reference.py` and commit the result (a test fails
  while they are stale). New arguments need help text, new doctor checks a docstring: both are what the reference prints.
- CI fails if the library's line coverage drops below the floor in `.github/workflows/ci.yml` (`coverage report --fail-under`,
  measured on Linux with Python 3.12). Locally: `cd tests && COVERAGE_RCFILE=../pyproject.toml coverage run -m unittest discover -s . -p 'test_*.py'`,
  then `coverage combine && coverage report` (`COVERAGE_CORE=sysmon` is much faster on Python 3.12+).
- A validator that guards generated config (names, hosts, labels, `om.caddy`, settings) gets its hostile cases in `tests/test_fuzz.py`:
  the suite is seeded, so a failure reproduces, and a refused value must never reach a config file.
- Every text read and write passes `encoding="utf-8"` (writes also `newline="\n"`); subprocess output goes
  through `omstate.run()`. Host paths handed to compose go through `omsettings.compose_path()`.
- Behaviour must be the same on every OS. Where it cannot be (a Linux-only kernel feature), say so in
  the code, the docs and `om doctor`.
- The docs are pinned to the code by `tests/test_docs_match_code.py`: a new command needs help text on every argument (the
  generated `docs/COMMANDS.md` lists them) and, if it is an everyday one, a mention in the README,
  a new setting in `docs/ARCHITECTURE.md`, a new module in `CLAUDE.md`, a new user label in the docs.
  Add a command or module without them and CI fails.
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

## Tests that fail sometimes

A test that fails once and passes on a rerun is a bug in the test, not bad luck. Do not just rerun it: find what it
races or depends on (a port, a clock, a socket the OS closes) and fix that. The tests that talk to a local server
go through `_env.http_roundtrip`, which retries a refused or aborted loopback connection; a test that cannot be made
reliable on one OS is skipped there with the reason written next to the skip, never silently.

## Releasing

om follows semantic versioning: a patch is fixes, a minor adds things, a major removes or changes a command, a
setting or a label.

1. `main` is green and `docs/REMAINING.md` has no blocker you have not accepted on purpose.
2. In `CHANGELOG.md`, rename `Unreleased` to `## X.Y.Z — YYYY-MM-DD` and put a new empty `Unreleased` above it. If
   users have to act, the entry says how.
3. Set `VERSION` in `lib/gitops/omstate.py` to `X.Y.Z` (no test depends on the number).
4. Commit it, then tag that commit with a signed tag and push both: `git tag -s vX.Y.Z -m "om X.Y.Z"`,
   `git push origin main vX.Y.Z`.
5. Publish the release from the changelog entry: `gh release create vX.Y.Z --title "om X.Y.Z" --notes-file <entry>`.
6. Check CI on the tag, then `git clone` into a fresh folder and run `om version` and `om doctor`.

`tests/test_docs_match_code.py` fails if the changelog has no entry for the current `VERSION`.

## Pull requests

Everyone taking part follows `CODE_OF_CONDUCT.md`. Pull requests are small and focused, with tests for new behaviour and the docs updated in the same change. Commits are
signed (om itself deploys signed commits). For security issues, see `SECURITY.md` instead.
