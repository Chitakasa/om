# Contributing

Thanks for helping. om is small on purpose: one static Go binary using only the standard library, a few
pinned container images, and generated configuration. Contributions that keep it that way are the
easiest to accept.

## Setup and tests

- Go (the version in `go.mod`); no dependencies, no cgo. Build: `CGO_ENABLED=0 go build -o build/om ./cmd/om`.
- Lint: `gofmt -l .` prints nothing and `go vet ./...` is clean (CI also vets with `GOOS=darwin` and `GOOS=windows`).
- Tests need no container engine:

  ```
  go test -race ./...
  ```

  CI runs them on Linux, macOS and Windows, checks the Caddy configuration, builds every target statically, and
  checks the generated firewall with each OS's own parser (`nft`, `pfctl`, PowerShell). Tests must pass on all
  three: skip OS-specific ones with `t.Skip` and the reason, and never compare output containing a path
  without normalizing it (Windows prints backslashes).
- Most tests replay **goldens recorded from the original Python implementation** (`testdata/`): a behaviour is
  right when om prints exactly what the recording says. A change that alters recorded output is a change of
  behaviour: say so in the changelog and re-record on purpose, never to make a test pass.
- A change to networking, the core or the firewall also needs a real run: `om core restart`,
  `om start` in a workspace, then `om doctor` — it attacks the setup and must pass. CI's `integration` job does
  the same on Podman.

## Rules that keep om portable

- `docs/COMMANDS.md`, `SETTINGS.md`, `LABELS.md` and `DOCTOR.md` are generated from the code: after changing a command,
  argument, setting, label or doctor check, run `go test ./internal/cli -run TestReferenceDocs -update` and commit the
  result (a test fails while they are stale). New arguments need help text, new settings an entry in `settingAbout`,
  new doctor checks an entry in `doctorDocs` (`internal/cli/refdata.go`): both are what the reference prints.
- CI fails if line coverage drops below the floors in `.github/workflows/ci.yml` (`COVER_FLOOR` for the library,
  `COVER_FLOOR_ALL` for the whole program). Locally: `go test -coverprofile=cover.out ./... && go tool cover -func=cover.out`.
- A validator that guards generated config (names, hosts, labels, `om.caddy`, settings) gets its hostile cases in
  `internal/attacks`: the generators are seeded, so a failure reproduces, and a refused value must never reach a
  config file.
- Text files are UTF-8 with `\n`; subprocess output goes through `state.Run`. Host paths handed to compose go
  through `settings.ComposePath`. Python-compatible text and JSON come from `internal/py`.
- Behaviour must be the same on every OS. Where it cannot be (a Linux-only kernel feature), say so in
  the code, the docs and `om doctor`.
- The docs are pinned to the code by `internal/repocheck`: a new command needs help text on every argument (the
  generated `docs/COMMANDS.md` lists them) and, if it is an everyday one, a mention in the README,
  a new setting in `docs/ARCHITECTURE.md`, a new package in `CLAUDE.md`, a new user label in the docs.
  Add a command or package without them and CI fails.
- om is generic: never special-case a service, workspace, host name or VPN product. If something needs
  different behaviour, add a label and set it in the workspace's compose file.

## Rules that keep om secure

- Services use `expose:`, never `ports:`. Only the edge has host ports.
- The edge never joins a workspace or project network; it reaches services only through the router's
  socket with the edge token.
- Anything that creates or recreates containers goes through `startWorkspace` (it applies the policy
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
races or depends on (a port, a clock, a socket the OS closes) and fix that. Tests that talk to a local server use
`httptest` or a socket in a temp folder; a test that cannot be made reliable on one OS is skipped there with the
reason written next to the skip, never silently.

## Releasing

om follows semantic versioning: a patch is fixes, a minor adds things, a major removes or changes a command, a
setting or a label.

1. `main` is green and `docs/REMAINING.md` has no blocker you have not accepted on purpose.
2. In `CHANGELOG.md`, rename `Unreleased` to `## X.Y.Z — YYYY-MM-DD` and put a new empty `Unreleased` above it. If
   users have to act, the entry says how.
3. Set `Version` in `internal/state/state.go` to `X.Y.Z` (the release workflow refuses a tag that differs).
4. Commit it, then tag that commit with a signed tag and push both: `git tag -s vX.Y.Z -m "om X.Y.Z"`,
   `git push origin main vX.Y.Z`.
5. The `Release` workflow builds the static binaries for Linux, macOS and Windows (amd64, arm64), writes
   `SHA256SUMS` and publishes the release that `install.sh` and `install.ps1` download from. Add the changelog
   entry to its notes.
6. Check CI on the tag, then `git clone` into a fresh folder and run `install.sh`, `om version` and `om doctor`.

`internal/repocheck` fails if the changelog has no entry for the current `Version`.

## Pull requests

Everyone taking part follows `CODE_OF_CONDUCT.md`. Pull requests are small and focused, with tests for new behaviour and the docs updated in the same change. Commits are
signed (om itself deploys signed commits). For security issues, see `SECURITY.md` instead.
