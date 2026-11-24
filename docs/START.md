# Start here

om runs the apps you build or self-host on your own machine. Each one gets a clean address, runs sandboxed, and is
private unless you say otherwise. This page takes about ten minutes and ends with a service running and open in
your browser. It uses only the everyday commands; everything else is in [GUIDE.md](GUIDE.md).

You need `git`, Podman with a compose provider (docker-compose v2 or podman-compose), and either Go (the installer builds om) or internet access (it downloads the release binary). Docker is not supported and is not needed (the `docker-compose` binary works as the compose provider). Linux with rootless Podman is the setup
om has been verified on; macOS and Windows are designed for but not yet tested live (see the platform table in the
[README](../README.md#%EF%B8%8F-supported-platforms)).

## 1. Install (2 minutes)

```bash
git clone https://github.com/Chitakasa/om.git ~/.om
~/.om/install.sh
```

On Windows, clone to `$HOME\.om` and run `powershell -ExecutionPolicy Bypass -File $HOME\.om\install.ps1`.

The installer builds (or downloads and verifies) the `om` binary, checks the engine and compose, installs the `om` command, and asks before each optional step
(signed git commits, which VPN to trust, starting the core, starting at boot, the host firewall). The defaults are
safe, and you can run it again. Open a new terminal, then check the install:

```bash
om doctor
```

You want no `FAIL` lines. If one appears it says how to fix itself; [TROUBLESHOOTING.md](TROUBLESHOOTING.md) lists the
common ones.

## 2. Start the core (1 minute)

```bash
om core start
om status
```

The core is a few small containers: the edge proxy that everything goes through, a router, an outbound-access
proxy, and the dashboard. The first start downloads and builds images, so it needs the internet and takes a minute.
`om status` shows each one as running, and the dashboard is at <http://localhost/>.

## 3. Your first service (3 minutes)

A **workspace** is a folder om manages; a **service** is one app in it.

```bash
mkdir -p ~/apps && cd ~/apps
om init
om add web
om start
om routes
```

Prefer to be asked? Run `om add` with no name: it asks what you are adding (a web app, a TCP server, a background
service or a Node.js project), which image and port, and shows a summary before it writes anything. "Customise more"
covers who can reach it, outbound traffic, limits, updates and logging, and every answer shows the label it writes.

`om routes` prints the address, `http://apps.web.localhost` (the workspace is named after the folder). Open it in a
browser: you are looking at an nginx that om scaffolded for you. In a terminal, some systems only resolve
`*.localhost` inside browsers; `curl -H 'Host: apps.web.localhost' http://127.0.0.1/` works everywhere.

What om wrote is an ordinary compose file, `services/web/compose.yml`. It already runs the container as a non-root
user, read-only, without extra privileges, on its own network, with no ports published to the host. Nothing else
can reach it except through om's edge.

## 4. Look at it and control it (1 minute)

```bash
om status           # what runs, and where
om logs web -f      # follow its output (Ctrl+C stops following)
om stop web         # stop it
om start web        # start it again
```

## 5. Make it yours (2 minutes)

Open `services/web/compose.yml`. Below the active labels is a commented menu of every label om understands, grouped,
with an example and one line each: uncomment what you need and run `om start`. Or change the common ones from the
command line:

```bash
om edit web --scope public     # also reachable from your local network
om add notes --image <an-image> --port 8080     # any container image you like
```

Everything a service can say in its compose file is in [LABELS.md](LABELS.md).

## 6. A safety net

Put the workspace under git and commit. Each `om start` of a committed tree is recorded as a numbered
**generation** (signed when the commit is); if one goes wrong you can go back:

```bash
om log              # what was deployed, when, and by whom
om rollback         # redeploy the previous good generation
```

Once git is set up to sign with your SSH key (the installer helps), om refuses unsigned commits, and it pins every
image to an exact digest, so what runs is what you approved.

## 7. From your phone or another computer

om trusts one thing to decide who may reach the private side: a VPN made of your own devices. `om vpn` lists the VPNs
on this machine, and `om vpn trust <interface>` lets one in. Without a VPN, the private side is this machine only,
and `--public` services are visible on your local network. The details are in [GUIDE.md](GUIDE.md), section 9.

## Where next

| You want to… | Read |
| :--- | :--- |
| Do a specific task (secrets, sharing, updates, egress, previews) | [GUIDE.md](GUIDE.md) |
| Know what a command or setting takes | [COMMANDS.md](COMMANDS.md), [SETTINGS.md](SETTINGS.md), [LABELS.md](LABELS.md) |
| Fix something that does not work | [TROUBLESHOOTING.md](TROUBLESHOOTING.md), [DOCTOR.md](DOCTOR.md) |
| Look up a word | [GLOSSARY.md](GLOSSARY.md) |
| Understand how it is built and why | [ARCHITECTURE.md](ARCHITECTURE.md), [DESIGN.md](DESIGN.md) |
