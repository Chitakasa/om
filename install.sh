#!/usr/bin/env bash
# ==============================================================================
#  om — installer for Linux & macOS   (Windows: install.ps1)
#    git clone <repo> ~/.om && ~/.om/install.sh
#  Builds the om binary with Go when Go is installed, else downloads the release binary for your system and
#  checks its SHA-256. Re-running is safe (idempotent).
# ==============================================================================
set -euo pipefail

B="\033[1m"; G="\033[32m"; Y="\033[33m"; R="\033[31m"; C="\033[36m"; N="\033[0m"
[ -t 1 ] || { B=""; G=""; Y=""; R=""; C=""; N=""; }
ok()   { echo -e "  ${G}✓${N} $*"; }
warn() { echo -e "  ${Y}⚠${N} $*"; }
fail() { echo -e "  ${R}✗${N} $*"; exit 1; }
ask()  { [ -t 0 ] || return 1; read -r -p "  $1 [y/N] " a; [[ "$a" =~ ^[Yy] ]]; }

echo -e "\n${B}${C}om installer${N}\n"
[ "$(id -u)" -ne 0 ] || fail "Run the installer as yourself, not with sudo: om runs containers rootless under your user. It asks for sudo only for the steps that need it."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OM_HOME="${OM_HOME:-$SCRIPT_DIR}"
[ -f "$OM_HOME/core/compose.yml" ] || fail "Run this from the om checkout (core/compose.yml not found in $OM_HOME)."
echo -e "  Platform root: ${B}$OM_HOME${N}"

# 1. The om binary: built here with Go, else downloaded from the release and verified
case "$(uname -s)" in Linux) OS=linux ;; Darwin) OS=darwin ;; *) fail "Unsupported system $(uname -s) (Windows: install.ps1)." ;; esac
case "$(uname -m)" in x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) fail "Unsupported CPU $(uname -m)." ;; esac
VERSION="$(sed -n 's/^const Version = "\(.*\)"$/\1/p' "$OM_HOME/internal/state/state.go" 2>/dev/null | head -n 1)"
OM_BIN="$OM_HOME/build/om"
mkdir -p "$OM_HOME/build"

sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

# get_om <os> <arch> <output file>
get_om() {
    local os="$1" arch="$2" out="$3" tmp want have base
    if command -v go >/dev/null 2>&1 && [ -f "$OM_HOME/go.mod" ]; then
        (cd "$OM_HOME" && CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags="-s -w" -o "$out.new" ./cmd/om) \
            || fail "go build failed (om needs a Go toolchain matching go.mod)."
    else
        command -v curl >/dev/null 2>&1 || fail "Neither Go nor curl is installed: install one of them (Go: https://go.dev/dl/)."
        [ -n "$VERSION" ] || fail "Cannot read the version from $OM_HOME/internal/state/state.go."
        base="${OM_RELEASE_URL:-https://github.com/Chitakasa/om/releases/download/v$VERSION}"
        tmp="$(mktemp -d)"
        curl -fsSL "$base/om-$os-$arch" -o "$tmp/om" && curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS" \
            || { rm -rf "$tmp"; fail "Could not download $base/om-$os-$arch (install Go to build it instead)."; }
        want="$(awk -v f="om-$os-$arch" '$2 == f || $2 == "*" f {print $1}' "$tmp/SHA256SUMS")"
        have="$(sha256 "$tmp/om")"
        if [ -z "$want" ] || [ "$want" != "$have" ]; then rm -rf "$tmp"; fail "Checksum mismatch for om-$os-$arch: not installing it."; fi
        mv "$tmp/om" "$out.new"; rm -rf "$tmp"
    fi
    chmod 0755 "$out.new" && mv -f "$out.new" "$out"
}

get_om "$OS" "$ARCH" "$OM_BIN"
ok "om binary: $OM_BIN ($("$OM_BIN" version))"
# The engine runs in a Linux VM on macOS: the dashboard container needs a Linux build next to the binary
if [ "$OS" = darwin ]; then
    get_om linux "$ARCH" "$OM_HOME/build/om-linux-$ARCH"
    ok "Linux build for the dashboard container: $OM_HOME/build/om-linux-$ARCH"
fi

# 2. Container engine + compose
RUNTIME=""
if command -v podman >/dev/null 2>&1; then RUNTIME=podman; fi
if [ -z "$RUNTIME" ]; then
    if command -v docker >/dev/null 2>&1; then
        warn "Docker was found, but om runs on Podman only. Install Podman (https://podman.io/docs/installation), then re-run."
    else
        warn "Podman not found. Install it (https://podman.io/docs/installation), then re-run."
    fi
else
    ok "Engine: $RUNTIME"
    "$RUNTIME" info >/dev/null 2>&1 || warn "$RUNTIME is installed but not responding (macOS and Windows: 'podman machine start')."
    "$RUNTIME" compose version >/dev/null 2>&1 && ok "Compose: available" \
        || warn "'$RUNTIME compose' is missing — install a compose provider for Podman: docker-compose v2 or podman-compose."
fi

# 3. Rootless engines on Linux must be allowed to bind 80/443
if [ "$(uname -s)" = "Linux" ] && [ -r /proc/sys/net/ipv4/ip_unprivileged_port_start ]; then
    start=$(cat /proc/sys/net/ipv4/ip_unprivileged_port_start)
    if [ "$start" -gt 80 ]; then
        warn "Unprivileged processes cannot bind ports below $start (rootless engines need 80/443)."
        if ask "Allow it now with sudo (writes /etc/sysctl.d/99-om.conf)?"; then
            echo 'net.ipv4.ip_unprivileged_port_start=80' | sudo tee /etc/sysctl.d/99-om.conf >/dev/null
            sudo sysctl -q --system && ok "Ports 80/443 bindable."
        else
            warn "Later: echo 'net.ipv4.ip_unprivileged_port_start=80' | sudo tee /etc/sysctl.d/99-om.conf && sudo sysctl --system"
        fi
    fi
fi

# 4. Directories, default settings, registry
OM_HOME="$OM_HOME" "$OM_BIN" _prepare && ok "Settings and state directories ready (see: om doctor)"

# 5. Command wrapper (pins this checkout, whatever OM_HOME is)
BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"
WRAPPER="$BIN_DIR/om"
if [ -e "$WRAPPER" ] && ! grep -q "om-wrapper" "$WRAPPER" 2>/dev/null && [ ! -L "$WRAPPER" ]; then
    fail "$WRAPPER exists and is not om's wrapper; remove it and re-run."
fi
rm -f "$WRAPPER"
cat > "$WRAPPER" <<EOT
#!/bin/sh
# om-wrapper (generated by install.sh)
export OM_HOME="$OM_HOME"
exec "$OM_BIN" "\$@"
EOT
chmod +x "$WRAPPER"
ok "Installed command: $WRAPPER"
case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) warn "$BIN_DIR is not on your PATH. Add to your shell profile:  export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac

# 6. Signed commits: om deploys only commits signed by a key in .om/allowed_signers
if command -v git >/dev/null 2>&1; then
    if [ "$(git config --global --get gpg.format || true)" = "ssh" ] && [ -n "$(git config --global --get user.signingkey || true)" ]; then
        ok "git signs commits with your SSH key"
        SIGNING=1
    else
        SIGNING=0
        KEY="$HOME/.ssh/id_ed25519"
        if [ -z "$(git config --global --get user.email || true)" ]; then
            warn "git has no user.email; set it (git config --global user.email you@example.com) and re-run to set up signed commits."
        elif ask "Sign your git commits with an SSH key (om then deploys only signed commits)?"; then
            if [ ! -f "$KEY.pub" ]; then
                ssh-keygen -t ed25519 -f "$KEY" -C "$(git config --global --get user.email)" || fail "ssh-keygen failed."
            fi
            git config --global gpg.format ssh
            git config --global user.signingkey "$KEY.pub"
            git config --global commit.gpgsign true
            git config --global tag.gpgsign true
            ok "git signs commits with $KEY.pub"
            SIGNING=1
        else
            warn "Later: re-run this installer; until then om warns about unsigned deploys instead of refusing them."
        fi
    fi
    if [ "$SIGNING" = 1 ]; then
        "$WRAPPER" config set OM_SIGNED=enforce >/dev/null && ok "Unsigned or untrusted commits are refused at deploy (OM_SIGNED=enforce)"
    fi
else
    warn "git is not installed; workspaces are git repositories. Install git and re-run."
fi

# 7. Reaching om from your other devices: a VPN of your own devices (docs/adr/0003). Every tunnel
#    on this machine is listed; none is trusted without your yes — a tunnel may also be a
#    commercial or company VPN, or a public network.
VPNS="$("$WRAPPER" vpn | awk '/not trusted$/ {print $1 "=" $2}')"
if [ -z "$VPNS" ]; then
    ok "VPN: nothing new to trust (om vpn shows the state)"
fi
for PAIR in $VPNS; do
    IFACE="${PAIR%%=*}"; ADDR="${PAIR#*=}"
    if ask "VPN interface $IFACE ($ADDR): are ALL its members your own devices (not a commercial/company VPN, not a public network)?"; then
        "$WRAPPER" vpn trust "$IFACE" || true
    else
        warn "$IFACE not trusted (later: om vpn trust $IFACE)."
    fi
done
warn "Whoever can join a trusted VPN reaches your private services: keep joining it to devices you approve (your VPN's device-approval setting)."

# 8. Optional next steps
if [ -n "$RUNTIME" ] && "$RUNTIME" info >/dev/null 2>&1; then
    if ask "Start the om core now (edge proxy, router, dashboard)?"; then
        "$WRAPPER" core start || warn "Core did not start — run 'om doctor'."
        # The private tier has no login by default: whoever reaches localhost (or a trusted VPN) sees every private service.
        if "$WRAPPER" auth status 2>/dev/null | grep -q "off"; then
            if ask "The private tier has no login. Add one now (om auth add $(id -un))?"; then
                "$WRAPPER" auth add "$(id -un)" || warn "Later: om auth add <user>"
            else
                warn "No login: anyone who reaches this machine's localhost or your VPN sees every private service. 'om exposure' shows who reaches what; 'om auth add <user>' adds a login."
            fi
        fi
    fi
    if ask "Start containers automatically at boot?"; then "$WRAPPER" boot enable || true; fi
    if ask "Apply the host firewall (only ports 80/443 reachable from the network; uses sudo)?"; then
        "$WRAPPER" firewall apply || true
    fi
fi

echo -e "\n${G}${B}✓ om installed.${N}  Next:"
echo -e "    cd <your project folder> && om init && om add web && om start"
echo -e "    om doctor     # verify everything, with fixes for any problem\n"
