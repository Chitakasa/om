#!/bin/bash
# usage: fakebasic.sh <dir> — the tools basic.sh puts first on PATH: the fake `podman` (fake-podman) and an `ip` that
# knows no VPN tunnel, so what the machine running the scenario has installed never reaches the output.
set -e
dir=$1
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$dir"
cp "$here/fake-podman" "$dir/podman"
printf '#!/bin/sh\n[ "$*" = "-d -j link show" ] && echo "[]" && exit 0\nexit 1\n' > "$dir/ip"
chmod +x "$dir/podman" "$dir/ip"
