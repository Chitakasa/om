#!/bin/bash
# usage: fakebin.sh <dir> — builds the fake engine as <dir>/podman and <dir>/ip, plus logging stubs for the host tools om
# calls with sudo (systemctl, loginctl, sudo, ...): nothing the scenario runs reaches the real ones.
set -e
dir=$1
mkdir -p "$dir"
here=$(cd "$(dirname "$0")" && pwd)
(cd "$here/../.." && go build -o "$dir/podman" ./testdata/e2e/fakeengine)
cp "$dir/podman" "$dir/ip"
for t in sudo systemctl loginctl crontab notify-send launchctl schtasks; do
    printf '#!/bin/sh\necho "%s $*" >> "${FAKE_LOG:-/dev/null}"\nexit 0\n' "$t" > "$dir/$t"
    chmod +x "$dir/$t"
done
