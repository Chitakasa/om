#!/bin/bash
# Re-records engine.golden and engine.log.golden from the ORIGINAL Python om (kept in the tree as the reference):
#   testdata/e2e/record.sh      (needs python3, git, bash, go)
# A change in the goldens is a change of behaviour: review the diff before committing it.
set -e
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
bash "$here/fakebin.sh" "$tmp/fakebin"
port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
out="$tmp/OUT"
OM="python3 $out/home/.om/bin/om" OM_PY=1 OUT="$out" FAKEBIN="$tmp/fakebin" OM_SRC="$repo" FAKE_EDGE_PORT=$port \
    bash "$here/engine.sh" 2>&1 | sed -e "s#$out#OUT#g" -e "s#\\b$port\\b#18080#g" > "$here/engine.golden"
sed -e "s#$out#OUT#g" "$out/engine.log" > "$here/engine.log.golden"
echo "recorded $(wc -l < "$here/engine.golden") lines of output and $(wc -l < "$here/engine.log.golden") engine calls"
