#!/bin/bash
# Re-records basic.golden, engine.golden and engine.log.golden from the ORIGINAL Python om. That program is no longer in
# the tree: it is the last Python commit of this repository (OM_REFERENCE, default below), checked out in a throwaway
# git worktree. Needs python3 (for the reference only), git, bash and go.
#   testdata/e2e/record.sh
# A change in the goldens is a change of behaviour: review the diff before committing it.
set -e
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
reference=${OM_REFERENCE:-9b19235e}
tmp=$(mktemp -d)
trap 'git -C "$repo" worktree remove --force "$tmp/ref" 2>/dev/null; rm -rf "$tmp"' EXIT
git -C "$repo" worktree add --detach "$tmp/ref" "$reference" > /dev/null
(cd "$repo" && go build -o "$tmp/tools" ./testdata/e2e/tools)
bash "$here/fakebin.sh" "$tmp/fakebin"
port=$("$tmp/tools" freeport)
out="$tmp/OUT"
# what the machine itself holds (other login accounts, firewall rules installed in /etc, its user name) is not recorded
hostfree() { "$tmp/tools" hostfree; }
PYTHONUNBUFFERED=1 OM="python3 $out/home/.om/bin/om" OM_PY_SRC="$tmp/ref" OUT="$out" FAKEBIN="$tmp/fakebin" OM_SRC="$repo" FAKE_EDGE_PORT=$port \
    bash "$here/engine.sh" 2>&1 | sed -e "s#$out#OUT#g" -e "s#\\b$port\\b#18080#g" | hostfree > "$here/engine.golden"
sed -e "s#$out#OUT#g" "$out/engine.log" | hostfree > "$here/engine.log.golden"
echo "recorded $(wc -l < "$here/engine.golden") lines of output and $(wc -l < "$here/engine.log.golden") engine calls"

# basic.golden: the commands that need no engine
bash "$here/fakebasic.sh" "$tmp/fakebasic"
bout="$tmp/BASIC"
PYTHONUNBUFFERED=1 OM="python3 $bout/home/.om/bin/om" OM_PY_SRC="$tmp/ref" OM_SRC="$repo" OUT="$bout" FAKEBIN="$tmp/fakebasic" bash "$here/basic.sh" 2>&1 |
    sed -E -e "s#$bout#OUT#g" -e 's/"last_active": [0-9]+/"last_active": N/' -e 's/[0-9]{8}-[0-9]{6}/TS/g' \
        -e 's#/tmp/(tmp[a-z0-9_]+|[0-9]+)\.cfg#/tmp/X.cfg#g' | hostfree > "$here/basic.golden"
echo "recorded $(wc -l < "$here/basic.golden") lines of basic output"
