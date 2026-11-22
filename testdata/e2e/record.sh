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
# what the machine itself holds (other login accounts, firewall rules installed in /etc, its user name) is not recorded
hostfree() {
    python3 -c 'import re, sys
s = sys.stdin.read()
s = re.sub(r"; other accounts: .*", "", s)
s = re.sub(r"(?s)\"other_accounts\": \[.*?\]", "\"other_accounts\": []", s)
s = re.sub(r"(?m)^  (PASS|WARN|FAIL)  (Login|Address rules) .*\n(?:[ ]+↳ .*\n)*", "", s)
s = re.sub(r"(show-user|enable-linger) \S+", r"\1 USER", s)
sys.stdout.write(s)'
}
OM="python3 $out/home/.om/bin/om" OM_PY=1 OUT="$out" FAKEBIN="$tmp/fakebin" OM_SRC="$repo" FAKE_EDGE_PORT=$port \
    bash "$here/engine.sh" 2>&1 | sed -e "s#$out#OUT#g" -e "s#\\b$port\\b#18080#g" | hostfree > "$here/engine.golden"
sed -e "s#$out#OUT#g" "$out/engine.log" | hostfree > "$here/engine.log.golden"
echo "recorded $(wc -l < "$here/engine.golden") lines of output and $(wc -l < "$here/engine.log.golden") engine calls"

# basic.golden: the commands that need no engine
bash "$here/fakebasic.sh" "$tmp/fakebasic"
bout="$tmp/BASIC"
OM="python3 $bout/home/.om/bin/om" OM_PY=1 OM_SRC="$repo" OUT="$bout" FAKEBIN="$tmp/fakebasic" bash "$here/basic.sh" 2>&1 |
    sed -E -e "s#$bout#OUT#g" -e 's/"last_active": [0-9]+/"last_active": N/' -e 's/[0-9]{8}-[0-9]{6}/TS/g' \
        -e 's#/tmp/(tmp[a-z0-9_]+|[0-9]+)\.cfg#/tmp/X.cfg#g' | hostfree > "$here/basic.golden"
echo "recorded $(wc -l < "$here/basic.golden") lines of basic output"
