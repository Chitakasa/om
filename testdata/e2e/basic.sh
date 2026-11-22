#!/bin/bash
# End-to-end scenario: run with OM=<binary> OUT=<scratch dir> FAKEBIN=<dir holding fake podman>.
out=$OUT
rm -rf $out; mkdir -p $out/home/.om $out/ws
export HOME=$out/home OM_HOME=$out/home/.om NO_COLOR=1 PATH=$FAKEBIN:$PATH FAKE_LOG=$out/engine.log OM_RUNTIME=podman XDG_CONFIG_HOME=$out/home/.config XDG_DATA_HOME=$out/home/.local/share XDG_STATE_HOME=$out/home/.local/state
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
om() { $OM "$@"; }
cd $out/ws
run() { echo "\$ om $*"; om "$@" 2>&1; echo "rc=$?"; }
run init demo
run init
run add web --port 8080
run add api --image nginx:alpine --port 80 --public
run add worker --no-web
run add proj --project
run add "bad name!"
run edit web --scope public --icon 🌐 --desc "Hello"
run edit web
run scripts
mkdir -p scripts/ops; printf '#!/bin/sh\n# Say hi\necho hi "$@"\n' > scripts/hello.sh; chmod +x scripts/hello.sh; printf '#!/bin/sh\n# Nested one\necho nested\n' > scripts/ops/clean.sh
run scripts
run run hello a b
run run ops/clean
run run nope
run status
run status --json
run routes
run routes --json
run list --json
run lock
run log
run log --json
run disable worker
run enable worker
run remove worker -y
run network
run drift
run config show
run config set OM_POLICY=enforce
run config set OM_POLICY=bogus
run config set OM_HTTP_PORTT=1
run config get OM_POLICY
run config unset OM_POLICY
run exposure
run exposure --json
run policy check
run vpn
run firewall status
run auth list
run links
run secrets list
run autosync status
run sync
run preview
run egress
run prune
run scan
run notify
find . -path ./.git -prune -o -type f -print | sort | grep -v '^./.om/state.json' | head -80
for f in .om/config.json services/web/compose.yml services/api/compose.yml .gitignore; do echo "--- $f"; sed 's/"created_at": ".*"/"created_at": "X"/' $f; done
echo "--- engine log"; sed "s#$out#OUT#g" $out/engine.log | head -80
