#!/bin/bash
# End-to-end scenario with a fake container engine: the commands that need one (start, stop, update, core, sync, doctor...).
# Run with OM=<command> OUT=<scratch dir> FAKEBIN=<dir holding the fake engine as `podman` and `ip`> OM_SRC=<repo root>
# FAKE_EDGE_PORT=<free port> (the stand-in for the edge answers there). OM_PY_SRC=<a checkout of the reference program's last commit> also copies that program (record.sh).
out=$OUT
rm -rf $out; mkdir -p $out/home/.om $out/ws $out/fakestate
cp -r $OM_SRC/core $OM_SRC/docs $OM_SRC/README.md $out/home/.om/
[ -n "$OM_PY_SRC" ] && cp -r $OM_PY_SRC/lib $OM_PY_SRC/bin $out/home/.om/
export HOME=$out/home OM_HOME=$out/home/.om NO_COLOR=1 PATH=$FAKEBIN:$PATH FAKE_LOG=$out/engine.log FAKE_STATE=$out/fakestate OM_RUNTIME=podman
export XDG_CONFIG_HOME=$out/home/.config XDG_DATA_HOME=$out/home/.local/share XDG_STATE_HOME=$out/home/.local/state
export GIT_DISCOVERY_ACROSS_FILESYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_AUTHOR_DATE="2026-01-01T00:00:00+0000" GIT_COMMITTER_DATE="2026-01-01T00:00:00+0000"
om() { $OM "$@"; }
cd $out/ws
run() { echo "\$ om $*"; om "$@" 2>&1; echo "rc=$?"; }
podman __serve $FAKE_EDGE_PORT 2>/dev/null & SRV=$!
trap "kill $SRV 2>/dev/null" EXIT
sleep 0.3
run config set OM_LAN_IP=off
run config set OM_HTTP_PORT=$FAKE_EDGE_PORT
# both ports above 1023: whether the machine lets rootless engines bind 80/443 (a sysctl) must not change the output
run config set OM_HTTPS_PORT=18443
git init -q -b main . ; git config user.email t@t; git config user.name t
run init demo
run add web --port 8080
git add -A; git commit -qm init
run start
run status
run logs web
run add api --image nginx:alpine --port 80 --public
run add worker --no-web
run add proj --project
git add -A; git commit -qm more
run ports
run routes
run status --json
run docs
run docs start --path
run completion bash
run completion zsh
run completion fish
run doctor
run logs web -n 5
run logs nope
run shell web
run shell web ls -la
run shell nope
run stop web
run status
run start web
run restart web
run restart
run restart --build
run update --dry-run
run update
run update --image docker.io/library/nginx:alpine
run lock
run log
run log --json
run fsck
run reload
run drift
run network
run network harden
run dev proj
run dev nope
run disable worker
run status
run enable worker
run down
run start
run rollback
run rollback 1
git checkout -q main
run start
# --- a remote, a newer commit upstream, sync and drift
git init -q --bare $out/remote.git
git remote add origin $out/remote.git
git push -q -u origin main 2>&1
git clone -q -b main $out/remote.git $out/ws2 2>&1
( cd $out/ws2 && git config user.email t@t && git config user.name t && echo '# tweak' >> services/api/compose.yml && git commit -qam 'tweak api' && git push -q origin main 2>&1 )
run drift
run sync
run drift
run sync --force
run sync --rebase
echo x > services/web/dirty.txt
run sync
run drift
rm services/web/dirty.txt
run autosync on
run sync --scheduled
run autosync off
# --- previews
run preview list
run preview feat-x
git branch feat-y
run preview feat-y
run preview list
run preview rm feat-x
run preview rm feat-y
run preview list
# --- egress, images, scans, notifications
run egress
run egress web
run egress log
run egress log web
run prune
run prune --yes
run scan
run notify
run lock
run update --dry-run
run logs web -f
# --- a crashed core container and heal
podman stop om_router 2>/dev/null
run core status
run core heal
run core status
run status
run core status
run core stop
run core status
run core start
run core restart
run core restart router dashboard
run core restart nope
run core reload
run core update
run core heal
run boot status
run boot enable
run boot status
run boot disable
run autosync status
run autosync on
run autosync status
run autosync off
run firewall status
run firewall apply
run firewall status
run firewall remove
run stop --all
export FAKE_DOWN=1
run status
run start
run stop
run core start
run core status
run logs web
run reload
run doctor
unset FAKE_DOWN
run uninstall --yes
echo "--- files"; find $HOME -type f -not -path "*/.om/*" -not -path "*/fakestate/*" -not -path "*/.cache/*" | sed "s#$HOME#~#" | sort
