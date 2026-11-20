#!/usr/bin/env python3
"""Read-only views of a workspace's routes and host ports (`om routes`, `om ports`)."""

from __future__ import annotations

import re
from pathlib import Path

from gitops import hostsetup, omsettings, omstate, wsregistry
from gitops.cli import emit_json
from gitops.enginectl import detect_runtime
from gitops.omstate import run
from gitops.routes import SNIPPET_FILE
from gitops.workspace import get_workspace_id

CONF_D = omstate.ROUTES_DIR

def routes_data(ws_id: str) -> list[dict]:
    """Every web service of a workspace with its URLs per audience."""
    env = omstate.parse_env_file(omstate.RUNTIME_ENV)
    lan = env.get("LAN_IP", "")
    lan = "" if lan.endswith(".invalid") else lan
    vpn = omsettings.vpn_hosts()[-1:]  # the shortest name (the VPN's short name for this machine) or the address
    slots = wsregistry.service_slots()
    out = []
    for f in sorted(CONF_D.glob(f"{ws_id}-*.caddy")):
        svc = f.stem[len(ws_id) + 1:]
        text = f.read_text(encoding="utf-8")
        upstream = re.search(r"to_workspace\s+(\S+)", text)
        public = (CONF_D / f"{ws_id}-{svc}.public_alias").exists()
        slot = slots.get(f"{ws_id}/{svc}")
        urls = {"this_machine": f"{omsettings.base_url(f'{ws_id}.{svc}.localhost')}/"}
        if slot is not None:
            urls["vpn"] = [f"http://{h}:{omstate.PRIVATE_PORT_BASE + slot}/" for h in vpn]
            if public:
                urls["lan"] = [f"http://{lan}:{omstate.PUBLIC_PORT_BASE + slot}/"] if lan else []
                urls["vpn_guests"] = [f"http://{h}:{omstate.PUBLIC_PORT_BASE + slot}/" for h in vpn]
        net = wsregistry.net_policies().get(f"{ws_id}/{svc}")
        out.append({"service": svc, "scope": "public" if public else "private", "upstream": upstream.group(1) if upstream else None,
                    "custom_caddy": "# custom:" in text, "urls": urls, "logged": "log_skip" not in text,
                    "net": {"allow": net.get("allow"), "deny": net.get("deny", []),
                            "enforced": hostsetup.net_policy_enforced(f"{ws_id}/{svc}", net)} if net else None})

    st_ports = wsregistry.stream_ports()
    for key, st in sorted(st_ports.items()):
        if not key.startswith(f"{ws_id}/"):
            continue
        svc = key[len(ws_id) + 1:]
        hp = st.get("host_port")
        cp = st.get("container_port")
        scope = st.get("scope", "private")
        public = scope == "public"
        target = f"{ws_id}_{svc}:{cp}"
        urls = {"this_machine": f"tcp://127.0.0.1:{hp}"}
        if vpn:
            urls["vpn"] = [f"tcp://{h}:{hp}" for h in vpn]
        if public:
            if lan:
                urls["lan"] = [f"tcp://{lan}:{hp}"]
            if vpn:
                urls["vpn_guests"] = [f"tcp://{h}:{hp}" for h in vpn]
        net = wsregistry.net_policies().get(key)
        out.append({"service": svc, "scope": scope, "protocol": "tcp", "upstream": target,
                    "custom_caddy": False, "urls": urls, "logged": st.get("log") != "off",
                    "net": {"allow": net.get("allow"), "deny": net.get("deny", []),
                            "enforced": hostsetup.net_policy_enforced(key, net)} if net else None})
    return out

def cmd_routes(root: Path, args):
    ws_id = get_workspace_id(root)
    data = routes_data(ws_id)
    if getattr(args, "json", False):
        emit_json({"workspace": ws_id, "routes": data})
        return
    print(f"\n\033[1mROUTES: {ws_id}\033[0m")
    print("═" * 78)
    if not data:
        print("  No routes. Add a web service with `om add` and run `om start`.\n")
        return
    labels = {"vpn": "your VPN devices", "lan": "LAN", "vpn_guests": "VPN guests"}
    for r in data:
        tier = "\033[36mPUBLIC\033[0m" if r["scope"] == "public" else "\033[33mPRIVATE\033[0m"
        proto = " (tcp)" if r.get("protocol") == "tcp" else ""
        custom = f"  \033[35m+ custom {SNIPPET_FILE}\033[0m" if r["custom_caddy"] else ""
        print(f"  \033[1m{r['service']}\033[0m  ({tier}{proto}) → {r['upstream'] or '?'}{custom}")
        print(f"    {r['urls']['this_machine']}")
        for key in ("vpn", "lan", "vpn_guests"):
            for u in r["urls"].get(key, []):
                print(f"    {u}   ({labels[key]})")
        if not r["logged"]:
            print("    \033[36m🔇 om.log=off: no access log at the edge, no connection log in the firewall\033[0m")
        if r["net"]:
            allow = [f"VPN allow-list ({', '.join(omsettings.vpn_allow()) or 'empty'})" if a == "vpn" else a
                     for a in r["net"]["allow"] or []]
            rule = ([f"only {', '.join(allow)}"] if r["net"]["allow"] is not None else []) \
                + ([f"never {', '.join(r['net']['deny'])}"] if r["net"]["deny"] else [])
            print(f"    \033[36m🔒 om.net: {'; '.join(rule)} (and this machine)\033[0m" if r["net"]["enforced"] else
                  f"    \033[31m🔒 om.net: {'; '.join(rule)} — not in the host firewall yet: the ports above stay closed"
                  f" until `om firewall apply`\033[0m")
    print()

def cmd_ports(args):
    runtime = detect_runtime()
    print("\n\033[1mHOST PORTS\033[0m")
    print("═" * 78)
    r = run([runtime, "ps", "--format", "{{.Names}}\t{{.Ports}}"])
    leaks = []
    for line in r.stdout.splitlines():
        name, _, ports = line.partition("\t")
        binds = [p.strip() for p in ports.split(",") if "->" in p]
        if name in (omstate.EDGE, omstate.STREAM_EDGE):
            for b in binds:
                if name == omstate.STREAM_EDGE:
                    tier = "stream"
                else:
                    tier = "public (LAN)" if "->8080" in b or "->8443" in b else "private"
                print(f"  {b:<44} {tier}")
        elif binds:
            leaks.append((name, binds))
    if leaks:
        print("\n  \033[31mOther containers publishing host ports (bypass the proxy):\033[0m")
        for name, binds in leaks:
            print(f"    {name}: {', '.join(binds)}")
    else:
        print("\n  \033[32mNo other container publishes host ports.\033[0m")
    print()
