#!/usr/bin/env python3
"""`om firewall log`: refused and accepted connections from the kernel log, and what the edge logged."""

from __future__ import annotations

import json
import re

from gitops import omsettings, omstate, wsregistry
from gitops.enginectl import detect_runtime
from gitops.omstate import run

_KLOG_RE = re.compile(r"kernel: (om-(?:refused|in))(?: ([^:]*))?: .*?\bSRC=(\S+) .*?\bPROTO=(\S+)(?: .*?\bDPT=(\d+))?")

def port_names() -> dict:
    """{host port: what answers there} for om's ports."""
    h, s = omsettings.edge_ports()
    names = {h: "front door (http)", s: "front door (https)", 8080: "public tier (VPN)", 8443: "public tier https (VPN)"}
    for key, slot in wsregistry.service_slots().items():
        names[omstate.PRIVATE_PORT_BASE + slot] = f"{key} (private)"
        names[omstate.PUBLIC_PORT_BASE + slot] = f"{key} (public)"
    return names

def firewall_events(text: str) -> tuple[dict, dict]:
    """({(rule, source, target): count} refused, {(source, target): count} connected) from kernel log lines."""
    names, refused, connected = port_names(), {}, {}
    for m in _KLOG_RE.finditer(text):
        kind, rule, src, proto, dpt = m.groups()
        target = names.get(int(dpt), f"port {dpt}") if dpt else proto.lower()
        if kind == "om-in":
            connected[(src, target)] = connected.get((src, target), 0) + 1
        else:
            key = (rule or "not an om port", src, target)
            refused[key] = refused.get(key, 0) + 1
    return refused, connected

def edge_events(text: str) -> dict:
    """{site: {"requests", "4xx", "5xx", "logins"}} from the edge's access log (no URLs are logged)."""
    out = {}
    for line in text.splitlines():
        if '"handled request"' not in line:
            continue
        try:
            e = json.loads(line[line.index("{"):])
        except ValueError:
            continue
        site = (e.get("request") or {}).get("host", "?")
        st = out.setdefault(site, {"requests": 0, "4xx": 0, "5xx": 0, "logins": set()})
        st["requests"] += 1
        code = int(e.get("status") or 0)
        st["4xx"] += 400 <= code < 500
        st["5xx"] += code >= 500
        if e.get("user_id"):
            st["logins"].add(e["user_id"])
    return out

def cmd_firewall_log(args):
    since = args.since if re.fullmatch(r"\d+[smhd]", args.since) else "24h"
    print(f"\n\033[1mFIREWALL LOG\033[0m  (last {since}; real source addresses)")
    print("═" * 78)
    if omstate.IS_LINUX:
        r = run(["journalctl", "-k", "--no-pager", "-o", "short-iso", "--since", f"-{since}", "--grep", "om-(refused|in)"])
        if r.returncode not in (0, 1) or "No journal files" in r.stderr or ("permission" in r.stderr.lower() and not r.stdout):
            print("  The kernel log is not readable for this account (it needs the wheel, adm or systemd-journal group):")
            print(f"    sudo journalctl -k --since -{since} --grep 'om-(refused|in)'")
        else:
            refused, connected = firewall_events(r.stdout)
            print("  \033[31mRefused\033[0m" + ("  — none" if not refused else ""))
            for (rule, src, target), n in sorted(refused.items(), key=lambda x: -x[1])[:20]:
                print(f"    {n:>5}×  {src:<40} → {target:<34} ({rule})")
            print("  \033[32mConnected\033[0m" + ("  — none" if not connected else ""))
            for (src, target), n in sorted(connected.items(), key=lambda x: -x[1])[:20]:
                print(f"    {n:>5}×  {src:<40} → {target}")
    elif omstate.IS_MACOS:
        print("  pf logs refused packets to pflog0:  sudo tcpdump -n -e -ttt -i pflog0")
    else:
        print(r"  Windows Firewall logs dropped packets to %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log")
    runtime = detect_runtime()
    edge = edge_events(run([runtime, "logs", "--since", since, omstate.EDGE]).stdout)
    print("\n\033[1mEDGE\033[0m  (what happened, never what was asked: no URLs; om.log=off services absent)")
    print("═" * 78)
    if not edge:
        print("  no requests logged")
    for site, st in sorted(edge.items(), key=lambda x: -x[1]["requests"]):
        logins = f"  logins: {', '.join(sorted(st['logins']))}" if st["logins"] else ""
        print(f"  {st['requests']:>6} requests  {st['4xx']:>4} 4xx  {st['5xx']:>4} 5xx   {site}{logins}")
    print()
