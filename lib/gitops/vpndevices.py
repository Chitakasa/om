#!/usr/bin/env python3
"""VPN device listing for `om vpn` / `om vpn devices`: peers, names, allowed or not, last contact."""

from __future__ import annotations

import re

from gitops import core, hostsetup
from gitops.core import run
from gitops.cli import emit_json

_DEV_RE = re.compile(r"^(\S+) .*?kernel: (om-in|om-refused)[^:]*: .*?\bSRC=(\S+) DST=(\S+)")

def vpn_device_events(text: str, local: set) -> dict:
    """{source: {"connected", "refused", "last"}} for packets to this machine's VPN addresses (kernel log)."""
    out = {}
    for line in text.splitlines():
        m = _DEV_RE.match(line)
        if not m or m.group(4) not in local:
            continue
        ts, kind, src, _ = m.groups()
        d = out.setdefault(src, {"connected": 0, "refused": 0, "last": ""})
        d["connected" if kind == "om-in" else "refused"] += 1
        d["last"] = max(d["last"], ts)
    return out

def vpn_devices() -> list[dict]:
    """Every device on the trusted VPNs: the VPN's peers (core.vpn_peers: from the kernel's routes), the
    allow-list, and every VPN address seen in the firewall log (7 days); named through the VPN's own DNS
    (a PTR query), with allowed or not."""
    import ipaddress
    from concurrent.futures import ThreadPoolExecutor
    allowed = [ipaddress.ip_network(n) for n in core.vpn_allow()]
    local = set(core.resolve_settings().get("vpn_ips", []))
    events = {}
    if core.IS_LINUX and local:
        r = run(["journalctl", "-k", "--no-pager", "-o", "short-iso", "--since", "-7d", "--grep", "om-(refused|in)"])
        events = vpn_device_events(r.stdout, local)
    addrs = sorted(set(events) | {str(n.network_address) for n in allowed if n.num_addresses == 1} | set(core.vpn_peers()),
                   key=lambda a: ipaddress.ip_address(a))
    servers = core._nameservers()
    def name(ip):
        return next((n.split(".")[0] for s in servers for n in [core._ptr_query(ip, s)] if n), "")
    with ThreadPoolExecutor(max_workers=16) as pool:
        names = dict(zip(addrs, pool.map(name, addrs)))
    out = []
    for ip in addrs:
        a = ipaddress.ip_address(ip)
        e = events.get(ip, {"connected": 0, "refused": 0, "last": ""})
        out.append({"address": ip, "name": names[ip], "allowed": not allowed or any(a in n for n in allowed), **e})
    return out

def vpn_public_url() -> str:
    """Where VPN devices outside the allow-list find the public tier: this machine's VPN name, port 8080."""
    hosts = core.vpn_hosts()
    return f"http://{hosts[-1] if hosts else '<vpn address>'}:8080/"

def vpn_others() -> str:
    """What VPN devices outside the allow-list get (hostsetup._vpn_fallback)."""
    if hostsetup.vpn_fallback_applied():
        return f"the others get the public tier, at the same address (or {vpn_public_url()})"
    return f"the others get the public tier only, at {vpn_public_url()} (the private address gives them no answer)"

def print_vpn_devices(devices: list[dict]):
    allowed = core.vpn_allow()
    if allowed:
        state = "\033[32menforced by the firewall\033[0m" if hostsetup.vpn_allow_enforced() else \
            "\033[31mnot in the firewall: the VPN's private tier is closed until `om firewall apply`\033[0m"
        print(f"\n  Private tier over the VPN: only the allowed devices ({state});"
              f"\n  {vpn_others()}")
    else:
        print("\n  Private tier over the VPN: every device on it (`om vpn allow <device>` to keep it to yours)")
    if not devices:
        print("  No other device found on the trusted VPNs.")
        return
    print()
    for d in devices:
        state = "\033[32mallowed    \033[0m" if d["allowed"] else "\033[31mnot allowed\033[0m"
        seen = f"last seen {d['last'][:16].replace('T', ' ')}" if d["last"] else "no contact in 7 days"
        counts = ", ".join(x for x in (f"{d['connected']} connected" if d["connected"] else "",
                                         f"{d['refused']} refused" if d["refused"] else "") if x)
        print(f"  {d['name'] or '?':<20} {d['address']:<16} {state}  {seen:<27} {counts}")
    print("\n  Change it: om vpn allow|disallow <device> (updates the firewall at once).")

def cmd_vpn_devices(args):
    devices = vpn_devices()
    if getattr(args, "json", False):
        emit_json({"allow_list": core.vpn_allow() or None, "devices": devices})
        return
    print("\n\033[1mVPN DEVICES\033[0m")
    print_vpn_devices(devices)
    print()
