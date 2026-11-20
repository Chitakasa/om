#!/usr/bin/env python3
"""`om exposure`: who can reach what, from the registries and the generated files (never from what the docs say).

Three audiences can reach a machine running om: whoever uses this machine (loopback), the devices on a trusted VPN, and
the LAN. The private tier answers the first two (the VPN narrowed by `om vpn allow`), the public tier the LAN and the
VPN's guests. A service's own address rules (`om.net.allow` / `om.net.deny`) narrow its ports further, and only count
when the host firewall carries them. Egress is what a service may reach out to."""

from __future__ import annotations

import os
from pathlib import Path

from gitops import egress, hostsetup, omsettings, omstate, vpndetect, wsregistry
from gitops.cli import emit_json
from gitops.routesview import routes_data


def other_login_users() -> list[str]:
    """Other human accounts on this machine (Linux/macOS passwd; uid >= 1000 with a login shell)."""
    try:
        import pwd
        me = os.getuid()
        return sorted(u.pw_name for u in pwd.getpwall() if u.pw_uid >= 1000 and u.pw_uid != me and u.pw_uid < 60000
                      and not u.pw_shell.endswith(("nologin", "false")))
    except (ImportError, AttributeError):
        return []


def trusted_users() -> set[str]:
    """Accounts the user says are their own (OM_TRUSTED_USERS)."""
    return {u.strip() for u in omsettings.load_settings().get("OM_TRUSTED_USERS", "").split(",") if u.strip()}


def login_users() -> list[str]:
    """Names with a login on the private tier (`om auth`)."""
    from gitops.securitycmds import read_auth_users
    return sorted(read_auth_users(omstate.AUTH_DIR / "private.conf"))


def tiers() -> dict:
    """What each audience can reach, as the settings and the firewall have it now."""
    resolved = omsettings.resolve_settings()
    trusted = vpndetect.vpn_items(omsettings.load_settings().get("OM_VPN", ""))
    allow = omsettings.vpn_allow()
    others = other_login_users()
    return {
        "this_machine": {"you": True, "other_accounts": others, "trusted_accounts": sorted(set(others) & trusted_users())},
        "vpn": {"trusted": trusted, "addresses": resolved.get("vpn_ips", []), "allow_list": allow or None,
                "allow_list_enforced": hostsetup.vpn_allow_enforced() if allow else None},
        "lan": {"address": resolved.get("lan_ip") or None},
        "login": login_users(),
    }


def _is_loopback(network: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_network(network, strict=False).is_loopback
    except ValueError:
        return False


def egress_summary(ws: str, svc: str) -> str:
    rule = egress._load_rules(ws).get(svc)
    if rule is None:
        return "none (no way out)"
    if isinstance(rule, list):
        return f"{len(rule)} host{'s' if len(rule) != 1 else ''}"
    return {egress.INTERNET: "ANY public host", egress.LEARN: "ANY public host (learning)", egress.AUDIT: "ANY public host (audit)"}.get(rule, str(rule))


def audience(entry: dict, t: dict) -> list[str]:
    """Who reaches one service, one line per audience. `entry` is a routes_data row."""
    lines = ["this machine: yes"]
    net = entry.get("net") or {}
    allow = net.get("allow")
    deny = net.get("deny") or []
    vpn_allow = t["vpn"]["allow_list"]
    public = entry["scope"] == "public"

    def narrowed(devices: list[str]) -> str:
        if allow is not None:
            devices = [d for a in allow for d in (vpn_allow or ["(the VPN allow-list)"] if a == "vpn" else [a])]
            if all(_is_loopback(d) for d in devices):
                return "no one (the service's address rule allows only " + ", ".join(devices) + ")"
        text = ", ".join(devices)
        return text + (f", except {', '.join(deny)}" if deny else "")

    if net and not net.get("enforced"):
        lines.append("address rules: NOT in the host firewall yet; the service's own ports stay closed until `om firewall apply`")
    vpn = t["vpn"]
    if vpn["trusted"]:
        if public:
            lines.append("VPN: " + narrowed(["every device on " + "/".join(vpn["trusted"]) + " (public port)"]))
        else:
            devices = vpn_allow if vpn_allow else ["every device on " + "/".join(vpn["trusted"])]
            lines.append("VPN: " + narrowed(devices))
    if public:
        lan = t["lan"]["address"]
        lines.append("LAN: " + narrowed([f"every device on your network ({lan})" if lan else "every device on your network"]))
    return lines


def exposure_data() -> dict:
    """The whole picture: audiences and every routed service."""
    t = tiers()
    services = []
    for ws_id in sorted(wsregistry.read_registry()):
        for entry in routes_data(ws_id):
            svc = entry["service"]
            route = Path(omstate.ROUTES_DIR / f"{ws_id}-{svc}.caddy")
            has_login = route.is_file() and "basic_auth" in route.read_text(encoding="utf-8")
            services.append({"workspace": ws_id, "service": svc, "scope": entry["scope"], "protocol": entry.get("protocol", "http"),
                             "reachable_by": audience(entry, t), "egress": egress_summary(ws_id, svc),
                             "logged": entry["logged"], "own_login": has_login})
    return {"audiences": t, "services": services}


def print_exposure(data: dict):
    t = data["audiences"]
    print("\n\033[1mEXPOSURE\033[0m  (who can reach what, from the settings and the registries)")
    print("═" * 78)
    others, trusted = t["this_machine"]["other_accounts"], set(t["this_machine"]["trusted_accounts"])
    untrusted = [u for u in others if u not in trusted]
    print(f"  this machine   you{', ' + ', '.join(sorted(trusted)) + ' (yours)' if trusted else ''}"
          + (f"; \033[31mother accounts: {', '.join(untrusted)}\033[0m" if untrusted else ""))
    vpn = t["vpn"]
    if vpn["trusted"]:
        who = ", ".join(vpn["allow_list"]) if vpn["allow_list"] else "\033[33mevery device on it\033[0m"
        enforced = "" if not vpn["allow_list"] else (" (enforced by the firewall)" if vpn["allow_list_enforced"] else " \033[31m(not in the firewall: closed until om firewall apply)\033[0m")
        print(f"  VPN {'/'.join(vpn['trusted'])}   private tier: {who}{enforced}")
    else:
        print("  VPN            none trusted: nothing arrives from a VPN")
    print(f"  LAN            {t['lan']['address'] or 'not bound'}: public tier only")
    print("  private login  " + (f"on ({', '.join(t['login'])})" if t["login"] else "\033[33moff\033[0m: anyone who reaches the private tier sees every private service"))
    if not data["services"]:
        print("\n  No routed services yet.\n")
        return
    for s in data["services"]:
        tag = "\033[36mpublic \033[0m" if s["scope"] == "public" else "private"
        extra = []
        if s["own_login"]:
            extra.append("own login")
        if not s["logged"]:
            extra.append("not logged")
        print(f"\n  \033[1m{s['workspace']}/{s['service']}\033[0m  {tag} {s['protocol']}" + (f"  [{', '.join(extra)}]" if extra else ""))
        for line in s["reachable_by"]:
            print(f"    {line}")
        print(f"    outbound: {s['egress']}")
    print()


def cmd_exposure(root, args):
    data = exposure_data()
    if getattr(args, "json", False):
        emit_json(data)
    else:
        print_exposure(data)
