#!/usr/bin/env python3
"""Host-integration commands: `om vpn`, `om firewall`, `om boot` (moved out of bin/om; bin/om re-exports them)."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from gitops import core, hostsetup, policy
from gitops.cli import die, emit_json
from gitops.core import detect_runtime, read_registry
from gitops.firewalllog import cmd_firewall_log
from gitops.routesync import sync_caddy_routes
from gitops.vpndevices import cmd_vpn_devices, print_vpn_devices, vpn_devices, vpn_others
from gitops.workspace import discover_compose_dirs, find_compose_file, get_workspace_env


def vpn_device(name: str) -> tuple[str, str]:
    """(network, how to show it) for an address, a range, or a VPN device name this machine resolves."""
    import ipaddress
    import socket
    try:
        net = str(ipaddress.ip_network(name, strict=False))
        return net, net
    except ValueError:
        pass
    try:
        ip = next(a[4][0] for a in socket.getaddrinfo(name, None, socket.AF_INET))
    except (OSError, StopIteration):
        die(f"'{name}' is not an address, a range, or a name this machine can resolve.")
    return str(ipaddress.ip_network(ip)), f"{name} ({ip})"


def cmd_vpn_allow(args):
    """Only the listed VPN devices reach the private tier over the VPN (OM_VPN_ALLOW)."""
    if not (args.name or "").strip():
        die(f"Usage: om vpn {args.action} <device address, range or VPN name>")
    net, shown = vpn_device(args.name.strip())
    allowed = core.vpn_allow()
    if args.action == "allow":
        if net in allowed:
            print(f"  {shown} is already allowed.")
            return
        allowed.append(net)
    else:
        if net not in allowed:
            die(f"{shown} is not on the VPN allow-list ({', '.join(allowed) or 'empty'}).")
        allowed.remove(net)
    core.set_setting("OM_VPN_ALLOW", ",".join(allowed))
    print(f"\033[32m✓ OM_VPN_ALLOW={','.join(allowed) or '(none)'}\033[0m")
    runtime = detect_runtime()
    # The firewall first: once it carries the new list nothing is stale, so no device loses access in
    # between. Only where om's firewall is already installed (installing it is `om firewall apply`'s call).
    applied = False
    if not getattr(args, "no_apply", False) and hostsetup.firewall_installed():
        print("  Updating the host firewall now, so the change is in effect at once (sudo):")
        applied = apply_firewall(runtime) and hostsetup.vpn_allow_enforced()
    if not applied:
        # Fail closed: a stale firewall must not keep a removed device in, so the VPN's private tier
        # (and services with om.net.allow=vpn) close until `om firewall apply`.
        if any("vpn" in (p.get("allow") or []) for p in core.net_policies().values()):
            resync_all_routes(runtime)
        if core.core_running(runtime) and core.runtime_drift(runtime):
            core.core_up(runtime, recreate=True, quiet=True)
    if not allowed:
        print("  Every device on a trusted VPN reaches the private tier again."
              + ("" if not hostsetup.stale_net_rules() else " Run `om firewall apply` to drop the old firewall rule."))
    elif hostsetup.vpn_allow_enforced():
        print(f"  Only these VPN devices reach the private tier; {vpn_others()}.")
    else:
        print("  \033[33mThe VPN's private tier stays closed until the firewall carries the list: om firewall apply\033[0m")


def cmd_vpn(root, args):
    """Which VPNs reach the private tier; trust or untrust one (no om.env editing)."""
    if args.action in ("allow", "disallow"):
        return cmd_vpn_allow(args)
    if args.action == "devices":
        return cmd_vpn_devices(args)
    spec = core.load_settings().get("OM_VPN", "")
    trusted = core.vpn_items(spec)
    cands = core.vpn_candidates()
    allowed = core.vpn_allow()
    if args.action == "list" and getattr(args, "json", False):
        emit_json({"trusted": trusted, "names": core.vpn_hosts(),
                   "interfaces": [{"name": i, "address": ip, "trusted": i in trusted or ip in trusted} for i, ip in cands],
                   "allowed_devices": allowed or None, "allow_enforced": hostsetup.vpn_allow_enforced(),
                   "devices": vpn_devices() if trusted else []})
        return
    if args.action == "list":
        print(f"\n\033[1mVPN\033[0m  (OM_VPN={spec or '(none)'})")
        if not cands and not trusted:
            print("  No VPN on this machine. Install one whose members are your own devices, then `om vpn`.\n")
            return
        for iface, ip in cands:
            mark = "\033[32mtrusted\033[0m" if iface in trusted or ip in trusted else "\033[33mnot trusted\033[0m"
            print(f"  {iface:<14} {ip or '-':<16} {mark}")
        for item in trusted:
            if item not in [i for i, _ in cands] + [ip for _, ip in cands]:
                print(f"  {item:<14} {'-':<16} \033[32mtrusted\033[0m (not present now)")
        if trusted:
            print_vpn_devices(vpn_devices())
        untrusted = [i for i, ip in cands if i not in trusted and ip not in trusted]
        if untrusted:
            print("\n  Trust a VPN only if every member is your own device (not a commercial or company VPN,")
            print("  not a public network):")
            for i in untrusted:
                print(f"    om vpn trust {i}")
        print()
        return
    name = (args.name or "").strip()
    if not name:
        die(f"Usage: om vpn {args.action} <interface or address>")
    # Interface names as the OS spells them (Windows adapters: "Tailscale", "ZeroTier One [..]")
    name = next((i for i, _ in cands if i.lower() == name.lower()), None) \
        or next((t for t in trusted if t.lower() == name.lower()), name)
    if args.action == "trust":
        if name not in [i for i, _ in cands] and not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", name):
            die(f"No VPN interface '{name}'. `om vpn` lists them.")
        if name in trusted:
            print(f"  {name} is already trusted.")
            return
        trusted.append(name)
    else:
        if name not in trusted:
            die(f"{name} is not trusted.")
        trusted.remove(name)
    new = ",".join(trusted)
    core.set_setting("OM_VPN", new)
    print(f"\033[32m✓ OM_VPN={new or '(none)'}\033[0m")
    runtime = detect_runtime()
    if core.core_running(runtime) and not core.core_up(runtime, recreate=True, quiet=True):
        die("The core did not come back; `om doctor` shows why.")
    print("  Run `om firewall apply` so the firewall follows the new VPN addresses.")


def apply_firewall(runtime: str) -> bool:
    """Write and load the host firewall, then let the core and the routes follow it: the VPN's private
    tier is bound once the firewall carries the allow-list, services with om.net get their own ports."""
    ok = hostsetup.firewall_apply()
    if ok and core.core_running(runtime) and core.runtime_drift(runtime):
        print("  Restarting the core: the VPN's private tier follows the firewall's allow-list...")
        core.core_up(runtime, recreate=True, quiet=True)
    if ok and core.net_policies():
        resync_all_routes(runtime)  # services restricted by om.net get their own ports once the firewall has their rules
        if core.IS_WINDOWS:
            print("  After running the script above, run `om reload` in each workspace whose services use om.net.")
    return ok


def resync_all_routes(runtime: str):
    """Regenerate every registered workspace's routes (address rules decide which services have own ports)."""
    for _wid, d in sorted(read_registry().items()):
        ws_root = Path(d.get("path", ""))
        if (ws_root / ".om" / "config.json").exists():
            sync_caddy_routes(ws_root, runtime)


def cmd_firewall(root, args):
    if args.action == "log":
        return cmd_firewall_log(args)
    if args.action == "show":
        path = hostsetup.generate_firewall()
        print(path.read_text(encoding="utf-8"))
        print(f"# written to {path}")
    elif args.action == "apply":
        print("\033[1m🛡  Applying host firewall (inbound default-drop; only om ingress open)...\033[0m")
        sys.exit(0 if apply_firewall(detect_runtime()) else 1)
    elif args.action == "remove":
        hostsetup.firewall_remove()
    else:
        print(f"  Host firewall: {hostsetup.firewall_status()}")


def user_mounts() -> dict:
    """Host paths the registered workspaces need: their folders (read) and RW bind mounts (write)."""
    runtime = detect_runtime()
    read, write = [], []
    for wid, d in sorted(read_registry().items()):
        root = Path(d.get("path", ""))
        if not (root / ".om" / "config.json").exists():
            continue
        read.append(str(root))
        env = get_workspace_env(root, wid, runtime)
        for _, dd in discover_compose_dirs(root):
            cfg, _ = policy.compose_config(runtime, find_compose_file(dd), env)
            for svc in ((cfg or {}).get("services") or {}).values():
                for v in (svc or {}).get("volumes") or []:
                    if isinstance(v, dict) and v.get("type") == "bind" and not str(v.get("source", "")).endswith(".sock"):
                        src = str(v["source"])
                        (read if v.get("read_only") else write).append(src)
    workspaces = [str(Path(d["path"])) for d in read_registry().values()
                  if d.get("path") and (Path(d["path"]) / ".om" / "config.json").exists()]
    inside = lambda p: any(Path(p).is_relative_to(w) for w in workspaces)  # noqa: E731
    return {"workspaces": sorted(workspaces),
            "media": sorted({p for p in read if not inside(p)} - set(write)),
            "write": sorted(set(write))}


def cmd_boot(root, args):
    runtime = detect_runtime()
    if args.action == "enable":
        ok = hostsetup.boot_enable(runtime)
        print("\033[32m✓ Containers restart at boot; self-heal re-applies the network every 2 minutes.\033[0m"
              if ok else "\033[31m✗ Could not fully enable start at boot (see messages above).\033[0m")
    elif args.action == "disable":
        hostsetup.boot_disable()
        print("\033[32m✓ Self-heal disabled.\033[0m (Engine restart policy unchanged.)")
    else:
        print(f"  Start at boot: {hostsetup.boot_status(runtime)}")
