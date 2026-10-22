#!/usr/bin/env python3
"""
hostsetup.py — OS integration for 'om': host firewall, scheduled GitOps sync, start at boot.

Each feature has a Linux, macOS and Windows implementation. Anything needing admin
rights is done with `sudo` (Linux/macOS, interactive) or emitted as a script to run
from an elevated PowerShell (Windows).
"""

import re
import sys
import json
import shutil
import getpass
import hashlib
import ipaddress
import subprocess
from pathlib import Path

from gitops.core import OM_HOME, FIREWALL_DIR, USER_ENV, IS_LINUX, IS_MACOS, IS_WINDOWS, run, resolve_settings, edge_ports
from gitops.core import net_policies, no_log_ports

OM_BIN = OM_HOME / "bin" / "om"

# Ports every install needs open inbound besides the om front door.
BASE_UDP: list[str] = []       # VPN transports need no rule: their peers answer outgoing packets (conntrack)

def ingress_tcp() -> list[str]:
    """The front door's host ports (OM_HTTP_PORT / OM_HTTPS_PORT, default 80/443)."""
    return [str(p) for p in edge_ports()]

VPN_PUBLIC_TCP = ["8080", "8443"]  # the public tier on VPN addresses (core.render_ports)

def service_port_ranges() -> tuple[str, str]:
    """Per-service ports (core.render_ports): private range (loopback, VPN), public range (LAN, VPN)."""
    from gitops.core import PRIVATE_PORT_BASE, PUBLIC_PORT_BASE, PORT_SLOTS
    return (f"{PRIVATE_PORT_BASE}-{PRIVATE_PORT_BASE + PORT_SLOTS - 1}", f"{PUBLIC_PORT_BASE}-{PUBLIC_PORT_BASE + PORT_SLOTS - 1}")

def vpn_ips() -> list[str]:
    return resolve_settings().get("vpn_ips", [])

def ingress_udp() -> list[str]:
    return [str(edge_ports()[1])]  # HTTP/3

def _ports(spec: str) -> list[str]:
    out = []
    for part in (spec or "").replace(" ", "").split(","):
        if re.fullmatch(r"\d{1,5}(-\d{1,5})?", part):
            out.append(part)
    return out


# ── Firewall ────────────────────────────────────────────────────────────────

NFT_INSTALLED = Path("/etc/om-firewall.nft")
PF_INSTALLED = Path("/etc/pf.anchors/om")

# Per-service source addresses (om.net.allow / om.net.deny, see gitops.routes): the host firewall is the
# only place that sees who connects, so each service's own ports get their own rules. A refused address
# gets no answer at all: its packets are dropped before anything listens. This machine (loopback) is
# always allowed.

def _expand(pol: dict) -> dict:
    """om.net.allow=vpn → the devices on the VPN allow-list now (gitops.routes.VPN_KEYWORD)."""
    allow = pol.get("allow")
    if allow is None or "vpn" not in allow:
        return pol
    return {**pol, "allow": list(dict.fromkeys([a for a in allow if a != "vpn"] + vpn_allow()))}

def _by_family(nets) -> tuple[list[str], list[str]]:
    nets = [ipaddress.ip_network(n) for n in nets or []]
    return [str(n) for n in nets if n.version == 4], [str(n) for n in nets if n.version == 6]

def nft_net_rules(key: str, pol: dict, forward: bool = False) -> list[str]:
    """nft lines for one address rule: {"ports": tcp ports, "udp": udp ports, "daddr": local addresses (optional),
    "allow": [...] | None, "deny": [...]}. forward=True: the same rule for connections a rootful engine
    forwards to a container (DNAT): matched on the port and address the client connected to."""
    pol = _expand(pol)
    lines = [f"# om.net: {key}"]
    daddr = pol.get("daddr")
    for l4, ports in (("tcp", pol.get("ports")), ("udp", pol.get("udp"))):
        if not ports:
            continue
        plist = ", ".join(str(p) for p in ports)
        if forward:
            m = (f"meta l4proto {l4} ct status dnat " + (f"ct original ip daddr {{ {', '.join(daddr)} }} " if daddr else "")
                 + f"ct original proto-dst {{ {plist} }}")
        else:
            m = (f"ip daddr {{ {', '.join(daddr)} }} " if daddr else "") + f"{l4} dport {{ {plist} }}"
        if pol.get("allow") is not None:
            a4, a6 = _by_family(pol["allow"])
            lines.append(f"{m} ip saddr != {{ {', '.join(a4)} }} drop" if a4 else f"{m} meta nfproto ipv4 drop")
            if not daddr:  # an IPv4 local address never sees IPv6 sources
                lines.append(f"{m} ip6 saddr != {{ {', '.join(a6)} }} drop" if a6 else f"{m} meta nfproto ipv6 drop")
        d4, d6 = _by_family(pol.get("deny"))
        if d4:
            lines.append(f"{m} ip saddr {{ {', '.join(d4)} }} drop")
        if d6 and not daddr:
            lines.append(f"{m} ip6 saddr {{ {', '.join(d6)} }} drop")
    # Each drop is logged first, by its own rule: a `limit` on the drop itself would let packets over
    # the rate fall through to the accepts below.
    out = []
    for l in lines:
        if l.endswith(" drop"):
            out.append(f'{l[:-len(" drop")]} {LOG_LIMIT} log prefix "om-refused {key[:96]}: " level info')
        out.append(l)
    return out

def vpn_allow() -> list[str]:
    from gitops.core import vpn_allow as _vpn_allow
    return _vpn_allow()

def vpn_restriction() -> dict | None:
    """The VPN device allow-list (OM_VPN_ALLOW) as an address rule: on the VPN addresses, the private tier
    (front door and every service's private port) answers only the listed devices. The public tier stays."""
    allow, ips = vpn_allow(), vpn_ips()
    if not allow or not ips:
        return None
    h, s = edge_ports()
    return {"daddr": ips, "ports": [str(h), str(s), service_port_ranges()[0]], "udp": [str(s)], "allow": allow, "deny": []}

def restrictions() -> list[tuple[str, dict]]:
    """Every address rule: per-service om.net policies, then the VPN device allow-list."""
    out = sorted(net_policies().items())
    vpn = vpn_restriction()
    return out + ([("vpn", vpn)] if vpn else [])

# Logging (kernel log, `om firewall log`): refusals always — they are attacks, not your usage — and new
# connections to om's ports with their real source address, except to om.log=off services. Rate-limited,
# so a flood cannot fill the log; this machine's own connections (loopback) are never logged.
LOG_LIMIT = "limit rate 20/minute burst 30 packets"
IN_LOG_LIMIT = "limit rate 120/minute burst 240 packets"

def om_ports() -> list[str]:
    """Host ports om listens on: the front door, the VPN's public tier, every service's own ports."""
    priv, pub = service_port_ranges()
    return ingress_tcp() + VPN_PUBLIC_TCP + [priv, pub]

def nft_in_log(forward: bool = False) -> str:
    """Log every new connection to om's ports (not to om.log=off services) with its real source."""
    ports, quiet = ", ".join(om_ports()), ", ".join(str(p) for p in no_log_ports())
    if forward:
        m = f"meta l4proto tcp ct state new ct status dnat ct original proto-dst {{ {ports} }}"
        m += f" ct original proto-dst != {{ {quiet} }}" if quiet else ""
    else:
        m = f"ct state new tcp dport {{ {ports} }}" + (f" tcp dport != {{ {quiet} }}" if quiet else "")
    return f'{m} {IN_LOG_LIMIT} log prefix "om-in: " level info'

def _nft_net_block(forward: bool = False) -> str:
    lines = []
    rules = restrictions()
    if rules:
        lines.append("# Source addresses (om.net.allow / om.net.deny, OM_VPN_ALLOW): dropped before any accept below")
        for key, pol in rules:
            lines += nft_net_rules(key, pol, forward)
    lines += ["# New connections to om's ports, with their real source (not om.log=off services)", nft_in_log(forward)]
    return "".join(f"        {l}\n" for l in lines) + "\n"

def _nft_forward_chain() -> str:
    """Rootful engines (Docker, rootful Podman) publish ports by DNAT: those connections are forwarded to the
    container and never pass the input chain. The same rules (and logging) apply on that path; nothing
    else forwarded is touched."""
    return ("\n    chain forward {\n        type filter hook forward priority filter - 10; policy accept;\n\n"
            + _nft_net_block(forward=True).rstrip("\n") + "\n    }\n")

def _pf_table(key: str, kind: str) -> str:
    return f"om_{hashlib.sha256(key.encode()).hexdigest()[:12]}_{kind}"  # pf table names are short

def pf_net_rules(key: str, pol: dict) -> tuple[list[str], list[str]]:
    """(table definitions, rules). Tables, because pf expands `! { a b }` into rules that block everyone."""
    pol = _expand(pol)
    tables, rules = [], [f"# om.net: {key}"]
    to = f"to {{ {' '.join(pol['daddr'])} }}" if pol.get("daddr") else "to any"
    ta, td = _pf_table(key, "allow"), _pf_table(key, "deny")
    if pol.get("allow") is not None:
        tables.append(f"table <{ta}> {{ {' '.join(pol['allow'])} }}")
    if pol.get("deny"):
        tables.append(f"table <{td}> {{ {' '.join(pol['deny'])} }}")
    for proto, ports in (("tcp", pol.get("ports")), ("udp", pol.get("udp"))):
        if not ports:
            continue
        plist = " ".join(str(p).replace("-", ":") for p in ports)
        if pol.get("allow") is not None:
            rules.append(f"block drop in log quick proto {proto} from ! <{ta}> {to} port {{ {plist} }}")
        if pol.get("deny"):
            rules.append(f"block drop in log quick proto {proto} from <{td}> {to} port {{ {plist} }}")
    return tables, rules

def _complement(nets: list[str], version: int) -> list[str]:
    """Every address of that IP version outside nets (Windows block rules cannot say `not`)."""
    rest = [ipaddress.ip_network("0.0.0.0/0" if version == 4 else "::/0")]
    for n in ipaddress.collapse_addresses(ipaddress.ip_network(x) for x in nets):
        rest = [part for r in rest for part in (r.address_exclude(n) if n.subnet_of(r) else [] if r.subnet_of(n) else [r])]
    return [str(r) for r in ipaddress.collapse_addresses(rest)] if rest else []

def win_net_rules(key: str, pol: dict) -> list[tuple[str, str]]:
    """[(display name, PowerShell line)]; the name carries a digest of the rule, so a stale one is seen."""
    pol = _expand(pol)
    digest = hashlib.sha256(json.dumps(pol, sort_keys=True).encode()).hexdigest()[:8]
    local = f" -LocalAddress {','.join(pol['daddr'])}" if pol.get("daddr") else ""
    blocks = []
    if pol.get("allow") is not None:
        a4, a6 = _by_family(pol["allow"])
        blocks.append(("allow-only", _complement(a4, 4) + ([] if pol.get("daddr") else _complement(a6, 6))))
    if pol.get("deny"):
        blocks.append(("deny", list(pol["deny"])))
    out = []
    for proto, ports in (("TCP", pol.get("ports")), ("UDP", pol.get("udp"))):
        for kind, addrs in blocks:
            if ports and addrs:
                name = f"om net {key} {kind}{'' if proto == 'TCP' else ' udp'} {digest}"
                out.append((name, f'New-NetFirewallRule -Group "om" -DisplayName "{name}" -Direction Inbound -Protocol {proto}'
                                  f'{local} -LocalPort {",".join(str(p) for p in ports)} -RemoteAddress {",".join(addrs)} -Action Block | Out-Null'))
    return out

def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""

def vpn_allow_enforced() -> bool:
    """No VPN allow-list, or the firewall in effect carries it."""
    rule = vpn_restriction()
    return rule is None or net_policy_enforced("vpn", rule)

def net_policy_enforced(key: str, pol: dict) -> bool:
    """The host firewall in effect carries exactly this service's om.net rules."""
    if IS_LINUX:
        # The drops decide; the log lines beside them do not, so a firewall applied before logging
        # existed still counts as enforcing (om doctor reports the missing logging on its own).
        have = {l.strip() for l in _read(NFT_INSTALLED).splitlines()}
        drops = [l for fwd in (False, True) for l in nft_net_rules(key, pol, fwd) if l.endswith(" drop")]
        return firewall_status() == "active" and all(l in have for l in drops)
    if IS_MACOS:
        tables, rules = pf_net_rules(key, pol)
        have = {l.replace(" in log quick ", " in quick ") for l in _read(PF_INSTALLED).splitlines()}
        return all(l.replace(" in log quick ", " in quick ") in have for l in tables + rules)
    if IS_WINDOWS:
        out = run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                   "Get-NetFirewallRule -Group om -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName"])
        have = set(out.stdout.splitlines()) if out.returncode == 0 else set()
        return all(name in have for name, _ in win_net_rules(key, pol))
    return False

def logging_applied() -> bool | None:
    """The applied firewall logs refusals and connections; None where om cannot tell (Windows)."""
    if IS_LINUX:
        return 'log prefix "om-in: "' in _read(NFT_INSTALLED)
    if IS_MACOS:
        return "block in log all" in _read(PF_INSTALLED)
    return None

def stale_net_rules() -> list[str]:
    """Rules the applied firewall still carries although their om.net labels or OM_VPN_ALLOW changed or are gone."""
    text = _read(NFT_INSTALLED) if IS_LINUX else _read(PF_INSTALLED) if IS_MACOS else ""
    pols = dict(restrictions())
    applied = sorted(set(re.findall(r"# om\.net: (\S+)", text)))
    return [k for k in applied if k not in pols or not net_policy_enforced(k, pols[k])]

def render_nft(extra_tcp: list[str], extra_udp: list[str]) -> str:
    tcp = ", ".join(ingress_tcp() + extra_tcp)
    udp = ", ".join(ingress_udp() + BASE_UDP + extra_udp)
    ips = vpn_ips()
    priv, pub = service_port_ranges()
    vpn_rule = (f"# Public tier and every service's private port on VPN addresses only\n"
                f"        ip daddr {{ {', '.join(ips)} }} tcp dport {{ {', '.join(VPN_PUBLIC_TCP)}, {priv} }} accept\n"
                if ips else "# No VPN address: the public tier is on the LAN only\n")
    vpn_rule += f"        # Public services' own ports (bound only on the LAN and VPN addresses)\n        tcp dport {pub} accept"
    return f"""#!/usr/sbin/nft -f
# GENERATED by `om firewall` — edit OM_FIREWALL_EXTRA_* in {USER_ENV} instead.
# Inbound default-drop. Only om's front door (Caddy 80/443) and the listed system
# ports are reachable; anything else listening on this host is not.
# Own table: never touches a VPN's or the container engine's rules.

table inet om_guard
delete table inet om_guard

table inet om_guard {{
    chain input {{
        type filter hook input priority filter - 10; policy drop;

        iifname "lo" accept
        ct state invalid drop
        ct state {{ established, related }} accept

        # IPv6 needs neighbor discovery; ICMP errors keep TCP healthy (PMTU)
        icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, packet-too-big, destination-unreachable, time-exceeded, parameter-problem }} accept
        icmp type {{ destination-unreachable, time-exceeded, parameter-problem }} accept

        # DHCP replies
        udp sport 67 udp dport 68 accept
        udp sport 547 udp dport 546 accept

        # mDNS (.local names) on Ethernet/Wi-Fi only, never over a tunnel
        iiftype ether udp dport 5353 accept

{_nft_net_block()}        # Front door + user extras
        tcp dport {{ {tcp} }} accept
        udp dport {{ {udp} }} accept
        {vpn_rule}

        # Anything else unsolicited is dropped by the policy; log it first (unicast to this host only)
        meta pkttype host ct state new {LOG_LIMIT} log prefix "om-refused: " level info
    }}
{_nft_forward_chain()}}}
"""

def render_pf(extra_tcp: list[str], extra_udp: list[str]) -> str:
    def pf(p):
        return p.replace("-", ":")
    tcp = " ".join(pf(p) for p in ingress_tcp() + extra_tcp)
    udp = " ".join(pf(p) for p in ingress_udp() + BASE_UDP + ["5353"] + extra_udp)
    net = [pf_net_rules(k, v) for k, v in restrictions()]
    tables = "".join(f"{l}\n" for t, _ in net for l in t)
    blocks = "".join(f"{l}\n" for _, r in net for l in r)
    return f"""# GENERATED by `om firewall` (macOS pf anchor "om").
# Inbound default-block; only the om front door and listed ports are reachable.
set skip on lo0
{tables}block in log all
{blocks}pass out all keep state
pass in inet proto icmp all icmp-type {{ unreach, timex, paramprob }}
pass in inet6 proto ipv6-icmp all
pass in proto udp from any port 67 to any port 68
pass in proto tcp to any port {{ {tcp} }} keep state
pass in proto udp to any port {{ {udp} }} keep state
""" + "".join(f"pass in proto tcp to {ip} port {{ {' '.join(VPN_PUBLIC_TCP)} {service_port_ranges()[0].replace('-', ':')} }} keep state\n" for ip in vpn_ips()) \
      + f"pass in proto tcp to any port {service_port_ranges()[1].replace('-', ':')} keep state\n"

def render_windows(extra_tcp: list[str], extra_udp: list[str]) -> str:
    tcp = ",".join(ingress_tcp() + extra_tcp)
    udp = ",".join(ingress_udp() + BASE_UDP + extra_udp)
    ips = vpn_ips()
    priv, pub = service_port_ranges()
    vpn_rule = (f'New-NetFirewallRule -Group "om" -DisplayName "om public tier and service ports (VPN)" -Direction Inbound -Protocol TCP '
                f'-LocalAddress {",".join(ips)} -LocalPort {",".join(VPN_PUBLIC_TCP)},{priv} -Action Allow | Out-Null\n') if ips else ""
    vpn_rule += (f'New-NetFirewallRule -Group "om" -DisplayName "om public service ports" -Direction Inbound -Protocol TCP '
                 f'-LocalPort {pub} -Action Allow | Out-Null\n')
    return f"""# GENERATED by `om firewall`. Run from an elevated PowerShell:
#   powershell -ExecutionPolicy Bypass -File "{FIREWALL_DIR / 'om-firewall.ps1'}"
# Blocks unsolicited inbound traffic on all profiles and allows only om's ports.
# Note: other programs' existing "allow" rules still apply; review them with
#   Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True
$ErrorActionPreference = "Stop"
Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
Set-NetFirewallProfile -All -LogBlocked True -LogMaxSizeKilobytes 16384
Get-NetFirewallRule -Group "om" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -Group "om" -DisplayName "om ingress (TCP)" -Direction Inbound -Protocol TCP -LocalPort {tcp} -Action Allow | Out-Null
New-NetFirewallRule -Group "om" -DisplayName "om ingress (UDP)" -Direction Inbound -Protocol UDP -LocalPort {udp} -Action Allow | Out-Null
{vpn_rule}{"".join(line + chr(10) for k, v in restrictions() for _, line in win_net_rules(k, v))}Write-Host "om firewall applied."
"""

SYSTEMD_FW_UNIT = """[Unit]
Description=om host firewall (inbound default-drop, only om ingress exposed)
Wants=network-pre.target
Before=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/env nft -f /etc/om-firewall.nft
ExecStop=/usr/bin/env nft delete table inet om_guard

[Install]
WantedBy=multi-user.target
"""

def generate_firewall() -> Path:
    s = resolve_settings()
    tcp, udp = _ports(s["firewall_extra_tcp"]), _ports(s["firewall_extra_udp"])
    FIREWALL_DIR.mkdir(parents=True, exist_ok=True)
    if IS_LINUX:
        path = FIREWALL_DIR / "om.nft"
        path.write_text(render_nft(tcp, udp), encoding="utf-8", newline="\n")
        (FIREWALL_DIR / "om-firewall.service").write_text(SYSTEMD_FW_UNIT, encoding="utf-8", newline="\n")
    elif IS_MACOS:
        path = FIREWALL_DIR / "om.pf"
        path.write_text(render_pf(tcp, udp), encoding="utf-8", newline="\n")
    else:
        path = FIREWALL_DIR / "om-firewall.ps1"
        path.write_text(render_windows(tcp, udp), encoding="utf-8", newline="\n")
    return path

def _sudo(cmd: list[str]) -> bool:
    print(f"  $ sudo {' '.join(cmd)}")
    return subprocess.run(["sudo"] + cmd).returncode == 0

def firewall_apply() -> bool:
    path = generate_firewall()
    if IS_LINUX:
        if not shutil.which("nft"):
            print("\033[31m✗ nftables (nft) is not installed.\033[0m")
            return False
        steps = [
            ["install", "-m644", str(path), "/etc/om-firewall.nft"],
            ["install", "-m644", str(FIREWALL_DIR / "om-firewall.service"), "/etc/systemd/system/om-firewall.service"],
            ["systemctl", "daemon-reload"],
            ["systemctl", "enable", "om-firewall"],
            ["systemctl", "restart", "om-firewall"],
        ]
        return all(_sudo(s) for s in steps)
    if IS_MACOS:
        steps = [
            ["install", "-m644", str(path), "/etc/pf.anchors/om"],
            ["pfctl", "-a", "om", "-f", "/etc/pf.anchors/om"],
            ["pfctl", "-E"],
        ]
        ok = all(_sudo(s) for s in steps)
        print("  To keep it across reboots, add to /etc/pf.conf:\n"
              '    anchor "om"\n    load anchor "om" from "/etc/pf.anchors/om"')
        return ok
    print(f"Run this from an elevated PowerShell:\n  powershell -ExecutionPolicy Bypass -File \"{path}\"")
    return True

def firewall_remove() -> bool:
    if IS_LINUX:
        _sudo(["systemctl", "disable", "--now", "om-firewall"])
        return _sudo(["nft", "delete", "table", "inet", "om_guard"]) or True
    if IS_MACOS:
        return _sudo(["pfctl", "-a", "om", "-F", "all"])
    print('Run from an elevated PowerShell:\n  Get-NetFirewallRule -Group "om" | Remove-NetFirewallRule')
    return True

def firewall_status() -> str:
    """'active', 'inactive' or 'unknown' (checking may need privileges)."""
    if IS_LINUX:
        r = run(["systemctl", "is-active", "om-firewall"])
        return "active" if r.stdout.strip() == "active" else "inactive"
    if IS_MACOS:
        return "unknown"
    r = run(["powershell", "-NoProfile", "-Command", "(Get-NetFirewallRule -Group om -ErrorAction SilentlyContinue | Measure-Object).Count"])
    return "active" if r.stdout.strip() not in ("", "0") else "inactive"


# ── Scheduled jobs (auto-sync, self-heal) ────────────────────────────────────

def _om_cmd() -> list[str]:
    return [sys.executable, str(OM_BIN)]

def _systemd_user_dir() -> Path:
    return Path.home() / ".config" / "systemd" / "user"

def _launchd_plist(name: str) -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"dev.om.{name}.plist"

def schedule(name: str, args: list[str], every_minutes: int, description: str, boot_delay: str = "1min") -> bool:
    """Run `om <args>` every N minutes and shortly after boot, using the OS scheduler."""
    cmd = _om_cmd() + args
    if IS_LINUX and shutil.which("systemctl"):
        d = _systemd_user_dir()
        d.mkdir(parents=True, exist_ok=True)
        (d / f"om-{name}.service").write_text(f"""[Unit]
Description={description}

[Service]
Type=oneshot
Environment=OM_HOME={OM_HOME}
ExecStart={' '.join(cmd)}
""", encoding="utf-8", newline="\n")
        (d / f"om-{name}.timer").write_text(f"""[Unit]
Description={description} (timer)

[Timer]
OnBootSec={boot_delay}
OnUnitActiveSec={every_minutes}min
Persistent=true

[Install]
WantedBy=timers.target
""", encoding="utf-8", newline="\n")
        run(["systemctl", "--user", "daemon-reload"])
        return run(["systemctl", "--user", "enable", "--now", f"om-{name}.timer"]).returncode == 0
    if IS_MACOS:
        plist = _launchd_plist(name)
        plist.parent.mkdir(parents=True, exist_ok=True)
        argx = "".join(f"<string>{a}</string>" for a in cmd)
        plist.write_text(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>dev.om.{name}</string>
  <key>ProgramArguments</key><array>{argx}</array>
  <key>EnvironmentVariables</key><dict><key>OM_HOME</key><string>{OM_HOME}</string></dict>
  <key>StartInterval</key><integer>{every_minutes * 60}</integer>
  <key>RunAtLoad</key><true/>
</dict></plist>
""", encoding="utf-8", newline="\n")
        run(["launchctl", "unload", str(plist)])
        return run(["launchctl", "load", str(plist)]).returncode == 0
    if IS_WINDOWS:
        tr = " ".join(f'"{a}"' for a in cmd)
        return run(["schtasks", "/Create", "/F", "/SC", "MINUTE", "/MO", str(every_minutes),
                    "/TN", f"om-{name}", "/TR", tr]).returncode == 0
    print(f"No supported scheduler found. Add to `crontab -e`:\n  */{every_minutes} * * * * {' '.join(cmd)}")
    return False

def unschedule(name: str) -> bool:
    if IS_LINUX and shutil.which("systemctl"):
        run(["systemctl", "--user", "disable", "--now", f"om-{name}.timer"])
        for suffix in ("service", "timer"):
            (_systemd_user_dir() / f"om-{name}.{suffix}").unlink(missing_ok=True)
        run(["systemctl", "--user", "daemon-reload"])
        return True
    if IS_MACOS:
        plist = _launchd_plist(name)
        run(["launchctl", "unload", str(plist)])
        plist.unlink(missing_ok=True)
        return True
    if IS_WINDOWS:
        run(["schtasks", "/Delete", "/F", "/TN", f"om-{name}"])
        return True
    return True

def schedule_status(name: str) -> str:
    if IS_LINUX and shutil.which("systemctl"):
        return run(["systemctl", "--user", "is-active", f"om-{name}.timer"]).stdout.strip() or "inactive"
    if IS_MACOS:
        return "active" if run(["launchctl", "list", f"dev.om.{name}"]).returncode == 0 else "inactive"
    if IS_WINDOWS:
        return "active" if run(["schtasks", "/Query", "/TN", f"om-{name}"]).returncode == 0 else "inactive"
    return "unknown"

def autosync_enable(every_minutes: int = 1) -> bool:
    # Fires every minute; each workspace's own interval_seconds decides whether it syncs.
    return schedule("autosync", ["sync", "--scheduled"], every_minutes, "om scheduled GitOps sync", "2min")

def autosync_disable() -> bool:
    return unschedule("autosync")

def autosync_status() -> str:
    return schedule_status("autosync")


# ── Start at boot ───────────────────────────────────────────────────────────

def boot_status(runtime: str) -> str:
    heal = schedule_status("heal")
    engine = _engine_boot_status(runtime)
    if heal == "active" and engine.startswith("enabled") and "only after" not in engine:
        return "enabled"
    parts = [f"engine: {engine}", f"self-heal: {heal}"]
    return "partial (" + "; ".join(parts) + ")" if heal == "active" or engine.startswith("enabled") else "disabled"

def watch_enable() -> bool:
    """Linux/systemd: `om core watch` as a service, so a container whose process dies unseen is
    restarted within a couple of seconds instead of at the next 2-minute self-heal."""
    if not (IS_LINUX and shutil.which("systemctl")):
        return False
    d = _systemd_user_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / "om-watch.service").write_text(f"""[Unit]
Description=om container watcher (instant recovery)

[Service]
Type=simple
Environment=OM_HOME={OM_HOME}
ExecStart={' '.join(_om_cmd() + ['core', 'watch'])}
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
""", encoding="utf-8", newline="\n")
    run(["systemctl", "--user", "daemon-reload"])
    return run(["systemctl", "--user", "enable", "--now", "om-watch.service"]).returncode == 0

def watch_disable() -> bool:
    if IS_LINUX and shutil.which("systemctl"):
        run(["systemctl", "--user", "disable", "--now", "om-watch.service"])
        (_systemd_user_dir() / "om-watch.service").unlink(missing_ok=True)
        run(["systemctl", "--user", "daemon-reload"])
    return True

def boot_enable(runtime: str) -> bool:
    """Containers restart at boot, and a self-heal job re-applies the network every 2 minutes
    (new LAN address, a VPN coming up late, core crashed)."""
    ok = _engine_boot_enable(runtime)
    watch_enable()  # optional extra: instant recovery; the 2-minute self-heal below is the fallback
    return schedule("heal", ["core", "heal"], 2, "om core self-heal", "30s") and ok

def boot_disable() -> bool:
    watch_disable()
    return unschedule("heal")

def _engine_boot_status(runtime: str) -> str:
    if runtime == "podman" and IS_LINUX:
        en = run(["systemctl", "--user", "is-enabled", "podman-restart.service"]).stdout.strip()
        linger = run(["loginctl", "show-user", getpass.getuser(), "--property=Linger"]).stdout.strip()
        if en == "enabled" and linger.endswith("yes"):
            return "enabled"
        if en == "enabled":
            return "enabled (containers start only after you log in; run `om boot enable` to start at boot)"
        return "disabled"
    if runtime == "docker" and IS_LINUX:
        return "enabled" if run(["systemctl", "is-enabled", "docker"]).stdout.strip() == "enabled" else "disabled"
    return "managed by your engine's app (Docker Desktop / Podman Desktop: 'start at login')"

def _engine_boot_enable(runtime: str) -> bool:
    """Make containers with restart policies come back after a reboot."""
    if runtime == "podman" and IS_LINUX:
        ok = run(["systemctl", "--user", "enable", "--now", "podman-restart.service"]).returncode == 0
        if run(["loginctl", "enable-linger", getpass.getuser()]).returncode != 0:
            ok = _sudo(["loginctl", "enable-linger", getpass.getuser()]) and ok
        return ok
    if runtime == "docker" and IS_LINUX:
        return _sudo(["systemctl", "enable", "docker"])
    if IS_MACOS and runtime == "podman":
        plist = Path.home() / "Library" / "LaunchAgents" / "dev.om.podman-machine.plist"
        plist.parent.mkdir(parents=True, exist_ok=True)
        plist.write_text(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>dev.om.podman-machine</string>
  <key>ProgramArguments</key><array><string>{shutil.which('podman') or 'podman'}</string><string>machine</string><string>start</string></array>
  <key>RunAtLoad</key><true/>
</dict></plist>
""", encoding="utf-8", newline="\n")
        return run(["launchctl", "load", str(plist)]).returncode == 0
    print("Enable 'Start at login' in Docker Desktop / Podman Desktop settings; om's containers restart with the engine.")
    return True
