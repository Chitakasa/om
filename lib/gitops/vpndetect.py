#!/usr/bin/env python3
"""Address and VPN detection: the LAN address, every tunnel interface by kernel kind (never by product name),
the system's DNS servers, and names a VPN's own DNS gives an address (a plain PTR query)."""

import json
import re
import secrets
import socket
from pathlib import Path

from gitops.omstate import IS_MACOS, IS_WINDOWS, run


def is_local_address(ip: str) -> bool:
    """True if ip is assigned to this host (binding to it succeeds)."""
    try:
        fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
        with socket.socket(fam, socket.SOCK_DGRAM) as s:
            s.bind((ip, 0))
        return True
    except OSError:
        return False


def detect_lan_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))  # TEST-NET-1: no packet is sent for UDP connect
            ip = s.getsockname()[0]
        if not ip.startswith("127.") and not ip.startswith("100.") and is_local_address(ip):
            return ip
    except OSError:
        pass
    return ""


def _powershell(script: str) -> str:
    r = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script])
    return r.stdout if r.returncode == 0 else ""


def _windows_virtual_adapters() -> list[tuple[str, str]]:
    """(name, IPv4) of every non-hardware adapter that is up (Windows: Wintun, TAP, ZeroTier…)."""
    out = _powershell("Get-NetAdapter | Where-Object { -not $_.HardwareInterface -and $_.Status -eq 'Up' } | "
                      "ForEach-Object { $ip = (Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 "
                      "-ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress; \"$($_.Name)`t$ip\" }")
    return [(n.strip(), ip.strip()) for n, _, ip in (line.partition("\t") for line in out.splitlines()) if n.strip()]


def _iface_ipv4(name: str) -> str:
    """First IPv4 address of a network interface ('' if none or unknown)."""
    if IS_WINDOWS:
        return next((ip for n, ip in _windows_virtual_adapters() if n.lower() == name.lower()), "")
    r = run(["ip", "-j", "-4", "addr", "show", "dev", name])
    if r.returncode == 0:
        try:
            for info in json.loads(r.stdout or "[]"):
                for a in info.get("addr_info", []):
                    if a.get("local"):
                        return a["local"]
        except ValueError:
            pass
    r = run(["ifconfig", name])
    m = re.search(r"\binet (\d+\.\d+\.\d+\.\d+)", r.stdout) if r.returncode == 0 else None
    return m.group(1) if m else ""


def vpn_candidates() -> list[tuple[str, str]]:
    """(interface, IPv4) of every interface that may be a VPN, whatever its product or name.
    Linux: tunnel devices by kernel kind (`tun`, also tap; `wireguard`). macOS: every interface
    with an address that is not loopback or a hardware port. Windows: every non-hardware adapter.
    Listing too much is harmless: none is trusted without `om vpn trust`."""
    if IS_WINDOWS:
        return [(n, ip) for n, ip in _windows_virtual_adapters() if ip]
    r = run(["ip", "-d", "-j", "link", "show"])
    if r.returncode == 0:
        try:
            return [(link["ifname"], _iface_ipv4(link["ifname"])) for link in json.loads(r.stdout or "[]")
                    if (link.get("linkinfo") or {}).get("info_kind") in ("tun", "wireguard")]
        except (ValueError, KeyError):
            pass
    hw = set(re.findall(r"(?m)^Device:\s*(\S+)", run(["networksetup", "-listallhardwareports"]).stdout))
    r = run(["ifconfig"])
    out = []
    for block in re.split(r"\n(?=\S)", r.stdout if r.returncode == 0 else ""):
        m = re.match(r"([\w.-]+):", block)
        ip = re.search(r"\binet (\d+\.\d+\.\d+\.\d+)", block)
        if m and ip and m.group(1) not in hw and "LOOPBACK" not in block.split("\n")[0]:
            out.append((m.group(1), ip.group(1)))
    return out


def _bsd_route_dest(d: str) -> str:
    """macOS netstat's abbreviated IPv4 destination ('100.64/10', '192.168.1', '10', 'default') as CIDR."""
    if d == "default":
        return "0.0.0.0/0"
    addr, _, plen = d.split("%")[0].partition("/")
    octets = addr.split(".")
    if not 1 <= len(octets) <= 4 or not all(o.isdigit() for o in octets):
        return ""
    return ".".join(octets + ["0"] * (4 - len(octets))) + "/" + (plen or str(8 * len(octets)))


def _macos_routes(iface: str, text: str) -> list[str]:
    """Destinations routed via iface in `netstat -rn -f inet` output; the interface column is found by its
    header (Netif), since other columns (Refs, Use, Expire) come and go between macOS versions."""
    lines = text.splitlines()
    hdr = next((ln.split() for ln in lines if ln.startswith("Destination")), [])
    col = hdr.index("Netif") if "Netif" in hdr else -1
    return [_bsd_route_dest(t[0]) for t in (ln.split() for ln in lines) if col >= 0 and len(t) > col and t[col] == iface]


def vpn_items(spec: str) -> list[str]:
    """OM_VPN as a list: the interfaces and addresses you trusted (`om vpn trust`)."""
    spec = (spec or "").strip()
    if spec.lower() in ("", "off", "auto"):  # `auto` (before om vpn) trusts nothing by itself
        return []
    return list(dict.fromkeys(x.strip() for x in spec.split(",") if x.strip() and x.strip().lower() not in ("off", "auto")))


def _nameservers() -> list[str]:
    """IPv4 DNS servers the system uses, including a VPN's own (scoped resolvers on macOS,
    per-adapter servers on Windows)."""
    if IS_WINDOWS:
        found = re.findall(r"\d+\.\d+\.\d+\.\d+", _powershell("(Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses"))
    elif IS_MACOS:
        found = re.findall(r"nameserver\[\d+\]\s*:\s*(\d+\.\d+\.\d+\.\d+)", run(["scutil", "--dns"]).stdout)
    else:
        try:
            found = re.findall(r"(?m)^\s*nameserver\s+(\d+\.\d+\.\d+\.\d+)\s*$", Path("/etc/resolv.conf").read_text(encoding="utf-8"))
        except OSError:
            found = []
    return list(dict.fromkeys(found))


def _ptr_query(ip: str, server: str, timeout: float = 1.5) -> str:
    """One DNS PTR lookup (RFC 1035) straight to `server`; '' if none. Plain protocol, so it asks
    the VPN's own DNS (the system's NSS would answer with this host's name for its own address)."""
    qid = secrets.randbits(16)
    qname = b"".join(bytes([len(x)]) + x.encode() for x in reversed(ip.split("."))) + b"\x07in-addr\x04arpa\x00"
    packet = qid.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x0c\x00\x01"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (server, 53))
            data = sock.recv(1500)
    except OSError:
        return ""
    if len(data) < 12 or int.from_bytes(data[:2], "big") != qid or not int.from_bytes(data[6:8], "big"):
        return ""

    def name_at(pos, depth=0):
        labels = []
        while pos < len(data) and depth < 10:
            n = data[pos]
            if n == 0:
                return ".".join(labels), pos + 1
            if n & 0xC0 == 0xC0:
                label, _ = name_at(((n & 0x3F) << 8) | data[pos + 1], depth + 1)
                return ".".join(labels + ([label] if label else [])), pos + 2
            labels.append(data[pos + 1:pos + 1 + n].decode("ascii", "replace"))
            pos += 1 + n
        return "", pos

    pos = 12 + len(qname) + 4  # header + question
    for _ in range(int.from_bytes(data[6:8], "big")):
        _, pos = name_at(pos)
        rtype, rdlen = int.from_bytes(data[pos:pos + 2], "big"), int.from_bytes(data[pos + 8:pos + 10], "big")
        if rtype == 12:
            return name_at(pos + 10)[0].rstrip(".").lower()
        pos += 10 + rdlen
    return ""


def _reverse_names(ip: str) -> list[str]:
    """Names devices may use for this machine on a VPN: the VPN's own DNS name for the address
    (PTR, e.g. MagicDNS), its first label, and this machine's hostname."""
    names = []
    for server in _nameservers():
        name = _ptr_query(ip, server)
        if name and re.fullmatch(r"[a-z0-9.-]+", name) and not name.endswith((".arpa", "localhost")):
            names += [name, name.split(".")[0]]
            break
    host = socket.gethostname().split(".")[0].lower()
    if re.fullmatch(r"[a-z0-9-]+", host):
        names.append(host)
    return list(dict.fromkeys(names))


def detect_vpn(spec: str) -> tuple[list[str], list[str]]:
    """(addresses, names) of the VPNs you trusted (OM_VPN). No VPN is trusted by itself: a tunnel
    may be a commercial or company VPN or a public network, and om cannot tell without root."""
    ips = []
    for item in vpn_items(spec):
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", item):
            if is_local_address(item):
                ips.append(item)
        else:
            ip = _iface_ipv4(item)
            if ip and is_local_address(ip):
                ips.append(ip)
    ips = list(dict.fromkeys(ips))
    names = [n for ip in ips for n in _reverse_names(ip)]
    return ips, list(dict.fromkeys(names))
