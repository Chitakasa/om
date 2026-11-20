#!/usr/bin/env python3
"""Settings and what is generated from them: om.env (`auto` / `off` / a value), the edge ports, the edge token, the VPN
as configured (OM_VPN, OM_VPN_ALLOW), and the files `om core start` writes for compose (runtime.env, ports.yml,
dashboard-mounts.yml)."""

import json
import os
import re
import secrets
import shutil
import socket
from pathlib import Path

from gitops.enginectl import engine_info
from gitops.omstate import (
    DATA_DIR,
    IS_LINUX,
    IS_MACOS,
    MOUNTS_FILE,
    PORT_SLOTS,
    PORTS_FILE,
    PRIVATE_PORT_BASE,
    PUBLIC_PORT_BASE,
    RUNTIME_ENV,
    STATE_DIR,
    STREAM_PORT_BASE,
    STREAM_PORT_SLOTS,
    TOKEN_FILE,
    USER_ENV,
    VPN_HTTP_PORT,
    VPN_HTTPS_PORT,
    disabled,
    parse_env_file,
    run,
    write_private,
)
from gitops.vpndetect import (
    _macos_routes,
    _nameservers,
    _powershell,
    _ptr_query,
    detect_lan_ip,
    detect_vpn,
    is_local_address,
    vpn_candidates,
    vpn_items,
)
from gitops.wsregistry import net_policies, read_registry, stream_ports


def vpn_allow(settings: dict | None = None) -> list[str]:
    """OM_VPN_ALLOW as normalized networks (invalid entries are dropped; `om vpn allow` validates)."""
    import ipaddress
    out = []
    for x in (settings or load_settings()).get("OM_VPN_ALLOW", "").split(","):
        try:
            out.append(str(ipaddress.ip_network(x.strip(), strict=False)))
        except ValueError:
            pass
    return list(dict.fromkeys(out))


def vpn_private_open() -> bool:
    """The VPN's private tier may be bound: no device allow-list, or the firewall enforces it (fail closed)."""
    if not vpn_allow():
        return True
    from gitops import hostsetup  # imports core; late to avoid a cycle
    return hostsetup.vpn_allow_enforced()


def _vpn_interfaces() -> list[str]:
    """The trusted VPN interfaces (OM_VPN lists interfaces or addresses; an address maps to its interface)."""
    items, cands = vpn_items(load_settings().get("OM_VPN", "")), vpn_candidates()
    return list(dict.fromkeys(next((i for i, ip in cands if item in (i, ip)), item) for item in items
                              if any(item in (i, ip) for i, ip in cands)))


def vpn_peers() -> list[str]:
    """IPv4 addresses of the other devices on the trusted VPNs, from the kernel's routes through each VPN
    interface — no VPN product's tool: a mesh VPN routes every peer (one host route each), a hub VPN routes
    a small subnet (scanned, ≤ /24, keeping addresses its DNS names), a layer-2 VPN has neighbours."""
    import ipaddress
    own = set(resolve_settings().get("vpn_ips", [])) | set(_nameservers())
    hosts, ranges = set(), []
    for iface in _vpn_interfaces():
        if IS_LINUX:
            r = run(["ip", "-j", "-4", "route", "show", "table", "all", "dev", iface])
            n = run(["ip", "-j", "-4", "neigh", "show", "dev", iface])
            try:
                dsts = [x.get("dst", "") for x in json.loads(r.stdout or "[]") if x.get("type", "unicast") == "unicast"]
                hosts |= {x["dst"] for x in json.loads(n.stdout or "[]") if x.get("dst")}
            except ValueError:
                dsts = []
        elif IS_MACOS:
            dsts = _macos_routes(iface, run(["netstat", "-rn", "-f", "inet"]).stdout)
        else:
            dsts = _powershell(f"(Get-NetRoute -AddressFamily IPv4 -InterfaceAlias '{iface}').DestinationPrefix").split()
        for d in dsts:
            try:
                net = ipaddress.ip_network(d if d != "default" else "0.0.0.0/0", strict=False)
            except ValueError:
                continue
            if net.prefixlen == 32:
                hosts.add(str(net.network_address))
            elif net.prefixlen >= 24:
                ranges.append(net)
    if ranges and not hosts:  # a hub VPN: which addresses of its subnet does its DNS know?
        from concurrent.futures import ThreadPoolExecutor
        servers = _nameservers()
        cands = [str(a) for net in ranges for a in net.hosts()][:512]
        with ThreadPoolExecutor(max_workers=32) as pool:
            named = pool.map(lambda ip: ip if any(_ptr_query(ip, sv, timeout=1.0) for sv in servers) else "", cands)
        hosts |= {ip for ip in named if ip}
    return sorted((h for h in hosts if h not in own and not ipaddress.ip_address(h).is_multicast),
                  key=ipaddress.ip_address)


USER_ENV_TEMPLATE = """# om platform settings. Values: auto (detect), off (disable), or an explicit value.
# After changing, run: om core restart
OM_LAN_IP=auto
# VPNs whose devices reach the private tier (docs/adr/0003): interfaces or addresses you trusted,
# e.g. wg0,10.8.0.1. Set with `om vpn trust <iface>`: only VPNs whose members are all your devices.
OM_VPN=
# Only these VPN devices (addresses or ranges) reach the private tier over the VPN; other VPN devices get
# the public tier only. Empty: every device on a trusted VPN. Set with `om vpn allow <device>`; enforced
# by the host firewall (`om firewall apply`), and until it is, the VPN's private tier is not bound at all.
OM_VPN_ALLOW=
# Notifications about image updates (`om notify test`): auto (desktop toasts, nothing leaves the machine),
# off, or a comma list of desktop, webhook. Every message is also appended to <state>/logs/notify.log.
# webhook POSTs the text to OM_NOTIFY_URL (e.g. https://ntfy.sh/your-topic): it leaves the machine, so it is never automatic.
OM_NOTIFY=auto
OM_NOTIFY_URL=
# Other accounts on this machine that are yours (comma list). `om doctor` does not count them as people
# who could use the private tier without a login.
OM_TRUSTED_USERS=
OM_WALLPAPERS_DIR=auto
# Host ports of the front door. Change them to run a second om (another OS user) on this machine.
OM_HTTP_PORT=80
OM_HTTPS_PORT=443
# Extra inbound ports for the host firewall (comma-separated, ranges allowed), e.g. KDE Connect: 1714-1764
OM_FIREWALL_EXTRA_TCP=
OM_FIREWALL_EXTRA_UDP=
# Deploy policy gate (privileged, host namespaces, ports:, sockets, sensitive mounts, …):
# enforce refuses the compose file and names the fix (or the om.policy.allow label); warn only reports. See `om policy check`.
OM_POLICY=enforce
# Signed deploys: a clean commit must be signed by a key in the workspace's trusted .om/allowed_signers.
# warn reports and deploys anyway; enforce refuses. A dirty tree always runs as an unsigned dev generation.
OM_SIGNED=warn
"""


def load_settings() -> dict:
    raw = parse_env_file(USER_ENV)
    # Back-compat with pre-1.0 names
    for old, new in (("LAN_IP", "OM_LAN_IP"),):
        if old in raw and new not in raw:
            raw[new] = raw[old]
    defaults = parse_env_file_text(USER_ENV_TEMPLATE)
    defaults.update({k: v for k, v in raw.items() if v != ""})
    return defaults


def parse_env_file_text(text: str) -> dict:
    tmp = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            tmp[k.strip()] = v.strip()
    return tmp


def resolve_settings(settings: dict | None = None) -> dict:
    """Turn 'auto'/'off' settings into concrete values for this boot."""
    s = settings or load_settings()
    out = {}

    lan = s.get("OM_LAN_IP", "auto").lower()
    out["lan_ip"] = "" if lan == "off" else (detect_lan_ip() if lan == "auto" else lan)

    out["vpn_ips"], out["vpn_names"] = detect_vpn(s.get("OM_VPN", "auto"))

    wp = s.get("OM_WALLPAPERS_DIR", "auto")
    if wp.lower() == "auto":
        cand = Path.home() / "Pictures" / "Wallpapers"
        wp = str(cand if cand.is_dir() else DATA_DIR / "wallpapers")
    out["wallpapers_dir"] = str(Path(os.path.expanduser(wp)))

    out["http_port"], out["https_port"] = edge_ports(s)
    out["firewall_extra_tcp"] = s.get("OM_FIREWALL_EXTRA_TCP", "")
    out["firewall_extra_udp"] = s.get("OM_FIREWALL_EXTRA_UDP", "")
    return out


def vpn_hosts() -> list[str]:
    """VPN addresses and names the running core answers to (from runtime.env), names last."""
    v = parse_env_file(RUNTIME_ENV).get("VPN_HOSTS", "")
    return [h for h in v.split(",") if h and not h.endswith(".invalid")]


def edge_ports(settings: dict | None = None) -> tuple[int, int]:
    """(http, https) host ports of the edge. Invalid values fall back to 80/443."""
    s = settings or load_settings()
    out = []
    for key, default in (("OM_HTTP_PORT", 80), ("OM_HTTPS_PORT", 443)):
        v = s.get(key, str(default))
        out.append(int(v) if v.isdigit() and 1 <= int(v) <= 65535 else default)
    return out[0], out[1]


def base_url(host: str = "localhost") -> str:
    """http URL of a host on the private tier, with the port only when it is not 80."""
    port = edge_ports()[0]
    return f"http://{host}" + ("" if port == 80 else f":{port}")


def edge_token() -> str:
    """The shared secret proving a request came through the edge proxy. Created once."""
    if TOKEN_FILE.exists():
        tok = TOKEN_FILE.read_text(encoding="utf-8").strip()
        if re.fullmatch(r"[0-9a-f]{64}", tok):
            return tok
    tok = secrets.token_hex(32)
    write_private(TOKEN_FILE, tok + "\n")
    return tok


def set_setting(key: str, value: str):
    """Set KEY=value in the user's om.env, keeping every other line."""
    lines = USER_ENV.read_text(encoding="utf-8").splitlines() if USER_ENV.exists() else []
    lines = [ln for ln in lines if not ln.startswith(f"{key}=")] + [f"{key}={value}"]
    USER_ENV.parent.mkdir(parents=True, exist_ok=True)
    USER_ENV.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def _unique(items):
    return list(dict.fromkeys(items))


def _http_binds(resolved: dict) -> list[str]:
    """Edge (HTTP) bindings: loopback and VPN addresses → private tier, LAN → public tier, VPN addresses also the
    public tier on 8080/8443."""
    h, s = resolved.get("http_port", 80), resolved.get("https_port", 443)
    priv = f"{PRIVATE_PORT_BASE}-{PRIVATE_PORT_BASE + PORT_SLOTS - 1}"
    pub = f"{PUBLIC_PORT_BASE}-{PUBLIC_PORT_BASE + PORT_SLOTS - 1}"
    # per-service ports (own origin each, see SERVICE_PORTS_FILE) beside the front door
    binds = [f"127.0.0.1:{h}:80", f"127.0.0.1:{s}:443", f"127.0.0.1:{priv}:{priv}"]
    if is_local_address("::1"):
        binds += [f"[::1]:{h}:80", f"[::1]:{s}:443", f"[::1]:{priv}:{priv}"]
    vpn_ips = resolved.get("vpn_ips", [])
    for ip in vpn_ips:
        private = [f"{ip}:{h}:{VPN_HTTP_PORT}", f"{ip}:{s}:{VPN_HTTPS_PORT}", f"{ip}:{s}:{VPN_HTTPS_PORT}/udp", f"{ip}:{priv}:{priv}"]
        if not resolved.get("vpn_private", True):  # an OM_VPN_ALLOW the firewall does not enforce yet: not bound
            private = []
        binds += private[:3] + [f"{ip}:8080:8080", f"{ip}:8443:8443"] + private[3:] + [f"{ip}:{pub}:{pub}"]
    lan = resolved.get("lan_ip")
    if lan and lan not in vpn_ips:
        binds += [f"{lan}:{h}:8080", f"{lan}:{s}:8443", f"{lan}:{s}:8443/udp", f"{lan}:{pub}:{pub}"]
    return binds


def _stream_binds_for(resolved: dict, port: str, public: bool = True) -> list[str]:
    """Bindings of one stream port (or range): loopback, trusted VPN addresses, and the LAN address if public."""
    vpn_ips, lan = resolved.get("vpn_ips", []), resolved.get("lan_ip")
    binds = [f"127.0.0.1:{port}:{port}"]
    if is_local_address("::1"):
        binds.append(f"[::1]:{port}:{port}")
    if resolved.get("vpn_private", True):
        binds += [f"{ip}:{port}:{port}" for ip in vpn_ips]
    if public and lan and lan not in vpn_ips:
        binds.append(f"{lan}:{port}:{port}")
    return binds


def _stream_binds(resolved: dict) -> list[str]:
    """Raw TCP stream bindings: the default range (22000-22199) on loopback and VPN, and on the LAN too;
    plus the explicit ports (e.g. 25565) reserved in stream_ports.json, whose LAN binding needs a public scope."""
    default = f"{STREAM_PORT_BASE}-{STREAM_PORT_BASE + STREAM_PORT_SLOTS - 1}"
    binds = _stream_binds_for(resolved, default)
    for key, info in sorted(stream_ports().items()):
        hp = info.get("host_port")
        if not hp or (STREAM_PORT_BASE <= hp <= STREAM_PORT_BASE + STREAM_PORT_SLOTS - 1):
            continue
        pol = net_policies().get(key)
        if pol:
            from gitops import hostsetup
            if not hostsetup.net_policy_enforced(key, pol):
                continue
        binds += _stream_binds_for(resolved, hp, public=info.get("scope", "private") == "public")
    return _unique(binds)


def render_ports(resolved: dict) -> str:
    """Edge port bindings. Loopback and VPN addresses → private tier (container :80/:443);
    LAN → public tier (:8080/:8443) on the edge ports; VPN addresses also reach the public
    tier on 8080/8443, so a VPN's access rules can give a guest the public services only.
    Raw TCP stream ports: default range 22000-22199 on loopback and VPN (and LAN if public),
    plus explicit stream ports (e.g. 25565) reserved in stream_ports.json."""
    lines = "\n".join(f'      - "{b}"' for b in _http_binds(resolved))
    st_lines = "\n".join(f'      - "{b}"' for b in _stream_binds(resolved))
    return f"""# GENERATED by `om core start` from {USER_ENV} — do not edit.
services:
  caddy:
    ports:
{lines}
  stream_edge:
    ports:
{st_lines}
"""


def compose_path(path) -> str:
    """A host path as compose volume specs want it on every OS: forward slashes, so a
    Windows `C:\\Users\\me\\…` becomes `C:/Users/me/…` (one form, no escaping questions)."""
    return Path(path).as_posix()


def workspace_dashboard_dirs() -> dict:
    """{id: <workspace>/.om/dashboard} for every registered workspace that still exists on disk."""
    out = {}
    for ws_id, entry in sorted(read_registry().items()):
        path = Path(entry.get("path", ""))
        if re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", ws_id) and path.is_dir():
            out[ws_id] = path / ".om" / "dashboard"
    return out


def render_dashboard_mounts(dirs: dict) -> str:
    """Each workspace's own dashboard data (wallpaper, settings) mounted into the dashboard."""
    lines = "".join(f"      - {compose_path(d)}:/workspaces/{ws_id}:Z\n" for ws_id, d in dirs.items())
    return f"# GENERATED by `om core start` — do not edit.\nservices:\n  dashboard:\n    volumes:\n{lines}" if lines \
        else "# GENERATED by `om core start` — do not edit.\nservices: {}\n"


def migrate_dashboard_data(dirs: dict):
    """Copy dashboard data kept in STATE_DIR/data/dashboard/workspaces/<id>/ into the workspace
    (once: only into an empty folder, and the old copy is left in place)."""
    for ws_id, dest in dirs.items():
        dest.mkdir(parents=True, exist_ok=True)
        old = DATA_DIR / "dashboard" / "workspaces" / ws_id
        if old.is_dir() and not any(dest.iterdir()):
            for f in old.iterdir():
                if f.is_file():
                    shutil.copy2(f, dest / f.name)


def egress_image() -> str:
    from gitops import egress  # imports core; late to avoid a cycle
    return egress.image()


def write_runtime_files(runtime: str) -> dict:
    """Resolve settings and write STATE_DIR/runtime.env, ports.yml and dashboard-mounts.yml."""
    resolved = resolve_settings()
    eng = engine_info(runtime)
    Path(resolved["wallpapers_dir"]).mkdir(parents=True, exist_ok=True)
    vpn = resolved["vpn_ips"] + resolved["vpn_names"]
    lan = resolved["lan_ip"]
    public = ([lan] if lan else []) + [f"{ip}" for ip in resolved["vpn_ips"] if ip != lan]
    env = {
        "OM_ENGINE_SOCKET": eng["socket"] or "/var/run/docker.sock",
        "OM_WALLPAPERS_DIR": compose_path(resolved["wallpapers_dir"]),
        "OM_STATE_DIR": compose_path(STATE_DIR),
        "LAN_IP": lan or disabled("lan"),
        # Several site addresses each (Caddy substitutes {$...} before parsing the Caddyfile).
        "VPN_HTTP": ", ".join(f"http://{h}:{VPN_HTTP_PORT}" for h in vpn) or f"http://{disabled('vpn-http')}:{VPN_HTTP_PORT}",
        "VPN_HTTPS": ", ".join(f"https://{h}:{VPN_HTTPS_PORT}" for h in vpn) or f"https://{disabled('vpn-https')}:{VPN_HTTPS_PORT}",
        "PUBLIC_HTTPS": ", ".join(f"https://{h}:8443" for h in public) or f"https://{disabled('public')}:8443",
        "VPN_HOSTS": ",".join(vpn) or disabled("vpn"),
        # Host names a per-service port answers to (anything else is aborted: DNS rebinding).
        "PRIVATE_NAMES": " ".join(["localhost", "127.0.0.1"] + vpn),
        # <hostname>.local: the name the OS announces on the LAN (mDNS), as guests have always used it
        "PUBLIC_NAMES": " ".join(([lan, f"{socket.gethostname().split('.')[0].lower()}.local"] if lan else []) + vpn)
                        or disabled("public-names"),
        "OM_EDGE_TOKEN": edge_token(),
        "OM_EGRESS_IMAGE": egress_image(),
        "OM_PRIVATE_PORT_BASE": str(PRIVATE_PORT_BASE),
        "OM_PUBLIC_PORT_BASE": str(PUBLIC_PORT_BASE),
    }
    write_private(RUNTIME_ENV, f"# GENERATED by `om core start` — do not edit; edit {USER_ENV} instead.\n"
                  + "".join(f"{k}={v}\n" for k, v in env.items()))
    resolved["vpn_private"] = vpn_private_open()
    from gitops import stream
    stream.ensure_stream_configs()
    PORTS_FILE.write_text(render_ports(resolved), encoding="utf-8", newline="\n")
    dirs = workspace_dashboard_dirs()
    migrate_dashboard_data(dirs)
    MOUNTS_FILE.write_text(render_dashboard_mounts(dirs), encoding="utf-8", newline="\n")
    resolved["engine"] = eng
    return resolved
