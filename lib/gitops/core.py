#!/usr/bin/env python3
"""
core.py — Host/engine detection and Global Core lifecycle for 'om'.

Everything machine-specific (LAN/VPN addresses, engine socket, wallpaper dir,
the edge↔router secret) is resolved here at `om core start` time and written to
generated files, so the tracked compose/Caddy files contain no per-machine values.

OM_HOME (~/.om) holds only the program. Like git keeping its program apart from each
repo's .git, everything per-machine lives outside it, so om can be reinstalled or
updated without touching state:

  CONFIG_DIR/om.env          user settings (values may be 'auto' / 'off')
  STATE_DIR/runtime.env      generated: resolved values for compose (--env-file)
  STATE_DIR/ports.yml        generated: host port bindings for the edge proxy
  STATE_DIR/data/            Caddy PKI, edge↔router token, router + dashboard data
  STATE_DIR/routes/          generated workspace routes      STATE_DIR/auth/  login hash
  STATE_DIR/registry/        workspace registry                       STATE_DIR/logs/, firewall/

CONFIG_DIR / STATE_DIR default to $XDG_CONFIG_HOME/om and $XDG_STATE_HOME/om
(~/.config/om, ~/.local/state/om; %LOCALAPPDATA%\\om on Windows) and can be set
with OM_CONFIG_DIR / OM_STATE_DIR.
"""

import contextlib
import functools
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

VERSION = "1.0.0"

IS_WINDOWS = os.name == "nt"
IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

def _default_dirs() -> tuple[Path, Path]:
    if IS_WINDOWS:
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "om"
        return base, base
    cfg = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "om"
    state = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "om"
    return cfg, state

OM_HOME = Path(os.environ.get("OM_HOME", Path.home() / ".om"))
CORE_DIR = OM_HOME / "core"                      # program: compose file, Caddyfiles, dashboard app
CORE_ROUTES_DIR = CORE_DIR / "caddy" / "conf.d"  # program: om's own hand-written routes
CONFIG_DIR = Path(os.environ.get("OM_CONFIG_DIR") or _default_dirs()[0])
STATE_DIR = Path(os.environ.get("OM_STATE_DIR") or _default_dirs()[1])
USER_ENV = CONFIG_DIR / "om.env"
RUNTIME_ENV = STATE_DIR / "runtime.env"
PORTS_FILE = STATE_DIR / "ports.yml"
MOUNTS_FILE = STATE_DIR / "dashboard-mounts.yml"
DATA_DIR = STATE_DIR / "data"
TOKEN_FILE = DATA_DIR / "edge_token"
STOP_MARKER = DATA_DIR / "stopped"
ROUTES_DIR = STATE_DIR / "routes"
AUTH_DIR = STATE_DIR / "auth"
FIREWALL_DIR = STATE_DIR / "firewall"
LOG_DIR = STATE_DIR / "logs"
REGISTRY_FILE = STATE_DIR / "registry" / "workspaces.json"
# Each web service gets its own port, so its own browser origin, on the VPN and the LAN:
# PRIVATE_PORT_BASE + slot (loopback and VPN) and, if public, PUBLIC_PORT_BASE + slot (LAN and VPN).
# The registry folder is mounted read-only into the dashboard, which links to these ports.
SERVICE_PORTS_FILE = STATE_DIR / "registry" / "service_ports.json"
# Raw TCP stream service ports: default range (STREAM_PORT_BASE + slot) and explicit ports (e.g. 25565)
STREAM_PORTS_FILE = STATE_DIR / "registry" / "stream_ports.json"
# Per-service source-address policy (om.net.allow / om.net.deny) with the service's own ports, written by
# route generation; `om firewall` turns it into host firewall rules and `om doctor` checks they are applied.
NET_POLICY_FILE = STATE_DIR / "registry" / "net_policy.json"
# Own ports of services with om.log=off: the firewall never logs connections to them.
NO_LOG_FILE = STATE_DIR / "registry" / "no_log.json"
# Networks om_egress belongs on, per workspace: only those of projects with an om.egress service.
EGRESS_NETS_FILE = STATE_DIR / "networks" / "egress.json"
PRIVATE_PORT_BASE, PUBLIC_PORT_BASE, PORT_SLOTS = 20000, 21000, 200
STREAM_PORT_BASE, STREAM_PORT_SLOTS = 22000, 200
# Edge (container) ports the VPN addresses' host 80/443 land on: apart from loopback's 80/443, so the
# <ws>.<svc>.localhost sites (this machine only) never answer a VPN device that sends such a Host.
VPN_HTTP_PORT, VPN_HTTPS_PORT = 81, 444
ROUTER = "om_router"
EGRESS = "om_egress"
EDGE = "om_caddy"
STREAM_EDGE = "om_stream_edge"
STREAM_ROUTER = "om_stream_router"
CORE_CONTAINERS = (EDGE, ROUTER, EGRESS, "om_sockguard", "om_dashboard", STREAM_EDGE, STREAM_ROUTER)
# Containers of parts removed by ADR 0003; `om core start` deletes them if they still exist.
RETIRED_CONTAINERS = ("om_wg", "om_gate", "portainer")

# Reserved never-resolving names (RFC 2606 .invalid) used when an address is disabled,
# so the Caddyfile host lists stay valid; distinct per slot to avoid duplicate sites.
def disabled(slot: str) -> str:
    return f"{slot}.disabled.invalid"



# ── Small utilities ─────────────────────────────────────────────────────────

@contextlib.contextmanager
def file_lock(path: Path):
    """Exclusive inter-process lock (fcntl on POSIX, msvcrt on Windows)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a+", encoding="utf-8") as fh:
        if IS_WINDOWS:
            import msvcrt
            fh.seek(0)
            while True:
                try:
                    msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
                    break
                except OSError:
                    time.sleep(0.1)
            try:
                yield
            finally:
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)

def run(cmd: list, **kw) -> subprocess.CompletedProcess:
    """subprocess.run that never raises for a missing binary."""
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
    if kw.get("text"):
        # Engines and git print UTF-8 (labels may hold emoji); never the Windows code page
        kw.setdefault("encoding", "utf-8")
        kw.setdefault("errors", "replace")
    try:
        return subprocess.run(cmd, **kw)
    except (FileNotFoundError, PermissionError) as e:
        return subprocess.CompletedProcess(cmd, 127, "", str(e))

def write_private(path: Path, content: str):
    """Write a file readable only by the current user (best effort on Windows)."""
    write_private_bytes(path, content.encode("utf-8"))

def write_private_bytes(path: Path, data: bytes):
    """Atomic write of a file that is 0600 from the moment it exists (no window where others can read it)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    try:
        os.chmod(tmp, 0o600)  # a leftover .tmp keeps its old mode through O_CREAT
    except OSError:
        pass
    os.replace(tmp, path)

def write_atomic(path: Path, text: str):
    """Replace a file in one step, so a reader (Caddy reloading routes) never sees half of it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    os.replace(tmp, path)

def parse_env_file(path: Path) -> dict:
    data = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip().strip('"').strip("'")
    return data


# ── Registry ────────────────────────────────────────────────────────────────

def _read_slots() -> dict:
    try:
        data = json.loads(SERVICE_PORTS_FILE.read_text(encoding="utf-8"))
        return {k: int(v) for k, v in data.items() if isinstance(v, int) and 0 <= v < PORT_SLOTS}
    except (OSError, ValueError):
        return {}

def service_slots() -> dict:
    """{"<ws>/<svc>": slot} for every web service that has a port."""
    return _read_slots()

def assign_slots(ws: str, services: list[str]) -> dict:
    """Give each of the workspace's web services a stable slot (kept across restarts; the lowest
    free one for a new service) and release the slots of its services that are gone."""
    with file_lock(SERVICE_PORTS_FILE.with_suffix(".lock")):
        slots = _read_slots()
        slots = {k: v for k, v in slots.items() if k.split("/")[0] != ws or k.split("/", 1)[1] in services}
        used = set(slots.values())
        for svc in services:
            key = f"{ws}/{svc}"
            if key not in slots:
                free = next((i for i in range(PORT_SLOTS) if i not in used), None)
                if free is None:
                    raise RuntimeError(f"all {PORT_SLOTS} service ports are in use")
                slots[key] = free
                used.add(free)
        SERVICE_PORTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = SERVICE_PORTS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(dict(sorted(slots.items())), indent=2) + "\n", encoding="utf-8", newline="\n")
        os.replace(tmp, SERVICE_PORTS_FILE)
        return {k: v for k, v in slots.items() if k.split("/")[0] == ws}

def release_slots(ws: str):
    """Free every slot of a workspace (its routes were pruned), and drop its address policies."""
    assign_slots(ws, [])
    release_stream_slots(ws)
    set_net_policies(ws, {})
    set_no_log(ws, {})

def _read_stream_registry() -> dict:
    try:
        data = json.loads(STREAM_PORTS_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {}
        out = {}
        for k, v in data.items():
            if isinstance(v, dict) and "host_port" in v and "container_port" in v:
                out[k] = v
        return out
    except (OSError, ValueError):
        return {}

def stream_ports() -> dict:
    """{"<ws>/<svc>": {"host_port": int, "container_port": int, "slot": int | None, "scope": str, "log": str}}"""
    return _read_stream_registry()

def stream_slots() -> dict:
    """{"<ws>/<svc>": host_port} for every raw TCP stream service."""
    return {k: v["host_port"] for k, v in _read_stream_registry().items()}

def assign_stream_slots(ws: str, services: dict[str, dict]) -> dict:
    """Give each raw TCP service of this workspace a stable slot (default 22000+n) or reserve
    an explicit host port, releasing slots/ports for services that are gone."""
    with file_lock(STREAM_PORTS_FILE.with_suffix(".lock")):
        reg = _read_stream_registry()
        reg = {k: v for k, v in reg.items() if k.split("/")[0] != ws or k.split("/", 1)[1] in services}
        used_slots = {v["slot"] for v in reg.values() if v.get("slot") is not None}
        used_ports = {v["host_port"]: k for k, v in reg.items() if v.get("host_port") is not None}

        for svc, meta in services.items():
            key = f"{ws}/{svc}"
            req_port = meta.get("host_port")
            c_port = meta["container_port"]
            scope = meta.get("scope", "private")
            log = meta.get("log", "on")

            if req_port is not None:
                if req_port in used_ports and used_ports[req_port] != key:
                    raise RuntimeError(f"stream port {req_port} is already reserved by {used_ports[req_port]}")
                reg[key] = {
                    "host_port": req_port,
                    "container_port": c_port,
                    "slot": None,
                    "scope": scope,
                    "log": log,
                }
                used_ports[req_port] = key
            else:
                if key in reg and reg[key].get("slot") is not None:
                    slot = reg[key]["slot"]
                    reg[key] = {
                        "host_port": STREAM_PORT_BASE + slot,
                        "container_port": c_port,
                        "slot": slot,
                        "scope": scope,
                        "log": log,
                    }
                else:
                    free = next((i for i in range(STREAM_PORT_SLOTS) if i not in used_slots), None)
                    if free is None:
                        raise RuntimeError(f"all {STREAM_PORT_SLOTS} stream ports are in use")
                    slot = free
                    hp = STREAM_PORT_BASE + slot
                    if hp in used_ports and used_ports[hp] != key:
                        raise RuntimeError(f"default stream port {hp} clashes with explicit reservation by {used_ports[hp]}")
                    reg[key] = {
                        "host_port": hp,
                        "container_port": c_port,
                        "slot": slot,
                        "scope": scope,
                        "log": log,
                    }
                    used_slots.add(slot)
                    used_ports[hp] = key

        STREAM_PORTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = STREAM_PORTS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(dict(sorted(reg.items())), indent=2) + "\n", encoding="utf-8", newline="\n")
        os.replace(tmp, STREAM_PORTS_FILE)
        return {k: v for k, v in reg.items() if k.split("/")[0] == ws}

def release_stream_slots(ws: str):
    """Free every stream slot/port of a workspace (its routes were pruned)."""
    assign_stream_slots(ws, {})

def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}

def _replace_ws_entries(path: Path, ws: str, entries: dict):
    """Replace the "<ws>/<svc>" entries of one workspace in a JSON state file, keeping the others'."""
    with file_lock(path.with_suffix(".lock")):
        data = {k: v for k, v in _read_json(path).items() if k.split("/")[0] != ws}
        data.update({f"{ws}/{svc}": v for svc, v in entries.items()})
        if not data and not path.exists():
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(dict(sorted(data.items())), indent=2) + "\n", encoding="utf-8", newline="\n")
        os.replace(tmp, path)

def net_policies() -> dict:
    """{"<ws>/<svc>": {"ports": [...], "allow": [...] | None, "deny": [...]}} for services with om.net.*."""
    return {k: v for k, v in _read_json(NET_POLICY_FILE).items() if isinstance(v, dict) and v.get("ports")}

def set_net_policies(ws: str, policies: dict):
    """Replace one workspace's address policies ({svc: policy}), keeping every other workspace's."""
    _replace_ws_entries(NET_POLICY_FILE, ws, policies)

def no_log_ports() -> list[int]:
    """Own ports of every service with om.log=off."""
    return sorted({p for v in _read_json(NO_LOG_FILE).values() if isinstance(v, list) for p in v if isinstance(p, int)})

def set_no_log(ws: str, services: dict):
    """Replace one workspace's om.log=off services ({svc: [ports]})."""
    _replace_ws_entries(NO_LOG_FILE, ws, services)

def egress_networks(ws: str) -> list[str] | None:
    """Networks of the workspace that om_egress belongs on; None if unknown yet (then: all of them)."""
    v = _read_json(EGRESS_NETS_FILE).get(ws)
    return list(v) if isinstance(v, list) else None

def set_egress_networks(ws: str, nets: list[str] | None):
    with file_lock(EGRESS_NETS_FILE.with_suffix(".lock")):
        data = _read_json(EGRESS_NETS_FILE)
        if nets is None:
            data.pop(ws, None)
        else:
            data[ws] = sorted(set(nets))
        EGRESS_NETS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = EGRESS_NETS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(dict(sorted(data.items())), indent=2) + "\n", encoding="utf-8", newline="\n")
        os.replace(tmp, EGRESS_NETS_FILE)

def read_registry() -> dict:
    try:
        return json.loads(REGISTRY_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}

def update_registry(mutate):
    """Apply mutate(registry_dict) under the registry lock and write atomically."""
    with file_lock(STATE_DIR / "workspaces.lock"):
        reg = read_registry()
        mutate(reg)
        REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = REGISTRY_FILE.with_name("workspaces.json.tmp")
        tmp.write_text(json.dumps(reg, indent=2), encoding="utf-8", newline="\n")
        os.replace(tmp, REGISTRY_FILE)


# ── Engine detection ────────────────────────────────────────────────────────

def detect_runtime() -> str:
    """Prefer podman, then docker; honor OM_RUNTIME if set."""
    forced = os.environ.get("OM_RUNTIME")
    if forced:
        return forced
    for cmd in ("podman", "docker"):
        if run([cmd, "--version"]).returncode == 0:
            return cmd
    return "podman"

def engine_info(runtime: str) -> dict:
    """Facts about the container engine that change how om must behave."""
    info = {"runtime": runtime, "ok": False, "rootless": False, "remote_vm": False, "socket": ""}
    if runtime == "podman":
        r = run(["podman", "info", "--format", "{{.Host.Security.Rootless}}|{{.Host.RemoteSocket.Path}}|{{.Host.ServiceIsRemote}}"])
        if r.returncode == 0 and "|" in r.stdout:
            rootless, sock, remote = r.stdout.strip().split("|")[:3]
            info.update(ok=True, rootless=rootless == "true", remote_vm=remote == "true",
                        socket=sock.replace("unix://", "").strip())
            if info["remote_vm"]:
                # podman machine (macOS/Windows): RemoteSocket.Path is the *client-side* socket,
                # which doesn't exist inside the VM where containers run. Mount the VM's own one.
                conns = run(["podman", "system", "connection", "list", "--format", "json"])
                info["socket"] = vm_socket_from_connections(conns.stdout) or "/run/podman/podman.sock"
        if not info["socket"] and hasattr(os, "getuid"):
            info["socket"] = f"/run/user/{os.getuid()}/podman/podman.sock"
    else:
        r = run(["docker", "info", "--format", "{{.OperatingSystem}}|{{json .SecurityOptions}}"])
        if r.returncode == 0 and "|" in r.stdout:
            os_name, secopts = r.stdout.strip().split("|", 1)
            desktop = "Docker Desktop" in os_name
            info.update(ok=True, rootless="rootless" in secopts, remote_vm=desktop or IS_MACOS or IS_WINDOWS)
            sock = "/var/run/docker.sock"
            if info["rootless"] and not desktop:
                ctx = run(["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"])
                if ctx.returncode == 0 and ctx.stdout.strip().startswith("unix://"):
                    sock = ctx.stdout.strip()[len("unix://"):]
            info["socket"] = sock
    return info

def vm_socket_from_connections(json_text: str) -> str:
    """Engine socket path *inside* the podman machine VM, from `podman system connection list
    --format json` (default connection URI, e.g. ssh://core@127.0.0.1:53210/run/user/501/podman/podman.sock)."""
    try:
        conns = json.loads(json_text or "[]")
    except ValueError:
        return ""
    if isinstance(conns, dict):  # older podman: {"Connections": [...]}
        conns = conns.get("Connections", [])
    default = [c for c in conns if c.get("Default")] or conns
    for c in default:
        uri = c.get("URI", "")
        if uri.startswith("ssh://"):
            path = "/" + uri.split("://", 1)[1].split("/", 1)[-1] if "/" in uri.split("://", 1)[1] else ""
            if path.endswith(".sock"):
                return path
    return ""

def compose_available(runtime: str) -> bool:
    return run([runtime, "compose", "version"]).returncode == 0

def unprivileged_port_start() -> int | None:
    """Linux only: lowest port an unprivileged process may bind (rootless engines need <= 80)."""
    try:
        return int(Path("/proc/sys/net/ipv4/ip_unprivileged_port_start").read_text(encoding="utf-8").strip())
    except Exception:
        return None


# ── Address detection ───────────────────────────────────────────────────────

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


# ── Configuration resolution ────────────────────────────────────────────────

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

def render_ports(resolved: dict) -> str:
    """Edge port bindings. Loopback and VPN addresses → private tier (container :80/:443);
    LAN → public tier (:8080/:8443) on the edge ports; VPN addresses also reach the public
    tier on 8080/8443, so a VPN's access rules can give a guest the public services only.
    Raw TCP stream ports: default range 22000-22199 on loopback and VPN (and LAN if public),
    plus explicit stream ports (e.g. 25565) reserved in stream_ports.json."""
    h, s = resolved.get("http_port", 80), resolved.get("https_port", 443)
    priv = f"{PRIVATE_PORT_BASE}-{PRIVATE_PORT_BASE + PORT_SLOTS - 1}"
    pub = f"{PUBLIC_PORT_BASE}-{PUBLIC_PORT_BASE + PORT_SLOTS - 1}"
    # per-service ports (own origin each, see SERVICE_PORTS_FILE) beside the front door
    binds = [f"127.0.0.1:{h}:80", f"127.0.0.1:{s}:443", f"127.0.0.1:{priv}:{priv}"]
    if is_local_address("::1"):
        binds += [f"[::1]:{h}:80", f"[::1]:{s}:443", f"[::1]:{priv}:{priv}"]
    for ip in resolved.get("vpn_ips", []):
        private = [f"{ip}:{h}:{VPN_HTTP_PORT}", f"{ip}:{s}:{VPN_HTTPS_PORT}", f"{ip}:{s}:{VPN_HTTPS_PORT}/udp", f"{ip}:{priv}:{priv}"]
        if not resolved.get("vpn_private", True):  # an OM_VPN_ALLOW the firewall does not enforce yet: not bound
            private = []
        binds += private[:3] + [f"{ip}:8080:8080", f"{ip}:8443:8443"] + private[3:] + [f"{ip}:{pub}:{pub}"]
    lan = resolved.get("lan_ip")
    if lan and lan not in resolved.get("vpn_ips", []):
        binds += [f"{lan}:{h}:8080", f"{lan}:{s}:8443", f"{lan}:{s}:8443/udp", f"{lan}:{pub}:{pub}"]
    lines = "\n".join(f'      - "{b}"' for b in binds)

    # Stream edge ports
    st_def = f"{STREAM_PORT_BASE}-{STREAM_PORT_BASE + STREAM_PORT_SLOTS - 1}"
    st_binds = [f"127.0.0.1:{st_def}:{st_def}"]
    if is_local_address("::1"):
        st_binds += [f"[::1]:{st_def}:{st_def}"]
    for ip in resolved.get("vpn_ips", []):
        if resolved.get("vpn_private", True):
            st_binds.append(f"{ip}:{st_def}:{st_def}")
    if lan and lan not in resolved.get("vpn_ips", []):
        st_binds.append(f"{lan}:{st_def}:{st_def}")

    # Explicit stream ports from stream_ports.json
    for key, info in sorted(stream_ports().items()):
        hp = info.get("host_port")
        if not hp or (STREAM_PORT_BASE <= hp <= STREAM_PORT_BASE + STREAM_PORT_SLOTS - 1):
            continue
        pol = net_policies().get(key)
        if pol:
            from gitops import hostsetup
            if not hostsetup.net_policy_enforced(key, pol):
                continue
        scope = info.get("scope", "private")
        st_binds.append(f"127.0.0.1:{hp}:{hp}")
        if is_local_address("::1"):
            st_binds.append(f"[::1]:{hp}:{hp}")
        for ip in resolved.get("vpn_ips", []):
            if resolved.get("vpn_private", True):
                st_binds.append(f"{ip}:{hp}:{hp}")
        if scope == "public" and lan and lan not in resolved.get("vpn_ips", []):
            st_binds.append(f"{lan}:{hp}:{hp}")

    dedup_st = []
    seen = set()
    for b in st_binds:
        if b not in seen:
            seen.add(b)
            dedup_st.append(b)
    st_lines = "\n".join(f'      - "{b}"' for b in dedup_st)

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


# ── Legacy state migration (pre-split installs kept state inside OM_HOME) ───

# Generated routes carry their workspace in the header; om's own routes are owned by 'core'.
_GENERATED_ROUTE_RE = re.compile(r"^# (?:Service|Public Subpath|Private Subpath): [a-z0-9-]+ \(([a-z0-9-]+)\)", re.MULTILINE)

def _legacy_moves() -> list[tuple[Path, Path]]:
    """(old, new) pairs for state still sitting inside OM_HOME."""
    old_core, old_cfg = CORE_DIR, OM_HOME / "config"
    pairs = [
        (old_core / ".env", USER_ENV),
        (old_core / ".runtime.env", RUNTIME_ENV),
        (old_core / "ports.generated.yml", PORTS_FILE),
        (old_core / "firewall", FIREWALL_DIR),
        (old_cfg / "workspaces.json", REGISTRY_FILE),
        (OM_HOME / "logs", LOG_DIR),
    ]
    old_data = old_core / "data"
    if old_data.is_dir():
        pairs += [(p, DATA_DIR / p.name) for p in sorted(old_data.iterdir())]
    old_auth = old_core / "caddy" / "auth.d"
    if old_auth.is_dir():
        pairs += [(p, AUTH_DIR / p.name) for p in sorted(old_auth.glob("*.conf"))]
    if CORE_ROUTES_DIR.is_dir():
        for p in sorted(CORE_ROUTES_DIR.iterdir()):
            try:
                m = p.is_file() and _GENERATED_ROUTE_RE.search(p.read_text(encoding="utf-8")[:400])
            except OSError:
                m = None
            if m and m.group(1) != "core":  # 'core' is reserved for om's own routes
                pairs.append((p, ROUTES_DIR / p.name))
    return [(o, n) for o, n in pairs
            if (o.exists() or o.is_symlink()) and not o.name.endswith(".pre-migration")]

def legacy_state_present() -> bool:
    return bool(_legacy_moves())

def migrate_legacy_state() -> list[str]:
    """Move pre-split state out of OM_HOME. Idempotent; never overwrites newer state.

    Returns human-readable lines describing what moved. Run with the core stopped:
    the edge bind-mounts several of these paths.
    """
    done = []
    for old, new in _legacy_moves():
        if new.exists():
            # Already migrated (or recreated since): keep the new one, park the old one.
            parked = old.with_name(old.name + ".pre-migration")
            if not parked.exists():
                old.rename(parked)
                done.append(f"kept {new} (old copy left at {parked})")
            continue
        new.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(old), str(new))
        done.append(f"{old} → {new}")
    for d in (OM_HOME / "config", CORE_DIR / "data", CORE_DIR / "caddy" / "auth.d"):
        try:
            for leftover in ("workspaces.lock", ".keep"):
                (d / leftover).unlink(missing_ok=True)
            d.rmdir()
        except OSError:
            pass
    return done


# ── Core lifecycle ──────────────────────────────────────────────────────────

def ensure_core_prerequisites():
    """Files/dirs the core compose file bind-mounts must exist, or the engine fails or creates dirs."""
    for d in (DATA_DIR / "caddy", DATA_DIR / "caddy_config", DATA_DIR / "router", DATA_DIR / "dashboard",
              ROUTES_DIR, AUTH_DIR, CORE_ROUTES_DIR):
        d.mkdir(parents=True, exist_ok=True)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    from gitops import egress  # imports core; late to avoid a cycle
    egress.ensure_base()
    from gitops import stream
    stream.ensure_stream_configs()
    REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not REGISTRY_FILE.exists():
        REGISTRY_FILE.write_text("{}\n", encoding="utf-8", newline="\n")
    if not USER_ENV.exists():
        USER_ENV.write_text(USER_ENV_TEMPLATE, encoding="utf-8", newline="\n")

def core_compose(runtime: str, *args: str) -> list:
    if not MOUNTS_FILE.exists():  # state written before this file existed
        MOUNTS_FILE.write_text(render_dashboard_mounts({}), encoding="utf-8", newline="\n")
    core_file = CORE_DIR / "compose.yml" if (CORE_DIR / "compose.yml").exists() else CORE_DIR / "docker-compose.yml"
    return [runtime, "compose", "--env-file", str(RUNTIME_ENV),
            "-f", str(core_file), "-f", str(PORTS_FILE),
            "-f", str(MOUNTS_FILE), *args]

def ensure_network(runtime: str, name: str, internal: bool = False) -> bool:
    """Create the network if missing. internal=True: no route out and no external DNS (workspace networks)."""
    if run([runtime, "network", "inspect", name]).returncode == 0:
        return True
    return run([runtime, "network", "create", *(["--internal"] if internal else []), name]).returncode == 0

def network_is_internal(runtime: str, name: str) -> bool:
    r = run([runtime, "network", "inspect", "--format", "{{.Internal}}", name])
    return r.returncode == 0 and r.stdout.strip().lower() == "true"

def network_subnet(runtime: str, name: str) -> str | None:
    """Return the IPv4 subnet CIDR (e.g. '10.89.12.0/24') of the network, or None."""
    r = run([runtime, "network", "inspect", name])
    if r.returncode != 0:
        return None
    try:
        data = json.loads(r.stdout)[0]
        for s in data.get("subnets") or []:
            sub = s.get("subnet")
            if sub and ":" not in sub:
                return sub
        for c in (data.get("IPAM") or {}).get("Config") or []:
            sub = c.get("Subnet")
            if sub and ":" not in sub:
                return sub
    except (IndexError, KeyError, ValueError):
        pass
    return None

def project_networks(runtime: str, ws: str) -> list[str]:
    """The workspace's per-project networks (gitops.network): every service folder has its own."""
    r = run([runtime, "network", "ls", "--filter", f"label=om.workspace={ws}", "--format", "{{.Name}}"])
    return sorted(set(r.stdout.split())) if r.returncode == 0 else []

def connect_router(runtime: str, workspace_ids) -> list:
    """Attach the internal router to each workspace network and every project network of it, and the egress
    proxy only to those whose services may go out (om.egress). Returns failures."""
    failed = []
    for wid in sorted(set(workspace_ids)):
        net = f"{wid}_net"
        if not ensure_network(runtime, net, internal=True):
            failed.append(net)
            continue
        nets = [net] + project_networks(runtime, wid)
        egress_on = egress_networks(wid)  # None: not known yet (before the workspace's first start): all
        for n in nets:
            for container in (ROUTER, EGRESS, STREAM_ROUTER):
                if container == EGRESS and egress_on is not None and n not in egress_on:
                    # No service here may go out: the proxy is not even reachable from this network.
                    run([runtime, "network", "disconnect", n, container])
                    continue
                r = run([runtime, "network", "connect", n, container])
                if r.returncode != 0 and "already" not in (r.stderr + r.stdout).lower() and "exists" not in (r.stderr + r.stdout).lower():
                    failed.append(f"{n} ({container})")
    return failed

def preflight(runtime: str) -> list:
    """Problems that would make `compose up` fail, with fixes. Empty list = good to go."""
    problems = []
    eng = engine_info(runtime)
    if not eng["ok"]:
        problems.append(f"Container engine '{runtime}' is not responding. Start it (e.g. `podman machine start` / Docker Desktop).")
        return problems
    if not compose_available(runtime):
        problems.append(f"`{runtime} compose` is unavailable. Install docker-compose (or podman-compose).")
    if IS_LINUX and eng["rootless"] and not eng["remote_vm"]:
        start, low = unprivileged_port_start(), min(edge_ports())
        if start is not None and start > low:
            problems.append(f"Rootless engines cannot bind ports {'/'.join(map(str, edge_ports()))} yet. Fix (once):\n"
                            f"      echo 'net.ipv4.ip_unprivileged_port_start={low}' | sudo tee /etc/sysctl.d/99-om.conf && sudo sysctl --system")
    return problems

def core_up(runtime: str, recreate: bool = False, quiet: bool = False) -> bool:
    ensure_core_prerequisites()
    STOP_MARKER.unlink(missing_ok=True)
    problems = preflight(runtime)
    if problems:
        for p in problems:
            print(f"\033[31m✗ {p}\033[0m")
        return False
    from gitops import egress  # imports core; late to avoid a cycle
    if not egress.ensure_image(runtime):
        return False
    resolved = write_runtime_files(runtime)
    DRIFT_SEEN.unlink(missing_ok=True)  # the core now runs on the current addresses
    if not quiet:
        tiers = ["localhost"]
        if resolved["vpn_ips"]:
            tiers.append(f"VPN {', '.join(resolved['vpn_ips'])}")
        if resolved["lan_ip"]:
            tiers.append(f"LAN {resolved['lan_ip']} (public tier)")
        print(f"  Ingress: {', '.join(tiers)}")
        trusted = vpn_items(load_settings().get("OM_VPN", ""))
        for iface, ip in vpn_candidates():
            if iface not in trusted and ip not in trusted:
                print(f"  VPN {iface} ({ip or 'no address'}) is not trusted — if only your devices are on it: om vpn trust {iface}")
    # Parts removed by ADR 0003: their containers and state go on the first start after it.
    retired = [c for c in RETIRED_CONTAINERS if run([runtime, "container", "inspect", c]).returncode == 0]
    if "om_wg" in retired:
        run([runtime, "rm", "-f", EDGE])  # it ran in om_wg's network namespace; recreated below
    for c in retired:
        run([runtime, "rm", "-f", c])
    for d in ("access", "gate", "door", "mirror", "hostquiet"):
        shutil.rmtree(STATE_DIR / d, ignore_errors=True)
    for f in ROUTES_DIR.glob("*.caddy"):  # gated sites in routes generated before ADR 0003
        text = f.read_text(encoding="utf-8")
        cut = text.find("\n# Through the door, behind the gate")
        if cut >= 0:
            f.write_text(text[:cut].rstrip("\n") + "\n", encoding="utf-8", newline="\n")
    revive_zombies(runtime)  # compose would treat a container with a dead process as already running
    args = ["up", "-d", "--remove-orphans"] + (["--force-recreate"] if recreate else [])
    r = run(core_compose(runtime, *args), cwd=CORE_DIR)
    if r.returncode != 0:
        err = (r.stderr or r.stdout).strip()
        print(f"\033[31m✗ Global Core failed to start:\033[0m\n{err[-1500:]}")
        if "address" in err.lower() and ("assign" in err.lower() or "in use" in err.lower()):
            print("  Hint: an ingress address changed or a port is taken. Check `om doctor`,"
                  f" or set OM_LAN_IP / OM_VPN in {USER_ENV}.")
        return False
    # `up -d` succeeds even if a container crash-loops right after; verify they stay up.
    deadline = time.monotonic() + 20
    while True:
        down = [c for c in CORE_CONTAINERS if not container_running(runtime, c)]
        if not down or time.monotonic() > deadline:
            break
        time.sleep(1)
    if down:
        for c in down:
            logs = run([runtime, "logs", "--tail", "15", c])
            print(f"\033[31m✗ {c} is not running.\033[0m Last log lines:\n{(logs.stdout + logs.stderr).strip()[-1200:]}")
        return False
    failed = connect_router(runtime, read_registry().keys())
    for net in failed:
        print(f"\033[33m⚠ Could not attach the router to {net}\033[0m")
    return not failed

def core_down(runtime: str) -> bool:
    if not RUNTIME_ENV.exists() or not PORTS_FILE.exists() or not MOUNTS_FILE.exists():
        write_runtime_files(runtime)
    STOP_MARKER.parent.mkdir(parents=True, exist_ok=True)
    STOP_MARKER.write_text("stopped by `om core stop` / `om down`; `om core start` clears this\n", encoding="utf-8", newline="\n")
    return run(core_compose(runtime, "down"), cwd=CORE_DIR, capture_output=False).returncode == 0

def core_heal(runtime: str) -> str:
    """Bring the core back to the desired state without user action (run at boot and periodically).

    Returns a short description of what was done ('' if nothing was needed). Never starts a
    core the user deliberately stopped.
    """
    if STOP_MARKER.exists():
        return ""
    if not engine_info(runtime)["ok"]:
        return ""
    notes = []
    revived, dead = revive_zombies(runtime)
    if revived:
        notes.append(f"restarted {', '.join(revived)} (process had died unseen by the engine)")
    stuck = [n for n in dead if n not in CORE_CONTAINERS]
    if stuck:
        notes.append(f"could not restart {', '.join(stuck)}: run `om start`")
    drift, running = runtime_drift(runtime), core_running(runtime)
    if drift and running and not DRIFT_SEEN.exists():
        # A flapping LAN/VPN address must not recreate the edge every run: act when it persists to the next one.
        DRIFT_SEEN.parent.mkdir(parents=True, exist_ok=True)
        DRIFT_SEEN.write_text("drift seen once; the next heal run recreates the edge if it persists\n", encoding="utf-8", newline="\n")
        notes.append("ingress addresses changed; waiting one more run before restarting the core")
        drift = []
    elif not drift:
        DRIFT_SEEN.unlink(missing_ok=True)
    if drift or not running:
        reason = "ingress addresses changed" if drift else "core was not running"
        ok = core_up(runtime, recreate=bool(drift), quiet=True)
        return "; ".join(notes + [f"{reason}; core {'restarted' if ok else 'FAILED to restart'}"])
    failed = connect_router(runtime, read_registry().keys())
    from gitops import egress, links  # imports core; late to avoid a cycle
    links.sync(runtime)  # recreated containers lose their link networks; put them back
    egress.reload(runtime)
    sick = restart_unhealthy(runtime)
    if sick:
        notes.append(f"restarted unhealthy {', '.join(sick)}")
    if failed:
        notes.append(f"router re-attach failed for {', '.join(failed)}")
    write_memory_snapshot(runtime)
    return "; ".join(notes)

@functools.cache
def _local_engine(runtime: str) -> bool:
    """Podman or Docker running on this Linux host, so a container's pid can be looked up in /proc."""
    return runtime in ("podman", "docker") and IS_LINUX and engine_info(runtime)["remote_vm"] is False

@functools.cache
def _vm_engine(runtime: str) -> bool:
    """Podman machine / Docker Desktop: pids live in a VM, so ask the engine instead of /proc."""
    return runtime in ("podman", "docker") and not _local_engine(runtime) and engine_info(runtime)["remote_vm"] is True

@functools.cache
def _unit_oom_score_adj() -> int | None:
    """oom_score_adj that systemd user units get (podman's healthcheck timers are such units), read from a
    throwaway unit; None without a systemd user manager (macOS, Windows, Linux without systemd)."""
    if not (IS_LINUX and shutil.which("systemd-run")):
        return None
    r = run(["systemd-run", "--user", "--wait", "--pipe", "--quiet", "--collect", "cat", "/proc/self/oom_score_adj"])
    v = r.stdout.strip()
    return int(v) if r.returncode == 0 and re.fullmatch(r"-?\d{1,4}", v) else None

def _match_unit_oom(proc: Path = Path("/proc/self/oom_score_adj")):
    """Raise this process's oom_score_adj (inherited by the engine commands it runs) to the units' value.
    Raising needs no privilege; it is never lowered."""
    target = _unit_oom_score_adj()
    if target is None:
        return
    try:
        if int(proc.read_text(encoding="utf-8").strip()) < target:
            proc.write_text(str(target), encoding="utf-8")
    except (OSError, ValueError):
        pass

def engine_lifecycle(runtime: str, *args: str) -> list:
    """Command that starts or restarts containers (`start`, `restart`) with the engine CLI.

    Rootless Podman on Linux gives a container the oom_score_adj of whoever starts it, and runs its
    healthchecks from systemd user timers (oom_score_adj 200 by default). Started from a shell (0), the
    container then refuses those healthcheck execs (runc may not lower a process's oom_score_adj) and
    turns unhealthy. So for local Podman, om first raises its own oom_score_adj to the units' value.
    (Not by running podman inside a systemd unit: podman then keeps conmon in that unit, and systemd
    kills conmon when the unit ends.) Docker's daemon and Podman machine's VM start containers
    themselves, whoever asks, so there nothing changes."""
    if runtime == "podman" and _local_engine(runtime):
        _match_unit_oom()
    return [runtime, *args]

def _top_failed(runtime: str, name: str) -> bool:
    """`top` reads the container's processes through the engine; it fails for a container whose process is
    gone. Two failures 1.5 s apart, so a transient engine hiccup never restarts a healthy container."""
    for attempt in range(2):
        if run([runtime, "top", name, "pid"]).returncode == 0:
            return False
        if attempt == 0:
            time.sleep(1.5)
    return True

def _process_gone(runtime: str, pid, name: str = "") -> bool:
    """The engine lists the container as running but its main process no longer exists.

    Podman learns of an exit only through the container's conmon. If conmon is killed (e.g. systemd
    SIGKILLing podman-restart.service's cgroup after a failed boot start) the container shows 'Up'
    forever, `exec` fails with "cannot exec in a stopped container" and nothing restarts it. A local engine
    is checked through /proc, a VM-based one (Podman machine, Docker Desktop) through the engine (`top`).
    Docker's daemon normally marks a dead container as exited itself; this also catches a stuck record.
    """
    if name and _vm_engine(runtime):
        return _top_failed(runtime, name)
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    return pid > 0 and _local_engine(runtime) and not Path(f"/proc/{pid}").exists()

def container_running(runtime: str, name: str) -> bool:
    r = run([runtime, "container", "inspect", "-f", "{{.State.Running}} {{.State.Pid}}", name])
    if r.returncode != 0 or "true" not in r.stdout.lower():
        return False
    return not _process_gone(runtime, r.stdout.split()[-1], name)

def zombie_containers(runtime: str) -> list:
    """om's containers (core or workspace) listed as running whose process is gone."""
    if not (_local_engine(runtime) or _vm_engine(runtime)):
        return []
    r = run([runtime, "ps", "--format", "{{.Names}}"])
    names = r.stdout.split() if r.returncode == 0 else []
    if not names:
        return []
    info = run([runtime, "container", "inspect", "-f",
                '{{.Name}}|{{.State.Pid}}|{{index .Config.Labels "om.core"}}|{{index .Config.Labels "workspace.id"}}', *names])
    found = []
    for line in info.stdout.splitlines() if info.returncode == 0 else []:
        name, pid, core_label, ws_label = (line.split("|") + ["", "", "", ""])[:4]
        name = name.lstrip("/")
        if (core_label.strip() not in ("", "<no value>") or ws_label.strip() not in ("", "<no value>")) \
                and _process_gone(runtime, pid, name):
            found.append(name)
    return found

def revive_zombies(runtime: str) -> tuple:
    """Restart containers whose process died unseen. `stop` clears the stale 'running' record and
    `start` reuses the container exactly as created (same config, mounts, networks).
    Returns (revived, failed); a failed core container is removed so `core_up` recreates it."""
    revived, failed = [], []
    for name in zombie_containers(runtime):
        run([runtime, "stop", "-t", "0", name])
        if run(engine_lifecycle(runtime, "start", name)).returncode == 0:
            revived.append(name)
        else:
            failed.append(name)
            if name in CORE_CONTAINERS:
                run([runtime, "rm", "-f", name])
    return revived, failed

# A service opts in with the label om.heal=restart: if its healthcheck stays unhealthy for
# UNHEALTHY_AFTER seconds, core_heal restarts it, at most once per RESTART_COOLDOWN.
HEAL_STATE = DATA_DIR / "heal-state.json"
DRIFT_SEEN = DATA_DIR / "heal-drift-seen"
UNHEALTHY_AFTER, RESTART_COOLDOWN = 600, 3600

def restart_unhealthy(runtime: str, now: float | None = None) -> list:
    now = time.time() if now is None else now
    r = run([runtime, "ps", "--filter", "health=unhealthy", "--filter", "label=om.heal=restart", "--format", "{{.Names}}"])
    unhealthy = r.stdout.split() if r.returncode == 0 else []
    try:
        state = json.loads(HEAL_STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        state = {}
    restarted = []
    for name in list(state):  # forget healthy ones once their restart cooldown has passed
        if name not in unhealthy:
            state[name].pop("since", None)
            if "restarted" not in state[name] or now - state[name]["restarted"] >= RESTART_COOLDOWN:
                del state[name]
    for name in unhealthy:
        e = state.setdefault(name, {})
        e.setdefault("since", now)
        if now - e["since"] >= UNHEALTHY_AFTER and ("restarted" not in e or now - e["restarted"] >= RESTART_COOLDOWN):
            if run(engine_lifecycle(runtime, "restart", name)).returncode == 0:
                restarted.append(name)
            e["restarted"], e["since"] = now, now
    try:
        HEAL_STATE.parent.mkdir(parents=True, exist_ok=True)
        HEAL_STATE.write_text(json.dumps(state), encoding="utf-8", newline="\n")
    except OSError:
        pass
    return restarted

MEMORY_FILE = STATE_DIR / "registry" / "core_memory.json"

def write_memory_snapshot(runtime: str):
    """Anonymous memory per core container, for the dashboard's RAM tile. The engine API reports cgroup
    usage including shared file cache, which swings by tens of MB on a recreate; memory.stat splits it.
    Linux with a local engine only; elsewhere the dashboard keeps the engine figure."""
    if not _local_engine(runtime):
        return
    anon = {}
    for pid, name in _om_pids(runtime).items():
        if name not in CORE_CONTAINERS:
            continue
        try:
            line = next(ln for ln in Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8").splitlines() if ln.startswith("0::"))
            parts = line[3:].strip("/").split("/")
            end = next((i for i, p in enumerate(parts) if p.endswith(".scope")), len(parts) - 1)
            stat = (Path("/sys/fs/cgroup").joinpath(*parts[:end + 1]) / "memory.stat").read_text(encoding="utf-8")
            anon[name] = int(dict(ln.split() for ln in stat.splitlines())["anon"])
        except (OSError, StopIteration, KeyError, ValueError):
            continue
    if not anon:
        return
    try:
        MEMORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = MEMORY_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps({"ts": time.time(), "anon": anon}) + "\n", encoding="utf-8", newline="\n")
        os.replace(tmp, MEMORY_FILE)
    except OSError:
        pass

def _om_pids(runtime: str) -> dict:
    """{pid: container name} of om's running containers (core or workspace)."""
    r = run([runtime, "ps", "--format", "{{.Names}}"])
    names = r.stdout.split() if r.returncode == 0 else []
    info = run([runtime, "container", "inspect", "-f",
                '{{.Name}}|{{.State.Pid}}|{{index .Config.Labels "om.core"}}|{{index .Config.Labels "workspace.id"}}', *names]) if names else None
    found = {}
    for line in info.stdout.splitlines() if info and info.returncode == 0 else []:
        name, pid, core_label, ws_label = (line.split("|") + ["", "", "", ""])[:4]
        if pid.isdigit() and int(pid) > 0 and (core_label.strip() not in ("", "<no value>") or ws_label.strip() not in ("", "<no value>")):
            found[int(pid)] = name.lstrip("/")
    return found

def watch(runtime: str, max_events: int | None = None) -> int:
    """Event loop for `om core watch`: recover a container the moment its process dies unseen.

    A pidfd per container tells the kernel-level truth instantly (no polling); the engine's own event
    stream and a 60 s backstop refresh the set. When a process exits, wait 2 s for the engine to record a
    normal exit, then restart whatever it still lists as running (revive_zombies). Linux, local engine only;
    `om core heal` (every 2 min) remains the fallback everywhere else.
    """
    import select
    if not (IS_LINUX and hasattr(os, "pidfd_open") and _local_engine(runtime)):
        print("om core watch needs Linux with a local Podman/Docker engine; `om core heal` covers other setups.")
        return 1
    poller, fds = select.poll(), {}
    events = subprocess.Popen([runtime, "events", "--filter", "type=container", "--format", "{{.Status}}"],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    poller.register(events.stdout.fileno(), select.POLLIN | select.POLLHUP)
    handled = 0

    def refresh():
        for fd in list(fds):
            poller.unregister(fd)
            os.close(fd)
        fds.clear()
        for pid, name in _om_pids(runtime).items():
            try:
                fd = os.pidfd_open(pid)
            except OSError:
                continue  # already gone: revive_zombies below handles it
            poller.register(fd, select.POLLIN)
            fds[fd] = name
    def log(msg):
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)

    refresh()
    revive_zombies(runtime)
    log(f"watching {len(fds)} container(s)")
    while max_events is None or handled < max_events:
        exited, changed = [], False
        for fd, _ in poller.poll(60000) or [(None, 0)]:
            if fd is None:
                changed = True
            elif fd == events.stdout.fileno():
                if not events.stdout.readline():          # engine event stream ended
                    events = subprocess.Popen([runtime, "events", "--filter", "type=container", "--format", "{{.Status}}"],
                                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                    poller.unregister(fd)
                    poller.register(events.stdout.fileno(), select.POLLIN | select.POLLHUP)
                changed = True
            elif fd in fds:
                exited.append(fds[fd])
        if exited:
            time.sleep(2)
            revived, failed = revive_zombies(runtime)
            if revived or failed:
                log(f"process of {', '.join(exited)} died unseen; restarted {revived or 'nothing'}"
                    + (f", failed {failed}" if failed else ""))
                handled += 1
            changed = True
        if changed:
            refresh()
    return 0

def core_running(runtime: str) -> bool:
    return all(container_running(runtime, c) for c in CORE_CONTAINERS)

def runtime_drift(runtime: str) -> list:
    """Differences between what the running edge was started with and what detection says now."""
    if not PORTS_FILE.exists():
        return []
    drift = []
    if PORTS_FILE.read_text(encoding="utf-8") != render_ports({**resolve_settings(), "vpn_private": vpn_private_open()}):
        drift.append("Ingress addresses changed since the core was started (e.g. new LAN IP, or a VPN came up/down). Run: om core restart")
    mounts = MOUNTS_FILE.read_text(encoding="utf-8") if MOUNTS_FILE.exists() else ""
    if mounts != render_dashboard_mounts(workspace_dashboard_dirs()):
        drift.append("Workspaces were added or removed since the core started, so the dashboard doesn't see their data folders. Run: om core restart")
    return drift
