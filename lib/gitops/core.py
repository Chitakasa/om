#!/usr/bin/env python3
"""
core.py — Host/engine detection and Global Core lifecycle for 'om'.

Everything machine-specific (LAN/Tailscale addresses, engine socket, wallpaper dir,
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

import os
import re
import sys
import json
import time
import socket
import secrets
import subprocess
import shutil
import contextlib
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
CORE_ROUTES_DIR = CORE_DIR / "caddy" / "conf.d"  # program: om's own hand-written routes (portainer, …)
CONFIG_DIR = Path(os.environ.get("OM_CONFIG_DIR") or _default_dirs()[0])
STATE_DIR = Path(os.environ.get("OM_STATE_DIR") or _default_dirs()[1])
USER_ENV = CONFIG_DIR / "om.env"
RUNTIME_ENV = STATE_DIR / "runtime.env"
PORTS_FILE = STATE_DIR / "ports.yml"
DATA_DIR = STATE_DIR / "data"
TOKEN_FILE = DATA_DIR / "edge_token"
STOP_MARKER = DATA_DIR / "stopped"
ROUTES_DIR = STATE_DIR / "routes"
AUTH_DIR = STATE_DIR / "auth"
FIREWALL_DIR = STATE_DIR / "firewall"
LOG_DIR = STATE_DIR / "logs"
REGISTRY_FILE = STATE_DIR / "registry" / "workspaces.json"
ROUTER = "om_router"
EDGE = "om_caddy"
CORE_CONTAINERS = (EDGE, ROUTER, "om_sockguard", "om_dashboard", "portainer")

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
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(content, encoding="utf-8", newline="\n")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
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

def tailscale_cli() -> str | None:
    for cand in ("tailscale", "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
                 r"C:\Program Files\Tailscale\tailscale.exe"):
        if run([cand, "version"]).returncode == 0:
            return cand
    return None

def detect_tailscale() -> tuple[str, str]:
    """(ipv4, MagicDNS name) of this node, or ('', '') if Tailscale isn't up."""
    cli = tailscale_cli()
    if not cli:
        return "", ""
    r = run([cli, "status", "--json"])
    try:
        me = json.loads(r.stdout)["Self"]
        ips = [ip for ip in me.get("TailscaleIPs", []) if "." in ip]
        name = me.get("DNSName", "").rstrip(".")
        if ips and is_local_address(ips[0]):
            return ips[0], name
    except Exception:
        pass
    return "", ""


# ── Configuration resolution ────────────────────────────────────────────────

USER_ENV_TEMPLATE = """# om platform settings. Values: auto (detect), off (disable), or an explicit value.
# After changing, run: om core restart
OM_LAN_IP=auto
OM_TAILSCALE_IP=auto
OM_TAILSCALE_HOST=auto
OM_WALLPAPERS_DIR=auto
# Host ports of the front door. Change them to run a second om (another OS user) on this machine.
OM_HTTP_PORT=80
OM_HTTPS_PORT=443
# Extra inbound ports for the host firewall (comma-separated, ranges allowed), e.g. KDE Connect: 1714-1764
OM_FIREWALL_EXTRA_TCP=
OM_FIREWALL_EXTRA_UDP=
# Portainer (web container management) holds the raw engine socket: admin belongs at the console.
# on to run it (private tier only), off to remove it (its data volume is kept).
OM_PORTAINER=off
"""

def load_settings() -> dict:
    raw = parse_env_file(USER_ENV)
    # Back-compat with pre-1.0 names (LAN_IP=..., TAILSCALE_IP=..., TAILSCALE_HOST=...)
    for old, new in (("LAN_IP", "OM_LAN_IP"), ("TAILSCALE_IP", "OM_TAILSCALE_IP"), ("TAILSCALE_HOST", "OM_TAILSCALE_HOST")):
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

    ts_ip_cfg = s.get("OM_TAILSCALE_IP", "auto").lower()
    ts_host_cfg = s.get("OM_TAILSCALE_HOST", "auto")
    det_ip, det_host = detect_tailscale() if "auto" in (ts_ip_cfg, ts_host_cfg.lower()) else ("", "")
    out["tailscale_ip"] = "" if ts_ip_cfg == "off" else (det_ip if ts_ip_cfg == "auto" else ts_ip_cfg)
    out["tailscale_host"] = "" if ts_host_cfg.lower() == "off" else (det_host if ts_host_cfg.lower() == "auto" else ts_host_cfg)

    wp = s.get("OM_WALLPAPERS_DIR", "auto")
    if wp.lower() == "auto":
        cand = Path.home() / "Pictures" / "Wallpapers"
        wp = str(cand if cand.is_dir() else DATA_DIR / "wallpapers")
    out["wallpapers_dir"] = str(Path(os.path.expanduser(wp)))

    out["http_port"], out["https_port"] = edge_ports(s)
    out["firewall_extra_tcp"] = s.get("OM_FIREWALL_EXTRA_TCP", "")
    out["firewall_extra_udp"] = s.get("OM_FIREWALL_EXTRA_UDP", "")
    return out

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

def render_ports(resolved: dict) -> str:
    """Edge port bindings. Private tier → container :80/:443, LAN → :8080/:8443."""
    h, s = resolved.get("http_port", 80), resolved.get("https_port", 443)
    binds = [f"127.0.0.1:{h}:80", f"127.0.0.1:{s}:443"]
    if is_local_address("::1"):
        binds += [f"[::1]:{h}:80", f"[::1]:{s}:443"]
    ts = resolved.get("tailscale_ip")
    if ts:
        binds += [f"{ts}:{h}:80", f"{ts}:{s}:443", f"{ts}:{s}:443/udp"]
    lan = resolved.get("lan_ip")
    if lan:
        binds += [f"{lan}:{h}:8080", f"{lan}:{s}:8443", f"{lan}:{s}:8443/udp"]
    lines = "\n".join(f'      - "{b}"' for b in binds)
    return f"""# GENERATED by `om core start` from {USER_ENV} — do not edit.
services:
  caddy:
    ports:
{lines}
"""

def compose_path(path) -> str:
    """A host path as compose volume specs want it on every OS: forward slashes, so a
    Windows `C:\\Users\\me\\…` becomes `C:/Users/me/…` (one form, no escaping questions)."""
    return Path(path).as_posix()

def write_runtime_files(runtime: str) -> dict:
    """Resolve settings and write STATE_DIR/runtime.env + STATE_DIR/ports.yml."""
    resolved = resolve_settings()
    eng = engine_info(runtime)
    Path(resolved["wallpapers_dir"]).mkdir(parents=True, exist_ok=True)
    env = {
        "OM_ENGINE_SOCKET": eng["socket"] or "/var/run/docker.sock",
        "OM_WALLPAPERS_DIR": compose_path(resolved["wallpapers_dir"]),
        "OM_STATE_DIR": compose_path(STATE_DIR),
        "LAN_IP": resolved["lan_ip"] or disabled("lan"),
        "TAILSCALE_IP": resolved["tailscale_ip"] or disabled("ts-ip"),
        "TAILSCALE_HOST": resolved["tailscale_host"] or disabled("ts-host"),
        "TAILSCALE_SHORT": resolved["tailscale_host"].split(".")[0] if resolved["tailscale_host"] else disabled("ts-short"),
        "OM_EDGE_TOKEN": edge_token(),
    }
    write_private(RUNTIME_ENV, f"# GENERATED by `om core start` — do not edit; edit {USER_ENV} instead.\n"
                  + "".join(f"{k}={v}\n" for k, v in env.items()))
    PORTS_FILE.write_text(render_ports(resolved), encoding="utf-8", newline="\n")
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
    REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not REGISTRY_FILE.exists():
        REGISTRY_FILE.write_text("{}\n", encoding="utf-8", newline="\n")
    if not USER_ENV.exists():
        USER_ENV.write_text(USER_ENV_TEMPLATE, encoding="utf-8", newline="\n")

def portainer_enabled(settings: dict | None = None) -> bool:
    return (settings or load_settings()).get("OM_PORTAINER", "off").lower() in ("on", "true", "yes", "1")

def core_containers() -> tuple:
    """Core containers expected to run under the current settings."""
    return CORE_CONTAINERS if portainer_enabled() else tuple(c for c in CORE_CONTAINERS if c != "portainer")

def core_compose(runtime: str, *args: str) -> list:
    profiles = ["--profile", "portainer"] if portainer_enabled() else []
    return [runtime, "compose", *profiles, "--env-file", str(RUNTIME_ENV),
            "-f", str(CORE_DIR / "docker-compose.yml"), "-f", str(PORTS_FILE), *args]

def ensure_network(runtime: str, name: str) -> bool:
    if run([runtime, "network", "inspect", name]).returncode == 0:
        return True
    return run([runtime, "network", "create", name]).returncode == 0

def connect_router(runtime: str, workspace_ids) -> list:
    """Attach the internal router to each workspace network. Returns failures."""
    failed = []
    for wid in sorted(set(workspace_ids)):
        net = f"{wid}_net"
        if not ensure_network(runtime, net):
            failed.append(net)
            continue
        r = run([runtime, "network", "connect", net, ROUTER])
        if r.returncode != 0 and "already" not in (r.stderr + r.stdout).lower() and "exists" not in (r.stderr + r.stdout).lower():
            failed.append(net)
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
    resolved = write_runtime_files(runtime)
    if not quiet:
        tiers = ["localhost"]
        if resolved["tailscale_ip"]:
            tiers.append(f"Tailscale {resolved['tailscale_ip']}")
        if resolved["lan_ip"]:
            tiers.append(f"LAN {resolved['lan_ip']} (public tier)")
        print(f"  Ingress: {', '.join(tiers)}")
    args = ["up", "-d", "--remove-orphans"] + (["--force-recreate"] if recreate else [])
    r = run(core_compose(runtime, *args), cwd=CORE_DIR)
    if r.returncode != 0:
        err = (r.stderr or r.stdout).strip()
        print(f"\033[31m✗ Global Core failed to start:\033[0m\n{err[-1500:]}")
        if "address" in err.lower() and ("assign" in err.lower() or "in use" in err.lower()):
            print("  Hint: an ingress address changed or a port is taken. Check `om doctor`,"
                  f" or set OM_LAN_IP / OM_TAILSCALE_IP in {USER_ENV} (auto/off/address).")
        return False
    if not portainer_enabled():
        run([runtime, "rm", "-f", "portainer"])  # a disabled profile is not an orphan to compose
    # `up -d` succeeds even if a container crash-loops right after; verify they stay up.
    deadline = time.monotonic() + 20
    while True:
        down = [c for c in core_containers() if not container_running(runtime, c)]
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
    if not RUNTIME_ENV.exists() or not PORTS_FILE.exists():
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
    drift = runtime_drift(runtime)
    if drift or not core_running(runtime):
        reason = "ingress addresses changed" if drift else "core was not running"
        ok = core_up(runtime, recreate=bool(drift), quiet=True)
        return f"{reason}; core {'restarted' if ok else 'FAILED to restart'}"
    failed = connect_router(runtime, read_registry().keys())
    return f"router re-attach failed for {', '.join(failed)}" if failed else ""

def container_running(runtime: str, name: str) -> bool:
    r = run([runtime, "container", "inspect", "-f", "{{.State.Running}}", name])
    return r.returncode == 0 and "true" in r.stdout.lower()

def core_running(runtime: str) -> bool:
    return all(container_running(runtime, c) for c in core_containers())

def runtime_drift(runtime: str) -> list:
    """Differences between what the running edge was started with and what detection says now."""
    if not PORTS_FILE.exists():
        return []
    current = PORTS_FILE.read_text(encoding="utf-8")
    wanted = render_ports(resolve_settings())
    if current == wanted:
        return []
    return ["Ingress addresses changed since the core was started (e.g. new LAN IP or Tailscale came up/down). Run: om core restart"]
