#!/usr/bin/env python3
"""Paths, constants and small utilities shared by every om module: where state and settings live, the core's
container names and port bases, file locking, atomic and private writes, and the one subprocess wrapper.

OM_HOME (~/.om) holds only the program. Like git keeping its program apart from each repo's .git, everything
per-machine lives outside it, so om can be reinstalled or updated without touching state:

  CONFIG_DIR/om.env          user settings (values may be 'auto' / 'off')
  STATE_DIR/runtime.env      generated: resolved values for compose (--env-file)
  STATE_DIR/ports.yml        generated: host port bindings for the edge proxy
  STATE_DIR/data/            Caddy PKI, edge-router token, router + dashboard data
  STATE_DIR/routes/          generated workspace routes      STATE_DIR/auth/  login hash
  STATE_DIR/registry/        workspace registry              STATE_DIR/logs/, firewall/

CONFIG_DIR / STATE_DIR default to $XDG_CONFIG_HOME/om and $XDG_STATE_HOME/om
(~/.config/om, ~/.local/state/om; %LOCALAPPDATA%\\om on Windows) and can be set
with OM_CONFIG_DIR / OM_STATE_DIR."""

import contextlib
import os
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
