#!/usr/bin/env python3
"""The container engine: detection (Podman or Docker, rootless or in a VM), networks, and keeping containers alive
(starting through the engine with the right oom_score_adj, reviving containers whose process died unseen)."""

import functools
import json
import os
import re
import shutil
import time
from pathlib import Path

from gitops.omstate import CORE_CONTAINERS, EGRESS, IS_LINUX, IS_MACOS, IS_WINDOWS, ROUTER, STREAM_ROUTER, run
from gitops.wsregistry import egress_networks


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
