#!/usr/bin/env python3
"""The Global Core's lifecycle: its prerequisites, `up` / `down`, self-heal at boot and every two minutes, the instant
watcher, and drift between the running edge and what detection says now."""

import json
import os
import shutil
import time
from pathlib import Path

from gitops.enginectl import (
    _local_engine,
    _om_pids,
    compose_available,
    connect_router,
    container_running,
    engine_info,
    engine_lifecycle,
    revive_zombies,
    unprivileged_port_start,
)
from gitops.omsettings import (
    USER_ENV_TEMPLATE,
    edge_ports,
    load_settings,
    render_dashboard_mounts,
    render_ports,
    resolve_settings,
    vpn_private_open,
    workspace_dashboard_dirs,
    write_runtime_files,
)
from gitops.omstate import (
    AUTH_DIR,
    CONFIG_DIR,
    CORE_CONTAINERS,
    CORE_DIR,
    CORE_ROUTES_DIR,
    DATA_DIR,
    EDGE,
    IS_LINUX,
    MOUNTS_FILE,
    PORTS_FILE,
    REGISTRY_FILE,
    RETIRED_CONTAINERS,
    ROUTES_DIR,
    RUNTIME_ENV,
    STATE_DIR,
    STOP_MARKER,
    USER_ENV,
    run,
    write_private,
)
from gitops.vpndetect import vpn_candidates, vpn_items
from gitops.wsregistry import read_registry


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
        write_private(USER_ENV, USER_ENV_TEMPLATE)  # holds OM_NOTIFY_URL, a bearer-like secret


def core_compose(runtime: str, *args: str) -> list:
    if not MOUNTS_FILE.exists():  # state written before this file existed
        MOUNTS_FILE.write_text(render_dashboard_mounts({}), encoding="utf-8", newline="\n")
    core_file = CORE_DIR / "compose.yml" if (CORE_DIR / "compose.yml").exists() else CORE_DIR / "docker-compose.yml"
    return [runtime, "compose", "--env-file", str(RUNTIME_ENV),
            "-f", str(core_file), "-f", str(PORTS_FILE),
            "-f", str(MOUNTS_FILE), *args]


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


def _announce_ingress(resolved: dict):
    """Where the core answers, and the VPNs found but not trusted."""
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


def _remove_retired_parts(runtime: str):
    """Parts removed by ADR 0003: their containers, state and gated route sections go on the first start after it."""
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


def _compose_up(runtime: str, recreate: bool) -> bool:
    args = ["up", "-d", "--remove-orphans"] + (["--force-recreate"] if recreate else [])
    r = run(core_compose(runtime, *args), cwd=CORE_DIR)
    if r.returncode == 0:
        return True
    err = (r.stderr or r.stdout).strip()
    print(f"\033[31m✗ Global Core failed to start:\033[0m\n{err[-1500:]}")
    if "address" in err.lower() and ("assign" in err.lower() or "in use" in err.lower()):
        print("  Hint: an ingress address changed or a port is taken. Check `om doctor`,"
              f" or set OM_LAN_IP / OM_VPN in {USER_ENV}.")
    return False


def _core_stays_up(runtime: str) -> bool:
    """`up -d` succeeds even if a container crash-loops right after; wait up to 20 s for all of them, and say why not."""
    deadline = time.monotonic() + 20
    while True:
        down = [c for c in CORE_CONTAINERS if not container_running(runtime, c)]
        if not down or time.monotonic() > deadline:
            break
        time.sleep(1)
    for c in down:
        logs = run([runtime, "logs", "--tail", "15", c])
        print(f"\033[31m✗ {c} is not running.\033[0m Last log lines:\n{(logs.stdout + logs.stderr).strip()[-1200:]}")
    return not down


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
        _announce_ingress(resolved)
    _remove_retired_parts(runtime)
    revive_zombies(runtime)  # compose would treat a container with a dead process as already running
    if not _compose_up(runtime, recreate) or not _core_stays_up(runtime):
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
