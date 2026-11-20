#!/usr/bin/env python3
"""Route generation for om: workspace compose files -> Caddy route files in the state dir, and pruning of
routes whose workspace is gone. (Moved out of bin/om; bin/om re-exports every name.)"""

from __future__ import annotations

import re
from pathlib import Path

from gitops import core, hostsetup, policy, stream
from gitops.core import read_registry, run
from gitops.network import reload_caddy
from gitops.routes import (
    SNIPPET_FILE,
    compose_labels,
    config_meta,
    parse_service_meta,
    render_alias,
    render_vhost,
    route_options,
    validate_snippet,
)
from gitops.workspace import SAFE_NAME_RE, discover_compose_dirs, find_compose_file, get_workspace_env, get_workspace_id, is_safe_name

CONF_D = core.ROUTES_DIR          # generated workspace routes (state)


# *_subpath: routes of om before per-service ports; still listed so a sync prunes them.
ROUTE_SUFFIXES = (".caddy", ".private_alias", ".public_alias", ".public_subpath", ".private_subpath")


ROUTE_OWNER_RE = re.compile(r"^# (?:Service|Public Alias|Private Alias|Public Subpath|Private Subpath): [a-z0-9-]+ \(([a-z0-9-]+)\)")


def route_owner(path: Path) -> str | None:
    """Return the workspace id recorded in a generated route file's header, if any."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for _ in range(4):
                m = ROUTE_OWNER_RE.match(f.readline())
                if m:
                    return m.group(1)
    except Exception:
        pass
    return None


def find_alias_conflict(paths: list[str], ws_id: str) -> str | None:
    """A route file owned by another workspace that already redirects one of these paths."""
    for f in CONF_D.glob("*_alias"):
        if route_owner(f) == ws_id:
            continue
        try:
            text = f.read_text(encoding="utf-8")
        except OSError:
            continue
        if any(re.search(rf"^redir {re.escape(p)} ", text, re.MULTILINE) for p in paths):
            return f.name
    return None


def orphan_route_owners(runtime: str) -> tuple[dict[str, list[Path]], dict[str, list[Path]]]:
    """Route files whose workspace is gone, split into (prunable, still_running).

    A workspace is gone when it is unregistered or its folder no longer has .om/config.json
    (deleted without `om remove`, or on an unplugged drive). Workspaces that still have
    running containers are never pruned: their routes may be the only way in.
    """
    reg = read_registry()
    by_owner: dict[str, list[Path]] = {}
    if CONF_D.is_dir():
        for f in sorted(CONF_D.iterdir()):
            owner = route_owner(f) if f.suffix in ROUTE_SUFFIXES else None
            if owner and owner != "core":
                by_owner.setdefault(owner, []).append(f)
    prunable, running = {}, {}
    for ws, files in by_owner.items():
        path = reg.get(ws, {}).get("path")
        if path and (Path(path) / ".om" / "config.json").is_file():
            continue
        r = run([runtime, "ps", "-q", "--filter", f"label=workspace.id={ws}"])
        # Engine unreachable = can't prove nothing runs: keep the routes
        (running if r.returncode != 0 or r.stdout.strip() else prunable)[ws] = files
    return prunable, running


def prune_orphan_routes(runtime: str, reload: bool = True, quiet: bool = False, force: bool = False) -> list[Path]:
    """Delete routes of workspaces that no longer exist (see orphan_route_owners). Keeps the
    registry entry, so a workspace that comes back is re-routed by its next `om start`.
    force (explicit `om list --prune`) also drops workspaces whose containers may still run."""
    prunable, running = orphan_route_owners(runtime)
    if force:
        prunable, running = {**prunable, **running}, {}
    removed = []
    for ws, files in prunable.items():
        for f in files:
            f.unlink(missing_ok=True)
            removed.append(f)
        core.release_slots(ws)
        stream.prune_stream_fragments(ws, runtime)
        if not quiet:
            print(f"  \033[36m- Pruned {len(files)} route file(s) of missing workspace '{ws}'\033[0m")
    if not quiet:
        for ws in running:
            print(f"  \033[33m⚠ Workspace '{ws}' folder is missing but its containers may still run; routes kept."
                  f" Stop them, then `om core reload`.\033[0m")
    if removed and reload:
        reload_caddy(runtime, quiet=True)
    return removed


def sync_caddy_routes(root: Path, runtime: str, reload: bool = True, configs: dict | None = None):
    """Serialized: two `om` processes (a scheduled sync and a manual start) never write routes at once.
    configs: {compose dir: normalized config} already read by the caller (saves a `compose config` each)."""
    with core.file_lock(core.STATE_DIR / "routes.lock"):
        return _sync_caddy_routes(root, runtime, reload, configs or {})


def _warn(text: str) -> None:
    print(f"  \033[33m⚠ {text}\033[0m")


def _refuse(text: str, problems: list[str] | None = None) -> None:
    print(f"  \033[31m✗ {text}\033[0m")
    for pr in (problems or [])[:5]:
        print(f"      {pr}")


def _read_service(root: Path, dir_path: Path, runtime: str, ws_id: str, configs: dict):
    """(port, is_public, no_web, labels, route options) of one compose folder; None if it cannot be read.
    From the engine's normalized config, or from the file itself when there is no engine."""
    sname = dir_path.name
    try:
        compose_file = find_compose_file(dir_path)
        cfg = configs.get(dir_path) if dir_path in configs else \
            policy.compose_config(runtime, compose_file, get_workspace_env(root, ws_id, runtime))[0]
        if cfg:
            (port, is_public, no_web), labels = config_meta(cfg, sname)
            return port, is_public, no_web, labels, route_options("", sname, labels)
        content = compose_file.read_text(encoding="utf-8")
        port, is_public, no_web = parse_service_meta(content, sname)
        return port, is_public, no_web, compose_labels(content), route_options(content, sname)
    except Exception as e:
        _warn(f"Skipping routes for '{sname}': {e}")
        return None


def _load_snippet(dir_path: Path, opts: dict) -> bool:
    """Add the folder's om.caddy to opts. False (no route) when it is refused: fail closed, because the
    snippet may be what protects the service (e.g. basic_auth)."""
    snippet_file = dir_path / SNIPPET_FILE
    if not snippet_file.is_file():
        return True
    snippet = snippet_file.read_text(encoding="utf-8")
    problems = validate_snippet(snippet)
    if problems:
        _refuse(f"{dir_path.name}: {SNIPPET_FILE} refused — no route until fixed:", problems)
        return False
    opts["snippet"] = snippet.strip("\n") + "\n"
    return True


def _collect_services(root: Path, runtime: str, ws_id: str, configs: dict):
    """([(name, port, is_public, options)] with a web route, {name: stream meta}) for the workspace's folders."""
    services, stream_candidates = [], {}
    for _prio, dir_path in discover_compose_dirs(root, None):
        sname = dir_path.name
        if not is_safe_name(sname):
            _warn(f"Skipping routes for '{sname}': name must match {SAFE_NAME_RE.pattern}")
            continue
        read = _read_service(root, dir_path, runtime, ws_id, configs)
        if read is None:
            continue
        port, is_public, no_web, labels, opts = read
        st_meta, st_probs = stream.parse_stream_meta(labels, sname)
        if st_probs:
            _refuse(f"{sname}: om.tcp labels refused — no stream route until fixed:", st_probs)
            st_meta = None
        if st_meta is not None:
            stream_candidates[sname] = {**st_meta, "net": opts.get("net")}
            if "dashboard.port" not in labels and labels.get("dashboard.web", "").lower() != "true":
                no_web = True
        if not _load_snippet(dir_path, opts):
            continue
        if opts.get("net_problems"):
            # Fail closed: an address rule that cannot be read must not leave the service open to everyone.
            _refuse(f"{sname}: om.net labels refused — no route until fixed:", opts["net_problems"])
            continue
        if not no_web:
            services.append((sname, port, is_public, opts))
    return services, stream_candidates


def _assign_ports(ws_id: str, services: list, stream_candidates: dict):
    """({"<ws>/<svc>": slot}, stream registry entries of this workspace)."""
    try:
        slots = core.assign_slots(ws_id, [sname for sname, *_ in services])
    except RuntimeError as e:
        _warn(f"{e}; services without one are reachable on this machine only")
        slots = core.service_slots()
    stream_assigned = {}
    if stream_candidates:
        try:
            stream_assigned = core.assign_stream_slots(ws_id, stream_candidates)
        except RuntimeError as e:
            _warn(f"{e}; stream services not routed")
    else:
        core.release_stream_slots(ws_id)
    return slots, stream_assigned


def _http_routes(ws_id: str, services: list, slots: dict):
    """({file name: content}, {svc: address policy}, {svc: ports that are not logged}) for the web services."""
    expected, net_policies, no_log = {}, {}, {}
    for sname, port, is_public, opts in services:
        slot = slots.get(f"{ws_id}/{sname}")
        own_ports = [core.PRIVATE_PORT_BASE + slot] + ([core.PUBLIC_PORT_BASE + slot] if is_public else []) if slot is not None else []
        if opts.get("log") == "off" and slot is not None:
            no_log[sname] = list(own_ports)
        if opts.get("net") is not None and slot is not None:
            pol = {"ports": list(own_ports), **opts["net"]}
            net_policies[sname] = pol
            if not hostsetup.net_policy_enforced(f"{ws_id}/{sname}", pol):
                # Fail closed: until the host firewall carries its rules, the service has no port of its own
                # (it stays reachable on this machine through <ws>.<svc>.localhost).
                _refuse(f"{sname}: its om.net rules are not in the host firewall yet; its own ports stay closed until `om firewall apply`.")
                slot = None
        expected[f"{ws_id}-{sname}.caddy"] = render_vhost(ws_id, sname, port, opts, slot, is_public)
        if slot is None:
            continue
        conflict = find_alias_conflict([f"/{sname}"] + opts.get("aliases", []), ws_id)
        if conflict:
            _warn(f"/{sname} or an alias is already redirected by {conflict}; no redirects for {ws_id}/{sname} (its own ports still work).")
            continue
        expected[f"{ws_id}-{sname}.private_alias"] = render_alias(ws_id, sname, core.PRIVATE_PORT_BASE + slot, False, opts)
        if is_public:
            expected[f"{ws_id}-{sname}.public_alias"] = render_alias(ws_id, sname, core.PUBLIC_PORT_BASE + slot, True, opts)
    return expected, net_policies, no_log


def _stream_routes(ws_id: str, stream_candidates: dict, stream_assigned: dict, net_policies: dict, no_log: dict) -> dict:
    """The stream services that get a route; fills net_policies / no_log with their ports."""
    active = {}
    for sname, meta in stream_candidates.items():
        key = f"{ws_id}/{sname}"
        if key not in stream_assigned:
            continue
        hp = stream_assigned[key]["host_port"]
        if meta.get("log") == "off":
            no_log.setdefault(sname, []).append(hp)
        if meta.get("net") is not None:
            net_policies.setdefault(sname, {"ports": []})
            net_policies[sname]["ports"] = sorted(set(net_policies[sname].get("ports", []) + [hp]))
            for k in ("allow", "deny"):
                if meta["net"].get(k):
                    net_policies[sname][k] = meta["net"][k]
            if not hostsetup.net_policy_enforced(key, {"ports": [hp], **meta["net"]}):
                _refuse(f"{sname}: its om.net rules are not in the host firewall yet; stream port {hp} stays closed until `om firewall apply`.")
                continue
        active[sname] = {**meta, "host_port": hp}
    return active


def _write_routes(ws_id: str, expected: dict) -> bool:
    """Write the changed route files and remove this workspace's stale ones; True if anything changed."""
    changed = False
    for fname, content in expected.items():
        target = CONF_D / fname
        owner = route_owner(target) if target.exists() else None
        if owner not in (None, ws_id):
            # `<ws>-<svc>` is ambiguous ('-' is in both ids): never overwrite another workspace's route
            _refuse(f"{fname} already belongs to workspace '{owner}' (same <workspace>-<service> name);"
                    f" no route for {ws_id} until one of them is renamed.")
            continue
        if not target.exists() or target.read_text(encoding="utf-8") != content:
            core.write_atomic(target, content)
            changed = True
    # Prune routes for removed services and flipped tiers (a stale public route keeps a service on the LAN)
    for f in CONF_D.iterdir():
        if f.suffix in ROUTE_SUFFIXES and f.name not in expected and route_owner(f) == ws_id:
            f.unlink()
            print(f"  \033[36m- Removed stale route {f.name}\033[0m")
            changed = True
    return changed


def _sync_caddy_routes(root: Path, runtime: str, reload: bool, configs: dict):
    """Regenerate this workspace's route files from its compose files and prune stale ones.

    Only files whose header names this workspace are ever written or removed, so other
    workspaces' and core's routes are never touched.
    """
    ws_id = get_workspace_id(root)
    CONF_D.mkdir(parents=True, exist_ok=True)
    services, stream_candidates = _collect_services(root, runtime, ws_id, configs)
    slots, stream_assigned = _assign_ports(ws_id, services, stream_candidates)
    expected, net_policies, no_log = _http_routes(ws_id, services, slots)
    active_stream = _stream_routes(ws_id, stream_candidates, stream_assigned, net_policies, no_log)
    stream.sync_stream_routes(ws_id, active_stream, runtime)
    core.set_net_policies(ws_id, net_policies)
    core.set_no_log(ws_id, no_log)

    changed = _write_routes(ws_id, expected)
    if prune_orphan_routes(runtime, reload=False):
        changed = True
    if changed and reload:
        reload_caddy(runtime=runtime, workspace_id=ws_id)
    return changed
