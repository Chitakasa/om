#!/usr/bin/env python3
"""Route generation for om: workspace compose files -> Caddy route files in the state dir, and pruning of
routes whose workspace is gone. (Moved out of bin/om; bin/om re-exports every name.)"""

from __future__ import annotations

import re
from pathlib import Path

from gitops import core, hostsetup, policy, stream
from gitops.core import read_registry, run
from gitops.network import reload_caddy
from gitops.routes import (SNIPPET_FILE, compose_labels, config_meta, parse_service_meta, render_alias, render_vhost,
                           route_options, validate_snippet)
from gitops.workspace import (SAFE_NAME_RE, discover_compose_dirs, find_compose_file, get_workspace_env,
                              get_workspace_id, is_safe_name)

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


def _sync_caddy_routes(root: Path, runtime: str, reload: bool, configs: dict):
    """Regenerate this workspace's route files from its compose files and prune stale ones.

    Only files whose header names this workspace are ever written or removed, so other
    workspaces' and core's routes are never touched.
    """
    ws_id = get_workspace_id(root)
    CONF_D.mkdir(parents=True, exist_ok=True)
    expected = {}
    services = []
    stream_candidates = {}
    for prio, dir_path in discover_compose_dirs(root, None):
        sname = dir_path.name
        if not is_safe_name(sname):
            print(f"  \033[33m⚠ Skipping routes for '{sname}': name must match {SAFE_NAME_RE.pattern}\033[0m")
            continue
        try:
            compose_file = find_compose_file(dir_path)
            cfg = configs.get(dir_path) if dir_path in configs else \
                policy.compose_config(runtime, compose_file, get_workspace_env(root, ws_id, runtime))[0]
            if cfg:
                (port, is_public, no_web), labels = config_meta(cfg, sname)
                opts = route_options("", sname, labels)
            else:  # engine unavailable: read the file itself
                content = compose_file.read_text(encoding="utf-8")
                port, is_public, no_web = parse_service_meta(content, sname)
                opts = route_options(content, sname)
                labels = compose_labels(content)
        except Exception as e:
            print(f"  \033[33m⚠ Skipping routes for '{sname}': {e}\033[0m")
            continue
        st_meta, st_probs = stream.parse_stream_meta(labels, sname)
        if st_probs:
            print(f"  \033[31m✗ {sname}: om.tcp labels refused — no stream route until fixed:\033[0m")
            for pr in st_probs[:5]:
                print(f"      {pr}")
            st_meta = None
        if st_meta is not None:
            stream_candidates[sname] = {**st_meta, "net": opts.get("net")}
            if "dashboard.port" not in labels and labels.get("dashboard.web", "").lower() != "true":
                no_web = True
        snippet_file = dir_path / SNIPPET_FILE
        if snippet_file.is_file():
            snippet = snippet_file.read_text(encoding="utf-8")
            problems = validate_snippet(snippet)
            if problems:
                # Fail closed: the snippet may be what protects the service (e.g. basic_auth).
                print(f"  \033[31m✗ {sname}: {SNIPPET_FILE} refused — no route until fixed:\033[0m")
                for pr in problems[:5]:
                    print(f"      {pr}")
                continue
            opts["snippet"] = snippet.strip("\n") + "\n"
        if opts.get("net_problems"):
            # Fail closed: an address rule that cannot be read must not leave the service open to everyone.
            print(f"  \033[31m✗ {sname}: om.net labels refused — no route until fixed:\033[0m")
            for pr in opts["net_problems"][:5]:
                print(f"      {pr}")
            continue
        if not no_web:
            services.append((sname, port, is_public, opts))
    try:
        slots = core.assign_slots(ws_id, [sname for sname, *_ in services])
    except RuntimeError as e:
        print(f"  \033[33m⚠ {e}; services without one are reachable on this machine only\033[0m")
        slots = core.service_slots()

    stream_assigned = {}
    if stream_candidates:
        try:
            stream_assigned = core.assign_stream_slots(ws_id, stream_candidates)
        except RuntimeError as e:
            print(f"  \033[33m⚠ {e}; stream services not routed\033[0m")
    else:
        core.release_stream_slots(ws_id)

    net_policies, no_log = {}, {}
    for sname, port, is_public, opts in services:
        slot = slots.get(f"{ws_id}/{sname}")
        if opts.get("log") == "off" and slot is not None:
            no_log[sname] = [core.PRIVATE_PORT_BASE + slot] + ([core.PUBLIC_PORT_BASE + slot] if is_public else [])
        if opts.get("net") is not None and slot is not None:
            pol = {"ports": [core.PRIVATE_PORT_BASE + slot] + ([core.PUBLIC_PORT_BASE + slot] if is_public else []), **opts["net"]}
            net_policies[sname] = pol
            if not hostsetup.net_policy_enforced(f"{ws_id}/{sname}", pol):
                # Fail closed: until the host firewall carries its rules, the service has no port of its own
                # (it stays reachable on this machine through <ws>.<svc>.localhost).
                print(f"  \033[31m✗ {sname}: its om.net rules are not in the host firewall yet; its own ports stay closed"
                      f" until `om firewall apply`.\033[0m")
                slot = None
        expected[f"{ws_id}-{sname}.caddy"] = render_vhost(ws_id, sname, port, opts, slot, is_public)
        if slot is None:
            continue
        paths = [f"/{sname}"] + opts.get("aliases", [])
        conflict = find_alias_conflict(paths, ws_id)
        if conflict:
            print(f"  \033[33m⚠ /{sname} or an alias is already redirected by {conflict}; no redirects for {ws_id}/{sname}"
                  f" (its own ports still work).\033[0m")
            continue
        expected[f"{ws_id}-{sname}.private_alias"] = render_alias(ws_id, sname, core.PRIVATE_PORT_BASE + slot, False, opts)
        if is_public:
            expected[f"{ws_id}-{sname}.public_alias"] = render_alias(ws_id, sname, core.PUBLIC_PORT_BASE + slot, True, opts)

    active_stream = {}
    for sname, meta in stream_candidates.items():
        key = f"{ws_id}/{sname}"
        if key not in stream_assigned:
            continue
        hp = stream_assigned[key]["host_port"]
        if meta.get("log") == "off":
            no_log.setdefault(sname, []).append(hp)
        stream_allowed = True
        if meta.get("net") is not None:
            pol = {"ports": [hp], **meta["net"]}
            net_policies.setdefault(sname, {"ports": []})
            net_policies[sname]["ports"] = sorted(set(net_policies[sname].get("ports", []) + [hp]))
            for k in ("allow", "deny"):
                if meta["net"].get(k):
                    net_policies[sname][k] = meta["net"][k]
            if not hostsetup.net_policy_enforced(f"{ws_id}/{sname}", pol):
                print(f"  \033[31m✗ {sname}: its om.net rules are not in the host firewall yet; stream port {hp} stays closed"
                      f" until `om firewall apply`.\033[0m")
                stream_allowed = False
        if stream_allowed:
            active_stream[sname] = {**meta, "host_port": hp}

    stream.sync_stream_routes(ws_id, active_stream, runtime)

    core.set_net_policies(ws_id, net_policies)
    core.set_no_log(ws_id, no_log)

    changed = False
    for fname, content in expected.items():
        target = CONF_D / fname
        owner = route_owner(target) if target.exists() else None
        if owner not in (None, ws_id):
            # `<ws>-<svc>` is ambiguous ('-' is in both ids): never overwrite another workspace's route
            print(f"  \033[31m✗ {fname} already belongs to workspace '{owner}' (same <workspace>-<service> name);"
                  f" no route for {ws_id} until one of them is renamed.\033[0m")
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

    if prune_orphan_routes(runtime, reload=False):
        changed = True

    if changed and reload:
        reload_caddy(runtime=runtime, workspace_id=ws_id)
    return changed
