#!/usr/bin/env python3
"""Workspace helpers: names, ids, config files, the registry entry, compose-folder discovery and the environment compose runs with."""

from __future__ import annotations

import functools
import json
import os
import re
import time
from pathlib import Path

from gitops import enginectl, omsettings
from gitops.cli import die
from gitops.omstate import run
from gitops.wsregistry import read_registry, update_registry

COMPOSE_NAMES = ["compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"]

# \Z, not $: `$` also matches before a final newline, which would let "web\n" into config files and names
SAFE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}\Z")

SAFE_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?\Z")

def is_safe_name(name: str) -> bool:
    return bool(name) and bool(SAFE_NAME_RE.match(name))

# 'core' owns the platform's own routes; 'om' owns the container names `om_*` (om_caddy, om_router, ...) that a
# workspace called `om` would give to its own services. Neither can be a workspace.
RESERVED_WORKSPACE_IDS = ("core", "om")

def is_valid_workspace_id(ws_id: str) -> bool:
    return is_safe_name(ws_id) and ws_id not in RESERVED_WORKSPACE_IDS

def find_compose_file(dir_path: Path) -> Path | None:
    for cname in COMPOSE_NAMES:
        p = dir_path / cname
        if p.is_file():
            return p
    return None

def find_workspace_root() -> Path | None:
    """Walk up from cwd to find .om/config.json."""
    curr = Path.cwd().resolve()
    while True:
        if (curr / ".om" / "config.json").exists():
            return curr
        if curr.parent == curr:
            return None
        curr = curr.parent

def read_ws_config(root: Path) -> dict:
    try:
        return json.loads((root / ".om" / "config.json").read_text(encoding="utf-8"))
    except Exception:
        return {}

def write_ws_config(root: Path, cfg: dict):
    p = root / ".om" / "config.json"
    tmp = p.with_name("config.json.tmp")
    tmp.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8", newline="\n")
    os.replace(tmp, p)

LOCAL_FILES = (".om/local.json", ".om/state.json", ".om/trash/")

def hide_local_files(root: Path):
    """Keep om's machine-local files out of git without touching the tracked .gitignore
    (editing it would itself dirty the tree and block `om sync`)."""
    r = run(["git", "-C", str(root), "rev-parse", "--git-path", "info/exclude"])  # also inside a worktree
    if r.returncode != 0 or not r.stdout.strip():
        return
    exclude = Path(r.stdout.strip())
    if not exclude.is_absolute():
        exclude = root / exclude
    exclude.parent.mkdir(parents=True, exist_ok=True)
    have = exclude.read_text(encoding="utf-8").splitlines() if exclude.exists() else []
    missing = [p for p in LOCAL_FILES if p not in have]
    if missing:
        with open(exclude, "a", encoding="utf-8", newline="\n") as f:
            f.write("".join(f"{p}\n" for p in missing))

def read_local(root: Path) -> dict:
    """Machine-local workspace settings (never committed), e.g. whether this machine auto-syncs."""
    try:
        return json.loads((root / ".om" / "local.json").read_text(encoding="utf-8"))
    except Exception:
        return {}

def write_local(root: Path, data: dict):
    hide_local_files(root)
    (root / ".om" / "local.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")

def gitops_settings(root: Path) -> dict:
    """Shared defaults from .om/config.json, overridden by this machine's .om/local.json."""
    g = {"auto_sync": False, "auto_rollback": True, "interval_seconds": 300}
    g.update(read_ws_config(root).get("gitops", {}))
    g.update(read_local(root).get("gitops", {}))
    return g

def get_workspace_id(root: Path) -> str:
    # A preview's own id lives in its machine-local .om/local.json (the checked-out config is the original's)
    ws_id = read_local(root).get("workspace_id") or read_ws_config(root).get("workspace_id", root.name.lower())
    if not is_valid_workspace_id(ws_id):
        die(f"fatal: invalid workspace id '{ws_id}' (allowed: lowercase letters, digits, '-'; 'core' and 'om' are reserved)")
    return ws_id

def register_workspace(root: Path, ws_id: str):
    def mutate(reg):
        prev = reg.get(ws_id, {})
        if prev.get("path") and Path(prev["path"]).resolve() != root.resolve() and Path(prev["path"]).exists():
            die(f"Workspace id '{ws_id}' is already used by {prev['path']}. Pick another id in .om/config.json.")
        reg[ws_id] = {"id": ws_id, "path": str(root.resolve()), "last_active": int(time.time())}
    update_registry(mutate)

def get_known_workspaces() -> list:
    return list(read_registry().keys())

@functools.cache
def engine(runtime: str) -> dict:
    return enginectl.engine_info(runtime)

def get_workspace_env(root: Path, ws_id: str, runtime: str) -> dict:
    env = os.environ.copy()
    env["WORKSPACE_ID"] = ws_id
    env["COMPOSE_PROJECT_NAME"] = ws_id
    env["WORKSPACE_ROOT"] = omsettings.compose_path(root)
    env["DATA_DIR"] = omsettings.compose_path(root / "data")
    env["WORKSPACE_DATA"] = omsettings.compose_path(root / "data")
    env["WORKSPACE_NET"] = f"{ws_id}_net"
    env["DOCKER_SOCK"] = engine(runtime)["socket"] or "/var/run/docker.sock"
    return env

def discover_compose_dirs(root: Path, target: str | None = None) -> list[tuple[int, Path]]:
    """Discover compose directories (workspace root, depth 1 and 2) ordered by '# priority: N'."""
    found = []

    def get_priority(d: Path) -> int:
        cf = find_compose_file(d)
        if cf:
            try:
                for line in cf.read_text(encoding="utf-8").splitlines():
                    if "priority:" in line.lower():
                        digits = "".join(filter(str.isdigit, line.split(":", 1)[1]))
                        if digits:
                            return int(digits)
            except Exception:
                pass
        return 50

    if find_compose_file(root) and (not target or target.lower() in [root.name.lower(), "root"]):
        found.append((get_priority(root), root))

    ignored_dirs = {"data", ".om", ".git", "docs", "scripts", "overrides", "__pycache__", "node_modules"}
    seen_dirs = {root}
    try:
        for child in sorted(root.iterdir()):
            # A folder with an .omignore file (and everything below it) is not part of the workspace.
            if not child.is_dir() or child.name in ignored_dirs or child.name.startswith(".") \
                    or (child / ".omignore").exists():
                continue
            if find_compose_file(child) and child not in seen_dirs:
                if not target or target.lower() == child.name.lower():
                    found.append((get_priority(child), child))
                seen_dirs.add(child)
            try:
                for sub in sorted(child.iterdir()):
                    if sub.is_dir() and not sub.name.startswith(".") and sub.name not in ignored_dirs \
                            and not (sub / ".omignore").exists() and sub not in seen_dirs and find_compose_file(sub):
                        if not target or target.lower() == sub.name.lower():
                            found.append((get_priority(sub), sub))
                        seen_dirs.add(sub)
            except OSError:
                pass
    except OSError:
        pass

    found.sort(key=lambda x: (x[0], x[1].name))
    return found

def resolve_target(root: Path, target: str) -> Path:
    targets = discover_compose_dirs(root, target)
    if not targets:
        die(f"No service or project named '{target}' in this workspace. See `om status`.")
    return targets[0][1]

def service_containers(runtime: str, root: Path, dir_path: Path) -> list[str]:
    """Container names created from a compose directory (compose labels, then container_name fallback)."""
    r = run([runtime, "ps", "-a", "--filter", f"label=com.docker.compose.project.working_dir={dir_path}",
             "--format", "{{.Names}}"])
    names = [n for n in r.stdout.split() if n]
    if names:
        return names
    ws_id = get_workspace_id(root)
    cf = find_compose_file(dir_path)
    out = []
    if cf:
        for m in re.finditer(r"container_name:\s*[\"']?([^\s\"']+)", cf.read_text(encoding="utf-8")):
            out.append(re.sub(r"\$\{WORKSPACE_ID(:-[^}]*)?\}", ws_id, m.group(1)))
    return out or [f"{ws_id}_{dir_path.name}"]

def compose(runtime: str, compose_file: Path, *args: str) -> list:
    return [runtime, "compose", "-f", str(compose_file), *args]

def project_rel(root: Path, d: Path) -> str:
    """A compose folder's path inside the workspace ('' for the workspace root)."""
    return "" if d == root else d.relative_to(root).as_posix()

def has_build(compose_file: Path) -> bool:
    """True if a compose file builds an image (any Dockerfile/Containerfile name), not just pulls one."""
    return bool(re.search(r"^\s+build\s*:", compose_file.read_text(encoding="utf-8"), re.M))
