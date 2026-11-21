#!/usr/bin/env python3
"""`om cli [service] [args…]`: run the command-line tool a service ships, named by its `om.cli` label."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from gitops import policy
from gitops.cli import die
from gitops.enginectl import detect_runtime
from gitops.svclabels import service_labels
from gitops.workspace import discover_compose_dirs, find_compose_file, get_workspace_env, get_workspace_id, resolve_target

LABEL = "om.cli"
# the label in a compose file read as text (list form `- om.cli=./tool`, map form `om.cli: ./tool`, quoted or not)
_TEXT_RE = re.compile(r"""(?m)^\s*(?:-\s*)?["']?om\.cli["']?\s*[:=]\s*["']?([^"'\n#]+?)["']?\s*(?:#.*)?$""")
_BAD_RE = re.compile(r"[\x00-\x1f\x7f$]")


def resolve_cli(folder: Path, rel: str) -> Path:
    """The tool a label names, as a real file inside the service's own folder; ValueError says why not."""
    rel = rel.strip()
    if not rel or _BAD_RE.search(rel):
        raise ValueError("om.cli is empty, or has a control character or a variable")
    parts = rel.replace("\\", "/").split("/")
    if Path(rel).is_absolute() or rel[0] in "/\\~" or re.match(r"[A-Za-z]:", rel) or ".." in parts:
        raise ValueError("om.cli must be a path inside the service's folder (no absolute path, no ..)")
    base = folder.resolve()
    target = (base / rel).resolve()
    if not target.is_relative_to(base):
        raise ValueError("om.cli resolves outside the service's folder (through a symlink?)")
    if not target.is_file():
        raise ValueError(f"om.cli names {rel}, which is not a file in {folder.name}")
    return target


def command_for(path: Path) -> list[str]:
    """How to start the tool: its own interpreter by extension, else the file itself when it is executable."""
    ext = path.suffix.lower()
    if ext == ".py":
        return [sys.executable, str(path)]
    if ext == ".ps1":
        return ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(path)]
    if os.name == "nt" and ext in (".exe", ".cmd", ".bat"):
        return [str(path)]
    if os.name != "nt" and os.access(path, os.X_OK):
        return [str(path)]
    bash = shutil.which("bash")
    if ext in (".sh", ".bash") and bash:
        return [bash, str(path)]
    raise ValueError(f"{path.name} is not executable: `chmod +x` it, or give it a .sh, .py or .ps1 extension")


def folder_cli(folder: Path, runtime: str, env: dict) -> str | None:
    """The om.cli path declared by the services of one compose folder (the engine's normalized config, else the
    file's text); None when there is none, ValueError when its services disagree."""
    cf = find_compose_file(folder)
    if not cf:
        return None
    cfg, _ = policy.compose_config(runtime, cf, env)
    if cfg is not None:
        found = [str(service_labels(svc).get(LABEL, "")).strip() for svc in (cfg.get("services") or {}).values()]
    else:
        found = [m.strip() for m in _TEXT_RE.findall(cf.read_text(encoding="utf-8"))]
    found = sorted({v for v in found if v})
    if len(found) > 1:
        raise ValueError(f"services in {folder.name} declare different om.cli paths: {', '.join(found)}")
    return found[0] if found else None


def cmd_cli(root: Path, args):
    runtime = detect_runtime()
    env = get_workspace_env(root, get_workspace_id(root), runtime)
    if not args.service:
        rows = []
        for _, folder in discover_compose_dirs(root):
            try:
                rel = folder_cli(folder, runtime, env)
            except ValueError as e:
                die(str(e))
            if rel:
                rows.append((folder.name, rel))
        if not rows:
            print("No service declares om.cli (a label naming the tool the service ships, e.g. om.cli=./tool).")
            return
        for name, rel in rows:
            print(f"  {name:<24} {rel}")
        print("\n  Run one: om cli <service> [args…]")
        return
    folder = resolve_target(root, args.service)
    try:
        rel = folder_cli(folder, runtime, env)
        if not rel:
            raise ValueError(f"'{args.service}' has no om.cli label. `om cli` lists the services that do.")
        cmd = command_for(resolve_cli(folder, rel))
    except ValueError as e:
        die(str(e))
    try:
        sys.exit(subprocess.run(cmd + args.args, cwd=folder, env=env).returncode)
    except OSError as e:
        die(f"Could not start {cmd[0]}: {e}")
