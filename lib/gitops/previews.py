#!/usr/bin/env python3
"""Naming and portability checks for `om preview` (the command itself stays in bin/om)."""

from __future__ import annotations

import re
from pathlib import Path

from gitops import core
from gitops.cli import die
from gitops.workspace import discover_compose_dirs, find_compose_file, is_valid_workspace_id

PREVIEWS_DIR = core.STATE_DIR / "previews"

def preview_id(ws_id: str, branch: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", branch.lower()).strip("-")
    pid = f"{ws_id}--{slug}"[:63].rstrip("-")
    if not slug or not is_valid_workspace_id(pid):
        die(f"Cannot make a workspace id from branch '{branch}'.")
    return pid

def preview_portable(root: Path) -> list[str]:
    """Compose files that would collide with the original: container or network names that do
    not follow ${WORKSPACE_ID} / ${WORKSPACE_NET}."""
    bad = []
    for _, d in discover_compose_dirs(root, None):
        text = find_compose_file(d).read_text(encoding="utf-8")
        for m in re.finditer(r"(?m)^\s*container_name:\s*[\"']?([^\s\"']+)", text):
            if "${WORKSPACE_ID" not in m.group(1):
                bad.append(f"{d.relative_to(root)}: container_name: {m.group(1)}  → ${{WORKSPACE_ID:-…}}_<name>")
        for m in re.finditer(r"(?m)^\s*name:\s*[\"']?([^\s\"']+_net)\b", text):
            if "${WORKSPACE" not in m.group(1):
                bad.append(f"{d.relative_to(root)}: network name: {m.group(1)}  → ${{WORKSPACE_NET}}")
    return bad
