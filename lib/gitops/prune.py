#!/usr/bin/env python3
"""Unused images (`om prune`): after each `om update` the old digest stays on disk.

An image is removable when no container (running or stopped) uses it and no registered workspace's
.om/lock.json pins it, so a stopped workspace keeps its images. Removal is a plain `rmi` (never forced).
"""

import json
import re

from gitops.omstate import run

SIZE_RE = re.compile(r"^([0-9.]+)\s*([kKMGT]?)i?B$")
UNITS = {"": 1, "K": 10**3, "M": 10**6, "G": 10**9, "T": 10**12}


def parse_size(text: str) -> int:
    """'52.1 MB' / '52.1MB' / '980kB' → bytes (0 if unreadable)."""
    m = SIZE_RE.match(text.strip())
    if not m:
        return 0
    return int(float(m.group(1)) * UNITS[m.group(2).upper()])


def _short(image_id: str) -> str:
    return image_id.removeprefix("sha256:")[:12]


def in_use(runtime: str) -> set:
    """Short ids of the images any container, running or not, was created from."""
    ids = run([runtime, "ps", "-a", "-q"]).stdout.split()
    if not ids:
        return set()
    r = run([runtime, "container", "inspect", "--format", "{{.Image}}", *ids])
    return {_short(i) for i in r.stdout.split()}


def candidates(runtime: str, locked: set) -> list:
    """[{'id', 'names', 'size'}] of images nothing uses and no lock pins."""
    r = run([runtime, "images", "-a", "--format", "{{.ID}}\t{{.Repository}}:{{.Tag}}\t{{.Size}}"])
    if r.returncode != 0:
        return []
    by_id = {}
    for line in r.stdout.splitlines():
        image_id, _, rest = line.partition("\t")
        name, _, size = rest.partition("\t")
        entry = by_id.setdefault(_short(image_id), {"id": _short(image_id), "names": [], "size": parse_size(size)})
        if "<none>" not in name:
            entry["names"].append(name)
    used, out = in_use(runtime), []
    for image_id, entry in sorted(by_id.items()):
        if image_id in used:
            continue
        info = run([runtime, "image", "inspect", "--format", "{{json .RepoDigests}}", image_id])
        try:
            digests = {d.rsplit("@", 1)[-1] for d in json.loads(info.stdout or "[]")}
        except ValueError:
            digests = set()
        if digests & locked:
            continue
        out.append(entry)
    return out


def remove(runtime: str, entry: dict) -> bool:
    """rmi every name of the image (or its id when it has none); False if the engine refuses any."""
    return all(run([runtime, "rmi", target]).returncode == 0 for target in entry["names"] or [entry["id"]])
