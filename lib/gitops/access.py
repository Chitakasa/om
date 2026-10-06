#!/usr/bin/env python3
"""The access file: who may reach what (VISION idea 4 — "requests read; signatures write").

One plain JSON document per version in $OM_STATE_DIR/access/<n>.json, each with a detached SSH
signature <n>.json.sig made by an owner key (`ssh-keygen -Y sign -n om-access`). Version n
records the SHA-256 of version n-1 and is valid only if signed by an owner listed in n-1, so a
change cannot authorise itself and a rewrite breaks the chain. Version 1 is trusted on first use.

Only the console changes it (om device add/revoke, later invite/approve); the data plane (door,
edge, gate) only reads what om renders from the verified head.
"""

import copy
import hashlib
import ipaddress
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

from gitops.core import STATE_DIR, load_settings

ACCESS_DIR = STATE_DIR / "access"
NAMESPACE = "om-access"


def owner_key_path(settings: dict | None = None) -> Path:
    s = settings if settings is not None else load_settings()
    return Path(os.path.expanduser(s.get("OM_OWNER_KEY", "~/.ssh/id_ed25519")))


def _versions() -> list[int]:
    return sorted(int(p.stem) for p in ACCESS_DIR.glob("*.json") if p.stem.isdigit())


def _path(n: int) -> Path:
    return ACCESS_DIR / f"{n}.json"


def _sha(n: int) -> str:
    return hashlib.sha256(_path(n).read_bytes()).hexdigest()


def _verify_sig(n: int, owners: list[str]) -> bool:
    if not owners:
        return False
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".signers", delete=False) as f:
        for key in owners:
            f.write(f'owner namespaces="{NAMESPACE}" {" ".join(key.split()[:2])}\n')
        signers = f.name
    try:
        with open(_path(n), "rb") as data:
            r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", signers, "-I", "owner", "-n", NAMESPACE,
                                "-s", str(_path(n)) + ".sig"], stdin=data, capture_output=True)
        return r.returncode == 0
    except OSError:
        return False
    finally:
        os.unlink(signers)


def verify_chain() -> tuple[dict | None, list[str]]:
    """(head document, problems). The head is the last version whose whole chain verifies."""
    problems, prev_doc, head = [], None, None
    for i, n in enumerate(_versions(), start=1):
        if n != i:
            problems.append(f"version {i} is missing (found {n})")
            break
        try:
            doc = json.loads(_path(n).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            problems.append(f"version {n}: unreadable")
            break
        if doc.get("version") != n:
            problems.append(f"version {n}: says it is version {doc.get('version')}")
            break
        if doc.get("prev") != (_sha(n - 1) if n > 1 else None):
            problems.append(f"version {n}: does not chain to version {n - 1} (rewritten?)")
            break
        signers = (prev_doc or doc).get("owners", [])  # n>1: the previous version's owners
        if not _verify_sig(n, signers):
            problems.append(f"version {n}: not signed by an owner of version {max(n - 1, 1)}")
            break
        prev_doc = head = doc
    return head, problems


def empty(owner_pub: str, server_pub: str, subnet: str) -> dict:
    net = ipaddress.ip_network(subnet, strict=False)
    return {
        "version": 0, "prev": None,
        "owners": [owner_pub],
        "door": {"subnet": str(net), "address": str(next(net.hosts())), "public_key": server_pub},
        "devices": {}, "people": {}, "grants": {},
    }


def next_address(doc: dict) -> str:
    net = ipaddress.ip_network(doc["door"]["subnet"])
    used = {doc["door"]["address"]} | {d["address"] for d in doc["devices"].values()}
    for ip in net.hosts():
        if str(ip) not in used:
            return str(ip)
    raise ValueError(f"door subnet {net} is full")


def commit(doc: dict, change: str) -> dict:
    """Write `doc` as the next version, sign it with the owner key, and verify the whole chain."""
    ACCESS_DIR.mkdir(parents=True, exist_ok=True)
    versions = _versions()
    n = (versions[-1] + 1) if versions else 1
    new = copy.deepcopy(doc)
    new.update({"version": n, "prev": _sha(n - 1) if n > 1 else None,
                "change": change, "time": time.strftime("%Y-%m-%dT%H:%M:%S%z")})
    path = _path(n)
    path.write_text(json.dumps(new, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    r = subprocess.run(["ssh-keygen", "-Y", "sign", "-q", "-f", str(owner_key_path()), "-n", NAMESPACE, str(path)],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    head, problems = verify_chain()
    if r.returncode != 0 or problems or not head or head.get("version") != n:
        path.unlink(missing_ok=True)
        Path(str(path) + ".sig").unlink(missing_ok=True)
        raise RuntimeError((r.stderr.strip() or "; ".join(problems) or "signature did not verify")[-400:])
    return head
