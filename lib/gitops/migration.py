#!/usr/bin/env python3
"""Legacy state migration: installs from before the program/state split kept their state inside OM_HOME."""

import re
import shutil
from pathlib import Path

from gitops.omstate import (
    AUTH_DIR,
    CORE_DIR,
    CORE_ROUTES_DIR,
    DATA_DIR,
    FIREWALL_DIR,
    LOG_DIR,
    OM_HOME,
    PORTS_FILE,
    REGISTRY_FILE,
    ROUTES_DIR,
    RUNTIME_ENV,
    USER_ENV,
)

# Generated routes carry their workspace in the header; om's own routes are owned by 'core'.
_GENERATED_ROUTE_RE = re.compile(r"^# (?:Service|Public Subpath|Private Subpath): [a-z0-9-]+ \(([a-z0-9-]+)\)", re.MULTILINE)


def _legacy_moves() -> list[tuple[Path, Path]]:
    """(old, new) pairs for state still sitting inside OM_HOME."""
    old_core, old_cfg = CORE_DIR, OM_HOME / "config"
    pairs = [
        (old_core / ".env", USER_ENV),
        (old_core / ".runtime.env", RUNTIME_ENV),
        (old_core / "ports.generated.yml", PORTS_FILE),
        (old_core / "firewall", FIREWALL_DIR),
        (old_cfg / "workspaces.json", REGISTRY_FILE),
        (OM_HOME / "logs", LOG_DIR),
    ]
    old_data = old_core / "data"
    if old_data.is_dir():
        pairs += [(p, DATA_DIR / p.name) for p in sorted(old_data.iterdir())]
    old_auth = old_core / "caddy" / "auth.d"
    if old_auth.is_dir():
        pairs += [(p, AUTH_DIR / p.name) for p in sorted(old_auth.glob("*.conf"))]
    if CORE_ROUTES_DIR.is_dir():
        for p in sorted(CORE_ROUTES_DIR.iterdir()):
            try:
                m = p.is_file() and _GENERATED_ROUTE_RE.search(p.read_text(encoding="utf-8")[:400])
            except OSError:
                m = None
            if m and m.group(1) != "core":  # 'core' is reserved for om's own routes
                pairs.append((p, ROUTES_DIR / p.name))
    return [(o, n) for o, n in pairs
            if (o.exists() or o.is_symlink()) and not o.name.endswith(".pre-migration")]


def legacy_state_present() -> bool:
    return bool(_legacy_moves())


def migrate_legacy_state() -> list[str]:
    """Move pre-split state out of OM_HOME. Idempotent; never overwrites newer state.

    Returns human-readable lines describing what moved. Run with the core stopped:
    the edge bind-mounts several of these paths.
    """
    done = []
    for old, new in _legacy_moves():
        if new.exists():
            # Already migrated (or recreated since): keep the new one, park the old one.
            parked = old.with_name(old.name + ".pre-migration")
            if not parked.exists():
                old.rename(parked)
                done.append(f"kept {new} (old copy left at {parked})")
            continue
        new.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(old), str(new))
        done.append(f"{old} → {new}")
    for d in (OM_HOME / "config", CORE_DIR / "data", CORE_DIR / "caddy" / "auth.d"):
        try:
            for leftover in ("workspaces.lock", ".keep"):
                (d / leftover).unlink(missing_ok=True)
            d.rmdir()
        except OSError:
            pass
    return done
