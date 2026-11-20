#!/usr/bin/env python3
"""The workspace registry and the other per-workspace state files: stable port slots for web and raw TCP stream
services, address policies (om.net.*), services whose connections are not logged, and the networks om_egress joins."""

import json
import os
from pathlib import Path

from gitops.omstate import (
    EGRESS_NETS_FILE,
    NET_POLICY_FILE,
    NO_LOG_FILE,
    PORT_SLOTS,
    REGISTRY_FILE,
    SERVICE_PORTS_FILE,
    STATE_DIR,
    STREAM_PORT_BASE,
    STREAM_PORT_SLOTS,
    STREAM_PORTS_FILE,
    file_lock,
)


def _read_slots() -> dict:
    try:
        data = json.loads(SERVICE_PORTS_FILE.read_text(encoding="utf-8"))
        return {k: int(v) for k, v in data.items() if isinstance(v, int) and 0 <= v < PORT_SLOTS}
    except (OSError, ValueError):
        return {}


def service_slots() -> dict:
    """{"<ws>/<svc>": slot} for every web service that has a port."""
    return _read_slots()


def assign_slots(ws: str, services: list[str]) -> dict:
    """Give each of the workspace's web services a stable slot (kept across restarts; the lowest
    free one for a new service) and release the slots of its services that are gone."""
    with file_lock(SERVICE_PORTS_FILE.with_suffix(".lock")):
        slots = _read_slots()
        slots = {k: v for k, v in slots.items() if k.split("/")[0] != ws or k.split("/", 1)[1] in services}
        used = set(slots.values())
        for svc in services:
            key = f"{ws}/{svc}"
            if key not in slots:
                free = next((i for i in range(PORT_SLOTS) if i not in used), None)
                if free is None:
                    raise RuntimeError(f"all {PORT_SLOTS} service ports are in use")
                slots[key] = free
                used.add(free)
        SERVICE_PORTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = SERVICE_PORTS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(dict(sorted(slots.items())), indent=2) + "\n", encoding="utf-8", newline="\n")
        os.replace(tmp, SERVICE_PORTS_FILE)
        return {k: v for k, v in slots.items() if k.split("/")[0] == ws}


def release_slots(ws: str):
    """Free every slot of a workspace (its routes were pruned), and drop its address policies."""
    assign_slots(ws, [])
    release_stream_slots(ws)
    set_net_policies(ws, {})
    set_no_log(ws, {})


def _read_stream_registry() -> dict:
    try:
        data = json.loads(STREAM_PORTS_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {}
        out = {}
        for k, v in data.items():
            if isinstance(v, dict) and "host_port" in v and "container_port" in v:
                out[k] = v
        return out
    except (OSError, ValueError):
        return {}


def stream_ports() -> dict:
    """{"<ws>/<svc>": {"host_port": int, "container_port": int, "slot": int | None, "scope": str, "log": str}}"""
    return _read_stream_registry()


def stream_slots() -> dict:
    """{"<ws>/<svc>": host_port} for every raw TCP stream service."""
    return {k: v["host_port"] for k, v in _read_stream_registry().items()}


def assign_stream_slots(ws: str, services: dict[str, dict]) -> dict:
    """Give each raw TCP service of this workspace a stable slot (default 22000+n) or reserve
    an explicit host port, releasing slots/ports for services that are gone."""
    with file_lock(STREAM_PORTS_FILE.with_suffix(".lock")):
        reg = _read_stream_registry()
        reg = {k: v for k, v in reg.items() if k.split("/")[0] != ws or k.split("/", 1)[1] in services}
        used_slots = {v["slot"] for v in reg.values() if v.get("slot") is not None}
        used_ports = {v["host_port"]: k for k, v in reg.items() if v.get("host_port") is not None}

        for svc, meta in services.items():
            key = f"{ws}/{svc}"
            req_port = meta.get("host_port")
            c_port = meta["container_port"]
            scope = meta.get("scope", "private")
            log = meta.get("log", "on")

            if req_port is not None:
                if req_port in used_ports and used_ports[req_port] != key:
                    raise RuntimeError(f"stream port {req_port} is already reserved by {used_ports[req_port]}")
                reg[key] = {
                    "host_port": req_port,
                    "container_port": c_port,
                    "slot": None,
                    "scope": scope,
                    "log": log,
                }
                used_ports[req_port] = key
            else:
                if key in reg and reg[key].get("slot") is not None:
                    slot = reg[key]["slot"]
                    reg[key] = {
                        "host_port": STREAM_PORT_BASE + slot,
                        "container_port": c_port,
                        "slot": slot,
                        "scope": scope,
                        "log": log,
                    }
                else:
                    free = next((i for i in range(STREAM_PORT_SLOTS) if i not in used_slots), None)
                    if free is None:
                        raise RuntimeError(f"all {STREAM_PORT_SLOTS} stream ports are in use")
                    slot = free
                    hp = STREAM_PORT_BASE + slot
                    if hp in used_ports and used_ports[hp] != key:
                        raise RuntimeError(f"default stream port {hp} clashes with explicit reservation by {used_ports[hp]}")
                    reg[key] = {
                        "host_port": hp,
                        "container_port": c_port,
                        "slot": slot,
                        "scope": scope,
                        "log": log,
                    }
                    used_slots.add(slot)
                    used_ports[hp] = key

        STREAM_PORTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = STREAM_PORTS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(dict(sorted(reg.items())), indent=2) + "\n", encoding="utf-8", newline="\n")
        os.replace(tmp, STREAM_PORTS_FILE)
        return {k: v for k, v in reg.items() if k.split("/")[0] == ws}


def release_stream_slots(ws: str):
    """Free every stream slot/port of a workspace (its routes were pruned)."""
    assign_stream_slots(ws, {})


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _replace_ws_entries(path: Path, ws: str, entries: dict):
    """Replace the "<ws>/<svc>" entries of one workspace in a JSON state file, keeping the others'."""
    with file_lock(path.with_suffix(".lock")):
        data = {k: v for k, v in _read_json(path).items() if k.split("/")[0] != ws}
        data.update({f"{ws}/{svc}": v for svc, v in entries.items()})
        if not data and not path.exists():
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(dict(sorted(data.items())), indent=2) + "\n", encoding="utf-8", newline="\n")
        os.replace(tmp, path)


def net_policies() -> dict:
    """{"<ws>/<svc>": {"ports": [...], "allow": [...] | None, "deny": [...]}} for services with om.net.*."""
    return {k: v for k, v in _read_json(NET_POLICY_FILE).items() if isinstance(v, dict) and v.get("ports")}


def set_net_policies(ws: str, policies: dict):
    """Replace one workspace's address policies ({svc: policy}), keeping every other workspace's."""
    _replace_ws_entries(NET_POLICY_FILE, ws, policies)


def no_log_ports() -> list[int]:
    """Own ports of every service with om.log=off."""
    return sorted({p for v in _read_json(NO_LOG_FILE).values() if isinstance(v, list) for p in v if isinstance(p, int)})


def set_no_log(ws: str, services: dict):
    """Replace one workspace's om.log=off services ({svc: [ports]})."""
    _replace_ws_entries(NO_LOG_FILE, ws, services)


def egress_networks(ws: str) -> list[str] | None:
    """Networks of the workspace that om_egress belongs on; None if unknown yet (then: all of them)."""
    v = _read_json(EGRESS_NETS_FILE).get(ws)
    return list(v) if isinstance(v, list) else None


def set_egress_networks(ws: str, nets: list[str] | None):
    with file_lock(EGRESS_NETS_FILE.with_suffix(".lock")):
        data = _read_json(EGRESS_NETS_FILE)
        if nets is None:
            data.pop(ws, None)
        else:
            data[ws] = sorted(set(nets))
        EGRESS_NETS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = EGRESS_NETS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(dict(sorted(data.items())), indent=2) + "\n", encoding="utf-8", newline="\n")
        os.replace(tmp, EGRESS_NETS_FILE)


def read_registry() -> dict:
    try:
        return json.loads(REGISTRY_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def update_registry(mutate):
    """Apply mutate(registry_dict) under the registry lock and write atomically."""
    with file_lock(STATE_DIR / "workspaces.lock"):
        reg = read_registry()
        mutate(reg)
        REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = REGISTRY_FILE.with_name("workspaces.json.tmp")
        tmp.write_text(json.dumps(reg, indent=2), encoding="utf-8", newline="\n")
        os.replace(tmp, REGISTRY_FILE)
