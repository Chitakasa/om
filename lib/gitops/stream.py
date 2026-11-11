#!/usr/bin/env python3
"""Raw TCP stream tier logic for 'om': label parsing, port validation, HAProxy config generation,
and stream slot registry."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from gitops import core

# Labels for raw TCP services
LABEL_TCP = "om.tcp"
LABEL_TCP_PORT = "om.tcp.port"

# Ports and port ranges reserved by om core or system
RESERVED_EXACT_PORTS = {80, 443, 8080, 8443}
HTTP_PORT_START = 20000
HTTP_PORT_END = 21199  # Covers 20000-20199 (private) and 21000-21199 (public)
STREAM_DEFAULT_START = 22000
STREAM_DEFAULT_END = 22199  # 200 default stream slots: 22000-22199

# HAProxy pinned image digest
HAPROXY_IMAGE = "docker.io/library/haproxy:3.0-alpine@sha256:35114f41284747c8b460babd0c082d5d8e0268218b167240f47d15d0474b718b"


def validate_host_port(port: int, edge_http: int = 80, edge_https: int = 443) -> list[str]:
    """Validate an explicit host port. Returns list of problem strings (empty = valid)."""
    problems = []
    if port < 1024:
        problems.append(f"host port {port} is privileged (must be >= 1024)")
    if port > 65535:
        problems.append(f"host port {port} is invalid (must be <= 65535)")
    reserved = RESERVED_EXACT_PORTS | {edge_http, edge_https}
    if port in reserved:
        problems.append(f"host port {port} clashes with core HTTP/HTTPS ports ({', '.join(sorted(map(str, reserved)))})")
    if HTTP_PORT_START <= port <= HTTP_PORT_END:
        problems.append(f"host port {port} clashes with HTTP per-service port range ({HTTP_PORT_START}-{HTTP_PORT_END})")
    if STREAM_DEFAULT_START <= port <= STREAM_DEFAULT_END:
        problems.append(f"host port {port} clashes with default stream port range ({STREAM_DEFAULT_START}-{STREAM_DEFAULT_END})")
    return problems


def parse_stream_meta(labels: dict[str, str], sname: str = "",
                      edge_http: int = 80, edge_https: int = 443) -> tuple[dict[str, Any] | None, list[str]]:
    """Extract stream routing configuration from compose labels:
        om.tcp=<container-port>
        om.tcp.port=<host-port>  (optional)
        dashboard.scope=public   (optional; default private)
        om.log=off               (optional; default on)

    Returns (config, problems). Fail closed: invalid or unreadable label returns (None, problems).
    When om.tcp is not set at all, returns (None, []).
    """
    raw_tcp = labels.get(LABEL_TCP)
    if raw_tcp is None or not str(raw_tcp).strip():
        return None, []

    problems: list[str] = []
    str_val = str(raw_tcp).strip().strip('"').strip("'")
    
    # Check container port
    if not str_val.isdigit():
        problems.append(f"{sname}: {LABEL_TCP} must be an integer port number (got '{raw_tcp}')")
        return None, problems

    container_port = int(str_val)
    if container_port < 1 or container_port > 65535:
        problems.append(f"{sname}: {LABEL_TCP} port {container_port} out of range (1-65535)")
        return None, problems

    # Check optional explicit host port
    host_port: int | None = None
    raw_host_port = labels.get(LABEL_TCP_PORT)
    if raw_host_port is not None and str(raw_host_port).strip():
        str_hp = str(raw_host_port).strip().strip('"').strip("'")
        if not str_hp.isdigit():
            problems.append(f"{sname}: {LABEL_TCP_PORT} must be an integer port number (got '{raw_host_port}')")
            return None, problems
        host_port = int(str_hp)
        port_probs = validate_host_port(host_port, edge_http, edge_https)
        if port_probs:
            for p in port_probs:
                problems.append(f"{sname}: {p}")
            return None, problems

    scope = "public" if labels.get("dashboard.scope", "").strip().lower() == "public" else "private"
    log = "off" if labels.get("om.log", "").strip().lower() == "off" else "on"

    return {
        "container_port": container_port,
        "host_port": host_port,
        "scope": scope,
        "log": log,
    }, []
