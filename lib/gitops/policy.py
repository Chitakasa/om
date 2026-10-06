#!/usr/bin/env python3
"""Deploy-time policy gate: refuse compose services that could escape their sandbox.

Checks run on the normalized output of `compose config --format json`, so they see what
the engine will actually run (env vars expanded, short syntax resolved). OM_POLICY in
om.env picks the mode: `warn` (default; report and continue) or `enforce` (refuse).
"""

import json
import posixpath
import re
from pathlib import Path

from gitops.core import load_settings, run

# A service may add back only capabilities the engine grants every container by default
# (useful after `cap_drop: ALL`); anything beyond that set is a privilege escalation.
DEFAULT_CAPS = {"CHOWN", "DAC_OVERRIDE", "FSETID", "FOWNER", "MKNOD", "NET_RAW", "SETGID", "SETUID",
                "SETFCAP", "SETPCAP", "NET_BIND_SERVICE", "SYS_CHROOT", "KILL", "AUDIT_WRITE"}
HOST_NAMESPACES = ("network_mode", "pid", "ipc", "uts", "userns_mode", "cgroup")
UNCONFINED = ("seccomp=unconfined", "seccomp:unconfined", "apparmor=unconfined", "apparmor:unconfined",
              "label=disable", "label:disable", "systempaths=unconfined")
SENSITIVE_PATHS = ("/", "/etc", "/proc", "/sys", "/dev", "/boot", "/root", "/run", "/var/run",
                   "/var/lib/docker", "/var/lib/containers", "/usr", "/bin", "/sbin", "/lib")
# Removable drives mount here; they hold user data, not system state.
USER_MEDIA = ("/run/media", "/media", "/mnt")
SENSITIVE_HOME = ("", ".ssh", ".gnupg", ".config", ".local/share/containers", ".local/state/om", ".om",
                  ".docker", ".kube", ".aws")


def mode(settings: dict | None = None) -> str:
    m = (settings if settings is not None else load_settings()).get("OM_POLICY", "warn").lower()
    return "enforce" if m == "enforce" else "warn"


def _norm(path: str) -> str:
    # Compare as forward-slash, lower-case paths so Windows (C:/Users/..) and
    # case-insensitive macOS volumes match the same rules as Linux.
    return posixpath.normpath(path.replace("\\", "/")).lower()


def _sensitive_source(src: str, home: str) -> bool:
    if not (src.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", src)):
        return False  # named volume
    src, home = _norm(src), _norm(home)
    if src.endswith(".sock"):
        return True
    if any(src == m or src.startswith(m + "/") for m in USER_MEDIA):
        return False
    for r in SENSITIVE_PATHS:
        r = _norm(r)
        # Whole system trees are off limits, including everything below them ("/" itself only exactly).
        if src == r or (r != "/" and src.startswith(r + "/")):
            return True
    for sub in SENSITIVE_HOME:
        r = posixpath.normpath(posixpath.join(home, sub))
        # $HOME itself only exactly; the listed dot-dirs including everything below them.
        if src == r or (sub and src.startswith(r + "/")):
            return True
    return False


# Rules a service may waive for itself with `om.policy.allow=<rule>,…`. The label is part of
# the compose file, so the exception is reviewed (and, from phase 2, signed) like any change,
# and `om policy check` keeps listing it. `privileged` and `ports` are laws: never waivable.
ALLOW_LABEL = "om.policy.allow"
WAIVABLE = ("host-namespace", "caps", "devices", "unconfined", "mounts")
LAWS = ("privileged", "ports")


def _findings(name: str, svc: dict, home: str) -> list[tuple[str, str]]:
    out = []
    if svc.get("privileged"):
        out.append(("privileged", f"{name}: privileged: true — remove it"))
    for key in HOST_NAMESPACES:
        v = str(svc.get(key, "") or "")
        if v == "host" or (key == "network_mode" and v.startswith("container:")):
            out.append(("host-namespace", f"{name}: {key}: {v} — joins a host/other namespace"))
    if svc.get("ports"):
        out.append(("ports", f"{name}: ports: publishes host ports — use `expose:`; the edge routes to it"))
    caps = {str(c).upper().removeprefix("CAP_") for c in (svc.get("cap_add") or [])} - DEFAULT_CAPS
    if caps:
        out.append(("caps", f"{name}: cap_add: {', '.join(sorted(caps))} — beyond the engine's default capability set"))
    if svc.get("devices"):
        out.append(("devices", f"{name}: devices: passes host devices into the container"))
    for opt in svc.get("security_opt") or []:
        if str(opt).replace(" ", "") in UNCONFINED:
            out.append(("unconfined", f"{name}: security_opt: {opt} — removes a kernel confinement layer"))
    for vol in svc.get("volumes") or []:
        src = vol.get("source", "") if isinstance(vol, dict) else str(vol).split(":", 1)[0]
        vtype = vol.get("type", "bind") if isinstance(vol, dict) else "bind"
        if vtype == "bind" and _sensitive_source(src, home):
            out.append(("mounts", f"{name}: volume {src} — engine socket or sensitive host path"))
    return out


def _allowed(name: str, svc: dict) -> tuple[set, list[str]]:
    """Rules waived by the service's label, plus violations for unreadable or non-waivable entries."""
    labels = svc.get("labels") or {}
    if isinstance(labels, list):
        labels = dict(l.split("=", 1) if "=" in l else (l, "") for l in labels)
    raw = str(labels.get(ALLOW_LABEL, "") or "")
    allowed, bad = set(), []
    for rule in filter(None, (r.strip().lower() for r in raw.split(","))):
        if rule in WAIVABLE:
            allowed.add(rule)
        elif rule in LAWS:
            bad.append(f"{name}: {ALLOW_LABEL}={rule} — `{rule}` is a law and cannot be waived")
        else:
            bad.append(f"{name}: {ALLOW_LABEL}={rule} — unknown rule (one of: {', '.join(WAIVABLE)})")
    return allowed, bad


def evaluate_service(name: str, svc: dict, home: str | None = None) -> tuple[list[str], list[str]]:
    """(violations, waived findings) for one normalized compose service."""
    allowed, bad = _allowed(name, svc)
    found = _findings(name, svc, home or str(Path.home()))
    return bad + [m for k, m in found if k not in allowed], [m for k, m in found if k in allowed]


def check_service(name: str, svc: dict, home: str | None = None) -> list[str]:
    """Return human-readable violations for one normalized compose service."""
    return evaluate_service(name, svc, home)[0]


def evaluate_config(cfg: dict, home: str | None = None) -> tuple[list[str], list[str]]:
    violations, waived = [], []
    for name, svc in sorted((cfg.get("services") or {}).items()):
        v, w = evaluate_service(name, svc or {}, home)
        violations += v
        waived += w
    return violations, waived


def check_config(cfg: dict, home: str | None = None) -> list[str]:
    return evaluate_config(cfg, home)[0]


def check_compose_file(runtime: str, compose_file: Path, env: dict) -> tuple[list[str], list[str]]:
    """(violations, waived findings) of one compose file, read through the engine's own `compose config`."""
    r = run([runtime, "compose", "-f", str(compose_file), "config", "--format", "json"],
            cwd=compose_file.parent, env=env)
    if r.returncode != 0:
        return [f"{compose_file}: `compose config` failed: {(r.stderr or r.stdout).strip()[-300:]}"], []
    try:
        return evaluate_config(json.loads(r.stdout))
    except json.JSONDecodeError:
        return [f"{compose_file}: `compose config` did not return JSON"], []
