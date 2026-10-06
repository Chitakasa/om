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


def check_service(name: str, svc: dict, home: str | None = None) -> list[str]:
    """Return human-readable violations for one normalized compose service."""
    home = home or str(Path.home())
    out = []
    if svc.get("privileged"):
        out.append(f"{name}: privileged: true — remove it")
    for key in HOST_NAMESPACES:
        v = str(svc.get(key, "") or "")
        if v == "host" or (key == "network_mode" and v.startswith("container:")):
            out.append(f"{name}: {key}: {v} — joins a host/other namespace; remove it")
    if svc.get("ports"):
        out.append(f"{name}: ports: publishes host ports — use `expose:`; the edge routes to it")
    caps = {str(c).upper().removeprefix("CAP_") for c in (svc.get("cap_add") or [])} - DEFAULT_CAPS
    if caps:
        out.append(f"{name}: cap_add: {', '.join(sorted(caps))} — beyond the engine's default capability set")
    if svc.get("devices"):
        out.append(f"{name}: devices: host devices are not allowed")
    for opt in svc.get("security_opt") or []:
        if str(opt).replace(" ", "") in UNCONFINED:
            out.append(f"{name}: security_opt: {opt} — removes a kernel confinement layer")
    for vol in svc.get("volumes") or []:
        src = vol.get("source", "") if isinstance(vol, dict) else str(vol).split(":", 1)[0]
        vtype = vol.get("type", "bind") if isinstance(vol, dict) else "bind"
        if vtype == "bind" and _sensitive_source(src, home):
            out.append(f"{name}: volume {src} — engine socket or sensitive host path; mount a narrower folder")
    return out


def check_config(cfg: dict, home: str | None = None) -> list[str]:
    out = []
    for name, svc in sorted((cfg.get("services") or {}).items()):
        out += check_service(name, svc or {}, home)
    return out


def check_compose_file(runtime: str, compose_file: Path, env: dict) -> list[str]:
    """Violations of one compose file, read through the engine's own `compose config`."""
    r = run([runtime, "compose", "-f", str(compose_file), "config", "--format", "json"],
            cwd=compose_file.parent, env=env)
    if r.returncode != 0:
        return [f"{compose_file}: `compose config` failed: {(r.stderr or r.stdout).strip()[-300:]}"]
    try:
        return check_config(json.loads(r.stdout))
    except json.JSONDecodeError:
        return [f"{compose_file}: `compose config` did not return JSON"]
