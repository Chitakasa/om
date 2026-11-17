#!/usr/bin/env python3
"""Deploy-time policy gate: refuse compose services that could escape their sandbox.

Checks run on the normalized output of `compose config --format json`, so they see what
the engine will actually run (env vars expanded, short syntax resolved). OM_POLICY in
om.env picks the mode: `enforce` (default; refuse) or `warn` (report and continue).
"""

import json
import posixpath
import re
from pathlib import Path

from gitops.core import load_settings, run
from gitops import egress

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
    m = (settings if settings is not None else load_settings()).get("OM_POLICY", "enforce").lower()
    return "warn" if m == "warn" else "enforce"  # fail closed: anything but `warn` enforces


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
WAIVABLE = ("host-namespace", "caps", "devices", "unconfined", "mounts", "networks", "egress", "egress-caps")
LAWS = ("privileged", "ports")


def _labels(svc: dict) -> dict:
    labels = svc.get("labels") or {}
    if isinstance(labels, list):
        labels = dict(l.split("=", 1) if "=" in l else (l, "") for l in labels)
    return labels


def _writes(svc: dict) -> bool:
    """Any bind or named volume not mounted read-only means the service can change data."""
    for vol in svc.get("volumes") or []:
        if isinstance(vol, dict):
            if vol.get("type", "volume") in ("bind", "volume") and not vol.get("read_only"):
                return True
        elif not str(vol).endswith(":ro") and ":ro," not in str(vol):
            return True
    return False


def _egress_findings(name: str, svc: dict) -> list[tuple[str, str]]:
    raw = _labels(svc).get("om.egress")
    if raw is None or not str(raw).strip():
        return []
    items = [v.strip().lower() for v in str(raw).split(",") if v.strip()]
    if egress.LEARN in items and len(items) > 1:
        return [("egress", f"{name}: om.egress: `learn` cannot be combined with hosts")]
    bad = [h for h in items if h not in (egress.INTERNET, egress.LEARN) and not egress.valid_host(h)]
    out = [("egress", f"{name}: om.egress: `{h}` is not a hostname (use api.example.com or *.example.com)") for h in bad]

    # Anti-spoofing checks: prevent source-IP spoofing on egress
    cap_drop = {str(c).upper().removeprefix("CAP_") for c in (svc.get("cap_drop") or [])}
    cap_add = {str(c).upper().removeprefix("CAP_") for c in (svc.get("cap_add") or [])}
    if "NET_RAW" in cap_add or "NET_ADMIN" in cap_add:
        out.append(("egress-caps", f"{name}: om.egress refuses cap_add with NET_RAW or NET_ADMIN (prevents source-IP spoofing)"))
    elif "ALL" not in cap_drop and "NET_RAW" not in cap_drop:
        out.append(("egress-caps", f"{name}: om.egress requires cap_drop: [NET_RAW] (or cap_drop: [ALL]) to prevent source-IP spoofing"))

    if egress.INTERNET in items:
        if len(items) > 1:
            out.append(("egress", f"{name}: om.egress: `internet` cannot be combined with hosts"))
        if _writes(svc):
            out.append(("egress", f"{name}: om.egress=internet but it can write data (a volume without :ro) — list the hosts it needs instead"))
        if svc.get("secrets"):
            out.append(("egress", f"{name}: om.egress=internet but it receives secrets — list the hosts it needs instead"))
    elif egress.LEARN in items:
        if _writes(svc):
            out.append(("egress", f"{name}: om.egress=learn but it can write data (a volume without :ro) — list the hosts it needs instead"))
        if svc.get("secrets"):
            out.append(("egress", f"{name}: om.egress=learn but it receives secrets — list the hosts it needs instead"))
    return out


def _findings(name: str, svc: dict, home: str) -> list[tuple[str, str]]:
    out = _egress_findings(name, svc)
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
    raw = str(_labels(svc).get(ALLOW_LABEL, "") or "")
    allowed, bad = set(), []
    for rule in filter(None, (r.strip().lower() for r in raw.split(","))):
        if rule in WAIVABLE:
            allowed.add(rule)
        elif rule in LAWS:
            bad.append(f"{name}: {ALLOW_LABEL}={rule} — `{rule}` is a law and cannot be waived")
        else:
            bad.append(f"{name}: {ALLOW_LABEL}={rule} — unknown rule (one of: {', '.join(WAIVABLE)})")
    return allowed, bad


def _network_findings(name: str, svc: dict, cfg: dict, ws_net: str | None) -> list[tuple[str, str]]:
    """Joining another stack's network (external, not the workspace's) would bridge this folder's own
    isolated network to it; om.link is the way to reach one other service."""
    if not ws_net:
        return []
    nets = (cfg or {}).get("networks") or {}
    out = []
    for key in (svc.get("networks") or {}):
        n = nets.get(key) or {}
        if n.get("external") and n.get("name") not in (ws_net, None):
            out.append(("networks", f"{name}: joins network {n['name']} of another stack — every folder gets its own;"
                                    " reach another service with om.link"))
    return out

def evaluate_service(name: str, svc: dict, home: str | None = None, extra=()) -> tuple[list[str], list[str]]:
    """(violations, waived findings) for one normalized compose service."""
    allowed, bad = _allowed(name, svc)
    found = _findings(name, svc, home or str(Path.home())) + list(extra)
    return bad + [m for k, m in found if k not in allowed], [m for k, m in found if k in allowed]


def check_service(name: str, svc: dict, home: str | None = None) -> list[str]:
    """Return human-readable violations for one normalized compose service."""
    return evaluate_service(name, svc, home)[0]


def evaluate_config(cfg: dict, home: str | None = None, ws_net: str | None = None) -> tuple[list[str], list[str]]:
    violations, waived = secret_findings(cfg), []
    for name, svc in sorted((cfg.get("services") or {}).items()):
        v, w = evaluate_service(name, svc or {}, home, _network_findings(name, svc or {}, cfg, ws_net))
        violations += v
        waived += w
    return violations, waived


def secret_findings(cfg: dict) -> list[str]:
    """No secrets in configuration: a declared secret must not exist as plaintext next to the compose file."""
    out = []
    for name, spec in sorted(((cfg or {}).get("secrets") or {}).items()):
        f = Path((spec or {}).get("file", "") or "")
        if str(f) and f.is_file():
            out.append(f"secret {name}: {f.name} is plaintext in the workspace — `om secrets set <project>/{name}`, then delete it")
    return out


def check_config(cfg: dict, home: str | None = None) -> list[str]:
    return evaluate_config(cfg, home)[0]


def compose_config(runtime: str, compose_file: Path, env: dict) -> tuple[dict | None, str]:
    """(normalized config, error) from the engine's own `compose config`."""
    r = run([runtime, "compose", "-f", str(compose_file), "config", "--format", "json"],
            cwd=compose_file.parent, env=env)
    if r.returncode != 0:
        return None, f"{compose_file}: `compose config` failed: {(r.stderr or r.stdout).strip()[-300:]}"
    try:
        return json.loads(r.stdout), ""
    except json.JSONDecodeError:
        return None, f"{compose_file}: `compose config` did not return JSON"


def evaluate_compose(cfg: dict | None, error: str, ws_net: str | None = None) -> tuple[list[str], list[str]]:
    return ([error], []) if cfg is None else evaluate_config(cfg, ws_net=ws_net)


def check_compose_file(runtime: str, compose_file: Path, env: dict) -> tuple[list[str], list[str]]:
    """(violations, waived findings) of one compose file."""
    return evaluate_compose(*compose_config(runtime, compose_file, env), ws_net=env.get("WORKSPACE_NET"))


def egress_services(cfg: dict | None) -> dict:
    """{svc: [hosts] | INTERNET} for services with a usable om.egress label."""
    out = {}
    for name, svc in ((cfg or {}).get("services") or {}).items():
        hosts = egress.parse_label(_labels(svc or {}).get("om.egress"))
        if hosts:
            out[name] = hosts
    return out
