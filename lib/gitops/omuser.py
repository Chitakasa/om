#!/usr/bin/env python3
"""Run om as its own OS user (GOALS: "runs on your daily computer, isolated in its own user").

After `om user setup --apply`, the containers, images, volumes and om's state belong to the
system user `om` (home /var/lib/om, program in /opt/om, rootless Podman with lingering). You keep
typing `om …`: with OM_RUN_AS=om your process re-runs the command as `sudo -u om` and stays
behind as the *signing broker* — the om process never reads your owner key; when it needs an
access version signed it drops the file in a shared directory and your process signs it with
`ssh-keygen -Y sign` (a hardware key's touch then happens in your terminal).

Linux only. Every host change is a printed sudo step; the default is a dry run.
"""

import getpass
import json
import os
import pwd
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from gitops.core import CONFIG_DIR, OM_HOME, STATE_DIR, load_settings, read_registry

OM_USER = "om"
OM_USER_HOME = Path("/var/lib/om")
PROGRAM_DIR = Path("/opt/om")
SUBID_SIZE = 65536


def run_as(settings: dict | None = None) -> str:
    s = settings if settings is not None else load_settings()
    return (s.get("OM_RUN_AS", "") or "").strip()


def user_exists(name: str = OM_USER) -> bool:
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def _free_subid_start() -> int:
    """First 65536-aligned range above everything in /etc/subuid and /etc/subgid."""
    top = 100000
    for f in ("/etc/subuid", "/etc/subgid"):
        try:
            for line in Path(f).read_text(encoding="utf-8").splitlines():
                parts = line.split(":")
                if len(parts) == 3 and parts[1].isdigit() and parts[2].isdigit():
                    top = max(top, int(parts[1]) + int(parts[2]))
        except OSError:
            pass
    return ((top + SUBID_SIZE - 1) // SUBID_SIZE) * SUBID_SIZE


def _parents(path: Path, stop: Path) -> list[Path]:
    """Directories from `stop` down to path's parent: each needs traverse (x) for om."""
    out, p = [], path.parent
    while p != stop.parent and p != p.parent:
        out.append(p)
        if p == stop:
            break
        p = p.parent
    return list(reversed(out))


def plan(mounts: dict) -> list[tuple[str, list[str]]]:
    """(why, sudo argv) steps. mounts = {"workspaces": [...], "media": [...], "write": [...]}:
    workspaces get a recursive read ACL; media (read-only mounts outside workspaces) only the
    traverse right on their parents — their files are normally world-readable, and om never
    rewrites metadata across a media library; data written by services becomes om's."""
    me = getpass.getuser()
    home = Path.home()
    start = _free_subid_start()
    om_state = OM_USER_HOME / ".local/state/om"
    om_config = OM_USER_HOME / ".config/om"
    steps = [
        ("create the system user om (no login shell)",
         ["useradd", "--system", "--create-home", "--home-dir", str(OM_USER_HOME), "--shell", "/usr/bin/nologin", OM_USER]),
        (f"give om its own user-namespace IDs ({start}–{start + SUBID_SIZE - 1}) for rootless Podman",
         ["usermod", "--add-subuids", f"{start}-{start + SUBID_SIZE - 1}", "--add-subgids", f"{start}-{start + SUBID_SIZE - 1}", OM_USER]),
        ("keep om's containers running without a login session", ["loginctl", "enable-linger", OM_USER]),
        ("install the om program read-only for om (it cannot change its own code)",
         ["rsync", "-a", "--delete", "--exclude", ".git", f"{OM_HOME}/", f"{PROGRAM_DIR}/"]),
        ("", ["chown", "-R", "root:root", str(PROGRAM_DIR)]),
        ("copy om's state (access chain, generations, keys, CA, gate data) to om",
         ["rsync", "-a", f"{STATE_DIR}/", f"{om_state}/"]),
        ("copy your settings to om", ["install", "-D", "-m600", str(CONFIG_DIR / "om.env"), str(om_config / "om.env")]),
        ("", ["chown", "-R", f"{OM_USER}:{OM_USER}", str(OM_USER_HOME)]),
        ("your user may read om's state (access chain, logs) for `om access`, `om log`",
         ["setfacl", "-R", "-m", f"u:{me}:rX", "-m", f"d:u:{me}:rX", str(om_state)]),
    ]
    workspaces = sorted(set(mounts.get("workspaces", [])))
    covered = lambda p: any(Path(p).is_relative_to(w) for w in workspaces)  # noqa: E731
    traverse = set()
    for p in workspaces + mounts.get("media", []) + mounts.get("write", []):
        if Path(p).is_relative_to(home):
            traverse.update(t for t in _parents(Path(p), home) if not covered(t))
    if traverse:
        steps.append(("om may pass through (not list) the folders above your workspaces and media",
                      ["setfacl", "-m", f"u:{OM_USER}:x", *sorted(str(t) for t in traverse)]))
    for w in workspaces:
        steps.append((f"om may read the workspace {w} (code, compose files, git history)",
                      ["setfacl", "-R", "-m", f"u:{OM_USER}:rX", "-m", f"d:u:{OM_USER}:rX", w]))
    for p in sorted(set(mounts.get("write", []))):
        steps.append((f"service data in {p} now belongs to om; you keep read/write by ACL", ["chown", "-R", f"{OM_USER}:{OM_USER}", p]))
        steps.append(("", ["setfacl", "-R", "-m", f"u:{me}:rwX", "-m", f"d:u:{me}:rwX", p]))
    for ws in sorted({str(Path(d["path"])) for d in read_registry().values() if d.get("path")}):
        steps.append((f"git may use {ws} as om (owned by you)",
                      ["-u", OM_USER, "git", "config", "--global", "--add", "safe.directory", ws]))
    return steps


def media_notes(mounts: dict) -> list[str]:
    """Read-only media mounts om can't promise to read after the move."""
    out = []
    for p in sorted(set(mounts.get("media", []))):
        if p.startswith(("/run/media", "/media")):
            out.append(f"{p}: drives mounted by your desktop are readable only by you; jellyfin won't see them as om "
                       "(mount them under /mnt with group/world read, or add a udisks rule)")
        elif Path(p).exists() and not (Path(p).stat().st_mode & 0o004):
            out.append(f"{p}: not world-readable; om (and the service) won't see it — chmod o+rX, or setfacl -R -m u:om:rX yourself")
    return out


def set_run_as(value: str):
    """OM_RUN_AS in your own om.env (no sudo)."""
    from gitops.core import set_setting
    set_setting("OM_RUN_AS", value)


def status() -> list[str]:
    out = []
    out.append(f"user om: {'exists' if user_exists() else 'not created'}")
    if user_exists():
        r = subprocess.run(["loginctl", "show-user", OM_USER, "-p", "Linger"], capture_output=True, text=True, encoding="utf-8")
        out.append(f"lingering: {r.stdout.strip().split('=')[-1] or 'no'}")
        out.append(f"program: {'installed in ' + str(PROGRAM_DIR) if (PROGRAM_DIR / 'bin' / 'om').exists() else 'not installed'}")
    out.append(f"your om commands run as: {run_as() or getpass.getuser() + ' (yourself)'}")
    return out


# ── Delegation and the signing broker ───────────────────────────────────────

SIGN_DIR_ENV = "OM_SIGN_DIR"


def delegate(argv: list[str]) -> int:
    """Re-run `om argv` as the om user; sign access versions it asks for, as you."""
    owner_key = os.path.expanduser(load_settings().get("OM_OWNER_KEY", "~/.ssh/id_ed25519"))
    box = Path(tempfile.mkdtemp(prefix="om-sign-"))
    subprocess.run(["setfacl", "-m", f"u:{OM_USER}:rwx", str(box)], check=False)
    done = threading.Event()

    def broker():
        while not done.is_set():
            for req in box.glob("*.json"):
                sig = Path(str(req) + ".sig")
                if sig.exists() or (box / (req.name + ".refused")).exists():
                    continue
                print(f"\n  om asks you to sign access change: {json.loads(req.read_text(encoding='utf-8')).get('change', '?')}")
                r = subprocess.run(["ssh-keygen", "-Y", "sign", "-q", "-f", owner_key, "-n", "om-access", str(req)])
                if r.returncode != 0:
                    (box / (req.name + ".refused")).write_text("", encoding="utf-8")
                else:
                    subprocess.run(["setfacl", "-m", f"u:{OM_USER}:r", str(sig)], check=False)
            time.sleep(0.2)

    t = threading.Thread(target=broker, daemon=True)
    t.start()
    try:
        cmd = ["sudo", "-u", OM_USER, f"--preserve-env={SIGN_DIR_ENV}", "--", "env",
               f"XDG_RUNTIME_DIR=/run/user/{pwd.getpwnam(OM_USER).pw_uid}", f"HOME={OM_USER_HOME}", f"OM_HOME={PROGRAM_DIR}",
               f"{SIGN_DIR_ENV}={box}", str(PROGRAM_DIR / "bin" / "om"), *argv]
        return subprocess.run(cmd).returncode
    finally:
        done.set()
        t.join(timeout=1)
        shutil.rmtree(box, ignore_errors=True)


def sign_via_broker(path: Path, timeout: float = 300) -> bool:
    """Inside the om process: ask the console user's broker to sign `path` (same dir, .sig)."""
    box = Path(os.environ[SIGN_DIR_ENV])
    req = box / path.name
    shutil.copy2(path, req)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        sig = Path(str(req) + ".sig")
        if sig.exists() and sig.stat().st_size:
            shutil.copy2(sig, str(path) + ".sig")
            return True
        if (box / (req.name + ".refused")).exists():
            return False
        time.sleep(0.2)
    return False
