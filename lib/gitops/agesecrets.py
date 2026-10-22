#!/usr/bin/env python3
"""Service secrets with age (GOALS G2): encrypted in the workspace repo, decrypted only at start.

A secret is one file `<project>/secrets/<name>.age`, encrypted (by the `age` tool, in the
om-tools image — om writes no cryptography) to the recipients in `.om/age-recipients`: the
host key (kept in $OM_STATE_DIR/data/age.key, never in a repo) and the owner's SSH key, so the
owner can always decrypt their own secrets. A service uses it through compose's own secrets:

    services:
      app:
        secrets: [db_password]          # → /run/secrets/db_password, read-only
    secrets:
      db_password:
        file: ./secrets/db_password     # om decrypts ./secrets/db_password.age for it

At start om decrypts into $XDG_RUNTIME_DIR (memory, 0700) and points the secret there with a
compose override. Secrets never become environment variables or labels.
"""

import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path

from gitops.core import CORE_DIR, DATA_DIR, run, write_private_bytes

KEY_FILE = DATA_DIR / "age.key"
RECIPIENTS_NAME = ".om/age-recipients"
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def image() -> str:
    h = hashlib.sha256()
    src = CORE_DIR / "tools"
    for f in sorted(src.iterdir()) if src.is_dir() else []:
        if f.is_file():
            h.update(f.name.encode() + b"\0" + f.read_bytes())
    return f"localhost/om-tools:{h.hexdigest()[:12]}"


def ensure_image(runtime: str) -> bool:
    if run([runtime, "image", "inspect", image()]).returncode == 0:
        return True
    return run([runtime, "build", "-q", "-t", image(), "-f", str(CORE_DIR / "tools" / "Containerfile"), str(CORE_DIR / "tools")]).returncode == 0


def _age(runtime: str, args: list[str], stdin: bytes | None = None, mounts: list[tuple[Path, str]] = ()) -> tuple[int, bytes, str]:
    import subprocess
    cmd = [runtime, "run", "--rm", "-i", "--network", "none", "--read-only", "--cap-drop", "ALL"]
    for host, inside in mounts:
        cmd += ["-v", f"{host}:{inside}:ro"]
    cmd += [image(), *args]
    try:
        r = subprocess.run(cmd, input=stdin, capture_output=True)
        return r.returncode, r.stdout, r.stderr.decode("utf-8", "replace")
    except OSError as e:
        return 1, b"", str(e)


def host_recipient(runtime: str) -> str:
    """Create the host key once; return its public age recipient."""
    if not ensure_image(runtime):
        raise RuntimeError("could not build the om-tools image (core/tools)")
    if not KEY_FILE.exists():
        code, out, err = _age(runtime, ["age-keygen"])
        if code != 0:
            raise RuntimeError(f"age-keygen failed: {err.strip()[-200:]}")
        write_private_bytes(KEY_FILE, out)
    m = re.search(rb"public key: (age1[0-9a-z]+)", KEY_FILE.read_bytes())
    if not m:
        raise RuntimeError(f"{KEY_FILE} has no public key line")
    return m.group(1).decode()


def recipients(root: Path) -> list[str]:
    try:
        lines = (root / RECIPIENTS_NAME).read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    return [l.strip() for l in lines if l.strip() and not l.startswith("#")]


def write_recipients(root: Path, host: str, owner_ssh: str) -> bool:
    """Add this host (and the owner's SSH key) to the recipients, keeping every machine already
    listed. Returns True when something was added (secrets then need `om secrets rekey`)."""
    have = recipients(root)
    add = [r for r in [host, " ".join(owner_ssh.split()[:2]) if owner_ssh else ""] if r and r not in have]
    if not add and have:
        return False
    body = ["# Who can decrypt this workspace's secrets (age): each machine running it, and the owner's SSH key."]
    (root / RECIPIENTS_NAME).write_text("\n".join(body + have + add) + "\n", encoding="utf-8", newline="\n")
    return bool(have)


def encrypt(runtime: str, root: Path, plaintext: bytes) -> bytes:
    rcpts = recipients(root)
    if not rcpts:
        raise RuntimeError(f"no {RECIPIENTS_NAME} (om secrets init)")
    args = ["age", "--encrypt", "--armor"]
    for r in rcpts:
        args += ["-r", r]
    code, out, err = _age(runtime, args, stdin=plaintext)
    if code != 0:
        raise RuntimeError(f"age failed: {err.strip()[-200:]}")
    return out


def decrypt(runtime: str, path: Path, ssh_key: Path | None = None) -> bytes:
    """With this host's key; with ssh_key also the owner's SSH key (`om secrets rekey`)."""
    tries = [KEY_FILE] + ([ssh_key] if ssh_key and ssh_key.is_file() else [])
    err = ""
    for key in tries:
        if not key.is_file():
            continue
        code, out, err = _age(runtime, ["age", "--decrypt", "-i", "/key", "/in"], mounts=[(key, "/key"), (path, "/in")])
        if code == 0:
            return out
    raise RuntimeError(f"cannot decrypt {path.name}: this machine is not a recipient yet — run `om secrets init` here and commit,"
                       f" then `om secrets rekey` on a machine that can decrypt ({err.strip()[-120:]})")

def rekey(runtime: str, root: Path, ssh_key: Path | None) -> list[str]:
    """Re-encrypt every secret of the workspace to the current recipients. Returns the files."""
    done = []
    for f in sorted(root.rglob("secrets/*.age")):
        if ".om" in f.relative_to(root).parts:
            continue
        f.write_bytes(encrypt(runtime, root, decrypt(runtime, f, ssh_key)))
        done.append(str(f.relative_to(root)))
    return done


def runtime_dir(ws: str, project: str) -> Path:
    base = Path(os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()) / "om-secrets"
    d = base / ws / hashlib.sha256(project.encode()).hexdigest()[:12]
    d.mkdir(parents=True, exist_ok=True)
    for p in (base, base / ws, d):
        os.chmod(p, 0o700)
    return d


def write_override(runtime: str, ws: str, project_dir: Path, cfg: dict | None, override_dir: Path):
    """Decrypt this project's secrets and return a compose override pointing at them (or None).
    A declared secret whose `<file>.age` is missing stays as compose has it."""
    out, lines = runtime_dir(ws, str(project_dir)), []
    for name, spec in sorted(((cfg or {}).get("secrets") or {}).items()):
        src = Path((spec or {}).get("file", ""))
        enc = Path(str(src) + ".age")
        if not NAME_RE.match(name) or not enc.is_file():
            continue
        target = out / name
        target.write_bytes(decrypt(runtime, enc))
        os.chmod(target, 0o600)
        lines += [f"  {json.dumps(name)}:", f"    file: {json.dumps(target.as_posix())}"]
    path = override_dir / f"{ws}-{hashlib.sha256(str(project_dir).encode()).hexdigest()[:12]}.yml"
    if not lines:
        path.unlink(missing_ok=True)
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# Generated by om — decrypted secrets live in memory only. Do not edit.\nsecrets:\n" + "\n".join(lines) + "\n",
                    encoding="utf-8", newline="\n")
    return path


def wipe(ws: str):
    base = Path(os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()) / "om-secrets" / ws
    shutil.rmtree(base, ignore_errors=True)
