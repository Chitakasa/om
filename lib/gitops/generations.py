#!/usr/bin/env python3
"""Signed deploys and numbered generations (GOALS G1).

Every `om start` / `om sync` / `om update` / `om rollback` of a workspace is a **generation**:
`$OM_STATE_DIR/generations/<ws>/<n>.json` = {n, kind, commit, dirty, signer, lock, time, result,
prev}, where `prev` is the SHA-256 of the previous entry, so the log is a hash chain that
`om fsck` verifies and any rewrite breaks.

A commit is trusted when `git verify-commit` accepts it against the *trusted* signer list:
the copy om took from the last deployed generation, not the file in the commit being checked
(a hostile commit could otherwise add its own key). The first deploy trusts the workspace's
`.om/allowed_signers` once (trust on first use) and says so. OM_SIGNED=auto|warn|enforce decides
whether an unsigned or untrusted commit is reported or refused.
"""

import hashlib
import json
import re
import shutil
import subprocess
import time
from pathlib import Path

from gitops.omsettings import load_settings
from gitops.omstate import STATE_DIR, file_lock, write_atomic

GEN_DIR = STATE_DIR / "generations"
HEAD_NAME = "head"
HEAD_SIG = "head.sig"
HEAD_NAMESPACE = "om-generations"
SIGNERS_NAME = ".om/allowed_signers"
_GOOD_RE = re.compile(r'Good "git" signature for (\S+) with (\S+) key (\S+)')


def signing_configured() -> bool:
    """Git is set up to sign commits with an SSH key (the only kind om verifies)."""
    def cfg(key):
        try:
            r = subprocess.run(["git", "config", "--global", "--get", key], capture_output=True, text=True, encoding="utf-8")
            return r.stdout.strip() if r.returncode == 0 else ""
        except OSError:
            return ""
    return cfg("gpg.format") == "ssh" and bool(cfg("user.signingkey"))


def mode(settings: dict | None = None) -> str:
    """`warn` or `enforce`. OM_SIGNED=auto (the default) enforces as soon as git is set up to sign, so a machine that can
    sign is never left deploying unsigned commits by accident; a mistyped value enforces."""
    m = (settings if settings is not None else load_settings()).get("OM_SIGNED", "auto").lower()
    if m == "auto":
        return "enforce" if signing_configured() else "warn"
    return "warn" if m == "warn" else "enforce"


def _git(root: Path, *args: str) -> tuple[int, str, str]:
    try:
        r = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, encoding="utf-8", errors="replace")
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except OSError as e:
        return 1, "", str(e)


def _dir(ws: str) -> Path:
    return GEN_DIR / ws


def trusted_signers_file(ws: str, root: Path) -> tuple[Path | None, bool]:
    """(signer file to verify against, first_use). None if neither copy exists."""
    kept = _dir(ws) / "allowed_signers"
    if kept.exists():
        return kept, False
    own = root / SIGNERS_NAME
    return (own, True) if own.exists() else (None, False)


def verify(ws: str, root: Path, rev: str = "HEAD") -> tuple[bool, str]:
    """(trusted, signer-or-reason) for commit `rev`."""
    signers, first_use = trusted_signers_file(ws, root)
    if signers is None:
        return False, f"no {SIGNERS_NAME} (list the keys allowed to deploy; `om init` writes yours)"
    code, out, err = _git(root, "-c", f"gpg.ssh.allowedSignersFile={signers}", "verify-commit", rev)
    m = _GOOD_RE.search(err + "\n" + out)
    if code == 0 and m:
        return True, m.group(1) + (" (first use: trusting this workspace's allowed_signers)" if first_use else "")
    if not (err + out).strip() or "no signature" in (err + out).lower():
        return False, "commit is not signed"
    return False, "signature not from a trusted key: " + ((err or out).splitlines() or ["?"])[-1][:160]


def signer_fingerprints(signers_file: Path) -> list[tuple[str, str]]:
    """[(principal, SHA256 fingerprint)] of an allowed_signers file, as `ssh-keygen -l` prints them."""
    import base64
    out = []
    try:
        lines = signers_file.read_text(encoding="utf-8").splitlines()
    except OSError:
        return out
    for line in lines:
        words = line.split()
        if not words or words[0].startswith("#"):
            continue
        key = next((words[i + 1] for i, w in enumerate(words[:-1]) if w.startswith(("ssh-", "ecdsa-", "sk-"))), None)
        if not key:
            continue
        try:
            blob = base64.b64decode(key, validate=True)
        except ValueError:
            continue
        out.append((words[0], "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")))
    return out


def is_first_use(ws: str, root: Path) -> list[tuple[str, str]]:
    """The signers about to be trusted for the first time (nothing kept from an earlier deploy), else []."""
    signers, first_use = trusted_signers_file(ws, root)
    return signer_fingerprints(signers) if signers is not None and first_use else []


def _signing_key() -> Path | None:
    """The SSH key git signs with (a private key, or a .pub whose private half is in the agent), if git is set up to."""
    if not signing_configured():
        return None
    r = subprocess.run(["git", "config", "--global", "--get", "user.signingkey"], capture_output=True, text=True, encoding="utf-8")
    key = Path(r.stdout.strip()).expanduser() if r.returncode == 0 and r.stdout.strip() else None
    return key if key and key.is_file() else None


def _keygen(*args: str, stdin=None, timeout: int = 10):
    """ssh-keygen without any chance of prompting: no terminal (a new session), no stdin."""
    return subprocess.run(["ssh-keygen", *args], capture_output=True, text=True, encoding="utf-8", timeout=timeout,
                          stdin=stdin if stdin is not None else subprocess.DEVNULL, start_new_session=True)


def sign_head(ws: str) -> bool:
    """Sign the log's head with the git signing key, so a log rewritten by someone who can only edit files is noticed. Best
    effort and silent: with no key, no agent or a passphrase it asks for, the head stays unsigned (and a signature of an
    older head is removed, never left to mismatch)."""
    head, sig = _dir(ws) / HEAD_NAME, _dir(ws) / HEAD_SIG
    sig.unlink(missing_ok=True)
    key = _signing_key()
    if key is None or not shutil.which("ssh-keygen") or not head.is_file():
        return False
    try:
        _keygen("-Y", "sign", "-n", HEAD_NAMESPACE, "-f", str(key), str(head))
    except (OSError, subprocess.SubprocessError):
        return False
    produced = head.with_name(HEAD_NAME + ".sig")
    if produced != sig and produced.exists():
        produced.replace(sig)
    return sig.exists()


def head_signature(ws: str) -> tuple[str, str]:
    """("absent" | "valid" | "invalid" | "untrusted", detail): does the head's signature match it, and was it made by a
    key in the trusted signer list (the one kept from the last trusted deploy)?"""
    head, sig = _dir(ws) / HEAD_NAME, _dir(ws) / HEAD_SIG
    if not sig.is_file() or not head.is_file():
        return "absent", ""
    try:
        with open(head, "rb") as data:
            r = _keygen("-Y", "check-novalidate", "-n", HEAD_NAMESPACE, "-s", str(sig), stdin=data)
    except (OSError, subprocess.SubprocessError) as e:
        return "invalid", str(e)
    found = re.search(r"key (SHA256:\S+)", r.stdout + r.stderr)
    if r.returncode != 0 or not found:
        return "invalid", (r.stderr or r.stdout).strip()[-160:]
    trusted = {fp for _, fp in signer_fingerprints(_dir(ws) / "allowed_signers")}
    if trusted and found.group(1) not in trusted:
        return "untrusted", found.group(1)
    return "valid", found.group(1)


def remember_signers(ws: str, root: Path, rev: str = "HEAD"):
    """After a trusted deploy, the deployed commit's signer list becomes the trusted one."""
    code, out, _ = _git(root, "show", f"{rev}:{SIGNERS_NAME}")
    if code == 0 and out.strip():
        d = _dir(ws)
        d.mkdir(parents=True, exist_ok=True)
        kept = d / "allowed_signers"
        if kept.exists() and kept.read_text(encoding="utf-8").strip() != out.strip():
            print("  \033[33m⚠ the trusted signer list changed with this deploy "
                  f"({SIGNERS_NAME}); it is now the one used to verify future commits.\033[0m")
        kept.write_text(out + "\n", encoding="utf-8", newline="\n")


def _entries(ws: str) -> list[dict]:
    out = []
    for p in sorted(_dir(ws).glob("*.json"), key=lambda p: int(p.stem) if p.stem.isdigit() else -1):
        if p.stem.isdigit():
            try:
                out.append(json.loads(p.read_text(encoding="utf-8")))
            except ValueError:
                out.append({"n": int(p.stem), "corrupt": True})
    return out


def entries(ws: str) -> list[dict]:
    return _entries(ws)


def _digest(entry: dict) -> str:
    return hashlib.sha256(json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def snapshot(root: Path) -> dict:
    """commit, dirty flag and lock hash of the workspace as it is now."""
    code, commit, _ = _git(root, "rev-parse", "HEAD")
    _, status, _ = _git(root, "status", "--porcelain")
    lock = root / ".om" / "lock.json"
    return {
        "commit": commit if code == 0 else None,
        "dirty": bool(status) if code == 0 else True,
        "lock": hashlib.sha256(lock.read_bytes()).hexdigest() if lock.exists() else None,
    }


def record(ws: str, root: Path, kind: str, result: str, signer: str | None) -> dict:
    """Append one generation to the chain and return it. Locked: two `om` processes (a scheduled sync and a
    manual start) must not both take number n+1."""
    with file_lock(_dir(ws) / ".lock"):
        return _record(ws, root, kind, result, signer)


def _record(ws: str, root: Path, kind: str, result: str, signer: str | None) -> dict:
    prev = _entries(ws)
    entry = {
        "n": (prev[-1].get("n", 0) + 1) if prev else 1,
        "kind": kind,
        **snapshot(root),
        "signer": signer,
        "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "result": result,
        "prev": _digest(prev[-1]) if prev else None,
    }
    d = _dir(ws)
    d.mkdir(parents=True, exist_ok=True)
    tmp = d / f".{entry['n']}.tmp"
    tmp.write_text(json.dumps(entry, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    tmp.replace(d / f"{entry['n']}.json")
    write_atomic(d / HEAD_NAME, f"{entry['n']} {_digest(entry)}\n")
    sign_head(ws)
    return entry


def current(ws: str) -> dict | None:
    """The last generation that started successfully."""
    for e in reversed(_entries(ws)):
        if e.get("result") == "running":
            return e
    return None


def verify_chain(ws: str) -> list[str]:
    """Problems in the generation log: gaps, corrupt entries, broken hash links."""
    problems, prev = [], None
    for i, e in enumerate(_entries(ws), start=1):
        if e.get("corrupt"):
            problems.append(f"generation {e.get('n')}: unreadable")
        elif e.get("n") != i:
            problems.append(f"generation {e.get('n')}: expected number {i} (missing or renumbered)")
        elif e.get("prev") != (_digest(prev) if prev else None):
            problems.append(f"generation {e.get('n')}: does not chain to generation {i - 1} (rewritten?)")
        prev = e
    problems += _check_head(ws, prev)
    state, detail = head_signature(ws)
    if state == "invalid":
        problems.append(f"the generation log's head signature does not match its head (log rewritten?): {detail}")
    elif state == "untrusted":
        problems.append(f"the generation log's head is signed by a key that is not a trusted signer: {detail}")
    return problems


def _check_head(ws: str, last: dict | None) -> list[str]:
    """The `head` file names the newest generation and its digest, so dropping entries from the end (which
    leaves a valid chain) or rewriting the last one is noticed. A log written before `head` existed has none
    until its next generation."""
    try:
        n, digest = (_dir(ws) / HEAD_NAME).read_text(encoding="utf-8").split()
    except (OSError, ValueError):
        return []
    if last is None:
        return [f"generation log is empty but its head says generation {n} (entries deleted?)"]
    if str(last.get("n")) != n or _digest(last) != digest:
        return [f"generation log ends at {last.get('n')} but its head says {n} (entries removed or rewritten?)"]
    return []
