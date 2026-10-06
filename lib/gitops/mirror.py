#!/usr/bin/env python3
"""Off-host mirror of the access chain and the generation logs (GOALS G2/G4).

$OM_STATE_DIR/mirror is a git repository holding copies of access/<n>.json(.sig) and
generations/<ws>/<n>.json. After every change om commits there and pushes to OM_MIRROR (any git
remote you can push to), never forcing: if the remote has diverged, the push is refused and om
says so. Nothing in it is secret (public keys, addresses, hashes, signatures, deploy metadata).

`om mirror verify` compares the local chains with the mirror's: a version or generation the
mirror has and the host lacks, or the same number with different content, means the host's
history was rewound or rewritten. Protect the remote branch against force pushes, so the
mirror itself cannot be rewritten from the host.
"""

import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path

from gitops.core import STATE_DIR, load_settings

MIRROR_DIR = STATE_DIR / "mirror"
BRANCH = "main"


def remote(settings: dict | None = None) -> str:
    s = settings if settings is not None else load_settings()
    return (s.get("OM_MIRROR", "") or "").strip()


def _git(cwd: Path, *args: str) -> tuple[int, str]:
    try:
        r = subprocess.run(["git", "-c", "user.name=om", "-c", "user.email=om@localhost", *args], cwd=cwd,
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
        return r.returncode, (r.stdout + r.stderr).strip()
    except OSError as e:
        return 1, str(e)


def _sources() -> list[tuple[Path, Path]]:
    """(source file, path inside the mirror) for everything mirrored."""
    out = []
    for f in sorted((STATE_DIR / "access").glob("*.json*")):
        out.append((f, Path("access") / f.name))
    for f in sorted((STATE_DIR / "generations").glob("*/*.json")):
        out.append((f, Path("generations") / f.parent.name / f.name))
    return out


def sync() -> str:
    """Copy, commit and push. Returns a one-line status ('' when no mirror is configured)."""
    url = remote()
    if not url:
        return ""
    MIRROR_DIR.mkdir(parents=True, exist_ok=True)
    if not (MIRROR_DIR / ".git").exists():
        _git(MIRROR_DIR, "init", "-q", "-b", BRANCH)
        _git(MIRROR_DIR, "remote", "add", "origin", url)
        if _git(MIRROR_DIR, "fetch", "-q", "origin", BRANCH)[0] == 0:
            _git(MIRROR_DIR, "reset", "-q", "--hard", f"origin/{BRANCH}")
    else:
        _git(MIRROR_DIR, "remote", "set-url", "origin", url)
    have = {rel for _, rel in _sources()}
    for sub in ("access", "generations"):
        for f in (MIRROR_DIR / sub).rglob("*.json*") if (MIRROR_DIR / sub).exists() else []:
            if f.relative_to(MIRROR_DIR) not in have:
                return f"✗ mirror: {f.relative_to(MIRROR_DIR)} was mirrored but is gone here — rewound? not pushing (om mirror verify)"
    for src, rel in _sources():
        dst = MIRROR_DIR / rel
        if dst.exists() and dst.read_bytes() != src.read_bytes():
            return f"✗ mirror: {rel} differs from what was mirrored before — history rewritten here or there; not pushing (om mirror verify)"
        if not dst.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
    _git(MIRROR_DIR, "add", "-A")
    if _git(MIRROR_DIR, "diff", "--cached", "--quiet")[0] != 0:
        _git(MIRROR_DIR, "commit", "-q", "-m", "om: mirror access chain and generations")
    code, out = _git(MIRROR_DIR, "push", "-q", "origin", f"HEAD:{BRANCH}")
    if code != 0:
        if "non-fast-forward" in out or "rejected" in out or "fetch first" in out:
            return "✗ mirror: the remote has history this host lacks — rewound here? (om mirror verify)"
        return f"⚠ mirror push failed (offline?): {out.splitlines()[-1][:160] if out else '?'}"
    return "✓ mirrored"


def _digests(root: Path) -> dict:
    out = {}
    for sub in ("access", "generations"):
        for f in sorted((root / sub).rglob("*.json*")) if (root / sub).exists() else []:
            out[str(f.relative_to(root))] = hashlib.sha256(f.read_bytes()).hexdigest()
    return out


def verify(url: str | None = None, compare_local: bool = True) -> list[str]:
    """Problems between the local chains and the mirror at `url` (default OM_MIRROR).
    compare_local=False (from another machine): only check the mirror's own chain."""
    url = url or remote()
    if not url:
        return ["no mirror configured (OM_MIRROR in om.env)"]
    tmp = Path(tempfile.mkdtemp(prefix="om-mirror-"))
    try:
        code, out = _git(tmp, "clone", "-q", "--branch", BRANCH, url, str(tmp / "m"))
        if code != 0:
            return [f"cannot read the mirror: {out.splitlines()[-1][:160] if out else '?'}"]
        theirs = _digests(tmp / "m")
        mine = _digests(STATE_DIR) if compare_local else theirs
        problems = [f"{p}: different here than in the mirror (rewritten)" for p in sorted(set(theirs) & set(mine)) if theirs[p] != mine[p]]
        problems += [f"{p}: in the mirror but missing here (rewound or deleted)" for p in sorted(set(theirs) - set(mine))]
        # The mirror's own access chain must verify (signatures, links) on its own.
        from gitops import access
        saved = access.ACCESS_DIR
        try:
            access.ACCESS_DIR = tmp / "m" / "access"
            _, chain_problems = access.verify_chain()
        finally:
            access.ACCESS_DIR = saved
        problems += [f"mirror access chain: {p}" for p in chain_problems]
        return problems
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
