#!/usr/bin/env python3
"""
engine.py — GitOps & Drift Reconciliation Engine for 'om'
Provides Git drift detection, remote conflict resolution guidance,
pull reconciliation, synthetic health checks, and automated rollbacks.
"""

import os
import sys
import time
import json
import urllib.error
import urllib.request
import subprocess
from pathlib import Path

def run_git(args: list[str], cwd: Path) -> tuple[int, str, str]:
    """Execute git command and return (code, stdout, stderr)."""
    try:
        res = subprocess.run(["git"] + args, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        return res.returncode, res.stdout.strip(), res.stderr.strip()
    except Exception as e:
        return 1, "", str(e)

def inspect_drift(workspace_root: Path, branch: str = "main") -> dict:
    """Analyze Git drift against remote branch."""
    # Check if this is a git repo
    code, _, _ = run_git(["rev-parse", "--is-inside-work-tree"], workspace_root)
    if code != 0:
        return {"status": "NO_GIT", "message": "Workspace is not a Git repository."}

    # Fetch remote silently
    run_git(["fetch", "origin", branch], workspace_root)

    # Local commit
    code_l, local_hash, _ = run_git(["rev-parse", "HEAD"], workspace_root)
    _, local_msg, _ = run_git(["log", "-1", "--format=%s", "HEAD"], workspace_root)

    # Remote upstream commit
    code_r, remote_hash, _ = run_git(["rev-parse", f"origin/{branch}"], workspace_root)
    _, remote_msg, _ = run_git(["log", "-1", "--format=%s", f"origin/{branch}"], workspace_root)

    if code_r != 0:
        return {
            "status": "NO_REMOTE",
            "local_hash": local_hash[:8] if local_hash else "none",
            "message": f"No remote branch 'origin/{branch}' found."
        }

    # Check ahead / behind counts
    _, counts, _ = run_git(["rev-list", "--left-right", "--count", f"HEAD...origin/{branch}"], workspace_root)
    ahead, behind = 0, 0
    if counts:
        parts = counts.split()
        if len(parts) == 2:
            ahead, behind = int(parts[0]), int(parts[1])

    # Working tree status
    _, status_out, _ = run_git(["status", "--porcelain"], workspace_root)
    has_dirty_files = bool(status_out.strip())

    state = "UP-TO-DATE"
    if ahead > 0 and behind > 0:
        state = "DIVERGED"
    elif ahead > 0:
        state = "AHEAD"
    elif behind > 0:
        state = "BEHIND"

    return {
        "status": state,
        "branch": branch,
        "local_hash": local_hash[:8] if local_hash else "unknown",
        "local_msg": local_msg or "No commit",
        "remote_hash": remote_hash[:8] if remote_hash else "unknown",
        "remote_msg": remote_msg or "No commit",
        "ahead": ahead,
        "behind": behind,
        "dirty": has_dirty_files
    }

def print_drift_report(workspace_root: Path, branch: str = "main"):
    """Format and print clear, actionable drift report for devs and non-devs."""
    info = inspect_drift(workspace_root, branch)
    print(f"\n\033[1mREMOTE GITOPS STATE (Branch: {branch})\033[0m")
    print("═" * 78)

    status = info.get("status")
    if status == "NO_GIT":
        print(f"  \033[33mℹ Workspace is local-only (not a Git repository).\033[0m")
        print(f"  To connect to GitOps: git init && git remote add origin <url>\n")
        return

    if status == "NO_REMOTE":
        print(f"  Local Commit:   {info.get('local_hash')}")
        print(f"  \033[33mℹ No remote branch origin/{branch} tracked yet.\033[0m\n")
        return

    print(f"  Local Commit:   {info['local_hash']} (\"{info['local_msg'][:45]}\")")
    print(f"  Remote Commit:  {info['remote_hash']} (\"{info['remote_msg'][:45]}\")")
    if info.get("dirty"):
        print("  Working Tree:   \033[33m⚠ Uncommitted local changes detected\033[0m")
    else:
        print("  Working Tree:   \033[32mClean\033[0m")

    print("\n  STATUS: ", end="")
    if status == "UP-TO-DATE":
        print("\033[32m✓ UP-TO-DATE (Local system matches remote truth)\033[0m\n")
    elif status == "BEHIND":
        print(f"\033[33m⬇ BEHIND by {info['behind']} commit(s) (New updates available on remote)\033[0m")
        print("\n  HOW TO RESOLVE:")
        print("  • Run: \033[1mom sync\033[0m")
        print("    Pulls new updates and gracefully reconciles services with health verification.\n")
    elif status == "AHEAD":
        print(f"\033[36m⬆ AHEAD by {info['ahead']} commit(s) (Local commits ready to publish)\033[0m")
        print("\n  HOW TO RESOLVE:")
        print(f"  • Run: \033[1mgit push origin {branch}\033[0m")
        print("    Publishes your changes so teammates or backups stay synchronized.\n")
    elif status == "DIVERGED":
        print(f"\033[31m⚠ DIVERGED (History Mismatch: {info['ahead']} ahead, {info['behind']} behind)\033[0m")
        print("\n  HOW TO RESOLVE:")
        print("  • Option 1 (Recommended - Rebase Local on Remote):")
        print("      Run: \033[1mom sync --rebase\033[0m (Applies remote updates, replays local work)")
        print("  • Option 2 (Discard Local & Align with Remote Truth):")
        print("      Run: \033[1mom sync --force\033[0m (Resets local state strictly to remote commit)\n")

def workspace_vhosts(ws_id: str) -> list[str]:
    """Hostnames of this workspace's generated Caddy vhosts (plus its dashboard)."""
    from gitops.core import ROUTES_DIR
    conf_d = ROUTES_DIR
    hosts = [f"{ws_id}.dashboard.localhost"]
    for f in sorted(conf_d.glob(f"{ws_id}-*.caddy")):
        try:
            for line in f.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line.startswith(f"http://{ws_id}.") and line.endswith("{"):
                    hosts.append(line[len("http://"):-1].strip())
                    break
        except Exception:
            pass
    return hosts

def run_synthetic_health_check(hosts: list[str], timeout_s: float = 60.0, ingress: str | None = None) -> bool:
    """Probe each vhost through the private ingress until none returns a 5xx (or the timeout expires).
    A 401 (private-tier login enabled) counts as healthy: the proxy and upstream answered."""
    if ingress is None:
        from gitops.core import base_url
        ingress = base_url("127.0.0.1")
    deadline = time.monotonic() + timeout_s
    pending = list(hosts)
    while pending and time.monotonic() < deadline:
        still_failing = []
        for host in pending:
            req = urllib.request.Request(f"{ingress}/", headers={"Host": host, "User-Agent": "om-healthcheck/1.0"})
            try:
                with urllib.request.urlopen(req, timeout=3.0):
                    pass
            except urllib.error.HTTPError as e:
                if e.code >= 500:
                    still_failing.append(host)
            except Exception:
                still_failing.append(host)
        pending = still_failing
        if pending:
            time.sleep(min(2.0, max(0.0, deadline - time.monotonic())))
    for host in pending:
        print(f"  \033[31m✗ {host} unhealthy\033[0m")
    return not pending

def read_workspace_config(workspace_root: Path) -> dict:
    cfg_file = workspace_root / ".om" / "config.json"
    try:
        return json.loads(cfg_file.read_text(encoding="utf-8"))
    except Exception:
        return {}

def sync_workspace(workspace_root: Path, branch: str = "main", force: bool = False, rebase: bool = False,
                   reconcile=None, verify=None) -> bool:
    """Pull remote state, reconcile containers/routes via `reconcile(kind)`, and roll back if unhealthy.
    `verify(rev)` is asked before anything is pulled; False refuses the incoming commit."""
    print(f"\033[1m🔄 Initiating GitOps Reconciliation on {branch}...\033[0m")

    # Both --force and the auto-rollback use `git reset --hard`, which would silently
    # destroy uncommitted work, so a dirty tree is never synced.
    _, status_out, _ = run_git(["status", "--porcelain"], workspace_root)
    if status_out.strip():
        print("\033[31m❌ Uncommitted changes in workspace; refusing to sync.\033[0m")
        print("  Commit or stash them first (see 'git status').")
        return False

    # 1. Fetch
    code, _, err = run_git(["fetch", "origin", branch], workspace_root)
    if code != 0:
        print(f"\033[31m❌ Git fetch failed:\033[0m {err}")
        return False

    if verify and not verify(f"origin/{branch}"):
        return False

    # 2. Check previous HEAD for rollback anchor
    _, prev_head, _ = run_git(["rev-parse", "HEAD"], workspace_root)

    # 3. Pull / Merge
    if force:
        print("  Forcing alignment to remote truth...")
        code, _, err = run_git(["reset", "--hard", f"origin/{branch}"], workspace_root)
        if code != 0:
            print(f"\033[31m❌ Reset failed:\033[0m {err}")
            return False
    elif rebase:
        code, out, err = run_git(["rebase", f"origin/{branch}"], workspace_root)
        if code != 0:
            print(f"\033[31m❌ Rebase conflict! Run 'git rebase --abort':\033[0m {err}")
            return False
    else:
        code, out, err = run_git(["pull", "--ff-only", "origin", branch], workspace_root)
        if code != 0:
            print(f"\033[31m❌ Fast-forward pull failed:\033[0m {err}")
            print("  Run 'om drift' to inspect history mismatch.")
            return False

    _, new_head, _ = run_git(["rev-parse", "HEAD"], workspace_root)
    if prev_head == new_head:
        print("\033[32m✓ System already matches remote state. Zero drift detected.\033[0m")
        return True

    print(f"\033[32m✓ Successfully pulled updates ({prev_head[:8]} ──► {new_head[:8]})\033[0m")

    # 4. Apply the new state (compose up + route regeneration) and verify it
    cfg = read_workspace_config(workspace_root)
    try:  # a preview's own id lives in its machine-local .om/local.json (as in bin/om get_workspace_id)
        local_id = json.loads((workspace_root / ".om" / "local.json").read_text(encoding="utf-8")).get("workspace_id")
    except (OSError, ValueError, AttributeError):
        local_id = None
    ws_id = local_id or cfg.get("workspace_id", workspace_root.name.lower())
    auto_rollback = cfg.get("gitops", {}).get("auto_rollback", True)

    if reconcile:
        reconcile("sync")
    print("  Running synthetic health probe on Caddy ingress...")
    healthy = run_synthetic_health_check(workspace_vhosts(ws_id))

    if not healthy:
        print("\033[31m❌ Health check failed after update!\033[0m")
        if auto_rollback and prev_head:
            _, dirty_now, _ = run_git(["status", "--porcelain"], workspace_root)
            if dirty_now.strip():  # edited while the probe ran: a hard reset would destroy it
                print("\033[31m❌ Uncommitted changes appeared during the update; not rolling back automatically.\033[0m")
                print(f"  Roll back by hand when ready: git reset --hard {prev_head[:8]}")
                return False
            print(f"\033[33m⏪ Auto-Rollback triggered: Reverting to {prev_head[:8]}...\033[0m")
            run_git(["reset", "--hard", prev_head], workspace_root)
            if reconcile:
                reconcile("rollback")
            print("\033[32m✓ Rolled back to last known good state.\033[0m")
        return False

    print("\033[32m✓ Reconciliation complete: System healthy and verified.\033[0m")
    return True
