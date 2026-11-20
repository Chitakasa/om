"""`om sync --scheduled` (scheduled_sync): which workspaces it syncs and when, what it logs, what it keeps in
.om/state.json and what it tells you. Real git repositories (a bare remote and a clone per workspace); the deploy, the
signature check, the auto-update and the notifications are recorded. Expected values are those recorded before
scheduled_sync was split into steps."""
import contextlib
import io
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _env

from gitops import notify

EXPECTED = {'auto_sync off': {'calls': [], 'log': '', 'notifications': [], 'rc': 0, 'state': None}, 'not due yet': {'calls': [], 'log': '', 'notifications': [], 'rc': 0, 'state': {'last_sync': 1699999990}}, 'dirty tree': {'calls': [], 'log': '[T] ws: skipped — uncommitted changes in <tmp>/ws\n', 'notifications': [], 'rc': 0, 'state': {'last_result': 'skipped (dirty)', 'last_sync': 1700000000}}, 'up to date, auto-update due': {'calls': ['sync_workspace', 'auto_update'], 'log': '[T] ws: syncing\n', 'notifications': [], 'rc': 0, 'state': {'last_auto_update': 1700000000, 'last_result': 'ok', 'last_sync': 1700000000}}, 'up to date, auto-update not due': {'calls': ['sync_workspace'], 'log': '[T] ws: syncing\n', 'notifications': [], 'rc': 0, 'state': {'last_auto_update': 1699999940, 'last_result': 'ok', 'last_sync': 1700000000}}, 'new commit, healthy': {'calls': ['sync_workspace', 'auto_update'], 'log': '[T] ws: syncing\n', 'notifications': [], 'rc': 0, 'state': {'last_auto_update': 1700000000, 'last_result': 'ok', 'last_sync': 1700000000}}, 'new commit, unhealthy': {'calls': ['sync_workspace'], 'log': '[T] ws: syncing\n[T] ws: remote <sha> quarantined until a new commit is pushed\n', 'notifications': [['om: ws', 'sync of main failed; remote <sha> is quarantined until a new commit is pushed (see <tmp>/logs/autosync.log)', 'sync:ws:<sha>']], 'rc': 1, 'state': {'last_result': 'failed', 'last_sync': 1700000000, 'quarantined': '<sha>'}}, 'quarantined remote': {'calls': [], 'log': '', 'notifications': [], 'rc': 0, 'state': {'last_result': 'skipped (remote <sha> quarantined)', 'last_sync': 1700000000, 'quarantined': '<sha>'}}, 'auto-update fails': {'calls': ['sync_workspace', 'auto_update'], 'log': '[T] ws: syncing\n[T] ws: auto-update of x FAILED its health check; lock reverted\n', 'notifications': [['om: ws', 'auto-update of x FAILED its health check; lock reverted', 'auto:ws:auto-update of x FAILED its health check; lock reverted']], 'rc': 0, 'state': {'last_auto_update': 1700000000, 'last_result': 'auto-update failed', 'last_sync': 1700000000}}, 'auto-update applies': {'calls': ['sync_workspace', 'auto_update'], 'log': '[T] ws: syncing\n[T] ws: auto-updated y 1 -> 2\n', 'notifications': [['om: ws', 'auto-updated y 1 -> 2', 'auto:ws:auto-updated y 1 -> 2']], 'rc': 0, 'state': {'last_auto_update': 1700000000, 'last_result': 'ok', 'last_sync': 1700000000}}}
NOW = 1_700_000_000


def git(cwd, *args):
    return subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false", *args],
                          cwd=cwd, capture_output=True, text=True, encoding="utf-8", check=True).stdout.strip()


def make_workspace(tmp, name, auto_sync=True, interval=300, state=None, dirty=False, new_commit=False):
    """A clone of a bare remote, registered as a workspace; optionally dirty, or behind the remote by a commit."""
    remote, work, other = tmp / f"{name}.git", tmp / name, tmp / f"{name}-other"
    git(tmp, "init", "-q", "--bare", "-b", "main", str(remote))
    git(tmp, "clone", "-q", str(remote), str(work))
    (work / ".om").mkdir()
    (work / ".om" / "config.json").write_text(json.dumps({"workspace_id": name, "gitops": {"auto_sync": auto_sync, "interval_seconds": interval}}),
                                              encoding="utf-8", newline="\n")
    (work / "a.txt").write_text("1", encoding="utf-8")
    git(work, "add", "-A")
    git(work, "commit", "-qm", "first")
    git(work, "push", "-q", "origin", "HEAD:main")
    if new_commit:
        git(tmp, "clone", "-q", str(remote), str(other))
        (other / "a.txt").write_text("2", encoding="utf-8")
        git(other, "commit", "-qam", "next")
        git(other, "push", "-q", "origin", "HEAD:main")
    if state is not None:
        (work / ".om" / "state.json").write_text(json.dumps(state), encoding="utf-8", newline="\n")
    if dirty:
        (work / "a.txt").write_text("edited", encoding="utf-8")
    return work


SCENARIOS = {
    "auto_sync off": {"auto_sync": False},
    "not due yet": {"state": {"last_sync": NOW - 10}},
    "dirty tree": {"dirty": True},
    "up to date, auto-update due": {},
    "up to date, auto-update not due": {"state": {"last_auto_update": NOW - 60}},
    "new commit, healthy": {"new_commit": True, "healthy": True},
    "new commit, unhealthy": {"new_commit": True, "healthy": False},
    "quarantined remote": {"new_commit": True, "quarantine": True},
    "auto-update fails": {"lines": ["auto-update of x FAILED its health check; lock reverted"]},
    "auto-update applies": {"lines": ["auto-updated y 1 -> 2"]},
}


def outputs(om, scenario):
    """Everything one scheduled run does for one workspace, as plain data."""
    g = om["scheduled_sync"].__globals__
    tmp = Path(tempfile.mkdtemp(prefix="om-ss-"))
    try:
        work = make_workspace(tmp, "ws", **{k: scenario[k] for k in ("auto_sync", "state", "dirty", "new_commit") if k in scenario})
        if scenario.get("quarantine"):
            remote_head = git(tmp, "-C", str(tmp / "ws.git"), "rev-parse", "main")
            (work / ".om" / "state.json").write_text(json.dumps({"quarantined": remote_head}), encoding="utf-8", newline="\n")
        calls = []
        logdir = tmp / "logs"
        logdir.mkdir()

        def fake_sync(root, **kw):
            calls.append("sync_workspace")
            return scenario.get("healthy", True)

        def fake_auto_update(root, state):
            calls.append("auto_update")
            return scenario.get("lines", [])

        patches = {"read_registry": lambda: {"ws": {"path": str(work)}, "gone": {"path": str(tmp / "missing")}},
                   "sync_workspace": fake_sync, "auto_update": fake_auto_update, "start_workspace": lambda *a, **k: True,
                   "sync_allowed": lambda *a: True}
        sent = []
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.dict(g, patches))
            stack.enter_context(mock.patch.object(g["omstate"], "LOG_DIR", logdir))
            stack.enter_context(mock.patch.object(g["time"], "time", lambda: NOW))
            stack.enter_context(mock.patch.object(g["time"], "strftime", lambda fmt: "T"))
            stack.enter_context(mock.patch.object(notify, "notify", lambda title, body, key=None: sent.append((title, body.replace(str(tmp), "<tmp>"), key))))
            with contextlib.redirect_stdout(io.StringIO()):
                rc = om["scheduled_sync"]()
        state_file = work / ".om" / "state.json"
        return {"rc": rc, "calls": calls,
                "log": re.sub(r"\b[0-9a-f]{8}\b", "<sha>", (logdir / "autosync.log").read_text(encoding="utf-8").replace(str(tmp), "<tmp>"))
               if (logdir / "autosync.log").exists() else "",
                "state": json.loads(state_file.read_text(encoding="utf-8")) if state_file.exists() else None,
                "notifications": [[t, re.sub(r"[0-9a-f]{8}", "<sha>", b), re.sub(r"[0-9a-f]{40}", "<sha>", k or "")] for t, b, k in sent]}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


class TestScheduledSync(unittest.TestCase):
    def test_every_scenario_behaves_as_recorded(self):
        om = _env.load_om()
        self.assertEqual(set(SCENARIOS), set(EXPECTED))
        for name, scenario in SCENARIOS.items():
            with self.subTest(name):
                got = json.loads(json.dumps(outputs(om, scenario), sort_keys=True))
                got["state"] = scrub(got["state"])
                self.assertEqual(got, EXPECTED[name])


def scrub(state):
    """Commit ids are different on every run."""
    if state and "quarantined" in state:
        state = {**state, "quarantined": "<sha>"}
    if state and "last_result" in state:
        state = {**state, "last_result": re.sub(r"[0-9a-f]{8}", "<sha>", state["last_result"])}
    return state


if __name__ == "__main__":
    unittest.main()
