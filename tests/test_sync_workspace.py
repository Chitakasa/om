"""sync_workspace against real git repositories (a bare "remote" and a clone), with the health probe replaced."""
import contextlib
import io
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _env  # noqa: F401

from gitops import engine


def git(cwd, *args):
    return subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false", *args],
                          cwd=cwd, capture_output=True, text=True, encoding="utf-8", check=True).stdout.strip()


class TestSync(unittest.TestCase):
    def setUp(self):
        # sync --rebase makes commits through plain git: it needs an identity on a runner without one
        ident = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
        patcher = mock.patch.dict(os.environ, ident)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.tmp = Path(tempfile.mkdtemp(prefix="om-sync-"))
        self.remote, self.work, self.other = self.tmp / "remote.git", self.tmp / "work", self.tmp / "other"
        git(self.tmp, "init", "-q", "--bare", "-b", "main", str(self.remote))
        git(self.tmp, "clone", "-q", str(self.remote), str(self.work))
        (self.work / "a.txt").write_text("1", encoding="utf-8")
        git(self.work, "add", "a.txt")
        git(self.work, "commit", "-qm", "first")
        git(self.work, "push", "-q", "origin", "HEAD:main")
        git(self.tmp, "clone", "-q", str(self.remote), str(self.other))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def push_new_commit(self, text="2"):
        (self.other / "a.txt").write_text(text, encoding="utf-8")
        git(self.other, "commit", "-qam", "next")
        git(self.other, "push", "-q", "origin", "HEAD:main")

    def sync(self, healthy=True, **kw):
        calls = []
        buf = io.StringIO()
        with mock.patch.object(engine, "run_synthetic_health_check", return_value=healthy), \
                mock.patch.object(engine, "workspace_vhosts", return_value=["h"]), contextlib.redirect_stdout(buf):
            ok = engine.sync_workspace(self.work, reconcile=calls.append, **kw)
        return ok, calls, buf.getvalue()

    def head(self):
        return git(self.work, "rev-parse", "HEAD")

    def test_already_up_to_date(self):
        ok, calls, out = self.sync()
        self.assertEqual((ok, calls), (True, []))
        self.assertIn("Zero drift", out)

    def test_dirty_tree_is_never_synced(self):
        (self.work / "a.txt").write_text("edited", encoding="utf-8")
        self.push_new_commit()
        ok, calls, out = self.sync()
        self.assertEqual((ok, calls), (False, []))
        self.assertIn("Uncommitted changes", out)
        self.assertEqual((self.work / "a.txt").read_text(encoding="utf-8"), "edited")

    def test_fast_forward_reconciles_once_and_stays(self):
        self.push_new_commit()
        ok, calls, out = self.sync()
        self.assertEqual((ok, calls), (True, ["sync"]))
        self.assertEqual((self.work / "a.txt").read_text(encoding="utf-8"), "2")
        self.assertIn("Reconciliation complete", out)

    def test_unhealthy_update_rolls_back_and_redeploys(self):
        before = self.head()
        self.push_new_commit()
        ok, calls, out = self.sync(healthy=False)
        self.assertEqual((ok, calls), (False, ["sync", "rollback"]))
        self.assertEqual(self.head(), before)
        self.assertIn("Rolled back", out)

    def test_auto_rollback_can_be_switched_off(self):
        (self.work / ".om").mkdir()
        (self.work / ".om" / "config.json").write_text('{"gitops": {"auto_rollback": false}}', encoding="utf-8")
        git(self.work, "add", ".om/config.json")
        git(self.work, "commit", "-qm", "cfg")
        git(self.work, "push", "-q", "origin", "HEAD:main")
        git(self.other, "pull", "-q", "origin", "main")
        before = self.head()
        self.push_new_commit()
        ok, calls, out = self.sync(healthy=False)
        self.assertEqual((ok, calls), (False, ["sync"]))  # no rollback, no redeploy of the old commit
        self.assertNotEqual(self.head(), before)
        self.assertNotIn("Rolled back", out)

    def test_verify_can_refuse_the_incoming_commit(self):
        before = self.head()
        self.push_new_commit()
        ok, calls, _ = self.sync(verify=lambda rev: False)
        self.assertEqual((ok, calls, self.head()), (False, [], before))

    def test_diverged_history_needs_force_or_rebase(self):
        (self.work / "b.txt").write_text("local", encoding="utf-8")
        git(self.work, "add", "b.txt")
        git(self.work, "commit", "-qm", "local")
        self.push_new_commit()
        self.assertEqual(self.sync()[:2], (False, []))
        ok, calls, _ = self.sync(rebase=True)
        self.assertEqual((ok, calls), (True, ["sync"]))
        self.assertTrue((self.work / "b.txt").exists())

    def test_force_resets_to_the_remote(self):
        (self.work / "b.txt").write_text("local", encoding="utf-8")
        git(self.work, "add", "b.txt")
        git(self.work, "commit", "-qm", "local")
        self.push_new_commit()
        ok, calls, _ = self.sync(force=True)
        self.assertEqual((ok, calls), (True, ["sync"]))
        self.assertFalse((self.work / "b.txt").exists())

    def test_preview_id_comes_from_local_json(self):
        (self.work / ".om").mkdir()
        (self.work / ".om" / "local.json").write_text('{"workspace_id": "app--feat"}', encoding="utf-8")
        self.assertEqual(engine._workspace_id(self.work, {"workspace_id": "app"}), "app--feat")
        self.assertEqual(engine._workspace_id(self.tmp, {"workspace_id": "app"}), "app")
        self.assertEqual(engine._workspace_id(self.tmp, {}), self.tmp.name.lower())


if __name__ == "__main__":
    unittest.main()
