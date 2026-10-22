import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import _env  # noqa: F401  (sets OM_HOME before importing om modules)
from gitops import generations


def git(root, *args):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
                          cwd=root, capture_output=True, text=True, encoding="utf-8", check=True)


@unittest.skipUnless(shutil.which("git") and shutil.which("ssh-keygen"), "needs git and ssh-keygen")
class TestSignedGenerations(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.root = self.tmp / "ws"
        self.root.mkdir()
        self.ws = "gentest" + self.tmp.name[-6:].lower().replace("_", "")
        for name in ("me", "evil"):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(self.tmp / name)], check=True)
        git(self.root, "init", "-q", "-b", "main")
        (self.root / ".om").mkdir()
        (self.root / ".om" / "allowed_signers").write_text(self.signer("me"), encoding="utf-8", newline="\n")
        self.commit("me", "init")

    def tearDown(self):
        shutil.rmtree(generations.GEN_DIR / self.ws, ignore_errors=True)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def signer(self, key):
        pub = (self.tmp / f"{key}.pub").read_text(encoding="utf-8").split()
        return f't@example.com namespaces="git" {pub[0]} {pub[1]}\n'

    def commit(self, key, msg):
        git(self.root, "add", "-A")
        sign = ["-c", "gpg.format=ssh", "-c", f"user.signingkey={self.tmp / key}", "commit", "-q", "-S", "-m", msg] if key \
            else ["-c", "commit.gpgsign=false", "commit", "-q", "-m", msg]
        git(self.root, *sign)

    def test_trusted_untrusted_unsigned(self):
        self.assertTrue(generations.verify(self.ws, self.root)[0])
        (self.root / "a").write_text("1", encoding="utf-8")
        self.commit(None, "unsigned")
        self.assertEqual(generations.verify(self.ws, self.root), (False, "commit is not signed"))
        (self.root / "a").write_text("2", encoding="utf-8")
        self.commit("evil", "evil")
        self.assertFalse(generations.verify(self.ws, self.root)[0])

    def test_commit_cannot_trust_itself(self):
        # Deploy once: the trusted signer list is now om's copy, not the workspace file.
        generations.remember_signers(self.ws, self.root)
        (self.root / ".om" / "allowed_signers").write_text(self.signer("me") + self.signer("evil"), encoding="utf-8", newline="\n")
        self.commit("evil", "evil adds itself")
        self.assertFalse(generations.verify(self.ws, self.root)[0])

    def test_chain_detects_rewrite(self):
        for _ in range(3):
            generations.record(self.ws, self.root, "start", "running", "t@example.com")
        self.assertEqual(generations.verify_chain(self.ws), [])
        self.assertEqual(generations.current(self.ws)["n"], 3)
        p = generations.GEN_DIR / self.ws / "2.json"
        e = json.loads(p.read_text(encoding="utf-8"))
        e["commit"] = "0" * 40
        p.write_text(json.dumps(e), encoding="utf-8", newline="\n")
        self.assertTrue(any("generation 3" in x for x in generations.verify_chain(self.ws)))
        (generations.GEN_DIR / self.ws / "1.json").unlink()
        self.assertTrue(generations.verify_chain(self.ws))

    def test_head_detects_dropped_tail(self):
        for _ in range(3):
            generations.record(self.ws, self.root, "start", "running", "t@example.com")
        (generations.GEN_DIR / self.ws / "3.json").unlink()   # the remaining chain 1-2 is still valid
        problems = generations.verify_chain(self.ws)
        self.assertTrue(any("head says 3" in x for x in problems), problems)

    def test_log_without_head_still_verifies(self):
        generations.record(self.ws, self.root, "start", "running", "t@example.com")
        (generations.GEN_DIR / self.ws / generations.HEAD_NAME).unlink()
        self.assertEqual(generations.verify_chain(self.ws), [])

    def test_snapshot_dirty(self):
        self.assertFalse(generations.snapshot(self.root)["dirty"])
        (self.root / "new").write_text("x", encoding="utf-8")
        self.assertTrue(generations.snapshot(self.root)["dirty"])


if __name__ == "__main__":
    unittest.main()
