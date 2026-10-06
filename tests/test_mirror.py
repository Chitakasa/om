import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import _env  # noqa: F401  (sets OM_HOME before importing om modules)
from gitops import mirror


@unittest.skipUnless(shutil.which("git"), "needs git")
class TestMirror(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(self.tmp / "remote.git")], check=True)
        self.state = self.tmp / "state"
        for rel, text in (("access/1.json", "{}"), ("generations/ws/1.json", '{"n": 1}')):
            (self.state / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.state / rel).write_text(text, encoding="utf-8", newline="\n")
        self.saved = (mirror.STATE_DIR, mirror.MIRROR_DIR, mirror.remote)
        mirror.STATE_DIR, mirror.MIRROR_DIR = self.state, self.state / "mirror"
        mirror.remote = lambda settings=None: str(self.tmp / "remote.git")

    def tearDown(self):
        mirror.STATE_DIR, mirror.MIRROR_DIR, mirror.remote = self.saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def problems(self):
        return [p for p in mirror.verify() if not p.startswith("mirror access chain")]

    def test_push_then_detect_rewind_and_rewrite(self):
        self.assertEqual(mirror.sync(), "✓ mirrored")
        self.assertEqual(self.problems(), [])
        (self.state / "generations/ws/1.json").write_text('{"n": 1, "x": 1}', encoding="utf-8", newline="\n")
        self.assertTrue(mirror.sync().startswith("✗"))
        self.assertTrue(any("rewritten" in p for p in self.problems()))
        (self.state / "generations/ws/1.json").unlink()
        self.assertTrue(mirror.sync().startswith("✗"))
        self.assertTrue(any("missing here" in p for p in self.problems()))

    def test_no_mirror_configured(self):
        mirror.remote = lambda settings=None: ""
        self.assertEqual(mirror.sync(), "")


if __name__ == "__main__":
    unittest.main()
