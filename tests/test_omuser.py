import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

import _env  # noqa: F401  (sets OM_HOME before importing om modules)
from gitops import omuser


class TestOmUser(unittest.TestCase):
    def test_plan_scopes_acls(self):
        home = str(Path.home())
        mounts = {"workspaces": [f"{home}/ws"], "media": [f"{home}/Pictures"], "write": [f"{home}/ws/data/app"]}
        steps = [argv for _, argv in omuser.plan(mounts)]
        flat = [" ".join(a) for a in steps]
        # recursive read only on the workspace, never on media
        self.assertTrue(any(f.startswith("setfacl -R -m u:om:rX") and f.endswith(f"{home}/ws") for f in flat))
        self.assertFalse(any("-R" in f and "Pictures" in f for f in flat))
        # media and workspaces only need traverse on the home folder
        self.assertIn(["setfacl", "-m", "u:om:x", home], steps)
        # service data changes owner, the user keeps rw by ACL
        self.assertIn(["chown", "-R", "om:om", f"{home}/ws/data/app"], steps)
        self.assertTrue(any(f.startswith("setfacl -R -m u:") and ":rwX" in f and f.endswith("ws/data/app") for f in flat))
        # no step edits the user's own om.env through sudo
        self.assertFalse(any("OM_RUN_AS" in f for f in flat))

    @unittest.skipUnless(shutil.which("ssh-keygen"), "needs ssh-keygen")
    def test_signing_broker_round_trip(self):
        tmp = Path(tempfile.mkdtemp())
        box = tmp / "box"
        box.mkdir()
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(tmp / "k")], check=True)
        doc = tmp / "5.json"
        doc.write_text('{"change": "test"}', encoding="utf-8", newline="\n")
        stop = threading.Event()

        def fake_console_user():  # what delegate()'s broker does, minus sudo and ACLs
            while not stop.is_set():
                for req in box.glob("*.json"):
                    if not Path(str(req) + ".sig").exists():
                        subprocess.run(["ssh-keygen", "-Y", "sign", "-q", "-f", str(tmp / "k"), "-n", "om-access", str(req)], check=True)
                time.sleep(0.05)
        t = threading.Thread(target=fake_console_user, daemon=True)
        t.start()
        os.environ[omuser.SIGN_DIR_ENV] = str(box)
        try:
            self.assertTrue(omuser.sign_via_broker(doc, timeout=10))
            self.assertTrue(Path(str(doc) + ".sig").read_text(encoding="utf-8").startswith("-----BEGIN SSH SIGNATURE"))
        finally:
            stop.set()
            os.environ.pop(omuser.SIGN_DIR_ENV, None)
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
