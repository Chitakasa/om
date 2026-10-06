import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import _env  # noqa: F401  (sets OM_HOME before importing om modules)
from gitops import access, core


@unittest.skipUnless(shutil.which("ssh-keygen"), "needs ssh-keygen")
class TestAccessFile(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.saved_dir, access.ACCESS_DIR = access.ACCESS_DIR, self.tmp / "access"
        for name in ("owner", "other"):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(self.tmp / name)], check=True)
        self.saved_key = access.owner_key_path
        self.use("owner")

    def tearDown(self):
        access.ACCESS_DIR, access.owner_key_path = self.saved_dir, self.saved_key
        shutil.rmtree(self.tmp, ignore_errors=True)

    def use(self, key):
        access.owner_key_path = lambda settings=None: self.tmp / key

    def pub(self, key):
        return (self.tmp / f"{key}.pub").read_text(encoding="utf-8").strip()

    def init(self):
        return access.commit(access.empty(self.pub("owner"), "S" * 43 + "=", "10.77.0.0/24"), "init")

    def test_chain_and_addresses(self):
        head = self.init()
        self.assertEqual(head["door"]["address"], "10.77.0.1")
        doc = dict(head, devices={"phone": {"public_key": "P" * 43 + "=", "address": access.next_address(head)}})
        head = access.commit(doc, "add phone")
        self.assertEqual(head["devices"]["phone"]["address"], "10.77.0.2")
        self.assertEqual(access.next_address(head), "10.77.0.3")
        self.assertEqual(access.verify_chain(), (head, []))

    def test_non_owner_cannot_sign(self):
        head = self.init()
        self.use("other")
        with self.assertRaises(RuntimeError):
            access.commit(dict(head, devices={}), "intruder")
        self.assertEqual(access.verify_chain()[0]["version"], 1)  # the failed version was removed

    def test_owner_change_cannot_authorise_itself(self):
        head = self.init()
        self.use("other")  # a version that adds `other` as owner, signed by `other`
        with self.assertRaises(RuntimeError):
            access.commit(dict(head, owners=[self.pub("owner"), self.pub("other")]), "self-add")
        self.use("owner")  # the real owner adds `other`; from then on `other` may sign
        head = access.commit(dict(head, owners=[self.pub("owner"), self.pub("other")]), "add owner")
        self.use("other")
        self.assertEqual(access.commit(dict(head), "by new owner")["version"], 3)

    def test_tampering_is_detected(self):
        head = self.init()
        access.commit(dict(head), "second")
        p = access.ACCESS_DIR / "1.json"
        doc = json.loads(p.read_text(encoding="utf-8"))
        doc["owners"].append("ssh-ed25519 AAAAevil")
        p.write_text(json.dumps(doc), encoding="utf-8", newline="\n")
        head, problems = access.verify_chain()
        self.assertIsNone(head)
        self.assertTrue(problems)


if __name__ == "__main__":
    unittest.main()
