import tempfile
import unittest
from pathlib import Path

import _env  # noqa: F401  (sets OM_HOME before importing om modules)

from gitops import agesecrets


class TestAgeSecrets(unittest.TestCase):
    def test_no_encrypted_file_means_no_override(self):
        d = Path(tempfile.mkdtemp())
        cfg = {"secrets": {"token": {"file": str(d / "token")}}}
        self.assertIsNone(agesecrets.write_override("podman", "ws", d, cfg, d / "ov"))

    def test_recipients_file(self):
        root = Path(tempfile.mkdtemp())
        (root / ".om").mkdir()
        agesecrets.write_recipients(root, "age1host", "ssh-ed25519 AAAAkey me@box")
        self.assertEqual(agesecrets.recipients(root), ["age1host", "ssh-ed25519 AAAAkey"])
        # A second machine is added, never replacing the first (its secrets would stop opening there)
        self.assertTrue(agesecrets.write_recipients(root, "age1second", "ssh-ed25519 AAAAkey me@box"))
        self.assertEqual(agesecrets.recipients(root), ["age1host", "ssh-ed25519 AAAAkey", "age1second"])
        self.assertFalse(agesecrets.write_recipients(root, "age1second", ""))

    def test_names(self):
        self.assertTrue(agesecrets.NAME_RE.match("db_password"))
        self.assertFalse(agesecrets.NAME_RE.match("../etc"))


if __name__ == "__main__":
    unittest.main()
