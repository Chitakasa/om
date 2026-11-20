"""The generation log's head, signed with the git signing key (ssh-keygen -Y). A log rewritten by someone who can only edit
files breaks the signature; no key, or no way to sign without a prompt, leaves the head unsigned and is never an error."""
import shutil
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import _env  # noqa: F401

from gitops import generations


@unittest.skipUnless(shutil.which("ssh-keygen"), "needs ssh-keygen")
class TestHeadSignature(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="om-sig-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.ws = f"sg-{uuid.uuid4().hex[:6]}"
        self.addCleanup(shutil.rmtree, generations.GEN_DIR / self.ws, True)
        self.key = self.new_key("mine")
        self.root = self.tmp / "repo"
        self.root.mkdir()

    def new_key(self, name):
        path = self.tmp / name
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)], check=True, capture_output=True)
        return path

    def record(self, key="default"):
        key = self.key if key == "default" else key
        with mock.patch.object(generations, "_signing_key", lambda: key):
            return generations.record(self.ws, self.root, "start", "running", None)

    def trust(self, key):
        pub = key.with_suffix(".pub").read_text(encoding="utf-8").split()
        kept = generations.GEN_DIR / self.ws / "allowed_signers"
        kept.parent.mkdir(parents=True, exist_ok=True)
        kept.write_text(f'me@x namespaces="git" {pub[0]} {pub[1]}\n', encoding="utf-8", newline="\n")

    def test_a_signed_head_verifies_and_follows_every_new_generation(self):
        self.record()
        self.assertEqual(generations.head_signature(self.ws)[0], "valid")
        self.record()
        self.assertEqual(generations.head_signature(self.ws)[0], "valid")
        self.assertEqual(generations.verify_chain(self.ws), [])

    def test_a_rewritten_head_breaks_the_signature(self):
        self.record()
        self.record()
        head = generations.GEN_DIR / self.ws / "head"
        head.write_text("1 " + "0" * 64 + "\n", encoding="utf-8", newline="\n")  # drop the newest entry and forge the head
        problems = generations.verify_chain(self.ws)
        self.assertTrue(any("head signature does not match" in p for p in problems), problems)

    def test_a_signature_by_a_key_that_is_not_a_trusted_signer_is_reported(self):
        self.record()
        self.trust(self.new_key("someone-else"))
        self.assertEqual(generations.head_signature(self.ws)[0], "untrusted")
        self.assertTrue(any("not a trusted signer" in p for p in generations.verify_chain(self.ws)))
        self.trust(self.key)
        self.assertEqual(generations.head_signature(self.ws)[0], "valid")

    def test_without_a_key_the_head_is_unsigned_and_an_old_signature_is_removed(self):
        self.record()
        sig = generations.GEN_DIR / self.ws / "head.sig"
        self.assertTrue(sig.exists())
        self.record(key=None)
        self.assertFalse(sig.exists())  # never left to mismatch the new head
        self.assertEqual(generations.head_signature(self.ws)[0], "absent")
        self.assertEqual(generations.verify_chain(self.ws), [])

    def test_a_key_that_needs_a_passphrase_cannot_hang_or_fail_the_deploy(self):
        locked = self.tmp / "locked"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "secret", "-f", str(locked)], check=True, capture_output=True)
        entry = self.record(key=locked)
        self.assertEqual(entry["n"], 1)
        self.assertEqual(generations.head_signature(self.ws)[0], "absent")


if __name__ == "__main__":
    unittest.main()
