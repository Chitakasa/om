"""Private-tier logins, cross-workspace links and secrets (lib/gitops/securitycmds.py), with the engine, Caddy and age
replaced: what is written, what is refused, and that a password or a secret never lands where it must not."""
import argparse
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _env  # noqa: F401

from gitops import securitycmds as sc

HASH = "$2a$14$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
HASH2 = "$2a$14$zyxwvutsrqponmlkjihgfeZYXWVUTSRQPONMLKJIHGFEDCBA543210"


def args(**kw):
    base = {"action": "list", "user": None, "file": None, "destination": None, "output": None, "allow_unauthenticated": False,
            "json": False}
    return argparse.Namespace(**{**base, **kw})


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="om-sec-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.out, self.err = io.StringIO(), io.StringIO()

    def call(self, fn, *a, **kw):
        """(exit code or None, stdout, stderr) of fn(*a), `die()` caught."""
        self.out.seek(0), self.out.truncate(), self.err.seek(0), self.err.truncate()
        code = None
        with contextlib.redirect_stdout(self.out), contextlib.redirect_stderr(self.err):
            try:
                fn(*a, **kw)
            except SystemExit as e:
                code = e.code if e.code is not None else 0
        return code, self.out.getvalue(), self.err.getvalue()


class TestAuthFile(Base):
    def test_users_round_trip_sorted_and_only_bcrypt_lines_count(self):
        conf = self.tmp / "private.conf"
        with mock.patch.object(sc, "AUTH_D", self.tmp):
            sc.write_auth_users(conf, {"zoe": HASH, "alice": HASH2})
            text = conf.read_text(encoding="utf-8")
            self.assertTrue(text.startswith("basic_auth {\n    alice "))
            self.assertEqual(sc.read_auth_users(conf), {"alice": HASH2, "zoe": HASH})
            conf.write_text(text + "    mallory plaintext-password\n    bad/name " + HASH + "\n", encoding="utf-8", newline="\n")
            self.assertEqual(sc.read_auth_users(conf), {"alice": HASH2, "zoe": HASH})
            sc.write_auth_users(conf, {})
            self.assertFalse(conf.exists())
            self.assertEqual(sc.read_auth_users(conf), {})


class TestAuthCommand(Base):
    def setUp(self):
        super().setUp()
        self.conf = self.tmp / "private.conf"
        self.reload = mock.Mock(return_value=True)
        self.hashing = mock.Mock(return_value=subprocess.CompletedProcess([], 0, f"{HASH}\n", ""))
        self.passwords = []
        for p in (mock.patch.object(sc, "AUTH_D", self.tmp), mock.patch.object(sc, "detect_runtime", return_value="podman"),
                  mock.patch.object(sc, "reload_caddy", self.reload), mock.patch.object(sc, "run", self.hashing),
                  mock.patch.object(sc.enginectl, "container_running", return_value=True),
                  mock.patch.object(sc.getpass, "getpass", side_effect=lambda prompt: self.passwords.pop(0))):
            p.start()
            self.addCleanup(p.stop)

    def auth(self, action, user=None, *passwords):
        self.passwords = list(passwords)
        return self.call(sc.cmd_auth, None, args(action=action, user=user))

    def test_status_names_the_logins_or_says_off(self):
        self.assertIn("off", self.auth("status")[1])
        sc.write_auth_users(self.conf, {"alice": HASH})
        self.assertIn("alice", self.auth("list")[1])

    def test_a_bad_login_name_is_refused(self):
        for bad in (None, "", "has space", "../x", "a;b", "x" * 65):
            self.assertNotEqual(self.auth("add", bad)[0], 0, repr(bad))
        self.assertFalse(self.conf.exists())

    def test_adding_a_login_stores_only_the_hash_and_never_shows_the_password(self):
        code, out, err = self.auth("add", "alice", "s3cret-pass", "s3cret-pass")
        self.assertIsNone(code)
        self.assertEqual(sc.read_auth_users(self.conf), {"alice": HASH})
        self.assertNotIn("s3cret-pass", self.conf.read_text(encoding="utf-8") + out + err)
        self.assertEqual(self.hashing.call_args.kwargs["input"], "s3cret-pass\n")   # piped to caddy, nowhere else
        self.reload.assert_called_once()

    def test_add_keeps_the_others_and_set_replaces_them(self):
        sc.write_auth_users(self.conf, {"bob": HASH2})
        self.auth("add", "alice", "longenough", "longenough")
        self.assertEqual(set(sc.read_auth_users(self.conf)), {"alice", "bob"})
        self.auth("set", "carol", "longenough", "longenough")
        self.assertEqual(set(sc.read_auth_users(self.conf)), {"carol"})

    def test_a_short_or_mismatched_password_is_refused_and_nothing_is_written(self):
        self.assertNotEqual(self.auth("add", "alice", "abc")[0], 0)
        self.assertNotEqual(self.auth("add", "alice", "longenough", "different!")[0], 0)
        self.assertFalse(self.conf.exists())

    def test_hashing_needs_the_edge_and_a_real_hash(self):
        with mock.patch.object(sc.enginectl, "container_running", return_value=False):
            self.assertIn("om core start", self.auth("add", "alice", "longenough", "longenough")[2])
        self.hashing.return_value = subprocess.CompletedProcess([], 0, "not a hash\n", "")
        self.assertIn("Could not hash", self.auth("add", "alice", "longenough", "longenough")[2])
        self.hashing.return_value = subprocess.CompletedProcess([], 1, "", "boom")
        self.assertNotEqual(self.auth("add", "alice", "longenough", "longenough")[0], 0)
        self.assertFalse(self.conf.exists())

    def test_removing_a_login_and_switching_the_login_off(self):
        sc.write_auth_users(self.conf, {"alice": HASH, "bob": HASH2})
        self.assertNotEqual(self.auth("remove", "nobody")[0], 0)
        self.assertIsNone(self.auth("remove", "alice")[0])
        self.assertEqual(set(sc.read_auth_users(self.conf)), {"bob"})
        self.assertIn("now off", self.auth("remove", "bob")[1])
        self.assertFalse(self.conf.exists())
        sc.write_auth_users(self.conf, {"bob": HASH2})
        self.assertIn("disabled", self.auth("off")[1])
        self.assertFalse(self.conf.exists())


class TestLinks(Base):
    def run_links(self, found, problems, as_json=False):
        with mock.patch.object(sc, "detect_runtime", return_value="podman"), \
                mock.patch.object(sc.links, "describe", return_value=(found, problems)):
            return self.call(sc.cmd_links, None, args(json=as_json))

    def test_json_text_and_empty(self):
        found = [("ws1/app", "ws2/db", "ws2_db")]
        data = json.loads(self.run_links(found, ["half a link"], as_json=True)[1])
        self.assertEqual(data["links"], [{"consumer": "ws1/app", "provider": "ws2/db", "reach_as": "ws2_db"}])
        self.assertEqual(data["problems"], ["half a link"])
        text = self.run_links(found, ["half a link"])[1]
        self.assertIn("ws1/app", text)
        self.assertIn("half a link", text)
        self.assertIn("None.", self.run_links([], [])[1])


class TestSecretTargets(unittest.TestCase):
    def test_a_target_is_project_slash_a_safe_name(self):
        for good in ("web/token", "db/api_key", "svc/a.b-c"):
            self.assertTrue(sc._valid_secret_target(good), good)
        for bad in ("", "web", "/token", "web/", "web/../x", "web/a b", "web/a;b", "web/" + "x" * 200):
            self.assertFalse(sc._valid_secret_target(bad), bad)


class TestLegacySecrets(Base):
    def test_reading_an_old_file(self):
        self.assertIn("usage", self.call(sc._read_legacy_secret, args())[2])
        self.assertIn("No such file", self.call(sc._read_legacy_secret, args(file=str(self.tmp / "none")))[2])
        f = self.tmp / "old.enc"
        f.write_bytes(b"x")
        with mock.patch.dict(os.environ, {"OM_SECRET_KEY": "pw"}), mock.patch.object(sc, "decrypt_file", return_value=b"plain") as dec:
            self.assertEqual(sc._read_legacy_secret(args(file=str(f), allow_unauthenticated=True)), b"plain")
            dec.assert_called_once_with(f, "pw", allow_unauthenticated=True)
        with mock.patch.dict(os.environ, {"OM_SECRET_KEY": "pw"}), mock.patch.object(sc, "decrypt_file", side_effect=ValueError("wrong passphrase")):
            self.assertIn("wrong passphrase", self.call(sc._read_legacy_secret, args(file=str(f)))[2])

    @unittest.skipIf(os.name == "nt", "POSIX file modes")
    def test_decrypt_to_a_file_is_private_and_to_stdout_is_raw(self):
        f = self.tmp / "old.enc"
        f.write_bytes(b"x")
        out = self.tmp / "plain.txt"
        with mock.patch.object(sc, "_read_legacy_secret", return_value=b"top secret"):
            code, text, _ = self.call(sc.cmd_secrets, None, args(action="decrypt", file=str(f), output=str(out)))
            self.assertIsNone(code)
            self.assertEqual(out.read_bytes(), b"top secret")
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)
            self.assertNotIn("top secret", text)
            raw = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
            with mock.patch.object(sys, "stdout", raw):
                sc.cmd_secrets(None, args(action="decrypt", file=str(f)))
                raw.flush()
                self.assertEqual(raw.buffer.getvalue(), b"top secret")


class TestAgeSecrets(Base):
    def setUp(self):
        super().setUp()
        self.root = self.tmp / "ws"
        (self.root / ".om").mkdir(parents=True)
        (self.root / ".om" / "config.json").write_text('{"workspace_id": "ws"}\n', encoding="utf-8", newline="\n")
        (self.root / "web").mkdir()
        (self.root / "web" / "compose.yml").write_text("services: {}\n", encoding="utf-8", newline="\n")
        self.encrypt = mock.Mock(return_value=b"AGE-CIPHERTEXT")
        for p in (mock.patch.object(sc, "detect_runtime", return_value="podman"),
                  mock.patch.object(sc.agesecrets, "host_recipient", return_value="age1abcdefghijklmnopqrstuvwxyz"),
                  mock.patch.object(sc.agesecrets, "encrypt", self.encrypt)):
            p.start()
            self.addCleanup(p.stop)

    def secrets(self, action, **kw):
        return self.call(sc.cmd_age_secrets, self.root, args(action=action, **kw))

    def test_everything_needs_a_workspace(self):
        self.assertIn("inside a workspace", self.call(sc.cmd_age_secrets, None, args(action="list"))[2])

    def test_set_encrypts_and_never_writes_the_plaintext(self):
        with mock.patch.object(sys, "stdin", mock.Mock(isatty=lambda: False, buffer=io.BytesIO(b"hunter2"))):
            code, out, _ = self.secrets("set", file="web/token")
        self.assertIsNone(code)
        written = self.root / "web" / "secrets" / "token.age"
        self.assertEqual(written.read_bytes(), b"AGE-CIPHERTEXT")
        self.assertEqual(self.encrypt.call_args.args[2], b"hunter2")
        self.assertNotIn("hunter2", out)
        self.assertIn("/run/secrets/token", out)
        self.assertIn("web/token", self.secrets("list")[1])

    def test_set_refuses_a_bad_target_an_empty_value_and_an_unknown_project(self):
        self.assertIn("usage: om secrets set", self.secrets("set", file="not-valid")[2])
        with mock.patch.object(sys, "stdin", mock.Mock(isatty=lambda: False, buffer=io.BytesIO(b""))):
            self.assertIn("Empty value", self.secrets("set", file="web/token")[2])
        with mock.patch.object(sys, "stdin", mock.Mock(isatty=lambda: False, buffer=io.BytesIO(b"x"))):
            self.assertIn("No service or project", self.secrets("set", file="nothere/token")[2])
        self.assertFalse((self.root / "web" / "secrets").exists())

    def test_migrate_stores_the_decrypted_old_secret(self):
        with mock.patch.object(sc, "_read_legacy_secret", return_value=b"old value"):
            self.assertIsNone(self.secrets("migrate", destination="web/legacy", file="x")[0])
        self.assertEqual((self.root / "web" / "secrets" / "legacy.age").read_bytes(), b"AGE-CIPHERTEXT")
        self.assertEqual(self.encrypt.call_args.args[2], b"old value")
        self.assertIn("usage: om secrets migrate", self.secrets("migrate", destination="bad", file="x")[2])

    def test_init_reports_the_recipients_and_whether_an_old_list_grew(self):
        with mock.patch.object(sc.agesecrets, "write_recipients", return_value=False), mock.patch.object(sc, "my_signer_line", return_value=""):
            out = self.secrets("init")[1]
        self.assertIn("this host", out)
        self.assertNotIn("rekey", out)
        signer = 'me@example.org namespaces="git" ssh-ed25519 AAAAkey'
        with mock.patch.object(sc.agesecrets, "write_recipients", return_value=True), mock.patch.object(sc, "my_signer_line", return_value=signer):
            out = self.secrets("init")[1]
        self.assertIn("your SSH key", out)
        self.assertIn("om secrets rekey", out)

    def test_rekey_counts_files_or_explains_why_not(self):
        with mock.patch.object(sc.agesecrets, "rekey", return_value=["a.age", "b.age"]), mock.patch.object(sc.agesecrets, "recipients", return_value=["r1", "r2"]), \
                mock.patch.object(sc, "run", return_value=subprocess.CompletedProcess([], 0, "~/.ssh/id_test.pub\n", "")):
            self.assertIn("2 secret(s) re-encrypted for 2 recipient(s)", self.secrets("rekey")[1])
        with mock.patch.object(sc.agesecrets, "rekey", side_effect=RuntimeError("no key can open these")), \
                mock.patch.object(sc, "run", return_value=subprocess.CompletedProcess([], 1, "", "")):
            self.assertIn("no key can open these", self.secrets("rekey")[2])


class TestSignerLine(unittest.TestCase):
    def line(self, cfg: dict, key_file_text=None):
        def fake_run(cmd, **kw):
            value = cfg.get(cmd[-1])
            return subprocess.CompletedProcess(cmd, 0 if value is not None else 1, (value or "") + "\n", "")
        with mock.patch.object(sc, "run", fake_run):
            if key_file_text is None:
                return sc.my_signer_line()
            with mock.patch.object(sc.Path, "read_text", return_value=key_file_text):
                return sc.my_signer_line()

    def test_only_an_ssh_signing_setup_gives_a_line(self):
        base = {"gpg.format": "ssh", "user.email": "me@example.org", "user.signingkey": "ssh-ed25519 AAAAkey comment"}
        self.assertEqual(self.line(base), 'me@example.org namespaces="git" ssh-ed25519 AAAAkey')
        self.assertEqual(self.line({**base, "gpg.format": "openpgp"}), "")
        self.assertEqual(self.line({**base, "user.email": ""}), "")
        self.assertEqual(self.line({"gpg.format": "ssh", "user.email": "me@example.org", "user.signingkey": "/some/key.pub"},
                                   key_file_text="ssh-ed25519 BBBBkey me@host\n"), 'me@example.org namespaces="git" ssh-ed25519 BBBBkey')

    def test_an_unreadable_key_file_gives_no_line(self):
        cfg = {"gpg.format": "ssh", "user.email": "me@example.org", "user.signingkey": str(Path(tempfile.gettempdir()) / "om-no-such-key.pub")}
        self.assertEqual(self.line(cfg), "")


if __name__ == "__main__":
    unittest.main()
