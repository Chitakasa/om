"""Regression tests for the smaller issues found in the code audit."""
import base64
import contextlib
import io
import os
import shutil
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from unittest import mock

import _env

from gitops import agesecrets, egress, generations, notify


class TestGenerationNumbers(unittest.TestCase):
    def test_concurrent_records_never_share_a_number(self):
        ws, root = f"gen-{uuid.uuid4().hex[:8]}", Path(tempfile.mkdtemp(prefix="om-ws-"))
        try:
            threads = [threading.Thread(target=generations.record, args=(ws, root, "start", "running", None)) for _ in range(8)]
            [t.start() for t in threads]
            [t.join() for t in threads]
            self.assertEqual([e["n"] for e in generations.entries(ws)], list(range(1, 9)))
            self.assertEqual(generations.verify_chain(ws), [])
        finally:
            shutil.rmtree(root, ignore_errors=True)
            shutil.rmtree(generations.GEN_DIR / ws, ignore_errors=True)


class TestNotifyRetry(unittest.TestCase):
    def test_a_message_every_channel_failed_to_send_is_tried_again(self):
        key, outcome = f"k-{uuid.uuid4().hex}", {"ok": False}
        chan = lambda title, body: (outcome["ok"], "x")  # noqa: E731
        with mock.patch.object(notify, "channels", return_value=["x"]), mock.patch.dict(notify.CHANNELS, {"x": chan}):
            self.assertEqual(len(notify.notify("t", "b", key=key)), 1)   # failed
            self.assertEqual(len(notify.notify("t", "b", key=key)), 1)   # so it is sent again
            outcome["ok"] = True
            self.assertEqual(len(notify.notify("t", "b", key=key)), 1)   # delivered
            self.assertEqual(notify.notify("t", "b", key=key), [])       # now once per key


class TestUnreadableSubnet(unittest.TestCase):
    def test_allocate_falls_back_instead_of_crashing(self):
        ws = f"ws-{uuid.uuid4().hex[:6]}"
        ip = egress.allocate_service_ip(ws, "svc", subnet="not-a-subnet")
        self.assertTrue(ip.startswith("10.89."), ip)
        (egress.IPS_DIR / f"{ws}.json").unlink(missing_ok=True)


class TestSecretsBase(unittest.TestCase):
    def test_refuses_a_symlinked_secrets_folder(self):
        tmp = Path(tempfile.mkdtemp(prefix="om-xdg-"))
        elsewhere = Path(tempfile.mkdtemp(prefix="om-else-"))
        try:
            (tmp / "om-secrets").symlink_to(elsewhere)
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": str(tmp)}), self.assertRaises(RuntimeError):
                agesecrets.runtime_dir("ws", "/some/project")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
            shutil.rmtree(elsewhere, ignore_errors=True)

    def test_secrets_dir_is_private(self):
        tmp = Path(tempfile.mkdtemp(prefix="om-xdg-"))
        try:
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": str(tmp)}):
                d = agesecrets.runtime_dir("ws", "/some/project")
                self.assertEqual(d.stat().st_mode & 0o777, 0o700)
                agesecrets.wipe("ws")
                self.assertFalse((tmp / "om-secrets" / "ws").exists())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestDoctorLogin(unittest.TestCase):
    def test_other_login_users_without_a_login_is_a_failure(self):
        from gitops import doctor
        with mock.patch.object(doctor, "_other_login_users", return_value=["guest"]), \
                mock.patch.object(doctor.omstate.AUTH_DIR.__class__, "glob", return_value=iter(())):
            status, msg, fix = doctor.check_auth()
        self.assertEqual(status, doctor.FAIL)
        self.assertIn("guest", msg)
        self.assertIn("om auth add", fix)

    def test_a_trusted_user_is_not_counted(self):
        from gitops import doctor
        with mock.patch.object(doctor, "_other_login_users", return_value=["me2", "guest"]), \
                mock.patch.object(doctor.omsettings, "load_settings", return_value={"OM_TRUSTED_USERS": "me2"}), \
                mock.patch.object(doctor.omstate.AUTH_DIR.__class__, "glob", return_value=iter(())):
            status, msg, _ = doctor.check_auth()
        self.assertEqual(status, doctor.FAIL)
        self.assertIn("guest", msg)
        self.assertNotIn("me2", msg)
        with mock.patch.object(doctor, "_other_login_users", return_value=["me2"]), \
                mock.patch.object(doctor.omsettings, "load_settings", return_value={"OM_TRUSTED_USERS": "me2"}), \
                mock.patch.object(doctor.omstate.AUTH_DIR.__class__, "glob", return_value=iter(())):
            self.assertEqual(doctor.check_auth()[0], doctor.PASS)

    def test_alone_on_the_machine_passes(self):
        from gitops import doctor
        with mock.patch.object(doctor, "_other_login_users", return_value=[]), \
                mock.patch.object(doctor.omstate.AUTH_DIR.__class__, "glob", return_value=iter(())):
            self.assertEqual(doctor.check_auth()[0], doctor.PASS)


if __name__ == "__main__":
    unittest.main()


class TestSigningDefault(unittest.TestCase):
    def test_auto_enforces_exactly_when_git_can_sign_with_an_ssh_key(self):
        for fmt, key, expected in (("ssh", "~/.ssh/id.pub", "enforce"), ("ssh", "", "warn"), ("openpgp", "ABCD", "warn"), ("", "", "warn")):
            def fake_run(cmd, fmt=fmt, key=key, **kw):
                value = {"gpg.format": fmt, "user.signingkey": key}[cmd[-1]]
                return mock.Mock(returncode=0 if value else 1, stdout=value + "\n")
            with self.subTest(fmt=fmt, key=key), mock.patch.object(generations.subprocess, "run", fake_run):
                self.assertEqual(generations.mode({"OM_SIGNED": "auto"}), expected)
                self.assertEqual(generations.mode({}), expected)  # auto is the default

    def test_explicit_values_win_and_typos_fail_closed(self):
        self.assertEqual(generations.mode({"OM_SIGNED": "warn"}), "warn")
        self.assertEqual(generations.mode({"OM_SIGNED": "enforce"}), "enforce")
        self.assertEqual(generations.mode({"OM_SIGNED": "enfroce"}), "enforce")


class TestFirstDeploySigners(unittest.TestCase):
    KEY = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519" + bytes(range(36))).decode()

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="om-fu-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        (self.root / ".om").mkdir()
        (self.root / ".om" / "allowed_signers").write_text(f'me@x namespaces="git" ssh-ed25519 {self.KEY}\n# a comment\nbad line\nme@x ssh-ed25519 not*base64\n', encoding="utf-8", newline="\n")
        self.ws = f"fu-{uuid.uuid4().hex[:6]}"
        self.addCleanup(shutil.rmtree, generations.GEN_DIR / self.ws, True)

    def test_fingerprints_are_listed_the_way_ssh_keygen_prints_them(self):
        found = generations.is_first_use(self.ws, self.root)
        self.assertEqual([p for p, _ in found], ["me@x"])
        self.assertRegex(found[0][1], r"^SHA256:[A-Za-z0-9+/]{43}$")

    def test_it_is_not_the_first_use_once_a_signer_list_was_kept(self):
        kept = generations.GEN_DIR / self.ws
        kept.mkdir(parents=True)
        (kept / "allowed_signers").write_text("x\n", encoding="utf-8", newline="\n")
        self.assertEqual(generations.is_first_use(self.ws, self.root), [])

    def test_enforce_needs_a_yes_and_warn_only_lists(self):
        om = _env.load_om()
        trust = om["_trust_first_signers"]
        signers = [("me@x", "SHA256:abc")]
        g = trust.__globals__
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            with mock.patch.object(generations, "mode", lambda: "warn"):
                self.assertTrue(trust("ws", signers, "start"))
            with mock.patch.object(generations, "mode", lambda: "enforce"), mock.patch.dict(g, {"confirm": lambda q: True}):
                self.assertTrue(trust("ws", signers, "start"))
            with mock.patch.object(generations, "mode", lambda: "enforce"), mock.patch.dict(g, {"confirm": lambda q: False}):
                self.assertFalse(trust("ws", signers, "start"))
            with mock.patch.object(generations, "mode", lambda: "enforce"), mock.patch.dict(g, {"confirm": lambda q: False}):
                self.assertTrue(trust("ws", signers, "dev"))  # `om dev` is the unsigned, local loop
        self.assertIn("SHA256:abc", out.getvalue())
        self.assertIn("signers were not confirmed", out.getvalue())
