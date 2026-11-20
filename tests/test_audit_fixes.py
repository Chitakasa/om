"""Regression tests for the smaller issues found in the code audit."""
import os
import shutil
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from unittest import mock

import _env  # noqa: F401  (sandboxed OM_HOME)
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
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": str(tmp)}):
                with self.assertRaises(RuntimeError):
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


if __name__ == "__main__":
    unittest.main()
