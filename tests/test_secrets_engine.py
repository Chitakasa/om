import os
import json
import base64
import hashlib
import shutil
import tempfile
import threading
import subprocess
import unittest
import http.server
from pathlib import Path

import _env  # noqa: F401
from gitops import secrets as S
from gitops import engine

S.has_sops = lambda: False  # exercise the built-in vault deterministically


class TestSecrets(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        self.plain = self.d / "p.txt"
        self.plain.write_bytes(os.urandom(5000))

    def test_roundtrip(self):
        S.encrypt_file(self.plain, self.d / "e", "pw")
        self.assertEqual(S.decrypt_file(self.d / "e", "pw"), self.plain.read_bytes())

    def test_wrong_passphrase_and_tamper_are_detected(self):
        S.encrypt_file(self.plain, self.d / "e", "pw")
        with self.assertRaises(ValueError):
            S.decrypt_file(self.d / "e", "nope")
        env = json.loads((self.d / "e").read_text(encoding="utf-8"))
        c = bytearray(base64.b64decode(env["payload"]))
        c[10] ^= 1
        env["payload"] = base64.b64encode(bytes(c)).decode()
        (self.d / "t").write_text(json.dumps(env), encoding="utf-8", newline="\n")
        with self.assertRaises(ValueError):
            S.decrypt_file(self.d / "t", "pw")

    def test_legacy_v1_still_decrypts(self):
        salt = os.urandom(16)
        key = S.derive_key("pw", salt)
        data, ks, i = b"legacy secret", b"", 0
        while len(ks) < len(data):
            ks += hashlib.sha256(key + i.to_bytes(4, "big")).digest()
            i += 1
        (self.d / "v1").write_text(json.dumps({"version": "om-v1", "salt": base64.b64encode(salt).decode(),
                                               "payload": base64.b64encode(bytes(a ^ b for a, b in zip(data, ks))).decode()}), encoding="utf-8", newline="\n")
        self.assertEqual(S.decrypt_file(self.d / "v1", "pw"), data)


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        host = self.headers.get("Host", "")
        code = 502 if host.startswith("bad.") else (401 if host.startswith("auth.") else 200)
        self.send_response(code)
        self.end_headers()
    def log_message(self, *a):
        pass


class TestHealth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.ingress = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def test_healthy_and_login_protected(self):
        self.assertTrue(engine.run_synthetic_health_check(["ok.localhost", "auth.localhost"], 3, self.ingress))

    def test_5xx_is_unhealthy(self):
        self.assertFalse(engine.run_synthetic_health_check(["ok.localhost", "bad.localhost"], 1, self.ingress))


@unittest.skipUnless(shutil.which("git"), "git not installed")
class TestSyncSafety(unittest.TestCase):
    def test_dirty_tree_is_never_synced(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        git = lambda *a: subprocess.run(["git", *a], cwd=d, capture_output=True)
        git("init", "-q")
        (d / "f").write_text("x", encoding="utf-8", newline="\n")
        git("add", "f")
        git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "x")
        (d / "f").write_text("local edit", encoding="utf-8", newline="\n")
        self.assertFalse(engine.sync_workspace(d, force=True))
        self.assertEqual((d / "f").read_text(encoding="utf-8"), "local edit")  # --force must not destroy it


if __name__ == "__main__":
    unittest.main()
