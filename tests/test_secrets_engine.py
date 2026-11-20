import base64
import contextlib
import hashlib
import http.server
import io
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

import _env  # noqa: F401

from gitops import engine
from gitops import secrets as S

S.has_sops = lambda: False  # exercise the built-in vault deterministically


def make_v2(filepath, output_path, passphrase):
    """Fixture writer for the legacy om-v2 envelope (the CLI only reads these now)."""
    salt = os.urandom(16)
    material = S.derive_key(passphrase, salt, S.PBKDF2_ITERATIONS_V2, 64)
    enc_key, mac_key = material[:32], material[32:]
    ct = S.keystream_xor(enc_key, filepath.read_bytes())
    output_path.write_text(json.dumps({"version": "om-v2", "salt": base64.b64encode(salt).decode("ascii"),
                                       "payload": base64.b64encode(ct).decode("ascii"),
                                       "mac": base64.b64encode(S._v2_mac(mac_key, salt, ct)).decode("ascii")}),
                           encoding="utf-8", newline="\n")


class TestSecrets(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        self.plain = self.d / "p.txt"
        self.plain.write_bytes(os.urandom(5000))

    def test_roundtrip(self):
        make_v2(self.plain, self.d / "e", "pw")
        self.assertEqual(S.decrypt_file(self.d / "e", "pw"), self.plain.read_bytes())

    def test_wrong_passphrase_and_tamper_are_detected(self):
        make_v2(self.plain, self.d / "e", "pw")
        with self.assertRaises(ValueError):
            S.decrypt_file(self.d / "e", "nope")
        env = json.loads((self.d / "e").read_text(encoding="utf-8"))
        c = bytearray(base64.b64decode(env["payload"]))
        c[10] ^= 1
        env["payload"] = base64.b64encode(bytes(c)).decode()
        (self.d / "t").write_text(json.dumps(env), encoding="utf-8", newline="\n")
        with self.assertRaises(ValueError):
            S.decrypt_file(self.d / "t", "pw")

    def test_legacy_v1_is_refused_unless_asked_for(self):
        self.write_v1(b"legacy secret")
        with self.assertRaisesRegex(ValueError, "no integrity check"):
            S.decrypt_file(self.d / "v1", "pw")
        self.assertEqual(S.decrypt_file(self.d / "v1", "pw", allow_unauthenticated=True), b"legacy secret")

    def write_v1(self, data):
        salt = os.urandom(16)
        key = S.derive_key("pw", salt)
        ks, i = b"", 0
        while len(ks) < len(data):
            ks += hashlib.sha256(key + i.to_bytes(4, "big")).digest()
            i += 1
        (self.d / "v1").write_text(json.dumps({"version": "om-v1", "salt": base64.b64encode(salt).decode(),
                                               "payload": base64.b64encode(bytes(a ^ b for a, b in zip(data, ks, strict=False))).decode()}), encoding="utf-8", newline="\n")

    def test_legacy_v1_still_decrypts_when_asked(self):
        salt = os.urandom(16)
        key = S.derive_key("pw", salt)
        data, ks, i = b"legacy secret", b"", 0
        while len(ks) < len(data):
            ks += hashlib.sha256(key + i.to_bytes(4, "big")).digest()
            i += 1
        (self.d / "v1").write_text(json.dumps({"version": "om-v1", "salt": base64.b64encode(salt).decode(),
                                               "payload": base64.b64encode(bytes(a ^ b for a, b in zip(data, ks, strict=False))).decode()}), encoding="utf-8", newline="\n")
        self.assertEqual(S.decrypt_file(self.d / "v1", "pw", allow_unauthenticated=True), data)


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
        def git(*a):
            return subprocess.run(["git", *a], cwd=d, capture_output=True)
        git("init", "-q")
        (d / "f").write_text("x", encoding="utf-8", newline="\n")
        git("add", "f")
        git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "x")
        (d / "f").write_text("local edit", encoding="utf-8", newline="\n")
        self.assertFalse(engine.sync_workspace(d, force=True))
        self.assertEqual((d / "f").read_text(encoding="utf-8"), "local edit")  # --force must not destroy it


if __name__ == "__main__":
    unittest.main()


class TestMigrate(unittest.TestCase):
    """om secrets migrate: an old file's plaintext, re-encrypted with age under <project>/secrets/<name>.age."""

    def setUp(self):
        from unittest import mock

        from gitops import agesecrets, securitycmds
        self.mock, self.agesecrets, self.cmds = mock, agesecrets, securitycmds
        self.root = Path(tempfile.mkdtemp(prefix="om-mig-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        (self.root / "services" / "db").mkdir(parents=True)
        (self.root / "services" / "db" / "compose.yml").write_text("services: {}\n", encoding="utf-8", newline="\n")
        salt = os.urandom(16)
        material = S.derive_key("pw", salt, S.PBKDF2_ITERATIONS_V2, 64)
        payload = S.keystream_xor(material[:32], b"hunter2")
        (self.root / "old").write_text(json.dumps({"version": "om-v2", "salt": base64.b64encode(salt).decode(), "payload": base64.b64encode(payload).decode(),
                                                   "mac": base64.b64encode(S._v2_mac(material[32:], salt, payload)).decode()}), encoding="utf-8", newline="\n")

    def migrate(self, destination, password="pw"):
        import argparse
        args = argparse.Namespace(action="migrate", file=str(self.root / "old"), destination=destination, allow_unauthenticated=False, output=None)
        stored = []
        with self.mock.patch.dict(os.environ, {"OM_SECRET_KEY": password}), \
                self.mock.patch.object(self.agesecrets, "host_recipient", lambda rt: "age1x"), \
                self.mock.patch.object(self.agesecrets, "encrypt", lambda rt, root, value: stored.append(value) or b"ENCRYPTED"), \
                self.mock.patch.object(self.cmds, "detect_runtime", lambda: "podman"), contextlib.redirect_stdout(io.StringIO()):
            self.cmds.cmd_secrets(self.root, args)
        return stored

    def test_the_plaintext_is_stored_encrypted_in_the_project(self):
        self.assertEqual(self.migrate("db/api_key"), [b"hunter2"])
        self.assertEqual((self.root / "services" / "db" / "secrets" / "api_key.age").read_bytes(), b"ENCRYPTED")

    def test_a_wrong_passphrase_or_a_bad_destination_stores_nothing(self):
        for destination, password in (("db/api_key", "wrong"), ("db/../x", "pw"), ("noslash", "pw"), ("", "pw")):
            with self.subTest(destination=destination, password=password), self.assertRaises(SystemExit):
                self.migrate(destination, password)
        self.assertFalse((self.root / "services" / "db" / "secrets").exists())
