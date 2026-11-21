import http.client
import json
import os
import shutil
import socketserver
import sys
import tempfile
import threading
import unittest
from pathlib import Path

import _env

sys.path.insert(0, str(_env.TMP_HOME / "core" / "dashboard" / "app"))
import server as dash  # noqa: E402

PNG = b"\x89PNG\r\n\x1a\n"


class TestDashboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        (cls.tmp / "data").mkdir()
        (cls.tmp / "wp").mkdir()
        (cls.tmp / "reg.json").write_text(json.dumps({"perso": {"id": "perso"}}), encoding="utf-8", newline="\n")
        os.environ["GLOBAL_REGISTRY"] = str(cls.tmp / "reg.json")
        dash.DATA_DIR = str(cls.tmp / "data")
        dash.WALLPAPERS_DIR = str(cls.tmp / "wp")
        dash.SOCKET_PATH = str(cls.tmp / "no.sock")
        (cls.tmp / "wp" / "evil.png").write_bytes(b"<svg onload=alert(1)>")
        cls.srv = socketserver.TCPServer(("127.0.0.1", 0), dash.DashboardHandler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def req(self, method, path, headers=None, body=None):
        return _env.http_roundtrip(self.port, method, path, headers, body)

    L = {"Host": "localhost"}
    PUB = {"Host": "192.168.1.10", "X-Access-Scope": "public"}

    def test_dns_rebinding_host_rejected(self):
        self.assertEqual(self.req("GET", "/api/workspaces", {"Host": "attacker.example"})[0], 403)
        self.assertEqual(self.req("GET", "/api/workspaces", self.L)[0], 200)
        self.assertEqual(self.req("GET", "/api/workspaces", {"Host": "[::1]:80"})[0], 200)
        self.assertEqual(self.req("GET", "/healthz", {"Host": "anything"})[0], 200)

    def test_index_csp_allows_only_hashed_inline_script(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("GET", "/", headers=self.L)
        r = c.getresponse()
        body, csp = r.read(), r.getheader("Content-Security-Policy") or ""
        self.assertIn("default-src 'none'", csp)
        self.assertIn("'sha256-", csp)
        self.assertNotIn("unsafe", csp.split("script-src")[1].split(";")[0])
        self.assertNotRegex(body.decode("utf-8"), r"\son(click|input|change|keydown|load|error)=")

    def test_public_scope_restrictions(self):
        self.assertEqual(self.req("GET", "/api/system", self.PUB)[0], 403)
        self.assertEqual(self.req("GET", "/api/wallpapers", self.PUB)[0], 403)
        self.assertEqual(self.req("POST", "/api/wallpaper/settings", self.PUB, b"{}")[0], 403)
        body = json.loads(self.req("GET", "/api/workspaces", self.PUB)[2])
        self.assertEqual(body["workspaces"], [])

    def test_traversal_creates_nothing(self):
        before = sorted(os.listdir(dash.DATA_DIR))
        self.req("GET", "/api/wallpaper/current?workspace=../../evil", self.PUB)
        self.req("GET", "/api/wallpaper/current?workspace=../../evil", self.L)
        self.assertEqual(sorted(os.listdir(dash.DATA_DIR)), before)
        self.assertFalse((self.tmp / "evil").exists())

    def test_csrf(self):
        h = {**self.L, "Origin": "https://evil.example"}
        self.assertEqual(self.req("POST", "/api/wallpaper/settings", h, b'{"dim":1}')[0], 403)
        h = {**self.L, "Sec-Fetch-Site": "cross-site"}
        self.assertEqual(self.req("POST", "/api/wallpaper/settings", h, b'{"dim":1}')[0], 403)
        h = {**self.L, "Origin": "http://localhost"}
        self.assertEqual(self.req("POST", "/api/wallpaper/settings", h, b'{"dim":1}')[0], 200)

    def test_bad_upload_keeps_current_wallpaper(self):
        wp = Path(dash.DATA_DIR) / "current_wallpaper"
        wp.write_bytes(PNG + b"OLD")
        self.assertEqual(self.req("POST", "/api/wallpaper/upload?name=x.png", self.L, b"hello")[0], 400)
        self.assertEqual(wp.read_bytes(), PNG + b"OLD")
        self.assertEqual(self.req("POST", "/api/wallpaper/upload?name=x.png", self.L, PNG + b"NEW")[0], 200)
        self.assertEqual(wp.read_bytes(), PNG + b"NEW")
        self.assertFalse([f for f in os.listdir(dash.DATA_DIR) if f.startswith(".upload-")])

    def test_machine_name_comes_from_settings_not_code(self):
        self.assertEqual(self.req("GET", "/api/workspaces", {"Host": "myhost"})[0], 403)
        dash.PRIVATE_HOSTNAMES.add("mybox")
        self.addCleanup(dash.PRIVATE_HOSTNAMES.discard, "mybox")
        self.assertEqual(self.req("GET", "/api/workspaces", {"Host": "mybox"})[0], 200)

    def test_opensearch_follows_search_label(self):
        self.assertEqual(self.req("GET", "/opensearch.xml", self.L)[0], 404)
        svc = {"is_search": True, "is_public": True, "name": "Find & Go", "domain": "ws.find.localhost",
               "path": "/", "port_private": 20004, "port_public": 21004, "search_url": "/search?q={searchTerms}"}
        orig = dash.get_running_services
        dash.get_running_services = lambda: [svc]
        self.addCleanup(setattr, dash, "get_running_services", orig)
        status, _, body = self.req("GET", "/opensearch.xml", self.L)
        self.assertEqual(status, 200)
        self.assertIn(b'template="http://ws.find.localhost/search?q={searchTerms}"', body)
        self.assertIn(b"Find &amp; Go", body)
        body = self.req("GET", "/opensearch.xml", self.PUB)[2]
        self.assertIn(b'template="http://192.168.1.10:21004/search?q={searchTerms}"', body)  # its own origin
        svc["is_public"] = False
        self.assertEqual(self.req("GET", "/opensearch.xml", self.PUB)[0], 404)

    def test_svg_never_served_as_image(self):
        status, ctype, _ = self.req("GET", "/api/wallpaper/preview_host?path=evil.png", self.L)
        self.assertEqual((status, ctype), (200, "application/octet-stream"))
        self.assertEqual(self.req("POST", "/api/wallpaper/set", self.L, b'{"name":"evil.png"}')[0], 404)


if __name__ == "__main__":
    unittest.main()
