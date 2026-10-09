"""End-to-end CLI tests that need no container engine (OM_RUNTIME points at a missing binary)."""
import os
import sys
import json
import shutil
import tempfile
import subprocess
import unittest
from pathlib import Path

import _env


def om(*args, cwd=None, stdin=""):
    return subprocess.run([sys.executable, str(_env.OM_BIN), *args], cwd=cwd, capture_output=True,
                          text=True, encoding="utf-8", input=stdin, env=os.environ.copy(), timeout=60)


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="om-cli-")) / "demo"
        self.ws.mkdir()

    def tearDown(self):
        shutil.rmtree(self.ws.parent, ignore_errors=True)
        om("list", "--prune")

    @unittest.skipUnless(hasattr(os, "geteuid"), "no root on this OS")
    def test_refuses_root(self):
        code = ("import os, runpy, sys; os.geteuid = lambda: 0; sys.argv = ['om', 'status'];"
                f"runpy.run_path({str(_env.OM_BIN)!r}, run_name='__main__')")
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, encoding="utf-8",
                           env=os.environ.copy(), timeout=60)
        self.assertEqual(r.returncode, 1)
        self.assertIn("does not run as root", r.stderr)

    def test_json_outputs_parse(self):
        self.assertIsInstance(json.loads(om("list", "--json").stdout), list)
        d = json.loads(om("doctor", "--json").stdout)            # no engine in tests: failures, still JSON
        self.assertIn("checks", d)
        self.assertTrue(all({"check", "status", "detail", "fix"} <= set(c) for c in d["checks"]))
        self.assertIn("core", json.loads(om("status", "--json").stdout))

    def test_disable_enable(self):
        om("init", cwd=self.ws)
        om("add", "web", cwd=self.ws)
        marker = self.ws / "services" / "web" / ".omignore"
        self.assertEqual(om("disable", "web", cwd=self.ws).returncode, 0)
        self.assertTrue(marker.exists())
        self.assertNotEqual(om("disable", "web", cwd=self.ws).returncode, 0)   # already disabled
        self.assertEqual(om("enable", "web", cwd=self.ws).returncode, 0)
        self.assertFalse(marker.exists())
        self.assertNotEqual(om("enable", "web", cwd=self.ws).returncode, 0)    # not disabled
        self.assertNotEqual(om("disable", "nope", cwd=self.ws).returncode, 0)

    def test_reload_caddy_edge_not_running(self):
        from gitops import network
        calls = []
        orig = network.run
        class R:  # container exists but is stopped
            returncode, stdout, stderr = 0, "false\n", ""
        network.run = lambda cmd, **kw: (calls.append(cmd), R())[1]
        try:
            self.assertFalse(network.reload_caddy("podman", quiet=True))
        finally:
            network.run = orig
        self.assertEqual(len(calls), 1)  # never reached exec/validate

    def test_version(self):
        r = om("--version")
        self.assertEqual(r.returncode, 0)
        self.assertRegex(r.stdout, r"^om \d+\.\d+\.\d+")

    def test_outside_workspace_is_a_clear_error(self):
        r = om("start", cwd=self.ws)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not an om workspace", r.stderr)

    def test_init_add_remove(self):
        self.assertEqual(om("init", cwd=self.ws).returncode, 0)
        cfg = json.loads((self.ws / ".om" / "config.json").read_text(encoding="utf-8"))
        self.assertEqual(cfg["workspace_id"], "demo")

        r = om("add", "web", cwd=self.ws)
        self.assertEqual(r.returncode, 0, r.stderr)
        compose = (self.ws / "services" / "web" / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("expose:", compose)
        self.assertNotIn("ports:", compose)
        self.assertIn("dashboard.port=80", compose)           # nginx listens on 80
        self.assertIn("dashboard.scope=private", compose)
        conf = _env.TMP_HOME / "_state" / "routes"
        self.assertTrue((conf / "demo-web.caddy").exists())
        self.assertTrue((conf / "demo-web.private_alias").exists())

        r = om("add", "app", "--project", cwd=self.ws)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((self.ws / "projects" / "app" / "server.js").exists())

        r = om("remove", "web", "-y", cwd=self.ws)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse((self.ws / "services" / "web").exists())
        self.assertFalse((conf / "demo-web.caddy").exists())
        self.assertTrue(any((self.ws / ".om" / "trash").rglob("docker-compose.yml")))

    def test_input_validation(self):
        om("init", cwd=self.ws)
        self.assertNotEqual(om("add", "../x", cwd=self.ws).returncode, 0)
        self.assertNotEqual(om("add", "x", "--image", "nginx", cwd=self.ws).returncode, 0)  # needs --port
        self.assertNotEqual(om("add", "y", "--desc", 'a"b', cwd=self.ws).returncode, 0)
        core_dir = self.ws.parent / "core"
        core_dir.mkdir()
        self.assertNotEqual(om("init", cwd=core_dir).returncode, 0)  # reserved id

    def test_prune_removes_routes_of_missing_workspaces(self):
        om("init", cwd=self.ws)
        om("add", "web", cwd=self.ws)
        shutil.rmtree(self.ws)
        om("list", "--prune")
        conf = _env.TMP_HOME / "_state" / "routes"
        self.assertFalse(list(conf.glob("demo-*")))

    def test_completion(self):
        r = om("completion", "bash")
        self.assertIn("doctor", r.stdout)


if __name__ == "__main__":
    unittest.main()


class TestDocsAndMultiUser(unittest.TestCase):
    def test_docs_lists_and_shows(self):
        r = om("docs")
        self.assertEqual(r.returncode, 0)
        for name in ("guide", "architecture", "design"):
            self.assertIn(name, r.stdout)
        r = om("docs", "gui")                       # prefix match; not a tty → printed, no pager
        self.assertEqual(r.returncode, 0)
        self.assertIn("Change, rebuild, update", r.stdout)
        self.assertTrue(om("docs", "guide", "--path").stdout.strip().endswith("GUIDE.md"))
        self.assertNotEqual(om("docs", "nope").returncode, 0)

    def test_auth_users_roundtrip(self):
        m = _env.load_om()
        conf = Path(tempfile.mkdtemp()) / "private.conf"
        users = {"alice": "$2a$14$" + "a" * 53, "bob": "$2a$14$" + "b" * 53}
        m["write_auth_users"](conf, users)
        self.assertEqual(m["read_auth_users"](conf), users)
        m["write_auth_users"](conf, {})
        self.assertFalse(conf.exists())

    def test_has_build(self):
        m = _env.load_om()
        cf = Path(tempfile.mkdtemp()) / "compose.yml"
        cf.write_text("services:\n  a:\n    build:\n      context: .\n", encoding="utf-8", newline="\n")
        self.assertTrue(m["has_build"](cf))
        cf.write_text("services:\n  a:\n    image: x:1\n", encoding="utf-8", newline="\n")
        self.assertFalse(m["has_build"](cf))

    def test_edge_ports_configurable(self):
        from gitops import core
        self.assertEqual(core.edge_ports({"OM_HTTP_PORT": "8081", "OM_HTTPS_PORT": "8444"}), (8081, 8444))
        self.assertEqual(core.edge_ports({"OM_HTTP_PORT": "x", "OM_HTTPS_PORT": "70000"}), (80, 443))
        ports = core.render_ports({"http_port": 8081, "https_port": 8444, "lan_ip": "192.168.1.5"})
        self.assertIn('"127.0.0.1:8081:80"', ports)
        self.assertIn('"192.168.1.5:8444:8443"', ports)
