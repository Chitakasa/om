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
        self.assertTrue((conf / "demo-web.private_subpath").exists())

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
