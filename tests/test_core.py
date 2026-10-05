import os
import re
import sys
import json
import shutil
import tempfile
import threading
import subprocess
import unittest
from pathlib import Path

import _env  # noqa: F401  (sets OM_HOME before importing om modules)
from gitops import core, hostsetup


class TestSettings(unittest.TestCase):
    def setUp(self):
        self.backup = core.USER_ENV.read_text(encoding="utf-8") if core.USER_ENV.exists() else None

    def tearDown(self):
        if self.backup is None:
            core.USER_ENV.unlink(missing_ok=True)
        else:
            core.USER_ENV.write_text(self.backup, encoding="utf-8", newline="\n")

    def test_legacy_names_and_explicit_values(self):
        core.USER_ENV.parent.mkdir(parents=True, exist_ok=True)
        core.USER_ENV.write_text("LAN_IP=10.1.2.3\nTAILSCALE_IP=off\nOM_TAILSCALE_HOST=off\nOM_WALLPAPERS_DIR=/tmp/wp\n", encoding="utf-8", newline="\n")
        r = core.resolve_settings()
        self.assertEqual(r["lan_ip"], "10.1.2.3")
        self.assertEqual(r["tailscale_ip"], "")
        self.assertEqual(r["tailscale_host"], "")
        self.assertTrue(r["wallpapers_dir"].endswith("wp"))

    def test_off_disables_lan(self):
        core.USER_ENV.write_text("OM_LAN_IP=off\nOM_TAILSCALE_IP=off\nOM_TAILSCALE_HOST=off\n", encoding="utf-8", newline="\n")
        self.assertEqual(core.resolve_settings()["lan_ip"], "")


class TestPorts(unittest.TestCase):
    def test_tiers_map_to_separate_container_ports(self):
        y = core.render_ports({"lan_ip": "192.168.9.9", "tailscale_ip": "100.64.1.1"})
        self.assertIn('"127.0.0.1:80:80"', y)
        self.assertIn('"100.64.1.1:80:80"', y)
        self.assertIn('"192.168.9.9:80:8080"', y)      # LAN → public tier only
        self.assertNotIn('"192.168.9.9:80:80"', y)
        self.assertNotIn("0.0.0.0", y)

    def test_disabled_addresses_are_not_bound(self):
        y = core.render_ports({"lan_ip": "", "tailscale_ip": ""})
        self.assertNotIn("8080", y)
        self.assertNotIn("100.", y)


class TestToken(unittest.TestCase):
    def test_token_is_stable_and_strong(self):
        a = core.edge_token()
        self.assertRegex(a, r"^[0-9a-f]{64}$")
        self.assertEqual(a, core.edge_token())

    def test_corrupt_token_is_replaced(self):
        core.TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        core.TOKEN_FILE.write_text("short", encoding="utf-8", newline="\n")
        self.assertRegex(core.edge_token(), r"^[0-9a-f]{64}$")


class TestLock(unittest.TestCase):
    def test_registry_updates_are_serialized(self):
        core.REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
        core.REGISTRY_FILE.write_text("{}", encoding="utf-8", newline="\n")

        def worker(i):
            core.update_registry(lambda reg: reg.__setitem__(f"w{i}", {"id": f"w{i}"}))
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(core.read_registry()), 20)


class TestFirewall(unittest.TestCase):
    def test_nft_only_front_door_plus_extras(self):
        nft = hostsetup.render_nft(["1714-1764"], [])
        self.assertIn("policy drop", nft)
        self.assertIn("tcp dport { 80, 443, 1714-1764 } accept", nft)
        self.assertNotIn("flush ruleset", nft)  # must never wipe other tables (Tailscale, engine)

    def test_pf_and_windows(self):
        self.assertIn("block in all", hostsetup.render_pf([], []))
        self.assertIn("-LocalPort 80,443", hostsetup.render_windows([], []))

    def test_port_spec_validation(self):
        self.assertEqual(hostsetup._ports("22, 1714-1764, x, 99999999, ;rm"), ["22", "1714-1764"])


class TestHeal(unittest.TestCase):
    def test_respects_deliberate_stop(self):
        core.STOP_MARKER.parent.mkdir(parents=True, exist_ok=True)
        core.STOP_MARKER.write_text("x", encoding="utf-8", newline="\n")
        try:
            self.assertEqual(core.core_heal("om-test-no-engine"), "")
        finally:
            core.STOP_MARKER.unlink(missing_ok=True)

    def test_no_engine_means_no_action(self):
        self.assertEqual(core.core_heal("om-test-no-engine"), "")


MIGRATE = """
import json, sys
sys.path.insert(0, sys.argv[1])
from gitops import core
print(json.dumps({"present": core.legacy_state_present(), "moved": core.migrate_legacy_state(),
                  "after": core.legacy_state_present()}))
"""


class TestStateMigration(unittest.TestCase):
    """Pre-split installs kept state inside OM_HOME; it must move out intact, exactly once."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="om-migrate-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home, self.state, self.cfg = self.tmp / "home", self.tmp / "state", self.tmp / "cfg"
        c = self.home / "core"
        (c / "data" / "caddy" / "pki").mkdir(parents=True)
        (c / "data" / "caddy" / "pki" / "root.key").write_text("KEY", encoding="utf-8", newline="\n")
        (c / "data" / "edge_token").write_text("a" * 64, encoding="utf-8", newline="\n")
        (c / ".env").write_text("OM_LAN_IP=off\n", encoding="utf-8", newline="\n")
        (c / "caddy" / "conf.d").mkdir(parents=True)
        (c / "caddy" / "conf.d" / "zz-app.caddy").write_text("# ===\n# Service: app (zz)\n", encoding="utf-8", newline="\n")
        (c / "caddy" / "conf.d" / "portainer.caddy").write_text("# Service: portainer (core) - hand-written\n", encoding="utf-8", newline="\n")
        (c / "caddy" / "auth.d").mkdir()
        (c / "caddy" / "auth.d" / "private.conf").write_text("basic_auth", encoding="utf-8", newline="\n")
        (self.home / "config").mkdir()
        (self.home / "config" / "workspaces.json").write_text('{"zz": {}}', encoding="utf-8", newline="\n")
        (self.home / "logs").mkdir()
        (self.home / "logs" / "heal.log").write_text("x", encoding="utf-8", newline="\n")

    def migrate(self):
        env = {**os.environ, "OM_HOME": str(self.home), "OM_STATE_DIR": str(self.state), "OM_CONFIG_DIR": str(self.cfg)}
        lib = str(Path(core.__file__).resolve().parent.parent)
        r = subprocess.run([sys.executable, "-c", MIGRATE, lib], env=env, capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def test_everything_moves_and_program_files_stay(self):
        res = self.migrate()
        self.assertTrue(res["present"])
        self.assertFalse(res["after"])
        self.assertEqual((self.state / "data" / "caddy" / "pki" / "root.key").read_text(encoding="utf-8"), "KEY")
        self.assertEqual((self.state / "data" / "edge_token").read_text(encoding="utf-8"), "a" * 64)
        self.assertEqual((self.cfg / "om.env").read_text(encoding="utf-8"), "OM_LAN_IP=off\n")
        self.assertTrue((self.state / "routes" / "zz-app.caddy").exists())
        self.assertTrue((self.state / "auth" / "private.conf").exists())
        self.assertEqual(json.loads((self.state / "registry" / "workspaces.json").read_text(encoding="utf-8")), {"zz": {}})
        self.assertTrue((self.state / "logs" / "heal.log").exists())
        # om's own core route is program code: it stays
        self.assertTrue((self.home / "core" / "caddy" / "conf.d" / "portainer.caddy").exists())
        self.assertFalse((self.home / "core" / "caddy" / "conf.d" / "zz-app.caddy").exists())
        self.assertFalse((self.home / "core" / "data").exists())
        self.assertFalse((self.home / "config").exists())

    def test_idempotent(self):
        self.migrate()
        self.assertEqual(self.migrate(), {"present": False, "moved": [], "after": False})

    def test_never_overwrites_newer_state(self):
        (self.state / "data").mkdir(parents=True)
        (self.state / "data" / "edge_token").write_text("b" * 64, encoding="utf-8", newline="\n")
        self.migrate()
        self.assertEqual((self.state / "data" / "edge_token").read_text(encoding="utf-8"), "b" * 64)
        parked = self.home / "core" / "data" / "edge_token.pre-migration"
        self.assertEqual(parked.read_text(encoding="utf-8"), "a" * 64)
        self.assertEqual(self.migrate()["moved"], [])  # parked copies are not legacy state


class TestCrossPlatform(unittest.TestCase):
    """Behavior that must be identical on Linux, macOS and Windows."""

    # Shape of `podman system connection list --format json` on a podman machine (macOS/Windows)
    MACHINE = json.dumps([
        {"Name": "podman-machine-default", "URI": "ssh://core@127.0.0.1:53210/run/user/501/podman/podman.sock",
         "Identity": "/Users/me/.local/share/containers/podman/machine/machine", "Default": True},
        {"Name": "podman-machine-default-root", "URI": "ssh://root@127.0.0.1:53210/run/podman/podman.sock",
         "Default": False},
    ])

    def test_vm_socket_is_the_one_inside_the_vm(self):
        self.assertEqual(core.vm_socket_from_connections(self.MACHINE), "/run/user/501/podman/podman.sock")
        rootful = json.loads(self.MACHINE)
        rootful[0]["Default"], rootful[1]["Default"] = False, True
        self.assertEqual(core.vm_socket_from_connections(json.dumps(rootful)), "/run/podman/podman.sock")
        self.assertEqual(core.vm_socket_from_connections(json.dumps({"Connections": json.loads(self.MACHINE)})),
                         "/run/user/501/podman/podman.sock")  # older podman wraps the list

    def test_vm_socket_bad_input(self):
        for bad in ("", "not json", "[]", json.dumps([{"URI": "unix:///x.sock", "Default": True}])):
            self.assertEqual(core.vm_socket_from_connections(bad), "")

    def test_compose_paths_use_forward_slashes(self):
        from pathlib import PureWindowsPath
        self.assertEqual(PureWindowsPath(r"C:\Users\me\AppData\Local\om").as_posix(), "C:/Users/me/AppData/Local/om")
        self.assertNotIn("\\", core.compose_path(core.STATE_DIR))

    def test_generated_files_are_utf8_and_lf(self):
        core.write_private(core.STATE_DIR / "t.env", "ICON=🔍\nB=2\n")
        raw = (core.STATE_DIR / "t.env").read_bytes()
        self.assertEqual(raw, "ICON=🔍\nB=2\n".encode("utf-8"))
        self.assertEqual(core.parse_env_file(core.STATE_DIR / "t.env")["ICON"], "🔍")


if __name__ == "__main__":
    unittest.main()
