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
        core.USER_ENV.write_text("LAN_IP=10.1.2.3\nTAILSCALE_IP=off\nOM_WALLPAPERS_DIR=/tmp/wp\n", encoding="utf-8", newline="\n")
        r = core.resolve_settings()
        self.assertEqual(r["lan_ip"], "10.1.2.3")
        self.assertEqual((r["vpn_ips"], r["vpn_names"]), ([], []))  # no VPN unless trusted
        self.assertTrue(r["wallpapers_dir"].endswith("wp"))

    def test_off_disables_lan(self):
        core.USER_ENV.write_text("OM_LAN_IP=off\nOM_VPN=off\n", encoding="utf-8", newline="\n")
        self.assertEqual(core.resolve_settings()["lan_ip"], "")

    def test_vpn_list_takes_only_local_addresses(self):
        self.assertEqual(core.detect_vpn("off"), ([], []))
        from unittest import mock
        with mock.patch.object(core, "_reverse_names", return_value=[]):
            self.assertEqual(core.detect_vpn("127.0.0.1,192.0.2.77"), (["127.0.0.1"], []))  # 192.0.2.77 is not this host's

    def test_no_vpn_is_trusted_by_itself(self):
        self.assertEqual(core.vpn_items(""), [])
        self.assertEqual(core.vpn_items("auto"), [])            # the old default trusts nothing now
        self.assertEqual(core.vpn_items("off"), [])
        self.assertEqual(core.vpn_items("tailscale0, wg0,wg0"), ["tailscale0", "wg0"])

    def test_vpn_detection_uses_kernel_kinds_not_names(self):
        from unittest import mock
        links = ('[{"ifname":"lo"},{"ifname":"eno1"},{"ifname":"home-vpn","linkinfo":{"info_kind":"wireguard"}},'
                 '{"ifname":"x7","linkinfo":{"info_kind":"tun"}},{"ifname":"podman0","linkinfo":{"info_kind":"bridge"}}]')
        ok = mock.Mock(returncode=0, stdout=links)
        with mock.patch.object(core, "run", return_value=ok), mock.patch.object(core, "_iface_ipv4", return_value="10.9.0.2"):
            self.assertEqual(core.vpn_candidates(), [("home-vpn", "10.9.0.2"), ("x7", "10.9.0.2")])

    def test_vpn_detection_on_macos_and_windows(self):
        from unittest import mock
        mac_ifconfig = ("lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000\n"
                        "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tinet 192.168.1.9 netmask 0xffffff00\n"
                        "utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1280\n\tinet 100.70.1.2 --> 100.70.1.2\n"
                        "feth1: flags=8863<UP,BROADCAST,RUNNING> mtu 2800\n\tinet 10.147.17.5 netmask 0xffffff00\n"
                        "utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380\n")
        def mac_run(cmd, **kw):
            out = {"networksetup": "Hardware Port: Wi-Fi\nDevice: en0\n", "ifconfig": mac_ifconfig}.get(cmd[0], "")
            return mock.Mock(returncode=0 if cmd[0] != "ip" else 1, stdout=out)
        with mock.patch.object(core, "IS_WINDOWS", False), mock.patch.object(core, "run", side_effect=mac_run):
            self.assertEqual(core.vpn_candidates(), [("utun4", "100.70.1.2"), ("feth1", "10.147.17.5")])  # incl. ZeroTier
        win = mock.Mock(returncode=0, stdout="Tailscale\t100.70.1.3\nZeroTier One [8056c2e21c]\t10.147.17.6\nvEthernet (WSL)\t\n")
        with mock.patch.object(core, "IS_WINDOWS", True), mock.patch.object(core, "run", return_value=win):
            self.assertEqual(core.vpn_candidates(), [("Tailscale", "100.70.1.3"), ("ZeroTier One [8056c2e21c]", "10.147.17.6")])
            self.assertEqual(core._iface_ipv4("tailscale"), "100.70.1.3")
        scutil = mock.Mock(returncode=0, stdout="resolver #1\n  nameserver[0] : 192.168.1.1\nresolver #2\n  nameserver[0] : 100.100.100.100\n")
        with mock.patch.object(core, "IS_WINDOWS", False), mock.patch.object(core, "IS_MACOS", True), mock.patch.object(core, "run", return_value=scutil):
            self.assertEqual(core._nameservers(), ["192.168.1.1", "100.100.100.100"])

    def test_ptr_answer_is_parsed(self):
        # a PTR response for 5.253.117.100.in-addr.arpa → box.example.ts.net (name compression in the answer)
        qname = b"\x015\x03253\x03117\x03100\x07in-addr\x04arpa\x00"
        rdata = b"\x03box\x07example\x02ts\x03net\x00"
        resp = (b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + qname + b"\x00\x0c\x00\x01"
                + b"\xc0\x0c\x00\x0c\x00\x01\x00\x00\x00\x3c" + len(rdata).to_bytes(2, "big") + rdata)
        from unittest import mock
        sock = mock.MagicMock()
        sock.__enter__.return_value.recv.return_value = resp
        with mock.patch.object(core.socket, "socket", return_value=sock), mock.patch.object(core.secrets, "randbits", return_value=0x1234):
            self.assertEqual(core._ptr_query("100.117.253.5", "100.100.100.100"), "box.example.ts.net")

    def test_core_has_no_retired_parts(self):
        for c in ("om_wg", "om_gate", "portainer"):
            self.assertNotIn(c, core.CORE_CONTAINERS)
        self.assertNotIn("--profile", core.core_compose("podman", "up"))


class TestPorts(unittest.TestCase):
    def test_tiers_map_to_separate_container_ports(self):
        y = core.render_ports({"lan_ip": "192.168.9.9", "vpn_ips": ["100.64.1.1"]})
        self.assertIn('"127.0.0.1:80:80"', y)
        self.assertIn('"100.64.1.1:80:80"', y)          # VPN → private tier
        self.assertIn('"100.64.1.1:8080:8080"', y)      # … and the public tier on 8080
        self.assertIn('"192.168.9.9:80:8080"', y)       # LAN → public tier only
        self.assertIn('"100.64.1.1:20000-20199:20000-20199"', y)   # every service's own private port
        self.assertIn('"192.168.9.9:21000-21199:21000-21199"', y)  # public services' ports on the LAN
        self.assertNotIn('"192.168.9.9:20000', y)                  # private ports never on the LAN
        self.assertNotIn('"192.168.9.9:80:80"', y)
        self.assertNotIn("0.0.0.0", y)
        self.assertNotIn("51820", y)

    def test_disabled_addresses_are_not_bound(self):
        y = core.render_ports({"lan_ip": "", "vpn_ips": []})
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

    def test_vpn_public_tier_only_on_vpn_addresses(self):
        from unittest import mock
        with mock.patch.object(hostsetup, "vpn_ips", return_value=["100.64.1.1"]):
            nft = hostsetup.render_nft([], [])
            self.assertIn("ip daddr { 100.64.1.1 } tcp dport { 8080, 8443, 20000-20199 } accept", nft)
            self.assertIn("tcp dport 21000-21199 accept", nft)          # public services' own ports
            self.assertNotIn("tcp dport { 80, 443, 8080", nft)
            self.assertIn("pass in proto tcp to 100.64.1.1 port { 8080 8443 20000:20199 }", hostsetup.render_pf([], []))
            self.assertIn("-LocalAddress 100.64.1.1 -LocalPort 8080,8443,20000-20199", hostsetup.render_windows([], []))
        with mock.patch.object(hostsetup, "vpn_ips", return_value=[]):
            nft = hostsetup.render_nft([], [])
            self.assertNotIn("8080", nft)
            self.assertNotIn("20000", nft)                               # private service ports: VPN only

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


class _Proc:
    def __init__(self, out="", code=0):
        self.stdout, self.stderr, self.returncode = out, "", code


class TestEngineLifecycle(unittest.TestCase):
    """Local Podman: om raises its own oom_score_adj to the systemd units' value; never a unit around podman."""

    def setUp(self):
        from unittest import mock
        self.mock = mock
        self.proc = Path(tempfile.mkdtemp()) / "oom_score_adj"
        self.addCleanup(shutil.rmtree, self.proc.parent, True)

    def _match(self, current, target):
        self.proc.write_text(str(current), encoding="utf-8")
        with self.mock.patch.object(core, "_unit_oom_score_adj", return_value=target):
            core._match_unit_oom(self.proc)
        return int(self.proc.read_text(encoding="utf-8"))

    def test_raised_to_the_units_value_never_lowered(self):
        self.assertEqual(self._match(0, 200), 200)
        self.assertEqual(self._match(300, 200), 300)
        self.assertEqual(self._match(0, None), 0)          # no systemd user manager: untouched

    def test_command_is_always_the_plain_engine_command(self):
        for runtime, local in (("podman", True), ("podman", False), ("docker", True)):
            with self.mock.patch.object(core, "_local_engine", return_value=local), \
                    self.mock.patch.object(core, "_match_unit_oom") as m:
                self.assertEqual(core.engine_lifecycle(runtime, "restart", "x"), [runtime, "restart", "x"])
            self.assertEqual(m.called, runtime == "podman" and local, runtime)

    def test_no_systemd_off_linux(self):
        core._unit_oom_score_adj.cache_clear()
        self.addCleanup(core._unit_oom_score_adj.cache_clear)
        with self.mock.patch.object(core, "IS_LINUX", False):
            self.assertIsNone(core._unit_oom_score_adj())


class TestZombieContainers(unittest.TestCase):
    """Podman keeps listing a container as running after its conmon was killed; om must notice."""

    def setUp(self):
        from unittest import mock
        self.mock = mock
        core._local_engine.cache_clear()
        for name, value in (("_local_engine", True), ("_match_unit_oom", None)):  # never touch the runner's own oom_score_adj
            p = mock.patch.object(core, name, return_value=value)
            p.start()
            self.addCleanup(p.stop)

    def test_dead_pid_is_gone_live_pid_is_not(self):
        self.assertTrue(core._process_gone("podman", 2 ** 22 + 12345))
        self.assertFalse(core._process_gone("podman", os.getpid()))
        self.assertFalse(core._process_gone("podman", 0))
        self.assertFalse(core._process_gone("podman", "not-a-pid"))

    def test_podman_machine_uses_engine_top_and_needs_two_failures(self):
        seq = iter([_Proc(code=125), _Proc(code=0)])
        with self.mock.patch.object(core, "_local_engine", return_value=False), \
                self.mock.patch.object(core, "_vm_engine", return_value=True), \
                self.mock.patch.object(core.time, "sleep"), \
                self.mock.patch.object(core, "run", side_effect=lambda *a, **k: next(seq)):
            self.assertFalse(core._process_gone("podman", 5, "x"))    # one failure, then ok: transient
        with self.mock.patch.object(core, "_local_engine", return_value=False), \
                self.mock.patch.object(core, "_vm_engine", return_value=True), \
                self.mock.patch.object(core.time, "sleep"), \
                self.mock.patch.object(core, "run", return_value=_Proc(code=125)):
            self.assertTrue(core._process_gone("podman", 5, "x"))

    def test_docker_on_linux_is_judged_through_proc(self):
        self.assertTrue(core._process_gone("docker", 2 ** 22 + 12345, "x"))
        self.assertFalse(core._process_gone("docker", os.getpid(), "x"))

    def test_watch_refuses_unsupported_engines(self):
        with self.mock.patch.object(core, "_local_engine", return_value=False):
            self.assertEqual(core.watch("podman"), 1)

    def test_unknown_engines_are_never_judged(self):
        with self.mock.patch.object(core, "_local_engine", return_value=False), \
                self.mock.patch.object(core, "_vm_engine", return_value=False):
            self.assertFalse(core._process_gone("docker", 2 ** 22 + 12345, "x"))

    def test_container_running_requires_a_live_process(self):
        dead = _Proc(f"true {2 ** 22 + 12345}")
        live = _Proc(f"true {os.getpid()}")
        with self.mock.patch.object(core, "run", return_value=dead):
            self.assertFalse(core.container_running("podman", "x"))
        with self.mock.patch.object(core, "run", return_value=live):
            self.assertTrue(core.container_running("podman", "x"))
        with self.mock.patch.object(core, "run", return_value=_Proc("false 0")):
            self.assertFalse(core.container_running("podman", "x"))

    def test_only_om_containers_are_zombies(self):
        gone = 2 ** 22 + 12345
        inspect = (f"/om_egress|{gone}|true|\n/svc|{gone}||ws\n/other|{gone}||\n/novalue|{gone}|<no value>|<no value>\n"
                   f"/live|{os.getpid()}|true|\n")
        def fake(cmd, **kw):
            return _Proc(inspect) if cmd[1] == "container" else _Proc("om_egress svc other novalue live")
        with self.mock.patch.object(core, "run", side_effect=fake):
            self.assertEqual(core.zombie_containers("podman"), ["om_egress", "svc"])
            self.assertEqual(core.zombie_containers("docker"), ["om_egress", "svc"])

    def test_revive_stops_then_starts_and_removes_failed_core(self):
        calls = []
        def fake(cmd, **kw):
            calls.append(cmd[1:3])
            return _Proc(code=1 if cmd[1] == "start" and cmd[-1] == "om_egress" else 0)
        with self.mock.patch.object(core, "zombie_containers", return_value=["om_egress", "svc"]), \
                self.mock.patch.object(core, "run", side_effect=fake):
            self.assertEqual(core.revive_zombies("podman"), (["svc"], ["om_egress"]))
        self.assertIn(["rm", "-f"], calls)
        self.assertEqual(calls.count(["stop", "-t"]), 2)

    def test_unhealthy_restart_waits_and_respects_cooldown(self):
        core.HEAL_STATE.unlink(missing_ok=True)
        self.addCleanup(core.HEAL_STATE.unlink, True)
        ps = _Proc("job\n")
        restarts = []
        def fake(cmd, **kw):
            if cmd[1] == "restart":
                restarts.append(cmd[-1])
                return _Proc()
            return ps
        with self.mock.patch.object(core, "run", side_effect=fake):
            self.assertEqual(core.restart_unhealthy("podman", now=1000), [])       # first sighting
            self.assertEqual(core.restart_unhealthy("podman", now=1000 + 599), [])  # not yet 10 min
            self.assertEqual(core.restart_unhealthy("podman", now=1000 + 600), ["job"])
            self.assertEqual(core.restart_unhealthy("podman", now=1000 + 1300), [])  # cooldown
            self.assertEqual(core.restart_unhealthy("podman", now=1000 + 600 + 3600 + 600), ["job"])
        self.assertEqual(restarts, ["job", "job"])


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
