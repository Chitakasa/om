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


class TestFileHelpers(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="om-files-"))
        self.addCleanup(shutil.rmtree, self.dir, True)

    @unittest.skipIf(os.name == "nt", "POSIX modes")
    def test_private_file_is_0600_and_replaced_in_one_step(self):
        p = self.dir / "sub" / "secret"
        core.write_private_bytes(p, b"one")
        core.write_private(p, "two\n")
        self.assertEqual(p.read_text(encoding="utf-8"), "two\n")
        self.assertEqual(p.stat().st_mode & 0o777, 0o600)
        self.assertEqual([f.name for f in p.parent.iterdir()], ["secret"])

    def test_write_atomic_leaves_no_temp_file(self):
        p = self.dir / "a" / "route.caddy"
        core.write_atomic(p, "x\n")
        core.write_atomic(p, "y\n")
        self.assertEqual(p.read_text(encoding="utf-8"), "y\n")
        self.assertEqual([f.name for f in p.parent.iterdir()], ["route.caddy"])

    def test_systemd_unit_words_are_quoted_and_escaped(self):
        self.assertEqual(hostsetup._unit_exec(["/opt/my om/bin/om", "core", "100%"]), '"/opt/my om/bin/om" "core" "100%%"')
        self.assertEqual(hostsetup._unit_arg('a"b\\c'), '"a\\"b\\\\c"')

    @unittest.skipIf(os.name == "nt", "POSIX modes")
    def test_doctor_flags_loose_secret_files(self):
        from gitops import doctor
        token, saved = self.dir / "edge_token", core.TOKEN_FILE
        token.write_text("x", encoding="utf-8")
        os.chmod(token, 0o644)
        core.TOKEN_FILE = token
        try:
            self.assertEqual(doctor.check_secret_modes()[0], doctor.WARN)
            os.chmod(token, 0o600)
            self.assertEqual(doctor.check_secret_modes()[0], doctor.PASS)
        finally:
            core.TOKEN_FILE = saved


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
        # a PTR response for 2.0.64.100.in-addr.arpa → box.example.ts.net (name compression in the answer)
        qname = b"\x012\x010\x0264\x03100\x07in-addr\x04arpa\x00"
        rdata = b"\x03box\x07example\x02ts\x03net\x00"
        resp = (b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + qname + b"\x00\x0c\x00\x01"
                + b"\xc0\x0c\x00\x0c\x00\x01\x00\x00\x00\x3c" + len(rdata).to_bytes(2, "big") + rdata)
        from unittest import mock
        sock = mock.MagicMock()
        sock.__enter__.return_value.recv.return_value = resp
        with mock.patch.object(core.socket, "socket", return_value=sock), mock.patch.object(core.secrets, "randbits", return_value=0x1234):
            self.assertEqual(core._ptr_query("100.64.0.2", "100.100.100.100"), "box.example.ts.net")

    def test_core_has_no_retired_parts(self):
        for c in ("om_wg", "om_gate", "portainer"):
            self.assertNotIn(c, core.CORE_CONTAINERS)
        self.assertNotIn("--profile", core.core_compose("podman", "up"))


class TestPorts(unittest.TestCase):
    def test_tiers_map_to_separate_container_ports(self):
        y = core.render_ports({"lan_ip": "192.168.9.9", "vpn_ips": ["100.64.1.1"]})
        self.assertIn('"127.0.0.1:80:80"', y)
        self.assertIn('"100.64.1.1:80:81"', y)          # VPN → private tier, on its own edge port
        self.assertIn('"100.64.1.1:443:444"', y)
        self.assertNotIn('"100.64.1.1:80:80"', y)       # never the loopback-only *.localhost sites
        self.assertIn('"100.64.1.1:8080:8080"', y)      # … and the public tier on 8080
        self.assertIn('"192.168.9.9:80:8080"', y)       # LAN → public tier only
        self.assertIn('"100.64.1.1:20000-20199:20000-20199"', y)   # every service's own private port
        self.assertIn('"192.168.9.9:21000-21199:21000-21199"', y)  # public services' ports on the LAN
        self.assertNotIn('"192.168.9.9:20000', y)                  # private ports never on the LAN
        self.assertNotIn('"192.168.9.9:80:80"', y)
        self.assertNotIn("0.0.0.0", y)
        self.assertNotIn("51820", y)

    def test_unenforced_vpn_allow_list_leaves_the_vpn_private_tier_unbound(self):
        y = core.render_ports({"lan_ip": "192.168.9.9", "vpn_ips": ["100.64.1.1"], "vpn_private": False})
        self.assertNotIn('"100.64.1.1:80:81"', y)
        self.assertNotIn('"100.64.1.1:20000-20199', y)
        self.assertIn('"100.64.1.1:8080:8080"', y)                     # guests keep the public tier
        self.assertIn('"100.64.1.1:21000-21199:21000-21199"', y)
        self.assertIn('"127.0.0.1:80:80"', y)                          # this machine is unaffected

    def test_vpn_allow_setting_is_normalized(self):
        self.assertEqual(core.vpn_allow({"OM_VPN_ALLOW": "100.64.0.10, nope,100.64.0.0/10,100.64.0.10"}),
                         ["100.64.0.10/32", "100.64.0.0/10"])
        self.assertEqual(core.vpn_allow({"OM_VPN_ALLOW": ""}), [])

    def test_disabled_addresses_are_not_bound(self):
        y = core.render_ports({"lan_ip": "", "vpn_ips": []})
        self.assertNotIn("8080", y)
        self.assertNotIn("100.", y)


class TestNetPolicyStore(unittest.TestCase):
    def test_replaced_per_workspace_and_released_with_its_ports(self):
        core.set_net_policies("w1", {"a": {"ports": [20001], "allow": None, "deny": ["10.0.0.0/8"]}})
        core.set_net_policies("w2", {"b": {"ports": [20002], "allow": ["100.64.0.5/32"], "deny": []}})
        core.set_net_policies("w1", {})
        self.assertEqual(sorted(core.net_policies()), ["w2/b"])
        core.release_slots("w2")
        self.assertEqual(core.net_policies(), {})


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
        self.assertIn("block in log all", hostsetup.render_pf([], []))     # refusals are logged (pflog0)
        self.assertIn("-LocalPort 80,443", hostsetup.render_windows([], []))

    def test_vpn_public_tier_only_on_vpn_addresses(self):
        from unittest import mock
        with mock.patch.object(hostsetup, "vpn_ips", return_value=["100.64.1.1"]):
            nft = hostsetup.render_nft([], [])
            self.assertIn("ip daddr { 100.64.1.1 } tcp dport { 8080, 8443, 20000-20199 } accept", nft)
            self.assertIn("tcp dport 21000-21199 accept", nft)          # public services' own ports
            self.assertFalse([l for l in nft.splitlines() if "tcp dport { 80, 443, 8080" in l and l.endswith("accept")])
            self.assertIn("pass in proto tcp to 100.64.1.1 port { 8080 8443 20000:20199 }", hostsetup.render_pf([], []))
            self.assertIn("-LocalAddress 100.64.1.1 -LocalPort 8080,8443,20000-20199", hostsetup.render_windows([], []))
        with mock.patch.object(hostsetup, "vpn_ips", return_value=[]):
            nft = hostsetup.render_nft([], [])
            accepts = [l for l in nft.splitlines() if l.strip().endswith("accept")]
            self.assertFalse([l for l in accepts if "8080" in l or "20000" in l])  # private service ports: VPN only

    def test_net_rules_drop_before_any_accept(self):
        from unittest import mock
        pols = {"ws/a": {"ports": [20001, 21001], "allow": ["100.101.0.7/32"], "deny": ["192.168.1.66/32"]}}
        with mock.patch.object(hostsetup, "net_policies", return_value=pols), mock.patch.object(hostsetup, "vpn_ips", return_value=[]), \
                mock.patch.object(hostsetup, "vpn_allow", return_value=[]):
            nft, pf = hostsetup.render_nft([], []), hostsetup.render_pf([], [])
        rule = nft.index("ct direction original tcp dport { 20001, 21001 } ip saddr != { 100.101.0.7/32 } drop")
        self.assertLess(nft.index('iifname "lo" accept'), rule)                  # this machine is always allowed
        self.assertLess(rule, nft.index("tcp dport { 80, 443 } accept"))
        self.assertLess(rule, nft.index("ct state { established, related } accept"))  # open connections are cut too
        self.assertIn("ct direction original tcp dport { 20001, 21001 } meta nfproto ipv6 drop", nft)   # IPv4-only allow-list: no IPv6
        self.assertIn("ct direction original tcp dport { 20001, 21001 } ip saddr { 192.168.1.66/32 } drop", nft)
        self.assertLess(pf.index("table <om_"), pf.index("block in log all"))   # tables: pf's `! {a b}` blocks all
        self.assertIn("block drop in log quick proto tcp from ! <om_", pf)
        self.assertLess(pf.index("block drop in log quick"), pf.index("pass in proto tcp"))

    def test_rootful_engines_forward_path_carries_the_same_rules(self):
        from unittest import mock
        pols = {"ws/a": {"ports": [20001], "allow": ["100.64.0.5/32"], "deny": []}}
        with mock.patch.object(hostsetup, "net_policies", return_value=pols), mock.patch.object(hostsetup, "vpn_ips", return_value=[]), \
                mock.patch.object(hostsetup, "vpn_allow", return_value=[]):
            nft = hostsetup.render_nft([], [])
        fwd = nft[nft.index("chain forward"):]
        self.assertIn("type filter hook forward priority filter - 10; policy accept;", fwd)   # touches nothing else
        self.assertIn("meta l4proto tcp ct status dnat ct original proto-dst { 20001 } ct original ip saddr != { 100.64.0.5/32 } drop", fwd)
        with mock.patch.object(hostsetup, "net_policies", return_value={}), mock.patch.object(hostsetup, "vpn_ips", return_value=[]), \
                mock.patch.object(hostsetup, "vpn_allow", return_value=[]):
            fwd = hostsetup.render_nft([], [])
            self.assertNotIn(" drop", fwd[fwd.index("chain forward"):])                 # no rules: logging only

    def test_vpn_allow_list_closes_the_private_tier_to_other_vpn_devices(self):
        from unittest import mock
        with mock.patch.object(hostsetup, "net_policies", return_value={}), mock.patch.object(hostsetup, "vpn_ips", return_value=["100.64.1.1"]), \
                mock.patch.object(hostsetup, "vpn_allow", return_value=["100.64.0.10/32"]):
            nft, pf, win = hostsetup.render_nft([], []), hostsetup.render_pf([], []), hostsetup.render_windows([], [])
        self.assertIn("ct direction original ip daddr { 100.64.1.1 } tcp dport { 80, 443, 20000-20199 } ip saddr != { 100.64.0.10/32 } drop", nft)
        self.assertIn("ct direction original ip daddr { 100.64.1.1 } udp dport { 443 } ip saddr != { 100.64.0.10/32 } drop", nft)      # HTTP/3
        self.assertNotIn("dport { 8080", nft.split("# Front door")[0])                     # the public tier stays for guests
        self.assertIn("ct original ip daddr { 100.64.1.1 } ct original proto-dst { 80, 443, 20000-20199 }", nft)
        self.assertIn("to { 100.64.1.1 } port { 80 443 20000:20199 }", pf)
        self.assertIn("-LocalAddress 100.64.1.1 -LocalPort 80,443,20000-20199", win)
        self.assertNotIn("::/", win.split("om net vpn")[1].split("\n")[0])                  # IPv4 address: no IPv6 complement

    def test_vpn_devices_outside_the_list_get_the_public_tier_at_the_same_address(self):
        from unittest import mock
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        with mock.patch.object(hostsetup, "net_policies", return_value={}), mock.patch.object(hostsetup, "vpn_ips", return_value=["100.64.1.1"]), \
                mock.patch.object(hostsetup, "vpn_allow", return_value=["100.64.0.10/32"]):
            nft, pf = hostsetup.render_nft([], []), hostsetup.render_pf([], [])
            nat = nft[nft.index("chain vpn_public"):]
            self.assertIn("type nat hook prerouting priority dstnat - 10; policy accept;", nat)
            self.assertIn("ip daddr 100.64.1.1 ip saddr != { 100.64.0.10/32 } tcp dport 80 dnat ip to 100.64.1.1:8080", nat)
            self.assertIn("ip daddr 100.64.1.1 ip saddr != { 100.64.0.10/32 } tcp dport 443 dnat ip to 100.64.1.1:8443", nat)
            self.assertIn("tcp dport { 80, 443, 20000-20199 } ip saddr != { 100.64.0.10/32 } drop", nft)  # open connections still cut
            rdr = "rdr proto tcp from ! <om_"
            self.assertIn("to 100.64.1.1 port 80 -> 100.64.1.1 port 8080", pf)
            self.assertLess(pf.index("table <om_"), pf.index(rdr))
            self.assertLess(pf.index(rdr), pf.index("block in log all"))               # pf: translation before filtering
            f = d / "om.nft"
            with mock.patch.object(hostsetup, "IS_LINUX", True), mock.patch.object(hostsetup, "NFT_INSTALLED", f):
                self.assertFalse(hostsetup.vpn_fallback_applied())                      # not applied yet
                f.write_text(nft, encoding="utf-8")
                self.assertTrue(hostsetup.vpn_fallback_applied())
            with mock.patch.object(hostsetup, "vpn_allow", return_value=["100.64.0.10/32", "100.64.0.20/32"]), \
                    mock.patch.object(hostsetup, "IS_LINUX", True), mock.patch.object(hostsetup, "NFT_INSTALLED", f):
                self.assertFalse(hostsetup.vpn_fallback_applied())                      # list changed: not yet applied
        with mock.patch.object(hostsetup, "net_policies", return_value={}), mock.patch.object(hostsetup, "vpn_ips", return_value=["100.64.1.1"]), \
                mock.patch.object(hostsetup, "vpn_allow", return_value=[]):
            self.assertNotIn("chain vpn_public", hostsetup.render_nft([], []))           # no list: every device is private
            self.assertNotIn("rdr ", hostsetup.render_pf([], []))

    def test_every_refusal_and_connection_is_logged_but_not_quiet_services(self):
        from unittest import mock
        pols = {"ws/a": {"ports": [20001], "allow": ["100.64.0.5/32"], "deny": []}}
        with mock.patch.object(hostsetup, "net_policies", return_value=pols), mock.patch.object(hostsetup, "vpn_ips", return_value=[]), \
                mock.patch.object(hostsetup, "vpn_allow", return_value=[]), mock.patch.object(hostsetup, "no_log_ports", return_value=[20002]):
            nft = hostsetup.render_nft([], [])
        lines = [l.strip() for l in nft.splitlines()]
        drop = lines.index("ct direction original tcp dport { 20001 } ip saddr != { 100.64.0.5/32 } drop")
        self.assertIn('log prefix "om-refused ws/a: "', lines[drop - 1])                # logged by its own rule, first
        self.assertNotIn(" drop", lines[drop - 1])                                       # the log rule never decides
        inlog = next(l for l in lines if 'prefix "om-in: "' in l and "ct original" not in l)
        self.assertIn("tcp dport != { 20002 }", inlog)                                   # om.log=off: no trace
        last = [l for l in lines[:lines.index("chain forward {")] if l and l != "}"][-1]   # input chain's last rule
        self.assertTrue(last.startswith("meta pkttype host ct state new") and 'prefix "om-refused: "' in last)

    def test_vpn_keyword_is_expanded_when_rendered_and_goes_stale_with_the_list(self):
        from unittest import mock
        pol = {"ports": [21001], "allow": ["vpn", "192.168.1.20/32"], "deny": []}
        with mock.patch.object(hostsetup, "vpn_allow", return_value=["100.64.0.10/32"]):
            rules = hostsetup.nft_net_rules("ws/a", pol)
            self.assertIn("ct direction original tcp dport { 21001 } ip saddr != { 192.168.1.20/32, 100.64.0.10/32 } drop", rules)
            self.assertIn("100.64.0.10/32", hostsetup.pf_net_rules("ws/a", pol)[0][0])
            name_before = hostsetup.win_net_rules("ws/a", pol)[0][0]
        with mock.patch.object(hostsetup, "vpn_allow", return_value=["100.64.0.10/32", "100.64.0.20/32"]):
            self.assertIn("100.64.0.20/32", hostsetup.nft_net_rules("ws/a", pol)[1])   # the label follows the list
            self.assertNotEqual(hostsetup.win_net_rules("ws/a", pol)[0][0], name_before)  # applied rule is now stale

    def test_windows_blocks_everything_but_the_allowed(self):
        import ipaddress
        pol = {"ports": [21001], "allow": ["100.64.0.5/32"], "deny": []}
        name, line = hostsetup.win_net_rules("ws/a", pol)[0]
        blocked = [ipaddress.ip_network(n) for n in line.split("-RemoteAddress ")[1].split(" ")[0].split(",")]
        self.assertFalse(any(ipaddress.ip_address("100.64.0.5") in n for n in blocked))
        for a in ("100.64.0.4", "100.64.0.6", "1.1.1.1", "255.255.255.255", "fd7a::1"):
            self.assertTrue(any(ipaddress.ip_address(a) in n for n in blocked), a)
        self.assertIn("-Action Block", line)
        changed = hostsetup.win_net_rules("ws/a", dict(pol, allow=["100.64.0.6/32"]))[0][0]
        self.assertNotEqual(name, changed)                                        # a stale rule is noticed by name

    def test_enforced_only_when_applied_and_active(self):
        from unittest import mock
        pol = {"ports": [20001], "allow": ["100.64.0.5/32"], "deny": []}
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        f = d / "om.nft"
        with mock.patch.object(hostsetup, "IS_LINUX", True), mock.patch.object(hostsetup, "NFT_INSTALLED", f), \
                mock.patch.object(hostsetup, "net_policies", return_value={"ws/a": pol}), \
                mock.patch.object(hostsetup, "vpn_ips", return_value=[]), mock.patch.object(hostsetup, "vpn_allow", return_value=[]):
            with mock.patch.object(hostsetup, "firewall_status", return_value="active"):
                self.assertFalse(hostsetup.net_policy_enforced("ws/a", pol))     # not applied yet
                full = hostsetup.render_nft([], [])
                f.write_text(full.split("    chain forward")[0], encoding="utf-8")
                self.assertFalse(hostsetup.net_policy_enforced("ws/a", pol))     # inbound path only: not enough
                f.write_text(full, encoding="utf-8")
                self.assertTrue(hostsetup.net_policy_enforced("ws/a", pol))
                f.write_text("\n".join(l for l in full.splitlines() if "log prefix" not in l), encoding="utf-8")
                self.assertTrue(hostsetup.net_policy_enforced("ws/a", pol))      # applied before logging: still enforced
                self.assertFalse(hostsetup.logging_applied())
                self.assertFalse(hostsetup.net_policy_enforced("ws/a", dict(pol, allow=["100.64.0.6/32"])))
                with mock.patch.object(hostsetup, "net_policies", return_value={}):
                    self.assertEqual(hostsetup.stale_net_rules(), ["ws/a"])        # label removed, rule still applied
            with mock.patch.object(hostsetup, "firewall_status", return_value="inactive"):
                self.assertFalse(hostsetup.net_policy_enforced("ws/a", pol))

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
        from unittest import mock
        with mock.patch.object(core, "engine_info", return_value={"ok": False}):
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


class TestProjectNetworks(unittest.TestCase):
    """Every service folder on its own internal network; the router and egress join each."""

    def setUp(self):
        from unittest import mock
        from gitops import network
        self.mock, self.network = mock, network
        self.cfg = {"services": {"app": {"labels": {"workspace.id": "ws"}}},
                    "networks": {"default": {"name": "ws_net", "external": True}, "other": {"name": "x_net"}}}

    def test_names_and_keys(self):
        n = self.network
        self.assertEqual(n.project_network_name("ws", "services/web"), "ws_services-web_net")
        self.assertEqual(n.project_network_name("ws", ""), "ws_root_net")
        self.assertEqual(n.workspace_network_keys(self.cfg, "ws"), ["default"])   # only the one naming <ws>_net
        shared = {"services": {"app": {"labels": ["om.network=shared"]}}}
        self.assertTrue(n.shares_workspace_network(shared))
        self.assertFalse(n.shares_workspace_network(self.cfg))

    def test_override_points_the_workspace_network_at_the_project_one(self):
        calls = []
        created = set()
        def fake(cmd, **kw):
            calls.append(cmd)
            if cmd[1:3] == ["network", "inspect"]:
                return _Proc(code=0 if cmd[3] in created else 1)
            if cmd[1:3] == ["network", "create"]:
                created.add(cmd[-1])
            return _Proc()
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        with self.mock.patch.object(self.network, "run", side_effect=fake), \
                self.mock.patch.object(self.network, "network_is_internal", return_value=True), \
                self.mock.patch.object(self.network, "project_networks", return_value=["ws_services-web_net"]):
            net, path = self.network.project_network("podman", "ws", "services/web", d / "web", self.cfg)
        self.assertEqual(net, "ws_services-web_net")
        create = next(c for c in calls if c[1:3] == ["network", "create"])
        self.assertIn("--internal", create)
        self.assertIn("om.workspace=ws", create)
        text = path.read_text(encoding="utf-8")
        self.assertIn('"default":\n    name: "ws_services-web_net"\n    external: true', text)
        self.assertIn('"other":\n    name: "ws_services-web_other"\n    internal: true', text)   # its own: per folder, no way out
        path.unlink()

    def test_any_compose_file_is_isolated(self):
        """Implicit default network, a network of its own, another stack's network, a service on neither."""
        cfg = {"services": {"web": {"networks": {"default": None, "backend": None}}, "db": {"networks": {"backend": None}},
                            "tool": {"network_mode": "none"}, "spy": {"networks": {"foreign": None}}},
               "networks": {"default": {"name": "ws_default"}, "backend": {"name": "ws_backend"},
                            "foreign": {"name": "other_stack_net", "external": True}}}
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        with self.mock.patch.object(self.network, "OVERRIDE_DIR", d), \
                self.mock.patch.object(self.network, "run", return_value=_Proc(code=0)), \
                self.mock.patch.object(self.network, "network_is_internal", return_value=True), \
                self.mock.patch.object(self.network, "project_networks", return_value=["ws_app_net"]):
            net, path = self.network.project_network("podman", "ws", "app", d / "app", cfg)
        text = path.read_text(encoding="utf-8")
        self.assertIn('"default":\n    name: "ws_app_net"\n    external: true', text)          # implicit default → its om network
        self.assertIn('"backend":\n    name: "ws_app_backend"\n    internal: true', text)       # not shared with other folders
        self.assertNotIn("other_stack_net", text)                                              # left to the policy gate
        self.assertIn('"db":\n    networks:\n      om_project: {}', text)                    # reachable by the edge
        self.assertIn('"spy":\n    networks:\n      om_project: {}', text)
        self.assertNotIn('"web":\n    networks', text)                                        # already on it
        self.assertNotIn('"tool"', text)                                                       # network_mode: none

    def test_refuses_a_non_internal_network_of_that_name(self):
        with self.mock.patch.object(self.network, "run", return_value=_Proc(code=0)), \
                self.mock.patch.object(self.network, "network_is_internal", return_value=False), \
                self.mock.patch.object(self.network, "project_networks", return_value=["ws_services-web_net"]):
            with self.assertRaises(RuntimeError):
                self.network.project_network("podman", "ws", "services/web", Path("/x/web"), self.cfg)

    def test_shared_or_unjoined_projects_get_no_override(self):
        shared = dict(self.cfg, services={"app": {"labels": {"om.network": "shared"}}})
        with self.mock.patch.object(self.network, "run") as r:
            self.assertEqual(self.network.project_network("podman", "ws", "a", Path("/x/a"), shared), (None, None))
            self.assertEqual(self.network.project_network("podman", "ws", "a", Path("/x/a"), {"services": {}}), (None, None))
            r.assert_not_called()

    def test_router_and_egress_join_every_project_network(self):
        calls = []
        def fake(cmd, **kw):
            calls.append(cmd)
            if cmd[1:3] == ["network", "ls"]:
                return _Proc("ws_services-a_net\nws_services-b_net\n")
            return _Proc()
        with self.mock.patch.object(core, "run", side_effect=fake):
            self.assertEqual(core.connect_router("podman", ["ws"]), [])
        joined = {(c[3], c[4]) for c in calls if c[1:3] == ["network", "connect"]}
        for net in ("ws_net", "ws_services-a_net", "ws_services-b_net"):
            self.assertIn((net, core.ROUTER), joined)
            self.assertIn((net, core.EGRESS), joined)

    def test_egress_proxy_only_where_a_service_may_go_out(self):
        calls = []
        def fake(cmd, **kw):
            calls.append(cmd)
            if cmd[1:3] == ["network", "ls"]:
                return _Proc("ws_services-a_net\nws_services-b_net\n")
            return _Proc()
        with self.mock.patch.object(core, "run", side_effect=fake), \
                self.mock.patch.object(core, "egress_networks", return_value=["ws_services-a_net"]):
            core.connect_router("podman", ["ws"])
        acts = {(c[2], c[-2] if c[2] == "connect" else c[-2], c[-1]) for c in calls if c[1] == "network" and c[2] in ("connect", "disconnect")}
        self.assertIn(("connect", "ws_services-a_net", core.EGRESS), acts)
        self.assertIn(("disconnect", "ws_services-b_net", core.EGRESS), acts)              # not even reachable there
        self.assertIn(("connect", "ws_services-b_net", core.ROUTER), acts)                 # the router reaches every service

    def test_prune_keeps_existing_folders(self):
        calls = []
        def fake(cmd, **kw):
            calls.append(cmd)
            return _Proc()
        with self.mock.patch.object(self.network, "run", side_effect=fake), \
                self.mock.patch.object(self.network, "project_networks", return_value=["ws_a_net", "ws_gone_net"]):
            self.assertEqual(self.network.prune_project_networks("podman", "ws", {"ws_a_net"}), ["ws_gone_net"])
        self.assertNotIn(["podman", "network", "rm", "ws_a_net"], calls)


class TestVpnPeers(unittest.TestCase):
    """Devices on a VPN from the kernel's routes through its interface — no VPN product's tool."""

    def _peers(self, routes, ptr=lambda ip, s, timeout=1.5: ""):
        from unittest import mock
        def fake(cmd, **kw):
            if cmd[:2] == ["ip", "-j"] and "route" in cmd:
                return _Proc(json.dumps(routes))
            return _Proc("[]")
        with mock.patch.object(core, "IS_LINUX", True), mock.patch.object(core, "run", side_effect=fake), \
                mock.patch.object(core, "_vpn_interfaces", return_value=["tun0"]), \
                mock.patch.object(core, "_nameservers", return_value=["100.100.100.100"]), \
                mock.patch.object(core, "_ptr_query", side_effect=ptr), \
                mock.patch.object(core, "resolve_settings", return_value={"vpn_ips": ["100.64.0.2"]}):
            return core.vpn_peers()

    def test_mesh_vpn_one_host_route_per_peer(self):
        routes = [{"dst": "100.64.0.10"}, {"dst": "100.100.100.100"}, {"dst": "100.64.0.30"},
                  {"dst": "100.64.0.2"}, {"dst": "100.64.0.0/10"}]
        self.assertEqual(self._peers(routes), ["100.64.0.10", "100.64.0.30"])   # not its DNS, not this machine

    def test_hub_vpn_subnet_keeps_the_addresses_its_dns_names(self):
        named = {"10.8.0.2": "laptop.vpn", "10.8.0.7": "phone.vpn"}
        peers = self._peers([{"dst": "10.8.0.0/24"}], ptr=lambda ip, s, timeout=1.5: named.get(ip, ""))
        self.assertEqual(peers, ["10.8.0.2", "10.8.0.7"])


class TestMacosRoutes(unittest.TestCase):
    NETSTAT = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
100.64/10          link#25            UCS                 utun4
100.64.0.10       link#25            UHWIi               utun4
192.168.1          link#14            UCS                   en0      !
192.168.1.20       a4:83:e7:1:2:3     UHLWIi                en0   1180
"""

    def test_interface_column_found_by_header_and_abbreviations_expanded(self):
        self.assertEqual(core._macos_routes("utun4", self.NETSTAT), ["100.64.0.0/10", "100.64.0.10/32"])
        self.assertEqual(core._macos_routes("en0", self.NETSTAT), ["0.0.0.0/0", "192.168.1.0/24", "192.168.1.20/32"])
        self.assertEqual(core._bsd_route_dest("10"), "10.0.0.0/8")
        self.assertEqual(core._bsd_route_dest("fe80::%utun4"), "")
