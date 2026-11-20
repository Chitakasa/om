#!/usr/bin/env python3
import unittest

import _env  # noqa: F401  (sets up sandboxed OM_HOME and python path)

from gitops import omstate, stream, wsregistry


class TestStreamLabels(unittest.TestCase):
    def test_default_private_slot_stream(self):
        labels = {"om.tcp": "25565"}
        meta, probs = stream.parse_stream_meta(labels, "mc")
        self.assertEqual(probs, [])
        self.assertIsNotNone(meta)
        self.assertEqual(meta["container_port"], 25565)
        self.assertIsNone(meta["host_port"])
        self.assertEqual(meta["scope"], "private")
        self.assertEqual(meta["log"], "on")

    def test_explicit_host_port_public_and_nolog(self):
        labels = {
            "om.tcp": "25565",
            "om.tcp.port": "25565",
            "dashboard.scope": "public",
            "om.log": "off",
        }
        meta, probs = stream.parse_stream_meta(labels, "mc")
        self.assertEqual(probs, [])
        self.assertIsNotNone(meta)
        self.assertEqual(meta["container_port"], 25565)
        self.assertEqual(meta["host_port"], 25565)
        self.assertEqual(meta["scope"], "public")
        self.assertEqual(meta["log"], "off")

    def test_scope_fails_closed_to_private(self):
        for bad_scope in ("", "pub", "PUBLIC_LAN", "local", "invalid"):
            labels = {"om.tcp": "25565", "dashboard.scope": bad_scope}
            meta, probs = stream.parse_stream_meta(labels, "mc")
            self.assertEqual(probs, [])
            self.assertEqual(meta["scope"], "private")

    def test_reject_privileged_host_ports(self):
        for p in (1, 22, 53, 80, 443, 1023):
            labels = {"om.tcp": "8080", "om.tcp.port": str(p)}
            meta, probs = stream.parse_stream_meta(labels, "svc")
            self.assertIsNone(meta)
            self.assertTrue(any("privileged" in pr or "clashes" in pr for pr in probs), probs)

    def test_reject_reserved_and_clashing_ports(self):
        # Exact clash: 80, 443, 8080, 8443
        for p in (8080, 8443):
            labels = {"om.tcp": "9000", "om.tcp.port": str(p)}
            meta, probs = stream.parse_stream_meta(labels, "svc")
            self.assertIsNone(meta)
            self.assertTrue(any("clashes" in pr for pr in probs), probs)

        # HTTP per-service range: 20000 - 21199
        for p in (20000, 20050, 20199, 21000, 21100, 21199):
            labels = {"om.tcp": "9000", "om.tcp.port": str(p)}
            meta, probs = stream.parse_stream_meta(labels, "svc")
            self.assertIsNone(meta)
            self.assertTrue(any("clashes with HTTP" in pr for pr in probs), probs)

        # Default stream range: 22000 - 22199
        for p in (22000, 22050, 22199):
            labels = {"om.tcp": "9000", "om.tcp.port": str(p)}
            meta, probs = stream.parse_stream_meta(labels, "svc")
            self.assertIsNone(meta)
            self.assertTrue(any("clashes with default stream" in pr for pr in probs), probs)

    def test_reject_invalid_container_ports(self):
        for bad in ("abc", "-1", "0", "70000", "25565a"):
            labels = {"om.tcp": bad}
            meta, probs = stream.parse_stream_meta(labels, "svc")
            self.assertIsNone(meta)
            self.assertTrue(len(probs) > 0)

    def test_no_tcp_label_returns_none_cleanly(self):
        meta, probs = stream.parse_stream_meta({"dashboard.port": "8080"}, "web")
        self.assertIsNone(meta)
        self.assertEqual(probs, [])


class TestStreamRegistry(unittest.TestCase):
    def setUp(self):
        # Reset stream ports file in test sandbox
        self.core = wsregistry
        omstate.STREAM_PORTS_FILE.unlink(missing_ok=True)

    def tearDown(self):
        omstate.STREAM_PORTS_FILE.unlink(missing_ok=True)

    def test_assign_default_stream_slots(self):
        services = {
            "echo": {"container_port": 7, "host_port": None, "scope": "private"},
            "time": {"container_port": 13, "host_port": None, "scope": "public"},
        }
        res = self.core.assign_stream_slots("ws1", services)
        self.assertEqual(len(res), 2)
        self.assertEqual(res["ws1/echo"]["slot"], 0)
        self.assertEqual(res["ws1/echo"]["host_port"], 22000)
        self.assertEqual(res["ws1/time"]["slot"], 1)
        self.assertEqual(res["ws1/time"]["host_port"], 22001)

        # Stable slots on re-assignment
        res2 = self.core.assign_stream_slots("ws1", services)
        self.assertEqual(res2["ws1/echo"]["slot"], 0)
        self.assertEqual(res2["ws1/time"]["slot"], 1)

    def test_assign_explicit_port(self):
        services = {
            "mc": {"container_port": 25565, "host_port": 25565, "scope": "public"},
        }
        res = self.core.assign_stream_slots("ws1", services)
        self.assertIn("ws1/mc", res)
        self.assertEqual(res["ws1/mc"]["host_port"], 25565)
        self.assertIsNone(res["ws1/mc"]["slot"])

    def test_explicit_port_clash_raises(self):
        self.core.assign_stream_slots("ws1", {"mc": {"container_port": 25565, "host_port": 25565, "scope": "public"}})
        with self.assertRaises(RuntimeError) as ctx:
            self.core.assign_stream_slots("ws2", {"mc2": {"container_port": 25565, "host_port": 25565, "scope": "public"}})
        self.assertIn("already reserved", str(ctx.exception))

    def test_release_stream_slots(self):
        self.core.assign_stream_slots("ws1", {
            "s1": {"container_port": 1000, "host_port": None, "scope": "private"},
            "s2": {"container_port": 2000, "host_port": 25565, "scope": "public"},
        })
        self.core.assign_stream_slots("ws2", {
            "s3": {"container_port": 3000, "host_port": None, "scope": "private"},
        })
        self.assertEqual(len(self.core.stream_ports()), 3)

        # Release ws1
        self.core.release_stream_slots("ws1")
        ports = self.core.stream_ports()
        self.assertEqual(len(ports), 1)
        self.assertIn("ws2/s3", ports)
        self.assertNotIn("ws1/s1", ports)
        self.assertNotIn("ws1/s2", ports)

        # Now port 25565 is free for ws2 to claim
        res = self.core.assign_stream_slots("ws2", {
            "s3": {"container_port": 3000, "host_port": None, "scope": "private"},
            "mc": {"container_port": 25565, "host_port": 25565, "scope": "public"},
        })
        self.assertEqual(res["ws2/mc"]["host_port"], 25565)


class TestStreamConfigGeneration(unittest.TestCase):
    def setUp(self):
        import shutil
        if stream.STREAM_DIR.exists():
            shutil.rmtree(stream.STREAM_DIR)
        stream.ensure_stream_configs()

    def tearDown(self):
        import shutil
        if stream.STREAM_DIR.exists():
            shutil.rmtree(stream.STREAM_DIR)

    def test_fragments_rendering(self):
        edge = stream.render_edge_fragment("ws", "mc", 25565, log="off")
        self.assertIn("frontend stream_25565", edge)
        self.assertIn("bind :25565", edge)
        self.assertIn("default_backend sock_25565", edge)
        self.assertNotIn("option tcplog", edge)

        edge_log = stream.render_edge_fragment("ws", "mc", 25565, log="on")
        self.assertIn("option tcplog", edge_log)

        router = stream.render_router_fragment("ws", "mc", 25565, 25565)
        self.assertIn("frontend sock_25565", router)
        self.assertIn("bind /run/om-stream/25565.sock mode 660", router)
        self.assertIn("server s1 ws_mc:25565", router)

    def test_sync_stream_routes_and_atomic_update(self):
        services = {
            "mc": {"host_port": 25565, "container_port": 25565, "log": "off", "scope": "public"}
        }
        ok = stream.sync_stream_routes("ws", services, runtime="om-test-no-engine")
        self.assertTrue(ok)
        edge_cfg = stream.EDGE_CONFIG_FILE.read_text(encoding="utf-8")
        router_cfg = stream.ROUTER_CONFIG_FILE.read_text(encoding="utf-8")
        self.assertIn("stream_25565", edge_cfg)
        self.assertIn("sock_25565", edge_cfg)
        self.assertIn("ws_mc:25565", router_cfg)

    def test_invalid_config_leaves_live_untouched(self):
        # Establish known valid state
        stream.sync_stream_routes("ws", {"mc": {"host_port": 25565, "container_port": 25565, "log": "on"}}, "om-test-no-engine")
        live_edge = stream.EDGE_CONFIG_FILE.read_text(encoding="utf-8")

        # Manually drop a corrupt fragment
        corrupt = stream.EDGE_FRAGMENTS_DIR / "bad.cfg"
        corrupt.write_text("invalid directive outside sections\n", encoding="utf-8")

        # Sync another service; assembly will fail validation and leave live_edge untouched
        ok = stream.sync_stream_routes("ws2", {"svc": {"host_port": 22000, "container_port": 80}}, "om-test-no-engine")
        self.assertFalse(ok)
        self.assertEqual(stream.EDGE_CONFIG_FILE.read_text(encoding="utf-8"), live_edge)

    def test_prune_stream_fragments(self):
        stream.sync_stream_routes("ws1", {"mc": {"host_port": 25565, "container_port": 25565}}, "om-test-no-engine")
        stream.sync_stream_routes("ws2", {"echo": {"host_port": 22000, "container_port": 7}}, "om-test-no-engine")
        self.assertIn("stream_25565", stream.EDGE_CONFIG_FILE.read_text(encoding="utf-8"))
        self.assertIn("stream_22000", stream.EDGE_CONFIG_FILE.read_text(encoding="utf-8"))

        stream.prune_stream_fragments("ws1", "om-test-no-engine")
        edge_cfg = stream.EDGE_CONFIG_FILE.read_text(encoding="utf-8")
        self.assertNotIn("stream_25565", edge_cfg)
        self.assertIn("stream_22000", edge_cfg)


class TestStreamFirewall(unittest.TestCase):
    def test_stream_firewall_ports(self):
        from unittest import mock

        from gitops import hostsetup
        mock_ports = {
            "ws/s1": {"container_port": 1234, "host_port": 22000, "scope": "private"},
            "ws/s2": {"container_port": 5678, "host_port": 22001, "scope": "public"},
            "ws/mc": {"container_port": 25565, "host_port": 25565, "scope": "public"},
            "ws/priv": {"container_port": 9000, "host_port": 9000, "scope": "private"},
        }
        with mock.patch("gitops.wsregistry.stream_ports", return_value=mock_ports):
            priv, pub = hostsetup.stream_firewall_ports()
            self.assertIn("22000-22199", priv)
            self.assertIn("9000", priv)
            self.assertIn("22001", pub)
            self.assertIn("25565", pub)

    def test_stream_render_nft_rules(self):
        from unittest import mock

        from gitops import hostsetup
        mock_ports = {
            "ws/mc": {"container_port": 25565, "host_port": 25565, "scope": "public"},
        }
        with mock.patch("gitops.wsregistry.stream_ports", return_value=mock_ports), \
                mock.patch.object(hostsetup, "vpn_ips", return_value=["100.64.1.1"]):
            nft = hostsetup.render_nft([], [])
            self.assertIn("ip daddr { 100.64.1.1 } tcp dport { 22000-22199 } accept", nft)
            self.assertIn("tcp dport { 25565 } accept", nft)

    def test_stream_render_pf_and_windows(self):
        from unittest import mock

        from gitops import hostsetup
        mock_ports = {
            "ws/mc": {"container_port": 25565, "host_port": 25565, "scope": "public"},
        }
        with mock.patch("gitops.wsregistry.stream_ports", return_value=mock_ports), \
                mock.patch.object(hostsetup, "vpn_ips", return_value=["100.64.1.1"]):
            pf = hostsetup.render_pf([], [])
            win = hostsetup.render_windows([], [])
            self.assertIn("pass in proto tcp to 100.64.1.1 port { 22000:22199 } keep state", pf)
            self.assertIn("pass in proto tcp to any port { 25565 } keep state", pf)
            self.assertIn('DisplayName "om stream ports (VPN)" -Direction Inbound -Protocol TCP -LocalAddress 100.64.1.1 -LocalPort 22000-22199', win)
            self.assertIn('DisplayName "om public stream ports" -Direction Inbound -Protocol TCP -LocalPort 25565', win)

    def test_stream_vpn_restriction_includes_private_stream_ports(self):
        from unittest import mock

        from gitops import hostsetup
        mock_ports = {
            "ws/priv": {"container_port": 9000, "host_port": 9000, "scope": "private"},
        }
        with mock.patch("gitops.wsregistry.stream_ports", return_value=mock_ports), \
                mock.patch.object(hostsetup, "vpn_ips", return_value=["100.64.1.1"]), \
                mock.patch.object(hostsetup, "vpn_allow", return_value=["100.64.0.10/32"]):
            restr = hostsetup.vpn_restriction()
            self.assertIsNotNone(restr)
            self.assertIn("9000", restr["ports"])
            self.assertIn("22000-22199", restr["ports"])

    def test_stream_fail_closed_unapplied_net_policy(self):
        from unittest import mock

        from gitops import hostsetup, omsettings
        mock_ports = {
            "ws/mc": {"container_port": 25565, "host_port": 25565, "scope": "public"},
        }
        mock_pols = {
            "ws/mc": {"ports": [25565], "allow": ["100.64.0.5/32"], "deny": []},
        }
        resolved = {"http_port": 80, "https_port": 443, "vpn_ips": [], "lan_ip": "192.168.1.50"}
        with mock.patch("gitops.omsettings.stream_ports", return_value=mock_ports), \
                mock.patch("gitops.omsettings.net_policies", return_value=mock_pols):
            # When firewall policy is not enforced -> port is NOT bound
            with mock.patch.object(hostsetup, "net_policy_enforced", return_value=False):
                rendered = omsettings.render_ports(resolved)
                self.assertNotIn("25565:25565", rendered)

            # When firewall policy IS enforced -> port is bound
            with mock.patch.object(hostsetup, "net_policy_enforced", return_value=True):
                rendered = omsettings.render_ports(resolved)
                self.assertIn("25565:25565", rendered)


class TestStreamDoctor(unittest.TestCase):
    def test_check_stream_published_ports_pass(self):
        from unittest import mock

        from gitops import doctor
        ps_output = "om_stream_edge\t127.0.0.1:22000-22199->22000-22199/tcp, 127.0.0.1:25565->25565/tcp\nom_caddy\t80->80/tcp\n"
        mock_res = mock.Mock(stdout=ps_output, returncode=0)
        mock_ports = {"ws/mc": {"host_port": 25565, "container_port": 25565}}
        with mock.patch("gitops.wsregistry.stream_ports", return_value=mock_ports), \
                mock.patch("gitops.omstate.run", return_value=mock_res):
            st, msg, fix = doctor.check_stream_published_ports("podman")
            self.assertEqual(st, doctor.PASS)
            self.assertIn("only declared stream ports", msg)

    def test_check_stream_published_ports_undeclared_fails(self):
        from unittest import mock

        from gitops import doctor
        # om_stream_edge publishes 25565 but stream_ports only knows default range
        ps_output = "om_stream_edge\t127.0.0.1:22000-22199->22000-22199/tcp, 127.0.0.1:25565->25565/tcp\n"
        mock_res = mock.Mock(stdout=ps_output, returncode=0)
        with mock.patch("gitops.wsregistry.stream_ports", return_value={}), \
                mock.patch("gitops.omstate.run", return_value=mock_res):
            st, msg, fix = doctor.check_stream_published_ports("podman")
            self.assertEqual(st, doctor.FAIL)
            self.assertIn("undeclared port(s) published", msg)
            self.assertIn("25565", msg)
            self.assertIn("om core restart (ports.yml binds only declared stream ports)", fix)

    def test_check_stream_published_ports_leak_fails(self):
        from unittest import mock

        from gitops import doctor
        ps_output = "om_stream_edge\t127.0.0.1:22000-22199->22000-22199/tcp\nother_container\t0.0.0.0:25565->25565/tcp\n"
        mock_res = mock.Mock(stdout=ps_output, returncode=0)
        mock_ports = {"ws/mc": {"host_port": 25565, "container_port": 25565}}
        with mock.patch("gitops.wsregistry.stream_ports", return_value=mock_ports), \
                mock.patch("gitops.omstate.run", return_value=mock_res):
            st, msg, fix = doctor.check_stream_published_ports("podman")
            self.assertEqual(st, doctor.FAIL)
            self.assertIn("bypassing stream proxy", msg)
            self.assertIn("other_container (:25565)", msg)
            self.assertIn("om core restart (ports.yml binds only declared stream ports)", fix)

    def test_check_stream_firewall(self):
        from unittest import mock

        from gitops import doctor, hostsetup
        with mock.patch.object(hostsetup, "firewall_status", return_value="active"):
            # Pass case: rules are present
            nft_pass = "tcp dport { 25565 } accept\nip daddr { 100.64.0.1 } tcp dport { 22000-22199 } accept\n"
            with mock.patch.object(hostsetup, "_read", return_value=nft_pass), \
                    mock.patch("gitops.wsregistry.stream_ports", return_value={"ws/mc": {"host_port": 25565, "scope": "public"}}), \
                    mock.patch.object(hostsetup, "vpn_ips", return_value=["100.64.0.1"]):
                st, msg, fix = doctor.check_stream_firewall()
                self.assertEqual(st, doctor.PASS)

            # Fail case: public rule missing
            nft_missing = "tcp dport { 80, 443 } accept\n"
            with mock.patch.object(hostsetup, "_read", return_value=nft_missing), \
                    mock.patch("gitops.wsregistry.stream_ports", return_value={"ws/mc": {"host_port": 25565, "scope": "public"}}), \
                    mock.patch.object(hostsetup, "vpn_ips", return_value=[]):
                st, msg, fix = doctor.check_stream_firewall()
                self.assertEqual(st, doctor.FAIL)
                self.assertIn("firewall rule missing for stream port(s): 25565", msg)
                self.assertEqual(fix, "om firewall apply")

    def test_check_stream_isolation(self):
        from unittest import mock

        from gitops import doctor
        with mock.patch("gitops.wsregistry.read_registry", return_value={"ws1": {"path": "/fake"}}), \
                mock.patch("gitops.wsregistry.stream_ports", return_value={"ws2/svc": {"container_port": 25565}}):
            # Inspect network returns ok (0)
            def run_mock(cmd, **kwargs):
                if cmd[1] == "network" and cmd[2] == "inspect":
                    return mock.Mock(returncode=0)
                if cmd[1] == "run":
                    # Probe output
                    return mock.Mock(stdout=run_mock.probe_output, returncode=0)
                return mock.Mock(returncode=0, stdout="")

            # 1. Pass: edge unreachable, router refused, other ws unreachable
            run_mock.probe_output = "unreachable refused unreachable\n"
            with mock.patch("gitops.omstate.run", side_effect=run_mock):
                st, msg, fix = doctor.check_stream_isolation("podman")
                self.assertEqual(st, doctor.PASS)
                self.assertIn("isolated from workspace containers", msg)

            # 2. Fail: edge is open
            run_mock.probe_output = "open refused unreachable\n"
            with mock.patch("gitops.omstate.run", side_effect=run_mock):
                st, msg, fix = doctor.check_stream_isolation("podman")
                self.assertEqual(st, doctor.FAIL)
                self.assertIn("directly reachable over network", msg)
                self.assertIn("om_stream_edge is only on om_core_net", fix)

            # 3. Fail: router has a listener
            run_mock.probe_output = "unreachable open unreachable\n"
            with mock.patch("gitops.omstate.run", side_effect=run_mock):
                st, msg, fix = doctor.check_stream_isolation("podman")
                self.assertEqual(st, doctor.FAIL)
                self.assertIn("open network port", msg)
                self.assertIn("om_stream_router has no network listener", fix)

            # 4. Fail: cross-workspace target open
            run_mock.probe_output = "unreachable refused open\n"
            with mock.patch("gitops.omstate.run", side_effect=run_mock):
                st, msg, fix = doctor.check_stream_isolation("podman")
                self.assertEqual(st, doctor.FAIL)
                self.assertIn("cross-workspace stream target", msg)

    def test_cmd_ports_recognises_stream_edge(self):
        import io
        from contextlib import redirect_stdout
        from unittest import mock

        from gitops import routesview
        ps_out = "om_stream_edge\t127.0.0.1:22000-22199->22000-22199/tcp\nom_caddy\t127.0.0.1:80->80/tcp\n"
        with mock.patch("gitops.routesview.run", return_value=mock.Mock(stdout=ps_out, returncode=0)), \
                mock.patch("gitops.routesview.detect_runtime", return_value="podman"):
            f = io.StringIO()
            with redirect_stdout(f):
                routesview.cmd_ports(mock.Mock())
            out = f.getvalue()
            self.assertIn("stream", out)
            self.assertIn("No other container publishes host ports.", out)
            self.assertNotIn("bypass the proxy", out)

    def test_sync_never_prunes_another_workspaces_fragments(self):
        # workspace ids contain '-': syncing `a` must not touch the fragments of `a-b`
        meta = {"container_port": 80, "host_port": 22005, "log": "on"}
        stream.sync_stream_routes("a-b", {"web": meta}, "om-test-no-engine")
        stream.sync_stream_routes("a", {}, "om-test-no-engine")
        self.assertTrue((stream.EDGE_FRAGMENTS_DIR / stream.fragment_name("a-b", "web")).exists())
        self.assertTrue((stream.ROUTER_FRAGMENTS_DIR / stream.fragment_name("a-b", "web")).exists())
        stream.prune_stream_fragments("a", "om-test-no-engine")
        self.assertTrue((stream.EDGE_FRAGMENTS_DIR / stream.fragment_name("a-b", "web")).exists())
        stream.prune_stream_fragments("a-b", "om-test-no-engine")
        self.assertFalse((stream.EDGE_FRAGMENTS_DIR / stream.fragment_name("a-b", "web")).exists())

    def test_colliding_ids_get_distinct_fragments_and_old_names_migrate(self):
        # `a`+`b-web` and `a-b`+`web` used to share `a-b-web.cfg`
        one = {"container_port": 80, "host_port": 22010, "log": "on"}
        two = {"container_port": 80, "host_port": 22011, "log": "on"}
        stream.sync_stream_routes("a", {"b-web": one}, "om-test-no-engine")
        stream.sync_stream_routes("a-b", {"web": two}, "om-test-no-engine")
        self.assertTrue((stream.EDGE_FRAGMENTS_DIR / stream.fragment_name("a", "b-web")).exists())
        self.assertTrue((stream.EDGE_FRAGMENTS_DIR / stream.fragment_name("a-b", "web")).exists())
        # an old-named fragment of the same workspace is replaced, not duplicated
        old = stream.EDGE_FRAGMENTS_DIR / "a-b-web.cfg"
        old.write_text(stream.render_edge_fragment("a-b", "web", 22011), encoding="utf-8")
        stream.sync_stream_routes("a-b", {"web": two}, "om-test-no-engine")
        self.assertFalse(old.exists())
        self.assertEqual(stream.EDGE_CONFIG_FILE.read_text(encoding="utf-8").count("frontend stream_22011"), 1)
        for ws in ("a", "a-b"):
            stream.prune_stream_fragments(ws, "om-test-no-engine")


if __name__ == "__main__":
    unittest.main()
