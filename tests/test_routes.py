import subprocess
import unittest
import shutil
import tempfile
from pathlib import Path

from _env import load_om, TMP_HOME

om = load_om()
CONF_D = om["CONF_D"]


def make_service(root: Path, name: str, labels: list[str], kind: str = "services"):
    d = root / kind / name
    d.mkdir(parents=True, exist_ok=True)
    lab = "".join(f'      - "{l}"\n' for l in labels)
    (d / "docker-compose.yml").write_text(f"services:\n  {name}:\n    image: x\n    labels:\n{lab}", encoding="utf-8", newline="\n")
    return d


class TestNames(unittest.TestCase):
    def test_safe_names(self):
        self.assertTrue(om["is_safe_name"]("my-svc1"))
        for bad in ("", "-x", "A", "a_b", "../x", "a}b", "a\nb", "x" * 64):
            self.assertFalse(om["is_safe_name"](bad), bad)

    def test_core_is_reserved(self):
        self.assertFalse(om["is_valid_workspace_id"]("core"))
        self.assertTrue(om["is_valid_workspace_id"]("perso"))


class TestParse(unittest.TestCase):
    def test_label_port_wins_over_expose(self):
        port, public, no_web = om["parse_service_meta"]('labels:\n  - "dashboard.port=9000"\nexpose:\n  - "80"\n', "s")
        self.assertEqual((port, public, no_web), (9000, False, False))

    def test_public_requires_explicit_scope(self):
        self.assertTrue(om["parse_service_meta"]('- "dashboard.scope=public"', "s")[1])
        self.assertFalse(om["parse_service_meta"]('- "dashboard.domain=x.local"', "s")[1])
        self.assertFalse(om["parse_service_meta"]('# - "dashboard.scope=public"', "s")[1])

    def test_no_web(self):
        self.assertTrue(om["parse_service_meta"]('- "dashboard.web=false"', "s")[2])
        # om never special-cases service names: only the label hides a service
        self.assertFalse(om["parse_service_meta"]("", "backup")[2])


class TestRouteLabels(unittest.TestCase):
    COMPOSE = (
        'labels:\n'
        '  - "om.route.keep_prefix=true"\n'
        '  - "om.route.aliases=/search, /System/Info/Public"\n'
        "  om.route.dashboard_paths: '/api/wallpaper*'\n"
    )

    def test_labels_parsed_in_list_and_map_form(self):
        opts = om["route_options"](self.COMPOSE, "s")
        self.assertEqual(opts, {"keep_prefix": True, "aliases": ["/search", "/System/Info/Public"],
                                "dashboard_paths": ["/api/wallpaper*"], "net": None, "net_problems": [], "log": "on"})

    def test_no_labels_means_plain_routes(self):
        opts = om["route_options"]("", "searxng")
        self.assertEqual(opts, {"keep_prefix": False, "aliases": [], "dashboard_paths": [], "net": None, "net_problems": [], "log": "on"})
        self.assertEqual(om["render_vhost"]("ws", "searxng", 8080, opts), om["render_vhost"]("ws", "searxng", 8080))
        self.assertNotIn("to_dashboard", om["render_vhost"]("ws", "searxng", 8080, opts))

    def test_injection_is_rejected(self):
        bad = '- "om.route.dashboard_paths=/x {\\n abort }, /ok*, /../etc, //x, /a b"'
        self.assertEqual(om["route_options"](bad, "s")["dashboard_paths"], ["/ok*"])

    def test_keep_prefix_and_aliases_render(self):
        opts = om["route_options"](self.COMPOSE, "app")
        v = om["render_vhost"]("ws", "app", 80, opts, 5, True)
        self.assertIn("redir / /app/", v)
        self.assertIn("handle /api/wallpaper* {\n        import to_dashboard\n", v)
        self.assertIn("import to_dashboard_public", v)       # dashboard paths on the public port stay public-scoped
        alias = om["render_alias"]("ws", "app", 20005, False, opts)
        self.assertIn("redir /app http://{host}:20005/app/", alias)
        self.assertIn("redir /search http://{host}:20005{uri}\nredir /search/* http://{host}:20005{uri}", alias)

    def test_alias_default_goes_to_root(self):
        alias = om["render_alias"]("ws", "app", 20003, False)
        self.assertIn("redir /app/* http://{host}:20003/", alias)

    def test_each_service_gets_its_own_ports(self):
        v = om["render_vhost"]("ws", "app", 80, None, 7, True)
        self.assertIn("http://:20007 {", v)
        self.assertIn("@foreign not host {$PRIVATE_NAMES}", v)  # DNS rebinding: unknown Host → abort
        self.assertIn("http://:21007 {", v)
        self.assertIn("@foreign not host {$PUBLIC_NAMES}", v)
        private = om["render_vhost"]("ws", "app", 80, None, 7, False)
        self.assertIn("http://:20007 {", private)
        self.assertNotIn("21007", private)                       # private services have no public port
        self.assertNotIn("http://:", om["render_vhost"]("ws", "app", 80))


class TestSnippets(unittest.TestCase):
    def test_allowed_snippet(self):
        ok = 'header X-A "b"\n@old path /old*\nredir @old /new{uri}\nhandle /api/* {\n    respond "hi" 200\n}\n' \
             'basic_auth {\n    me $2a$14$abc\n}\n@m {\n    method POST\n    header X-Y z\n}\n'
        self.assertEqual(om["validate_snippet"](ok), [])

    def test_forbidden_snippets(self):
        for bad in ("root * /data\nfile_server\n", "reverse_proxy example.com\n", "respond {$OM_EDGE_TOKEN}\n",
                    "respond {env.OM_EDGE_TOKEN}\n", "respond {file./data/caddy/pki/authorities/local/root.key}\n",
                    "import /etc/caddy/auth.d/*\n", "handle {\n    file_server\n}\n", "@x file /etc/passwd\n",
                    "header X {\n", "templates\n"):
            self.assertTrue(om["validate_snippet"](bad), bad)

    def test_client_address_rules_are_refused(self):
        for bad in ("@x remote_ip 10.0.0.0/8\nabort @x\n", "@x client_ip 1.2.3.4\nabort @x\n",
                    'header X-Who "{remote_host}"\n', "@x expression `{http.request.remote.host} == '1.2.3.4'`\nabort @x\n"):
            problems = om["validate_snippet"](bad)
            self.assertTrue(any("om.net.allow" in p for p in problems), bad)

    def test_log_off_leaves_no_trace_on_any_site(self):
        v = om["render_vhost"]("ws", "app", 80, {"log": "off"}, 3, True)
        self.assertEqual(v.count("log_skip"), 3)                     # .localhost, private port, public port
        self.assertNotIn("log_skip", om["render_vhost"]("ws", "app", 80, {"log": "on"}, 3, True))

    def test_snippet_runs_first_on_every_site(self):
        v = om["render_vhost"]("ws", "app", 80, {"snippet": 'header X-A "b"\n'}, 3, True)
        self.assertEqual(v.count('header X-A "b"'), 3)             # .localhost, private port, public port
        self.assertIn("route {", v)
        self.assertIn("# custom: om.caddy", v)


class TestNetLabels(unittest.TestCase):
    def test_parsed_and_normalised(self):
        pol, problems = om["net_policy"]({"om.net.allow": "192.168.1.9/24, 100.101.0.7,fd7a::1", "om.net.deny": "192.168.1.66"})
        self.assertEqual(problems, [])
        self.assertEqual(pol, {"allow": ["100.101.0.7/32", "192.168.1.0/24", "fd7a::1/128"], "deny": ["192.168.1.66/32"]})
        self.assertEqual(om["net_policy"]({"om.net.deny": "10.0.0.0/8"})[0], {"allow": None, "deny": ["10.0.0.0/8"]})
        self.assertEqual(om["net_policy"]({}), (None, []))

    def test_vpn_keyword_follows_the_vpn_allow_list(self):
        net_policy = om["net_policy"]
        pol, problems = net_policy({"om.net.allow": "VPN, 192.168.1.20"}, vpn_allow=["100.64.0.10/32"])
        self.assertEqual(problems, [])
        self.assertEqual(pol["allow"], ["vpn", "192.168.1.20/32"])               # kept as the word, expanded later
        _, problems = net_policy({"om.net.allow": "vpn"}, vpn_allow=[])
        self.assertTrue(problems and "om vpn allow" in problems[0])              # no list yet: refused (no route)
        _, problems = net_policy({"om.net.deny": "vpn"}, vpn_allow=["100.64.0.10/32"])
        self.assertTrue(problems)                                                # only for om.net.allow

    def test_bad_entries_are_problems(self):
        _, problems = om["net_policy"]({"om.net.allow": "100.64.0.5, nope, 1.2.3.4/99"})
        self.assertEqual(len(problems), 2)


class TestPreview(unittest.TestCase):
    def test_preview_id(self):
        self.assertEqual(om["preview_id"]("shop", "Feature/New_UI"), "shop--feature-new-ui")
        self.assertTrue(om["is_valid_workspace_id"](om["preview_id"]("shop", "x" * 200)))

    def test_literal_names_are_reported(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        d = root / "services" / "a"
        d.mkdir(parents=True)
        (d / "compose.yml").write_text("services:\n  a:\n    container_name: shop_a\nnetworks:\n  default:\n    name: shop_net\n",
                                       encoding="utf-8", newline="\n")
        self.assertEqual(len(om["preview_portable"](root)), 2)
        (d / "compose.yml").write_text("services:\n  a:\n    container_name: ${WORKSPACE_ID:-shop}_a\nnetworks:\n  default:\n"
                                       "    name: ${WORKSPACE_NET:-shop_net}\n", encoding="utf-8", newline="\n")
        self.assertEqual(om["preview_portable"](root), [])


class TestRender(unittest.TestCase):
    def test_vhost_goes_through_router_with_auth(self):
        v = om["render_vhost"]("ws", "app", 3000)
        self.assertIn("http://ws.app.localhost {", v)
        self.assertIn("import private_auth", v)
        self.assertIn("import to_workspace ws_app:3000", v)
        self.assertNotIn("reverse_proxy ws_app", v)  # never direct: the edge can't reach workspace nets

    def test_owner_header_roundtrip(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        p = d / "ws-app.public_alias"
        p.write_text(om["render_alias"]("ws", "app", 21000, True), encoding="utf-8", newline="\n")
        self.assertEqual(om["route_owner"](p), "ws")


class TestSync(unittest.TestCase):
    def setUp(self):
        for f in CONF_D.iterdir():
            f.unlink()
        self.root = Path(tempfile.mkdtemp(prefix="om-ws-"))
        (self.root / ".om").mkdir()
        (self.root / ".om" / "config.json").write_text('{"workspace_id": "alpha"}', encoding="utf-8", newline="\n")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def files(self):
        return sorted(f.name for f in CONF_D.iterdir())

    def test_generate_flip_and_prune(self):
        make_service(self.root, "web", ["dashboard.port=80", "dashboard.scope=public"])
        make_service(self.root, "daemon", ["dashboard.web=false"])
        (CONF_D / "alpha-web.private_subpath").write_text("# Private Subpath: web (alpha)\n", encoding="utf-8", newline="\n")
        om["sync_caddy_routes"](self.root, "none", reload=False)
        self.assertEqual(self.files(), ["alpha-web.caddy", "alpha-web.private_alias", "alpha-web.public_alias"])  # old subpath pruned
        slot = om["core"].service_slots()["alpha/web"]
        self.assertIn(f"http://:{21000 + slot} {{", (CONF_D / "alpha-web.caddy").read_text(encoding="utf-8"))

        # Flip to private: the public port and redirect must disappear (otherwise it stays on the LAN)
        make_service(self.root, "web", ["dashboard.port=80", "dashboard.scope=private"])
        om["sync_caddy_routes"](self.root, "none", reload=False)
        self.assertEqual(self.files(), ["alpha-web.caddy", "alpha-web.private_alias"])
        self.assertNotIn(f"{21000 + slot}", (CONF_D / "alpha-web.caddy").read_text(encoding="utf-8"))
        self.assertEqual(om["core"].service_slots()["alpha/web"], slot)  # the port stays the same

        # Remove the service: all its routes are pruned
        shutil.rmtree(self.root / "services" / "web")
        om["sync_caddy_routes"](self.root, "none", reload=False)
        self.assertEqual(self.files(), [])
        self.assertNotIn("alpha/web", om["core"].service_slots())  # its port is free again

    def test_never_touches_other_owners(self):
        (CONF_D / "beta-web.caddy").write_text(om["render_vhost"]("beta", "web", 80), encoding="utf-8", newline="\n")
        (CONF_D / "portainer.caddy").write_text("# Service: portainer (core)\nhttp://core.portainer.localhost {\n}\n", encoding="utf-8", newline="\n")
        (CONF_D / "web.caddy").write_text("# hand-written, no owner\n", encoding="utf-8", newline="\n")
        om["sync_caddy_routes"](self.root, "none", reload=False)
        self.assertEqual(self.files(), ["beta-web.caddy", "portainer.caddy", "web.caddy"])

    def test_alias_conflict_is_skipped(self):
        (CONF_D / "beta-tool.private_alias").write_text("# Private Alias: tool (beta)\nredir /tool http://{host}:20100/\n", encoding="utf-8", newline="\n")
        make_service(self.root, "tool", ["dashboard.port=9000"])
        om["sync_caddy_routes"](self.root, "none", reload=False)
        self.assertIn("alpha-tool.caddy", self.files())          # its own ports still work
        self.assertNotIn("alpha-tool.private_alias", self.files())

    def test_net_policy_keeps_ports_closed_until_the_firewall_has_it(self):
        from unittest import mock
        hs, core = om["hostsetup"], om["core"]
        self.addCleanup(core.set_net_policies, "alpha", {})
        make_service(self.root, "web", ["dashboard.port=80", "om.net.allow=100.64.0.5"])
        with mock.patch.object(hs, "net_policy_enforced", return_value=False):
            om["sync_caddy_routes"](self.root, "none", reload=False)
        slot = core.service_slots()["alpha/web"]
        self.assertEqual(core.net_policies()["alpha/web"], {"ports": [20000 + slot], "allow": ["100.64.0.5/32"], "deny": []})
        self.assertNotIn(f"http://:{20000 + slot}", (CONF_D / "alpha-web.caddy").read_text(encoding="utf-8"))
        self.assertNotIn("alpha-web.private_alias", self.files())          # nothing points at a closed port
        with mock.patch.object(hs, "net_policy_enforced", return_value=True):
            om["sync_caddy_routes"](self.root, "none", reload=False)
        self.assertIn(f"http://:{20000 + slot} {{", (CONF_D / "alpha-web.caddy").read_text(encoding="utf-8"))

    def test_log_off_ports_are_recorded_for_the_firewall(self):
        core = om["core"]
        self.addCleanup(core.set_no_log, "alpha", {})
        make_service(self.root, "web", ["dashboard.port=80", "dashboard.scope=public", "om.log=off"])
        om["sync_caddy_routes"](self.root, "none", reload=False)
        slot = core.service_slots()["alpha/web"]
        self.assertEqual(core.no_log_ports(), [20000 + slot, 21000 + slot])

    def test_unreadable_net_label_means_no_route(self):
        make_service(self.root, "web", ["dashboard.port=80", "om.net.allow=everyone-I-like"])
        om["sync_caddy_routes"](self.root, "none", reload=False)
        self.assertEqual(self.files(), [])

    def test_unsafe_directory_names_are_skipped(self):
        make_service(self.root, "Bad_Name", ["dashboard.port=80"])
        om["sync_caddy_routes"](self.root, "none", reload=False)
        self.assertEqual(self.files(), [])


class TestOrphanRoutes(unittest.TestCase):
    """Routes of a workspace deleted without `om remove` are pruned, but never while it may still run."""

    def setUp(self):
        for f in CONF_D.iterdir():
            f.unlink()
        self.root = Path(tempfile.mkdtemp(prefix="om-ws-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        (self.root / ".om").mkdir()
        (self.root / ".om" / "config.json").write_text('{"workspace_id": "alpha"}', encoding="utf-8", newline="\n")
        om["update_registry"](lambda reg: (reg.clear(), reg.update({
            "alpha": {"id": "alpha", "path": str(self.root)},
            "gone": {"id": "gone", "path": str(self.root / "deleted")},
        })))
        self.addCleanup(om["update_registry"], lambda reg: reg.clear())
        for ws in ("alpha", "gone", "stray"):
            (CONF_D / f"{ws}-web.caddy").write_text(om["render_vhost"](ws, "web", 80), encoding="utf-8", newline="\n")
        (CONF_D / "portainer.caddy").write_text("# Service: portainer (core)\n", encoding="utf-8", newline="\n")
        self.running = set()
        self.engine_ok = True
        g = om["prune_orphan_routes"].__globals__  # runpy hands back a copy; patch the live globals
        orig = g["run"]
        g["run"] = self.fake_run
        self.addCleanup(g.__setitem__, "run", orig)

    def fake_run(self, cmd, **kw):
        ws = cmd[-1].rsplit("=", 1)[-1] if cmd[1:2] == ["ps"] else ""
        if not self.engine_ok:
            return subprocess.CompletedProcess(cmd, 127, "", "no engine")
        return subprocess.CompletedProcess(cmd, 0, "abc123\n" if ws in self.running else "", "")

    def files(self):
        return sorted(f.name for f in CONF_D.iterdir())

    def test_prunes_deleted_and_unregistered_only(self):
        removed = om["prune_orphan_routes"]("fake", reload=False, quiet=True)
        self.assertEqual(sorted(f.name for f in removed), ["gone-web.caddy", "stray-web.caddy"])
        self.assertEqual(self.files(), ["alpha-web.caddy", "portainer.caddy"])
        self.assertIn("gone", om["read_registry"]())  # registry kept: an unplugged drive can come back

    def test_running_containers_block_prune(self):
        self.running = {"gone"}
        om["prune_orphan_routes"]("fake", reload=False, quiet=True)
        self.assertEqual(self.files(), ["alpha-web.caddy", "gone-web.caddy", "portainer.caddy"])

    def test_engine_down_prunes_nothing(self):
        self.engine_ok = False
        self.assertEqual(om["prune_orphan_routes"]("fake", reload=False, quiet=True), [])
        self.assertEqual(len(self.files()), 4)

    def test_force_ignores_running(self):
        self.running = {"gone"}
        om["prune_orphan_routes"]("fake", reload=False, quiet=True, force=True)
        self.assertEqual(self.files(), ["alpha-web.caddy", "portainer.caddy"])

    def test_sync_of_any_workspace_prunes_orphans(self):
        om["sync_caddy_routes"](self.root, "fake", reload=False)
        self.assertNotIn("gone-web.caddy", self.files())


class TestOmIgnore(unittest.TestCase):
    def test_folder_with_omignore_is_not_part_of_the_workspace(self):
        import tempfile
        root = Path(tempfile.mkdtemp())
        for d in ("services/web", "services/backup", "tools"):
            (root / d).mkdir(parents=True)
            (root / d / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8", newline="\n")
        (root / "services" / "backup" / ".omignore").write_text("", encoding="utf-8", newline="\n")
        (root / "tools" / ".omignore").write_text("", encoding="utf-8", newline="\n")
        names = [d.name for _, d in om["discover_compose_dirs"](root)]
        self.assertEqual(names, ["web"])


if __name__ == "__main__":
    unittest.main()



class TestConfigMeta(unittest.TestCase):
    def test_reads_labels_and_expose_from_normalized_config(self):
        cfg = {"services": {"web": {"expose": ["3000"], "labels": {
            "dashboard.scope": "public", "om.route.keep_prefix": "true", "other": "x"}}}}
        (port, public, no_web), labels = om["config_meta"](cfg, "web")
        self.assertEqual((port, public, no_web), (3000, True, False))
        self.assertNotIn("other", labels)
        self.assertTrue(om["route_options"]("", "web", labels)["keep_prefix"])

    def test_label_port_wins_and_default_is_8080(self):
        self.assertEqual(om["config_meta"]({"services": {"a": {"labels": {"dashboard.port": "9000"}, "expose": ["1"]}}}, "a")[0][0], 9000)
        self.assertEqual(om["config_meta"]({"services": {"a": {}}}, "a")[0][0], 8080)


class TestUpdateCache(unittest.TestCase):
    def test_update_refreshes_the_cached_update_list(self):
        """After `om update` moves the pins, `om status` must not keep listing an applied update."""
        import argparse
        import json
        from unittest import mock
        root = Path(tempfile.mkdtemp()) / "upd"
        self.addCleanup(shutil.rmtree, root.parent, True)
        (root / ".om").mkdir(parents=True)
        (root / ".om" / "config.json").write_text('{"workspace_id": "upd"}', encoding="utf-8")
        make_service(root, "app", [])
        cache = om["UPDATES_DIR"] / "upd.json"
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps({"checked": 1, "updates": ["docker.io/library/python:alpine"]}), encoding="utf-8")
        self.addCleanup(cache.unlink, True)
        fakes = {"lock_workspace": lambda r, t, refresh, only=None: ({}, {}), "start_workspace": lambda *a, **k: True,
                 "run_synthetic_health_check": lambda hosts: True, "workspace_vhosts": lambda ws: []}
        with mock.patch.dict(om["cmd_update"].__globals__, fakes):  # load_om() returns a copy of these
            om["cmd_update"](root, argparse.Namespace(dry_run=False, target=None, image=None, choose=False))
        ups, checked = om["cached_updates"]("upd")
        self.assertEqual(ups, [])
        self.assertGreater(checked, 1)


class TestAutoUpdate(unittest.TestCase):
    OLD, NEW = {"img:1": "sha256:" + "a" * 64}, {"img:1": "sha256:" + "b" * 64}

    def _run(self, healthy, state=None):
        from unittest import mock
        calls = []
        fakes = {
            "get_workspace_id": lambda r: "ws",
            "workspace_images": lambda r, t, report=False: ({"img:1": ["web"]}, set(), {"img:1"}),
            "available_updates": lambda r, t=None: {"img:1": (self.OLD["img:1"], self.NEW["img:1"])},
            "lock_workspace": lambda r, t, refresh, only=None: (self.OLD, self.NEW),
            "commit_lock": lambda r, m: calls.append("commit"),
            "run_git": lambda a, r: (calls.append(a[0]) or (0, "", "")),
            "start_workspace": lambda r, t, kind="": (calls.append(kind) or True),
            "run_synthetic_health_check": lambda hosts: healthy,
            "workspace_vhosts": lambda ws: [],
        }
        state = {} if state is None else state
        with mock.patch.dict(om["auto_update"].__globals__, fakes):
            return om["auto_update"](Path("/nonexistent"), state), calls, state

    def test_healthy_update_stays(self):
        lines, calls, state = self._run(True)
        self.assertTrue(lines[0].startswith("auto-updated img:1 aaaaaaaaaaaa → bbbbbbbbbbbb"))
        self.assertEqual(calls, ["commit", "status", "update"])
        self.assertEqual(state["auto_failed"], {})

    def test_failed_health_check_reverts_and_is_not_retried(self):
        lines, calls, state = self._run(False)
        self.assertIn("FAILED its health check; lock reverted", lines[0])
        self.assertEqual(calls, ["commit", "status", "update", "revert", "rollback"])
        self.assertEqual(state["auto_failed"], self.NEW)
        lines, calls, _ = self._run(False, state)  # the same digest is skipped next time
        self.assertEqual((lines, calls), ([], []))


class TestFirewallLog(unittest.TestCase):
    def test_kernel_log_maps_ports_to_services(self):
        core = om["core"]
        self.addCleanup(core.release_slots, "logws")
        slot = core.assign_slots("logws", ["app"])["logws/app"]
        text = ("x kernel: om-refused vpn: IN=tailscale0 SRC=100.64.0.30 DST=100.1.1.1 LEN=60 PROTO=TCP SPT=5 DPT=80 SYN\n"
                f"x kernel: om-in: IN=tailscale0 SRC=100.64.0.10 DST=100.1.1.1 LEN=60 PROTO=TCP SPT=5 DPT={20000 + slot} SYN\n"
                "x kernel: om-refused: IN=wlan0 SRC=fe80::1 DST=fe80::2 LEN=72 PROTO=ICMPv6 TYPE=128\n"
                "x kernel: unrelated: SRC=1.1.1.1 PROTO=TCP DPT=80\n")
        refused, connected = om["firewall_events"](text)
        self.assertEqual(refused[("vpn", "100.64.0.30", "front door (http)")], 1)
        self.assertEqual(refused[("not an om port", "fe80::1", "icmpv6")], 1)
        self.assertEqual(connected, {("100.64.0.10", "logws/app (private)"): 1})

    def test_edge_log_counts_without_urls(self):
        line = '{"level":"info","msg":"handled request","request":{"host":"ws.app.localhost","method":"GET"},"status":%d,"user_id":"%s"}'
        text = "\n".join([line % (200, ""), line % (401, ""), line % (502, "cyber"), '{"msg":"other"}'])
        st = om["edge_events"](text)["ws.app.localhost"]
        self.assertEqual((st["requests"], st["4xx"], st["5xx"], st["logins"]), (3, 1, 1, {"cyber"}))


class TestNoLogOverride(unittest.TestCase):
    def test_only_labelled_services_lose_their_output(self):
        cfg = {"services": {"search": {"labels": {"om.log": "off"}}, "db": {"labels": ["om.log=on"]}, "app": {}}}
        path = om["nolog_override"]("ws", Path("/x/search"), cfg)
        self.addCleanup(path.unlink, True)
        text = path.read_text(encoding="utf-8")
        self.assertIn('"search":\n    logging:\n      driver: "none"', text)
        self.assertNotIn('"db"', text)
        self.assertNotIn('"app"', text)
        self.assertIsNone(om["nolog_override"]("ws", Path("/x/search"), {"services": {"app": {}}}))
        self.assertFalse(path.exists())                      # the label went away: so does the override


class TestVpnDevices(unittest.TestCase):
    def test_events_per_vpn_source(self):
        text = ("2026-10-22T14:02:11+0530 h kernel: om-refused vpn: IN=tun0 SRC=100.64.0.20 DST=100.1.1.1 LEN=60 PROTO=TCP DPT=80\n"
                "2026-10-22T14:03:11+0530 h kernel: om-refused vpn: IN=tun0 SRC=100.64.0.20 DST=100.1.1.1 LEN=60 PROTO=TCP DPT=80\n"
                "2026-10-22T14:09:00+0530 h kernel: om-in: IN=tun0 SRC=100.64.0.10 DST=100.1.1.1 LEN=60 PROTO=TCP DPT=80\n"
                "2026-10-22T14:10:00+0530 h kernel: om-in: IN=wlan0 SRC=192.168.1.4 DST=192.168.1.10 LEN=60 PROTO=TCP DPT=80\n")
        ev = om["vpn_device_events"](text, {"100.1.1.1"})
        self.assertEqual(ev["100.64.0.20"], {"connected": 0, "refused": 2, "last": "2026-10-22T14:03:11+0530"})
        self.assertEqual(ev["100.64.0.10"]["connected"], 1)
        self.assertNotIn("192.168.1.4", ev)                      # LAN traffic is not a VPN device


class TestVpnAllowAppliesFirewall(unittest.TestCase):
    """om vpn allow|disallow updates the firewall first, so no device loses access; fail closed otherwise."""

    def run_allow(self, installed=True, applies=True, no_apply=False):
        import argparse
        from unittest import mock
        core, hs = om["core"], om["hostsetup"]
        apply = mock.Mock(return_value=applies)
        up = mock.Mock(return_value=True)
        g = om["cmd_vpn_allow"].__globals__
        with mock.patch.dict(g, {"vpn_device": lambda n: ("100.64.0.20/32", n), "apply_firewall": apply,
                                 "detect_runtime": lambda: "podman", "resync_all_routes": mock.Mock()}), \
                mock.patch.object(core, "vpn_allow", return_value=["100.64.0.10/32"]), \
                mock.patch.object(core, "set_setting"), mock.patch.object(core, "net_policies", return_value={}), \
                mock.patch.object(core, "core_running", return_value=True), \
                mock.patch.object(core, "runtime_drift", return_value=[] if (installed and applies and not no_apply) else ["stale"]), \
                mock.patch.object(core, "core_up", up), \
                mock.patch.object(hs, "firewall_installed", return_value=installed), \
                mock.patch.object(hs, "vpn_allow_enforced", return_value=installed and applies and not no_apply), \
                mock.patch.object(hs, "stale_net_rules", return_value=[]):
            om["cmd_vpn_allow"](argparse.Namespace(action="allow", name="old-phone", no_apply=no_apply))
        return apply.called, up.called

    def test_applied_firewall_means_the_tier_never_closes(self):
        self.assertEqual(self.run_allow(), (True, False))

    def test_failed_or_declined_sudo_fails_closed(self):
        self.assertEqual(self.run_allow(applies=False), (True, True))

    def test_no_apply_and_no_installed_firewall_leave_the_firewall_alone(self):
        self.assertEqual(self.run_allow(no_apply=True), (False, True))
        self.assertEqual(self.run_allow(installed=False), (False, True))
