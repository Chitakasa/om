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
                                "dashboard_paths": ["/api/wallpaper*"]})

    def test_no_labels_means_plain_routes(self):
        opts = om["route_options"]("", "searxng")
        self.assertEqual(opts, {"keep_prefix": False, "aliases": [], "dashboard_paths": []})
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

