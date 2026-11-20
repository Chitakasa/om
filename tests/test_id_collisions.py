"""Workspace and service ids both contain '-', so names built as `<ws>-<svc>` can collide
(`a`+`b-web` and `a-b`+`web`). Every place that derives a file or id from the pair must keep two pairs apart,
or refuse loudly; none may silently overwrite or delete the other's."""
import itertools
import shutil
import tempfile
import unittest
from pathlib import Path

from _env import load_om
from test_routes import make_service

from gitops import omstate, stream, wsregistry

om = load_om()
CONF_D = om["CONF_D"]

# (workspace, service) pairs that build the same `<ws>-<svc>` string
COLLIDING = [("a", "b-web"), ("a-b", "web")]


def _workspace(ws_id: str) -> Path:
    root = Path(tempfile.mkdtemp(prefix="om-ws-"))
    (root / ".om").mkdir()
    (root / ".om" / "config.json").write_text(f'{{"workspace_id": "{ws_id}"}}', encoding="utf-8", newline="\n")
    return root


class TestRouteFileCollision(unittest.TestCase):
    def setUp(self):
        for f in CONF_D.iterdir():
            f.unlink()
        self.roots = []

    def tearDown(self):
        for r in self.roots:
            shutil.rmtree(r, ignore_errors=True)

    def test_second_workspace_never_overwrites_the_first_ones_route(self):
        owners = {}
        for ws, svc in COLLIDING:
            root = _workspace(ws)
            self.roots.append(root)
            make_service(root, svc, ["dashboard.port=80"])
            om["sync_caddy_routes"](root, "none", reload=False)
            owners[ws] = root
        route = CONF_D / "a-b-web.caddy"
        self.assertEqual(om["route_owner"](route), "a")  # the first one keeps it
        # and syncing again in either order never flips it
        for ws in ("a-b", "a", "a-b"):
            om["sync_caddy_routes"](owners[ws], "none", reload=False)
            self.assertEqual(om["route_owner"](route), "a")

    def test_pruning_one_workspace_leaves_the_others_routes(self):
        roots = {}
        for ws, svc in [("a", "web"), ("a-b", "web")]:
            roots[ws] = _workspace(ws)
            self.roots.append(roots[ws])
            make_service(roots[ws], svc, ["dashboard.port=80"])
            om["sync_caddy_routes"](roots[ws], "none", reload=False)
        shutil.rmtree(roots["a"] / "services")
        om["sync_caddy_routes"](roots["a"], "none", reload=False)
        self.assertEqual(om["route_owner"](CONF_D / "a-b-web.caddy"), "a-b")


class TestRoutePortBookkeeping(unittest.TestCase):
    def test_log_off_and_address_rules_keep_separate_port_lists(self):
        for f in CONF_D.iterdir():
            f.unlink()
        root = _workspace("books")
        try:
            make_service(root, "mc", ["dashboard.port=80", "om.log=off", "om.net.allow=10.0.0.0/8", "om.tcp=25565", "om.tcp.port=25570"])
            om["sync_caddy_routes"](root, "none", reload=False)
            slot = wsregistry.service_slots()["books/mc"]
            http_port = omstate.PRIVATE_PORT_BASE + slot
            self.assertEqual(sorted(wsregistry.net_policies()["books/mc"]["ports"]), sorted([http_port, 25570]))
            self.assertIn(http_port, wsregistry.no_log_ports())
            self.assertIn(25570, wsregistry.no_log_ports())
        finally:
            shutil.rmtree(root, ignore_errors=True)
            for ws in ("books",):
                wsregistry.release_slots(ws)


class TestStreamFragmentCollision(unittest.TestCase):
    def test_every_pair_keeps_its_own_fragment_through_any_sync_order(self):
        metas = {ws: {"container_port": 80, "host_port": 22100 + i, "log": "on"} for i, (ws, _) in enumerate(COLLIDING)}
        try:
            for order in itertools.permutations(COLLIDING):
                for ws, svc in order:
                    stream.sync_stream_routes(ws, {svc: metas[ws]}, "om-test-no-engine")
                for ws, svc in COLLIDING:
                    self.assertTrue((stream.EDGE_FRAGMENTS_DIR / stream.fragment_name(ws, svc)).exists(), (ws, svc, order))
        finally:
            for ws, _ in COLLIDING:
                stream.prune_stream_fragments(ws, "om-test-no-engine")


class TestPreviewIds(unittest.TestCase):
    def test_long_branches_with_a_common_prefix_get_different_ids(self):
        from gitops.previews import preview_id
        base = "feature/" + "x" * 80
        ids = {preview_id("perso", base + suffix) for suffix in ("-one", "-two", "-three")}
        self.assertEqual(len(ids), 3)
        for i in ids:
            self.assertLessEqual(len(i), 63)
            self.assertTrue(om["is_valid_workspace_id"](i), i)

    def test_same_branch_same_id(self):
        from gitops.previews import preview_id
        self.assertEqual(preview_id("perso", "Feature/Login"), preview_id("perso", "feature/login"))
        self.assertEqual(preview_id("perso", "fix/x"), "perso--fix-x")


if __name__ == "__main__":
    unittest.main()
