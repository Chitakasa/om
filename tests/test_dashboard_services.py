"""How the dashboard describes containers (service_entry and its helpers); expectations recorded from the
behaviour before the function was split up."""
import sys
import unittest
from unittest import mock

import _env

sys.path.insert(0, str(_env.TMP_HOME / "core" / "dashboard" / "app"))
import server as dash  # noqa: E402

SLOTS = {"ws1/web": 3}


def entry(container):
    with mock.patch.object(dash, "updates_for", lambda ws: {"web"} if ws == "ws1" else set()), \
            mock.patch.dict(dash.STATS_CACHE, {"a" * 12: {"mem_usage": 5 * 1024 * 1024, "mem_limit": 50 * 1024 * 1024}}):
        return dash.service_entry(container, SLOTS)


def container(name, labels=None, ports=(), state="running", status="Up", cid="f"):
    return {"Id": cid * 64, "Names": [f"/{name}"], "Labels": labels or {}, "Ports": list(ports), "State": state, "Status": status}


class TestServiceEntry(unittest.TestCase):
    def test_labelled_public_search_service(self):
        e = entry(container("ws1_web", {"workspace.id": "ws1", "dashboard.port": "8080", "dashboard.scope": "public",
                                        "dashboard.name": "My Web", "dashboard.path": "sub", "dashboard.search": "true",
                                        "com.docker.compose.service": "web"}, [{"PrivatePort": 8080}], status="Up 3 hours", cid="a"))
        self.assertEqual((e["key"], e["name"], e["port"], e["path"], e["domain"]), ("web", "My Web", 8080, "/sub", "ws1.web.localhost"))
        self.assertEqual((e["port_private"], e["port_public"], e["is_public"]), (20003, 21003, True))
        self.assertEqual((e["is_search"], e["search_url"], e["update_available"]), (True, "/search?q={searchTerms}", True))
        self.assertEqual((e["memory_str"], e["memory_percent"]), ("5.0 MB", "10.0%"))

    def test_exited_container_without_ports_is_not_a_web_service(self):
        e = entry(container("ws1_db", {"workspace.id": "ws1"}, state="exited", status="Exited (137) 2 minutes ago"))
        self.assertEqual((e["has_web"], e["port"], e["state"], e["exit_code"]), (False, None, "exited", 137))
        self.assertEqual((e["port_private"], e["memory_str"], e["memory_percent"]), (None, "—", "0%"))

    def test_port_choice_skips_80_and_443(self):
        self.assertEqual(entry(container("x_y", ports=[{"PublicPort": 9000, "PrivatePort": 80}]))["port"], 9000)
        self.assertEqual(entry(container("lone", ports=[{"PrivatePort": 80}, {"PrivatePort": 443}]))["port"], 80)
        self.assertEqual(entry(container("lone", {"dashboard.port": "4567"}))["port"], 4567)

    def test_unreadable_port_label_and_dashboard_web_false(self):
        e = entry(container("zz_myproject", {"com.docker.compose.project": "zz", "dashboard.web": "false", "dashboard.port": "bad"},
                            [{"PrivatePort": 3000}], state={"Status": "Running", "ExitCode": 0}))
        self.assertEqual((e["has_web"], e["port"], e["state"], e["workspace_id"], e["category"]), (False, None, "running", "zz", "projects"))
        self.assertEqual(dash.detect_port({"dashboard.port": "bad"}, [{"PrivatePort": 3000}]), 3000)

    def test_workspace_comes_from_labels_then_the_name(self):
        self.assertEqual(entry(container("lone"))["workspace_id"], "uncategorized")
        self.assertEqual(entry(container("om_y", {"om.core": "true", "dashboard.name": "Y"}))["workspace_id"], "om")

    def test_hidden_containers_have_no_entry(self):
        self.assertIsNone(entry(container("om_caddy")))
        self.assertIsNone(entry(container("zz_hidden", {"dashboard.hide": "true"})))
        self.assertIsNone(entry(container("om_x", {"om.core": "true"})))

    def test_state_shapes(self):
        self.assertEqual(dash.container_state({"State": "paused", "Status": "Up (Paused)"}), ("paused", 0))
        self.assertEqual(dash.container_state({"State": {"Status": "Exited", "ExitCode": 3}}), ("exited", 3))
        self.assertEqual(dash.container_state({"State": "exited", "Status": "Exited (2) a day ago"}), ("exited", 2))


if __name__ == "__main__":
    unittest.main()
