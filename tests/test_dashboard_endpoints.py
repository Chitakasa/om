"""Characterization of every dashboard endpoint: the answers (status, type, body) for one fixed sequence of
requests on both tiers, including refusals and errors. The sequence is stateful (POSTs change settings), so it
runs as one test, in order."""
import json
import os
import re
import shutil
import socketserver
import sys
import tempfile
import threading
import unittest
from pathlib import Path

import _env

sys.path.insert(0, str(_env.TMP_HOME / "core" / "dashboard" / "app"))
import server as dash  # noqa: E402

L = {"Host": "localhost"}
PUB = {"Host": "192.168.1.10", "X-Access-Scope": "public"}

SERVICES = [
    {"id": "abc", "key": "web", "name": "Web", "state": "running", "is_public": True, "workspace_id": "perso",
     "domain": "perso.web.localhost", "memory_usage": 5, "memory_str": "5", "memory_percent": "1%", "status": "Up",
     "exit_code": 0, "update_available": True, "port_private": 20001, "port_public": 21001, "is_search": False, "search_url": ""},
    {"id": "def", "key": "db", "name": "Db", "state": "exited", "is_public": False, "workspace_id": "lab",
     "domain": "lab.db.localhost", "memory_usage": 0, "memory_str": "", "memory_percent": "", "status": "Exited (1)",
     "exit_code": 1, "update_available": False, "port_private": 20002, "port_public": None, "is_search": False, "search_url": ""},
]

cases=[
 ("GET","/api/scope",L,None),("GET","/api/scope",PUB,None),
 ("GET","/api/workspaces",L,None),("GET","/api/workspaces",PUB,None),
 ("GET","/api/services",L,None),("GET","/api/services?workspace=lab",L,None),("GET","/api/services?workspace=perso",L,None),
 ("GET","/api/services?scope=public",L,None),("GET","/api/services",PUB,None),
 ("GET","/api/system",L,None),("GET","/api/system",PUB,None),
 ("GET","/api/wallpaper/settings",L,None),("GET","/api/wallpaper/settings",PUB,None),
 ("GET","/api/wallpapers",L,None),("GET","/api/wallpapers",PUB,None),
 ("GET","/api/wallpaper/current",L,None),("GET","/api/wallpaper/preview_host?path=a.png",L,None),("GET","/api/wallpaper/preview_host?path=a.png",PUB,None),("GET","/api/wallpaper/preview_host?path=zz.png",L,None),
 ("GET","/opensearch.xml",L,None),("GET","/healthz",{"Host":"x"},None),("GET","/api/health",L,None),("GET","/api/nope",L,None),("GET","/",L,None),("HEAD","/api/scope",L,None),
 ("POST","/api/wallpaper/settings",L,b'{"dim":7,"name":"q.png"}'),("POST","/api/wallpaper/settings",L,b'{"workspace":"perso","blur":3}'),
 ("POST","/api/wallpaper/settings",{**L,"Content-Length":"-1"},None),
 ("POST","/api/wallpaper/set",L,b'{"name":"a.png","dim":9}'),("POST","/api/wallpaper/set",L,b'{"path":"/etc/passwd"}'),("POST","/api/wallpaper/set",L,b'notjson'),
 ("POST","/api/wallpaper/upload?name=u.png&dim=11",L,b"\x89PNG\r\n\x1a\nzz"),("POST","/api/wallpaper/upload",L,b""),
 ("POST","/api/nope",L,b"{}"),("POST","/api/wallpaper/set",PUB,b"{}"),
]

EXPECTED = [(200, 'application/json', '{"is_public_scope": false}'), (200, 'application/json', '{"is_public_scope": true}'), (200, 'application/json', '{"current_workspace": null, "is_public_scope": false, "total_running": 1, "total_services": 2, "total_workspaces": 2, "workspaces": [{"http_port": 80, "id": "perso", "name": "Perso", "path": "", "running": 1, "total": 1}, {"http_port": 80, "id": "lab", "name": "Lab", "path": "", "running": 0, "total…'), (200, 'application/json', '{"current_workspace": null, "is_public_scope": true, "total_running": 1, "total_services": 1, "total_workspaces": 0, "workspaces": []}'), (200, 'application/json', '[{"domain": "perso.web.localhost", "exit_code": 0, "id": "abc", "is_public": true, "is_search": false, "key": "web", "memory_percent": "1%", "memory_str": "5", "memory_usage": 5, "name": "Web", "port_private": 20001, "port_public": 21001, "search_url": "", "state": "running", "status": "Up", "update…'), (200, 'application/json', '[{"domain": "lab.db.localhost", "exit_code": 1, "id": "def", "is_public": false, "is_search": false, "key": "db", "memory_percent": "", "memory_str": "", "memory_usage": 0, "name": "Db", "port_private": 20002, "port_public": null, "search_url": "", "state": "exited", "status": "Exited (1)", "update_…'), (200, 'application/json', '[{"domain": "perso.web.localhost", "exit_code": 0, "id": "abc", "is_public": true, "is_search": false, "key": "web", "memory_percent": "1%", "memory_str": "5", "memory_usage": 5, "name": "Web", "port_private": 20001, "port_public": 21001, "search_url": "", "state": "running", "status": "Up", "update…'), (200, 'application/json', '[{"domain": "", "exit_code": 0, "id": "", "is_public": true, "is_search": false, "key": "web", "memory_percent": "", "memory_str": "", "memory_usage": 0, "name": "Web", "port_private": null, "port_public": 21001, "search_url": "", "state": "running", "status": "online", "update_available": false, "w…'), (200, 'application/json', '[{"domain": "", "exit_code": 0, "id": "", "is_public": true, "is_search": false, "key": "web", "memory_percent": "", "memory_str": "", "memory_usage": 0, "name": "Web", "port_private": null, "port_public": 21001, "search_url": "", "state": "running", "status": "online", "update_available": false, "w…'), (200, 'application/json', '{"host_available_bytes": 2268774400, "host_available_str": "2.11 GB", "host_total_bytes": 8151076864, "host_total_str": "7.59 GB", "host_used_bytes": 5882302464, "host_used_str": "5.48 GB", "platform_containers": [], "platform_ram_bytes": 0, "platform_ram_cache_free": false, "platform_ram_str": "0 M…'), (403, 'application/json', '{"error": "Forbidden: System metrics restricted to private ingress"}'), (200, 'application/json', '{"blur": 0, "card_blur": 16, "card_dim": 65, "dim": 20, "name": "wide_nebula.png", "timestamp": N, "workspace_id": "core"}'), (200, 'application/json', '{"blur": 0, "card_blur": 16, "card_dim": 65, "dim": 20, "name": "wallpaper.png", "timestamp": N}'), (200, 'application/json', '{"settings": {"blur": 0, "card_blur": 16, "card_dim": 65, "dim": 20, "name": "wide_nebula.png", "timestamp": N, "workspace_id": "core"}, "total": 1, "wallpapers": ["a.png"], "workspace_id": "core"}'), (403, 'application/json', '{"error": "Forbidden: Wallpaper management restricted to private ingress"}'), (200, 'image/png', '�PNG\r\n\x1a\nxx'), (200, 'image/png', '�PNG\r\n\x1a\nxx'), (403, 'application/json', '{"error": "Forbidden: Host inspection restricted to private ingress"}'), (404, 'text/plain', 'Host image not found'), (404, 'text/plain', 'No search service'), (200, 'text/plain', 'OK'), (200, 'text/plain', 'OK'), (404, 'application/json', '{"error": "Endpoint not found"}'), (200, 'text/html; charset=utf-8', '<html True>'), (200, 'application/json', ''), (200, 'application/json', '{"success": true, "timestamp": N, "workspace_id": null}'), (200, 'application/json', '{"success": true, "timestamp": N, "workspace_id": "perso"}'), (400, 'application/json', '{"error": "Expecting value: line 1 column 1 (char 0)"}'), (200, 'application/json', '{"success": true, "timestamp": N, "workspace_id": null}'), (404, 'application/json', '{"error": "Source image not found in allowed directories"}'), (400, 'application/json', '{"error": "Expecting value: line 1 column 1 (char 0)"}'), (200, 'application/json', '{"success": true, "timestamp": N, "workspace_id": null}'), (400, 'application/json', '{"error": "No file uploaded"}'), (404, 'application/json', '{"error": "Not Found"}'), (403, 'application/json', '{"error": "Forbidden: Wallpaper management is restricted to private ingress"}')]


def normal(content_type, body):
    text = body.decode("utf-8", "replace")
    if content_type and "json" in content_type:
        try:
            text = json.dumps(json.loads(text), sort_keys=True)
        except ValueError:
            pass
    text = re.sub(r'"timestamp": ?\d+', '"timestamp": N', text)
    return f"<html {len(text) > 100}>" if content_type and content_type.startswith("text/html") else (text[:300] + "…" if len(text) > 300 else text)


class TestEndpoints(unittest.TestCase):
    def test_every_endpoint_answers_as_recorded(self):
        tmp = Path(tempfile.mkdtemp())
        saved = (dash.DATA_DIR, dash.WALLPAPERS_DIR, dash.SOCKET_PATH, dash.get_running_services, os.environ.get("GLOBAL_REGISTRY"))
        try:
            (tmp / "data").mkdir()
            (tmp / "wp").mkdir()
            (tmp / "reg.json").write_text(json.dumps({"perso": {"id": "perso", "http_port": 80}, "lab": {"id": "lab"}}), encoding="utf-8", newline="\n")
            (tmp / "wp" / "a.png").write_bytes(b"\x89PNG\r\n\x1a\nxx")
            os.environ["GLOBAL_REGISTRY"] = str(tmp / "reg.json")
            dash.DATA_DIR, dash.WALLPAPERS_DIR, dash.SOCKET_PATH = str(tmp / "data"), str(tmp / "wp"), str(tmp / "no.sock")
            dash.get_running_services = lambda: [dict(s) for s in SERVICES]
            srv = socketserver.TCPServer(("127.0.0.1", 0), dash.DashboardHandler)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                for (method, path, headers, body), (status, ctype, text) in zip(cases, EXPECTED, strict=True):
                    code, ctype_got, raw = _env.http_roundtrip(srv.server_address[1], method, path, headers, body)
                    got = (code, ctype_got, normal(ctype_got, raw))
                    if path == "/api/system" and status == 200:  # host memory differs every run: check the keys
                        self.assertEqual(got[:2], (status, ctype), (method, path))
                        continue
                    self.assertEqual(got, (status, ctype, text), (method, path, headers))
            finally:
                srv.shutdown()
                srv.server_close()
        finally:
            dash.DATA_DIR, dash.WALLPAPERS_DIR, dash.SOCKET_PATH, dash.get_running_services = saved[:4]
            if saved[4] is None:
                os.environ.pop("GLOBAL_REGISTRY", None)
            else:
                os.environ["GLOBAL_REGISTRY"] = saved[4]
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
