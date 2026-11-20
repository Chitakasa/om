"""`om status` (text and --json), with and without a workspace: container states, tiers and URLs for core containers
that are running, crashed, stopped and absent. Expected output recorded before cmd_status was split into steps."""
import argparse
import contextlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _env

from gitops import generations, omstate, wsregistry

om = _env.load_om()
PS = {
    "om_caddy": ("Up 3 hours", "running"), "om_router": ("Up 3 hours", "running"),
    "om_egress": ("Exited (1) 2 minutes ago", "exited"), "om_sockguard": ("Exited (0) 2 minutes ago", "exited"),
    "om_dashboard": ("Created", "created"), "ws_web": ("Up 1 hour (healthy)", "running"),
    "ws_db": ("Exited (137) 5 minutes ago", "exited"), "ws_tcp": ("Up 1 hour", "running"),
}
EXPECTED = {'ws-json': '{\n  "core": {\n    "om_caddy": "running",\n    "om_dashboard": "stopped",\n    "om_egress": "crashed",\n    "om_router": "running",\n    "om_sockguard": "stopped",\n    "om_stream_edge": "absent",\n    "om_stream_router": "absent"\n  },\n  "runtime": "podman",\n  "version": "1.0.0",\n  "workspace": {\n    "generation": {\n      "n": 3\n    },\n    "id": "ws",\n    "path": "<root>",\n    "services": [\n      {\n        "containers": {\n          "ws_web": "running"\n        },\n        "scope": "private",\n        "service": "web"\n      },\n      {\n        "containers": {\n          "ws_db": "crashed"\n        },\n        "scope": "public",\n        "service": "db"\n      },\n      {\n        "containers": {\n          "ws_tcp": "running"\n        },\n        "scope": "public",\n        "service": "tcp"\n      }\n    ],\n    "updates": [\n      "docker.io/x/y:1"\n    ],\n    "updates_checked": 123\n  }\n}\n', 'ws-text': '\n\x1b[1mOM PLATFORM\x1b[0m  (om 1.0.0)\n══════════════════════════════════════════════════════════════════════════════\n  om_caddy         \x1b[32m🟢 Running\x1b[0m     edge proxy\n  om_router        \x1b[32m🟢 Running\x1b[0m     internal router\n  om_egress        \x1b[31m❌ Crashed\x1b[0m     outbound allow-list proxy\n  om_sockguard     \x1b[33m⏹ Stopped\x1b[0m     read-only engine filter\n  om_stream_edge   \x1b[90m⚪ Offline\x1b[0m     raw TCP edge\n  om_stream_router \x1b[90m⚪ Offline\x1b[0m     raw TCP router\n  om_dashboard     \x1b[33m⏹ Stopped\x1b[0m     dashboard  http://localhost/\n\n\x1b[1mWORKSPACE: ws\x1b[0m  (<root>)\n──────────────────────────────────────────────────────────────────────────────\n  generation 3  clean\n  \x1b[36mupdates  1 available (y:1) — om update --dry-run\x1b[0m\n  web                  service  \x1b[32m🟢 Running\x1b[0m     private  http://ws.web.localhost\n  db                   service  \x1b[31m❌ Crashed\x1b[0m     public   —\n  tcp                  service  \x1b[32m🟢 Running\x1b[0m     public   tcp://192.168.1.5:22001\n\n', 'nows-json': '{\n  "core": {\n    "om_caddy": "running",\n    "om_dashboard": "stopped",\n    "om_egress": "crashed",\n    "om_router": "running",\n    "om_sockguard": "stopped",\n    "om_stream_edge": "absent",\n    "om_stream_router": "absent"\n  },\n  "runtime": "podman",\n  "version": "1.0.0"\n}\n', 'nows-text': '\n\x1b[1mOM PLATFORM\x1b[0m  (om 1.0.0)\n══════════════════════════════════════════════════════════════════════════════\n  om_caddy         \x1b[32m🟢 Running\x1b[0m     edge proxy\n  om_router        \x1b[32m🟢 Running\x1b[0m     internal router\n  om_egress        \x1b[31m❌ Crashed\x1b[0m     outbound allow-list proxy\n  om_sockguard     \x1b[33m⏹ Stopped\x1b[0m     read-only engine filter\n  om_stream_edge   \x1b[90m⚪ Offline\x1b[0m     raw TCP edge\n  om_stream_router \x1b[90m⚪ Offline\x1b[0m     raw TCP router\n  om_dashboard     \x1b[33m⏹ Stopped\x1b[0m     dashboard  http://localhost/\nLIST\n'}


def status_output(with_workspace: bool, as_json: bool) -> str:
    g = om["cmd_status"].__globals__
    conf = om["CONF_D"]
    conf.mkdir(parents=True, exist_ok=True)
    (conf / "ws-web.caddy").write_text("# Service: web (ws)\n", encoding="utf-8", newline="\n")
    (conf / "ws-db.public_alias").write_text("x", encoding="utf-8", newline="\n")
    root = None
    if with_workspace:
        root = Path(tempfile.mkdtemp(prefix="om-st-"))
        (root / ".om").mkdir()
        (root / ".om" / "config.json").write_text('{"workspace_id": "ws"}', encoding="utf-8", newline="\n")
        for name in ("web", "db", "tcp", "empty"):
            (root / "services" / name).mkdir(parents=True)
            (root / "services" / name / "compose.yml").write_text("services: {}\n", encoding="utf-8", newline="\n")
    dirs = [(50, root / "services" / n) for n in ("web", "db", "tcp")] if root else []
    containers = {"web": ["ws_web"], "db": ["ws_db"], "tcp": ["ws_tcp"], "empty": ["ws_empty"]}
    patches = {
        "run": lambda cmd, **k: subprocess.CompletedProcess(cmd, 0, "".join(f"{n}\t{s}\t{st}\n" for n, (s, st) in PS.items()), ""),
        "detect_runtime": lambda: "podman", "service_containers": lambda rt, r, d: containers[d.name],
        "discover_compose_dirs": lambda r, t=None: dirs,
        "cached_updates": lambda ws: (["docker.io/x/y:1"], 123) if with_workspace else ([], 0),
        "generation_summary": lambda ws, r: "generation 3  clean", "cmd_list": lambda a: print("LIST"),
    }
    buf = io.StringIO()
    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.dict(g, patches))
        stack.enter_context(mock.patch.object(generations, "current", lambda ws: {"n": 3}))
        stack.enter_context(mock.patch.object(wsregistry, "stream_ports", lambda: {"ws/tcp": {"host_port": 22001, "scope": "public"}}))
        stack.enter_context(mock.patch.object(omstate, "parse_env_file", lambda p: {"LAN_IP": "192.168.1.5"}))
        with contextlib.redirect_stdout(buf):
            om["cmd_status"](root, argparse.Namespace(json=as_json))
    for f in (conf / "ws-web.caddy", conf / "ws-db.public_alias"):
        f.unlink(missing_ok=True)
    if root:
        shutil.rmtree(root, ignore_errors=True)
    return buf.getvalue().replace(str(root), "<root>").replace(json.dumps(str(root))[1:-1], "<root>") if root else buf.getvalue()


class TestStatus(unittest.TestCase):
    def test_each_mode_prints_as_recorded(self):
        for with_workspace in (True, False):
            for as_json in (True, False):
                key = f"{'ws' if with_workspace else 'nows'}-{'json' if as_json else 'text'}"
                with self.subTest(key):
                    self.assertEqual(status_output(with_workspace, as_json), EXPECTED[key])

    def test_container_state_classification(self):
        classify = om["container_state"]
        states = {"a": ("up 2 hours", "running"), "b": ("exited (0) 1 hour ago", "exited"), "c": ("exited (2) 1 hour ago", "exited"),
                  "d": ("created", "created")}
        self.assertEqual([classify(states, n) for n in "abcdz"], ["running", "stopped", "crashed", "stopped", "absent"])


if __name__ == "__main__":
    unittest.main()
