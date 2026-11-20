"""start_workspace, step by step: ten scenarios run with every collaborator replaced by a recorder. The result, the
text printed and the order of the calls are those recorded before the function was split into steps (gate, networks,
egress, routes, one `compose up` per folder, generation record)."""
import contextlib
import io
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _env

from gitops import agesecrets, egress, enginectl, generations, limits, links, lock, policy, wsregistry

om = _env.load_om()


def norm(x):
    if isinstance(x, (set, frozenset)):
        return sorted(map(str, x))
    if isinstance(x, (list, tuple)):
        return [norm(i) for i in x]
    return x


def run_scenario(scenario):
    log = []

    def rec(name, ret=None):
        def f(*a, **k):
            log.append(name)
            return ret(*a, **k) if callable(ret) else ret
        return f

    cfgs = scenario["cfgs"]
    root = Path(tempfile.mkdtemp(prefix="om-sw-"))
    (root / ".om").mkdir()
    (root / ".om" / "config.json").write_text('{"workspace_id": "swt"}', encoding="utf-8", newline="\n")
    for name in scenario["dirs"]:
        d = root / "services" / name
        d.mkdir(parents=True)
        (d / "compose.yml").write_text("services: {}\n", encoding="utf-8", newline="\n")
    g = om["start_workspace"].__globals__

    def compose_up(cmd, **k):
        log.append("run")
        folder = cmd[cmd.index("-f") + 1].replace("\\", "/").split("/")[-2] if "-f" in cmd else ""
        return subprocess.CompletedProcess(cmd, scenario.get("rc", {}).get(folder, 0), "", scenario.get("stderr", ""))

    patches = {
        "ensure_core_running": rec("ensure_core_running"), "ensure_workspace_network": rec("ensure_ws_net"),
        "register_workspace": rec("register"), "hide_local_files": rec("hide"), "sync_caddy_routes": rec("sync_routes"),
        "reload_caddy": rec("reload_caddy"), "warn_exposed_ports": rec("warn_ports"),
        "prune_project_networks": rec("prune_nets", scenario.get("pruned", [])), "run": compose_up,
        "nolog_override": rec("nolog"), "detect_runtime": lambda: "podman",
        "project_network": rec("project_network", lambda rt, ws, rel, d, cfg: scenario["net"](d)),
    }
    attrs = [
        (policy, "compose_config", lambda runtime, cf, env: cfgs[cf.parent.name]),
        (enginectl, "network_subnet", lambda rt, n: "10.9.9.0/24"), (enginectl, "connect_router", lambda rt, ws: scenario.get("router_fail", [])),
        (wsregistry, "egress_networks", lambda ws: scenario.get("known")), (wsregistry, "set_egress_networks", lambda ws, nets: None),
        (egress, "render_workspace", lambda *a, **k: {"api": "http://om_egress:3128"}), (egress, "write_override", lambda *a, **k: None),
        (lock, "read", lambda root: scenario.get("pinned", {})), (lock, "write_override", lambda *a, **k: None),
        (limits, "write_override", lambda *a, **k: (None, scenario.get("limit_problems", []))),
        (generations, "snapshot", lambda root: {"commit": "abc", "dirty": scenario.get("dirty", False), "lock": None}),
        (generations, "verify", lambda ws, root: (scenario.get("trusted", True), "me@x")),
        (generations, "mode", lambda: scenario.get("mode", "warn")),
        (generations, "record", lambda *a, **k: {"n": 7}), (generations, "remember_signers", lambda *a, **k: None),
        (links, "sync", lambda rt: scenario.get("link_problems", [])),
    ]

    def secrets(*a, **k):
        if "secret_exc" in scenario:
            raise RuntimeError(scenario["secret_exc"])

    attrs.append((agesecrets, "write_override", secrets))
    with contextlib.ExitStack() as st:
        for k, v in patches.items():
            st.enter_context(mock.patch.dict(g, {k: v}))
        for obj, attr, fn in attrs:
            st.enter_context(mock.patch.object(obj, attr, fn))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            result = om["start_workspace"](root, scenario.get("target"), build=scenario.get("build", False), kind=scenario.get("kind", "start"))
    shutil.rmtree(root, ignore_errors=True)
    text = buf.getvalue().replace(str(root), "<root>")
    return result, re.sub(r"[^ ]*/_state/", "<state>/", text), log


def cfg(**svc):
    return ({"services": dict(svc)}, "")


plain = {"image": "nginx:1", "labels": {}}
SCENARIOS = {
 "plain two projects": {"dirs": ["web","api"], "cfgs": {"web":cfg(web=plain),"api":cfg(api=plain)}, "net": lambda d:(f"swt_{d.name}_net", Path(f"/o/{d.name}.yml"))},
 "egress learn + audit": {"dirs": ["web","api"], "cfgs": {"web":cfg(web={"image":"x","labels":{"om.egress":"learn"},"cap_drop":["ALL"]}),"api":cfg(api={"image":"y","labels":{"om.egress":"audit"},"cap_drop":["ALL"]})}, "net": lambda d:(f"swt_{d.name}_net", None)},
 "policy violation enforced": {"dirs": ["bad"], "cfgs": {"bad":cfg(bad={"image":"x","privileged":True})}, "net": lambda d:(None,None)},
 "net failure": {"dirs": ["web"], "cfgs": {"web":cfg(web=plain)}, "net": lambda d:(_ for _ in ()).throw(RuntimeError("boom"))},
 "compose fails": {"dirs": ["web"], "cfgs": {"web":cfg(web=plain)}, "net": lambda d:(None,None), "rc": {"web":1}, "stderr": "err text"},
 "secrets fail": {"dirs": ["web"], "cfgs": {"web":cfg(web=plain)}, "net": lambda d:(None,None), "secret_exc": "no key"},
 "target + unsigned dirty": {"dirs": ["web","api"], "cfgs": {"web":cfg(web=plain),"api":cfg(api=plain)}, "net": lambda d:(None,None), "target": "web", "dirty": True, "known": ["a"], "pinned": {}},
 "shared network warning": {"dirs": ["web"], "cfgs": {"web":cfg(web={"image":"x","labels":{"om.network":"shared"}})}, "net": lambda d:(None,None), "router_fail": ["swt_net"], "link_problems": ["swt/web: x"], "limit_problems": ["bad limit"]},
 "enforce refuses unsigned": {"dirs": ["web"], "cfgs": {"web":cfg(web=plain)}, "net": lambda d:(None,None), "trusted": False, "mode": "enforce"},
 "unlocked images + build + prune": {"dirs": ["web"], "cfgs": {"web":cfg(web={"image":"nginx:1","labels":{}})}, "net": lambda d:(None,None), "build": True, "pruned": ["swt_old_net"]},
}
EXPECTED = {'plain two projects': (True, '  \x1b[32m✓ commit abc signed by me@x\x1b[0m\n\n\x1b[1m🚀 Starting User Workloads [SWT]\x1b[0m\n──────────────────────────────────────────────────────────────────────────────\n  \x1b[33m⚠ not in .om/lock.json (tag can change under you): nginx:1 — run `om lock`\x1b[0m\n  ▶ [Priority 50] Starting \x1b[1mapi\x1b[0m...\n    \x1b[32m✓ api running\x1b[0m\n  ▶ [Priority 50] Starting \x1b[1mweb\x1b[0m...\n    \x1b[32m✓ web running\x1b[0m\n\n\x1b[32m✓ User workloads live (generation 7). Access via: http://swt.<service>.localhost\x1b[0m\n\n', ['register', 'hide', 'ensure_ws_net', 'ensure_core_running', 'sync_routes', 'project_network', 'project_network', 'prune_nets', 'nolog', 'run', 'nolog', 'run', 'reload_caddy', 'warn_ports']), 'egress learn + audit': (True, '  \x1b[32m✓ commit abc signed by me@x\x1b[0m\n\n\x1b[1m🚀 Starting User Workloads [SWT]\x1b[0m\n──────────────────────────────────────────────────────────────────────────────\n  \x1b[33m⚠ not in .om/lock.json (tag can change under you): x, y — run `om lock`\x1b[0m\n  \x1b[33m⚠ learning (any public host allowed, recorded): web — `om egress log`, then list the hosts\x1b[0m\n  \x1b[36mℹ audit mode (all public egress logged permanently): api — see `om egress log`\x1b[0m\n  ▶ [Priority 50] Starting \x1b[1mapi\x1b[0m...\n    \x1b[32m✓ api running\x1b[0m\n  ▶ [Priority 50] Starting \x1b[1mweb\x1b[0m...\n    \x1b[32m✓ web running\x1b[0m\n\n\x1b[32m✓ User workloads live (generation 7). Access via: http://swt.<service>.localhost\x1b[0m\n\n', ['register', 'hide', 'ensure_ws_net', 'ensure_core_running', 'sync_routes', 'project_network', 'project_network', 'prune_nets', 'nolog', 'run', 'nolog', 'run', 'reload_caddy', 'warn_ports']), 'policy violation enforced': (False, '  \x1b[32m✓ commit abc signed by me@x\x1b[0m\n\n\x1b[1m🚀 Starting User Workloads [SWT]\x1b[0m\n──────────────────────────────────────────────────────────────────────────────\n  \x1b[33m⚠ not in .om/lock.json (tag can change under you): x — run `om lock`\x1b[0m\n  ▶ [Priority 50] Starting \x1b[1mbad\x1b[0m...\n    \x1b[31m✗ policy: 1 violation(s) in compose.yml\x1b[0m\n      - bad: privileged: true — remove it\n      Not started (OM_POLICY=enforce). Fix the lines above; `om policy check` re-checks.\n\n\x1b[32m✓ User workloads live (generation 7). Access via: http://swt.<service>.localhost\x1b[0m\n\n', ['register', 'hide', 'ensure_ws_net', 'ensure_core_running', 'sync_routes', 'project_network', 'prune_nets', 'reload_caddy', 'warn_ports']), 'net failure': (False, '  \x1b[32m✓ commit abc signed by me@x\x1b[0m\n\n\x1b[1m🚀 Starting User Workloads [SWT]\x1b[0m\n──────────────────────────────────────────────────────────────────────────────\n    \x1b[31m✗ web: boom — not started (it would share the workspace network)\x1b[0m\n  \x1b[33m⚠ not in .om/lock.json (tag can change under you): nginx:1 — run `om lock`\x1b[0m\n  ▶ [Priority 50] Starting \x1b[1mweb\x1b[0m...\n\n\x1b[32m✓ User workloads live (generation 7). Access via: http://swt.<service>.localhost\x1b[0m\n\n', ['register', 'hide', 'ensure_ws_net', 'ensure_core_running', 'sync_routes', 'project_network', 'prune_nets', 'reload_caddy', 'warn_ports']), 'compose fails': (False, '  \x1b[32m✓ commit abc signed by me@x\x1b[0m\n\n\x1b[1m🚀 Starting User Workloads [SWT]\x1b[0m\n──────────────────────────────────────────────────────────────────────────────\n  \x1b[33m⚠ not in .om/lock.json (tag can change under you): nginx:1 — run `om lock`\x1b[0m\n  ▶ [Priority 50] Starting \x1b[1mweb\x1b[0m...\n    \x1b[31m❌ Failed to start web:\x1b[0m\nerr text\n\n\x1b[32m✓ User workloads live (generation 7). Access via: http://swt.<service>.localhost\x1b[0m\n\n', ['register', 'hide', 'ensure_ws_net', 'ensure_core_running', 'sync_routes', 'project_network', 'prune_nets', 'nolog', 'run', 'reload_caddy', 'warn_ports']), 'secrets fail': (False, '  \x1b[32m✓ commit abc signed by me@x\x1b[0m\n\n\x1b[1m🚀 Starting User Workloads [SWT]\x1b[0m\n──────────────────────────────────────────────────────────────────────────────\n  \x1b[33m⚠ not in .om/lock.json (tag can change under you): nginx:1 — run `om lock`\x1b[0m\n  ▶ [Priority 50] Starting \x1b[1mweb\x1b[0m...\n    \x1b[31m✗ secrets: no key — not started (the host key is in <state>/data/age.key)\x1b[0m\n\n\x1b[32m✓ User workloads live (generation 7). Access via: http://swt.<service>.localhost\x1b[0m\n\n', ['register', 'hide', 'ensure_ws_net', 'ensure_core_running', 'sync_routes', 'project_network', 'prune_nets', 'reload_caddy', 'warn_ports']), 'target + unsigned dirty': (True, '  \x1b[33m⚠ uncommitted changes: running the working tree unsigned, generation marked dirty.\x1b[0m\n\n\x1b[1m🚀 Starting User Workloads [SWT]\x1b[0m\n──────────────────────────────────────────────────────────────────────────────\n  \x1b[33m⚠ not in .om/lock.json (tag can change under you): nginx:1 — run `om lock`\x1b[0m\n  ▶ [Priority 50] Starting \x1b[1mweb\x1b[0m...\n    \x1b[32m✓ web running\x1b[0m\n\n\x1b[32m✓ User workloads live (generation 7). Access via: http://swt.<service>.localhost\x1b[0m\n\n', ['register', 'hide', 'ensure_ws_net', 'ensure_core_running', 'sync_routes', 'project_network', 'nolog', 'run', 'reload_caddy', 'warn_ports']), 'shared network warning': (True, "  \x1b[32m✓ commit abc signed by me@x\x1b[0m\n\n\x1b[1m🚀 Starting User Workloads [SWT]\x1b[0m\n──────────────────────────────────────────────────────────────────────────────\n  \x1b[33m⚠ not in .om/lock.json (tag can change under you): x — run `om lock`\x1b[0m\n    \x1b[33m⚠ could not attach the router/egress to swt_net: its routes return 502\x1b[0m\n  ▶ [Priority 50] Starting \x1b[1mweb\x1b[0m...\n    \x1b[33m⚠ compose.yml has om.network=shared but doesn't join swt_net: its routes return 502.\x1b[0m\n      Add: networks: {default: {name: ${WORKSPACE_NET}, external: true}}\n    \x1b[33m⚠ bad limit — ignored, no such limit\x1b[0m\n    \x1b[32m✓ web running\x1b[0m\n    \x1b[33m⚠ link swt/web: x\x1b[0m\n\n\x1b[32m✓ User workloads live (generation 7). Access via: http://swt.<service>.localhost\x1b[0m\n\n", ['register', 'hide', 'ensure_ws_net', 'ensure_core_running', 'sync_routes', 'project_network', 'prune_nets', 'nolog', 'run', 'reload_caddy', 'warn_ports']), 'enforce refuses unsigned': (False, '  \x1b[31m✗ commit abc: me@x. Not deployed (OM_SIGNED=enforce).\x1b[0m\n', []), 'unlocked images + build + prune': (True, '  \x1b[32m✓ commit abc signed by me@x\x1b[0m\n\n\x1b[1m🚀 Starting User Workloads [SWT]\x1b[0m\n──────────────────────────────────────────────────────────────────────────────\n  \x1b[33m⚠ not in .om/lock.json (tag can change under you): nginx:1 — run `om lock`\x1b[0m\n  \x1b[36m- Removed network swt_old_net (its folder is gone)\x1b[0m\n  ▶ [Priority 50] Starting \x1b[1mweb\x1b[0m...\n    \x1b[32m✓ web running\x1b[0m\n\n\x1b[32m✓ User workloads live (generation 7). Access via: http://swt.<service>.localhost\x1b[0m\n\n', ['register', 'hide', 'ensure_ws_net', 'ensure_core_running', 'sync_routes', 'project_network', 'prune_nets', 'nolog', 'run', 'reload_caddy', 'warn_ports'])}


class TestStartWorkspace(unittest.TestCase):
    def test_scenarios_behave_as_recorded(self):
        for name, scenario in SCENARIOS.items():
            with self.subTest(name):
                result, text, calls = run_scenario(scenario)
                want_result, want_text, want_calls = EXPECTED[name]
                self.assertEqual(calls, want_calls)
                self.assertEqual(text, want_text)
                self.assertEqual(result, want_result)


if __name__ == "__main__":
    unittest.main()
