"""core_up: preflight, the egress image, the generated files, retired parts, `compose up`, and the check that every core
container stays up. Twelve scenarios with every collaborator recorded: the result, the text printed and the calls made, in
order. Expected values were recorded before core_up was split into steps."""
import contextlib
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _env  # noqa: F401

from gitops import core, egress, omstate

EXPECTED = {'preflight problems': {'result': False, 'out': '\x1b[31m✗ engine is down\x1b[0m\n\x1b[31m✗ no compose\x1b[0m\n', 'calls': [['ensure_core_prerequisites', [], []], ['preflight', ['podman'], []]], 'route': None}, 'image build fails': {'result': False, 'out': '', 'calls': [['ensure_core_prerequisites', [], []], ['preflight', ['podman'], []], ['ensure_image', ['podman'], []]], 'route': None}, 'quiet, all good': {'result': True, 'out': '', 'calls': [['ensure_core_prerequisites', [], []], ['preflight', ['podman'], []], ['ensure_image', ['podman'], []], ['write_runtime_files', ['podman'], []], ['run', ['podman', 'container', 'inspect', 'om_wg'], []], ['run', ['podman', 'container', 'inspect', 'om_gate'], []], ['run', ['podman', 'container', 'inspect', 'portainer'], []], ['rmtree', ['<tmp>/state/access'], ['ignore_errors']], ['rmtree', ['<tmp>/state/gate'], ['ignore_errors']], ['rmtree', ['<tmp>/state/door'], ['ignore_errors']], ['rmtree', ['<tmp>/state/mirror'], ['ignore_errors']], ['rmtree', ['<tmp>/state/hostquiet'], ['ignore_errors']], ['revive_zombies', ['podman'], []], ['core_compose', ['podman', 'up', '-d', '--remove-orphans'], []], ['run', ['podman', 'compose', 'up', '-d', '--remove-orphans'], ['cwd']], ['connect_router', ['podman', "dict_keys(['ws'])"], []]], 'route': None}, 'verbose with an untrusted VPN': {'result': True, 'out': '  Ingress: localhost, VPN 100.64.0.1, LAN 192.168.1.5 (public tier)\n  VPN wg9 (no address) is not trusted — if only your devices are on it: om vpn trust wg9\n', 'calls': [['ensure_core_prerequisites', [], []], ['preflight', ['podman'], []], ['ensure_image', ['podman'], []], ['write_runtime_files', ['podman'], []], ['run', ['podman', 'container', 'inspect', 'om_wg'], []], ['run', ['podman', 'container', 'inspect', 'om_gate'], []], ['run', ['podman', 'container', 'inspect', 'portainer'], []], ['rmtree', ['<tmp>/state/access'], ['ignore_errors']], ['rmtree', ['<tmp>/state/gate'], ['ignore_errors']], ['rmtree', ['<tmp>/state/door'], ['ignore_errors']], ['rmtree', ['<tmp>/state/mirror'], ['ignore_errors']], ['rmtree', ['<tmp>/state/hostquiet'], ['ignore_errors']], ['revive_zombies', ['podman'], []], ['core_compose', ['podman', 'up', '-d', '--remove-orphans'], []], ['run', ['podman', 'compose', 'up', '-d', '--remove-orphans'], ['cwd']], ['connect_router', ['podman', "dict_keys(['ws'])"], []]], 'route': None}, 'retired parts are removed': {'result': True, 'out': '', 'calls': [['ensure_core_prerequisites', [], []], ['preflight', ['podman'], []], ['ensure_image', ['podman'], []], ['write_runtime_files', ['podman'], []], ['run', ['podman', 'container', 'inspect', 'om_wg'], []], ['run', ['podman', 'container', 'inspect', 'om_gate'], []], ['run', ['podman', 'container', 'inspect', 'portainer'], []], ['run', ['podman', 'rm', '-f', 'om_caddy'], []], ['run', ['podman', 'rm', '-f', 'om_wg'], []], ['run', ['podman', 'rm', '-f', 'portainer'], []], ['rmtree', ['<tmp>/state/access'], ['ignore_errors']], ['rmtree', ['<tmp>/state/gate'], ['ignore_errors']], ['rmtree', ['<tmp>/state/door'], ['ignore_errors']], ['rmtree', ['<tmp>/state/mirror'], ['ignore_errors']], ['rmtree', ['<tmp>/state/hostquiet'], ['ignore_errors']], ['revive_zombies', ['podman'], []], ['core_compose', ['podman', 'up', '-d', '--remove-orphans'], []], ['run', ['podman', 'compose', 'up', '-d', '--remove-orphans'], ['cwd']], ['connect_router', ['podman', "dict_keys(['ws'])"], []]], 'route': None}, 'gated routes are cut': {'result': True, 'out': '', 'calls': [['ensure_core_prerequisites', [], []], ['preflight', ['podman'], []], ['ensure_image', ['podman'], []], ['write_runtime_files', ['podman'], []], ['run', ['podman', 'container', 'inspect', 'om_wg'], []], ['run', ['podman', 'container', 'inspect', 'om_gate'], []], ['run', ['podman', 'container', 'inspect', 'portainer'], []], ['rmtree', ['<tmp>/state/access'], ['ignore_errors']], ['rmtree', ['<tmp>/state/gate'], ['ignore_errors']], ['rmtree', ['<tmp>/state/door'], ['ignore_errors']], ['rmtree', ['<tmp>/state/mirror'], ['ignore_errors']], ['rmtree', ['<tmp>/state/hostquiet'], ['ignore_errors']], ['revive_zombies', ['podman'], []], ['core_compose', ['podman', 'up', '-d', '--remove-orphans'], []], ['run', ['podman', 'compose', 'up', '-d', '--remove-orphans'], ['cwd']], ['connect_router', ['podman', "dict_keys(['ws'])"], []]], 'route': 'keep\n'}, 'recreate': {'result': True, 'out': '', 'calls': [['ensure_core_prerequisites', [], []], ['preflight', ['podman'], []], ['ensure_image', ['podman'], []], ['write_runtime_files', ['podman'], []], ['run', ['podman', 'container', 'inspect', 'om_wg'], []], ['run', ['podman', 'container', 'inspect', 'om_gate'], []], ['run', ['podman', 'container', 'inspect', 'portainer'], []], ['rmtree', ['<tmp>/state/access'], ['ignore_errors']], ['rmtree', ['<tmp>/state/gate'], ['ignore_errors']], ['rmtree', ['<tmp>/state/door'], ['ignore_errors']], ['rmtree', ['<tmp>/state/mirror'], ['ignore_errors']], ['rmtree', ['<tmp>/state/hostquiet'], ['ignore_errors']], ['revive_zombies', ['podman'], []], ['core_compose', ['podman', 'up', '-d', '--remove-orphans', '--force-recreate'], []], ['run', ['podman', 'compose', 'up', '-d', '--remove-orphans', '--force-recreate'], ['cwd']], ['connect_router', ['podman', "dict_keys(['ws'])"], []]], 'route': None}, 'compose fails with an address hint': {'result': False, 'out': '\x1b[31m✗ Global Core failed to start:\x1b[0m\nError: cannot assign requested address\n  Hint: an ingress address changed or a port is taken. Check `om doctor`, or set OM_LAN_IP / OM_VPN in <config>/om.env.\n', 'calls': [['ensure_core_prerequisites', [], []], ['preflight', ['podman'], []], ['ensure_image', ['podman'], []], ['write_runtime_files', ['podman'], []], ['run', ['podman', 'container', 'inspect', 'om_wg'], []], ['run', ['podman', 'container', 'inspect', 'om_gate'], []], ['run', ['podman', 'container', 'inspect', 'portainer'], []], ['rmtree', ['<tmp>/state/access'], ['ignore_errors']], ['rmtree', ['<tmp>/state/gate'], ['ignore_errors']], ['rmtree', ['<tmp>/state/door'], ['ignore_errors']], ['rmtree', ['<tmp>/state/mirror'], ['ignore_errors']], ['rmtree', ['<tmp>/state/hostquiet'], ['ignore_errors']], ['revive_zombies', ['podman'], []], ['core_compose', ['podman', 'up', '-d', '--remove-orphans'], []], ['run', ['podman', 'compose', 'up', '-d', '--remove-orphans'], ['cwd']]], 'route': None}, 'compose fails otherwise': {'result': False, 'out': '\x1b[31m✗ Global Core failed to start:\x1b[0m\nboom\n', 'calls': [['ensure_core_prerequisites', [], []], ['preflight', ['podman'], []], ['ensure_image', ['podman'], []], ['write_runtime_files', ['podman'], []], ['run', ['podman', 'container', 'inspect', 'om_wg'], []], ['run', ['podman', 'container', 'inspect', 'om_gate'], []], ['run', ['podman', 'container', 'inspect', 'portainer'], []], ['rmtree', ['<tmp>/state/access'], ['ignore_errors']], ['rmtree', ['<tmp>/state/gate'], ['ignore_errors']], ['rmtree', ['<tmp>/state/door'], ['ignore_errors']], ['rmtree', ['<tmp>/state/mirror'], ['ignore_errors']], ['rmtree', ['<tmp>/state/hostquiet'], ['ignore_errors']], ['revive_zombies', ['podman'], []], ['core_compose', ['podman', 'up', '-d', '--remove-orphans'], []], ['run', ['podman', 'compose', 'up', '-d', '--remove-orphans'], ['cwd']]], 'route': None}, 'a container does not stay up': {'result': False, 'out': '\x1b[31m✗ om_caddy is not running.\x1b[0m Last log lines:\n\n', 'calls': [['ensure_core_prerequisites', [], []], ['preflight', ['podman'], []], ['ensure_image', ['podman'], []], ['write_runtime_files', ['podman'], []], ['run', ['podman', 'container', 'inspect', 'om_wg'], []], ['run', ['podman', 'container', 'inspect', 'om_gate'], []], ['run', ['podman', 'container', 'inspect', 'portainer'], []], ['rmtree', ['<tmp>/state/access'], ['ignore_errors']], ['rmtree', ['<tmp>/state/gate'], ['ignore_errors']], ['rmtree', ['<tmp>/state/door'], ['ignore_errors']], ['rmtree', ['<tmp>/state/mirror'], ['ignore_errors']], ['rmtree', ['<tmp>/state/hostquiet'], ['ignore_errors']], ['revive_zombies', ['podman'], []], ['core_compose', ['podman', 'up', '-d', '--remove-orphans'], []], ['run', ['podman', 'compose', 'up', '-d', '--remove-orphans'], ['cwd']], ['run', ['podman', 'logs', '--tail', '15', 'om_caddy'], []]], 'route': None}, 'router cannot attach': {'result': False, 'out': '\x1b[33m⚠ Could not attach the router to ws_net\x1b[0m\n', 'calls': [['ensure_core_prerequisites', [], []], ['preflight', ['podman'], []], ['ensure_image', ['podman'], []], ['write_runtime_files', ['podman'], []], ['run', ['podman', 'container', 'inspect', 'om_wg'], []], ['run', ['podman', 'container', 'inspect', 'om_gate'], []], ['run', ['podman', 'container', 'inspect', 'portainer'], []], ['rmtree', ['<tmp>/state/access'], ['ignore_errors']], ['rmtree', ['<tmp>/state/gate'], ['ignore_errors']], ['rmtree', ['<tmp>/state/door'], ['ignore_errors']], ['rmtree', ['<tmp>/state/mirror'], ['ignore_errors']], ['rmtree', ['<tmp>/state/hostquiet'], ['ignore_errors']], ['revive_zombies', ['podman'], []], ['core_compose', ['podman', 'up', '-d', '--remove-orphans'], []], ['run', ['podman', 'compose', 'up', '-d', '--remove-orphans'], ['cwd']], ['connect_router', ['podman', "dict_keys(['ws'])"], []]], 'route': None}, 'zombies are revived first': {'result': True, 'out': '', 'calls': [['ensure_core_prerequisites', [], []], ['preflight', ['podman'], []], ['ensure_image', ['podman'], []], ['write_runtime_files', ['podman'], []], ['run', ['podman', 'container', 'inspect', 'om_wg'], []], ['run', ['podman', 'container', 'inspect', 'om_gate'], []], ['run', ['podman', 'container', 'inspect', 'portainer'], []], ['rmtree', ['<tmp>/state/access'], ['ignore_errors']], ['rmtree', ['<tmp>/state/gate'], ['ignore_errors']], ['rmtree', ['<tmp>/state/door'], ['ignore_errors']], ['rmtree', ['<tmp>/state/mirror'], ['ignore_errors']], ['rmtree', ['<tmp>/state/hostquiet'], ['ignore_errors']], ['revive_zombies', ['podman'], []], ['core_compose', ['podman', 'up', '-d', '--remove-orphans'], []], ['run', ['podman', 'compose', 'up', '-d', '--remove-orphans'], ['cwd']], ['connect_router', ['podman', "dict_keys(['ws'])"], []]], 'route': None}}

SCENARIOS = {
    "preflight problems": {"preflight": ["engine is down", "no compose"]},
    "image build fails": {"image": False},
    "quiet, all good": {"quiet": True},
    "verbose with an untrusted VPN": {"resolved": {"vpn_ips": ["100.64.0.1"], "lan_ip": "192.168.1.5"}, "candidates": [("tailscale0", "100.64.0.1"), ("wg9", "")], "spec": "tailscale0"},
    "retired parts are removed": {"retired": ["om_wg", "portainer"], "quiet": True},
    "gated routes are cut": {"gated_route": True, "quiet": True},
    "recreate": {"recreate": True, "quiet": True},
    "compose fails with an address hint": {"compose": (1, "Error: cannot assign requested address"), "quiet": True},
    "compose fails otherwise": {"compose": (1, "boom"), "quiet": True},
    "a container does not stay up": {"down": {"om_caddy"}, "quiet": True},
    "router cannot attach": {"router_failed": ["ws_net"], "quiet": True},
    "zombies are revived first": {"quiet": True, "zombies": True},
}


def run_core_up(sc):
    tmp = Path(tempfile.mkdtemp(prefix="om-cu-"))
    routes, state = tmp / "routes", tmp / "state"
    routes.mkdir()
    state.mkdir()
    if sc.get("gated_route"):
        (routes / "ws-web.caddy").write_text("keep\n# Through the door, behind the gate\ngated\n", encoding="utf-8", newline="\n")
    calls = []

    def record(name, answer=None):
        def call(*a, **k):
            calls.append([name, [str(x) for x in a], sorted(str(x) for x in k)])
            return answer(*a, **k) if callable(answer) else answer
        return call

    def fake_run(cmd, **kw):
        calls.append(["run", [str(c) for c in cmd], sorted(kw)])
        words = [str(c) for c in cmd]
        if "inspect" in words:
            return subprocess.CompletedProcess(cmd, 0 if words[-1] in sc.get("retired", []) else 1, "", "")
        if words[:2] == ["podman", "compose"] or "up" in words:
            code, err = sc.get("compose", (0, ""))
            return subprocess.CompletedProcess(cmd, code, "", err)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    clock = iter(range(0, 1000, 25))
    out = io.StringIO()
    with contextlib.ExitStack() as stack:
        for name, answer in (("ensure_core_prerequisites", None), ("revive_zombies", ([], []))):
            stack.enter_context(mock.patch.object(core, name, record(name, answer)))
        stack.enter_context(mock.patch.object(core, "preflight", record("preflight", sc.get("preflight", []))))
        stack.enter_context(mock.patch.object(egress, "ensure_image", record("ensure_image", sc.get("image", True))))
        stack.enter_context(mock.patch.object(core, "write_runtime_files", record("write_runtime_files", {"vpn_ips": [], "lan_ip": "", **sc.get("resolved", {})})))
        stack.enter_context(mock.patch.object(core, "load_settings", lambda: {"OM_VPN": sc.get("spec", "")}))
        stack.enter_context(mock.patch.object(core, "vpn_candidates", lambda: sc.get("candidates", [])))
        stack.enter_context(mock.patch.object(core, "run", fake_run))
        stack.enter_context(mock.patch.object(core, "core_compose", record("core_compose", lambda rt, *a: ["podman", "compose", *a])))
        stack.enter_context(mock.patch.object(core, "container_running", lambda rt, c: c not in sc.get("down", set())))
        stack.enter_context(mock.patch.object(core, "connect_router", record("connect_router", sc.get("router_failed", []))))
        stack.enter_context(mock.patch.object(core, "read_registry", lambda: {"ws": {}}))
        stack.enter_context(mock.patch.object(core, "ROUTES_DIR", routes))
        stack.enter_context(mock.patch.object(core, "STATE_DIR", state))
        stack.enter_context(mock.patch.object(core.shutil, "rmtree", record("rmtree")))
        stack.enter_context(mock.patch.object(core.time, "monotonic", lambda: next(clock)))
        stack.enter_context(mock.patch.object(core.time, "sleep", record("sleep")))
        with contextlib.redirect_stdout(out):
            result = core.core_up("podman", recreate=sc.get("recreate", False), quiet=sc.get("quiet", False))
    text = out.getvalue().replace(str(tmp), "<tmp>").replace(str(omstate.USER_ENV.parent), "<config>")
    cut = (routes / "ws-web.caddy").read_text(encoding="utf-8") if sc.get("gated_route") else None
    return {"result": result, "out": text, "calls": [[c[0], [a.replace(str(tmp), "<tmp>") for a in c[1]], c[2]] for c in calls], "route": cut}


class TestCoreUp(unittest.TestCase):
    def test_every_scenario_behaves_as_recorded(self):
        self.assertEqual(set(SCENARIOS), set(EXPECTED))
        for name, scenario in SCENARIOS.items():
            with self.subTest(name):
                self.assertEqual(run_core_up(scenario), EXPECTED[name])
        self.assertTrue(omstate.CORE_CONTAINERS)


if __name__ == "__main__":
    unittest.main()
