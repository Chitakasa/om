"""The doctor's egress check: open networks, the probe of every internal network, services in learn / audit mode and
services that combine open egress with data. Eight scenarios with the engine and registry replaced; the verdict (status,
message, fix) and the probes that were started are checked. Expected values were recorded before check_egress was split."""
import contextlib
import subprocess
import unittest
from pathlib import Path
from unittest import mock

import _env  # noqa: F401

from gitops import doctor, egress, enginectl, omsettings, omstate, wsregistry

EXPECTED = {'all internal, proxy refuses': {'verdict': ['PASS', 'workspace networks are internal; only om_egress leads out (source-IP ACL enforced)', ''], 'probes': [['ws_net', 'example.com', ['example.com', '192.168.1.5', '100.64.0.1']]]}, 'internal without any proxy': {'verdict': ['PASS', 'workspace networks are internal; only om_egress leads out (source-IP ACL enforced); no proxy at all on 1 network(s) without om.egress', ''], 'probes': [['ws_net', 'example.com', ['example.com', '192.168.1.5', '100.64.0.1']]]}, 'an open network': {'verdict': ['WARN', 'open network(s) with internet access: ws_net', 'cd <workspace> && om network harden (project networks: om start recreates them internal)'], 'probes': [['ws_a_net', 'example.com', ['example.com', '192.168.1.5', '100.64.0.1']]]}, 'probe fails': {'verdict': ['FAIL', "egress probe failed (expected dns, direct, host addresses blocked; proxy refused without assigned IP; raw forging blocked): ws_net: 'open blocked blocked refused blocked' (expected blocked ×3, proxy refused, raw_forge blocked)", 'om core restart; check egress ACLs and container capabilities; om start'], 'probes': [['ws_net', 'example.com', ['example.com', '192.168.1.5', '100.64.0.1']]]}, 'probe prints nothing': {'verdict': ['FAIL', "egress probe failed (expected dns, direct, host addresses blocked; proxy refused without assigned IP; raw forging blocked): ws_net: 'podman: boom' (expected blocked ×3, proxy refused, raw_forge blocked)", 'om core restart; check egress ACLs and container capabilities; om start'], 'probes': [['ws_net', 'example.com', ['example.com', '192.168.1.5', '100.64.0.1']]]}, 'learning, auditing and an expired one': {'verdict': ['WARN', 'in learn mode (any public host allowed): ws/a (1h 30m left), ws/c (expired); in audit mode (any public host allowed, permanently logged): ws/b', 'om egress log <svc> --apply, then list the hosts; om egress log <svc> to inspect; use om.egress=<hosts> to enforce specific destinations'], 'probes': [['ws_net', 'example.com', ['example.com', '192.168.1.5', '100.64.0.1']]]}, 'permanent learn': {'verdict': ['WARN', 'in learn mode (any public host allowed): ws/a (permanent)', 'om egress log <svc> --apply, then list the hosts'], 'probes': [['ws_net', 'example.com', ['example.com', '192.168.1.5', '100.64.0.1']]]}, 'open egress with data': {'verdict': ['FAIL', "service 'ws/a' has writable volume with om.egress=internet (refused by policy)", 'list the hosts it needs or waive with om.policy.allow=egress'], 'probes': [['ws_net', 'example.com', ['example.com', '192.168.1.5', '100.64.0.1']]]}, 'allowed host is probed': {'verdict': ['PASS', 'workspace networks are internal; only om_egress leads out (source-IP ACL enforced)', ''], 'probes': [['ws_net', 'exact.example.com', ['exact.example.com', '192.168.1.5', '100.64.0.1']]]}}

SCENARIOS = {
    "all internal, proxy refuses": {"nets": {"ws_net": {"members": ["om_egress", "ws_web"]}}},
    "internal without any proxy": {"nets": {"ws_net": {"members": ["ws_web"], "probe": "blocked blocked blocked error blocked"}}},
    "an open network": {"nets": {"ws_net": {"internal": False}, "ws_a_net": {"members": ["om_egress"]}}},
    "probe fails": {"nets": {"ws_net": {"members": ["om_egress"], "probe": "open blocked blocked refused blocked"}}},
    "probe prints nothing": {"nets": {"ws_net": {"members": ["om_egress"], "probe": "", "stderr": "podman: boom"}}},
    "learning, auditing and an expired one": {
        "nets": {"ws_net": {"members": ["om_egress"]}},
        "rules": {"ws": {"a": egress.LEARN, "b": egress.AUDIT, "c": egress.LEARN, "d": ["x.example.com"]}},
        "remaining": {"a": 5400, "c": 0}},
    "permanent learn": {"nets": {"ws_net": {"members": ["om_egress"]}}, "rules": {"ws": {"a": egress.LEARN}}, "remaining": {"a": -1}},
    "open egress with data": {"nets": {"ws_net": {"members": ["om_egress"]}}, "rules": {"ws": {"a": egress.INTERNET}}, "data_problem": "writable volume"},
    "allowed host is probed": {"nets": {"ws_net": {"members": ["om_egress", "ws_api"]}}, "rules": {"ws": {"api": ["*.wild.example", "exact.example.com"]}}},
}


def run_check(sc):
    probes, nets = [], sc["nets"]

    def fake_run(cmd, **kw):
        words = [str(c) for c in cmd]
        if words[1:3] == ["network", "inspect"]:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if words[1] == "ps":
            net = next(w.split("=", 1)[1] for w in words if w.startswith("network="))
            return subprocess.CompletedProcess(cmd, 0, " ".join(nets[net].get("members", [])), "")
        if words[1] == "run":
            net = words[words.index("--network") + 1]
            probes.append([net, words[-3] if len(words) > 3 else "", words[words.index("-c") + 2:]])
            spec = nets[net]
            return subprocess.CompletedProcess(cmd, 0, spec.get("probe", "blocked blocked blocked refused blocked"), spec.get("stderr", ""))
        raise AssertionError(words)

    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.object(omstate, "run", fake_run))
        stack.enter_context(mock.patch.object(omstate, "parse_env_file", lambda p: {"LAN_IP": "192.168.1.5"}))
        stack.enter_context(mock.patch.object(omsettings, "vpn_hosts", lambda: ["100.64.0.1", "name.ts.net", "x.invalid"]))
        stack.enter_context(mock.patch.object(wsregistry, "read_registry", lambda: {"ws": {"path": "/nonexistent"}}))
        stack.enter_context(mock.patch.object(egress, "_load_rules", lambda ws: sc.get("rules", {}).get(ws, {})))
        stack.enter_context(mock.patch.object(egress, "learn_remaining", lambda ws, svc: sc.get("remaining", {}).get(svc, 0)))
        stack.enter_context(mock.patch.object(enginectl, "project_networks", lambda rt, ws: [n for n in nets if n != "ws_net"]))
        stack.enter_context(mock.patch.object(enginectl, "network_is_internal", lambda rt, net: nets[net].get("internal", True)))
        stack.enter_context(mock.patch.object(doctor, "_probe_image", lambda: "probe:image"))
        stack.enter_context(mock.patch.object(doctor, "_open_egress_with_data", lambda *a: sc.get("data_problem", "")))
        stack.enter_context(mock.patch.object(Path, "is_dir", lambda self: str(self) == "/nonexistent"))
        verdict = doctor.check_egress("podman")
    return {"verdict": list(verdict), "probes": probes}


class TestDoctorEgress(unittest.TestCase):
    def test_every_scenario_behaves_as_recorded(self):
        self.assertEqual(set(SCENARIOS), set(EXPECTED))
        for name, scenario in SCENARIOS.items():
            with self.subTest(name):
                self.assertEqual(run_check(scenario), EXPECTED[name])


if __name__ == "__main__":
    unittest.main()
