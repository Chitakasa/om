"""`om vpn`: listing the VPNs (text and --json), trusting and untrusting an interface or address, and what it refuses.
Engine, firewall and settings are replaced; what is checked is the output, the exit, the setting that is written and
whether the core is restarted. Expected values were recorded before cmd_vpn was split into steps."""
import argparse
import contextlib
import io
import unittest
from unittest import mock

import _env  # noqa: F401

from gitops import core, hostcmds, hostsetup, omsettings, vpndetect

EXPECTED = {'list, nothing on the machine': {'code': None, 'out': '\n\x1b[1mVPN\x1b[0m  (OM_VPN=(none))\n  No VPN on this machine. Install one whose members are your own devices, then `om vpn`.\n\n', 'err': '', 'written': [], 'restarted': []}, 'list, none trusted': {'code': None, 'out': '\n\x1b[1mVPN\x1b[0m  (OM_VPN=(none))\n  tailscale0     100.64.0.1       \x1b[33mnot trusted\x1b[0m\n  wg0            10.8.0.1         \x1b[33mnot trusted\x1b[0m\n  tun7           -                \x1b[33mnot trusted\x1b[0m\n\n  Trust a VPN only if every member is your own device (not a commercial or company VPN,\n  not a public network):\n    om vpn trust tailscale0\n    om vpn trust wg0\n    om vpn trust tun7\n\n', 'err': '', 'written': [], 'restarted': []}, 'list, one trusted by name': {'code': None, 'out': "\n\x1b[1mVPN\x1b[0m  (OM_VPN=tailscale0)\n  tailscale0     100.64.0.1       \x1b[32mtrusted\x1b[0m\n  wg0            10.8.0.1         \x1b[33mnot trusted\x1b[0m\n  tun7           -                \x1b[33mnot trusted\x1b[0m\nDEVICES [{'address': '100.64.0.9'}]\n\n  Trust a VPN only if every member is your own device (not a commercial or company VPN,\n  not a public network):\n    om vpn trust wg0\n    om vpn trust tun7\n\n", 'err': '', 'written': [], 'restarted': []}, 'list, trusted by address and one absent': {'code': None, 'out': "\n\x1b[1mVPN\x1b[0m  (OM_VPN=10.8.0.1,gone0)\n  tailscale0     100.64.0.1       \x1b[33mnot trusted\x1b[0m\n  wg0            10.8.0.1         \x1b[32mtrusted\x1b[0m\n  tun7           -                \x1b[33mnot trusted\x1b[0m\n  gone0          -                \x1b[32mtrusted\x1b[0m (not present now)\nDEVICES [{'address': '100.64.0.9'}]\n\n  Trust a VPN only if every member is your own device (not a commercial or company VPN,\n  not a public network):\n    om vpn trust tailscale0\n    om vpn trust tun7\n\n", 'err': '', 'written': [], 'restarted': []}, 'list --json': {'code': None, 'out': '{\n  "allow_enforced": true,\n  "allowed_devices": [\n    "100.64.0.9/32"\n  ],\n  "devices": [\n    {\n      "address": "100.64.0.9"\n    }\n  ],\n  "interfaces": [\n    {\n      "address": "100.64.0.1",\n      "name": "tailscale0",\n      "trusted": false\n    },\n    {\n      "address": "10.8.0.1",\n      "name": "wg0",\n      "trusted": true\n    },\n    {\n      "address": "",\n      "name": "tun7",\n      "trusted": false\n    }\n  ],\n  "names": [\n    "box",\n    "100.64.0.1"\n  ],\n  "trusted": [\n    "wg0"\n  ]\n}\n', 'err': '', 'written': [], 'restarted': []}, 'list --json, nothing trusted': {'code': None, 'out': '{\n  "allow_enforced": true,\n  "allowed_devices": null,\n  "devices": [],\n  "interfaces": [\n    {\n      "address": "100.64.0.1",\n      "name": "tailscale0",\n      "trusted": false\n    },\n    {\n      "address": "10.8.0.1",\n      "name": "wg0",\n      "trusted": false\n    },\n    {\n      "address": "",\n      "name": "tun7",\n      "trusted": false\n    }\n  ],\n  "names": [\n    "box",\n    "100.64.0.1"\n  ],\n  "trusted": []\n}\n', 'err': '', 'written': [], 'restarted': []}, 'trust an interface': {'code': None, 'out': '\x1b[32m✓ OM_VPN=wg0\x1b[0m\n  Run `om firewall apply` so the firewall follows the new VPN addresses.\n', 'err': '', 'written': [('OM_VPN', 'wg0')], 'restarted': [{'recreate': True, 'quiet': True}]}, 'trust, core does not come back': {'code': 1, 'out': '\x1b[32m✓ OM_VPN=wg0\x1b[0m\n', 'err': 'The core did not come back; `om doctor` shows why.\n', 'written': [('OM_VPN', 'wg0')], 'restarted': [{'recreate': True, 'quiet': True}]}, 'trust, core stopped': {'code': None, 'out': '\x1b[32m✓ OM_VPN=tailscale0,wg0\x1b[0m\n  Run `om firewall apply` so the firewall follows the new VPN addresses.\n', 'err': '', 'written': [('OM_VPN', 'tailscale0,wg0')], 'restarted': []}, 'trust an address': {'code': None, 'out': '\x1b[32m✓ OM_VPN=100.1.2.3\x1b[0m\n  Run `om firewall apply` so the firewall follows the new VPN addresses.\n', 'err': '', 'written': [('OM_VPN', '100.1.2.3')], 'restarted': []}, 'trust twice': {'code': None, 'out': '  wg0 is already trusted.\n', 'err': '', 'written': [], 'restarted': []}, 'trust an unknown interface': {'code': 1, 'out': '', 'err': "No VPN interface 'nope0'. `om vpn` lists them.\n", 'written': [], 'restarted': []}, 'untrust': {'code': None, 'out': '\x1b[32m✓ OM_VPN=tailscale0\x1b[0m\n  Run `om firewall apply` so the firewall follows the new VPN addresses.\n', 'err': '', 'written': [('OM_VPN', 'tailscale0')], 'restarted': [{'recreate': True, 'quiet': True}]}, 'untrust the last one': {'code': None, 'out': '\x1b[32m✓ OM_VPN=(none)\x1b[0m\n  Run `om firewall apply` so the firewall follows the new VPN addresses.\n', 'err': '', 'written': [('OM_VPN', '')], 'restarted': []}, 'untrust something not trusted': {'code': 1, 'out': '', 'err': 'wg0 is not trusted.\n', 'written': [], 'restarted': []}, 'trust without a name': {'code': 1, 'out': '', 'err': 'Usage: om vpn trust <interface or address>\n', 'written': [], 'restarted': []}}

CANDIDATES = [("tailscale0", "100.64.0.1"), ("wg0", "10.8.0.1"), ("tun7", "")]
SCENARIOS = {
    "list, nothing on the machine": {"action": "list", "cands": [], "trusted_spec": ""},
    "list, none trusted": {"action": "list", "cands": CANDIDATES, "trusted_spec": ""},
    "list, one trusted by name": {"action": "list", "cands": CANDIDATES, "trusted_spec": "tailscale0", "devices": True},
    "list, trusted by address and one absent": {"action": "list", "cands": CANDIDATES, "trusted_spec": "10.8.0.1,gone0", "devices": True},
    "list --json": {"action": "list", "json": True, "cands": CANDIDATES, "trusted_spec": "wg0", "allowed": ["100.64.0.9/32"], "devices": True},
    "list --json, nothing trusted": {"action": "list", "json": True, "cands": CANDIDATES, "trusted_spec": ""},
    "trust an interface": {"action": "trust", "name": "WG0", "cands": CANDIDATES, "trusted_spec": "", "core_running": True},
    "trust, core does not come back": {"action": "trust", "name": "wg0", "cands": CANDIDATES, "trusted_spec": "", "core_running": True, "core_up": False},
    "trust, core stopped": {"action": "trust", "name": "wg0", "cands": CANDIDATES, "trusted_spec": "tailscale0"},
    "trust an address": {"action": "trust", "name": "100.1.2.3", "cands": CANDIDATES, "trusted_spec": ""},
    "trust twice": {"action": "trust", "name": "wg0", "cands": CANDIDATES, "trusted_spec": "wg0"},
    "trust an unknown interface": {"action": "trust", "name": "nope0", "cands": CANDIDATES, "trusted_spec": ""},
    "untrust": {"action": "untrust", "name": "wg0", "cands": CANDIDATES, "trusted_spec": "tailscale0,wg0", "core_running": True},
    "untrust the last one": {"action": "untrust", "name": "tailscale0", "cands": CANDIDATES, "trusted_spec": "tailscale0"},
    "untrust something not trusted": {"action": "untrust", "name": "wg0", "cands": CANDIDATES, "trusted_spec": ""},
    "trust without a name": {"action": "trust", "name": "  ", "cands": CANDIDATES, "trusted_spec": ""},
}


def run_vpn(sc):
    args = argparse.Namespace(action=sc["action"], name=sc.get("name"), json=sc.get("json", False), no_apply=False)
    written, restarted = [], []
    out, err = io.StringIO(), io.StringIO()
    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.object(omsettings, "load_settings", lambda: {"OM_VPN": sc["trusted_spec"]}))
        stack.enter_context(mock.patch.object(vpndetect, "vpn_candidates", lambda: sc["cands"]))
        stack.enter_context(mock.patch.object(omsettings, "vpn_allow", lambda: sc.get("allowed", [])))
        stack.enter_context(mock.patch.object(omsettings, "vpn_hosts", lambda: ["box", "100.64.0.1"]))
        stack.enter_context(mock.patch.object(omsettings, "set_setting", lambda k, v: written.append((k, v))))
        stack.enter_context(mock.patch.object(hostsetup, "vpn_allow_enforced", lambda: True))
        stack.enter_context(mock.patch.object(hostcmds, "vpn_devices", lambda: [{"address": "100.64.0.9"}] if sc.get("devices") else []))
        stack.enter_context(mock.patch.object(hostcmds, "print_vpn_devices", lambda devices: print("DEVICES", devices)))
        stack.enter_context(mock.patch.object(hostcmds, "detect_runtime", lambda: "podman"))
        stack.enter_context(mock.patch.object(core, "core_running", lambda runtime: sc.get("core_running", False)))
        stack.enter_context(mock.patch.object(core, "core_up", lambda runtime, **kw: restarted.append(kw) or sc.get("core_up", True)))
        code = None
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                hostcmds.cmd_vpn(None, args)
            except SystemExit as e:
                code = e.code
    return {"code": code, "out": out.getvalue(), "err": err.getvalue(), "written": written, "restarted": restarted}


class TestVpnCommand(unittest.TestCase):
    def test_every_scenario_behaves_as_recorded(self):
        self.assertEqual(set(SCENARIOS), set(EXPECTED))
        for name, scenario in SCENARIOS.items():
            with self.subTest(name):
                self.assertEqual(run_vpn(scenario), EXPECTED[name])


if __name__ == "__main__":
    unittest.main()
