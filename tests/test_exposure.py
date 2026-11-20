"""`om exposure`: who reaches a service, from the audiences (this machine, the VPN, the LAN), the service's tier and its
own address rules; and the doctor's "Private reach" check."""
import contextlib
import io
import unittest
from unittest import mock

import _env  # noqa: F401

from gitops import doctor, exposure

TIERS = {"this_machine": {"you": True, "other_accounts": [], "trusted_accounts": []},
         "vpn": {"trusted": ["tailscale0"], "addresses": ["100.64.0.1"], "allow_list": ["100.64.0.9/32"], "allow_list_enforced": True},
         "lan": {"address": "192.168.1.5"}, "login": []}


def entry(scope="private", net=None, protocol="http"):
    return {"service": "web", "scope": scope, "net": net, "logged": True, "protocol": protocol}


def tiers(**changes):
    out = {k: dict(v) if isinstance(v, dict) else v for k, v in TIERS.items()}
    for key, value in changes.items():
        out[key] = {**out[key], **value} if isinstance(value, dict) else value
    return out


class TestAudience(unittest.TestCase):
    def test_a_private_service_reaches_this_machine_and_the_allowed_vpn_devices_only(self):
        self.assertEqual(exposure.audience(entry(), TIERS), ["this machine: yes", "VPN: 100.64.0.9/32"])

    def test_without_an_allow_list_every_vpn_device_reaches_it(self):
        t = tiers(vpn={"allow_list": None})
        self.assertEqual(exposure.audience(entry(), t)[1], "VPN: every device on tailscale0")

    def test_a_public_service_reaches_the_lan_and_every_vpn_device(self):
        lines = exposure.audience(entry("public"), TIERS)
        self.assertEqual(lines[1:], ["VPN: every device on tailscale0 (public port)", "LAN: every device on your network (192.168.1.5)"])

    def test_address_rules_narrow_it_and_deny_is_listed(self):
        net = {"allow": ["100.64.0.0/24"], "deny": ["100.64.0.66"], "enforced": True}
        self.assertEqual(exposure.audience(entry(net=net), TIERS)[1], "VPN: 100.64.0.0/24, except 100.64.0.66")
        vpn_rule = {"allow": ["vpn"], "deny": [], "enforced": True}
        self.assertEqual(exposure.audience(entry(net=vpn_rule), TIERS)[1], "VPN: 100.64.0.9/32")

    def test_a_loopback_only_rule_means_no_one_from_the_vpn(self):
        net = {"allow": ["127.0.0.1/32"], "deny": [], "enforced": True}
        self.assertIn("no one", exposure.audience(entry(net=net), TIERS)[1])

    def test_unenforced_rules_are_called_out(self):
        net = {"allow": ["100.64.0.0/24"], "deny": [], "enforced": False}
        self.assertTrue(any("NOT in the host firewall" in line for line in exposure.audience(entry(net=net), TIERS)))

    def test_no_trusted_vpn_means_no_vpn_line(self):
        t = tiers(vpn={"trusted": [], "allow_list": None})
        self.assertEqual(exposure.audience(entry(), t), ["this machine: yes"])


class TestExposureOutput(unittest.TestCase):
    def data(self):
        return {"audiences": {**TIERS, "this_machine": {"you": True, "other_accounts": ["guest", "me2"], "trusted_accounts": ["me2"]}},
                "services": [{"workspace": "ws", "service": "web", "scope": "public", "protocol": "http", "own_login": True, "logged": False,
                              "reachable_by": ["this machine: yes", "LAN: every device on your network (192.168.1.5)"], "egress": "ANY public host (audit)"}]}

    def test_printout_names_untrusted_accounts_the_missing_login_and_the_service(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            exposure.print_exposure(self.data())
        text = out.getvalue()
        for needle in ("me2 (yours)", "other accounts: guest", "100.64.0.9/32", "enforced by the firewall", "off", "ws/web", "own login",
                       "not logged", "LAN: every device on your network", "ANY public host (audit)"):
            self.assertIn(needle, text)

    def test_egress_wording(self):
        with mock.patch.object(exposure.egress, "_load_rules", lambda ws: {"a": ["x.example.com", "y.example.com"], "b": "internet", "c": "learn", "d": "audit"}):
            self.assertEqual(exposure.egress_summary("ws", "a"), "2 hosts")
            self.assertEqual(exposure.egress_summary("ws", "z"), "none (no way out)")
            self.assertIn("ANY", exposure.egress_summary("ws", "b"))
            self.assertIn("learning", exposure.egress_summary("ws", "c"))
            self.assertIn("audit", exposure.egress_summary("ws", "d"))


class TestPrivateReachCheck(unittest.TestCase):
    def check(self, t):
        with mock.patch.object(exposure, "tiers", lambda: t):
            return doctor.check_private_reach()

    def test_an_open_vpn_without_a_login_is_a_warning(self):
        status, message, fix = self.check(tiers(vpn={"allow_list": None}))
        self.assertEqual(status, doctor.WARN)
        self.assertIn("every device on tailscale0", message)
        self.assertIn("om vpn allow", fix)

    def test_an_allow_list_or_a_login_or_no_vpn_passes(self):
        self.assertEqual(self.check(TIERS)[0], doctor.PASS)
        self.assertEqual(self.check(tiers(vpn={"allow_list": None}, login=["me"]))[0], doctor.PASS)
        self.assertEqual(self.check(tiers(vpn={"trusted": [], "allow_list": None}))[0], doctor.PASS)


if __name__ == "__main__":
    unittest.main()
