"""Edge port bindings (omsettings.render_ports) over 432 input combinations: HTTP and HTTPS port, zero to two VPN
addresses, a VPN tier the firewall does or does not enforce yet, no LAN / a LAN / a LAN that is also the VPN address,
IPv6 loopback or not, and six sets of stream ports (none, a default slot, explicit private / public, explicit with an
address rule enforced / not enforced). The expected hashes are those of the output before render_ports was split."""
import hashlib
import itertools
import unittest
from unittest import mock

import _env  # noqa: F401

from gitops import hostsetup, omsettings

STREAMS = [
    {},
    {"ws/a": {"host_port": 22003, "scope": "public"}},
    {"ws/b": {"host_port": 25565, "scope": "private"}},
    {"ws/c": {"host_port": 25566, "scope": "public"}},
    {"ws/d": {"host_port": 25567, "scope": "public"}, "ws/e": {"host_port": 0}},
    {"ws/f": {"host_port": 25568, "scope": "public"}},
]
POLICIES = {4: {"ws/d": {"ports": [25567], "allow": ["1.2.3.4/32"]}}, 5: {"ws/f": {"ports": [25568], "allow": ["1.2.3.4/32"]}}}
EXPECTED = "a6eff1fca6eff1fc52a0267f3f60630af854e326a6eff1fccdd907accdd907ac356a958042507bc2d5dc93e9cdd907ac003be10c003be10c7dd68a4cac0ef8dba94fecbc003be10c15bd6e0d15bd6e0d58237158dce7a91d10015f9f15bd6e0dc01f69cfc01f69cf596c0c39c2a7bc80bafb15dac01f69cfd7ce124fd7ce124fe0e6c06e44daa7fa100b7043d7ce124fa6eff1fca6eff1fc52a0267f3f60630af854e326a6eff1fccdd907accdd907ac356a958042507bc2d5dc93e9cdd907ac003be10c003be10c7dd68a4cac0ef8dba94fecbc003be10c15bd6e0d15bd6e0d58237158dce7a91d10015f9f15bd6e0dc01f69cfc01f69cf596c0c39c2a7bc80bafb15dac01f69cfd7ce124fd7ce124fe0e6c06e44daa7fa100b7043d7ce124fc5ad67bcc5ad67bc1147c60cf29e833c8e37c67dc5ad67bc1a66796e1a66796eb47b2d4d46b02e09a14efe801a66796e7459324a7459324a14f89369b3794dba9144e9e57459324a2fca968f2fca968fb18f0d2a262c950dbd48c8842fca968fc5ad67bcc5ad67bc1147c60cf29e833c8e37c67dc5ad67bc1a66796e1a66796eb47b2d4d46b02e09a14efe801a66796e0d049d7a0d049d7ab3be739e04a6dd19caaddbd90d049d7a2362e44d2362e44d3d3827ebeb1cb6d658f741f32362e44dce4b269ece4b269e68b253d488a4cd0d9f911487ce4b269e801908d3801908d3be1d43bfaeba9aa3c0bcee4c801908d30d049d7a0d049d7ab3be739e04a6dd19caaddbd90d049d7a2362e44d2362e44d3d3827ebeb1cb6d658f741f32362e44d43adb5d343adb5d37290ebd966fa8032b4516f8043adb5d35449e6735449e673bd565dfa6651e8be69fce1ef5449e67360be216560be216534ef6f34afd7e81123d4a72060be21654fe29e984fe29e987a2b1b9e859f66994dd707f94fe29e9843adb5d343adb5d37290ebd966fa8032b4516f8043adb5d35449e6735449e673bd565dfa6651e8be69fce1ef5449e6736bcf4bf06bcf4bf0e6456f6c396a287c31d6eda26bcf4bf0df6c9bc6df6c9bc67cd5710ce1cf761ba1480a98df6c9bc684f71f9784f71f97d573a5e4861da3480eab4d8984f71f970fc2dded0fc2ddede485eaf94c80c0318219423f0fc2dded6bcf4bf06bcf4bf0e6456f6c396a287c31d6eda26bcf4bf0df6c9bc6df6c9bc67cd5710ce1cf761ba1480a98df6c9bc6fdb62865fdb62865e2d111a81af4a6300f84e29afdb628656652898a6652898a3b674457513e7cfc1ec3e8d06652898aec700164ec7001643a4221ac19b4aa24d0106cfdec700164af04a626af04a626c64d5c63e64c9ded7de80b7aaf04a626d6e185c9d6e185c927003e5577577a3bcd66b209d6e185c9167e7f85167e7f85217b34a40efb40a5587515ba167e7f85fdb62865fdb62865e2d111a81af4a6300f84e29afdb628656652898a6652898a3b674457513e7cfc1ec3e8d06652898aec700164ec7001643a4221ac19b4aa24d0106cfdec700164af04a626af04a626c64d5c63e64c9ded7de80b7aaf04a626d6e185c9d6e185c927003e5577577a3bcd66b209d6e185c9167e7f85167e7f85217b34a40efb40a5587515ba167e7f85654007e4654007e46ec61f3d1db54ac5e8a7f36e654007e41774669917746699258636301d5346b211ed8b3817746699484932de484932dee7e8dd59e8900d0035ea965b484932de46979aa846979aa893c441e61eb6fad7012f837b46979aa8654007e4654007e46ec61f3d1db54ac5e8a7f36e654007e41774669917746699258636301d5346b211ed8b3817746699c848e7b5c848e7b5082d5c4d07ec2d2519c72006c848e7b59864dd8a9864dd8a8d9f0b77d36c46788f69de009864dd8af69bc21bf69bc21b5279e9cefd2d70b2a189d885f69bc21b114cec47114cec47c5f4c22ccce9fcbe27302152114cec47c848e7b5c848e7b5082d5c4d07ec2d2519c72006c848e7b59864dd8a9864dd8a8d9f0b77d36c46788f69de009864dd8a9935d0369935d0366a5bda06abd2a43b83cc51fe9935d036764bc152764bc1525f2f1eb525c3179db8e7d4b3764bc152da9fbf36da9fbf36c9375bf546d7c65c11ca526cda9fbf36d98a7d6dd98a7d6d255fa96ff0f653ba4bb1f81fd98a7d6d9935d0369935d0366a5bda06abd2a43b83cc51fe9935d036764bc152764bc1525f2f1eb525c3179db8e7d4b3764bc1528fb8a9a28fb8a9a2201bc2361f24a993836a6c9a8fb8a9a2862d0617862d0617d29a7a6bb399e3aa5ceade38862d061758fc88a658fc88a6a784895c5f3080e0032dfec958fc88a664b4ba0a64b4ba0aeabe5a920f6914df7686ae7564b4ba0a8fb8a9a28fb8a9a2201bc2361f24a993836a6c9a8fb8a9a2862d0617862d0617d29a7a6bb399e3aa5ceade38862d0617"


def cases():
    return itertools.product(((80, 443), (8081, 8444)), ([], ["100.64.0.1"], ["100.64.0.1", "100.64.0.2"]), (True, False),
                             (None, "192.168.1.5", "100.64.0.1"), (True, False), range(6))


class TestRenderPorts(unittest.TestCase):
    def render(self, ports, vpn, vpn_private, lan, ipv6, streams):
        resolved = {"http_port": ports[0], "https_port": ports[1], "vpn_ips": vpn, "vpn_private": vpn_private, "lan_ip": lan}
        with mock.patch.object(omsettings, "is_local_address", lambda ip: ipv6 if ip == "::1" else True), \
                mock.patch.object(omsettings, "stream_ports", lambda: STREAMS[streams]), \
                mock.patch.object(omsettings, "net_policies", lambda: POLICIES.get(streams, {})), \
                mock.patch.object(hostsetup, "net_policy_enforced", lambda key, pol: streams == 4):
            return omsettings.render_ports(resolved).split("\n", 1)[1]  # the first line names this machine's state folder

    def test_every_combination_renders_as_recorded(self):
        for i, case in enumerate(cases()):
            got = hashlib.sha256(self.render(*case).encode()).hexdigest()[:8]
            self.assertEqual(got, EXPECTED[i * 8:(i + 1) * 8], f"case {i}: {case}")

    def test_the_default_and_explicit_ports_are_bound_where_they_should_be(self):
        text = self.render((80, 443), ["100.64.0.1"], True, "192.168.1.5", True, 3)
        stream = text.split("stream_edge:")[1]
        for bind in ("127.0.0.1:22000-22199:22000-22199", "[::1]:25566:25566", "100.64.0.1:25566:25566", "192.168.1.5:25566:25566"):
            self.assertIn(f'"{bind}"', stream)
        private = self.render((80, 443), ["100.64.0.1"], True, "192.168.1.5", True, 2).split("stream_edge:")[1]
        self.assertNotIn("192.168.1.5:25565", private)  # a private explicit port never reaches the LAN
        unenforced = self.render((80, 443), [], True, None, False, 5).split("stream_edge:")[1]
        self.assertNotIn("25568", unenforced)           # an address rule the firewall does not carry: not bound

    def test_a_vpn_tier_the_firewall_does_not_enforce_is_not_bound_privately(self):
        text = self.render((80, 443), ["100.64.0.1"], False, None, False, 0)
        self.assertIn("100.64.0.1:8080:8080", text)
        self.assertNotIn("100.64.0.1:80:81", text)


if __name__ == "__main__":
    unittest.main()
