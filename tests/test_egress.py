import ipaddress
import unittest
from pathlib import Path

import _env  # noqa: F401  (sets OM_HOME before importing om modules)
from gitops import egress


class TestEgress(unittest.TestCase):
    def test_parse_label(self):
        self.assertIsNone(egress.parse_label(None))
        self.assertIsNone(egress.parse_label("  "))
        self.assertEqual(egress.parse_label("internet"), egress.INTERNET)
        self.assertEqual(egress.parse_label("API.example.com, *.cdn.example.org"), ["api.example.com", "*.cdn.example.org"])
        # Anything that could break out of a Squid acl line is dropped
        self.assertEqual(egress.parse_label("ok.com,bad host.com,x.com\nhttp_access allow all,*.,10.0.0.1"), ["ok.com"])

    def test_render_acl_pairs_user_with_its_own_hosts(self):
        conf = egress.render_acl("ws", {"web": ["api.example.com", "*.cdn.example.org"], "bot": egress.INTERNET})
        lines = conf.splitlines()
        web = egress._acl_id("ws", "web")
        self.assertIn(f"acl u_{web} proxy_auth ws.web", lines)
        self.assertIn(f"acl d_{web} dstdomain api.example.com .cdn.example.org", lines)
        self.assertIn(f"http_access allow u_{web} d_{web}", lines)
        self.assertIn(f"http_access allow u_{egress._acl_id('ws', 'bot')}", lines)
        self.assertNotIn("http_access allow all", conf)

    def test_image_tag_is_a_hash_of_the_containerfile_dir(self):
        self.assertRegex(egress.image(), r"^localhost/om-egress:[0-9a-f]{12}$")
        real = egress.IMAGE_DIR
        try:
            egress.IMAGE_DIR = Path(__file__).resolve().parent.parent / "core" / "egress"
            a = egress.image()
            self.assertEqual(a, egress.image())
            self.assertNotEqual(a, "localhost/om-egress:" + __import__("hashlib").sha256().hexdigest()[:12])  # it hashed the file
        finally:
            egress.IMAGE_DIR = real

    def test_acl_ids_do_not_collide(self):
        self.assertNotEqual(egress._acl_id("ws", "a-b"), egress._acl_id("ws", "a_b"))

    def test_base_denies_private_and_ends_with_deny_all(self):
        base = egress.BASE_CONF
        self.assertLess(base.index("http_access deny to_private"), base.index("include /etc/om-egress/acl/*.conf"))
        self.assertTrue(base.rstrip().endswith("http_access deny all"))

    def test_private_ranges_cover_mapped_and_special_use_addresses(self):
        line = next(l for l in egress.BASE_CONF.splitlines() if l.startswith("acl to_private dst"))
        self.assertNotIn("::ffff:0:0/96", line)   # Squid reads it as 0.0.0.0/0: every destination would be refused
        nets = [ipaddress.ip_network(x) for x in line.split()[3:]]
        for addr in ("10.0.0.1", "127.0.0.1", "169.254.169.254", "192.168.1.1", "198.18.0.5", "240.0.0.1", "255.255.255.255",
                     "::1", "64:ff9b::a00:1", "fe80::1", "fd00::1", "ff02::1"):
            self.assertTrue(any(ipaddress.ip_address(addr) in n for n in nets), addr)
        for addr in ("1.1.1.1", "93.184.216.34", "2606:4700::1111"):
            self.assertFalse(any(ipaddress.ip_address(addr) in n for n in nets if n.version == ipaddress.ip_address(addr).version), addr)

    def test_override_only_for_egress_services(self):
        cfg = {"services": {"web": {"container_name": "ws_web"}, "db": {}}}
        path = egress.write_override("ws", "/p", cfg, {"web": "http://ws.web:t@om_egress:3128", "other": "x"})
        text = path.read_text(encoding="utf-8")
        self.assertIn('"web":', text)
        self.assertNotIn('"db":', text)
        self.assertIn('HTTPS_PROXY: "http://ws.web:t@om_egress:3128"', text)
        self.assertIn("db,localhost", text.replace("127.0.0.1,", "").replace("::1,", ""))
        self.assertIsNone(egress.write_override("ws", "/p", cfg, {}))
        self.assertFalse(path.exists())

    def test_denied_hosts_and_suggestion(self):
        log = "\n".join([
            "1791323834.967     60 10.89.6.4 TCP_DENIED/403 3392 CONNECT github.com:443 ws.web HIER_NONE/- text/html",
            "1791323835.000      1 10.89.6.4 TCP_DENIED/403 3392 GET http://deb.debian.org/debian/ ws.web HIER_NONE/- text/html",
            "1791323836.470   1494 10.89.6.4 TCP_DENIED/407 3468 CONNECT example.com:443 ws.web HIER_NONE/- text/html",
            "1791323836.480      0 10.89.6.4 TCP_DENIED/403 3468 CONNECT evil.com:443 - HIER_NONE/- text/html",
            "1791323837.000     10 10.89.6.4 TCP_TUNNEL/200 3468 CONNECT example.com:443 ws.web HIER_DIRECT/1.2.3.4 -",
        ])
        self.assertEqual(egress.denied_hosts(log), {"ws.web": {"github.com", "deb.debian.org"}})
        self.assertEqual(egress.suggestion(["example.com"], {"github.com"}), "example.com,github.com")
        self.assertEqual(egress.suggestion(egress.LEARN, {"b.com", "a.com"}), "a.com,b.com")

    def test_learn_allows_and_records(self):
        self.assertEqual(egress.parse_label("learn"), egress.LEARN)
        conf = egress.render_acl("ws", {"web": egress.LEARN})
        self.assertIn(f"http_access allow u_{egress._acl_id('ws', 'web')}", conf.splitlines())
        log = "\n".join([
            "1791323837.000     10 10.89.6.4 TCP_TUNNEL/200 3468 CONNECT api.example.com:443 ws.web HIER_DIRECT/1.2.3.4 -",
            "1791323838.000     10 10.89.6.4 TCP_MISS/200 3468 GET http://deb.debian.org/x ws.web HIER_DIRECT/1.2.3.4 -",
            "1791323839.000      0 10.89.6.4 TCP_DENIED/403 3468 CONNECT 10.0.0.1:443 ws.web HIER_NONE/- -",
        ])
        self.assertEqual(egress.used_hosts(log), {"ws.web": {"api.example.com", "deb.debian.org"}})

if __name__ == "__main__":
    unittest.main()
