import unittest

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

    def test_acl_ids_do_not_collide(self):
        self.assertNotEqual(egress._acl_id("ws", "a-b"), egress._acl_id("ws", "a_b"))

    def test_base_denies_private_and_ends_with_deny_all(self):
        base = egress.BASE_CONF
        self.assertLess(base.index("http_access deny to_private"), base.index("include /etc/om-egress/acl/*.conf"))
        self.assertTrue(base.rstrip().endswith("http_access deny all"))


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

if __name__ == "__main__":
    unittest.main()
