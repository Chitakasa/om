import ipaddress
import tempfile
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

    def test_render_acl_pairs_source_ip_with_its_own_hosts(self):
        ips = {"web": "10.89.56.50", "bot": "10.89.56.51"}
        conf = egress.render_acl("ws", {"web": ["api.example.com", "*.cdn.example.org"], "bot": egress.INTERNET}, ips=ips)
        lines = conf.splitlines()
        web = egress._acl_id("ws", "web")
        bot = egress._acl_id("ws", "bot")
        self.assertIn(f"acl s_{web} src 10.89.56.50/32", lines)
        self.assertIn(f"acl d_{web} dstdomain api.example.com .cdn.example.org", lines)
        self.assertIn(f"http_access allow s_{web} d_{web}", lines)
        self.assertIn(f"acl s_{bot} src 10.89.56.51/32", lines)
        self.assertIn(f"http_access allow s_{bot}", lines)
        self.assertNotIn("http_access allow all", conf)

    def test_render_acl_deterministic(self):
        ips = {"svc_b": "10.89.1.51", "svc_a": "10.89.1.50"}
        services1 = {"svc_a": ["github.com", "api.github.com"], "svc_b": ["example.org"]}
        services2 = {"svc_b": ["example.org"], "svc_a": ["github.com", "api.github.com"]}
        conf1 = egress.render_acl("myws", services1, ips=ips)
        conf2 = egress.render_acl("myws", services2, ips=ips)
        self.assertEqual(conf1, conf2)

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
        line = next(ln for ln in egress.BASE_CONF.splitlines() if ln.startswith("acl to_private dst"))
        self.assertNotIn("::ffff:0:0/96", line)   # Squid reads it as 0.0.0.0/0: every destination would be refused
        nets = [ipaddress.ip_network(x) for x in line.split()[3:]]
        for addr in ("10.0.0.1", "127.0.0.1", "169.254.169.254", "192.168.1.1", "198.18.0.5", "240.0.0.1", "255.255.255.255",
                     "::1", "64:ff9b::a00:1", "fe80::1", "fd00::1", "ff02::1"):
            self.assertTrue(any(ipaddress.ip_address(addr) in n for n in nets), addr)
        for addr in ("1.1.1.1", "93.184.216.34", "2606:4700::1111"):
            self.assertFalse(any(ipaddress.ip_address(addr) in n for n in nets if n.version == ipaddress.ip_address(addr).version), addr)

    def test_override_injects_static_ip_and_plain_proxy_url(self):
        cfg = {"services": {"web": {"container_name": "ws_web"}, "db": {}}}
        path = egress.write_override("ws", "/p", cfg, {"web": "http://om_egress:3128"}, subnet="10.89.50.0/24")
        text = path.read_text(encoding="utf-8")
        self.assertIn('"web":', text)
        self.assertNotIn('"db":', text)
        self.assertIn('HTTPS_PROXY: "http://om_egress:3128"', text)
        self.assertIn("ipv4_address:", text)
        self.assertIn("10.89.50.", text)
        self.assertIn("db,localhost", text.replace("127.0.0.1,", "").replace("::1,", ""))
        self.assertIsNone(egress.write_override("ws", "/p", cfg, {}))
        self.assertFalse(path.exists())

    def test_override_jvm_detection_and_java_tool_options(self):
        cfg = {"services": {"suwayomi": {"image": "ghcr.io/suwayomi/suwayomi-server:stable", "environment": {"JAVA_TOOL_OPTIONS": "-Xmx2g"}}}}
        path = egress.write_override("ws", "/p_jvm", cfg, {"suwayomi": "http://om_egress:3128"}, subnet="10.89.50.0/24")
        text = path.read_text(encoding="utf-8")
        self.assertIn("JAVA_TOOL_OPTIONS:", text)
        self.assertIn("-Xmx2g", text)
        self.assertIn("-Dhttp.proxyHost=om_egress", text)
        self.assertIn("-Dhttps.proxyHost=om_egress", text)

    def test_denied_hosts_and_suggestion(self):
        log = "\n".join([
            "1791323834.967     60 10.89.6.4 TCP_DENIED/403 3392 CONNECT github.com:443 - HIER_NONE/- text/html",
            "1791323835.000      1 10.89.6.4 TCP_DENIED/403 3392 GET http://deb.debian.org/debian/ - HIER_NONE/- text/html",
            "1791323836.470   1494 10.89.6.4 TCP_DENIED/407 3468 CONNECT example.com:443 - HIER_NONE/- text/html",
            "1791323836.480      0 10.89.6.5 TCP_DENIED/403 3468 CONNECT evil.com:443 - HIER_NONE/- text/html",
            "1791323837.000     10 10.89.6.4 TCP_TUNNEL/200 3468 CONNECT example.com:443 - HIER_DIRECT/1.2.3.4 -",
        ])
        ips = {"10.89.6.4": "ws.web", "10.89.6.5": "ws.other"}
        self.assertEqual(egress.denied_hosts(log, ips=ips), {"ws.web": {"github.com", "deb.debian.org"}, "ws.other": {"evil.com"}})
        self.assertEqual(egress.suggestion(["example.com"], {"github.com"}), "example.com,github.com")
        self.assertEqual(egress.suggestion(egress.LEARN, {"b.com", "a.com"}), "a.com,b.com")

    def test_learn_allows_and_records(self):
        self.assertEqual(egress.parse_label("learn"), egress.LEARN)
        ips = {"web": "10.89.56.50"}
        conf = egress.render_acl("ws", {"web": egress.LEARN}, ips=ips)
        self.assertIn(f"http_access allow s_{egress._acl_id('ws', 'web')}", conf.splitlines())
        log = "\n".join([
            "1791323837.000     10 10.89.6.4 TCP_TUNNEL/200 3468 CONNECT api.example.com:443 - HIER_DIRECT/1.2.3.4 -",
            "1791323838.000     10 10.89.6.4 TCP_MISS/200 3468 GET http://deb.debian.org/x - HIER_DIRECT/1.2.3.4 -",
            "1791323839.000      0 10.89.6.4 TCP_DENIED/403 3468 CONNECT 10.0.0.1:443 - HIER_NONE/- -",
        ])
        ips_map = {"10.89.6.4": "ws.web"}
        self.assertEqual(egress.used_hosts(log, ips=ips_map), {"ws.web": {"api.example.com", "deb.debian.org"}})

    def test_learn_expiry(self):
        ws, svc = "test_exp", "app"
        egress.init_learn(ws, svc, ttl_sec=1)
        self.assertFalse(egress.is_learn_expired(ws, svc))
        import time
        time.sleep(1.2)
        self.assertTrue(egress.is_learn_expired(ws, svc))
        ips = {svc: "10.89.99.50"}
        conf = egress.render_acl(ws, {svc: egress.LEARN}, ips=ips)
        self.assertNotIn(f"http_access allow s_{egress._acl_id(ws, svc)}", conf)
        self.assertIn(f"# learn mode expired for {svc}", conf)

    def test_audit_mode_and_never_ttl(self):
        self.assertEqual(egress.parse_label("audit"), egress.AUDIT)
        self.assertEqual(egress.parse_label("monitor"), egress.AUDIT)
        self.assertEqual(egress.parse_ttl("never"), 0)
        self.assertEqual(egress.parse_ttl("off"), 0)
        self.assertEqual(egress.parse_ttl("0"), 0)

        # Audit mode in ACL
        ips = {"app": "10.89.56.55"}
        conf = egress.render_acl("ws", {"app": egress.AUDIT}, ips=ips)
        self.assertIn(f"http_access allow s_{egress._acl_id('ws', 'app')}", conf.splitlines())

        # Never expired when ttl is 0
        ws, svc = "test_perm", "app"
        egress.init_learn(ws, svc, ttl_sec=0)
        self.assertFalse(egress.is_learn_expired(ws, svc))
        self.assertEqual(egress.learn_remaining(ws, svc), -1)

        # Suggestion replaces AUDIT
        self.assertEqual(egress.suggestion(egress.AUDIT, {"foo.com"}), "foo.com")

    def test_apply_egress_label(self):
        content = """services:
  web:
    image: nginx
    labels:
      - "om.egress=learn"
  api:
    image: node
    labels:
      - "om.egress=other.com"
"""
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False, encoding="utf-8") as f:
            f.write(content)
            f.flush()
            path = Path(f.name)

        # Apply to web only
        ok = egress.apply_egress_label(path, "web", ["api.github.com", "cdn.example.com"])
        self.assertTrue(ok)
        updated = path.read_text(encoding="utf-8")
        self.assertIn('om.egress=api.github.com,cdn.example.com', updated)
        self.assertNotIn('om.egress=learn', updated)
        # api service label untouched
        self.assertIn('om.egress=other.com', updated)

        # Apply to nonexistent service returns False
        ok_nonexistent = egress.apply_egress_label(path, "missing", ["evil.com"])
        self.assertFalse(ok_nonexistent)

        path.unlink(missing_ok=True)

    def test_learn_ttl_label_replaces_stored_ttl(self):
        ws, svc = "ttl_ws", "app"
        egress.init_learn(ws, svc, ttl_sec=egress.DEFAULT_LEARN_TTL)  # what render_workspace writes first
        self.assertEqual(egress.learn_remaining(ws, svc) > 0, True)
        egress.init_learn(ws, svc, ttl_sec=0, update_ttl=True)        # what write_override applies from the label
        self.assertEqual(egress.learn_remaining(ws, svc), -1)

    def test_log_reading_only_records_for_learning_services(self):
        ws = "rec_ws"
        egress._write(egress.EGRESS_DIR / f"{ws}.rules", '{"plain": ["x.example.com"], "lrn": "learn"}\n')
        line = "1791323837.000 10 10.0.0.%d TCP_TUNNEL/200 1 CONNECT api.example.com:443 - HIER_DIRECT/1.2.3.4 -"
        ips = {"10.0.0.1": f"{ws}.plain", "10.0.0.2": f"{ws}.lrn"}
        log = line % 1 + "\n" + line % 2
        egress.used_hosts(log, ips=ips)
        egress.used_hosts(log, ips=ips)  # the same log read again must not count twice
        self.assertEqual(egress.load_learn(ws, "plain"), {})
        self.assertEqual(egress.load_learn(ws, "lrn")["hosts"]["api.example.com"]["count"], 1)


if __name__ == "__main__":
    unittest.main()
