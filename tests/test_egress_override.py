"""egress.write_override over 48 combinations: nine service layouts (label list or mapping, learn / audit / hosts / internet,
JVM by image, label or short label, environment as mapping, list or string, a fixed container_name, an extra network),
a config with all of them, an empty one and none; with and without an explicit list of proxy urls; with and without a subnet.
The hashes cover the override file and the learn TTLs written; recorded before write_override was split."""
import hashlib
import json
import unittest

import _env  # noqa: F401

from gitops import egress

EXPECTED = "1ab4b30d0eb6c2f680d63bcae993e63607fb62cc07fb62cc25655bb9dbed384a9ce1cc368842e2946781348c542e7116e640bc10ed3cdc1af977b6f2c867bad92ccd4d7b567f63902fa4add33c46546307fb62cc07fb62ccc52d11ad907468e907fb62cc07fb62ccccf4ebbdfc7df0d798f2545eef8728f10ace196df218a989cdf2e5080a5df2704f3cc8c5739d783dc633247df10d70c56ef5a2d2728bc01e07fb62cc07fb62cc07fb62cc07fb62cc07fb62cc07fb62cc07fb62cc07fb62cc"
VARIANTS = [{'image': 'nginx', 'labels': {'om.egress': 'api.example.com'}}, {'image': 'nginx', 'labels': ['om.egress=learn', 'om.egress.learn_ttl=7d']}, {'image': 'nginx', 'labels': {'om.egress': 'audit'}, 'container_name': 'fixed_name'}, {'image': 'eclipse-temurin:21', 'labels': {'om.egress': 'x.example.com'}, 'environment': {'JAVA_TOOL_OPTIONS': '-Xmx1g', 'A': 'b'}}, {'image': 'x', 'labels': {'om.egress.jvm': 'true', 'om.egress': 'internet'}, 'environment': ['JAVA_TOOL_OPTIONS=-Xms64m', 'Z=1']}, {'image': 'x', 'labels': ['om.jvm=yes', 'om.egress=learn']}, {'image': 'x'}, {'image': 'minecraft-server', 'labels': {'om.egress': 'learn', 'om.egress.learn_ttl': 'never'}, 'networks': {'backend': {}}}, {'image': 'x', 'labels': {'om.egress': 'learn', 'om.egress.learn_ttl': '30m'}, 'environment': 'weird'}]


def configs():
    out = [{"services": {f"s{i}": v, "plain": {"image": "p"}}, "networks": {"default": {"name": "ws_net"}}} for i, v in enumerate(VARIANTS)]
    out.append({"services": {f"s{i}": v for i, v in enumerate(VARIANTS)}, "networks": {"default": {"name": "ws_net"}, "backend": {"name": "x"}}})
    return [*out, {"services": {}}, None]


def clear():
    for f in [*egress.IPS_DIR.glob("*.json"), *egress.LEARN_DIR.glob("*.json")]:
        f.unlink()


class TestWriteOverride(unittest.TestCase):
    def test_every_combination_as_recorded(self):
        got = []
        for ci, cfg in enumerate(configs()):
            for with_urls in (False, True):
                for subnet in (None, "10.89.50.0/24"):
                    clear()
                    urls = dict.fromkeys((cfg or {}).get("services") or {}, "http://om_egress:3128") if with_urls else None
                    path = egress.write_override("ws", f"/proj/{ci}", cfg, urls, subnet=subnet)
                    ttl = {f.name: json.loads(f.read_text(encoding="utf-8"))["ttl"] for f in sorted(egress.LEARN_DIR.glob("*.json"))}
                    text = (path.read_text(encoding="utf-8") if path else "-") + json.dumps(ttl, sort_keys=True)
                    got.append(hashlib.sha256(text.encode()).hexdigest()[:8])
        clear()
        self.assertEqual("".join(got), EXPECTED)

    def test_the_jvm_gets_its_proxy_in_java_tool_options(self):
        clear()
        cfg = {"services": {"jvm": {"image": "x", "labels": ["om.jvm=true", "om.egress=a.example.com"], "environment": ["JAVA_TOOL_OPTIONS=-Xmx1g"]}}}
        text = egress.write_override("ws", "/p", cfg, {"jvm": "http://om_egress:3128"}).read_text(encoding="utf-8")
        self.assertIn("-Xmx1g", text)
        self.assertIn("-Dhttps.proxyHost=om_egress", text)
        clear()

    def test_learn_ttl_label_is_applied(self):
        clear()
        cfg = {"services": {"a": {"image": "x", "labels": {"om.egress": "learn", "om.egress.learn_ttl": "never"}}}}
        egress.write_override("ws", "/p", cfg, {"a": "http://om_egress:3128"})
        self.assertEqual(egress.learn_remaining("ws", "a"), -1)
        clear()


if __name__ == "__main__":
    unittest.main()
