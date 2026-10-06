import unittest

import _env  # noqa: F401  (sets OM_HOME before importing om modules)
from gitops import policy

HOME = "/home/u"


def check(**svc):
    return policy.check_service("web", svc, HOME)


class TestPolicy(unittest.TestCase):
    def test_clean_service_passes(self):
        self.assertEqual(check(image="nginx:1.31-alpine", expose=["80"], cap_add=["NET_BIND_SERVICE", "CHOWN", "CAP_SETUID"],
                               volumes=[{"type": "bind", "source": "/home/u/proj/data", "target": "/data"},
                                        {"type": "volume", "source": "db", "target": "/db"}],
                               network_mode="none"), [])

    def test_escapes_are_refused(self):
        for svc in ({"privileged": True}, {"network_mode": "host"}, {"network_mode": "container:om_caddy"},
                    {"pid": "host"}, {"ipc": "host"}, {"userns_mode": "host"},
                    {"ports": [{"target": 80, "published": "8080"}]}, {"cap_add": ["SYS_ADMIN"]},
                    {"devices": ["/dev/kvm:/dev/kvm"]}, {"security_opt": ["seccomp=unconfined"]},
                    {"security_opt": ["label:disable"]}):
            self.assertEqual(len(check(**svc)), 1, svc)

    def test_sensitive_mounts(self):
        bad = ["/var/run/docker.sock", "/run/user/1000/podman/podman.sock", "/", "/etc", "/etc/ssh",
               "/home/u", "/home/u/.ssh", "/home/u/.config/om", "/home/u/.local/state/om/data", "/proc/1",
               "C:\\Users\\u\\proj\\engine.sock"]
        for src in bad:
            self.assertTrue(check(volumes=[{"type": "bind", "source": src, "target": "/x"}]), src)
        for src in ["/home/u/Pictures", "/home/u/proj/.config", "/srv/media", "/home/u/.configx", "/run/media/u/disk"]:
            self.assertEqual(check(volumes=[{"type": "bind", "source": src, "target": "/x"}]), [], src)

    def test_windows_home(self):
        v = [{"type": "bind", "source": "C:\\Users\\u\\.ssh", "target": "/x"}]
        self.assertTrue(policy.check_service("w", {"volumes": v}, "C:\\Users\\u"))
        self.assertTrue(policy.check_service("w", {"volumes": v}, "c:/users/u"))

    def test_config_lists_every_service(self):
        cfg = {"services": {"a": {"privileged": True}, "b": {"ports": ["80:80"]}, "c": {}}}
        out = policy.check_config(cfg, HOME)
        self.assertEqual([o.split(":")[0] for o in out], ["a", "b"])

    def test_allow_label_waives_listed_rules_only(self):
        svc = {"devices": ["/dev/dri:/dev/dri"], "cap_add": ["SYS_ADMIN"],
               "volumes": [{"type": "bind", "source": "/", "target": "/host"}],
               "labels": {"om.policy.allow": "devices, mounts"}}
        violations, waived = policy.evaluate_service("web", svc, HOME)
        self.assertEqual(len(waived), 2)
        self.assertEqual(len(violations), 1)
        self.assertIn("cap_add", violations[0])

    def test_allow_label_cannot_waive_laws_or_unknown_rules(self):
        svc = {"privileged": True, "ports": ["80:80"], "labels": ["om.policy.allow=privileged,ports,devcies"]}
        violations, waived = policy.evaluate_service("web", svc, HOME)
        self.assertEqual(waived, [])
        self.assertEqual(len(violations), 5)  # 2 laws refused as waivers, 1 typo, 2 findings

    def test_mode_defaults_to_warn(self):
        self.assertEqual(policy.mode({}), "warn")
        self.assertEqual(policy.mode({"OM_POLICY": "enforce"}), "enforce")
        self.assertEqual(policy.mode({"OM_POLICY": "bogus"}), "warn")


if __name__ == "__main__":
    unittest.main()
