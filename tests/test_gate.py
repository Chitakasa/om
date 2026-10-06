import unittest

import _env  # noqa: F401  (sets OM_HOME before importing om modules)
from gitops import gate

S = {"OM_DOMAIN": "box.internal"}
HEAD = {
    "door": {"subnet": "10.77.0.0/24", "address": "10.77.0.1"},
    "devices": {"a-phone": {"address": "10.77.0.2", "person": "alice"},
                "laptop": {"address": "10.77.0.3"}},
    "people": {"alice": {"status": "active", "grants": [{"service": "ws/notes", "until": None},
                                                         {"service": "ws/vault", "until": None},
                                                         {"service": "ws/old", "until": "2000-01-01"}]},
               "bob": {"status": "invited", "grants": [{"service": "ws/notes", "until": None}]}},
}


class TestGate(unittest.TestCase):
    def test_domains_and_hosts(self):
        self.assertEqual(gate.domains(S), ("box.internal", "box-p.internal"))
        self.assertEqual(gate.host_for("ws", "notes", "member", S), "ws-notes.box.internal")
        self.assertEqual(gate.host_for("ws", "vault", "private", S), "ws-vault.box-p.internal")

    def test_level_defaults_to_private_and_rejects_typos(self):
        self.assertEqual(gate.level_of({}), "private")
        self.assertEqual(gate.level_of({"om.access": "Shared"}), "shared")
        self.assertIsNone(gate.level_of({"om.access": "publik"}))

    def test_rules(self):
        services = {("ws", "status"): "shared", ("ws", "notes"): "member", ("ws", "vault"): "private",
                    ("ws", "old"): "member", ("ws", "nobody"): "member"}
        rs = {r["domain"]: r for r in gate.rules(HEAD, services, S)}
        self.assertEqual(rs["ws-status.box.internal"], {"domain": "ws-status.box.internal", "networks": ["10.77.0.0/24"], "policy": "bypass"})
        # member: any enrolled device, only active people with a grant (bob is only invited)
        self.assertEqual(rs["ws-notes.box.internal"]["subject"], ["user:alice"])
        self.assertEqual(rs["ws-notes.box.internal"]["networks"], ["10.77.0.0/24"])
        # private: only alice's own devices
        self.assertEqual(rs["ws-vault.box-p.internal"]["networks"], ["10.77.0.2/32"])
        # expired grant and no grant at all: no rule, so the default deny applies
        self.assertNotIn("ws-old.box.internal", rs)
        self.assertNotIn("ws-nobody.box.internal", rs)

    def test_no_door_no_rules(self):
        self.assertEqual(gate.rules({}, {("ws", "x"): "shared"}, S), [])


if __name__ == "__main__":
    unittest.main()
