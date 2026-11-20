import unittest

import _env  # noqa: F401  (sets OM_HOME / state for the library)

from gitops import links


def c(ws, svc, **labels):
    return {"name": f"{ws}_{svc}", "ws": ws, "svc": svc, "labels": labels, "networks": [], "running": True}


class TestLinks(unittest.TestCase):
    def test_both_sides_must_declare(self):
        conts = [c("app", "web", **{"om.link": "data/db"}), c("data", "db")]
        want, problems = links.desired(conts)
        self.assertEqual(want, {})
        self.assertIn("om.link.allow=app/web", problems[0])  # the refusal names the fix

    def test_link_and_wildcard(self):
        conts = [c("app", "web", **{"om.link": "data/db"}), c("app", "worker", **{"om.link": "data/db"}),
                 c("data", "db", **{"om.link.allow": "app/*"}), c("other", "x", **{"om.link": "data/db"})]
        want, problems = links.desired(conts)
        self.assertEqual(sorted(want.values()), [("app/web", "data/db"), ("app/worker", "data/db")])
        self.assertEqual(len(problems), 1)                       # other/x is not allowed
        self.assertNotEqual(links.network_name("app/web", "data/db"), links.network_name("app/worker", "data/db"))
        self.assertEqual(links.alias("data/db"), "data-db")      # one private network per pair

    def test_bad_targets(self):
        _, problems = links.desired([c("app", "web", **{"om.link": "nodb, data/missing"})])
        self.assertEqual(len(problems), 2)


if __name__ == "__main__":
    unittest.main()
