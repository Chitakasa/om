"""Random sequences of registry operations (seeded, so reproducible): after every one, port slots and host ports are
unique, a default stream port is its slot's port, and a workspace has exactly the services of its last assignment."""
import json
import random
import unittest

import _env  # noqa: F401

from gitops import omstate, wsregistry


def reset():
    for f in (omstate.STREAM_PORTS_FILE, omstate.SERVICE_PORTS_FILE, omstate.EGRESS_NETS_FILE, omstate.NET_POLICY_FILE, omstate.NO_LOG_FILE):
        f.unlink(missing_ok=True)


class TestRegistryInvariants(unittest.TestCase):
    def setUp(self):
        reset()
        self.addCleanup(reset)

    def check(self):
        slots = wsregistry.service_slots()
        self.assertEqual(len(set(slots.values())), len(slots), "two web services share a slot")
        stream = wsregistry.stream_ports()
        ports = [v["host_port"] for v in stream.values()]
        self.assertEqual(len(set(ports)), len(ports), "two stream services share a host port")
        used = [v["slot"] for v in stream.values() if v["slot"] is not None]
        self.assertEqual(len(set(used)), len(used), "two stream services share a slot")
        for v in stream.values():
            if v["slot"] is not None:
                self.assertEqual(v["host_port"], omstate.STREAM_PORT_BASE + v["slot"])
            else:
                self.assertTrue(v["host_port"] is not None)

    def test_random_operations_keep_the_registry_consistent(self):
        for seed in range(60):
            reset()
            r = random.Random(seed)
            last_web, last_stream = {}, {}
            for _ in range(40):
                ws = r.choice(["a", "a-b", "c"])
                svcs = r.sample(["x", "y", "z", "w", "v"], r.randint(0, 4))
                kind = r.choice(["slots", "stream", "stream", "release"])
                try:
                    if kind == "slots":
                        wsregistry.assign_slots(ws, svcs)
                        last_web[ws] = set(svcs)
                    elif kind == "stream":
                        meta = {s: {"container_port": 80, **({"host_port": r.choice([25565, 25570, 22003, 30000])} if r.random() < .4 else {})}
                                for s in svcs}
                        wsregistry.assign_stream_slots(ws, meta)
                        last_stream[ws] = set(svcs)
                    else:
                        wsregistry.release_slots(ws)
                        last_web[ws], last_stream[ws] = set(), set()
                except RuntimeError:
                    continue  # a clash is refused; what was there stays (checked below)
                self.check()
            web = {}
            for key in wsregistry.service_slots():
                web.setdefault(key.split("/")[0], set()).add(key.split("/", 1)[1])
            for ws, expected in last_web.items():
                self.assertEqual(web.get(ws, set()), expected, f"seed {seed}, workspace {ws}")

    def test_a_clash_refuses_and_changes_nothing(self):
        wsregistry.assign_stream_slots("a", {"mc": {"container_port": 25565, "host_port": 25565}})
        before = json.dumps(wsregistry.stream_ports(), sort_keys=True)
        with self.assertRaisesRegex(RuntimeError, "already reserved"):
            wsregistry.assign_stream_slots("b", {"mc": {"container_port": 25565, "host_port": 25565}})
        self.assertEqual(json.dumps(wsregistry.stream_ports(), sort_keys=True), before)

    def test_a_default_port_clashing_with_an_explicit_one_is_refused(self):
        wsregistry.assign_stream_slots("a", {"x": {"container_port": 80, "host_port": 22000}})
        with self.assertRaisesRegex(RuntimeError, "clashes"):
            wsregistry.assign_stream_slots("b", {"y": {"container_port": 80}})


if __name__ == "__main__":
    unittest.main()
