import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _env  # noqa: F401  (sets OM_HOME before importing om modules)

from gitops import limits, prune


class TestLimits(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(limits.parse({"om.mem": "256M", "om.pids": "200", "om.cpus": "0.5"}),
                         ({"mem_limit": "256m", "pids_limit": 200, "cpus": 0.5}, []))
        out, problems = limits.parse({"om.mem": "lots", "om.pids": "0", "om.cpus": "0"})
        self.assertEqual(out, {})
        self.assertEqual(len(problems), 3)

    def test_override_written_only_for_labelled_services(self):
        old = limits.OVERRIDE_DIR
        limits.OVERRIDE_DIR = Path(tempfile.mkdtemp())
        self.addCleanup(setattr, limits, "OVERRIDE_DIR", old)
        cfg = {"services": {"a": {"labels": {"om.mem": "64m"}}, "b": {"labels": ["om.pids=50", "om.cpus=x"]}, "c": {}}}
        path, problems = limits.write_override("ws", Path("/p"), cfg)
        text = path.read_text(encoding="utf-8")
        self.assertIn('"a":', text)
        self.assertIn('mem_limit: "64m"', text)
        self.assertIn("pids_limit: 50", text)
        self.assertNotIn('"c"', text)
        self.assertEqual(len(problems), 1)
        self.assertEqual(limits.write_override("ws", Path("/p"), {"services": {"a": {}}}), (None, []))
        self.assertFalse(path.exists())


class TestPrune(unittest.TestCase):
    def test_parse_size(self):
        self.assertEqual(prune.parse_size("52.1 MB"), 52_100_000)
        self.assertEqual(prune.parse_size("980kB"), 980_000)
        self.assertEqual(prune.parse_size("1.5GB"), 1_500_000_000)
        self.assertEqual(prune.parse_size("n/a"), 0)

    def test_candidates_skip_used_and_locked_images(self):
        D = "sha256:" + "d" * 64
        outputs = {
            "images": "aaa111111111\tx/used:1\t10MB\nbbb222222222\tx/locked:1\t20MB\nccc333333333\tx/old:1\t30MB\nccc333333333\tx/old:2\t30MB\nddd444444444\t<none>:<none>\t5MB\n",
            "ps": "c1\n",
            "container": "sha256:aaa111111111deadbeef\n",
        }

        def fake_run(cmd, **kw):
            if cmd[1] == "image":  # image inspect <id>
                digests = f'["x/locked@{D}"]' if cmd[-1] == "bbb222222222" else "[]"
                return mock.Mock(returncode=0, stdout=digests)
            return mock.Mock(returncode=0, stdout=outputs[cmd[1]])

        with mock.patch.object(prune, "run", fake_run):
            found = prune.candidates("podman", {D})
        self.assertEqual([(e["id"], e["names"]) for e in found],
                         [("ccc333333333", ["x/old:1", "x/old:2"]), ("ddd444444444", [])])


if __name__ == "__main__":
    unittest.main()
