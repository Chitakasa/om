"""stream.validate_haproxy_syntax: the host's haproxy if there is one, else the engine's haproxy image, else a structural
check in Python. The first two are only asked; the third is the one that can run anywhere."""
import os
import subprocess
import unittest
from pathlib import Path
from unittest import mock

import _env  # noqa: F401

from gitops import stream

GOOD = stream.base_edge_config() + "\n" + stream.render_edge_fragment("ws", "mc", 25565)


def proc(code, out="", err=""):
    return subprocess.CompletedProcess([], code, out, err)


class TestValidation(unittest.TestCase):
    def patched(self, which, run):
        return mock.patch.multiple(stream, shutil=mock.Mock(which=which), omstate=mock.Mock(run=run))

    @unittest.skipIf(os.name == "nt", "POSIX file modes")
    def test_host_haproxy_decides_when_present(self):
        seen = []

        def run(cmd, **kw):
            seen.append(cmd)
            self.assertTrue(Path(cmd[-1]).is_file())      # the config is written for it...
            self.assertEqual(Path(cmd[-1]).stat().st_mode & 0o777, 0o644)
            return proc(0)
        with self.patched(lambda name: "/usr/bin/haproxy" if name == "haproxy" else None, run):
            self.assertEqual(stream.validate_haproxy_syntax(GOOD, "podman"), [])
        self.assertEqual(seen[0][:3], ["/usr/bin/haproxy", "-c", "-f"])
        self.assertFalse(Path(seen[0][-1]).exists())      # ...and removed afterwards

    def test_host_haproxy_exit_codes(self):
        for code, expected in ((0, False), (2, False), (1, True), (3, True)):
            with self.patched(lambda name: "/usr/bin/haproxy", lambda cmd, code=code, **kw: proc(code, "", "bad things")):
                problems = stream.validate_haproxy_syntax(GOOD)
            self.assertEqual(bool(problems), expected, code)
            if expected:
                self.assertEqual(problems, ["HAProxy validation error: bad things"])

    def test_engine_image_is_used_without_a_host_haproxy(self):
        seen = []
        which = lambda name: "/usr/bin/podman" if name == "podman" else None  # noqa: E731
        with self.patched(which, lambda cmd, **kw: seen.append(cmd) or proc(1, "engine says no")):
            problems = stream.validate_haproxy_syntax(GOOD, "podman")
        self.assertEqual(problems, ["HAProxy engine validation error: engine says no"])
        self.assertEqual(seen[0][:4], ["podman", "run", "--rm", "-v"])
        self.assertIn(stream.HAPROXY_IMAGE, seen[0])
        self.assertTrue(seen[0][4].endswith(":/tmp/check.cfg:ro,Z"))

    def test_the_test_runtime_never_reaches_an_engine(self):
        ran = []
        which = lambda name: None if name == "haproxy" else "/usr/bin/x"  # noqa: E731  (an engine binary exists, no haproxy)
        with self.patched(which, lambda cmd, **kw: ran.append(cmd) or proc(0)):
            stream.validate_haproxy_syntax("frontend x\n    bind :1\n", "om-test-no-engine")
        self.assertEqual(ran, [])  # the test runtime falls through to the Python check, never to an engine

    def test_structural_fallback(self):
        with self.patched(lambda name: None, lambda *a, **k: self.fail("nothing may run")):
            self.assertEqual(stream.validate_haproxy_syntax(GOOD), [])
            self.assertEqual(stream.validate_haproxy_syntax("bind :80\n"), ["line 1: directive 'bind' outside any section"])
            bad = stream.validate_haproxy_syntax("global\n    invalid x\nfrontend stream_1\n    bind :1\n")
            self.assertIn("line 2: unknown or invalid directive 'invalid' in section 'global'", bad)
            self.assertIn("frontend 'stream_1' has no matching backend 'sock_1'", bad)
            router = "frontend sock_9\n    bind /x\n"
            self.assertEqual(stream.validate_haproxy_syntax(router), ["frontend 'sock_9' has no matching backend 'target_9'"])
            self.assertEqual(stream.validate_haproxy_syntax("frontend health\n    bind /x\n"), [])


if __name__ == "__main__":
    unittest.main()
