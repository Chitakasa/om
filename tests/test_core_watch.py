"""core.watch, the loop behind `om core watch`: a pidfd per container, the engine's event stream, a 60 s backstop, and
`revive_zombies` two seconds after a process exits. The poller, the event stream and the pidfds are scripted; what is
checked is what it printed and the order of what it did. Expected values were recorded before watch was split."""
import contextlib
import io
import unittest
from unittest import mock

import _env  # noqa: F401

from gitops import corewatch

EVENTS_FD = 900
EXPECTED = {'a process exits and is revived': {'result': 0, 'out': "[T] watching 1 container(s)\n[T] process of om_caddy died unseen; restarted ['om_caddy']\n", 'log': [['popen', '{{.Status}}'], ['register', 900], ['register', 1101], ['revive', 'podman'], ['poll', 60000], ['sleep', 2], ['revive', 'podman'], ['unregister', 1101], ['close', 1101], ['register', 1101]]}, 'a restart that fails is reported': {'result': 0, 'out': "[T] watching 1 container(s)\n[T] process of om_caddy died unseen; restarted nothing, failed ['om_caddy']\n", 'log': [['popen', '{{.Status}}'], ['register', 900], ['register', 1101], ['revive', 'podman'], ['poll', 60000], ['sleep', 2], ['revive', 'podman'], ['unregister', 1101], ['close', 1101], ['register', 1101]]}, 'an exit the engine recorded changes nothing': {'result': 0, 'out': "[T] watching 2 container(s)\n[T] process of om_router died unseen; restarted ['om_router']\n", 'log': [['popen', '{{.Status}}'], ['register', 900], ['register', 1101], ['register', 1102], ['revive', 'podman'], ['poll', 60000], ['sleep', 2], ['revive', 'podman'], ['unregister', 1101], ['close', 1101], ['unregister', 1102], ['close', 1102], ['register', 1101], ['register', 1102], ['poll', 60000], ['sleep', 2], ['revive', 'podman'], ['unregister', 1101], ['close', 1101], ['unregister', 1102], ['close', 1102], ['register', 1101], ['register', 1102]]}, 'the event stream ends': {'result': 0, 'out': "[T] watching 1 container(s)\n[T] process of om_caddy died unseen; restarted ['om_caddy']\n", 'log': [['popen', '{{.Status}}'], ['register', 900], ['register', 1101], ['revive', 'podman'], ['poll', 60000], ['popen', '{{.Status}}'], ['unregister', 900], ['register', 900], ['unregister', 1101], ['close', 1101], ['register', 1101], ['poll', 60000], ['sleep', 2], ['revive', 'podman'], ['unregister', 1101], ['close', 1101], ['register', 1101]]}, 'an event arrives': {'result': 0, 'out': "[T] watching 1 container(s)\n[T] process of om_caddy died unseen; restarted ['om_caddy']\n", 'log': [['popen', '{{.Status}}'], ['register', 900], ['register', 1101], ['revive', 'podman'], ['poll', 60000], ['unregister', 1101], ['close', 1101], ['register', 1101], ['poll', 60000], ['sleep', 2], ['revive', 'podman'], ['unregister', 1101], ['close', 1101], ['register', 1101]]}, 'the backstop refreshes the set': {'result': 0, 'out': "[T] watching 1 container(s)\n[T] process of om_caddy died unseen; restarted ['om_caddy']\n", 'log': [['popen', '{{.Status}}'], ['register', 900], ['register', 1101], ['revive', 'podman'], ['poll', 60000], ['unregister', 1101], ['close', 1101], ['register', 1101], ['poll', 60000], ['sleep', 2], ['revive', 'podman'], ['unregister', 1101], ['close', 1101], ['register', 1101]]}, 'a container gone before its pidfd opens': {'result': 0, 'out': "[T] watching 1 container(s)\n[T] process of om_router died unseen; restarted ['om_router']\n", 'log': [['popen', '{{.Status}}'], ['register', 900], ['register', 1102], ['revive', 'podman'], ['poll', 60000], ['sleep', 2], ['revive', 'podman'], ['unregister', 1102], ['close', 1102], ['register', 1102]]}, 'two exits in one poll': {'result': 0, 'out': "[T] watching 2 container(s)\n[T] process of om_caddy, om_router died unseen; restarted ['om_caddy', 'om_router']\n", 'log': [['popen', '{{.Status}}'], ['register', 900], ['register', 1101], ['register', 1102], ['revive', 'podman'], ['poll', 60000], ['sleep', 2], ['revive', 'podman'], ['unregister', 1101], ['close', 1101], ['unregister', 1102], ['close', 1102], ['register', 1101], ['register', 1102]]}}


class FakePoller:
    def __init__(self, script, log):
        self.script, self.log = list(script), log

    def register(self, fd, mask):
        self.log.append(("register", fd))

    def unregister(self, fd):
        self.log.append(("unregister", fd))

    def poll(self, timeout):
        self.log.append(("poll", timeout))
        return self.script.pop(0)


class FakeStream:
    def __init__(self, lines):
        self.lines = list(lines)

    def fileno(self):
        return EVENTS_FD

    def readline(self):
        return self.lines.pop(0) if self.lines else ""


# A script is the list of what each poll() returns: (fd, mask) pairs; [] is the 60 s timeout.
SCENARIOS = {
    "a process exits and is revived": {"script": [[(1101, 1)]], "pids": {101: "om_caddy"}, "revive": [(["om_caddy"], [])], "max_events": 1},
    "a restart that fails is reported": {"script": [[(1101, 1)]], "pids": {101: "om_caddy"}, "revive": [([], ["om_caddy"])], "max_events": 1, "extra": [[(1101, 1)]]},
    "an exit the engine recorded changes nothing": {"script": [[(1101, 1)], [(1102, 1)]], "pids": {101: "om_caddy", 102: "om_router"},
                                                   "revive": [([], []), (["om_router"], [])], "max_events": 1},
    "the event stream ends": {"script": [[(EVENTS_FD, 1)], [(1101, 1)]], "pids": {101: "om_caddy"}, "revive": [(["om_caddy"], [])],
                              "max_events": 1, "lines": []},
    "an event arrives": {"script": [[(EVENTS_FD, 1)], [(1101, 1)]], "pids": {101: "om_caddy"}, "revive": [(["om_caddy"], [])],
                         "max_events": 1, "lines": ["start\n"]},
    "the backstop refreshes the set": {"script": [[], [(1101, 1)]], "pids": {101: "om_caddy"}, "revive": [(["om_caddy"], [])], "max_events": 1},
    "a container gone before its pidfd opens": {"script": [[(1102, 1)]], "pids": {101: "om_caddy", 102: "om_router"}, "gone": {101},
                                                 "revive": [(["om_router"], [])], "max_events": 1},
    "two exits in one poll": {"script": [[(1101, 1), (1102, 1)]], "pids": {101: "om_caddy", 102: "om_router"},
                              "revive": [(["om_caddy", "om_router"], [])], "max_events": 1},
}


def run_watch(sc):
    log, out = [], io.StringIO()
    revive = [([], [])] + list(sc.get("revive", []))  # the first call is the one at start-up
    stream = FakeStream(sc.get("lines", ["x\n"] * 5))
    poller = FakePoller(sc["script"] + sc.get("extra", []), log)

    def popen(cmd, **kw):
        log.append(("popen", cmd[-1]))
        return mock.Mock(stdout=stream)

    def pidfd_open(pid):
        if pid in sc.get("gone", ()):
            raise OSError("gone")
        return 1000 + pid

    def revive_zombies(runtime):
        log.append(("revive", runtime))
        return revive.pop(0) if revive else ([], [])

    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.object(corewatch, "IS_LINUX", True))
        stack.enter_context(mock.patch.object(corewatch, "_local_engine", lambda rt: True))
        stack.enter_context(mock.patch.object(corewatch.os, "pidfd_open", pidfd_open, create=True))
        stack.enter_context(mock.patch.object(corewatch.os, "close", lambda fd: log.append(("close", fd))))
        stack.enter_context(mock.patch.object(corewatch.subprocess, "Popen", popen))
        stack.enter_context(mock.patch("select.poll", lambda: poller))
        stack.enter_context(mock.patch.object(corewatch, "_om_pids", lambda rt: sc["pids"]))
        stack.enter_context(mock.patch.object(corewatch, "revive_zombies", revive_zombies))
        stack.enter_context(mock.patch.object(corewatch.time, "sleep", lambda s: log.append(("sleep", s))))
        stack.enter_context(mock.patch.object(corewatch.time, "strftime", lambda fmt: "T"))
        with contextlib.redirect_stdout(out):
            result = corewatch.watch("podman", max_events=sc["max_events"])
    return {"result": result, "out": out.getvalue(), "log": [list(entry) for entry in log]}


class TestWatch(unittest.TestCase):
    def test_every_scenario_behaves_as_recorded(self):
        self.assertEqual(set(SCENARIOS), set(EXPECTED))
        for name, scenario in SCENARIOS.items():
            with self.subTest(name):
                self.assertEqual(run_watch(scenario), EXPECTED[name])

    def test_unsupported_engines_are_refused_with_a_hint(self):
        out = io.StringIO()
        with mock.patch.object(corewatch, "_local_engine", lambda rt: False), contextlib.redirect_stdout(out):
            self.assertEqual(corewatch.watch("podman"), 1)
        self.assertIn("om core heal", out.getvalue())


if __name__ == "__main__":
    unittest.main()
