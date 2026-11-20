"""`om egress log`: what the proxy refused or let through, per service, for learning, audit and enforced services, with and
without --apply, a service filter, all workspaces, nothing to show, and an unreadable log. Expected output recorded before
cmd_egress was split into steps."""
import argparse
import contextlib
import io
import subprocess
import unittest
from pathlib import Path
from unittest import mock

import _env

from gitops import egress

om = _env.load_om()
LOG="\n".join([
 "1791323837.000 10 10.0.0.1 TCP_TUNNEL/200 1 CONNECT api.example.com:443 - HIER_DIRECT/1.2.3.4 -",
 "1791323838.000 10 10.0.0.1 TCP_MISS/200 1 GET http://deb.example.org/x - HIER_DIRECT/1.2.3.4 -",
 "1791323839.000 10 10.0.0.2 TCP_DENIED/403 1 CONNECT evil.example:443 - HIER_NONE/- -",
 "1791323840.000 10 10.0.0.3 TCP_TUNNEL/200 1 CONNECT cdn.example.net:443 - HIER_DIRECT/1.2.3.4 -",
 "1791323841.000 10 10.0.0.4 TCP_TUNNEL/200 1 CONNECT x.example.io:443 - HIER_DIRECT/1.2.3.4 -",
 "1791323842.000 10 10.0.0.5 TCP_DENIED/403 1 CONNECT blocked.example:443 - HIER_NONE/- -"])
IPS={"10.0.0.1":"ws.learner","10.0.0.2":"ws.strict","10.0.0.3":"ws.auditor","10.0.0.4":"other.thing","10.0.0.5":"ws.expired"}
RULES={"ws":{"learner":egress.LEARN,"strict":["a.example.com"],"auditor":egress.AUDIT,"expired":egress.LEARN},"other":{"thing":["t.example.com"]}}
REM={("ws","learner"):5400,("ws","auditor"):-1,("ws","expired"):0}
LEARN={("ws","learner"):{"hosts":{"api.example.com":{"count":3},"deb.example.org":{"count":1}}}}
EXPECTED = {'all': '\n  \x1b[1mws/auditor\x1b[0m \x1b[33m(audit mode — permanent, no expiry)\x1b[0m\n    used: cdn.example.net\n    when done, run: \x1b[36mom egress log auditor --apply\x1b[0m\n    or set in compose: \x1b[36mom.egress=cdn.example.net\x1b[0m\n\n  \x1b[1mws/expired\x1b[0m \x1b[33m(learning expired — fell back to deny-all)\x1b[0m\n    when done, run: \x1b[36mom egress log expired --apply\x1b[0m\n    or set in compose: \x1b[36mom.egress=blocked.example\x1b[0m\n\n  \x1b[1mws/learner\x1b[0m \x1b[33m(learning, 1h 30m left)\x1b[0m\n    - api.example.com (3 requests)\n    - deb.example.org (1 requests)\n    when done, run: \x1b[36mom egress log learner --apply\x1b[0m\n    or set in compose: \x1b[36mom.egress=api.example.com,deb.example.org\x1b[0m\n\n  \x1b[1mws/strict\x1b[0m was refused: evil.example\n    to allow, run: \x1b[36mom egress log strict --apply\x1b[0m\n    or set in compose: \x1b[36mom.egress=a.example.com,evil.example\x1b[0m\n\n', 'apply': "\n  \x1b[1mws/auditor\x1b[0m \x1b[33m(audit mode — permanent, no expiry)\x1b[0m\n    used: cdn.example.net\nAPPLIED ('ws', 'auditor', 'cdn.example.net')\n\n  \x1b[1mws/expired\x1b[0m \x1b[33m(learning expired — fell back to deny-all)\x1b[0m\nAPPLIED ('ws', 'expired', 'blocked.example')\n\n  \x1b[1mws/learner\x1b[0m \x1b[33m(learning, 1h 30m left)\x1b[0m\n    - api.example.com (3 requests)\n    - deb.example.org (1 requests)\nAPPLIED ('ws', 'learner', 'api.example.com,deb.example.org')\n\n  \x1b[1mws/strict\x1b[0m was refused: evil.example\nAPPLIED ('ws', 'strict', 'a.example.com,evil.example')\n\n", 'one service': '\n  \x1b[1mws/learner\x1b[0m \x1b[33m(learning, 1h 30m left)\x1b[0m\n    - api.example.com (3 requests)\n    - deb.example.org (1 requests)\n    when done, run: \x1b[36mom egress log learner --apply\x1b[0m\n    or set in compose: \x1b[36mom.egress=api.example.com,deb.example.org\x1b[0m\n\n', 'log word only': '\n  \x1b[1mws/auditor\x1b[0m \x1b[33m(audit mode — permanent, no expiry)\x1b[0m\n    used: cdn.example.net\n    when done, run: \x1b[36mom egress log auditor --apply\x1b[0m\n    or set in compose: \x1b[36mom.egress=cdn.example.net\x1b[0m\n\n  \x1b[1mws/expired\x1b[0m \x1b[33m(learning expired — fell back to deny-all)\x1b[0m\n    when done, run: \x1b[36mom egress log expired --apply\x1b[0m\n    or set in compose: \x1b[36mom.egress=blocked.example\x1b[0m\n\n  \x1b[1mws/learner\x1b[0m \x1b[33m(learning, 1h 30m left)\x1b[0m\n    - api.example.com (3 requests)\n    - deb.example.org (1 requests)\n    when done, run: \x1b[36mom egress log learner --apply\x1b[0m\n    or set in compose: \x1b[36mom.egress=api.example.com,deb.example.org\x1b[0m\n\n  \x1b[1mws/strict\x1b[0m was refused: evil.example\n    to allow, run: \x1b[36mom egress log strict --apply\x1b[0m\n    or set in compose: \x1b[36mom.egress=a.example.com,evil.example\x1b[0m\n\n', 'all workspaces': '\n  \x1b[1mws/auditor\x1b[0m \x1b[33m(audit mode — permanent, no expiry)\x1b[0m\n    used: cdn.example.net\n    when done, run: \x1b[36mom egress log auditor --apply\x1b[0m\n    or set in compose: \x1b[36mom.egress=cdn.example.net\x1b[0m\n\n  \x1b[1mws/expired\x1b[0m \x1b[33m(learning expired — fell back to deny-all)\x1b[0m\n    when done, run: \x1b[36mom egress log expired --apply\x1b[0m\n    or set in compose: \x1b[36mom.egress=blocked.example\x1b[0m\n\n  \x1b[1mws/learner\x1b[0m \x1b[33m(learning, 1h 30m left)\x1b[0m\n    - api.example.com (3 requests)\n    - deb.example.org (1 requests)\n    when done, run: \x1b[36mom egress log learner --apply\x1b[0m\n    or set in compose: \x1b[36mom.egress=api.example.com,deb.example.org\x1b[0m\n\n  \x1b[1mws/strict\x1b[0m was refused: evil.example\n    to allow, run: \x1b[36mom egress log strict --apply\x1b[0m\n    or set in compose: \x1b[36mom.egress=a.example.com,evil.example\x1b[0m\n\n', 'nothing': '  Nothing refused or learned in the last 24h for workspace ws.\n  A service without om.egress never reaches the proxy; set `om.egress=learn` (discovery) or `om.egress=audit` (permanent) to record and allow what it uses.\n\n', 'permanent learn': '\n  \x1b[1mws/auditor\x1b[0m \x1b[33m(audit mode — permanent, no expiry)\x1b[0m\n    used: cdn.example.net\n    when done, run: \x1b[36mom egress log auditor --apply\x1b[0m\n    or set in compose: \x1b[36mom.egress=cdn.example.net\x1b[0m\n\n'}
SCENARIOS = {
    "all": {}, "apply": {"apply": True}, "one service": {"target": ["learner", "log"]}, "log word only": {"target": ["log"]},
    "all workspaces": {"all": True}, "nothing": {"target": ["nope"]}, "permanent learn": {"target": ["auditor"]},
}


def run_egress(**kw):
    g = om["cmd_egress"].__globals__
    args = argparse.Namespace(since="24h", apply=kw.get("apply", False), target=kw.get("target", []), all=kw.get("all", False))
    with mock.patch.dict(g, {"detect_runtime": lambda: "podman", "run": lambda cmd, **k: subprocess.CompletedProcess(cmd, 0, LOG, ""),
                             "get_workspace_id": lambda r: "ws", "_apply_suggestion_to_root": lambda *a: print("APPLIED", a[1:])}), \
            mock.patch.object(egress, "all_service_ips", lambda: IPS), \
            mock.patch.object(egress, "_load_rules", lambda ws: RULES.get(ws, {})), \
            mock.patch.object(egress, "learn_remaining", lambda ws, svc: REM.get((ws, svc), 0)), \
            mock.patch.object(egress, "load_learn", lambda ws, svc: LEARN.get((ws, svc), {})), \
            mock.patch.object(egress, "record_learned_host", lambda *a, **k: None):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            om["cmd_egress"](Path("/tmp/x"), args)
    return buf.getvalue()


class TestEgressLog(unittest.TestCase):
    def test_each_scenario_prints_as_recorded(self):
        for name, kw in SCENARIOS.items():
            with self.subTest(name):
                self.assertEqual(run_egress(**kw), EXPECTED[name])

    def test_an_unreadable_log_is_a_clear_error(self):
        g = om["cmd_egress"].__globals__
        failing_run = lambda cmd, **k: subprocess.CompletedProcess(cmd, 1, "", "engine is down")  # noqa: E731
        with mock.patch.dict(g, {"detect_runtime": lambda: "podman", "run": failing_run}), self.assertRaises(SystemExit) as cm:
            om["cmd_egress"](Path("/tmp/x"), argparse.Namespace(since="1h", apply=False, target=[], all=False))
        self.assertEqual(cm.exception.code, 1)

    def test_learning_status_wording(self):
        status = om["_learning_status"]
        self.assertEqual(status(egress.AUDIT, 0), "(audit mode — permanent, no expiry)")
        self.assertEqual(status(egress.LEARN, -1), "(learning — permanent, no expiry)")
        self.assertEqual(status(egress.LEARN, 3 * 3600 + 120), "(learning, 3h 2m left)")
        self.assertEqual(status(egress.LEARN, 0), "(learning expired — fell back to deny-all)")


if __name__ == "__main__":
    unittest.main()
