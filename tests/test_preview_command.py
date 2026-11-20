"""`om preview`: listing, removing and starting a branch as a throw-away workspace. Thirteen scenarios run with every
collaborator replaced by a recorder; what is checked is the exit code, the text printed and the calls made, in order.
The expected values are those recorded before cmd_preview was split into list / remove / create / start."""
import argparse
import contextlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _env

from gitops import agesecrets, egress, links, omstate, wsregistry

om = _env.load_om()
EXPECTED = {'list none': {'code': None, 'out': '\n\x1b[1mPREVIEWS of app\x1b[0m\n  None. `om preview <branch>` runs a branch next to this workspace.\n\n', 'err': '', 'calls': []}, 'list some': {'code': None, 'out': '\n\x1b[1mPREVIEWS of app\x1b[0m\n  app--feat                            branch main                     /p/feat\n  app--x                               branch main                     /p/x\n\n', 'err': '', 'calls': [['run', ['git', '-C', '/p/feat', 'branch', '--show-current'], {}], ['run', ['git', '-C', '/p/x', 'branch', '--show-current'], {}]]}, 'rm existing': {'code': None, 'out': '\x1b[32m✓ Preview app--feat removed\x1b[0m: containers, data, routes, ports and worktree. The branch feat is kept (git branch -D feat to delete it).\n', 'err': '', 'calls': [['env', ['<tmp>/previews/app--feat', 'app--feat', 'podman'], {}], ['discover', ['<tmp>/previews/app--feat', None], {}], ['run', ['podman', 'compose', '-f', '<tmp>/svc/compose.yml', 'down', '-v'], {'cwd': '<tmp>/svc'}], ['wipe', ['app--feat'], {}], ['render', ['podman', 'app--feat', {}], {'prune': True}], ['update_registry', ['<callable>'], {}], ['release', ['app--feat'], {}], ['reload_caddy', ['podman'], {'quiet': True}], ['run', ['podman', 'network', 'disconnect', 'app--feat_net', 'om_router'], {}], ['run', ['podman', 'network', 'disconnect', 'app--feat_net', 'om_egress'], {}], ['run', ['podman', 'network', 'rm', 'app--feat_net'], {}], ['prune_nets', ['podman', 'app--feat', []], {}], ['set_egress', ['app--feat', None], {}], ['rmtree', ['<state>/generations/app--feat'], {'ignore_errors': True}], ['run', ['git', '-C', '<tmp>/root', 'worktree', 'remove', '--force', '<tmp>/previews/app--feat'], {}], ['rmtree', ['<tmp>/previews/app--feat'], {'ignore_errors': True}], ['run', ['git', '-C', '<tmp>/root', 'worktree', 'prune'], {}], ['links_sync', ['podman'], {}]]}, 'rm registry only': {'code': None, 'out': '\x1b[32m✓ Preview app--feat removed\x1b[0m: containers, data, routes, ports and worktree. The branch feat is kept (git branch -D feat to delete it).\n', 'err': '', 'calls': [['wipe', ['app--feat'], {}], ['render', ['podman', 'app--feat', {}], {'prune': True}], ['update_registry', ['<callable>'], {}], ['release', ['app--feat'], {}], ['reload_caddy', ['podman'], {'quiet': True}], ['run', ['podman', 'network', 'disconnect', 'app--feat_net', 'om_router'], {}], ['run', ['podman', 'network', 'disconnect', 'app--feat_net', 'om_egress'], {}], ['run', ['podman', 'network', 'rm', 'app--feat_net'], {}], ['prune_nets', ['podman', 'app--feat', []], {}], ['set_egress', ['app--feat', None], {}], ['rmtree', ['<state>/generations/app--feat'], {'ignore_errors': True}], ['run', ['git', '-C', '<tmp>/root', 'worktree', 'remove', '--force', '<tmp>/previews/app--feat'], {}], ['links_sync', ['podman'], {}]]}, 'rm missing': {'code': 1, 'out': '', 'err': 'No preview app--feat.\n', 'calls': []}, 'start new branch': {'code': None, 'out': '\x1b[32m✓ feat checked out as preview app--feat\x1b[0m (new branch from main)\n  Throw it away: om preview rm feat\n\n', 'err': '', 'calls': [['run', ['git', '-C', '<tmp>/root', 'rev-parse', '--is-inside-work-tree'], {}], ['run', ['git', '-C', '<tmp>/root', 'branch', '--show-current'], {}], ['run', ['git', '-C', '<tmp>/root', 'rev-parse', '--verify', '--quiet', 'refs/heads/feat'], {}], ['run', ['git', '-C', '<tmp>/root', 'worktree', 'add', '-b', 'feat', '<tmp>/previews/app--feat'], {}], ['write_local', ['<tmp>/previews/app--feat', {'workspace_id': 'app--feat', 'preview_of': 'app'}], {}], ['run', ['git', '-C', '<tmp>/root', 'branch', '--show-current'], {}], ['register', ['<tmp>/previews/app--feat', 'app--feat'], {}], ['start', ['<tmp>/previews/app--feat'], {'kind': 'preview'}], ['routes', ['<tmp>/previews/app--feat', "Namespace(action='start', branch='feat')"], {}]]}, 'start existing branch': {'code': None, 'out': '\x1b[32m✓ feat checked out as preview app--feat\x1b[0m\n  Throw it away: om preview rm feat\n\n', 'err': '', 'calls': [['run', ['git', '-C', '<tmp>/root', 'rev-parse', '--is-inside-work-tree'], {}], ['run', ['git', '-C', '<tmp>/root', 'branch', '--show-current'], {}], ['run', ['git', '-C', '<tmp>/root', 'rev-parse', '--verify', '--quiet', 'refs/heads/feat'], {}], ['run', ['git', '-C', '<tmp>/root', 'worktree', 'add', '<tmp>/previews/app--feat', 'feat'], {}], ['write_local', ['<tmp>/previews/app--feat', {'workspace_id': 'app--feat', 'preview_of': 'app'}], {}], ['register', ['<tmp>/previews/app--feat', 'app--feat'], {}], ['start', ['<tmp>/previews/app--feat'], {'kind': 'preview'}], ['routes', ['<tmp>/previews/app--feat', "Namespace(action='start', branch='feat')"], {}]]}, 'start checked out': {'code': 1, 'out': '', 'err': 'main is checked out here already — `om start` runs it.\n', 'calls': [['run', ['git', '-C', '<tmp>/root', 'rev-parse', '--is-inside-work-tree'], {}], ['run', ['git', '-C', '<tmp>/root', 'branch', '--show-current'], {}]]}, 'not git': {'code': 1, 'out': '', 'err': 'Previews need the workspace to be a git repository (git init).\n', 'calls': [['run', ['git', '-C', '<tmp>/root', 'rev-parse', '--is-inside-work-tree'], {}]]}, 'worktree fails': {'code': 1, 'out': '', 'err': 'git worktree failed: wt error\n', 'calls': [['run', ['git', '-C', '<tmp>/root', 'rev-parse', '--is-inside-work-tree'], {}], ['run', ['git', '-C', '<tmp>/root', 'branch', '--show-current'], {}], ['run', ['git', '-C', '<tmp>/root', 'rev-parse', '--verify', '--quiet', 'refs/heads/feat'], {}], ['run', ['git', '-C', '<tmp>/root', 'worktree', 'add', '-b', 'feat', '<tmp>/previews/app--feat'], {}]]}, 'path exists, portable problem': {'code': 1, 'out': '', 'err': 'These names would collide with the original workspace; use the variables om sets:\n  web: container_name: x\n', 'calls': []}, 'path exists, start fails': {'code': 1, 'out': '', 'err': 'The preview did not start cleanly; `om preview rm feat` throws it away.\n', 'calls': [['register', ['<tmp>/previews/app--feat', 'app--feat'], {}], ['start', ['<tmp>/previews/app--feat'], {'kind': 'preview'}]]}, 'path exists, ok': {'code': None, 'out': '  Throw it away: om preview rm feat\n\n', 'err': '', 'calls': [['register', ['<tmp>/previews/app--feat', 'app--feat'], {}], ['start', ['<tmp>/previews/app--feat'], {'kind': 'preview'}], ['routes', ['<tmp>/previews/app--feat', "Namespace(action='start', branch='feat')"], {}]]}}

SCENARIOS = {
    "list none": {"action": "list"},
    "list some": {"action": "list", "reg": {"app--feat": {"path": "/p/feat"}, "app--x": {"path": "/p/x"}}},
    "rm existing": {"action": "rm", "branch": "feat", "path_exists": True, "reg": {"app--feat": {"path": "/p"}}, "rmfail": True},
    "rm registry only": {"action": "rm", "branch": "feat", "path_exists": False, "reg": {"app--feat": {"path": "/p"}}},
    "rm missing": {"action": "rm", "branch": "feat", "path_exists": False, "reg": {}},
    "start new branch": {"action": "start", "branch": "feat", "git_ok": True, "current": "main", "branch_exists": False},
    "start existing branch": {"action": "start", "branch": "feat", "git_ok": True, "current": "main", "branch_exists": True},
    "start checked out": {"action": "start", "branch": "main", "git_ok": True, "current": "main"},
    "not git": {"action": "start", "branch": "feat", "git_ok": False},
    "worktree fails": {"action": "start", "branch": "feat", "git_ok": True, "current": "main", "branch_exists": False, "wt_fail": True},
    "path exists, portable problem": {"action": "start", "branch": "feat", "path_exists": True, "bad": ["web: container_name: x"]},
    "path exists, start fails": {"action": "start", "branch": "feat", "path_exists": True, "start_ok": False},
    "path exists, ok": {"action": "start", "branch": "feat", "path_exists": True},
}


def plain(x):
    """A JSON-friendly copy of a call argument (sets sorted, functions named, the environment left out)."""
    if isinstance(x, (set, frozenset)):
        return sorted(map(str, x))
    if isinstance(x, (list, tuple)):
        return [plain(i) for i in x]
    if isinstance(x, dict):
        return {str(k): plain(v) for k, v in x.items() if k != "env"}
    if callable(x):
        return "<callable>"
    return x if isinstance(x, (int, float, bool, str, type(None))) else str(x)


class Recorder:
    """Records every call made through it (name, arguments) and answers with a fixed value or a function."""

    def __init__(self):
        self.calls = []

    def __call__(self, name, answer=None):
        def call(*args, **kwargs):
            self.calls.append((name, plain(args), plain(kwargs)))
            return answer(*args, **kwargs) if callable(answer) else answer
        return call


def git_answer(sc, cmd):
    """What the faked git says to a command, as the scenario wants it."""
    words = [str(c) for c in cmd]
    code = 0
    if "--is-inside-work-tree" in words:
        code = 0 if sc.get("git_ok", True) else 1
    elif "--show-current" in words:
        return subprocess.CompletedProcess(cmd, 0, sc.get("current", "main") + "\n", "")
    elif "--verify" in words:
        code = 0 if sc.get("branch_exists") else 1
    elif "add" in words and "worktree" in words:
        code = 1 if sc.get("wt_fail") else 0
        return subprocess.CompletedProcess(cmd, code, "", "wt error" if code else "")
    elif "remove" in words and "worktree" in words:
        code = 1 if sc.get("rmfail") else 0
    return subprocess.CompletedProcess(cmd, code, "true" if "--is-inside-work-tree" in words else "", "")


def run_scenario(sc):
    g = om["cmd_preview"].__globals__
    tmp = Path(tempfile.mkdtemp(prefix="om-pv-"))
    try:
        previews, root, conf = tmp / "previews", tmp / "root", tmp / "conf"
        for d in (previews, root, conf):
            d.mkdir()
        pid = f"app--{sc.get('branch') or ''}"
        if sc.get("path_exists"):
            (previews / pid).mkdir()
        (conf / f"{pid}-web.caddy").write_text(f"# Service: web ({pid})\n", encoding="utf-8", newline="\n")
        rec = Recorder()

        def fake_run(cmd, **kwargs):
            rec.calls.append(("run", plain(cmd), plain({k: v for k, v in kwargs.items() if k != "env"})))
            return git_answer(sc, cmd)

        patches = {
            "run": fake_run, "detect_runtime": lambda: "podman", "read_registry": lambda: sc.get("reg", {}),
            "read_local": lambda r: {}, "get_workspace_id": lambda r: "app", "get_workspace_env": rec("env", {}),
            "discover_compose_dirs": rec("discover", [(50, tmp / "svc")]), "find_compose_file": lambda d: d / "compose.yml",
            "update_registry": rec("update_registry"), "route_owner": lambda f: pid, "reload_caddy": rec("reload_caddy"),
            "prune_project_networks": rec("prune_nets"), "write_local": rec("write_local"),
            "preview_portable": lambda p: sc.get("bad", []), "register_workspace": rec("register"),
            "start_workspace": rec("start", lambda *a, **k: sc.get("start_ok", True)), "cmd_routes": rec("routes"),
            "PREVIEWS_DIR": previews, "CONF_D": conf,
        }
        out, err, code = io.StringIO(), io.StringIO(), None
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.dict(g, patches))
            for obj, attr, name, answer in ((agesecrets, "wipe", "wipe", None), (egress, "render_workspace", "render", None),
                                            (wsregistry, "release_slots", "release", None),
                                            (wsregistry, "set_egress_networks", "set_egress", None), (links, "sync", "links_sync", []),
                                            (shutil, "rmtree", "rmtree", None)):
                stack.enter_context(mock.patch.object(obj, attr, rec(name, answer)))
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                try:
                    om["cmd_preview"](root, argparse.Namespace(action=sc["action"], branch=sc.get("branch")))
                except SystemExit as e:
                    code = e.code
        return json.loads(json.dumps({"code": code, "out": out.getvalue(), "err": err.getvalue(), "calls": rec.calls}).replace(str(tmp), "<tmp>").replace(str(omstate.STATE_DIR), "<state>"))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


class TestPreview(unittest.TestCase):
    def test_every_scenario_behaves_as_recorded(self):
        self.assertEqual(set(SCENARIOS), set(EXPECTED))
        for name, scenario in SCENARIOS.items():
            with self.subTest(name):
                self.assertEqual(run_scenario(scenario), EXPECTED[name])


if __name__ == "__main__":
    unittest.main()
