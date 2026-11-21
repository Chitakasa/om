"""Things a newcomer meets first: every command answers --help cleanly, the docs only name commands that exist,
and a folder om skips (.omignore) is reported instead of silently missing."""
import argparse
import contextlib
import io
import re
import shutil
import tempfile
import unittest
from pathlib import Path

import _env
from _env import load_om

from gitops import cliparser, workspace

REPO = _env.REPO
DOC_FILES = [REPO / "README.md", REPO / "CONTRIBUTING.md", *sorted((REPO / "docs").glob("*.md"))]


def commands() -> set:
    sub = next(a for a in cliparser.build_parser()._actions if isinstance(a, argparse._SubParsersAction))
    return set(sub.choices)


class TestHelp(unittest.TestCase):
    def test_every_command_answers_help_cleanly(self):
        for name in sorted(commands()):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as cm:
                cliparser.build_parser().parse_args([name, "--help"])
            self.assertEqual(cm.exception.code, 0, name)
            self.assertTrue(out.getvalue().startswith("usage:"), name)
            self.assertNotIn("==", out.getvalue(), name)

    def test_the_command_list_has_no_internal_markers(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            cliparser.build_parser().parse_args(["--help"])
        self.assertNotIn("==SUPPRESS==", out.getvalue())


class TestGroupedHelp(unittest.TestCase):
    def test_every_command_is_in_exactly_one_group(self):
        listed = [name for _, names in cliparser.HELP_GROUPS for name in names]
        self.assertEqual(len(listed), len(set(listed)), "a command is in two groups")
        self.assertEqual(set(listed), commands() - cliparser.UNLISTED)

    def test_top_level_help_shows_the_groups_and_every_command(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            cliparser.build_parser().parse_args(["--help"])
        text = out.getvalue()
        for group, names in cliparser.HELP_GROUPS:
            self.assertIn(f"{group}:", text)
            for name in names:
                self.assertRegex(text, rf"(?m)^  {name}\s+\S", name)   # listed with a description
        self.assertLess(text.index("Everyday:"), text.index("Platform and upkeep:"))

    def test_a_commands_own_help_is_unchanged(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            cliparser.build_parser().parse_args(["start", "--help"])
        self.assertIn("usage: om start", out.getvalue())


class TestNextSteps(unittest.TestCase):
    om = load_om()

    def test_a_stopped_core_and_no_workspace_say_what_to_type(self):
        steps = self.om["next_steps"](None, {})
        self.assertEqual([c for c, _ in steps], ["om core start", "cd <folder>; om init"])

    def test_a_running_core_inside_a_workspace_needs_no_hint(self):
        self.assertEqual(self.om["next_steps"](Path("."), {"om_caddy": ("up 2 hours", "running")}), [])


class TestDocsNameRealCommands(unittest.TestCase):
    def test_backticked_om_commands_exist(self):
        known = commands() | {"help"}
        bad = []
        for path in DOC_FILES:
            text = re.sub(r"(?ms)^## (?:Horizons|\d+\. Ideas).*?(?=^## |\Z)", "", path.read_text(encoding="utf-8"))  # ideas are not commands yet
            for m in re.finditer(r"`om ([a-z][a-z-]*)\b", text):
                if m.group(1) not in known:
                    bad.append(f"{path.name}: om {m.group(1)}")
        self.assertEqual(bad, [])


class TestIgnoredFolders(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="om-ign-"))
        self.addCleanup(shutil.rmtree, self.root, True)

    def compose(self, *parts, ignored=False):
        folder = self.root.joinpath(*parts)
        folder.mkdir(parents=True)
        (folder / "compose.yml").write_text("services: {}\n", encoding="utf-8", newline="\n")
        if ignored:
            (folder / ".omignore").write_text("not managed\n", encoding="utf-8", newline="\n")
        return folder

    def test_ignored_folders_are_listed_and_managed_ones_are_not(self):
        managed = self.compose("web")
        top = self.compose("backup", ignored=True)
        deep = self.compose("services", "db", ignored=True)
        self.compose("services", "api")
        self.assertEqual(workspace.ignored_compose_dirs(self.root), [top, deep])
        self.assertIn(managed, [d for _, d in workspace.discover_compose_dirs(self.root)])
        self.assertNotIn(top, [d for _, d in workspace.discover_compose_dirs(self.root)])

    def test_a_folder_without_a_compose_file_is_not_reported(self):
        (self.root / "notes").mkdir()
        (self.root / "notes" / ".omignore").write_text("x\n", encoding="utf-8", newline="\n")
        self.assertEqual(workspace.ignored_compose_dirs(self.root), [])


if __name__ == "__main__":
    unittest.main()
