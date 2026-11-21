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
