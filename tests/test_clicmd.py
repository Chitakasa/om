"""`om cli`: the om.cli label names a tool inside the service's own folder; nothing outside it can be run."""
import argparse
import contextlib
import io
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _env  # noqa: F401

from gitops import clicmd


def write(path: Path, text: str, mode=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    if mode:
        os.chmod(path, mode)
    return path


class TestResolve(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="om-cli-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.folder = self.tmp / "svc"
        write(self.folder / "tool", "#!/bin/sh\n", 0o755)
        write(self.folder / "bin" / "admin.py", "print(1)\n")
        write(self.tmp / "outside", "#!/bin/sh\n", 0o755)

    def test_a_file_inside_the_folder_is_accepted(self):
        self.assertEqual(clicmd.resolve_cli(self.folder, "./tool"), (self.folder / "tool").resolve())
        self.assertEqual(clicmd.resolve_cli(self.folder, "bin/admin.py").name, "admin.py")

    def test_anything_that_leaves_the_folder_or_is_not_a_plain_path_is_refused(self):
        for bad in ("", "  ", "../outside", "bin/../../outside", "/etc/passwd", "~/tool", "$HOME/tool", "C:\\tool",
                    "\\tool", "to\nol", "missing", "bin"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                clicmd.resolve_cli(self.folder, bad)

    @unittest.skipIf(os.name == "nt", "symlinks need privileges on Windows")
    def test_a_symlink_out_of_the_folder_is_refused(self):
        (self.folder / "link").symlink_to(self.tmp / "outside")
        with self.assertRaises(ValueError):
            clicmd.resolve_cli(self.folder, "link")

    def test_how_the_tool_is_started(self):
        self.assertEqual(clicmd.command_for(self.folder / "bin" / "admin.py"), [sys.executable, str(self.folder / "bin" / "admin.py")])
        if os.name != "nt":
            self.assertEqual(clicmd.command_for(self.folder / "tool"), [str(self.folder / "tool")])
            plain = write(self.folder / "plain", "x\n", 0o644)
            with self.assertRaises(ValueError):
                clicmd.command_for(plain)
            self.assertEqual(clicmd.command_for(write(self.folder / "run.sh", "x\n", 0o644))[1:], [str(self.folder / "run.sh")])


class TestLabelLookup(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="om-cli-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def lookup(self, compose_text, cfg=None):
        write(self.tmp / "compose.yml", compose_text)
        with mock.patch.object(clicmd.policy, "compose_config", return_value=(cfg, "" if cfg else "no engine")):
            return clicmd.folder_cli(self.tmp, "podman", {})

    def test_text_forms_when_there_is_no_engine(self):
        for text in ('services:\n  a:\n    labels:\n      - "om.cli=./tool"\n', "services:\n  a:\n    labels:\n      om.cli: ./tool\n",
                     'services:\n  a:\n    labels:\n      "om.cli": "./tool"  # the admin tool\n',
                     "services:\n  a:\n    labels:\n      - om.cli=./tool\n"):
            self.assertEqual(self.lookup(text), "./tool", text)

    def test_the_engines_normalized_config_wins(self):
        cfg = {"services": {"a": {"labels": {"om.cli": "./from-engine"}}, "b": {"labels": ["om.cli=./from-engine"]}, "c": {}}}
        self.assertEqual(self.lookup("services: {}\n", cfg), "./from-engine")

    def test_no_label_and_conflicting_labels(self):
        self.assertIsNone(self.lookup("services:\n  a:\n    image: x\n"))
        with self.assertRaises(ValueError):
            self.lookup("services: {}\n", {"services": {"a": {"labels": {"om.cli": "./one"}}, "b": {"labels": {"om.cli": "./two"}}}})


@unittest.skipIf(os.name == "nt", "the sample tool is a shell script")
class TestRun(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="om-cli-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        write(self.tmp / ".om" / "config.json", '{"workspace_id": "ws"}\n')
        write(self.tmp / "tool" / "compose.yml", 'services:\n  a:\n    image: x\n    labels:\n      - "om.cli=./admin"\n')
        write(self.tmp / "tool" / "admin", '#!/bin/sh\nprintf "%s|%s|%s\\n" "$*" "$WORKSPACE_ID" "$(basename "$PWD")" > "$OUT"\nexit 3\n', 0o755)
        write(self.tmp / "plain" / "compose.yml", "services:\n  a:\n    image: x\n")
        self.out = self.tmp / "out.txt"

    def cli(self, service, *args):
        env = {**os.environ, "WORKSPACE_ID": "ws", "OUT": str(self.out)}
        ns = argparse.Namespace(service=service, args=list(args))
        buf = io.StringIO()
        with mock.patch.object(clicmd, "detect_runtime", return_value="podman"), \
                mock.patch.object(clicmd, "get_workspace_env", return_value=env), \
                mock.patch.object(clicmd, "get_workspace_id", return_value="ws"), \
                mock.patch.object(clicmd.policy, "compose_config", return_value=(None, "no engine")), \
                contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            try:
                clicmd.cmd_cli(self.tmp, ns)
                code = 0
            except SystemExit as e:
                code = e.code
        return code, buf.getvalue()

    def test_arguments_environment_folder_and_exit_code_pass_through(self):
        code, _ = self.cli("tool", "logs", "-f")
        self.assertEqual(code, 3)
        self.assertEqual(self.out.read_text(encoding="utf-8").strip(), "logs -f|ws|tool")

    def test_listing_and_refusals(self):
        code, out = self.cli(None)
        self.assertEqual(code, 0)
        self.assertIn("tool", out)
        self.assertIn("./admin", out)
        self.assertNotIn("plain", out)
        self.assertNotEqual(self.cli("plain")[0], 0)        # no label
        self.assertNotEqual(self.cli("nothing-here")[0], 0)  # no such service


if __name__ == "__main__":
    unittest.main()
