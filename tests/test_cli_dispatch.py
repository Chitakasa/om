"""Every command the parser accepts has a handler, and every handler a command."""
import argparse
import unittest

from _env import load_om

om = load_om()


class TestDispatch(unittest.TestCase):
    def commands(self):
        parser = om["build_parser"]()
        sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
        return set(sub.choices)

    def test_every_parser_command_has_a_handler(self):
        handlers = set(om["global_commands"](None, None, None)) | set(om["workspace_commands"]()) | {"status"}
        self.assertEqual(self.commands() - handlers, set(), "commands without a handler")
        self.assertEqual(handlers - self.commands(), set(), "handlers without a command")

    def test_parser_builds_in_groups(self):
        from gitops import cliparser
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        cliparser._add_core_command(sub)
        self.assertEqual(set(sub.choices), {"core"})


if __name__ == "__main__":
    unittest.main()
