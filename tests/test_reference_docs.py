"""docs/COMMANDS.md, SETTINGS.md, LABELS.md and DOCTOR.md are generated from the code (tests/gen_reference.py): they must
be exactly what the code produces now, and must cover every command, setting, label and doctor check."""
import unittest

import _env
import gen_reference

from gitops import cliparser, doctor, scaffold, settingscmd

HOW = "run `python3 tests/gen_reference.py` and commit the result"


class TestReferenceDocs(unittest.TestCase):
    def test_the_files_are_what_the_code_produces(self):
        for rel, text in gen_reference.render_all().items():
            self.assertEqual((_env.REPO / rel).read_text(encoding="utf-8"), text, f"{rel} is stale: {HOW}")

    def test_every_command_setting_label_and_check_is_covered(self):
        docs = gen_reference.render_all()
        for _, names in cliparser.HELP_GROUPS:
            for name in names:
                self.assertIn(f"### `om {name}`", docs["docs/COMMANDS.md"], name)
        for key in settingscmd.KEYS:
            self.assertIn(f"## `{key}`", docs["docs/SETTINGS.md"], key)
        for label, _, _ in [*scaffold.ACTIVE_LABELS, *(i for _, items in scaffold.LABEL_MENU for i in items)]:
            self.assertIn(f"| `{label}` |", docs["docs/LABELS.md"], label)
        for checks in (doctor.BASIC_CHECKS, doctor.PERIMETER_CHECKS, doctor.HOST_CHECKS):
            for name, fn, _ in checks:
                self.assertIn(f"### {name}\n", docs["docs/DOCTOR.md"], name)
                self.assertTrue((fn.__doc__ or "").strip(), f"check {name} has no docstring (it is the doctor doc)")

    def test_the_settings_text_covers_exactly_the_settings(self):
        self.assertEqual(set(settingscmd.ABOUT), settingscmd.KEYS)


if __name__ == "__main__":
    unittest.main()
