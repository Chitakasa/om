"""The installers run small Python snippets against om's library (`from gitops import …; module.function(…)`). They are
not Python files, so nothing else would notice a function that moved: every module and attribute they use must exist."""
import importlib
import re
import unittest

import _env

INSTALLERS = ("install.sh", "install.ps1")
MODULES = ("omstate", "wsregistry", "enginectl", "vpndetect", "omsettings", "migration", "core", "corewatch")


class TestInstallers(unittest.TestCase):
    def test_every_library_call_in_an_installer_exists(self):
        checked = 0
        for name in INSTALLERS:
            text = (_env.REPO / name).read_text(encoding="utf-8")
            imported = set()
            for group in re.findall(r"from gitops import ([\w, ]+)", text):
                imported |= {m.strip() for m in group.split(",")}
            for module in imported:
                importlib.import_module(f"gitops.{module}")
            for module, attr in re.findall(rf"\b({'|'.join(MODULES)})\.([A-Za-z_]\w*)\(", text):
                self.assertIn(module, imported, f"{name} calls {module}.{attr} without importing {module}")
                self.assertTrue(hasattr(importlib.import_module(f"gitops.{module}"), attr), f"{name}: {module}.{attr} does not exist")
                checked += 1
        self.assertGreaterEqual(checked, 5)  # the installers do call the library, so the checks above ran


if __name__ == "__main__":
    unittest.main()
