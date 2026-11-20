"""core.py was split by job into modules that may only import downward: omstate is the base, the others build on
it, and only core (the lifecycle) may use them all. A cycle or an upward import fails here before it fails at import time."""
import ast
import unittest
from pathlib import Path

import _env

LIB = _env.REPO / "lib" / "gitops"
# module -> the gitops modules it may import at the top of the file (late imports inside functions are the way
# around a cycle and are allowed)
MAY_IMPORT = {
    "omstate": set(),
    "wsregistry": {"omstate"},
    "vpndetect": {"omstate"},
    "migration": {"omstate"},
    "enginectl": {"omstate", "wsregistry"},
    "omsettings": {"omstate", "wsregistry", "vpndetect", "enginectl"},
    "core": {"omstate", "wsregistry", "vpndetect", "enginectl", "omsettings"},
    "corewatch": {"omstate", "enginectl"},
    "svclabels": set(),
}


def top_level_gitops_imports(path: Path) -> set:
    found = set()
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("gitops"):
            found.update([node.module.split(".")[1]] if "." in node.module else [a.name for a in node.names])
        elif isinstance(node, ast.Import):
            found.update(a.name.split(".")[1] for a in node.names if a.name.startswith("gitops."))
    return found


class TestLayering(unittest.TestCase):
    def test_modules_import_only_downward(self):
        for module, allowed in MAY_IMPORT.items():
            extra = top_level_gitops_imports(LIB / f"{module}.py") - allowed
            self.assertEqual(extra, set(), f"{module}.py imports {sorted(extra)} at the top; allowed: {sorted(allowed)}")

    def test_the_split_modules_are_small(self):
        for module in MAY_IMPORT:
            n = len((LIB / f"{module}.py").read_text(encoding="utf-8").splitlines())
            self.assertLess(n, 400, f"{module}.py has {n} lines")


if __name__ == "__main__":
    unittest.main()
