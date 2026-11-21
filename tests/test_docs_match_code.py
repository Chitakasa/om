"""The docs are checked against the code, so they cannot drift quietly: commands, settings, doctor checks, labels,
dashboard routes, modules and image pins that the code defines must be the ones the docs name."""
import argparse
import glob
import os
import re
import unittest
from pathlib import Path

import _env

from gitops import cliparser, doctor, omsettings

REPO = _env.REPO
DOCS = {f: Path(f).read_text(encoding="utf-8") for f in
        [str(REPO / "README.md"), str(REPO / "CLAUDE.md"), *map(str, (REPO / "docs").glob("*.md"))]}
ALL = "\n".join(DOCS.values())


def doc(name):
    return DOCS[str(REPO / name)]


class TestDocsMatchCode(unittest.TestCase):
    def test_doctor_check_count_is_the_one_in_the_docs(self):
        n = len(doctor.BASIC_CHECKS) + len(doctor.PERIMETER_CHECKS) + len(doctor.HOST_CHECKS)
        for name in ("README.md", "docs/ARCHITECTURE.md"):
            counts = {int(c) for c in re.findall(r"\((\d+) checks\)", doc(name))}
            self.assertEqual(counts, {n}, f"{name} names {counts} doctor checks, the code has {n}")

    def test_every_command_is_documented(self):
        sub = next(a for a in cliparser.build_parser()._actions if isinstance(a, argparse._SubParsersAction))
        readme = doc("README.md")
        for name in set(sub.choices) - {"script", "rm"}:  # `script` is an undocumented alias, `rm` is named with `remove`
            self.assertRegex(readme, rf"om {name}\b|`{name}\b|· `?om {name}\b", name)

    def test_every_setting_is_in_the_architecture_doc(self):
        for key in re.findall(r"(?m)^(OM_[A-Z_]+)=", omsettings.USER_ENV_TEMPLATE):
            self.assertTrue(key in doc("docs/ARCHITECTURE.md"), f"{key} is not in docs/ARCHITECTURE.md")

    def test_every_dashboard_route_is_in_the_architecture_doc(self):
        import sys
        sys.path.insert(0, str(_env.TMP_HOME / "core" / "dashboard" / "app"))
        import server
        for path in (*server.DashboardHandler.GET_ROUTES, *server.DashboardHandler.POST_ROUTES):
            self.assertTrue(path in doc("docs/ARCHITECTURE.md"), f"{path} is not in docs/ARCHITECTURE.md")

    def test_every_module_is_in_claude_md(self):
        for f in glob.glob(str(REPO / "lib" / "gitops" / "*.py")):
            module = os.path.basename(f)[:-3]
            if module != "__init__":
                self.assertTrue(f"{module}.py" in doc("CLAUDE.md"), f"CLAUDE.md does not name lib/gitops/{module}.py")

    def test_user_labels_the_code_reads_are_documented(self):
        # labels users put in compose files (the others are om's own bookkeeping labels on networks, or file names)
        for label in ("om.egress", "om.egress.learn_ttl", "om.egress.jvm", "om.net.allow", "om.net.deny", "om.link", "om.link.allow", "om.log",
                      "om.cli", "om.mem", "om.pids", "om.cpus", "om.update", "om.tcp", "om.tcp.port", "om.policy.allow", "om.network",
                      "om.route.keep_prefix", "om.route.aliases", "om.route.dashboard_paths", "dashboard.port", "dashboard.scope",
                      "dashboard.url", "dashboard.search_url", "workspace.category"):
            self.assertTrue(label in ALL, f"label {label} is in no doc")

    def test_core_images_in_compose_are_pinned_by_digest(self):
        compose = (REPO / "core" / "compose.yml").read_text(encoding="utf-8")
        for image in re.findall(r"image: (docker\.io/\S+)", compose):
            self.assertRegex(image, r":\S+@sha256:[0-9a-f]{64}$", image)
        self.assertNotRegex(compose, r"image: \S+:latest")

    def test_module_attributes_named_in_the_docs_exist(self):
        import importlib
        modules = {m: importlib.import_module(f"gitops.{m}") for m in
                   ("omstate", "wsregistry", "enginectl", "vpndetect", "omsettings", "migration", "core")}
        for name, text in DOCS.items():
            for module, attr in re.findall(r"`(omstate|wsregistry|enginectl|vpndetect|omsettings|migration|core)\.([A-Za-z_]\w*)", text):
                if attr != "py":
                    self.assertTrue(hasattr(modules[module], attr), f"{Path(name).name} names {module}.{attr}, which does not exist")


if __name__ == "__main__":
    unittest.main()
