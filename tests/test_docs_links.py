"""Links inside the docs must lead somewhere: the file exists and, for a #fragment, the heading exists
(GitHub's way of turning a heading into an anchor)."""
import re
import unicodedata
import unittest
from pathlib import Path
from urllib.parse import unquote

import _env

REPO = _env.REPO
FILES = [REPO / "README.md", REPO / "CONTRIBUTING.md", REPO / "SECURITY.md", REPO / "CODE_OF_CONDUCT.md", REPO / "CHANGELOG.md",
         *sorted((REPO / "docs").rglob("*.md"))]
LINK_RE = re.compile(r"(?<!\!)\[[^\]]*\]\(([^)\s]+)\)")


def slug(heading: str) -> str:
    """GitHub's anchor for a heading: lowercase, keep letters, marks, numbers, `_`, `-` and spaces, spaces become `-`."""
    kept = "".join(c for c in heading.strip().lower() if c in " -_" or unicodedata.category(c)[0] in "LMN")
    return kept.replace(" ", "-")


def anchors(path: Path) -> set:
    out, seen, in_code = set(), {}, False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("```"):
            in_code = not in_code
        m = None if in_code else re.match(r"#{1,6}\s+(.*?)\s*#*\s*$", line)
        if m:
            text = re.sub(r"`([^`]*)`", r"\1", re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", m.group(1)))
            base = slug(text)
            n = seen.get(base, 0)
            seen[base] = n + 1
            out.add(base if n == 0 else f"{base}-{n}")
    return out


class TestDocLinks(unittest.TestCase):
    def test_every_relative_link_and_anchor_resolves(self):
        bad = []
        for path in FILES:
            text = re.sub(r"(?s)```.*?```", "", path.read_text(encoding="utf-8"))
            for target in LINK_RE.findall(text):
                if re.match(r"[a-z][a-z0-9+.-]*:", target):
                    continue                                           # http(s), mailto, …
                name, _, frag = target.partition("#")
                dest = (path.parent / unquote(name)).resolve() if name else path
                if not dest.exists():
                    bad.append(f"{path.relative_to(REPO)}: {target} (no such file)")
                elif frag and dest.suffix == ".md" and unquote(frag).lower() not in anchors(dest):
                    bad.append(f"{path.relative_to(REPO)}: {target} (no such heading)")
        self.assertEqual(bad, [])

    def test_the_anchor_rule_matches_github(self):
        self.assertEqual(slug("🖥️ Supported Platforms"), "️-supported-platforms")
        self.assertEqual(slug("Tier 1 — Private (container ports)"), "tier-1--private-container-ports")


if __name__ == "__main__":
    unittest.main()
