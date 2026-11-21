"""The CI workflow keeps its supply-chain hygiene: every third-party action is pinned to a full commit SHA, the token
is read-only, every job has a timeout, secrets are scanned, and Dependabot keeps the pins current."""
import re
import unittest

import _env

WORKFLOW = (_env.REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")


def jobs() -> dict:
    body = WORKFLOW.split("\njobs:\n", 1)[1]
    blocks, name = {}, None
    for line in body.split("\n"):
        m = re.match(r"  ([a-z0-9-]+):\s*$", line)
        if m:
            name = m.group(1)
            blocks[name] = []
        elif name:
            blocks[name].append(line)
    return {k: "\n".join(v) for k, v in blocks.items()}


class TestCiHygiene(unittest.TestCase):
    def test_every_action_is_pinned_to_a_commit_sha_with_its_version(self):
        uses = re.findall(r"(?m)^\s*-?\s*uses:\s*(\S+)(.*)$", WORKFLOW)
        self.assertTrue(uses)
        for ref, rest in uses:
            self.assertRegex(ref, r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$", f"{ref} is not pinned to a full commit SHA")
            self.assertRegex(rest, r"#\s*v\d", f"{ref} has no version comment (Dependabot and readers need it)")

    def test_the_token_is_read_only_and_checkouts_keep_no_credentials(self):
        self.assertRegex(WORKFLOW, r"(?m)^permissions:\n  contents: read\n")
        self.assertNotIn("contents: write", WORKFLOW)
        self.assertEqual(WORKFLOW.count("persist-credentials: false"), WORKFLOW.count("actions/checkout@"))

    def test_every_job_has_a_timeout_and_secrets_are_scanned(self):
        blocks = jobs()
        for name, block in blocks.items():
            self.assertIn("timeout-minutes:", block, f"job {name} has no timeout")
        self.assertIn("gitleaks", blocks["secrets"])

    def test_the_coverage_floor_is_enforced_with_a_pinned_tool(self):
        self.assertRegex(WORKFLOW, r"pip install coverage==\d+\.\d+\.\d+")
        self.assertRegex(WORKFLOW, r"coverage report .*--fail-under=\d+")

    def test_dependabot_keeps_the_actions_current(self):
        text = (_env.REPO / ".github" / "dependabot.yml").read_text(encoding="utf-8")
        self.assertIn("package-ecosystem: github-actions", text)


if __name__ == "__main__":
    unittest.main()
