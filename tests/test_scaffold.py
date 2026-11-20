"""`om add` scaffolding (lib/gitops/scaffold.py): the compose files and project files it writes, and what it refuses.
Expected texts are those `om add` wrote before the code moved out of bin/om."""
import argparse
import tempfile
import unittest
from pathlib import Path

import _env  # noqa: F401

from gitops import scaffold

EXPECTED = {'pub': ({'desc': 'hello', 'icon': '🔥', 'name': 'pub', 'public': True}, {'services/pub/compose.yml': '# priority: 50\nservices:\n  pub:\n    image: docker.io/nginxinc/nginx-unprivileged:1.31-alpine\n    container_name: ${WORKSPACE_ID:-adds}_pub\n    restart: unless-stopped\n    security_opt:\n      - no-new-privileges:true\n    cap_drop:\n      - ALL\n    read_only: true\n    tmpfs:\n      - /tmp\n    labels:\n      - "workspace.id=${WORKSPACE_ID:-adds}"\n      - "dashboard.name=Pub"\n      - "dashboard.icon=🔥"\n      - "dashboard.description=hello"\n      - "dashboard.port=8080"\n      - "dashboard.domain=adds.pub.localhost"\n      - "dashboard.scope=public"\n      - "dashboard.web=true"\n      # Opt in when needed (om docs guide):\n      # - "om.egress=audit"     # permanent: all public egress allowed & logged, no expiry\n      # - "om.egress=learn"     # discovery: record what it uses, then apply with om egress log --apply\n      # - "om.net.allow=vpn"    # only the devices on your VPN allow-list\n      # - "om.log=off"          # leave no trace: no access or connection log, no output kept\n    expose:\n      - "8080"\n    networks:\n      - default\n\nnetworks:\n  default:\n    name: ${WORKSPACE_NET:-adds_net}\n    external: true\n'}), 'api': ({'image': 'ghcr.io/x/y:1', 'name': 'api', 'port': 9000}, {'services/api/compose.yml': '# priority: 50\nservices:\n  api:\n    image: ghcr.io/x/y:1\n    container_name: ${WORKSPACE_ID:-adds}_api\n    restart: unless-stopped\n    security_opt:\n      - no-new-privileges:true\n    # Most images start as root and switch to their own user, which needs these five;\n    # remove them if your image runs as non-root from the start.\n    cap_drop:\n      - ALL\n    cap_add:\n      - CHOWN\n      - DAC_OVERRIDE\n      - FOWNER\n      - SETGID\n      - SETUID\n    labels:\n      - "workspace.id=${WORKSPACE_ID:-adds}"\n      - "dashboard.name=Api"\n      - "dashboard.icon=📦"\n      - "dashboard.description=Self-hosted service: api"\n      - "dashboard.port=9000"\n      - "dashboard.domain=adds.api.localhost"\n      - "dashboard.scope=private"\n      - "dashboard.web=true"\n      # Opt in when needed (om docs guide):\n      # - "om.egress=audit"     # permanent: all public egress allowed & logged, no expiry\n      # - "om.egress=learn"     # discovery: record what it uses, then apply with om egress log --apply\n      # - "om.net.allow=vpn"    # only the devices on your VPN allow-list\n      # - "om.log=off"          # leave no trace: no access or connection log, no output kept\n    expose:\n      - "9000"\n    networks:\n      - default\n\nnetworks:\n  default:\n    name: ${WORKSPACE_NET:-adds_net}\n    external: true\n'}), 'My App': ({'name': 'My App', 'project': True}, {'projects/my-app/compose.yml': '# priority: 50\nservices:\n  my-app:\n    image: docker.io/library/node:24-alpine\n    container_name: ${WORKSPACE_ID:-adds}_my-app\n    restart: unless-stopped\n    working_dir: /app\n    command: ["node", "--watch", "server.js"]\n    environment:\n      - PORT=3000\n      - PROJECT_NAME=my-app\n    volumes:\n      - ./:/app:Z\n    security_opt:\n      - no-new-privileges:true\n    cap_drop:\n      - ALL\n    read_only: true\n    tmpfs:\n      - /tmp\n    labels:\n      - "workspace.id=${WORKSPACE_ID:-adds}"\n      - "dashboard.name=My-App"\n      - "dashboard.icon=⚡"\n      - "dashboard.description=Developer project: my-app"\n      - "dashboard.port=3000"\n      - "dashboard.domain=adds.my-app.localhost"\n      - "dashboard.scope=private"\n      - "dashboard.web=true"\n      # Opt in when needed (om docs guide):\n      # - "om.egress=audit"     # permanent: all public egress allowed & logged, no expiry\n      # - "om.egress=learn"     # discovery: record what it uses, then apply with om egress log --apply\n      # - "om.net.allow=vpn"    # only the devices on your VPN allow-list\n      # - "om.log=off"          # leave no trace: no access or connection log, no output kept\n    expose:\n      - "3000"\n    networks:\n      - default\n\nnetworks:\n  default:\n    name: ${WORKSPACE_NET:-adds_net}\n    external: true\n', 'projects/my-app/package.json': '{\n  "name": "my-app",\n  "private": true,\n  "scripts": {\n    "dev": "node --watch server.js"\n  }\n}\n', 'projects/my-app/server.js': '// Minimal dev server scaffolded by `om add --project`. Edit freely: `node --watch` restarts on save.\nconst http = require("http");\nconst port = Number(process.env.PORT || 3000);\nhttp.createServer((req, res) => {\n  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });\n  res.end(`<h1>${process.env.PROJECT_NAME} is running</h1><p>Edit server.js — it reloads automatically.</p>`);\n}).listen(port, () => console.log(`listening on :${port}`));\n'}), 'web': ({'name': 'web'}, {'services/web/compose.yml': '# priority: 50\nservices:\n  web:\n    image: docker.io/nginxinc/nginx-unprivileged:1.31-alpine\n    container_name: ${WORKSPACE_ID:-adds}_web\n    restart: unless-stopped\n    security_opt:\n      - no-new-privileges:true\n    cap_drop:\n      - ALL\n    read_only: true\n    tmpfs:\n      - /tmp\n    labels:\n      - "workspace.id=${WORKSPACE_ID:-adds}"\n      - "dashboard.name=Web"\n      - "dashboard.icon=📦"\n      - "dashboard.description=Self-hosted service: web"\n      - "dashboard.port=8080"\n      - "dashboard.domain=adds.web.localhost"\n      - "dashboard.scope=private"\n      - "dashboard.web=true"\n      # Opt in when needed (om docs guide):\n      # - "om.egress=audit"     # permanent: all public egress allowed & logged, no expiry\n      # - "om.egress=learn"     # discovery: record what it uses, then apply with om egress log --apply\n      # - "om.net.allow=vpn"    # only the devices on your VPN allow-list\n      # - "om.log=off"          # leave no trace: no access or connection log, no output kept\n    expose:\n      - "8080"\n    networks:\n      - default\n\nnetworks:\n  default:\n    name: ${WORKSPACE_NET:-adds_net}\n    external: true\n'})}


def args(**kw):
    base = {"name": "web", "project": False, "port": None, "image": None, "public": False, "domain": None, "icon": None,
            "desc": None, "no_web": False}
    return argparse.Namespace(**{**base, **kw})


class TestScaffold(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="om-scaf-"))

    def files(self, a):
        p = scaffold.plan(a, "adds", self.root)
        out = {"compose.yml": scaffold.render_compose(p), **scaffold.project_files(p)}
        return {f"{'projects' if p['is_project'] else 'services'}/{p['name']}/{n}": c for n, c in out.items()}

    def test_recorded_outputs(self):
        for name, (kw, expected) in EXPECTED.items():
            with self.subTest(name):
                self.assertEqual(self.files(args(**kw)), expected)

    def test_refusals(self):
        for kw, text in [({"name": "Bad_Name"}, "invalid name"), ({"name": "x", "image": "a b", "port": 1}, "invalid image"),
                         ({"name": "y", "icon": 'bad"icon'}, "--icon/--desc"), ({"name": "z", "domain": "bad domain"}, "invalid domain"),
                         ({"name": "w", "image": "ghcr.io/x/y:1"}, "also pass --port")]:
            with self.subTest(kw), self.assertRaisesRegex(ValueError, text):
                scaffold.plan(args(**kw), "adds", self.root)

    def test_existing_folder_is_refused(self):
        (self.root / "services" / "web").mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, "already exists"):
            scaffold.plan(args(), "adds", self.root)

    def test_defaults_are_least_privileged(self):
        text = self.files(args())["services/web/compose.yml"]
        for needle in ("cap_drop:\n      - ALL", "read_only: true", "no-new-privileges:true", "expose:"):
            self.assertIn(needle, text)
        self.assertNotIn("ports:", text)
        self.assertIn("cap_add:", self.files(args(name="c", image="img:1", port=80))["services/c/compose.yml"])


if __name__ == "__main__":
    unittest.main()
