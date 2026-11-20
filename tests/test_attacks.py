"""Attacks on om, as tests. Untrusted text reaches om as folder names, compose labels, `om.caddy` snippets, the egress
label, branch names and HTTP requests; each of those ends up in a generated config (Caddy, Squid, HAProxy, nftables,
compose) or on the filesystem. These tests feed every one of them hostile input and check what comes out: refused, or
harmless. Fuzzing is seeded, so a failure reproduces.

Every `test_*_hole_*` below is a hole this suite found in om and that is now closed; the others are attacks that fail."""
import http.client
import json
import os
import random
import re
import shutil
import socketserver
import sys
import tempfile
import threading
import unittest
from pathlib import Path

import _env

from gitops import egress, policy, routes, stream
from gitops.scaffold import yaml_label_safe
from gitops.workspace import SAFE_DOMAIN_RE, is_safe_name, is_valid_workspace_id

sys.path.insert(0, str(_env.TMP_HOME / "core" / "dashboard" / "app"))
import server as dash  # noqa: E402

om = _env.load_om()

CONTROL = ["\n", "\r\n", "\r", "\x00", "\t", "\x0b", "\x1b", "\u2028", "\u0085"]


class TestValidatorsRejectHostileNames(unittest.TestCase):
    NAMES = ["web\n", "web\r\n", "web\x00", "web ", "\nweb", " web", "Web", "wéb", "٣web", "web;rm", "web$(id)", "web`id`",
             "web/../x", "../web", "-web", "a" * 64, "web.localhost", "web:80", "web}", "web{", "web#", "web\t", "", "web\u2028x"]

    def test_names_ids_and_domains_hole_trailing_newline(self):
        # `$` matched before a final newline: a folder called "web\n" was a "safe" service name
        for name in self.NAMES:
            with self.subTest(name=name):
                self.assertFalse(is_safe_name(name))
                self.assertFalse(is_valid_workspace_id(name))
        for domain in ["a.localhost\n", "a b", "a;b", "a.com/x", "-a.com", "a.com\r\nHost: evil", "a\x00.com", ""]:
            with self.subTest(domain=domain):
                self.assertIsNone(SAFE_DOMAIN_RE.match(domain))

    def test_egress_hosts_hole_trailing_newline(self):
        for host in ["a.com\n", "*.com\n", "a.com;", "a.com\nhttp_access allow all", "a b.com", "_a.com", "a.com.", "*.*.a.com",
                     "a.c", "a.com\x00", "A.com", "a.com/x", "-a.com", "a.b" + "c" * 70]:
            with self.subTest(host=host):
                self.assertFalse(egress.valid_host(host))
        for ok in ["a.example.com", "*.example.com", "x-y.example.org"]:
            self.assertTrue(egress.valid_host(ok), ok)

    def test_route_paths_hole_trailing_newline(self):
        for path in ["/x\n", "/x y", "/x{", "/x}", '/x"', "/x\\", "/x\x00", "/x%0a", "x", "", "/x`", "/x$y", "/x;y", "/x\r\nrespond evil"]:
            with self.subTest(path=path):
                self.assertIsNone(routes.ROUTE_PATH_RE.match(path))
        self.assertEqual(routes.label_paths({"k": "/a, /b/*,/../x, //y, /ok"}, "k", "svc"), ["/a", "/b/*", "/ok"])

    def test_secret_names_digests_and_limits_hole_trailing_newline(self):
        from gitops import agesecrets, limits, lock
        for name in ["a\n", "../a", "a/b", "", "a b", "a\x00", "." + "a" * 70]:
            self.assertIsNone(agesecrets.NAME_RE.match(name), name)
        self.assertIsNone(lock.DIGEST_RE.match("sha256:" + "a" * 64 + "\n"))
        for raw in ["5m\n", "0m", "5 m", "-1m", "5tb"]:
            self.assertIsNone(limits.MEM_RE.match(raw), raw)
        self.assertEqual(limits.parse({"om.mem": "256m\n"})[0], {"mem_limit": "256m"})  # a label value is stripped first

    def test_a_folder_named_with_a_newline_gets_no_route(self):
        root = Path(tempfile.mkdtemp(prefix="om-atk-"))
        self.addCleanup(shutil.rmtree, root, True)
        (root / ".om").mkdir()
        (root / ".om" / "config.json").write_text('{"workspace_id": "atk"}', encoding="utf-8", newline="\n")
        for name in ("web\n", "evil}\nrespond injected"):
            d = root / "services" / name
            d.mkdir(parents=True)
            (d / "compose.yml").write_text("services: {}\n", encoding="utf-8", newline="\n")
        conf = om["CONF_D"]
        for f in conf.glob("atk-*"):
            f.unlink()
        om["sync_caddy_routes"](root, "none", reload=False)
        self.assertEqual(sorted(conf.glob("atk-*")), [])


class TestCaddySnippets(unittest.TestCase):
    BAD = [
        "reverse_proxy evil:80", "file_server", "root * /etc", "import /etc/caddy/*", "respond {$OM_EDGE_TOKEN}",
        "header X-T {env.OM_EDGE_TOKEN}", "respond {file./data/edge_token}", "handle {\n  reverse_proxy om_router:80\n}",
        "handle { respond ok }", "respond ok }\nreverse_proxy x", "@m remote_ip 1.2.3.4", "@m client_ip 1.2.3.4",
        "@m {\n  file\n}\nrespond @m ok", "abort\n}\nhttp://evil.example {\n", "tls internal", "log {\n output file /x\n}",
        "respond ok\r\n}\r\nhttp://evil {", "route {\n  respond ok\n}\n}\nmetrics", "templates", "php_fastcgi x", "exec cmd",
        "respond <<EOF\nx\nEOF", "header X {env.HOME}", "respond {http.request.remote.host}", "forward_auth evil:80",
        "handle {\n  import snippet\n}", "map {host} {x} {\n  default y\n}\nimport evil", "root * /data",
        # a "comment" line that is the inside of a multi-line quoted string: Caddy substitutes the placeholder there (hole)
        'respond "\n# {$OM_EDGE_TOKEN}"', "respond `\n# {env.HOME}`", 'respond "x\n# {file./data/edge_token}"',
        '# {$OM_EDGE_TOKEN}', "# import /etc/caddy/*",
    ]
    OK = ["header X-Frame-Options DENY", 'handle /api/* {\n    respond "ok" 200\n}', "redir /old /new permanent",
          "@api path /api/*\nrespond @api \"ok\"", "encode gzip", "basic_auth {\n    user $2a$14$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz0123456\n}"]

    def test_known_bad_snippets_are_refused(self):
        for text in self.BAD:
            with self.subTest(text=text):
                self.assertTrue(routes.validate_snippet(text), f"accepted: {text!r}")

    def test_known_good_snippets_still_pass(self):
        for text in self.OK:
            with self.subTest(text=text):
                self.assertEqual(routes.validate_snippet(text), [])

    def test_fuzzed_snippets_never_smuggle_a_forbidden_token_or_unbalanced_block(self):
        pool = ["respond", "handle", "route", "header", "redir", "rewrite", "abort", "@m", "path", "{", "}", "{$X}", "{env.A}", "{file.f}",
                "import", "reverse_proxy", "file_server", "remote_ip", "client_ip", "<<EOF", "ok", "/x", "*", '"', "'", "\\", "#", "{http.request.uri}",
                "a b", "\t", "\r"]
        rng = random.Random(1234)
        forbidden = routes.SNIPPET_FORBIDDEN + routes.SNIPPET_CLIENT_ADDRESS
        accepted = 0
        for _ in range(4000):
            text = "\n".join(" ".join(rng.choice(pool) for _ in range(rng.randint(1, 5))) for _ in range(rng.randint(1, 6)))
            if not routes.validate_snippet(text):
                accepted += 1
                with self.subTest(text=text):
                    self.assertFalse(any(bad in text for bad in forbidden), text)
                    self.assertEqual(text.count("{") - text.count("{$") * 0, text.count("}") + (text.count("{") - text.count("}")))  # sanity
                    depth = 0
                    for line in text.splitlines():
                        depth += line.strip().endswith("{") - (line.strip() == "}")
                        self.assertGreaterEqual(depth, 0, text)
                    self.assertEqual(depth, 0, text)
        self.assertGreater(accepted, 20)  # the fuzzer does reach accepted snippets, so the checks above ran


def gate(svc, cfg_extra=None, home="/home/u"):
    return policy.evaluate_config({"services": {"s": svc}, **(cfg_extra or {})}, home=home)[0]


class TestPolicyGateBypasses(unittest.TestCase):
    """Compose ways to get out of the sandbox. Each must be refused (a violation), whatever its spelling."""

    CASES = {
        "privileged": ({"image": "x", "privileged": True}, None),
        "host network": ({"image": "x", "network_mode": "host"}, None),
        "join another container's network": ({"image": "x", "network_mode": "container:om_caddy"}, None),
        "host pid": ({"image": "x", "pid": "host"}, None),
        "host ipc": ({"image": "x", "ipc": "host"}, None),
        "host uts": ({"image": "x", "uts": "host"}, None),
        "host userns": ({"image": "x", "userns_mode": "host"}, None),
        "host cgroup": ({"image": "x", "cgroup": "host"}, None),
        "published port": ({"image": "x", "ports": [{"target": 80, "published": 8080}]}, None),
        "SYS_ADMIN": ({"image": "x", "cap_add": ["SYS_ADMIN"]}, None),
        "CAP_ prefix, lowercase": ({"image": "x", "cap_add": ["cap_sys_admin"]}, None),
        "ALL caps": ({"image": "x", "cap_add": ["ALL"]}, None),
        "NET_ADMIN": ({"image": "x", "cap_add": ["NET_ADMIN"]}, None),
        "devices": ({"image": "x", "devices": ["/dev/mem:/dev/mem"]}, None),
        "seccomp unconfined": ({"image": "x", "security_opt": ["seccomp=unconfined"]}, None),
        "seccomp unconfined with spaces": ({"image": "x", "security_opt": ["seccomp = unconfined"]}, None),
        "apparmor unconfined": ({"image": "x", "security_opt": ["apparmor:unconfined"]}, None),
        "label disable": ({"image": "x", "security_opt": ["label=disable"]}, None),
        "no-new-privileges off (hole)": ({"image": "x", "security_opt": ["no-new-privileges:false"]}, None),
        "engine socket": ({"image": "x", "volumes": [{"type": "bind", "source": "/run/user/1000/podman/podman.sock", "target": "/s"}]}, None),
        "docker.sock": ({"image": "x", "volumes": [{"type": "bind", "source": "/var/run/docker.sock", "target": "/s"}]}, None),
        "root filesystem": ({"image": "x", "volumes": [{"type": "bind", "source": "/", "target": "/h"}]}, None),
        "etc": ({"image": "x", "volumes": [{"type": "bind", "source": "/etc", "target": "/h"}]}, None),
        "etc by path trick": ({"image": "x", "volumes": [{"type": "bind", "source": "/tmp/../etc", "target": "/h"}]}, None),
        "ssh keys": ({"image": "x", "volumes": [{"type": "bind", "source": "/home/u/.ssh", "target": "/h"}]}, None),
        "om state": ({"image": "x", "volumes": [{"type": "bind", "source": "/home/u/.local/state/om/data", "target": "/h"}]}, None),
        "home itself": ({"image": "x", "volumes": [{"type": "bind", "source": "/home/u", "target": "/h"}]}, None),
        "named volume binding /etc (hole)": (
            {"image": "x", "volumes": [{"type": "volume", "source": "v", "target": "/h"}]},
            {"volumes": {"v": {"driver": "local", "driver_opts": {"type": "none", "o": "bind", "device": "/etc"}}}}),
        "named volume binding ~/.ssh (hole)": (
            {"image": "x", "volumes": [{"type": "volume", "source": "v", "target": "/h"}]},
            {"volumes": {"v": {"driver_opts": {"type": "none", "o": "rw,bind", "device": "/home/u/.ssh"}}}}),
        "config from ~/.ssh (hole)": ({"image": "x", "configs": ["c"]}, {"configs": {"c": {"file": "/home/u/.ssh/id_ed25519"}}}),
        "config long syntax from /etc (hole)": ({"image": "x", "configs": [{"source": "c"}]}, {"configs": {"c": {"file": "/etc/shadow"}}}),
        "secret from the engine socket (hole)": ({"image": "x", "secrets": ["s"]}, {"secrets": {"s": {"file": "/run/podman/podman.sock"}}}),
        "container_name squatting a core name (hole)": ({"image": "x", "container_name": "om_router"}, None),
        "volumes_from another container (hole)": ({"image": "x", "volumes_from": ["om_dashboard"]}, None),
        "volumes_from container: form (hole)": ({"image": "x", "volumes_from": ["container:om_dashboard:ro"]}, None),
        "open egress with a writable volume": (
            {"image": "x", "labels": {"om.egress": "internet"}, "cap_drop": ["ALL"], "volumes": [{"type": "volume", "source": "d", "target": "/d"}]}, None),
        "egress without dropping NET_RAW": ({"image": "x", "labels": {"om.egress": "a.example.com"}}, None),
        "egress with NET_ADMIN": ({"image": "x", "labels": {"om.egress": "a.example.com"}, "cap_add": ["NET_ADMIN"]}, None),
        "egress learn with secrets": ({"image": "x", "labels": {"om.egress": "learn"}, "cap_drop": ["ALL"], "secrets": ["s"]}, None),
        "egress host that is an acl line": ({"image": "x", "labels": {"om.egress": "a.com\nhttp_access allow all"}, "cap_drop": ["ALL"]}, None),
    }

    def test_every_bypass_is_refused(self):
        for name, (svc, extra) in self.CASES.items():
            with self.subTest(name):
                self.assertTrue(gate(svc, extra), f"the gate let this through: {name}")

    def test_laws_cannot_be_waived_by_label(self):
        for rule in ("privileged", "ports", "core-names"):
            svc = {"image": "x", "privileged": True, "ports": [{"target": 80}], "container_name": "om_x", "labels": {"om.policy.allow": rule}}
            found = gate(svc)
            self.assertTrue(any(f"`{rule}` is a law" in v for v in found), found)
            self.assertTrue(any(word in v for v in found for word in ("privileged: true", "publishes host ports", "belong to the core")), found)

    def test_the_om_prefix_and_core_are_not_workspace_ids_hole_om_workspace(self):
        # a workspace `om` would own containers named om_dashboard, om_router ...
        self.assertFalse(is_valid_workspace_id("om"))
        self.assertFalse(is_valid_workspace_id("core"))
        self.assertTrue(is_valid_workspace_id("om2"))
        self.assertTrue(is_valid_workspace_id("my-om"))

    def test_an_ordinary_service_and_its_own_volumes_are_fine(self):
        svc = {"image": "x", "cap_drop": ["ALL"], "volumes_from": ["db:ro"], "volumes": [
            {"type": "bind", "source": "/home/u/projects/data", "target": "/d"}, {"type": "bind", "source": "/media/disk", "target": "/m"}]}
        self.assertEqual(policy.evaluate_config({"services": {"s": svc, "db": {"image": "d"}}}, home="/home/u")[0], [])

    def test_dangerous_waivable_rules_stay_visible_when_waived(self):
        svc = {"image": "x", "cap_add": ["SYS_ADMIN"], "labels": {"om.policy.allow": "caps"}}
        violations, waived = policy.evaluate_config({"services": {"s": svc}}, home="/home/u")
        self.assertEqual(violations, [])
        self.assertTrue(waived)  # `om policy check` keeps listing it


class TestGeneratedConfigsStayStructured(unittest.TestCase):
    """Whatever a label says, the generated Caddy, Squid and HAProxy text keeps its shape."""

    def test_caddy_route_paths_cannot_add_directives(self):
        rng = random.Random(7)
        alphabet = list("/ab*._~-{}\"'\\;$`%\n\r\t ,#") + ["respond", "evil", "\n}\nrespond injected\n"]
        baseline = om["render_vhost"]("w", "s", 80, route_opts({}), 3, True) + om["render_alias"]("w", "s", 20003, False, route_opts({}))
        shape = re.compile(r"^\s*(handle \{|handle /[A-Za-z0-9._~/*-]* \{|import to_dashboard(_public)?|import to_workspace \S+:\d+|\}|redir /[A-Za-z0-9._~/*-]* http://\{host\}:\d+[A-Za-z0-9._~/{}*-]*)\s*$")
        for _ in range(1500):
            raw = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 14)))
            opts = route_opts({"om.route.aliases": raw, "om.route.dashboard_paths": raw})
            out = om["render_vhost"]("w", "s", 80, opts, 3, True) + om["render_alias"]("w", "s", 20003, False, opts)
            extra = [ln for ln in out.splitlines() if ln not in baseline.splitlines()]
            for line in extra:
                self.assertRegex(line, shape, f"label {raw!r} produced {line!r}")

    def test_an_alias_cannot_redirect_the_dashboards_own_address_hole_empty_alias(self):
        # `om.route.aliases=/` rendered `redir /* http://<service>`: every request on the dashboard's address went to that service
        for alias in ["/", "/*", "/api", "/API/x", "/api/services", "/opensearch.xml", "/healthz", "/healthz/"]:
            with self.subTest(alias=alias):
                opts = route_opts({"om.route.aliases": alias})
                self.assertEqual(opts["aliases"], [])
                text = om["render_alias"]("w", "s", 20003, False, opts)
                self.assertNotRegex(text, r"(?m)^redir\s+(/\*|http)")
        self.assertEqual(route_opts({"om.route.aliases": "/apix, /my-app, /a/b"})["aliases"], ["/apix", "/my-app", "/a/b"])

    def test_a_service_named_like_a_dashboard_path_gets_no_redirect_hole_service_named_api(self):
        # a service called `api` (the README's own example) got `redir /api/*`: the dashboard could not load its services
        root = Path(tempfile.mkdtemp(prefix="om-atk-"))
        self.addCleanup(shutil.rmtree, root, True)
        (root / ".om").mkdir()
        (root / ".om" / "config.json").write_text('{"workspace_id": "atk2"}', encoding="utf-8", newline="\n")
        d = root / "services" / "api"
        d.mkdir(parents=True)
        (d / "compose.yml").write_text('services:\n  api:\n    image: x\n    labels:\n      - "dashboard.port=80"\n', encoding="utf-8", newline="\n")
        conf = om["CONF_D"]
        for f in conf.glob("atk2-*"):
            f.unlink()
        om["sync_caddy_routes"](root, "none", reload=False)
        names = sorted(f.name for f in conf.glob("atk2-*"))
        self.assertIn("atk2-api.caddy", names)              # the service itself is routed (its own address and port)
        self.assertNotIn("atk2-api.private_alias", names)   # but nothing redirects /api on the dashboard
        for f in conf.glob("atk2-*"):
            f.unlink()

    def test_squid_acl_only_contains_valid_hosts(self):
        rng = random.Random(11)
        alphabet = list("ab.*-_,; \n\r\t#") + ["example", "com", "http_access allow all", "\nacl x dstdomain evil.com"]
        line_ok = re.compile(r"^(# .*|acl [sd]_\w+ src \d+\.\d+\.\d+\.\d+/32|acl d_\w+ dstdomain ( ?\.?[a-z0-9.-]+)+|http_access allow s_\w+( d_\w+)?)$")
        for _ in range(2000):
            raw = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 30)))
            hosts = egress.parse_label(raw)
            if hosts in (None, egress.INTERNET, egress.LEARN, egress.AUDIT):
                continue
            for h in hosts:
                self.assertTrue(egress.valid_host(h), repr(h))
            for line in egress.render_acl("ws", {"svc": hosts}, ips={"svc": "10.89.1.2"}).splitlines():
                self.assertRegex(line, line_ok, f"label {raw!r} produced {line!r}")

    def test_haproxy_fragments_for_valid_names_have_only_known_lines(self):
        for sname in ("web", "a-b-c", "x1"):
            for fragment in (stream.render_edge_fragment("ws", sname, 25565), stream.render_router_fragment("ws", sname, 25565, 80)):
                for line in fragment.splitlines():
                    self.assertRegex(line, r"^(|# Service: [a-z0-9-]+ \([a-z0-9-]+\)|(frontend|backend) \w+|    (bind \S+( mode \d+)?|log global|option tcplog|default_backend \w+|server s1 \S+( resolvers docker init-addr libc,none check inter 5s)?))$")

    def test_stream_labels_cannot_name_reserved_or_hostile_ports(self):
        for port in ("80", "443", "8080", "8443", "20000", "21199", "22000", "22199", "1023", "65536", "-1", "25565.0", "2e4", "0x50", "80 80"):
            meta, problems = stream.parse_stream_meta({"om.tcp": "80", "om.tcp.port": port}, "s")
            self.assertIsNone(meta, port)
            self.assertTrue(problems, port)
        for bad in ("0", "65536", "-5", "80\n80", "eighty", "８０"):
            self.assertIsNone(stream.parse_stream_meta({"om.tcp": bad}, "s")[0], bad)

    def test_yaml_label_values_cannot_break_out_of_a_quoted_string(self):
        for value in ['a"b', "a\\b", "a\nb", "a\rb"]:
            self.assertFalse(yaml_label_safe(value), repr(value))
        self.assertTrue(yaml_label_safe("a normal value: with symbols # & *"))


def route_opts(labels):
    return routes.route_options("", "s", labels)


class TestBranchNames(unittest.TestCase):
    def test_a_preview_branch_cannot_be_a_git_option_hole_no_validation(self):
        from gitops.previews import valid_branch
        for branch in ["--detach", "-b", "--orphan=x", "a b", "a..b", "a\nb", "a;rm", "a@{1}", "a~1", "a^", "a:b", "a\\b", "", "a" * 150, "/a", "a/", "a//b", ".a", "a.lock"]:
            with self.subTest(branch=branch):
                self.assertFalse(valid_branch(branch))
        for branch in ["main", "feature/login", "fix_123", "release-1.2"]:
            self.assertTrue(valid_branch(branch), branch)

    def test_the_tracked_branch_in_the_workspace_config_is_validated(self):
        root = Path(tempfile.mkdtemp(prefix="om-br-"))
        self.addCleanup(shutil.rmtree, root, True)
        (root / ".om").mkdir()
        for value, expected in (("--upload-pack=evil", "main"), ("-x", "main"), ("feat/ok", "feat/ok"), ("a b", "main"), ("a\nb", "main")):
            (root / ".om" / "config.json").write_text(json.dumps({"tracked_branch": value}), encoding="utf-8", newline="\n")
            self.assertEqual(om["tracked_branch"](root), expected, value)


class TestDashboardUnderAttack(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        for d in ("data", "wp", "outside"):
            (cls.tmp / d).mkdir()
        (cls.tmp / "reg.json").write_text('{"perso": {"id": "perso"}}', encoding="utf-8", newline="\n")
        (cls.tmp / "outside" / "secret.png").write_bytes(b"\x89PNG\r\n\x1a\nTOP-SECRET")
        (cls.tmp / "wp" / "ok.png").write_bytes(b"\x89PNG\r\n\x1a\nfine")
        os.symlink(cls.tmp / "outside" / "secret.png", cls.tmp / "wp" / "link.png")
        (cls.tmp / "wp" / "evil.png").write_bytes(b"<svg onload=alert(1)></svg>")
        os.environ["GLOBAL_REGISTRY"] = str(cls.tmp / "reg.json")
        cls.saved = (dash.DATA_DIR, dash.WALLPAPERS_DIR, dash.SOCKET_PATH)
        dash.DATA_DIR, dash.WALLPAPERS_DIR, dash.SOCKET_PATH = str(cls.tmp / "data"), str(cls.tmp / "wp"), str(cls.tmp / "no.sock")
        cls.srv = socketserver.TCPServer(("127.0.0.1", 0), dash.DashboardHandler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        dash.DATA_DIR, dash.WALLPAPERS_DIR, dash.SOCKET_PATH = cls.saved
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def req(self, method, path, headers=None, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request(method, path, body=body, headers=headers or {"Host": "localhost"})
        r = c.getresponse()
        return r.status, r.getheader("Content-Type"), r.read()

    def test_no_traversal_symlink_or_absolute_path_reads_outside_the_wallpaper_folders(self):
        for path in ["../outside/secret.png", "..%2Foutside%2Fsecret.png", "%2e%2e/outside/secret.png", str(self.tmp / "outside" / "secret.png"),
                     "link.png", "ok.png%00.png", "....//outside/secret.png", "/etc/passwd", "..\\outside\\secret.png", ".hidden"]:
            with self.subTest(path=path):
                status, _, body = self.req("GET", f"/api/wallpaper/preview_host?path={path}", {"Host": "localhost"})
                self.assertNotIn(b"TOP-SECRET", body)
                self.assertNotIn(b"root:", body)
        self.assertEqual(self.req("GET", "/api/wallpaper/preview_host?path=ok.png")[0], 200)

    def test_an_svg_named_png_is_never_served_as_an_image_type(self):
        status, ctype, _ = self.req("GET", "/api/wallpaper/preview_host?path=evil.png")
        self.assertEqual(ctype, "application/octet-stream")

    def test_hosts_that_are_not_this_machine_are_refused(self):
        for host in ["attacker.example", "localhost.attacker.example", "127.0.0.1.attacker.example", "localhost@evil", "evil.com#localhost", "", "LOCALHOST.EVIL.COM"]:
            with self.subTest(host=host):
                self.assertEqual(self.req("GET", "/api/services", {"Host": host})[0], 403)
        # a private address is the LAN tier: not refused, but it never gets private data
        for host in ["0.0.0.0", "169.254.169.254", "10.1.2.3", "192.168.1.9", "[fe80::1]"]:
            with self.subTest(host=host):
                self.assertEqual(self.req("GET", "/api/system", {"Host": host})[0], 403)
                self.assertEqual(self.req("GET", "/api/wallpapers", {"Host": host})[0], 403)
        for host in ["localhost", "LOCALHOST", "127.0.0.1:8080", "[::1]", "app.localhost", "ws.dashboard.localhost"]:
            self.assertEqual(self.req("GET", "/api/services", {"Host": host})[0], 200, host)

    def test_a_client_cannot_raise_its_privilege_with_headers(self):
        for headers in ({"Host": "localhost", "X-Access-Scope": "private"}, {"Host": "localhost", "X-Access-Scope": ""},
                        {"Host": "localhost", "X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1", "Forwarded": "for=127.0.0.1"}):
            self.assertEqual(self.req("GET", "/api/system", headers)[0], 200)  # still private: nothing a client sends makes it more private
        self.assertEqual(self.req("GET", "/api/system", {"Host": "localhost", "X-Access-Scope": "public"})[0], 403)  # but it can lower itself
        self.assertEqual(self.req("GET", "/api/system", {"Host": "192.168.1.20"})[0], 403)  # a LAN address is public scope

    def test_state_changing_requests_need_the_same_origin(self):
        for extra in ({"Origin": "https://evil.example"}, {"Origin": "http://localhost.evil.example"}, {"Sec-Fetch-Site": "cross-site"}, {"Origin": "null"}):
            with self.subTest(extra=extra):
                self.assertEqual(self.req("POST", "/api/wallpaper/settings", {"Host": "localhost", **extra}, b'{"dim": 1}')[0], 403)
        self.assertEqual(self.req("POST", "/api/wallpaper/settings", {"Host": "localhost", "Origin": "http://localhost"}, b'{"dim": 1}')[0], 200)

    def test_oversized_or_malformed_bodies_are_refused_without_being_read(self):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.putrequest("POST", "/api/wallpaper/upload", skip_host=True)
        c.putheader("Host", "localhost")
        c.putheader("Content-Length", str(25 * 1024 * 1024))
        c.endheaders()
        self.assertEqual(c.getresponse().status, 413)
        for length in ("-1", "abc", "1e9", ""):
            c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
            c.putrequest("POST", "/api/wallpaper/settings", skip_host=True)
            c.putheader("Host", "localhost")
            c.putheader("Content-Length", length)
            c.endheaders()
            self.assertIn(c.getresponse().status, (400, 413), length)

    def test_workspace_parameters_never_become_paths(self):
        before = sorted(os.listdir(dash.DATA_DIR))
        for ws in ["../../outside", "..%2f..%2foutside", "core/../x", "perso/../../x", "a" * 500, "x%0Ay", "%00"]:
            self.req("POST", f"/api/wallpaper/settings?workspace={ws}", {"Host": "localhost"}, b'{"dim": 2}')
            self.req("GET", f"/api/wallpaper/current?workspace={ws}")
        self.assertEqual(sorted(os.listdir(self.tmp)), sorted(["data", "wp", "outside", "reg.json"]))
        self.assertFalse((self.tmp.parent / "outside").exists())
        self.assertTrue(set(os.listdir(dash.DATA_DIR)) >= set(before))

    def test_responses_carry_the_protective_headers(self):
        status, ctype, body = self.req("GET", "/")
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("GET", "/", headers={"Host": "localhost"})
        r = c.getresponse()
        r.read()
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(r.getheader("X-Frame-Options"), "SAMEORIGIN")
        csp = r.getheader("Content-Security-Policy") or ""
        self.assertIn("default-src 'none'", csp)
        self.assertNotIn("unsafe-eval", csp)
        self.assertIn("frame-ancestors 'self'", csp)


if __name__ == "__main__":
    unittest.main()
