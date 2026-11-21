"""Seeded fuzzing of everything a user (or a compose file from someone else) can put in front of om's generated
configuration: names, hosts, route labels, `om.caddy` snippets, address rules, limits and settings. Each property
holds for thousands of hostile inputs: nothing raises, and nothing a validator rejects reaches a config file.

The seed is fixed, so a failure reproduces; change SEED (or ROUNDS) to look further."""
import contextlib
import io
import random
import re
import unittest

from _env import load_om

from gitops import egress, hostsetup, limits, omsettings, routes, settingscmd, workspace

SEED = 20261121
ROUNDS = 2500

ATOMS = ["a", "b", "web", "0", "9", "-", "_", ".", "/", "//", "..", "*", "~", "%2f", "%00", "$", "{", "}", "{$", "{env.", "{file.",
         "{uri}", "\n", "\r", "\t", "\x00", "\x1b", "‮", "／", "∕", "é", "٣", "\"", "'", "`", "\\", ";", "#", " ", "  ",
         "@", "import ", "respond ", "reverse_proxy ", "}\n", "{\n", "https://", "http://127.0.0.1", "ntfy.sh/", "example.org",
         "10.0.0.1", "/24", "::1", "vpn", "256m", "200", "0.5", ",", "|", "<<", "remote_ip", "OM_POLICY=warn"]
CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def hostile(rng: random.Random) -> str:
    if rng.random() < 0.05:
        return rng.choice(ATOMS) * rng.randint(50, 400)
    return "".join(rng.choice(ATOMS) for _ in range(rng.randint(1, 9)))


def mutate(rng: random.Random, good: str) -> str:
    """A known-good value with one hostile atom spliced in."""
    i = rng.randint(0, len(good))
    return good[:i] + rng.choice(ATOMS) + good[i:]


def cases(good, rounds=ROUNDS):
    rng = random.Random(SEED)
    for n in range(rounds):
        yield hostile(rng) if n % 2 else mutate(rng, rng.choice(good))


class TestNames(unittest.TestCase):
    def test_a_safe_name_is_only_lowercase_letters_digits_and_hyphens(self):
        for x in cases(["web", "my-app", "a1"]):
            if workspace.SAFE_NAME_RE.match(x):
                self.assertRegex(x, r"\A[a-z0-9][a-z0-9-]{0,62}\Z", repr(x))
            self.assertEqual(workspace.is_safe_name(x), bool(workspace.SAFE_NAME_RE.match(x)), repr(x))

    def test_a_safe_domain_is_only_letters_digits_dots_and_hyphens(self):
        for x in cases(["web.example.org", "a-b.localhost"]):
            if workspace.SAFE_DOMAIN_RE.match(x):
                self.assertRegex(x, r"\A[a-z0-9.-]+\Z", repr(x))


class TestEgressHosts(unittest.TestCase):
    def test_an_accepted_host_cannot_carry_proxy_config(self):
        for x in cases(["api.example.org", "*.example.org", "cdn.example.com"]):
            if egress.valid_host(x):
                self.assertRegex(x, r"\A(\*\.)?[a-z0-9.-]+\Z", repr(x))

    def test_parsing_the_label_never_raises_and_keeps_only_valid_hosts(self):
        rng = random.Random(SEED)
        for _ in range(ROUNDS):
            value = ",".join(hostile(rng) for _ in range(rng.randint(1, 4)))
            got = egress.parse_label(value)
            if isinstance(got, list):
                for host in got:
                    self.assertTrue(egress.valid_host(host), f"{host!r} from {value!r}")


class TestLimits(unittest.TestCase):
    def test_limits_are_numbers_or_refused(self):
        rng = random.Random(SEED)
        for _ in range(ROUNDS):
            labels = {"om.mem": hostile(rng), "om.pids": hostile(rng), "om.cpus": hostile(rng)}
            out, _problems = limits.parse(labels)
            if "mem_limit" in out:
                self.assertRegex(out["mem_limit"], r"\A\d+[kmg]\Z", repr(labels))
            if "pids_limit" in out:
                self.assertIsInstance(out["pids_limit"], int)
            if "cpus" in out:
                self.assertRegex(str(out["cpus"]), r"\A[0-9.]+\Z", repr(labels))


class TestAddressRules(unittest.TestCase):
    def test_only_addresses_ranges_and_the_vpn_word_survive_into_firewall_rules(self):
        rng = random.Random(SEED)
        for _ in range(ROUNDS):
            labels = {"om.net.allow": ",".join(hostile(rng) for _ in range(3)), "om.net.deny": hostile(rng)}
            net, _problems = routes.net_policy(labels, vpn_allow=["100.64.0.1"])
            for field in ("allow", "deny"):
                for item in (net or {}).get(field) or []:
                    self.assertRegex(item, r"\A(vpn|[0-9a-f:.]+/\d+)\Z", f"{item!r} from {labels!r}")
            if net:
                for forward in (False, True):
                    for line in hostsetup.nft_net_rules("ws/svc", {**net, "ports": [8080]}, forward):
                        self.assertFalse(CONTROL.search(line) or re.search(r"[;\\$`]", line), repr(line))


class TestRouteLabels(unittest.TestCase):
    def test_a_rejected_path_never_reaches_the_generated_caddyfile(self):
        rng = random.Random(SEED)
        for _ in range(ROUNDS // 2):
            alias, dpath = hostile(rng), hostile(rng)
            labels = {"om.route.aliases": alias, "om.route.dashboard_paths": dpath, "om.log": hostile(rng)}
            with contextlib.redirect_stdout(io.StringIO()):  # om says why it ignored each bad path
                opts = routes.route_options("", "svc", labels)
            for p in [*opts["aliases"], *opts["dashboard_paths"]]:
                self.assertRegex(p, routes.ROUTE_PATH_RE, f"{p!r} from {labels!r}")
            texts = [routes.render_vhost("ws", "svc", 8080, opts, 3, True), routes.render_alias("ws", "svc", 20003, False, opts)]
            for out in texts:
                self.assertEqual(out.count("{"), out.count("}"), f"unbalanced braces for {labels!r}")
                self.assertNotRegex(out, r"[\x00\x1b‮]")
            accepted = set(opts["aliases"]) | set(opts["dashboard_paths"])
            for raw in re.split(r"[,\s]+", f"{alias},{dpath}"):
                # text with a quote, backslash, `;` or control character that the validator refused must not appear at all
                if len(raw) >= 2 and raw not in accepted and re.search(r"[\"\\;\x00-\x1f]", raw):
                    for out in texts:
                        self.assertNotIn(raw, out, f"rejected {raw!r} was written to the config")


SNIPPET_BASE = ["header X-Frame-Options DENY\n", "respond /health 200\n", "redir /old /new 301\n", "@api path /api/*\nrespond @api 204\n"]


class TestCaddySnippets(unittest.TestCase):
    def test_validation_never_raises_on_anything(self):
        rng = random.Random(SEED)
        for _ in range(ROUNDS):
            text = "\n".join(hostile(rng) for _ in range(rng.randint(1, 6)))
            self.assertIsInstance(routes.validate_snippet(text), list)

    def test_a_forbidden_token_anywhere_makes_a_snippet_fail(self):
        rng = random.Random(SEED)
        for base in SNIPPET_BASE:
            self.assertEqual(routes.validate_snippet(base), [], f"the base snippet {base!r} must pass")
        for _ in range(ROUNDS):
            base = rng.choice(SNIPPET_BASE)
            token = rng.choice(routes.SNIPPET_FORBIDDEN + routes.SNIPPET_CLIENT_ADDRESS)
            line = rng.choice(["{t}", "# {t}", "  \t{t}  ", 'respond "{t}"', "header X {t}", 'respond "\n# {t}"'])
            lines = base.splitlines()
            lines.insert(rng.randint(0, len(lines)), line.format(t=token))
            text = "\n".join(lines) + "\n"
            self.assertTrue(routes.validate_snippet(text), f"accepted a snippet with {token!r}: {text!r}")

    def test_unbalanced_braces_fail(self):
        rng = random.Random(SEED)
        for _ in range(ROUNDS):
            base = rng.choice(SNIPPET_BASE)
            text = rng.choice([base + "}\n", "{\n" + base, base + "route {\n"])
            self.assertTrue(routes.validate_snippet(text), repr(text))


class TestSettings(unittest.TestCase):
    om = load_om()

    def test_an_accepted_setting_is_one_clean_line(self):
        rng = random.Random(SEED)
        good = {"OM_HTTP_PORT": "8080", "OM_POLICY": "warn", "OM_NOTIFY_URL": "https://ntfy.sh/topic", "OM_WALLPAPERS_DIR": "~/Pictures",
                "OM_TRUSTED_USERS": "alice", "OM_FIREWALL_EXTRA_TCP": "22,1714-1764", "OM_LAN_IP": "192.168.1.5", "OM_NOTIFY": "desktop"}
        for _ in range(ROUNDS):
            key = rng.choice(sorted(settingscmd.SCHEMA))
            value = mutate(rng, good.get(key, "x")) if rng.random() < 0.5 else hostile(rng)
            try:
                why = settingscmd.check_value(key, value)
            except Exception as e:  # a validator must refuse, never crash
                self.fail(f"{key}={value!r} raised {e!r}")
            if why is None:
                self.assertFalse(CONTROL.search(value), f"{key}={value!r} was accepted but would write more than one line to om.env")


class TestFoundByFuzzing(unittest.TestCase):
    """Plain examples of the two bugs this suite found, so a regression names itself."""

    def test_an_ipv6_scope_id_is_not_an_address_rule(self):
        net, problems = routes.net_policy({"om.net.allow": "fe80::1%eth0"}, vpn_allow=[])
        self.assertTrue(problems)                     # the label is reported, and callers fail closed on it
        self.assertNotIn("%", str(net))
        self.assertEqual(omsettings.vpn_allow({"OM_VPN_ALLOW": "fe80::1%eth0,10.0.0.1"}), ["10.0.0.1/32"])

    def test_a_setting_cannot_smuggle_in_a_second_line(self):
        self.assertIsNotNone(settingscmd.check_value("OM_WALLPAPERS_DIR", "a\nOM_POLICY=warn"))
        self.assertIsNotNone(settingscmd.check_value("OM_NOTIFY_URL", "https://ntfy.sh/x\nOM_POLICY=warn"))
        with self.assertRaises(ValueError):
            omsettings.set_setting("OM_POLICY", "enforce\nOM_SIGNED=warn")


if __name__ == "__main__":
    unittest.main()
