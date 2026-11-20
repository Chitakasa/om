"""The perimeter is built by several generators (Caddy routes, the port registries, the edge's published ports, the host
firewall, om exposure). A bug in one that the others do not notice quietly weakens the whole. This test builds random
workspaces (seeded) with random labels, runs the real route sync, renders everything, and checks what must hold across
the outputs, whatever the labels were:

  1. a service whose address rules the firewall does not carry has no port of its own and no redirects
  2. a service whose labels or `om.caddy` are refused has no route at all
  3. own ports are unique, inside their ranges, and each belongs to a registered slot
  4. an address policy only names ports of its own service
  5. a stream port with an address rule is published only when that rule is in the firewall
  6. the firewall has a drop rule for every port of every enforced address rule, and opens the public range only
  7. om exposure lists every routed service, and flags the rules that are not in the firewall"""
import contextlib
import io
import random
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _env

from gitops import exposure, hostsetup, omsettings, omstate, routes, wsregistry

om = _env.load_om()
CONF = om["CONF_D"]
PRIVATE = range(omstate.PRIVATE_PORT_BASE, omstate.PRIVATE_PORT_BASE + omstate.PORT_SLOTS)
PUBLIC = range(omstate.PUBLIC_PORT_BASE, omstate.PUBLIC_PORT_BASE + omstate.PORT_SLOTS)
NAMES = ["web", "api", "db", "x-1", "a-b", "cache", "docs", "app"]
GOOD_SNIPPET = 'header X-Frame-Options DENY\nhandle /health {\n    respond "ok" 200\n}\n'
BAD_SNIPPETS = ["reverse_proxy evil:80\n", 'respond "\n# {$OM_EDGE_TOKEN}"\n', "import /etc/caddy/*\n", "@m remote_ip 1.2.3.4\nrespond @m x\n"]
NET_ALLOW = [None, None, "100.64.0.9", "100.64.0.0/24, 192.168.1.0/24", "vpn", "garbage", "127.0.0.1/32", "10.0.0.0/8,notanip"]
NET_DENY = [None, None, None, "100.64.0.66", "bad", "fe80::/10"]
TCP = [None, None, None, ("25565", None), ("25565", "25570"), ("80", "443"), ("25565", "22005"), ("²", None), ("25565", "99999")]


def make_workspace(rng, tmp, ws):
    root = tmp / ws
    (root / ".om").mkdir(parents=True)
    (root / ".om" / "config.json").write_text(f'{{"workspace_id": "{ws}"}}', encoding="utf-8", newline="\n")
    spec = {}
    for name in rng.sample(NAMES, rng.randint(2, 5)):
        labels = [f"dashboard.port={rng.choice([80, 8080, 3000])}"]
        if rng.random() < 0.5:
            labels.append(f"dashboard.scope={rng.choice(['public', 'private'])}")
        for key, pool in (("om.net.allow", NET_ALLOW), ("om.net.deny", NET_DENY)):
            value = rng.choice(pool)
            if value:
                labels.append(f"{key}={value}")
        if rng.random() < 0.25:
            labels.append("om.log=off")
        tcp = rng.choice(TCP)
        if tcp:
            labels.append(f"om.tcp={tcp[0]}")
            if tcp[1]:
                labels.append(f"om.tcp.port={tcp[1]}")
        snippet = rng.choice([None, None, GOOD_SNIPPET, rng.choice(BAD_SNIPPETS)])
        d = root / "services" / name
        d.mkdir(parents=True)
        body = "".join(f'      - "{label}"\n' for label in labels)
        (d / "compose.yml").write_text(f"services:\n  {name}:\n    image: x\n    labels:\n{body}", encoding="utf-8", newline="\n")
        if snippet:
            (d / "om.caddy").write_text(snippet, encoding="utf-8", newline="\n")
        spec[name] = {"labels": labels, "snippet": snippet, "bad_snippet": snippet in BAD_SNIPPETS}
    return root, spec


def own_ports(text):
    return [int(p) for p in re.findall(r"(?m)^http://:(\d+) \{", text)]


class TestPerimeterConsistency(unittest.TestCase):
    def run_seed(self, seed):
        rng = random.Random(seed)
        ws = f"pc{seed}"
        tmp = Path(tempfile.mkdtemp(prefix="om-pc-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        root, spec = make_workspace(rng, tmp, ws)
        wsregistry.update_registry(lambda reg: reg.__setitem__(ws, {"id": ws, "path": str(root)}))  # om exposure walks the registry
        enforced = {}

        def net_policy_enforced(key, pol):
            return enforced.setdefault(key, rng.random() < 0.6)

        vpn_allow = ["100.64.0.9/32", "100.64.0.20/32"]
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(hostsetup, "net_policy_enforced", net_policy_enforced))
            stack.enter_context(mock.patch.object(omsettings, "vpn_allow", lambda *a, **k: vpn_allow))
            stack.enter_context(mock.patch.object(hostsetup, "vpn_allow", lambda: vpn_allow))
            stack.enter_context(mock.patch.object(hostsetup, "vpn_ips", lambda: ["100.64.0.1"]))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            om["sync_caddy_routes"](root, "none", reload=False)
            self.addCleanup(self.clean, ws)
            self.check(ws, spec, enforced, vpn_allow)
        return spec, enforced

    def clean(self, ws):
        for f in CONF.glob(f"{ws}-*"):
            f.unlink()
        wsregistry.release_slots(ws)
        wsregistry.update_registry(lambda reg: reg.pop(ws, None))

    def check(self, ws, spec, enforced, vpn_allow):
        files = {f.name: f.read_text(encoding="utf-8") for f in CONF.glob(f"{ws}-*")}
        slots = {k.split("/", 1)[1]: v for k, v in wsregistry.service_slots().items() if k.startswith(f"{ws}/")}
        policies = {k.split("/", 1)[1]: v for k, v in wsregistry.net_policies().items() if k.startswith(f"{ws}/")}
        streams = {k.split("/", 1)[1]: v for k, v in wsregistry.stream_ports().items() if k.startswith(f"{ws}/")}
        ctx = f"workspace {ws}, services {sorted(spec)}"

        # 2. refused labels or snippets: no route at all, web or TCP, and no port slot
        for name, s in spec.items():
            labels = dict(label.split("=", 1) for label in s["labels"])
            unreadable_rules = bool(routes.net_policy(labels, vpn_allow=vpn_allow)[1])
            if s["bad_snippet"] or unreadable_rules:
                why = "a refused om.caddy" if s["bad_snippet"] else f"unreadable address rules {labels.get('om.net.allow')!r}/{labels.get('om.net.deny')!r}"
                self.assertEqual([f for f in files if f.startswith(f"{ws}-{name}.")], [], f"{name} has {why} but a route; {ctx}")
                self.assertNotIn(name, streams, f"{name} has {why} but its TCP port is published; {ctx}")
                self.assertNotIn(name, slots, f"{name} has {why} but a port slot; {ctx}")

        # 1. address rules the firewall does not carry: no own port, no redirects
        for name in policies:
            if not enforced.get(f"{ws}/{name}", False) and f"{ws}-{name}.caddy" in files:
                self.assertEqual(own_ports(files[f"{ws}-{name}.caddy"]), [], f"{name}: rules not in the firewall but its own port is open; {ctx}")
                self.assertNotIn(f"{ws}-{name}.private_alias", files, f"{name}: redirect to a closed port; {ctx}")

        # 3. own ports: unique, in range, each a registered slot's port
        seen = {}
        for fname, text in files.items():
            for port in own_ports(text):
                name = fname[len(ws) + 1:].split(".")[0]
                self.assertTrue(port in PRIVATE or port in PUBLIC, f"{fname}: port {port} outside the ranges; {ctx}")
                slot = slots.get(name)
                self.assertIsNotNone(slot, f"{fname}: own port without a slot; {ctx}")
                self.assertIn(port, (omstate.PRIVATE_PORT_BASE + slot, omstate.PUBLIC_PORT_BASE + slot), f"{fname}: port {port} is not its slot's; {ctx}")
                self.assertNotIn(port, seen, f"port {port} used by {seen.get(port)} and {fname}; {ctx}")
                seen[port] = fname
        self.assertEqual(len(set(slots.values())), len(slots), f"two services share a slot; {ctx}")

        # 4. address policies name only their own service's ports
        for name, pol in policies.items():
            allowed = set()
            if name in slots:
                allowed |= {omstate.PRIVATE_PORT_BASE + slots[name], omstate.PUBLIC_PORT_BASE + slots[name]}
            if name in streams:
                allowed.add(streams[name]["host_port"])
            for port in pol["ports"]:
                self.assertIn(port, allowed, f"{name}: policy names port {port}, not one of its own; {ctx}")

        # 5. a stream port with an address rule is published only when the rule is in the firewall
        resolved = {"http_port": 80, "https_port": 443, "vpn_ips": ["100.64.0.1"], "lan_ip": "192.168.1.5", "vpn_private": True}
        with mock.patch.object(omsettings, "is_local_address", lambda ip: False):
            published = omsettings.render_ports(resolved).split("stream_edge:")[1]
        for name, info in streams.items():
            port = info["host_port"]
            in_default_range = omstate.STREAM_PORT_BASE <= port < omstate.STREAM_PORT_BASE + omstate.STREAM_PORT_SLOTS
            if name in policies and not in_default_range and not enforced.get(f"{ws}/{name}", False):
                self.assertNotIn(f":{port}:{port}", published, f"{name}: stream port {port} published without its address rule in the firewall; {ctx}")

        # 6. the firewall drops for every enforced rule's ports, and opens only the public range to everyone
        nft = hostsetup.render_nft([], [])
        for name, pol in policies.items():
            if enforced.get(f"{ws}/{name}", False):
                rendered = "\n".join(hostsetup.nft_net_rules(f"{ws}/{name}", pol))
                for port in pol["ports"]:
                    self.assertRegex(rendered, rf"dport \{{[^}}]*\b{port}\b[^}}]*\}} .*drop", f"{name}: no drop rule for port {port}; {ctx}")
        self.assertIn(f"tcp dport {omstate.PUBLIC_PORT_BASE}-{omstate.PUBLIC_PORT_BASE + omstate.PORT_SLOTS - 1} accept", nft)
        for line in nft.splitlines():
            if f"{omstate.PRIVATE_PORT_BASE}-" in line and "accept" in line:
                self.assertIn("ip daddr", line, f"the private range is open to everyone: {line.strip()}")

        # 7. om exposure lists every routed service and flags rules that are not in the firewall
        with mock.patch.object(exposure, "tiers", lambda: {"this_machine": {"you": True, "other_accounts": [], "trusted_accounts": []},
                                                            "vpn": {"trusted": ["tailscale0"], "addresses": ["100.64.0.1"], "allow_list": vpn_allow,
                                                                    "allow_list_enforced": True}, "lan": {"address": "192.168.1.5"}, "login": []}):
            data = exposure.exposure_data()
        listed = {s["service"]: s for s in data["services"] if s["workspace"] == ws}
        routed = {f[len(ws) + 1:].split(".")[0] for f in files if f.endswith(".caddy")} | set(streams)
        self.assertTrue(routed <= set(listed), f"exposure misses {sorted(routed - set(listed))}; {ctx}")
        for name, s in listed.items():
            if name in policies and not enforced.get(f"{ws}/{name}", False):
                self.assertTrue(any("NOT in the host firewall" in line for line in s["reachable_by"]), f"{name}: unenforced rule not flagged; {ctx}")

    def test_random_workspaces_keep_every_generator_in_agreement(self):
        tried_rules = tried_streams = 0
        for seed in range(60):
            with self.subTest(seed=seed):
                spec, enforced = self.run_seed(seed)
                tried_rules += len(enforced)
                tried_streams += sum(any(label.startswith("om.tcp=") for label in s["labels"]) for s in spec.values())
        self.assertGreater(tried_rules, 20)   # the random workspaces do exercise address rules...
        self.assertGreater(tried_streams, 10)  # ...and stream ports, so the checks above ran


if __name__ == "__main__":
    unittest.main()
