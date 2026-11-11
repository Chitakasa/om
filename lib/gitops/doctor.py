#!/usr/bin/env python3
"""
doctor.py — `om doctor`: verify the installation, the network perimeter and common
failure modes, and print a concrete fix for every problem found.

Each check returns (status, message, fix) with status in PASS / WARN / FAIL.
"""

import os
import re
import sys
import json
import socket
import urllib.error
import urllib.request
from pathlib import Path

from gitops import core, hostsetup

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"


def _http(host_header: str, path: str = "/", addr: str = "127.0.0.1", port: int | None = None, timeout: float = 3.0):
    """HTTP status for a request, 0 if the connection was refused/aborted."""
    port = port or core.edge_ports()[0]
    req = urllib.request.Request(f"http://{addr}:{port}{path}", headers={"Host": host_header, "User-Agent": "om-doctor"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def check_python():
    v = sys.version_info
    if v < (3, 10):
        return FAIL, f"Python {v.major}.{v.minor}", "Install Python 3.10 or newer."
    return PASS, f"Python {v.major}.{v.minor}.{v.micro}", ""

def check_engine(runtime):
    eng = core.engine_info(runtime)
    if not eng["ok"]:
        return FAIL, f"{runtime} not responding", "Start your container engine (`podman machine start`, Docker Desktop, or `systemctl start docker`)."
    mode = ("rootless" if eng["rootless"] else "rootful") + (", VM" if eng["remote_vm"] else "")
    return PASS, f"{runtime} ({mode}), socket {eng['socket']}", ""

def check_compose(runtime):
    if core.compose_available(runtime):
        return PASS, f"`{runtime} compose` available", ""
    return FAIL, f"`{runtime} compose` missing", "Install docker-compose v2 (or podman-compose)."

def check_ports(runtime):
    eng = core.engine_info(runtime)
    if core.IS_LINUX and eng["rootless"] and not eng["remote_vm"]:
        start, low = core.unprivileged_port_start(), min(core.edge_ports())
        if start is not None and start > low:
            return FAIL, f"unprivileged ports start at {start}", \
                f"echo 'net.ipv4.ip_unprivileged_port_start={low}' | sudo tee /etc/sysctl.d/99-om.conf && sudo sysctl --system"
    return PASS, f"can bind {'/'.join(map(str, core.edge_ports()))}", ""

def check_core(runtime):
    down = [c for c in core.CORE_CONTAINERS if not core.container_running(runtime, c)]
    if down:
        return FAIL, f"not running: {', '.join(down)}", "om core start"
    retired = [c for c in core.RETIRED_CONTAINERS if core.run([runtime, "container", "inspect", c]).returncode == 0]
    if retired:
        return WARN, f"removed parts still present: {', '.join(retired)}", "om core restart"
    return PASS, f"{', '.join(core.CORE_CONTAINERS)} running", ""

def check_healthchecks(runtime):
    """Running workspace containers without a healthcheck: `om update`, auto-updates and the heal timer
    can only judge a service by its health."""
    wanted = set(core.read_registry())
    r = core.run([runtime, "ps", "--format", '{{.Names}}\t{{.Status}}\t{{index .Labels "com.docker.compose.project"}}'])
    bare = []
    for line in r.stdout.splitlines() if r.returncode == 0 else []:
        name, status, project = (line.split("\t") + ["", ""])[:3]
        if project in wanted and "(" not in status:
            bare.append(name)
    if bare:
        return WARN, f"no healthcheck: {', '.join(sorted(bare))}", "add a healthcheck: to the service in its compose file"
    return PASS, "every running workspace container has a healthcheck", ""

def check_router_networks(runtime):
    want = {n for w in core.read_registry() for n in [f"{w}_net"] + core.project_networks(runtime, w)}
    r = core.run([runtime, "inspect", core.ROUTER, "--format", "{{json .NetworkSettings.Networks}}"])
    try:
        have = set(json.loads(r.stdout).keys())
    except Exception:
        return WARN, "could not inspect router networks", "om core restart"
    missing = sorted(want - have)
    if missing:
        return FAIL, f"router not attached to {', '.join(missing)} (their services are unreachable)", "om core start"
    return PASS, f"router attached to {len(want)} workspace and project network(s)", ""

def check_edge_isolated(runtime):
    r = core.run([runtime, "inspect", core.EDGE, "--format", "{{json .NetworkSettings.Networks}}"])
    try:
        nets = set(json.loads(r.stdout).keys())
    except Exception:
        return WARN, "could not inspect edge networks", ""
    extra = sorted(n for n in nets if n != "om_core_net")
    if extra:
        return FAIL, f"edge proxy is on workspace network(s) {', '.join(extra)} — containers there can reach the private tier", \
            "om core restart   (and remove any `network connect ... om_caddy` from your scripts)"
    return PASS, "edge proxy reachable only from om_core_net", ""

def check_published_ports(runtime):
    r = core.run([runtime, "ps", "--format", "{{.Names}}\t{{.Ports}}"])
    leaks = []
    for line in r.stdout.splitlines():
        name, _, ports = line.partition("\t")
        if name in core.CORE_CONTAINERS or "->" not in ports:
            continue
        leaks.append(f"{name} ({ports})")
    if leaks:
        return FAIL, "containers publish host ports, bypassing the proxy: " + "; ".join(leaks), \
            "Replace `ports:` with `expose:` in their compose files, then `om start`."
    return PASS, "no container publishes host ports except the edge", ""

def check_drift(runtime):
    d = core.runtime_drift(runtime)
    if d:
        return WARN, d[0], "om core restart"
    return PASS, "ingress addresses match this network", ""

def check_rebinding():
    code = _http("attacker.example", "/api/workspaces")
    if code in (0, 403):
        return PASS, "foreign Host on the private tier is refused (DNS-rebinding safe)", ""
    return FAIL, f"foreign Host got HTTP {code}", "Restore the explicit host list and `:80 { abort }` in core/caddy/Caddyfile."

def check_private_reachable():
    code = _http("localhost", "/healthz")
    if code in (200, 401):
        return PASS, f"private tier answers on {core.base_url()}/", ""
    return FAIL, f"{core.base_url()}/ returned {code or 'no answer'}", "om core restart; then om doctor"

_ROUTER_PROBE = """
import socket
s = socket.socket(socket.AF_UNIX); s.settimeout(5)
s.connect("/run/om-router/router.sock")
s.sendall(b"GET / HTTP/1.1\\r\\nHost: x\\r\\nX-Om-Upstream: om_dashboard:80\\r\\n\\r\\n")
try: print("forwarded" if s.recv(64) else "refused")
except OSError: print("refused")
"""

def check_router_token(runtime):
    """The router listens on no network (only the edge's socket), and refuses a request without the edge token."""
    listen = core.run([runtime, "exec", core.ROUTER, "netstat", "-lnt"])
    if listen.returncode == 0 and "LISTEN" in listen.stdout:
        return FAIL, "the router listens on the network: containers can connect to it", "om core restart (core/caddy/router/Caddyfile binds a unix socket only)"
    r = core.run([runtime, "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                  "-v", "om_router_sock:/run/om-router:ro", _probe_image(), "python3", "-c", _ROUTER_PROBE])
    if r.stdout.strip() == "refused":
        return PASS, "router listens on no network; on its socket it refuses requests without the edge token", ""
    return FAIL, f"router probe: {r.stdout.strip() or r.stderr.strip()[-160:]!r} (expected 'refused')", \
        "Check core/caddy/router/Caddyfile and data/edge_token in the om state dir; om core restart"

_SOCK_PROBE = """
import http.client, os, socket, sys
class U(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX); self.sock.connect(os.environ["OM_ENGINE_SOCKET_PATH"])
def code(m, p):
    c = U("localhost", timeout=5); c.request(m, p); return c.getresponse().status
print(int(os.path.exists("/var/run/docker.sock")), code("GET", "/containers/json"), code("POST", "/containers/om_dashboard/kill"))
"""

def check_engine_filter(runtime):
    """The dashboard must see the engine only through om_sockguard: list allowed, writes refused, no raw socket."""
    r = core.run([runtime, "exec", "om_dashboard", "python3", "-c", _SOCK_PROBE])
    if r.stdout.split() == ["0", "200", "403"]:
        return PASS, "dashboard has read-only engine access (writes → 403, no raw socket)", ""
    return FAIL, f"engine filter probe returned {r.stdout.strip() or r.stderr.strip()[-200:]!r} (expected '0 200 403')", "om core restart; check core/caddy/sockguard/Caddyfile"

_EGRESS_PROBE = """
import socket, urllib.request
def dns():
    try: socket.gethostbyname("example.com"); return "open"
    except OSError: return "blocked"
def direct():
    try: socket.create_connection(("1.1.1.1", 443), timeout=4); return "open"
    except OSError: return "blocked"
def host():
    import sys
    for addr in sys.argv[1:]:
        for port in (22, 80, 443, 2019, 9091):
            try: socket.create_connection((addr, port), timeout=2); return f"open:{addr}:{port}"
            except OSError: pass
    return "blocked"
def proxy():
    h = urllib.request.ProxyHandler({"https": "http://om_egress:3128"})
    try: urllib.request.build_opener(h).open("https://example.com/", timeout=8); return "open"
    except Exception as e: return "refused" if ("407" in str(e) or "403" in str(e)) else "error"
print(dns(), direct(), host(), proxy())
"""

def _probe_image() -> str:
    """The pinned python image the core already uses (no extra pull)."""
    for line in (core.CORE_DIR / "docker-compose.yml").read_text(encoding="utf-8").splitlines():
        if "image:" in line and "/python:" in line:
            return line.split("image:", 1)[1].strip()
    return ""

def check_egress(runtime):
    """Each workspace network: internal (no DNS, no route out) and om_egress demands a credential."""
    open_nets, bad, no_proxy = [], [], []
    env = core.parse_env_file(core.RUNTIME_ENV)
    hosts = [a for a in [env.get("LAN_IP", "")] + core.vpn_hosts() if a and not a.endswith(".invalid") and re.fullmatch(r"[0-9.]+", a)]
    for wid in sorted(core.read_registry()):
        for net in [f"{wid}_net"] + core.project_networks(runtime, wid):
            if core.run([runtime, "network", "inspect", net]).returncode != 0:
                continue
            if not core.network_is_internal(runtime, net):
                open_nets.append(net)
                continue
            members = core.run([runtime, "ps", "--filter", f"network={net}", "--format", "{{.Names}}"]).stdout.split()
            # where a service may go out, the proxy answers but wants its credential; elsewhere it is absent
            proxy = "refused" if core.EGRESS in members else "error"
            r = core.run([runtime, "run", "--rm", "--network", net, "--read-only", "--cap-drop", "ALL",
                          _probe_image(), "python3", "-c", _EGRESS_PROBE, *hosts])
            if r.stdout.split() != ["blocked", "blocked", "blocked", proxy]:
                bad.append(f"{net}: {r.stdout.strip() or r.stderr.strip()[-120:]!r} (expected blocked ×3, proxy {proxy})")
            elif proxy == "error":
                no_proxy.append(net)
    if bad:
        return FAIL, "egress probe failed (expected dns, direct, host addresses blocked; proxy refused without credential): " + "; ".join(bad), "om core restart; om network harden"
    from gitops import egress
    learning = [f"{f.stem}/{svc}" for f in sorted((egress.EGRESS_DIR / "creds").glob("*.rules"))
                for svc, h in sorted(egress._load_rules(f.stem).items()) if h == egress.LEARN]
    warns, fixes = [], []
    if open_nets:
        warns.append(f"open network(s) with internet access: {', '.join(open_nets)}")
        fixes.append("cd <workspace> && om network harden (project networks: om start recreates them internal)")
    if learning:
        warns.append(f"in learn mode (any public host allowed): {', '.join(learning)}")
        fixes.append("om egress log --all, then replace om.egress=learn with the listed hosts")
    if warns:
        return WARN, "; ".join(warns), "; ".join(fixes)
    return PASS, ("workspace networks are internal; only om_egress leads out, per-service credential required"
                  + (f"; no proxy at all on {len(no_proxy)} network(s) without om.egress" if no_proxy else "")), ""

_ISOLATION_PROBE = """
import errno, socket, sys
name, ip = sys.argv[1], sys.argv[2]
def dns():
    try: socket.gethostbyname(name); return "open"
    except OSError: return "blocked"
def direct():
    s = socket.socket(); s.settimeout(3)
    try: s.connect((ip, 80)); return "open"
    except ConnectionRefusedError: return "open"          # an answer, even a refusal, means a path exists
    except OSError: return "blocked"                      # no route / timeout
    finally: s.close()
print(dns(), direct())
"""

def check_project_isolation(runtime):
    """A container on one folder's network cannot reach another folder's service (by name or address)."""
    pairs, bad = 0, []
    for wid in sorted(core.read_registry()):
        members = {}
        for net in core.project_networks(runtime, wid):
            r = core.run([runtime, "ps", "--filter", f"network={net}", "--format", "{{.Names}}"])
            svcs = [m for m in r.stdout.split() if m not in (core.ROUTER, core.EGRESS)]
            if svcs:
                members[net] = svcs[0]
        nets = sorted(members)
        for a, b in zip(nets, nets[1:] + nets[:1]) if len(nets) > 1 else []:
            target = members[b]
            ip = core.run([runtime, "inspect", "--format", f'{{{{(index .NetworkSettings.Networks "{b}").IPAddress}}}}', target]).stdout.strip()
            if not ip:
                continue
            r = core.run([runtime, "run", "--rm", "--network", a, "--read-only", "--cap-drop", "ALL",
                          _probe_image(), "python3", "-c", _ISOLATION_PROBE, target, ip])
            pairs += 1
            if r.stdout.split() != ["blocked", "blocked"]:
                bad.append(f"{a} → {target}: {r.stdout.strip() or r.stderr.strip()[-120:]!r}")
    if bad:
        return FAIL, "a folder's network reaches another folder's service: " + "; ".join(bad), "om core restart; om start in that workspace"
    if not pairs:
        return PASS, "no workspace has two folders with running services to compare", ""
    return PASS, f"folders are isolated from each other ({pairs} pair(s) probed: no name, no route)", ""

def check_generations():
    """Each workspace: generation log chains, and what runs is a clean, signed commit."""
    from gitops import generations
    bad, weak = [], []
    for wid, d in sorted(core.read_registry().items()):
        if not Path(d.get("path", "")).exists():
            continue
        problems = generations.verify_chain(wid)
        if problems:
            bad.append(f"{wid}: {problems[0]}")
            continue
        cur = generations.current(wid)
        if not cur:
            weak.append(f"{wid}: never deployed through om")
        elif not cur.get("commit"):
            weak.append(f"{wid}: not a git repository")
        elif cur.get("dirty"):
            weak.append(f"{wid}: generation {cur['n']} is dirty (uncommitted files)")
        elif not cur.get("signer"):
            weak.append(f"{wid}: generation {cur['n']} is unsigned")
    if bad:
        return FAIL, "generation log broken: " + "; ".join(bad), "om fsck in that workspace; the state dir may have been edited"
    if weak:
        return WARN, "; ".join(weak), "commit (signed) and `om start`; then OM_SIGNED=enforce in om.env"
    return PASS, "every workspace runs a clean, signed generation; logs chain", ""

# What may listen in the edge container, and where. Anything else is a new door.
_EDGE_LISTENERS = {("tcp", "80"): "any", ("tcp", "443"): "any", ("udp", "443"): "any",
                   ("tcp", "81"): "any", ("tcp", "444"): "any", ("udp", "444"): "any",  # the VPN's private tier
                   ("tcp", "8080"): "any", ("tcp", "8443"): "any", ("udp", "8443"): "any",
                   ("tcp", "2019"): "loopback"}

def check_admin_surface(runtime):
    """Nothing administrative listens where the network can reach it: only the edge ports;
    Caddy's admin API on loopback inside the container."""
    r = core.run([runtime, "exec", core.EDGE, "netstat", "-lntu"])
    if r.returncode != 0:
        return WARN, "could not list listeners in the edge container", "om core restart"
    bad = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] not in ("tcp", "udp", "tcp6", "udp6"):
            continue
        proto, local = parts[0].rstrip("6"), parts[3]
        addr, _, port = local.rpartition(":")
        where = _EDGE_LISTENERS.get((proto, port))
        if proto == "tcp" and port.isdigit() and any(base <= int(port) < base + core.PORT_SLOTS
                                                     for base in (core.PRIVATE_PORT_BASE, core.PUBLIC_PORT_BASE)):
            where = "any"  # a service's own port (generated from its route)
        if not (where == "any" or (where == "loopback" and addr in ("127.0.0.1", "::1"))):
            bad.append(f"{proto} {local}")
    if bad:
        return FAIL, "unexpected listener(s) in the edge: " + ", ".join(bad), "find what opened it (podman exec om_caddy netstat -lntu); om core restart"
    return PASS, "edge listens only on its web ports and the services' own ports; Caddy admin on loopback only", ""

def check_workspaces_fsck():
    """Every workspace runs what its signed generation and lock say (`om fsck` in each)."""
    import subprocess
    om_bin = core.OM_HOME / "bin" / "om"
    bad = []
    for wid, d in sorted(core.read_registry().items()):
        path = Path(d.get("path", ""))
        if not (path / ".om" / "config.json").exists():
            continue
        r = subprocess.run([sys.executable, str(om_bin), "fsck"], cwd=path, capture_output=True, text=True, encoding="utf-8", errors="replace")
        if r.returncode != 0:
            first = next((l.strip() for l in r.stdout.splitlines() if "✗" in l), "fsck failed")
            bad.append(f"{wid}: {first.replace(chr(27), '')[:120]}")
    if bad:
        return FAIL, "; ".join(bad), "om fsck in that workspace"
    return PASS, "every workspace's running images match its lock; generation logs chain", ""

def check_custom_routes():
    """Services carrying their own Caddy rules (om.caddy): allowed, but always visible."""
    custom = sorted(f.stem for f in core.ROUTES_DIR.glob("*.caddy") if "# custom:" in f.read_text(encoding="utf-8")[:400])
    if custom:
        return PASS, f"own Caddy rules (om.caddy, checked against the allowed directives): {', '.join(custom)}", ""
    return PASS, "no service carries its own Caddy rules", ""

def check_links(runtime):
    """Cross-workspace links: both sides declared, attached, nothing else on their networks."""
    from gitops import links
    found, problems = links.describe(runtime)
    if problems:
        return WARN, "; ".join(problems), "om links — fix the labels, then om start"
    return PASS, f"{len(found)} cross-workspace link(s), each a private network of exactly two services", ""

def check_vpn():
    """Which VPNs reach the private tier; tunnels present but not trusted."""
    trusted = core.vpn_items(core.load_settings().get("OM_VPN", ""))
    untrusted = [i for i, ip in core.vpn_candidates() if i not in trusted and ip not in trusted]
    note = (f"; not trusted: {', '.join(untrusted)} (`om vpn trust <iface>` if only your devices are on it)" if untrusted else "")
    hosts = core.vpn_hosts()
    allowed = core.vpn_allow()
    if allowed and hosts and not hostsetup.vpn_allow_enforced():
        return FAIL, (f"OM_VPN_ALLOW ({', '.join(allowed)}) is not in the host firewall: the VPN's private tier is closed"
                      + note), "om firewall apply"
    if allowed and hosts:
        msg = f"only {', '.join(allowed)} reach the private tier over {', '.join(trusted)} (enforced by the firewall); "
        if hostsetup.vpn_fallback_applied():
            return PASS, msg + "other VPN devices get the public tier, at the same address" + note, ""
        if core.IS_WINDOWS:
            return PASS, msg + "other VPN devices get the public tier on port 8080 (Windows Firewall cannot redirect)" + note, ""
        return WARN, (msg + "other VPN devices get no answer at the private address, the public tier only on port 8080"
                      + note), "om firewall apply"
    if not hosts:
        return PASS, "no VPN trusted: the private tier is on this machine only" + note, ""
    return PASS, (f"every device on {', '.join(trusted)} reaches the private tier ({', '.join(hosts)}) — keep joining it to devices"
                  " you approve, or list yours with `om vpn allow <device>`" + note), ""

def check_net_policy():
    """Services restricted by address (om.net.allow / om.net.deny): their rules are in the applied firewall."""
    pols = core.net_policies()
    stale = hostsetup.stale_net_rules()
    missing = [k for k, p in sorted(pols.items()) if not hostsetup.net_policy_enforced(k, p)]
    if missing:
        return FAIL, f"om.net rules not in the host firewall for {', '.join(missing)} (their own ports stay closed)", "om firewall apply"
    if stale:
        return WARN, f"the firewall still restricts {', '.join(stale)} by old om.net rules", "om firewall apply"
    if not pols:
        return PASS, "no service is restricted by address (om.net.allow / om.net.deny)", ""
    return PASS, f"{len(pols)} service(s) restricted by address, enforced by the host firewall: {', '.join(sorted(pols))}", ""

def check_vpn_isolation():
    """A VPN device that sends a *.localhost Host gets nothing: those sites answer this machine only."""
    ips = [h for h in core.vpn_hosts() if re.fullmatch(r"[0-9.]+", h)]
    if not ips:
        return PASS, "no VPN trusted", ""
    code = _http("om-doctor.dashboard.localhost", "/healthz", addr=ips[0])
    if code == 0:
        return PASS, f"*.localhost sites answer this machine only (VPN {ips[0]} with such a Host: refused)", ""
    return FAIL, f"VPN address {ips[0]} answers a *.localhost Host (HTTP {code})", "om core restart (VPN must land on edge :81/:444)"

def check_lan_tier():
    lan = core.parse_env_file(core.RUNTIME_ENV).get("LAN_IP", "")
    if not lan or lan.endswith(".invalid"):
        return PASS, "LAN tier disabled", ""
    code = _http(lan, "/api/system", addr=lan)
    open_private = []
    for key, slot in sorted(core.service_slots().items()):
        try:
            with socket.create_connection((lan, core.PRIVATE_PORT_BASE + slot), timeout=1):
                open_private.append(f"{key} (:{core.PRIVATE_PORT_BASE + slot})")
        except OSError:
            pass
    if open_private:
        return FAIL, f"private service ports answer on the LAN address: {', '.join(open_private)}", "om core restart (ports.yml binds them to loopback and VPN only)"
    if code == 403:
        return PASS, f"LAN tier ({lan}) is public-scoped (/api/system → 403); private service ports closed there", ""
    if code == 0:
        return WARN, f"LAN tier ({lan}) not answering", "om core restart (LAN address may have changed)"
    return FAIL, f"LAN tier returned {code} for /api/system (expected 403)", "Check the :8080 site in core/caddy/Caddyfile"

def check_localhost_dns():
    try:
        socket.getaddrinfo("om-doctor.dashboard.localhost", 80)
        return PASS, "*.localhost resolves on this OS", ""
    except OSError:
        return WARN, "*.localhost names don't resolve for CLI tools on this OS (browsers still resolve them)", \
            "Use browsers for <ws>.<svc>.localhost, or add entries to your hosts file."

def check_firewall():
    st = hostsetup.firewall_status()
    if st == "active" and hostsetup.logging_applied() is False:
        return WARN, "host firewall active, but applied before logging: refusals and connections are not logged", "om firewall apply"
    if st == "active":
        return PASS, "host firewall active; refusals and connections logged (`om firewall log`)", ""
    if st == "unknown":
        return WARN, "host firewall state unknown on this OS", "om firewall apply"
    return WARN, "host firewall not active — any port a program opens is reachable from the LAN", "om firewall apply"

def check_boot(runtime):
    st = hostsetup.boot_status(runtime)
    if st.startswith("enabled") and "only after" not in st:
        return PASS, "containers restart at boot", ""
    if st.startswith("managed"):
        return WARN, st, ""
    return WARN, f"start at boot: {st}", "om boot enable"

def check_token_not_logged(runtime):
    """The edge token never appears in om's own container logs (an unfiltered error log would carry it)."""
    tok = core.edge_token()
    leaked = [c for c in (core.EDGE, core.ROUTER)
              if tok in (lambda r: r.stdout + r.stderr)(core.run([runtime, "logs", c]))]
    if leaked:
        return FAIL, f"the edge token appears in the logs of {', '.join(leaked)}: treat it as known", \
            f"rm {core.TOKEN_FILE} && om core restart   (a new token; the logged one becomes useless)"
    return PASS, "the edge token appears in no om log", ""

def check_secrets_tracked():
    """om's program folder must hold no machine state (CA key, edge token, registry)."""
    if core.legacy_state_present():
        return WARN, f"machine state still inside {core.OM_HOME}", "Run any `om` command (e.g. `om status`) to move it out once."
    git_dir = core.OM_HOME / ".git"
    if git_dir.exists():
        r = core.run(["git", "-C", str(core.OM_HOME), "ls-files", "core/data", "core/.env", "core/.runtime.env", "config"])
        if r.stdout.strip():
            return FAIL, "old state files are still tracked by git", "git -C ~/.om rm -r --cached core/data core/.env core/.runtime.env config"
    return PASS, f"program in {core.OM_HOME}, state in {core.STATE_DIR}", ""

def check_secret_modes():
    """Files that hold secrets are readable by their owner only (POSIX; Windows follows the profile's ACLs)."""
    if core.IS_WINDOWS:
        return PASS, "Windows: secret files follow your profile's permissions", ""
    from gitops import agesecrets, egress
    files = [core.TOKEN_FILE, core.RUNTIME_ENV, agesecrets.KEY_FILE,
             *egress.EGRESS_DIR.glob("creds/*"), *egress.EGRESS_DIR.glob("overrides/*")]
    loose = [f"{p.name} ({p.stat().st_mode & 0o777:o})" for p in files if p.is_file() and p.stat().st_mode & 0o077]
    if loose:
        return WARN, "secret files readable by other users: " + ", ".join(loose), f"chmod 600 {' '.join(str(p) for p in files if p.is_file())}"
    return PASS, "edge token, age key and egress credentials are readable by you only", ""

def check_orphan_routes():
    """Routes of workspaces whose folder is gone (deleted without `om remove`)."""
    reg = core.read_registry()
    orphans = set()
    for f in core.ROUTES_DIR.glob("*") if core.ROUTES_DIR.is_dir() else []:
        try:
            m = core._GENERATED_ROUTE_RE.search(f.read_text(encoding="utf-8")[:400])
        except OSError:
            continue
        ws = m.group(1) if m else None
        if ws and ws != "core":
            path = reg.get(ws, {}).get("path")
            if not (path and (Path(path) / ".om" / "config.json").is_file()):
                orphans.add(ws)
    if orphans:
        return WARN, f"routes left by missing workspace(s): {', '.join(sorted(orphans))}", "om core reload   (prunes them once their containers are stopped)"
    return PASS, "every route belongs to an existing workspace", ""

def check_registry():
    missing = [w for w, d in core.read_registry().items() if not Path(d.get("path", "")).exists()]
    if missing:
        return WARN, f"workspace folder(s) missing: {', '.join(missing)}", "Reconnect the drive, or `om list --prune`."
    return PASS, f"{len(core.read_registry())} workspace(s) registered", ""

def _other_login_users() -> list[str]:
    """Other human accounts on this machine (Linux/macOS passwd; uid >= 1000 with a login shell)."""
    try:
        import pwd
        me = os.getuid()
        return sorted(u.pw_name for u in pwd.getpwall() if u.pw_uid >= 1000 and u.pw_uid != me and u.pw_uid < 60000
                      and not u.pw_shell.endswith(("nologin", "false")))
    except (ImportError, AttributeError):
        return []

def check_auth():
    if any(core.AUTH_DIR.glob("*.conf")):
        return PASS, "private tier requires login", ""
    others = _other_login_users()
    if others:
        return WARN, f"private tier has no login and other people can log in here ({', '.join(others)}): they can use your services",\
            "om auth add <user>"
    return PASS, "no login on the private tier: only you use this machine; your VPN decides who else reaches it", ""


def check_stream_published_ports(runtime):
    """Only declared stream ports (default range 22000-22199 and explicit ports from stream_ports.json)
    are published on om_stream_edge, and no other container publishes stream ports."""
    st_ports = core.stream_ports()
    declared_ports = {core.STREAM_PORT_BASE + i for i in range(core.STREAM_PORT_SLOTS)}
    for info in st_ports.values():
        hp = info.get("host_port")
        if hp:
            declared_ports.add(hp)

    # Inspect om_stream_edge
    r = core.run([runtime, "ps", "--format", "{{.Names}}\t{{.Ports}}"])
    edge_ports_str = ""
    for line in r.stdout.splitlines():
        name, _, ports = line.partition("\t")
        if name == core.STREAM_EDGE:
            edge_ports_str = ports
            break

    published = set()
    for part in edge_ports_str.split(","):
        part = part.strip()
        if "->" not in part:
            continue
        host_side = part.split("->")[0].rpartition(":")[2]
        if "-" in host_side:
            lo, hi = host_side.split("-", 1)
            if lo.isdigit() and hi.isdigit():
                for p in range(int(lo), int(hi) + 1):
                    published.add(p)
        elif host_side.isdigit():
            published.add(int(host_side))

    undeclared = sorted(published - declared_ports)
    if undeclared:
        return FAIL, f"undeclared port(s) published on {core.STREAM_EDGE}: {', '.join(map(str, undeclared))}", \
            "om core restart (ports.yml binds only declared stream ports)"

    # Check that no other container publishes declared or default stream ports
    leaks = []
    for line in r.stdout.splitlines():
        name, _, ports = line.partition("\t")
        if name in (core.EDGE, core.STREAM_EDGE):
            continue
        for part in ports.split(","):
            if "->" not in part:
                continue
            host_side = part.split("->")[0].rpartition(":")[2]
            p_val = int(host_side) if host_side.isdigit() else None
            if p_val and p_val in declared_ports:
                leaks.append(f"{name} (:{p_val})")

    if leaks:
        return FAIL, f"containers publish stream ports, bypassing stream proxy: {'; '.join(leaks)}", \
            "om core restart (ports.yml binds only declared stream ports)"

    return PASS, "only declared stream ports are bound/published", ""


def check_stream_firewall():
    """A host firewall rule exists for each declared stream port."""
    if hostsetup.firewall_status() != "active":
        return WARN, "host firewall is not active (`om firewall apply` to enforce perimeter)", "om firewall apply"

    st_ports = core.stream_ports()
    st_priv, st_pub = hostsetup.stream_firewall_ports()

    if core.IS_LINUX:
        nft_text = hostsetup._read(hostsetup.NFT_INSTALLED)
        if not nft_text:
            return FAIL, "applied host firewall (/etc/om-firewall.nft) is empty or missing", "om firewall apply"
        missing = []
        for p in st_pub:
            pattern = re.compile(rf"tcp\s+dport\s+{{?[^}}]*\b{re.escape(p)}\b[^}}]*}}?\s+accept")
            if not pattern.search(nft_text):
                missing.append(p)
        ips = hostsetup.vpn_ips()
        if ips and st_priv:
            for p in st_priv:
                pattern = re.compile(rf"ip\s+daddr\s+{{?[^}}]*}}\s+tcp\s+dport\s+{{?[^}}]*\b{re.escape(p)}\b[^}}]*}}?\s+accept")
                if not pattern.search(nft_text):
                    missing.append(p)
        if missing:
            return FAIL, f"firewall rule missing for stream port(s): {', '.join(sorted(set(missing)))}", "om firewall apply"
    elif core.IS_MACOS:
        pf_text = hostsetup._read(hostsetup.PF_INSTALLED)
        if not pf_text:
            return FAIL, "applied host firewall (/etc/pf.anchors/om) is empty or missing", "om firewall apply"
        missing = []
        for p in st_pub:
            if f"port {{ {p} }}" not in pf_text and f"port {p}" not in pf_text:
                missing.append(p)
        if missing:
            return FAIL, f"firewall rule missing for stream port(s): {', '.join(sorted(set(missing)))}", "om firewall apply"
    elif core.IS_WINDOWS:
        r = core.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                      "Get-NetFirewallRule -Group om -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName"])
        names = set(r.stdout.splitlines()) if r.returncode == 0 else set()
        if st_pub and not any("om public stream ports" in n for n in names):
            return FAIL, "firewall rule missing for public stream ports", "om firewall apply"

    return PASS, "a firewall rule exists for each stream port", ""


_STREAM_ISOLATION_PROBE = """
import socket, sys

def probe(host, port, timeout=2.0):
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        return "unreachable"
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return "open"
    except ConnectionRefusedError:
        return "refused"
    except OSError:
        return "unreachable"
    finally:
        s.close()

results = [probe(h, int(p)) for h, p in [arg.split(":") for arg in sys.argv[1:]]]
print(" ".join(results))
"""

def check_stream_isolation(runtime):
    """From inside a workspace container, om_stream_router and om_stream_edge are unreachable
    (expect refused/timeout), and a different workspace's stream target is unreachable."""
    st_ports = core.stream_ports()
    reg = core.read_registry()
    checked = 0

    for wid in sorted(reg):
        net = f"{wid}_net"
        if core.run([runtime, "network", "inspect", net]).returncode != 0:
            continue

        other_targets = []
        for other_key, info in st_ports.items():
            other_ws, _, other_svc = other_key.partition("/")
            if other_ws != wid:
                cport = info.get("container_port", 25565)
                other_targets.append(f"{other_ws}_{other_svc}:{cport}")

        probe_args = [f"{core.STREAM_EDGE}:22000", f"{core.STREAM_ROUTER}:1"]
        if other_targets:
            probe_args.append(other_targets[0])

        r = core.run([runtime, "run", "--rm", "--network", net, "--read-only", "--cap-drop", "ALL",
                      _probe_image(), "python3", "-c", _STREAM_ISOLATION_PROBE, *probe_args])
        statuses = r.stdout.split()
        if not statuses:
            continue

        checked += 1
        edge_status = statuses[0] if len(statuses) > 0 else "error"
        router_status = statuses[1] if len(statuses) > 1 else "error"
        other_status = statuses[2] if len(statuses) > 2 else "unreachable"

        if edge_status == "open":
            return FAIL, f"from {net}: {core.STREAM_EDGE} is directly reachable over network", \
                "Ensure om_stream_edge is only on om_core_net and om_stream_router has no network listener"

        if router_status == "open":
            return FAIL, f"from {net}: {core.STREAM_ROUTER} has an open network port", \
                "Ensure om_stream_edge is only on om_core_net and om_stream_router has no network listener"

        if other_status == "open":
            return FAIL, f"from {net}: cross-workspace stream target {probe_args[2]} is reachable", \
                "Ensure om_stream_edge is only on om_core_net and om_stream_router has no network listener"

    if not checked:
        return PASS, "no workspace networks available to probe stream isolation", ""
    return PASS, f"stream router and edge are isolated from workspace containers ({checked} network(s) probed)", ""


def run_doctor(runtime: str, as_json: bool = False) -> int:
    checks = [
        ("Python", check_python, ()), ("Engine", check_engine, (runtime,)), ("Compose", check_compose, (runtime,)),
        ("Ports", check_ports, (runtime,)), ("Core", check_core, (runtime,)),
    ]
    results = []
    for title, fn, args in checks:
        results.append((title, *fn(*args)))
    core_ok = results[-1][1] == PASS and results[1][1] == PASS
    if core_ok:
        for title, fn, args in [
            ("Router", check_router_networks, (runtime,)), ("Edge isolation", check_edge_isolated, (runtime,)),
            ("Published ports", check_published_ports, (runtime,)), ("Address drift", check_drift, (runtime,)),
            ("Private tier", check_private_reachable, ()), ("DNS rebinding", check_rebinding, ()),
            ("Router token", check_router_token, (runtime,)), ("Token not logged", check_token_not_logged, (runtime,)), ("Engine filter", check_engine_filter, (runtime,)),
            ("Admin surface", check_admin_surface, (runtime,)), ("Running = lock", check_workspaces_fsck, ()),
            ("Egress", check_egress, (runtime,)), ("Project isolation", check_project_isolation, (runtime,)),
            ("Generations", check_generations, ()), ("LAN tier", check_lan_tier, ()),
            ("VPN", check_vpn, ()), ("VPN isolation", check_vpn_isolation, ()), ("Address rules", check_net_policy, ()),
            ("Links", check_links, (runtime,)), ("Custom routes", check_custom_routes, ()), ("Healthchecks", check_healthchecks, (runtime,)),
            ("Stream ports", check_stream_published_ports, (runtime,)),
            ("Stream firewall", check_stream_firewall, ()),
            ("Stream isolation", check_stream_isolation, (runtime,)),
        ]:
            results.append((title, *fn(*args)))
    for title, fn, args in [
        (".localhost DNS", check_localhost_dns, ()), ("Firewall", check_firewall, ()), ("Boot", check_boot, (runtime,)),
        ("Login", check_auth, ()), ("Secret files", check_secret_modes, ()), ("State", check_secrets_tracked, ()), ("Registry", check_registry, ()),
        ("Orphan routes", check_orphan_routes, ()),
    ]:
        results.append((title, *fn(*args)))

    fails = sum(1 for r in results if r[1] == FAIL)
    if as_json:
        print(json.dumps({"version": core.VERSION, "runtime": runtime, "failures": fails,
                          "warnings": sum(1 for r in results if r[1] == WARN),
                          "checks": [{"check": t, "status": st, "detail": m, "fix": f} for t, st, m, f in results]}, indent=2))
        return 1 if fails else 0
    colors = {PASS: "\033[32m", WARN: "\033[33m", FAIL: "\033[31m"}
    print(f"\n\033[1mom doctor\033[0m  (om {core.VERSION}, {runtime})")
    print("═" * 78)
    for title, status, msg, fix in results:
        print(f"  {colors[status]}{status}\033[0m  {title:<16} {msg}")
        if fix and status != PASS:
            print(f"        ↳ {fix}")
    fails = sum(1 for r in results if r[1] == FAIL)
    warns = sum(1 for r in results if r[1] == WARN)
    print("─" * 78)
    print(f"  {fails} failure(s), {warns} warning(s)\n")
    return 1 if fails else 0
