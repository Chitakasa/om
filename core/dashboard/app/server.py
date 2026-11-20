#!/usr/bin/env python3
import base64
import hashlib
import html
import http.client
import http.server
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import socketserver
import sys
import tempfile
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

PORT = 80
SOCKET_PATH = os.environ.get("OM_ENGINE_SOCKET_PATH", "/var/run/docker.sock")
WALLPAPERS_DIR = "/wallpapers"
DATA_DIR = "/data"
WORKSPACES_MOUNT = "/workspaces"
INDEX_HTML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=5):
        super().__init__('localhost', timeout=timeout)
        self.path = path
        self.timeout = timeout
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)

STATS_CACHE = {}
STATS_LOCK = threading.Lock()
STATS_WANTED = threading.Event()
STATS_IDLE_AFTER = 30  # seconds without a stats consumer before the worker stops polling the engine
STATS_LAST_USE = 0.0

def touch_stats():
    global STATS_LAST_USE
    STATS_LAST_USE = time.time()
    STATS_WANTED.set()

def format_bytes(b):
    if not b or b <= 0:
        return "0 MB"
    if b >= 1024**3:
        return f"{b / (1024**3):.2f} GB"
    return f"{b / (1024**2):.1f} MB"

def _fetch_stat(c):
    """(id, name, {mem_usage, mem_limit} | None) for one container; one slow stats call no longer delays the rest."""
    cid = c.get('Id', '')
    cname = (c.get('Names', [''])[0]).lstrip('/')
    sconn = None
    try:
        sconn = UnixHTTPConnection(SOCKET_PATH, timeout=3)
        sconn.request('GET', f'/containers/{cid}/stats?stream=false')
        sres = sconn.getresponse()
        if sres.status == 200:
            mem = json.loads(sres.read().decode('utf-8')).get('memory_stats', {})
            return cid, cname, {'mem_usage': mem.get('usage', 0), 'mem_limit': max(mem.get('limit', 1), 1)}
    except Exception:
        pass
    finally:
        if sconn:
            try:
                sconn.close()
            except Exception:
                pass
    return cid, cname, None

def stats_worker():
    """Background worker that continuously collects container memory and CPU stats."""
    backoff = 3
    while True:
        if time.time() - STATS_LAST_USE > STATS_IDLE_AFTER:
            STATS_WANTED.clear()
            if time.time() - STATS_LAST_USE > STATS_IDLE_AFTER:  # a consumer may have touched in between
                STATS_WANTED.wait()
        success = False
        try:
            if os.path.exists(SOCKET_PATH):
                conn = None
                try:
                    conn = UnixHTTPConnection(SOCKET_PATH, timeout=5)
                    conn.request('GET', '/containers/json')
                    res = conn.getresponse()
                    if res.status == 200:
                        containers = json.loads(res.read().decode('utf-8'))
                        new_stats = {}
                        with ThreadPoolExecutor(max_workers=8) as pool:
                            for cid, cname, stat_entry in pool.map(_fetch_stat, containers):
                                if stat_entry:
                                    new_stats[cid[:12]] = stat_entry
                                    new_stats[cname] = stat_entry
                        with STATS_LOCK:
                            STATS_CACHE.clear()
                            STATS_CACHE.update(new_stats)
                        success = True
                except Exception:
                    pass
                finally:
                    if conn:
                        try:
                            conn.close()
                        except Exception:
                            pass
        except Exception:
            pass

        if success:
            backoff = 3
            time.sleep(3)
        else:
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)

UPDATES_CACHE = {}  # {workspace id: (read at, set of services with a newer image)}

def updates_for(ws_id):
    """Services of a workspace whose image has a newer digest, from the list `om` keeps in the registry dir."""
    if not ws_id or not re.fullmatch(r'[A-Za-z0-9_.-]+', ws_id):
        return set()
    now = time.time()
    hit = UPDATES_CACHE.get(ws_id)
    if hit and now - hit[0] < 30:
        return hit[1]
    try:
        path = os.path.join(os.path.dirname(os.environ.get("GLOBAL_REGISTRY", "/etc/om/workspaces.json")), 'updates', ws_id + '.json')
        with open(path, encoding='utf-8') as f:
            found = {str(s) for s in json.load(f).get('services', [])}
    except (OSError, ValueError, AttributeError, TypeError):
        found = set()
    UPDATES_CACHE[ws_id] = (now, found)
    return found

def core_anon_memory():
    """{container: anonymous bytes} from the snapshot `om core heal` writes (Linux, local engine), else {}.
    The engine reports cgroup usage including shared file cache; this is the cache-free figure."""
    try:
        with open(os.path.join(os.path.dirname(os.environ.get("GLOBAL_REGISTRY", "/etc/om/workspaces.json")), 'core_memory.json'), encoding='utf-8') as f:
            snap = json.load(f)
        if time.time() - float(snap.get('ts', 0)) <= 600:  # heal runs every 2 minutes
            return {k: int(v) for k, v in snap.get('anon', {}).items()}
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    return {}

def get_system_stats():
    """Calculates live platform overhead (every om_* core container) and host memory."""
    touch_stats()
    anon = core_anon_memory()
    mem_total = 0
    mem_avail = 0
    try:
        with open('/proc/meminfo', encoding='utf-8') as f:
            for line in f:
                if line.startswith('MemTotal:'):
                    mem_total = int(line.split()[1]) * 1024
                elif line.startswith('MemAvailable:'):
                    mem_avail = int(line.split()[1]) * 1024
    except Exception:
        pass

    platform_bytes = 0
    platform_containers = []
    cache_free = True
    workload_bytes = 0

    with STATS_LOCK:
        cache_items = list(STATS_CACHE.items())

    for name, stat in cache_items:
        if len(name) == 12 and all(ch in '0123456789abcdef' for ch in name):
            continue
        mem_usage = stat.get('mem_usage', 0)
        if name.startswith(('om_', 'om-')):
            if name in anon:
                mem_usage = anon[name]
            else:
                cache_free = False
            platform_bytes += mem_usage
            platform_containers.append({
                'name': name,
                'memory_usage': mem_usage,
                'memory_str': format_bytes(mem_usage)
            })
        else:
            workload_bytes += mem_usage

    platform_str = format_bytes(platform_bytes)
    workload_str = format_bytes(workload_bytes)

    return {
        'platform_ram_bytes': platform_bytes,
        'platform_ram_str': platform_str,
        'platform_ram_cache_free': cache_free and bool(platform_containers),
        'platform_containers': platform_containers,
        'workload_ram_bytes': workload_bytes,
        'workload_ram_str': workload_str,
        'host_total_bytes': mem_total,
        'host_available_bytes': mem_avail,
        'host_used_bytes': max(0, mem_total - mem_avail) if mem_total else 0,
        'host_total_str': format_bytes(mem_total) if mem_total else "",
        'host_available_str': format_bytes(mem_avail) if mem_avail else "",
        'host_used_str': format_bytes(max(0, mem_total - mem_avail)) if mem_total else ""
    }

def detect_image_mime(filepath):
    """Detect image MIME type by inspecting file header magic bytes."""
    try:
        with open(filepath, 'rb') as f:
            header = f.read(32)
        if header.startswith(b'\x89PNG\r\n\x1a\n'):
            return 'image/png'
        if header.startswith(b'\xff\xd8\xff'):
            return 'image/jpeg'
        if header.startswith((b'GIF87a', b'GIF89a')):
            return 'image/gif'
        if len(header) >= 12 and header.startswith(b'RIFF') and header[8:12] == b'WEBP':
            return 'image/webp'
        if header.startswith(b'BM'):
            return 'image/bmp'
    except Exception:
        pass
    # Never fall back to an extension-derived type: an SVG/HTML file served from the
    # dashboard origin would execute script there.
    return 'application/octet-stream'

def get_workspaces_registry():
    # Only the registry om mounts in; never guess at host paths (an old copy could linger there)
    candidates = [os.environ.get("GLOBAL_REGISTRY", "/etc/om/workspaces.json")]
    for p in candidates:
        if os.path.exists(p):
            try:
                with open(p, encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                pass
    return {}

# Each web service's own ports (written by om next to the registry): private base + slot on
# loopback and the VPN, public base + slot on the LAN for public services.
PRIVATE_PORT_BASE = int(os.environ.get('OM_PRIVATE_PORT_BASE', '20000'))
PUBLIC_PORT_BASE = int(os.environ.get('OM_PUBLIC_PORT_BASE', '21000'))

def get_service_slots():
    p = os.path.join(os.path.dirname(os.environ.get("GLOBAL_REGISTRY", "/etc/om/workspaces.json")), 'service_ports.json')
    try:
        with open(p, encoding='utf-8') as f:
            data = json.load(f)
        return {k: v for k, v in data.items() if isinstance(v, int) and v >= 0}
    except Exception:
        return {}

SAFE_WS_RE = re.compile(r'^[a-z0-9][a-z0-9_-]{0,62}$')
# Addresses and names of the VPNs you trusted (`om vpn trust`), resolved by `om core start`
PRIVATE_HOSTNAMES = {h.strip().lower() for h in os.environ.get('VPN_HOSTS', '').split(',') if h.strip() and not h.strip().endswith('.invalid')}

def parse_host(value):
    """Return the lowercase hostname from a Host/Origin authority, handling [IPv6]:port."""
    value = (value or '').strip().lower()
    if value.startswith('['):
        return value[1:value.find(']')] if ']' in value else ''
    return value.split(':')[0]

def is_private_host_allowed(host):
    """Hostnames the private tier answers to. Anything else (e.g. a DNS-rebound attacker domain) is rejected."""
    if host == 'localhost' or host in PRIVATE_HOSTNAMES or host.endswith('.localhost'):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback
    except ValueError:
        return False

def resolve_workspace_alias(name):
    """Match workspace name or alias fuzzily e.g. 'container' -> 'containers'.

    Returns a registered id, 'core', an unregistered but syntactically safe id (only usable
    as a filter), or None. Never returns anything containing path separators.
    """
    if not name or name == 'all':
        return None
    name = name.strip().lower()
    if name == 'core':
        return 'core'
    reg = get_workspaces_registry()
    if name in reg:
        return name
    for wid in reg:
        if wid == name or wid.rstrip('s') == name.rstrip('s'):
            return wid
    return name if SAFE_WS_RE.match(name) else None

def get_workspace_for_request(headers, query_params):
    """Detect workspace from direct query param or Host header."""
    ws_q = query_params.get('workspace', [''])[0].strip().lower()
    if ws_q and ws_q != 'all':
        return resolve_workspace_alias(ws_q)

    host = parse_host(headers.get('Host', ''))
    parts = host.split('.')
    if len(parts) >= 3 and parts[1] == 'dashboard' and parts[2] == 'localhost':
        return resolve_workspace_alias(parts[0])

    return None

def get_dashboard_storage_dir(ws_id=None, create=False):
    """Settings storage: <workspace>/.om/dashboard (mounted at /workspaces/<ws_id>) for registered workspaces, /data/ for core.

    A registered workspace whose folder isn't mounted yet (added since the core started) uses
    /data/workspaces/<ws_id>/. Unregistered ids share core storage so request input can never
    choose a filesystem path.
    """
    if ws_id and ws_id != "core" and ws_id in get_workspaces_registry() and SAFE_WS_RE.match(ws_id):
        d = os.path.join(WORKSPACES_MOUNT, ws_id)
        if not os.path.isdir(d):
            d = os.path.join(DATA_DIR, "workspaces", ws_id)
    else:
        d = DATA_DIR
    if create:
        os.makedirs(d, exist_ok=True)
    return d

def get_settings(ws_id=None):
    sdir = get_dashboard_storage_dir(ws_id)
    sfile = os.path.join(sdir, "settings.json")
    defaults = {
        "name": "wide_nebula.png",
        "blur": 0,
        "dim": 20,
        "card_blur": 16,
        "card_dim": 65,
        "timestamp": int(time.time()),
        "workspace_id": ws_id or "core"
    }
    if os.path.exists(sfile):
        try:
            with open(sfile, encoding='utf-8') as f:
                saved = json.load(f)
                defaults.update(saved)
        except Exception:
            pass
    elif ws_id and ws_id != "core":
        # Fallback to core settings if workspace hasn't customized yet
        core_settings = get_settings(None)
        defaults.update({k: v for k, v in core_settings.items() if k not in ["workspace_id", "timestamp"]})
    defaults['workspace_id'] = ws_id or "core"
    return defaults

def save_settings(new_settings, ws_id=None):
    sdir = get_dashboard_storage_dir(ws_id, create=True)
    sfile = os.path.join(sdir, "settings.json")
    current = get_settings(ws_id)
    current.update(new_settings)
    current['timestamp'] = int(time.time())
    current['workspace_id'] = ws_id or "core"
    try:
        with open(sfile, 'w', encoding='utf-8') as f:
            json.dump(current, f, indent=2)
    except Exception as e:
        print(f"Error saving settings for {ws_id}: {e}", file=sys.stderr)
    return current

def get_wallpaper_file_path(ws_id=None):
    sdir = get_dashboard_storage_dir(ws_id)
    if sdir != DATA_DIR:
        ws_wp = os.path.join(sdir, "current_wallpaper")
        if os.path.exists(ws_wp) and os.path.getsize(ws_wp) > 0:
            return ws_wp
    core_wp = os.path.join(DATA_DIR, "current_wallpaper")
    if os.path.exists(core_wp) and os.path.getsize(core_wp) > 0:
        return core_wp
    return None

def resolve_host_path(input_path):
    """Safely resolve an image path strictly restricted to WALLPAPERS_DIR or DATA_DIR."""
    if not input_path:
        return None
    base = os.path.basename(input_path.strip())
    if not base or base.startswith('.'):
        return None
    candidates = [
        os.path.join(WALLPAPERS_DIR, base),
        os.path.join(DATA_DIR, base)
    ]
    allowed_roots = [os.path.realpath(WALLPAPERS_DIR), os.path.realpath(DATA_DIR)]
    for p in candidates:
        try:
            real = os.path.realpath(p)
            if any(os.path.commonpath([real, r]) == r for r in allowed_roots) and os.path.isfile(real):
                return real
        except Exception:
            pass
    return None

def list_wallpapers():
    valid_exts = {'.jpg', '.jpeg', '.png', '.webp', '.bmp'}
    wallpapers = []
    if os.path.exists(WALLPAPERS_DIR):
        try:
            for item in sorted(os.listdir(WALLPAPERS_DIR)):
                ext = os.path.splitext(item)[1].lower()
                if ext in valid_exts and not item.startswith('.'):
                    wallpapers.append(item)
        except Exception as e:
            print(f"Error scanning wallpapers: {e}", file=sys.stderr)
    return wallpapers

_SERVICES_CACHE = (0.0, [])
_SERVICES_TTL = 2.0

def get_running_services():
    """Containers across all workspaces; recomputed at most every _SERVICES_TTL seconds."""
    global _SERVICES_CACHE
    ts, cached = _SERVICES_CACHE
    if time.monotonic() - ts < _SERVICES_TTL:
        return [dict(x) for x in cached]
    fresh = _load_running_services()
    _SERVICES_CACHE = (time.monotonic(), fresh)
    return [dict(x) for x in fresh]

def list_containers():
    """Every container (running or not) from the engine's read-only API socket; [] when it cannot be read."""
    if not os.path.exists(SOCKET_PATH):
        return []
    conn = None
    try:
        conn = UnixHTTPConnection(SOCKET_PATH)
        conn.request('GET', '/containers/json?all=true')
        res = conn.getresponse()
        return json.loads(res.read().decode('utf-8')) if res.status == 200 else []
    except Exception as e:
        print(f"Error querying podman socket: {e}", file=sys.stderr)
        return []
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def detect_port(labels, ports):
    """The service's web port: its dashboard.port label, else the first published/exposed port that is not 80/443."""
    if 'dashboard.port' in labels:
        try:
            return int(labels['dashboard.port'])
        except ValueError:
            pass
    for p in ports:
        port = p.get('PublicPort') or p.get('PrivatePort')
        if port and port not in (80, 443):
            return port
    if ports:
        return ports[0].get('PublicPort') or ports[0].get('PrivatePort', 80)
    return 80


def container_state(c):
    """(state, exit code) of a container list entry, whichever shape the engine reports."""
    raw = c.get('State', 'unknown')
    if isinstance(raw, dict):
        return raw.get('Status', 'unknown').lower(), raw.get('ExitCode', 0)
    status = c.get('Status', '')
    code = 0
    if 'exited' in status.lower():
        try:
            code = int(status.split('(')[1].split(')')[0])
        except Exception:
            pass
    return str(raw).lower(), code


def service_memory(c, raw_name):
    """(bytes, display text, percent text) of live memory from the stats cache."""
    with STATS_LOCK:
        stat = STATS_CACHE.get(c.get('Id', '')[:12], {}) or STATS_CACHE.get(raw_name, {})
    used, limit = stat.get('mem_usage', 0), max(stat.get('mem_limit', 1), 1)
    if used > 0:
        return used, format_bytes(used), f"{(used / limit * 100):.1f}%"
    return used, "—", "0%"


def service_entry(c, slots):
    """The dashboard's description of one container, or None for containers it hides."""
    raw_name = c.get('Names', ['/'])[0].lstrip('/')
    labels = c.get('Labels', {})
    if labels.get('dashboard.hide', '').lower() == 'true' or raw_name in ('om_caddy', 'om_dashboard', 'om_router'):
        return None
    if labels.get('om.core', '').lower() == 'true' and not labels.get('dashboard.name'):
        return None

    ws_id = labels.get('workspace.id') or labels.get('com.docker.compose.project')
    if not ws_id:
        ws_id = raw_name.split('_')[0] if '_' in raw_name else 'uncategorized'
    clean_name = raw_name[len(ws_id) + 1:] if raw_name.startswith(f"{ws_id}_") else raw_name

    # Services describe themselves with dashboard.* labels; om knows no product by name.
    ports = c.get('Ports', [])
    state, exit_code = container_state(c)
    has_web = labels.get('dashboard.web', '').lower() != 'false' and bool(ports or labels.get('dashboard.port'))
    subpath = labels.get('dashboard.path', '/')
    if not subpath.startswith('/'):
        subpath = '/' + subpath
    # Same rule as the CLI's route generator: public only with an explicit dashboard.scope=public label
    scope = 'public' if labels.get('dashboard.scope', '').strip().lower() == 'public' else 'private'
    # A search engine marks itself with dashboard.search=true; dashboard.search_url is the query path
    # relative to the service (default /search?q={searchTerms})
    is_search = labels.get('dashboard.search', '').lower() == 'true'
    slot = slots.get(f"{ws_id}/{clean_name}")
    default_name = clean_name.replace('-', ' ').replace('_', ' ').title()
    mem_bytes, mem_str, mem_pct = service_memory(c, raw_name)
    return {
        'id': c.get('Id', '')[:12],
        'key': clean_name,
        'name': labels.get('dashboard.name', default_name),
        'icon': labels.get('dashboard.icon', '📦'),
        'description': labels.get('dashboard.description', 'Self-hosted Service'),
        'port': detect_port(labels, ports) if has_web else None,
        'has_web': has_web,
        'domain': f"{ws_id}.{clean_name}.localhost",
        'path': subpath,
        'port_private': PRIVATE_PORT_BASE + slot if slot is not None else None,
        'port_public': PUBLIC_PORT_BASE + slot if slot is not None and scope == 'public' else None,
        'scope': scope,
        'is_public': scope == 'public',
        'is_search': is_search,
        'search_url': labels.get('dashboard.search_url', '/search?q={searchTerms}') if is_search else '',
        'url': labels.get('dashboard.url', ''),
        'state': state,
        'exit_code': exit_code,
        'status': c.get('Status', ''),
        'workspace_id': ws_id,
        'update_available': labels.get('com.docker.compose.service', clean_name) in updates_for(ws_id),
        'category': labels.get('workspace.category', 'projects' if 'project' in clean_name else 'services'),
        'memory_usage': mem_bytes,
        'memory_str': mem_str,
        'memory_percent': mem_pct,
    }


def _load_running_services():
    """Containers across all workspaces, running ones first."""
    touch_stats()
    slots = get_service_slots()
    services = [e for e in (service_entry(c, slots) for c in list_containers()) if e]
    services.sort(key=lambda s: (0 if s['state'] == 'running' else 1, s['name'].lower()))
    return services


def get_index_html():
    candidates = [
        INDEX_HTML_PATH,
        "/app/index.html",
        os.path.join(os.getcwd(), "index.html")
    ]
    for p in candidates:
        if os.path.exists(p) and os.path.isfile(p):
            try:
                with open(p, 'rb') as f:
                    return f.read()
            except Exception as e:
                print(f"Error reading index.html: {e}", file=sys.stderr)
                return b"<h1>Internal Server Error</h1>"
    return b"<h1>Dashboard index.html not found</h1>"

_INLINE_SCRIPT_RE = re.compile(rb'<script>(.*?)</script>', re.S)

def content_security_policy(body_bytes):
    """Strict CSP: only the page's own inline scripts (by hash) run; no inline handlers, no
    javascript: URLs, no third-party origins."""
    hashes = ' '.join("'sha256-" + base64.b64encode(hashlib.sha256(m).digest()).decode() + "'"
                      for m in _INLINE_SCRIPT_RE.findall(body_bytes))
    return ("default-src 'none'; script-src " + (hashes or "'none'") + "; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; "
            "base-uri 'none'; form-action 'self'; frame-ancestors 'self'")

def workspace_summaries(registry, services):
    """[{id, name, path, http_port, total, running}] for every registered workspace, then any workspace that
    only has containers (e.g. the core). Host paths are never included."""
    def entry(ws_id, name, http_port):
        mine = [s for s in services if s.get('workspace_id') == ws_id]
        return {"id": ws_id, "name": name, "path": "", "http_port": http_port, "total": len(mine),
                "running": sum(1 for s in mine if s.get('state') == 'running')}
    out = [entry(ws_id, ws_id.replace('-', ' ').title(), data.get("http_port", 80)) for ws_id, data in registry.items()]
    seen = {w['id'] for w in out}
    for s in services:
        ws_id = s.get('workspace_id')
        if ws_id and ws_id not in seen:
            out.append(entry(ws_id, "Platform Core" if ws_id == "core" else ws_id.replace('-', ' ').title(), 80))
            seen.add(ws_id)
    return out


JSON = 'application/json'
SETTING_KEYS = ('blur', 'dim', 'card_blur', 'card_dim')
IMAGE_EXTS = {'.jpg', '.jpeg', '.png', '.webp', '.bmp'}
MAX_UPLOAD_BYTES = 20 * 1024 * 1024  # 20 MB cap
MAX_JSON_BYTES = 1024 * 1024


def is_image_start(chunk):
    """Whether the first bytes of an upload are those of a supported image (magic bytes, never the name)."""
    return (chunk.startswith((b'\x89PNG\r\n\x1a\n', b'\xff\xd8\xff', b'BM', b'GIF87a', b'GIF89a'))
            or (len(chunk) >= 12 and chunk.startswith(b'RIFF') and chunk[8:12] == b'WEBP'))


def sanitize_public_service(svc):
    """What a LAN visitor may see of a service: no container id, memory, crash status, exit code, workspace
    name, private port or internal domain."""
    item = dict(svc)
    item.update(id='', workspace_id='', update_available=False, memory_usage=0, memory_str='', memory_percent='',
                status='online' if svc.get('state') == 'running' else 'stopped', exit_code=0, port_private=None, domain='')
    return item


def opensearch_base(svc, public, host):
    """Base URL of the search service as the visitor reaches it, or None when it has no port there."""
    hostname = parse_host(host)
    if not public and (hostname == 'localhost' or hostname.endswith('.localhost')):
        port = re.search(r":\d{1,5}$", host)  # non-default OM_HTTP_PORT
        return f"http://{svc['domain']}{port.group(0) if port else ''}"
    port = svc.get('port_public') if public else svc.get('port_private')
    if not port:
        return None
    h = f"[{hostname}]" if ':' in hostname else hostname
    return f"http://{h}:{port}{svc['path'].rstrip('/')}"


class DashboardHandler(http.server.BaseHTTPRequestHandler):
    # path -> method name; each takes (query, workspace, is_head) for GET and (query, workspace) for POST
    GET_ROUTES = {
        '/api/scope': '_get_scope', '/api/workspaces': '_get_workspaces', '/api/services': '_get_services',
        '/api/system': '_get_system', '/api/wallpaper/settings': '_get_wallpaper_settings',
        '/api/wallpaper/current': '_get_wallpaper_current', '/api/wallpaper/preview_host': '_get_preview_host',
        '/api/wallpapers': '_get_wallpapers', '/opensearch.xml': '_get_opensearch',
        '/healthz': '_get_health', '/api/health': '_get_health',
    }
    POST_ROUTES = {
        '/api/wallpaper/upload': '_post_upload', '/api/wallpaper/set': '_post_set',
        '/api/wallpaper/settings': '_post_settings',
    }

    def log_message(self, format, *args):
        # Keep server stdout clean and fast
        pass

    def _respond(self, status, content_type, body_bytes, cache_control=None, etag=None, is_head=False):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body_bytes)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'SAMEORIGIN')
        if content_type.startswith('text/html'):
            self.send_header('Content-Security-Policy', content_security_policy(body_bytes))
        if cache_control:
            self.send_header('Cache-Control', cache_control)
        if etag:
            self.send_header('ETag', etag)
        self.end_headers()
        if not is_head:
            try:
                self.wfile.write(body_bytes)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _json(self, status, obj, **kw):
        self._respond(status, JSON, json.dumps(obj).encode('utf-8'), **kw)

    def _forbidden(self, message, is_head=False):
        self._json(403, {"error": message}, is_head=is_head)

    def _saved(self, settings, ws):
        self._json(200, {"success": True, "timestamp": settings['timestamp'], "workspace_id": ws})

    def _reject_foreign_host(self, is_head=False):
        """On the private tier, refuse Host headers we don't serve (DNS rebinding). Returns True if rejected."""
        if self._is_public_scope() or is_private_host_allowed(parse_host(self.headers.get('Host', ''))):
            return False
        self._forbidden("Forbidden: unknown host", is_head=is_head)
        return True

    def _reject_cross_origin(self):
        """CSRF guard for state-changing requests: browsers always send Origin on POST. Returns True if rejected."""
        origin = self.headers.get('Origin')
        cross_site = self.headers.get('Sec-Fetch-Site', '').lower() == 'cross-site'
        if cross_site or (origin is not None and parse_host(urllib.parse.urlparse(origin).netloc) != parse_host(self.headers.get('Host', ''))):
            self._forbidden("Forbidden: cross-origin request")
            return True
        return False

    def _is_public_scope(self):
        # X-Access-Scope: the edge sets it on every public-tier request (overwriting any client value);
        # a client can only send it to make itself public. Nothing else forwards to this server: it is on
        # om_core_net only, the router refuses om_*/unqualified upstreams and om_egress denies private
        # addresses. A foreign Host is refused separately (_reject_foreign_host).
        scope_hdr = self.headers.get('X-Access-Scope', '').strip().lower()
        if scope_hdr == 'public':
            return True
        host = parse_host(self.headers.get('Host', ''))
        if host in PRIVATE_HOSTNAMES:  # a trusted VPN's address or name
            return False
        if host.endswith(('.local', '.home')):
            return True
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_loopback:
                return False
            # LAN IPv4 / IPv6 private ranges
            if ip.is_private:
                return True
        except ValueError:
            pass
        return False

    def _content_length(self):
        try:
            return max(int(self.headers.get('Content-Length', 0)), 0)  # a negative length would block rfile.read() until EOF
        except (ValueError, TypeError):
            return 0

    # ── POST ────────────────────────────────────────────────────────────────

    def do_POST(self):
        if self._is_public_scope():
            self._forbidden("Forbidden: Wallpaper management is restricted to private ingress")
            return
        if self._reject_foreign_host() or self._reject_cross_origin():
            return
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        req_ws = get_workspace_for_request(self.headers, query)
        query_ws = query.get('workspace', [''])[0].strip()
        if query_ws and query_ws != 'all':
            req_ws = resolve_workspace_alias(query_ws)
        handler = self.POST_ROUTES.get(parsed.path)
        if handler is None:
            self._json(404, {"error": "Not Found"})
        else:
            getattr(self, handler)(query, req_ws)

    def _with_json_body(self, work):
        """Read a small JSON body and run work(data); any failure is a 400 carrying the error text."""
        length = self._content_length()
        if length > MAX_JSON_BYTES:
            self._json(413, {"error": "Payload too large"})
            return
        body = self.rfile.read(length)
        try:
            work(json.loads(body.decode('utf-8')))
        except Exception as e:
            self._json(400, {"error": str(e)})

    def _post_upload(self, query, req_ws):
        length = self._content_length()
        if length <= 0:
            self._json(400, {"error": "No file uploaded"})
            return
        if length > MAX_UPLOAD_BYTES:
            self._json(413, {"error": "Payload Too Large: Maximum upload size is 20MB"})
            return
        name = os.path.basename(query.get('name', ['custom_wallpaper.png'])[0])
        if os.path.splitext(name)[1].lower() not in IMAGE_EXTS:
            name = "custom_wallpaper.png"
        current = get_settings(req_ws)
        raw = {k: query[k][0] for k in SETTING_KEYS if k in query and query[k] and query[k][0] != ''}
        to_save = {'name': name, **self._numeric_settings(raw, current)}

        sdir = get_dashboard_storage_dir(req_ws, create=True)
        tmp_fd, tmp_path = tempfile.mkstemp(dir=sdir, prefix='.upload-')
        # Streamed in chunks to prevent memory spikes, into a temp file renamed only once validated, so a
        # bad upload never clobbers the current wallpaper.
        try:
            valid, remaining = self._stream_upload(tmp_fd, length)
            if not valid or remaining > 0:
                self._json(400, {"error": "Invalid image format"})
                return
            os.replace(tmp_path, os.path.join(sdir, "current_wallpaper"))
            self._saved(save_settings(to_save, ws_id=req_ws), req_ws)
        except Exception:
            self._json(500, {"error": "Upload failed"})
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def _stream_upload(self, fd, length):
        """Copy the request body into fd; (starts like an image, bytes still missing)."""
        remaining, valid, first = length, False, True
        with os.fdopen(fd, 'wb') as f:
            while remaining > 0:
                chunk = self.rfile.read(min(65536, remaining))
                if not chunk:
                    break
                if first:
                    first, valid = False, is_image_start(chunk)
                f.write(chunk)
                remaining -= len(chunk)
        return valid, remaining

    @staticmethod
    def _numeric_settings(raw, current):
        """{key: int} for the appearance numbers: the given value, else what is saved; unreadable -> saved/0."""
        out = {}
        for k in SETTING_KEYS:
            if k in raw:
                try:
                    out[k] = int(raw[k])
                except (ValueError, TypeError):
                    out[k] = current.get(k, 0)
            elif k in current:
                out[k] = current[k]
        return out

    def _post_set(self, query, req_ws):
        self._with_json_body(lambda data: self._set_wallpaper(data, req_ws))

    def _set_wallpaper(self, data, req_ws):
        if data.get('workspace'):
            req_ws = resolve_workspace_alias(data['workspace'])
        current = get_settings(req_ws)
        to_save = {'name': os.path.basename(data.get('name', current.get('name', 'wallpaper.png')))}
        to_save.update(self._numeric_settings({k: data[k] for k in SETTING_KEYS if data.get(k) is not None}, current))
        # an explicit host `path` wins over `name`; either must resolve inside the allowed directories
        source = resolve_host_path(data['path']) if 'path' in data else resolve_host_path(data['name']) if 'name' in data else None
        if source and 'path' in data:
            to_save['name'] = os.path.basename(source)
        if not (source and os.path.exists(source) and detect_image_mime(source).startswith('image/')):
            self._json(404, {"error": "Source image not found in allowed directories"})
            return
        target = os.path.join(get_dashboard_storage_dir(req_ws, create=True), "current_wallpaper")
        shutil.copyfile(source, target + '.tmp')
        os.replace(target + '.tmp', target)
        self._saved(save_settings(to_save, ws_id=req_ws), req_ws)

    def _post_settings(self, query, req_ws):
        self._with_json_body(lambda data: self._update_settings(data, req_ws))

    def _update_settings(self, data, req_ws):
        if data.get('workspace'):
            req_ws = resolve_workspace_alias(data['workspace'])
        new_vals = {}
        for k in SETTING_KEYS:
            if data.get(k) is not None:
                try:
                    new_vals[k] = int(data[k])
                except (ValueError, TypeError):
                    pass
        if data.get('name'):
            new_vals['name'] = os.path.basename(str(data['name']))
        self._saved(save_settings(new_vals, ws_id=req_ws), req_ws)

    # ── GET ─────────────────────────────────────────────────────────────────

    def do_HEAD(self):
        self._handle_request(is_head=True)

    def do_GET(self):
        self._handle_request(is_head=False)

    def _handle_request(self, is_head=False):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path not in ('/healthz', '/api/health') and self._reject_foreign_host(is_head):
            return
        query = urllib.parse.parse_qs(parsed.query)
        # LAN visitors only ever see core presentation data; never a workspace's (which would also reveal
        # which workspace names exist).
        req_ws = None if self._is_public_scope() else get_workspace_for_request(self.headers, query)
        handler = self.GET_ROUTES.get(path)
        if handler:
            getattr(self, handler)(query, req_ws, is_head)
        elif path.startswith('/api/'):
            self._json(404, {"error": "Endpoint not found"}, is_head=is_head)
        else:
            self._respond(200, 'text/html; charset=utf-8', get_index_html(), cache_control='no-cache', is_head=is_head)

    def _get_scope(self, query, req_ws, is_head):
        self._json(200, {"is_public_scope": self._is_public_scope()}, is_head=is_head)

    def _get_health(self, query, req_ws, is_head):
        self._respond(200, 'text/plain', b"OK", is_head=is_head)

    def _get_workspaces(self, query, req_ws, is_head):
        all_svcs = get_running_services()
        if self._is_public_scope():
            # Strict zero-knowledge privacy for the LAN: no private workspaces, host paths or container totals.
            public = [s for s in all_svcs if s.get('is_public')]
            data = {"workspaces": [], "current_workspace": None, "total_workspaces": 0, "total_services": len(public),
                    "total_running": sum(1 for s in public if s.get('state') == 'running'), "is_public_scope": True}
        else:
            ws_list = workspace_summaries(get_workspaces_registry(), all_svcs)
            data = {"workspaces": ws_list, "current_workspace": req_ws, "total_workspaces": len(ws_list),
                    "total_services": len(all_svcs), "total_running": sum(1 for s in all_svcs if s.get('state') == 'running'),
                    "is_public_scope": False}
        self._json(200, data, cache_control='no-cache', is_head=is_head)

    def _get_services(self, query, req_ws, is_head):
        public = self._public_view(query)
        services = get_running_services()
        if req_ws:
            services = [s for s in services if s.get('workspace_id') == req_ws]
        elif not self._is_public_scope():
            wanted = query.get('workspace', [''])[0]
            resolved = resolve_workspace_alias(wanted) if wanted and wanted != 'all' else None
            if resolved:
                services = [s for s in services if s.get('workspace_id') == resolved]
        if public:
            services = [sanitize_public_service(s) for s in services if s.get('is_public')]
        self._json(200, services, cache_control='no-cache', is_head=is_head)

    def _public_view(self, query):
        return query.get('scope', [''])[0].lower() == 'public' or self._is_public_scope()

    def _get_system(self, query, req_ws, is_head):
        if self._is_public_scope():
            self._forbidden("Forbidden: System metrics restricted to private ingress", is_head)
            return
        self._json(200, get_system_stats(), cache_control='no-cache', is_head=is_head)

    def _get_wallpaper_settings(self, query, req_ws, is_head):
        if self._is_public_scope():
            core = get_settings(None)
            data = {"name": "wallpaper.png", "blur": core.get("blur", 0), "dim": core.get("dim", 20),
                    "card_blur": core.get("card_blur", 16), "card_dim": core.get("card_dim", 65),
                    "timestamp": core.get("timestamp", 0)}
        else:
            data = get_settings(req_ws)
        self._json(200, data, cache_control='no-cache', is_head=is_head)

    def _get_wallpapers(self, query, req_ws, is_head):
        if self._is_public_scope():
            self._forbidden("Forbidden: Wallpaper management restricted to private ingress", is_head)
            return
        wallpapers = list_wallpapers()
        self._json(200, {"wallpapers": wallpapers, "total": len(wallpapers), "settings": get_settings(req_ws),
                         "workspace_id": req_ws or "core"}, cache_control='no-cache', is_head=is_head)

    def _current_wallpaper_path(self, req_ws):
        """The wallpaper file for a workspace: its own upload, else the core's, else a host wallpaper."""
        target = get_wallpaper_file_path(req_ws)
        if target:
            return target
        candidate = os.path.join(WALLPAPERS_DIR, get_settings(req_ws).get('name', 'wide_nebula.png'))
        if os.path.exists(candidate):
            return candidate
        wallpapers = list_wallpapers() if os.path.exists(WALLPAPERS_DIR) else []
        return os.path.join(WALLPAPERS_DIR, wallpapers[0]) if wallpapers else None

    def _get_wallpaper_current(self, query, req_ws, is_head):
        target = self._current_wallpaper_path(req_ws)
        if not (target and os.path.exists(target)):
            self._respond(404, 'text/plain', b'No wallpaper found')
            return
        etag = f'"{int(os.path.getmtime(target))}-{os.path.getsize(target)}"'
        if self.headers.get('If-None-Match') == etag:  # HTTP 304 caching
            self.send_response(304)
            self.send_header('ETag', etag)
            self.send_header('Cache-Control', 'private, max-age=86400')
            self.end_headers()
            return
        self._send_image(target, is_head, etag)

    def _get_preview_host(self, query, req_ws, is_head):
        if self._is_public_scope():
            self._forbidden("Forbidden: Host inspection restricted to private ingress", is_head)
            return
        resolved = resolve_host_path(query.get('path', [''])[0])
        if resolved and os.path.exists(resolved):
            self._send_image(resolved, is_head)
        else:
            self._respond(404, 'text/plain', b'Host image not found')

    def _send_image(self, path, is_head, etag=None):
        """Stream an image file; the type comes from its bytes, never its name."""
        try:
            size = os.path.getsize(path)
            self.send_response(200)
            self.send_header('Content-Type', detect_image_mime(path))
            self.send_header('Content-Length', str(size))
            if etag:
                self.send_header('ETag', etag)
            self.send_header('Cache-Control', 'private, max-age=86400')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            if not is_head:
                with open(path, 'rb') as f:
                    while chunk := f.read(65536):
                        self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self._respond(500, 'text/plain', b'Internal Server Error')

    def _get_opensearch(self, query, req_ws, is_head):
        """Browser search integration for whichever service declares dashboard.search=true."""
        public = self._is_public_scope()
        host = self.headers.get('Host', 'localhost')
        found = [svc for svc in get_running_services() if svc.get('is_search') and (svc.get('is_public') or not public)]
        base = opensearch_base(found[0], public, host) if found else None
        if base is None:
            self._respond(404, 'text/plain', b'No search service', is_head=is_head)
            return
        svc = found[0]
        path = svc['search_url'] if svc['search_url'].startswith('/') else '/' + svc['search_url']
        template, name = html.escape(base + path, quote=True), html.escape(svc['name'], quote=True)
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<OpenSearchDescription xmlns="http://a9.com/-/spec/opensearch/1.1/">
  <ShortName>{name}</ShortName>
  <Description>{name} via om</Description>
  <InputEncoding>UTF-8</InputEncoding>
  <Url type="text/html" method="get" template="{template}"/>
</OpenSearchDescription>
"""
        self._respond(200, 'application/opensearchdescription+xml', xml.encode('utf-8'), is_head=is_head)


httpd_server = None

def handle_shutdown(signum, frame):
    print(f"\n🛑 Received signal {signum}, initiating instant graceful shutdown...", file=sys.stderr)
    if httpd_server:
        threading.Thread(target=httpd_server.shutdown, daemon=True).start()
    else:
        sys.exit(0)

def run():
    global httpd_server
    try:
        signal.signal(signal.SIGTERM, handle_shutdown)
        signal.signal(signal.SIGINT, handle_shutdown)
    except Exception:
        pass

    threading.Thread(target=stats_worker, daemon=True).start()
    with ThreadedTCPServer(("", PORT), DashboardHandler) as httpd:
        httpd_server = httpd
        print(f"🚀 Podman Multi-Threaded Universal Dashboard running on port {PORT}...")
        try:
            httpd.serve_forever()
        finally:
            httpd.server_close()
            print("✓ Dashboard server stopped cleanly.", file=sys.stderr)

if __name__ == '__main__':
    run()
