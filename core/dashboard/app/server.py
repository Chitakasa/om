#!/usr/bin/env python3
import http.server
import socketserver
import socket
import http.client
import html
import json
import os
import shutil
import time
import urllib.parse
import threading
import ipaddress
import sys
import signal
import re
import tempfile
import hashlib
import base64
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
            mstats = mem.get('stats') or {}
            cache = mstats.get('inactive_file', mstats.get('total_inactive_file', 0))
            return cid, cname, {'mem_usage': max(0, mem.get('usage', 0) - cache), 'mem_limit': max(mem.get('limit', 1), 1)}
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

def get_system_stats():
    """Calculates live platform overhead (om_caddy + om_dashboard) and host memory."""
    mem_total = 0
    mem_avail = 0
    try:
        with open('/proc/meminfo', 'r', encoding='utf-8') as f:
            for line in f:
                if line.startswith('MemTotal:'):
                    mem_total = int(line.split()[1]) * 1024
                elif line.startswith('MemAvailable:'):
                    mem_avail = int(line.split()[1]) * 1024
    except Exception:
        pass

    platform_bytes = 0
    platform_containers = []
    workload_bytes = 0

    with STATS_LOCK:
        cache_items = list(STATS_CACHE.items())

    for name, stat in cache_items:
        if len(name) == 12 and all(ch in '0123456789abcdef' for ch in name):
            continue
        mem_usage = stat.get('mem_usage', 0)
        if name.startswith('om_') or name.startswith('om-'):
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
        if header.startswith(b'GIF87a') or header.startswith(b'GIF89a'):
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
                with open(p, 'r', encoding='utf-8') as f:
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
        with open(p, 'r', encoding='utf-8') as f:
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
            with open(sfile, 'r', encoding='utf-8') as f:
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

def _load_running_services():
    """Query Podman API socket for all containers across all workspaces."""
    if not os.path.exists(SOCKET_PATH):
        return []

    conn = None
    data = []
    try:
        conn = UnixHTTPConnection(SOCKET_PATH)
        conn.request('GET', '/containers/json?all=true')
        res = conn.getresponse()
        if res.status == 200:
            data = json.loads(res.read().decode('utf-8'))
    except Exception as e:
        print(f"Error querying podman socket: {e}", file=sys.stderr)
        return []
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

    services = []
    slots = get_service_slots()
    for c in data:
        raw_name = c.get('Names', ['/'])[0].lstrip('/')
        labels = c.get('Labels', {})

        if labels.get('dashboard.hide', '').lower() == 'true':
            continue
        if raw_name in ['om_caddy', 'om_dashboard', 'om_router']:
            continue
        if labels.get('om.core', '').lower() == 'true' and not labels.get('dashboard.name'):
            continue

        ws_id = labels.get('workspace.id') or labels.get('com.docker.compose.project')
        if not ws_id:
            if '_' in raw_name:
                ws_id = raw_name.split('_')[0]
            else:
                ws_id = 'uncategorized'

        clean_name = raw_name
        if clean_name.startswith(f"{ws_id}_"):
            clean_name = clean_name[len(ws_id) + 1:]


        # Services describe themselves with dashboard.* labels; om knows no product by name.
        preset = ('📦', clean_name.replace('-', ' ').replace('_', ' ').title(), 'Self-hosted Service', None, f'{clean_name}.private')

        ports = c.get('Ports', [])
        detected_port = None
        if 'dashboard.port' in labels:
            try:
                detected_port = int(labels['dashboard.port'])
            except ValueError:
                pass
        if not detected_port and preset and preset[3]:
            detected_port = preset[3]
        if not detected_port:
            for p in ports:
                prv = p.get('PublicPort') or p.get('PrivatePort')
                if prv and prv not in [80, 443]:
                    detected_port = prv
                    break
        if not detected_port and ports:
            detected_port = ports[0].get('PublicPort') or ports[0].get('PrivatePort', 80)
        if not detected_port:
            detected_port = 80

        raw_state = c.get('State', 'unknown')
        if isinstance(raw_state, dict):
            state = raw_state.get('Status', 'unknown').lower()
            exit_code = raw_state.get('ExitCode', 0)
        else:
            state = str(raw_state).lower()
            exit_code = 0
            status_str = c.get('Status', '')
            if 'exited' in status_str.lower():
                try:
                    exit_code = int(status_str.split('(')[1].split(')')[0])
                except Exception:
                    pass

        has_web = True
        if labels.get('dashboard.web', '').lower() == 'false':
            has_web = False
        elif not ports and not labels.get('dashboard.port') and not (preset and preset[3]):
            has_web = False

        # Path on the service's own address (default its root; keep_prefix apps redirect there)
        subpath = labels.get('dashboard.path', '/')
        if not subpath.startswith('/'):
            subpath = '/' + subpath

        # Same rule as the CLI's route generator: public only with an explicit dashboard.scope=public label
        scope = 'public' if labels.get('dashboard.scope', '').strip().lower() == 'public' else 'private'

        # A search engine marks itself with dashboard.search=true; dashboard.search_url is the
        # query path relative to the service (default /search?q={searchTerms})
        is_search = labels.get('dashboard.search', '').lower() == 'true'
        search_url = labels.get('dashboard.search_url', '/search?q={searchTerms}') if is_search else ''

        svc = {
            'id': c.get('Id', '')[:12],
            'key': clean_name,
            'name': labels.get('dashboard.name', preset[1]),
            'icon': labels.get('dashboard.icon', preset[0]),
            'description': labels.get('dashboard.description', preset[2]),
            'port': detected_port if has_web else None,
            'has_web': has_web,
            'domain': f"{ws_id}.{clean_name}.localhost" if ws_id else f"{clean_name}.localhost",
            'path': subpath,
            'port_private': (PRIVATE_PORT_BASE + slots[f"{ws_id}/{clean_name}"]) if f"{ws_id}/{clean_name}" in slots else None,
            'port_public': (PUBLIC_PORT_BASE + slots[f"{ws_id}/{clean_name}"]) if f"{ws_id}/{clean_name}" in slots and scope == 'public' else None,
            'scope': scope,
            'is_public': (scope == 'public'),
            'is_search': is_search,
            'search_url': search_url,
            'url': labels.get('dashboard.url', ''),
            'state': state,
            'exit_code': exit_code,
            'status': c.get('Status', ''),
            'workspace_id': ws_id,
            'category': labels.get('workspace.category', 'projects' if 'project' in clean_name else 'services'),
        }

        cid12 = c.get('Id', '')[:12]
        with STATS_LOCK:
            stat = STATS_CACHE.get(cid12, {}) or STATS_CACHE.get(raw_name, {})
        mem_bytes = stat.get('mem_usage', 0)
        mem_limit = max(stat.get('mem_limit', 1), 1)
        if mem_bytes > 0:
            mem_str = format_bytes(mem_bytes)
            mem_pct = f"{(mem_bytes / mem_limit * 100):.1f}%" if mem_limit > 0 else "0%"
        else:
            mem_str = "—"
            mem_pct = "0%"

        svc['memory_usage'] = mem_bytes
        svc['memory_str'] = mem_str
        svc['memory_percent'] = mem_pct

        services.append(svc)

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

class DashboardHandler(http.server.BaseHTTPRequestHandler):
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

    def _reject_foreign_host(self, is_head=False):
        """On the private tier, refuse Host headers we don't serve (DNS rebinding). Returns True if rejected."""
        if self._is_public_scope() or is_private_host_allowed(parse_host(self.headers.get('Host', ''))):
            return False
        self._respond(403, 'application/json', b'{"error": "Forbidden: unknown host"}', is_head=is_head)
        return True

    def _reject_cross_origin(self):
        """CSRF guard for state-changing requests: browsers always send Origin on POST. Returns True if rejected."""
        origin = self.headers.get('Origin')
        cross_site = self.headers.get('Sec-Fetch-Site', '').lower() == 'cross-site'
        if cross_site or (origin is not None and parse_host(urllib.parse.urlparse(origin).netloc) != parse_host(self.headers.get('Host', ''))):
            self._respond(403, 'application/json', b'{"error": "Forbidden: cross-origin request"}')
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
        if host.endswith('.local') or host.endswith('.home'):
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

    def do_HEAD(self):
        self._handle_request(is_head=True)

    def do_GET(self):
        self._handle_request(is_head=False)

    def do_POST(self):
        if self._is_public_scope():
            self._respond(403, 'application/json', b'{"error": "Forbidden: Wallpaper management is restricted to private ingress"}')
            return
        if self._reject_foreign_host() or self._reject_cross_origin():
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        req_ws = get_workspace_for_request(self.headers, query)

        query_ws = query.get('workspace', [''])[0].strip()
        if query_ws and query_ws != 'all':
            req_ws = resolve_workspace_alias(query_ws)

        if path == '/api/wallpaper/upload':
            MAX_UPLOAD_BYTES = 20 * 1024 * 1024  # 20 MB cap
            try:
                content_length = int(self.headers.get('Content-Length', 0))
            except (ValueError, TypeError):
                content_length = 0

            if content_length <= 0:
                self._respond(400, 'application/json', b'{"error": "No file uploaded"}')
                return

            if content_length > MAX_UPLOAD_BYTES:
                self._respond(413, 'application/json', b'{"error": "Payload Too Large: Maximum upload size is 20MB"}')
                return

            raw_name = query.get('name', ['custom_wallpaper.png'])[0]
            name = os.path.basename(raw_name)
            ext = os.path.splitext(name)[1].lower()
            if ext not in {'.jpg', '.jpeg', '.png', '.webp', '.bmp'}:
                name = f"custom_wallpaper.png"

            current = get_settings(req_ws)
            to_save = {'name': name}
            for k in ['blur', 'dim', 'card_blur', 'card_dim']:
                if k in query and query[k] and query[k][0] != '':
                    try:
                        to_save[k] = int(query[k][0])
                    except (ValueError, TypeError):
                        to_save[k] = current.get(k, 0)
                elif k in current:
                    to_save[k] = current[k]

            sdir = get_dashboard_storage_dir(req_ws, create=True)
            wp_target = os.path.join(sdir, "current_wallpaper")

            # Stream read in chunks to prevent memory spikes. Written to a temp file and
            # renamed only once validated, so a bad upload never clobbers the current wallpaper.
            remaining = content_length
            first_chunk = True
            is_valid_image = False
            tmp_fd, tmp_path = tempfile.mkstemp(dir=sdir, prefix='.upload-')

            try:
                with os.fdopen(tmp_fd, 'wb') as f:
                    while remaining > 0:
                        chunk_size = min(65536, remaining)
                        chunk = self.rfile.read(chunk_size)
                        if not chunk:
                            break
                        if first_chunk:
                            first_chunk = False
                            # Magic byte validation
                            if chunk.startswith(b'\x89PNG\r\n\x1a\n') or \
                               chunk.startswith(b'\xff\xd8\xff') or \
                               chunk.startswith(b'BM') or \
                               (len(chunk) >= 12 and chunk.startswith(b'RIFF') and chunk[8:12] == b'WEBP') or \
                               chunk.startswith(b'GIF87a') or chunk.startswith(b'GIF89a'):
                                is_valid_image = True
                            else:
                                is_valid_image = False
                        f.write(chunk)
                        remaining -= len(chunk)

                if not is_valid_image or remaining > 0:
                    self._respond(400, 'application/json', b'{"error": "Invalid image format"}')
                    return

                os.replace(tmp_path, wp_target)
                settings = save_settings(to_save, ws_id=req_ws)
                payload = json.dumps({"success": True, "timestamp": settings['timestamp'], "workspace_id": req_ws}).encode('utf-8')
                self._respond(200, 'application/json', payload)
            except Exception:
                self._respond(500, 'application/json', b'{"error": "Upload failed"}')
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)

        elif path == '/api/wallpaper/set':
            try:
                content_length = int(self.headers.get('Content-Length', 0))
            except (ValueError, TypeError):
                content_length = 0

            if content_length > 1024 * 1024:
                self._respond(413, 'application/json', b'{"error": "Payload too large"}')
                return

            body = self.rfile.read(content_length)
            try:
                data = json.loads(body.decode('utf-8'))
                if data.get('workspace'):
                    req_ws = resolve_workspace_alias(data['workspace'])
                current = get_settings(req_ws)
                name = os.path.basename(data.get('name', current.get('name', 'wallpaper.png')))

                to_save = {'name': name}
                for k in ['blur', 'dim', 'card_blur', 'card_dim']:
                    if k in data and data[k] is not None:
                        try:
                            to_save[k] = int(data[k])
                        except (ValueError, TypeError):
                            to_save[k] = current.get(k, 0)
                    elif k in current:
                        to_save[k] = current[k]

                source_path = None
                if 'path' in data:
                    source_path = resolve_host_path(data['path'])
                    if source_path:
                        name = os.path.basename(source_path)
                        to_save['name'] = name
                elif 'name' in data:
                    source_path = resolve_host_path(data['name'])

                if source_path and os.path.exists(source_path) and detect_image_mime(source_path).startswith('image/'):
                    sdir = get_dashboard_storage_dir(req_ws, create=True)
                    wp_target = os.path.join(sdir, "current_wallpaper")
                    tmp_target = wp_target + '.tmp'
                    shutil.copyfile(source_path, tmp_target)
                    os.replace(tmp_target, wp_target)
                    settings = save_settings(to_save, ws_id=req_ws)
                    payload = json.dumps({"success": True, "timestamp": settings['timestamp'], "workspace_id": req_ws}).encode('utf-8')
                    self._respond(200, 'application/json', payload)
                else:
                    self._respond(404, 'application/json', b'{"error": "Source image not found in allowed directories"}')
            except Exception as e:
                err_payload = json.dumps({"error": str(e)}).encode('utf-8')
                self._respond(400, 'application/json', err_payload)

        elif path == '/api/wallpaper/settings':
            try:
                content_length = int(self.headers.get('Content-Length', 0))
            except (ValueError, TypeError):
                content_length = 0

            if content_length > 1024 * 1024:
                self._respond(413, 'application/json', b'{"error": "Payload too large"}')
                return

            body = self.rfile.read(content_length)
            try:
                data = json.loads(body.decode('utf-8'))
                if data.get('workspace'):
                    req_ws = resolve_workspace_alias(data['workspace'])
                new_vals = {}
                for k in ['blur', 'dim', 'card_blur', 'card_dim']:
                    if k in data and data[k] is not None:
                        try:
                            new_vals[k] = int(data[k])
                        except (ValueError, TypeError):
                            pass
                if 'name' in data and data['name']:
                    new_vals['name'] = os.path.basename(str(data['name']))
                settings = save_settings(new_vals, ws_id=req_ws)
                payload = json.dumps({"success": True, "timestamp": settings['timestamp'], "workspace_id": req_ws}).encode('utf-8')
                self._respond(200, 'application/json', payload)
            except Exception as e:
                err_payload = json.dumps({"error": str(e)}).encode('utf-8')
                self._respond(400, 'application/json', err_payload)
        else:
            self._respond(404, 'application/json', b'{"error": "Not Found"}')

    def _handle_request(self, is_head=False):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path not in ('/healthz', '/api/health') and self._reject_foreign_host(is_head):
            return
        query = urllib.parse.parse_qs(parsed.query)
        req_ws = get_workspace_for_request(self.headers, query)
        if self._is_public_scope():
            # LAN visitors only ever see core presentation data; never a workspace's
            # (which would also reveal which workspace names exist).
            req_ws = None

        if path == '/api/scope':
            is_pub = self._is_public_scope()
            self._respond(200, 'application/json', json.dumps({"is_public_scope": is_pub}).encode('utf-8'), is_head=is_head)

        elif path == '/api/workspaces':
            if self._is_public_scope():
                # Strict Zero-Knowledge Privacy for LAN:
                # Do NOT return private workspaces, host paths, or internal container totals.
                all_pub = [s for s in get_running_services() if s.get('is_public')]
                pub_running = len([s for s in all_pub if s.get('state') == 'running'])
                response_data = {
                    "workspaces": [],
                    "current_workspace": None,
                    "total_workspaces": 0,
                    "total_services": len(all_pub),
                    "total_running": pub_running,
                    "is_public_scope": True
                }
                payload = json.dumps(response_data).encode('utf-8')
                self._respond(200, 'application/json', payload, cache_control='no-cache', is_head=is_head)
                return

            reg = get_workspaces_registry()
            all_svcs = get_running_services()
            ws_list = []
            for ws_id, data in reg.items():
                w_svcs = [s for s in all_svcs if s.get('workspace_id') == ws_id]
                running = len([s for s in w_svcs if s.get('state') == 'running'])
                ws_list.append({
                    "id": ws_id,
                    "name": ws_id.replace('-', ' ').title(),
                    "path": "",  # Internal host path omitted for security
                    "http_port": data.get("http_port", 80),
                    "total": len(w_svcs),
                    "running": running
                })
            found_ids = {w['id'] for w in ws_list}
            for s in all_svcs:
                s_ws = s.get('workspace_id')
                if s_ws and s_ws not in found_ids:
                    w_svcs = [x for x in all_svcs if x.get('workspace_id') == s_ws]
                    ws_list.append({
                        "id": s_ws,
                        "name": "Platform Core" if s_ws == "core" else s_ws.replace('-', ' ').title(),
                        "path": "",
                        "http_port": 80,
                        "total": len(w_svcs),
                        "running": len([x for x in w_svcs if x.get('state') == 'running'])
                    })
                    found_ids.add(s_ws)

            response_data = {
                "workspaces": ws_list,
                "current_workspace": req_ws,
                "total_workspaces": len(ws_list),
                "total_services": len(all_svcs),
                "total_running": len([s for s in all_svcs if s.get('state') == 'running']),
                "is_public_scope": False
            }
            payload = json.dumps(response_data).encode('utf-8')
            self._respond(200, 'application/json', payload, cache_control='no-cache', is_head=is_head)

        elif path == '/api/services':
            services = get_running_services()
            if req_ws:
                services = [s for s in services if s.get('workspace_id') == req_ws]
            elif not self._is_public_scope():
                filter_ws = query.get('workspace', [''])[0]
                if filter_ws and filter_ws != 'all':
                    resolved = resolve_workspace_alias(filter_ws)
                    if resolved:
                        services = [s for s in services if s.get('workspace_id') == resolved]

            scope_filter = query.get('scope', [''])[0].lower()
            if scope_filter == 'public' or self._is_public_scope():
                services = [s for s in services if s.get('is_public')]
                # Zero-Knowledge Public Sanitization:
                # Strip container ID, memory usage, raw crash status, and exit codes.
                sanitized = []
                for s in services:
                    item = dict(s)
                    item['id'] = ''
                    item['workspace_id'] = ''
                    item['memory_usage'] = 0
                    item['memory_str'] = ''
                    item['memory_percent'] = ''
                    item['status'] = 'online' if s.get('state') == 'running' else 'stopped'
                    item['exit_code'] = 0
                    item['port_private'] = None  # private ports are not announced to the LAN
                    # Sanitize domain on public scope to avoid leaking internal workspace naming
                    item['domain'] = ''
                    sanitized.append(item)
                services = sanitized

            payload = json.dumps(services).encode('utf-8')
            self._respond(200, 'application/json', payload, cache_control='no-cache', is_head=is_head)

        elif path == '/api/system':
            if self._is_public_scope():
                self._respond(403, 'application/json', b'{"error": "Forbidden: System metrics restricted to private ingress"}', is_head=is_head)
                return
            sys_stats = get_system_stats()
            payload = json.dumps(sys_stats).encode('utf-8')
            self._respond(200, 'application/json', payload, cache_control='no-cache', is_head=is_head)

        elif path == '/api/wallpaper/settings':
            if self._is_public_scope():
                core_settings = get_settings(None)
                public_safe = {
                    "name": "wallpaper.png",
                    "blur": core_settings.get("blur", 0),
                    "dim": core_settings.get("dim", 20),
                    "card_blur": core_settings.get("card_blur", 16),
                    "card_dim": core_settings.get("card_dim", 65),
                    "timestamp": core_settings.get("timestamp", 0)
                }
                payload = json.dumps(public_safe).encode('utf-8')
                self._respond(200, 'application/json', payload, cache_control='no-cache', is_head=is_head)
                return
            settings = get_settings(req_ws)
            payload = json.dumps(settings).encode('utf-8')
            self._respond(200, 'application/json', payload, cache_control='no-cache', is_head=is_head)

        elif path == '/api/wallpaper/current':
            target_path = get_wallpaper_file_path(req_ws)
            if not target_path:
                settings = get_settings(req_ws)
                cand = os.path.join(WALLPAPERS_DIR, settings.get('name', 'wide_nebula.png'))
                if os.path.exists(cand):
                    target_path = cand
                elif os.path.exists(WALLPAPERS_DIR):
                    all_wps = list_wallpapers()
                    if all_wps:
                        target_path = os.path.join(WALLPAPERS_DIR, all_wps[0])

            if target_path and os.path.exists(target_path):
                file_size = os.path.getsize(target_path)
                mtime = int(os.path.getmtime(target_path))
                etag = f'"{mtime}-{file_size}"'

                # HTTP 304 Caching
                if self.headers.get('If-None-Match') == etag:
                    self.send_response(304)
                    self.send_header('ETag', etag)
                    self.send_header('Cache-Control', 'private, max-age=86400')
                    self.end_headers()
                    return

                mime_type = detect_image_mime(target_path)
                try:
                    self.send_response(200)
                    self.send_header('Content-Type', mime_type)
                    self.send_header('Content-Length', str(file_size))
                    self.send_header('ETag', etag)
                    self.send_header('Cache-Control', 'private, max-age=86400')
                    self.send_header('X-Content-Type-Options', 'nosniff')
                    self.end_headers()
                    if not is_head:
                        with open(target_path, 'rb') as f:
                            while chunk := f.read(65536):
                                self.wfile.write(chunk)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                except Exception as e:
                    self._respond(500, 'text/plain', b'Internal Server Error')
            else:
                self._respond(404, 'text/plain', b'No wallpaper found')

        elif path == '/api/wallpaper/preview_host':
            if self._is_public_scope():
                self._respond(403, 'application/json', b'{"error": "Forbidden: Host inspection restricted to private ingress"}', is_head=is_head)
                return
            raw_path = query.get('path', [''])[0]
            resolved = resolve_host_path(raw_path)
            if resolved and os.path.exists(resolved):
                mime_type = detect_image_mime(resolved)
                try:
                    file_size = os.path.getsize(resolved)
                    self.send_response(200)
                    self.send_header('Content-Type', mime_type)
                    self.send_header('Content-Length', str(file_size))
                    self.send_header('Cache-Control', 'private, max-age=86400')
                    self.send_header('X-Content-Type-Options', 'nosniff')
                    self.end_headers()
                    if not is_head:
                        with open(resolved, 'rb') as f:
                            while chunk := f.read(65536):
                                self.wfile.write(chunk)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                except Exception as e:
                    self._respond(500, 'text/plain', b'Internal Server Error')
            else:
                self._respond(404, 'text/plain', b'Host image not found')

        elif path == '/api/wallpapers':
            if self._is_public_scope():
                self._respond(403, 'application/json', b'{"error": "Forbidden: Wallpaper management restricted to private ingress"}', is_head=is_head)
                return
            wallpapers = list_wallpapers()
            settings = get_settings(req_ws)
            payload = json.dumps({
                "wallpapers": wallpapers,
                "total": len(wallpapers),
                "settings": settings,
                "workspace_id": req_ws or "core"
            }).encode('utf-8')
            self._respond(200, 'application/json', payload, cache_control='no-cache', is_head=is_head)

        elif path == '/opensearch.xml':
            # Browser search integration for whichever service declares dashboard.search=true
            public = self._is_public_scope()
            host = self.headers.get('Host', 'localhost')
            candidates = [svc for svc in get_running_services()
                          if svc.get('is_search') and (svc.get('is_public') or not public)]
            if not candidates:
                self._respond(404, 'text/plain', b'No search service', is_head=is_head)
                return
            svc = candidates[0]
            query = svc['search_url'] if svc['search_url'].startswith('/') else '/' + svc['search_url']
            hostname = parse_host(host)
            if not public and (hostname == 'localhost' or hostname.endswith('.localhost')):
                port = re.search(r":\d{1,5}$", host)  # non-default OM_HTTP_PORT
                base = f"http://{svc['domain']}{port.group(0) if port else ''}"
            else:
                port = svc.get('port_public') if public else svc.get('port_private')
                if not port:
                    self._respond(404, 'text/plain', b'No search service', is_head=is_head)
                    return
                h = f"[{hostname}]" if ':' in hostname else hostname
                base = f"http://{h}:{port}{svc['path'].rstrip('/')}"
            search_tmpl = html.escape(base + query, quote=True)
            name = html.escape(svc['name'], quote=True)
            xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<OpenSearchDescription xmlns="http://a9.com/-/spec/opensearch/1.1/">
  <ShortName>{name}</ShortName>
  <Description>{name} via om</Description>
  <InputEncoding>UTF-8</InputEncoding>
  <Url type="text/html" method="get" template="{search_tmpl}"/>
</OpenSearchDescription>
"""
            payload = xml.encode('utf-8')
            self._respond(200, 'application/opensearchdescription+xml', payload, is_head=is_head)

        elif path in ('/healthz', '/api/health'):
            self._respond(200, 'text/plain', b"OK", is_head=is_head)

        elif path.startswith('/api/'):
            self._respond(404, 'application/json', b'{"error": "Endpoint not found"}', is_head=is_head)

        else:
            payload = get_index_html()
            self._respond(200, 'text/html; charset=utf-8', payload, cache_control='no-cache', is_head=is_head)

httpd_server = None

def handle_shutdown(signum, frame):
    global httpd_server
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
