"""Test bootstrap: point om at a throwaway OM_HOME and a missing engine before anything imports it."""
import atexit
import http.client
import os
import re
import runpy
import shutil
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TMP_HOME = Path(tempfile.mkdtemp(prefix="om-test-home-"))
atexit.register(shutil.rmtree, TMP_HOME, True)

# Copy the code (not runtime state) into the temp home so om resolves everything there.
# core/caddy/conf.d is copied without generated routes: only om's own core routes are code.
for sub in ("bin", "lib", "core/caddy", "core/dashboard", "core/compose.yml", "docs", "README.md", "CHANGELOG.md"):
    src = REPO / sub
    if not src.exists() and sub == "core/compose.yml":
        src = REPO / "core/docker-compose.yml"
    dst = TMP_HOME / sub
    if src.is_dir():
        shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "auth.d"))
    elif src.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
(TMP_HOME / "core" / "caddy" / "conf.d").mkdir(parents=True, exist_ok=True)
(TMP_HOME / "core" / "caddy" / "auth.d").mkdir(parents=True, exist_ok=True)

os.environ["OM_HOME"] = str(TMP_HOME)
# State and settings live outside OM_HOME; keep them in the sandbox too (never the real ones)
os.environ["OM_STATE_DIR"] = str(TMP_HOME / "_state")
os.environ["OM_CONFIG_DIR"] = str(TMP_HOME / "_config")
(TMP_HOME / "_state" / "routes").mkdir(parents=True, exist_ok=True)
os.environ["OM_RUNTIME"] = "om-test-no-engine"   # every engine call fails cleanly (exit 127)
os.environ["NO_COLOR"] = "1"
sys.path.insert(0, str(TMP_HOME / "lib"))
sys.dont_write_bytecode = True

OM_BIN = TMP_HOME / "bin" / "om"

def load_om():
    """Import bin/om as a module namespace (dict)."""
    return runpy.run_path(str(OM_BIN), run_name="om_under_test")


_MARKED = re.compile(r"<(?:tmp|config|state|root)>[^\s'\"\]),]*")


def scrub_paths(text, tmp, extra=()):
    """`str(tmp)` -> <tmp> (and each (path, mark) of `extra`), the rest of such a path with forward slashes."""
    text = text.replace(str(tmp), "<tmp>")
    for path, mark in extra:
        text = text.replace(str(path), mark)
    return _MARKED.sub(lambda m: m.group().replace("\\", "/"), text)


def posix_marked(obj):
    """scrub_paths' slash rule for every string inside a JSON-like structure."""
    if isinstance(obj, str):
        return _MARKED.sub(lambda m: m.group().replace("\\", "/"), obj)
    if isinstance(obj, list):
        return [posix_marked(x) for x in obj]
    if isinstance(obj, dict):
        return {k: posix_marked(v) for k, v in obj.items()}
    return obj


def http_roundtrip(port, method, path, headers=None, body=None, attempts=3):
    """One request to a local test server -> (status, content type, body). Windows sometimes aborts a loopback
    connection (WinError 10053) while the server is still closing the previous one: retry on a fresh connection."""
    for attempt in range(attempts):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            r = conn.getresponse()
            return r.status, r.getheader("Content-Type"), r.read()
        except ConnectionError:
            if attempt == attempts - 1:
                raise
            time.sleep(0.2 * (attempt + 1))
        finally:
            conn.close()
