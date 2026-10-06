"""Test bootstrap: point om at a throwaway OM_HOME and a missing engine before anything imports it."""
import os
import sys
import shutil
import runpy
import tempfile
from pathlib import Path

import atexit

REPO = Path(__file__).resolve().parent.parent
TMP_HOME = Path(tempfile.mkdtemp(prefix="om-test-home-"))
atexit.register(shutil.rmtree, TMP_HOME, True)

# Copy the code (not runtime state) into the temp home so om resolves everything there.
# core/caddy/conf.d is copied without generated routes: only om's own core routes are code.
for sub in ("bin", "lib", "core/caddy", "core/dashboard", "core/docker-compose.yml", "docs", "README.md", "CHANGELOG.md"):
    src = REPO / sub
    dst = TMP_HOME / sub
    if src.is_dir():
        shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "auth.d"))
    else:
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
