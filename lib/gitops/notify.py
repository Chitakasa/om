#!/usr/bin/env python3
"""Notifications (`om notify test`; image updates found, auto-updates applied or rolled back).

Every message is appended to <state>/logs/notify.log. OM_NOTIFY lists more channels (default: none):
  webhook  POST the text to OM_NOTIFY_URL (e.g. an ntfy topic): the same on every OS, works from a
           timer. It leaves the machine, so it is opt-in and carries only workspace and image names.
  desktop  notify-send (Linux), osascript (macOS), a PowerShell toast (Windows). Best effort: it needs
           a graphical session, which a timer may not reach.
A message with a key is sent once per key (<state>/notify/seen.json).
"""

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request

from gitops import core

LOG = core.LOG_DIR / "notify.log"
SEEN = core.STATE_DIR / "notify" / "seen.json"
KEEP_SECONDS = 30 * 86400

_TOAST = ("[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime];"
          "$x = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02);"
          "$t = $x.GetElementsByTagName('text');"
          "[void]$t.Item(0).AppendChild($x.CreateTextNode($env:OM_TITLE)); [void]$t.Item(1).AppendChild($x.CreateTextNode($env:OM_BODY));"
          "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe')"
          ".Show([Windows.UI.Notifications.ToastNotification]::new($x))")


def channels() -> list:
    return [c.strip() for c in core.load_settings().get("OM_NOTIFY", "").split(",") if c.strip()]


def _webhook(title: str, body: str) -> tuple:
    url = core.load_settings().get("OM_NOTIFY_URL", "").strip()
    if not url.startswith(("https://", "http://")):
        return False, "OM_NOTIFY_URL is not set to an http(s) URL"
    req = urllib.request.Request(url, data=f"{title}\n{body}".encode("utf-8"), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return 200 <= r.status < 300, f"HTTP {r.status}"
    except OSError as e:
        return False, str(e)


def _desktop(title: str, body: str) -> tuple:
    env = dict(os.environ, OM_TITLE=title, OM_BODY=body)
    if sys.platform.startswith("linux"):
        if not shutil.which("notify-send"):
            return False, "notify-send is not installed (libnotify)"
        env.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path={env.get('XDG_RUNTIME_DIR') or f'/run/user/{os.getuid()}'}/bus")
        cmd = ["notify-send", "--app-name=om", title, body]
    elif sys.platform == "darwin":
        cmd = ["osascript", "-e", f"display notification {json.dumps(body)} with title {json.dumps(title)}"]
    elif sys.platform == "win32":
        cmd = ["powershell", "-NoProfile", "-Command", _TOAST]
    else:
        return False, f"no desktop notifications on {sys.platform}"
    try:
        r = subprocess.run(cmd, env=env, capture_output=True, text=True, encoding="utf-8", timeout=15)
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)
    return r.returncode == 0, (r.stderr or "").strip()[-200:] or "sent"


CHANNELS = {"webhook": _webhook, "desktop": _desktop}


def _first_time(key: str) -> bool:
    try:
        seen = json.loads(SEEN.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        seen = {}
    now = time.time()
    seen = {k: t for k, t in seen.items() if now - t < KEEP_SECONDS}
    new = key not in seen
    seen.setdefault(key, now)
    try:
        SEEN.parent.mkdir(parents=True, exist_ok=True)
        SEEN.write_text(json.dumps(seen), encoding="utf-8", newline="\n")
    except OSError:
        pass
    return new


def notify(title: str, body: str, key: str | None = None) -> list:
    """Log the message and send it on the configured channels, once per `key`. Returns [(channel, ok, detail)]."""
    if key and not _first_time(key):
        return []
    try:
        LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG, "a", encoding="utf-8", newline="\n") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {title}: {body}\n")
    except OSError:
        pass
    results = []
    for name in channels():
        fn = CHANNELS.get(name)
        results.append((name, *(fn(title, body) if fn else (False, "unknown channel (webhook, desktop)"))))
    return results
