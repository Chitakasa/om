#!/usr/bin/env python3
"""Script discovery helpers for `om scripts`: which files are runnable and their one-line summary."""

from __future__ import annotations

import re
from pathlib import Path

SCRIPT_EXTS = {".sh", ".py", ".bash", ".ps1"}
EXEC_MAGIC = (b"#!", b"\x7fELF", b"MZ", b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe")
DOC_QUOTES = {'"""': '"""', "'''": "'''", "<#": "#>"}
COMMENT_DECOR = "=-─━═*~_#│| \t"
COMMENT_DIRECTIVE_RE = re.compile(r"(shellcheck\s|coding[:=]|vim?:|SPDX-|\.[A-Z]+$)")

def script_description(head: bytes, filename: str) -> str:
    """One-line summary: the first real line of the leading comment block or docstring."""
    lines = head.decode("utf-8", errors="ignore").splitlines()
    if lines and lines[0].startswith("#!"):
        lines = lines[1:]
    close = ""
    for line in lines:
        s = line.strip()
        opener = None if close else next((q for q in DOC_QUOTES if s.startswith(q)), None)
        if opener:
            close, s = DOC_QUOTES[opener], s[len(opener):]
        if close:
            text, closed = s.split(close, 1)[0], close in s
        elif s.startswith("#"):
            text, closed = s, False
        elif s:
            break                                   # first line of code ends the header
        else:
            continue
        text = text.strip(COMMENT_DECOR)
        if any(c.isalnum() for c in text) and not COMMENT_DIRECTIVE_RE.match(text):
            stem = Path(filename).stem              # "git.sh — simple menu" → "Simple menu"
            short = re.sub(rf"^(?:{re.escape(filename)}|{re.escape(stem)})\s*[—–:-]\s+", "", text, flags=re.I)
            return text if short == text else short[:1].upper() + short[1:]
        if closed:
            break
    return ""
