#!/usr/bin/env python3
"""Small CLI helpers shared by om's command modules: fatal errors, confirmation, JSON output."""

from __future__ import annotations

import json
import os
import sys


def die(msg: str, code: int = 1):
    color = sys.stderr.isatty() and not os.environ.get("NO_COLOR")
    print(f"\033[31m{msg}\033[0m" if color else msg, file=sys.stderr)
    sys.exit(code)

def confirm(question: str) -> bool:
    if not sys.stdin.isatty():
        return False
    return input(f"{question} [y/N] ").strip().lower() in ("y", "yes")

def emit_json(obj) -> None:
    """Machine-readable output for --json (scripts, editors, CI)."""
    print(json.dumps(obj, indent=2, sort_keys=True, default=str))
