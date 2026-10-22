#!/usr/bin/env python3
"""`om docs` and `om completion`."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys

from gitops.core import OM_HOME
from gitops.cli import die

def doc_files() -> dict:
    """{short name: path} for om's docs: docs/*.md plus README and CHANGELOG."""
    out = {}
    for f in sorted((OM_HOME / "docs").glob("*.md")) + [OM_HOME / "README.md", OM_HOME / "CHANGELOG.md"]:
        if f.is_file():
            out[re.sub(r"_(guide|architecture)$", "", f.stem.lower()).replace("_", "-")] = f
    return out

def cmd_docs(args):
    """List om's docs, or show one in a pager (like `git help`)."""
    docs = doc_files()
    if not args.name:
        print("\n\033[1mom docs\033[0m  (om docs <name>)")
        for name, f in docs.items():
            title = next((l.lstrip("# ").strip() for l in f.read_text(encoding="utf-8").splitlines() if l.startswith("# ")), "")
            print(f"  \033[36m{name:<12}\033[0m {title}")
        print()
        return
    matches = [n for n in docs if n == args.name.lower()] or [n for n in docs if n.startswith(args.name.lower())]
    if len(matches) != 1:
        die(f"No single doc matches '{args.name}'. Available: {', '.join(docs)}")
    f = docs[matches[0]]
    if args.path:
        print(f)
        return
    text = f.read_text(encoding="utf-8")
    pager = os.environ.get("PAGER") or ("less" if shutil.which("less") else "more" if shutil.which("more") else "")
    if not sys.stdout.isatty() or not pager:
        sys.stdout.write(text)
        return
    env = dict(os.environ, LESS=os.environ.get("LESS", "-FRX"))
    try:
        subprocess.run(pager, input=text, text=True, encoding="utf-8", env=env, shell=True)
    except (OSError, KeyboardInterrupt):
        sys.stdout.write(text)

def cmd_completion(parser: argparse.ArgumentParser, shell: str):
    cmds = sorted(a for a in parser._subparsers._group_actions[0].choices if a != "script")
    words = " ".join(cmds)
    if shell == "bash":
        print(f'complete -W "{words}" om')
    elif shell == "zsh":
        print(f"#compdef om\n_arguments '1:command:({words})'")
    else:
        print(f"complete -c om -f -n '__fish_use_subcommand' -a '{words}'")
