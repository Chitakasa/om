"""Writes docs/COMMANDS.md, SETTINGS.md, LABELS.md and DOCTOR.md from the code, so the reference cannot go stale.

    python3 tests/gen_reference.py        rewrites the four files
    tests/test_reference_docs.py          fails when a file differs from what the code produces

Nothing here depends on the Python version (no argparse-formatted help), so the files are the same everywhere."""
import argparse
import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _env  # noqa: E402  (sets OM_HOME and the import path)

from gitops import cliparser, doctor, omsettings, omstate, scaffold, settingscmd  # noqa: E402

NOTICE = "<!-- Generated from the code by tests/gen_reference.py: do not edit. Run `python3 tests/gen_reference.py` after a change. -->\n"


def _neutral(text: str) -> str:
    """A path of this machine (a help text may name om's folders) as its default location, so the files are the same everywhere."""
    for path, default in ((omstate.STATE_DIR, "~/.local/state/om"), (omstate.USER_ENV, "~/.config/om/om.env"), (omstate.OM_HOME, "~/.om")):
        text = text.replace(str(path), default)
    return text


def _cell(text: str) -> str:
    return " ".join(_neutral(text or "").replace("%%", "%").split()).replace("|", "\\|")


# ── COMMANDS.md ──────────────────────────────────────────────────────────────────────────────────

def _flag(a) -> str:
    return next((o for o in a.option_strings if o.startswith("--")), a.option_strings[0])


def _usage(name: str, parser) -> str:
    parts = ["om", name]
    for a in parser._actions:
        if isinstance(a, argparse._HelpAction):
            continue
        if a.option_strings:
            parts.append(f"[{_flag(a)}]" if a.nargs == 0 else f"[{_flag(a)} {(a.metavar or a.dest).upper()}]")
        else:
            nm = a.metavar or a.dest
            parts.append(f"[{nm}…]" if a.nargs == argparse.REMAINDER else f"[{nm}]" if a.nargs in ("?", "*") else f"<{nm}>")
    return " ".join(parts)


def _argument_rows(parser) -> list:
    rows = []
    for a in parser._actions:
        if isinstance(a, argparse._HelpAction):
            continue
        label = ", ".join(a.option_strings) if a.option_strings else (a.metavar or a.dest)
        if a.option_strings and a.nargs != 0:
            label += f" {(a.metavar or a.dest).upper()}"
        note = _cell(a.help if a.help != argparse.SUPPRESS else "")
        if a.choices:
            note += f" One of: {', '.join(map(str, a.choices))}."
        if a.option_strings and a.default not in (None, False, argparse.SUPPRESS):
            note += f" Default: {a.default}."
        rows.append((label, note.strip()))
    return rows


def commands_md() -> str:
    parser = cliparser.build_parser()
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    helps = {act.dest: act.help or "" for act in sub._choices_actions}
    out = [NOTICE, "# Commands\n\n",
           "Every `om` command, grouped as in `om --help`. A workspace command needs a folder with `.om/config.json` "
           "(`om init` makes one); the others work anywhere. New to om? Start with [START.md](START.md); for how to do a task, see [GUIDE.md](GUIDE.md).\n"]
    for group, names in cliparser.HELP_GROUPS:
        out.append(f"\n## {group}\n")
        for name in names:
            p = sub.choices[name]
            aliases = [n for n, q in sub.choices.items() if q is p and n != name]
            out.append(f"\n### `om {name}`\n\n")
            out.append(_cell(helps.get(name, "")) + (f" (alias: {', '.join(f'`om {a}`' for a in aliases)})" if aliases else "") + "\n")
            out.append(f"\n```text\n{_usage(name, p)}\n```\n")
            if p.description:
                out.append(f"\n```text\n{p.description.rstrip()}\n```\n")
            rows = _argument_rows(p)
            if rows:
                out.append("\n| Argument | Meaning |\n| :--- | :--- |\n")
                out += [f"| `{label}` | {note} |\n" for label, note in rows]
    return "".join(out)


# ── SETTINGS.md ──────────────────────────────────────────────────────────────────────────────────

def settings_md() -> str:
    defaults = omsettings.parse_env_file_text(omsettings.USER_ENV_TEMPLATE)
    out = [NOTICE, "# Settings\n\n",
           "Machine settings live in `~/.config/om/om.env` (`$OM_CONFIG_DIR/om.env`), one `KEY=value` per line, written "
           "readable by you only. Read and change them with `om config show`, `om config set KEY=value` and "
           "`om config unset KEY`: every value is checked, and `OM_NOTIFY_URL` is shown as `***` unless you ask. "
           "`auto` means \"detect it\"; `off` means \"switch it off\". Most changes take effect after the command named "
           "under *Then run*.\n"]
    for key in sorted(settingscmd.ABOUT):
        accepts, about = settingscmd.ABOUT[key]
        shown = defaults.get(key, "")
        out.append(f"\n## `{key}`\n\n{about}\n\n- **Default:** {f'`{shown}`' if shown else '(empty)'}\n- **Accepts:** {accepts}\n")
        if key in settingscmd.OWN_COMMAND:
            out.append(f"- **Change it with:** `{settingscmd.OWN_COMMAND[key]}` (it also updates the firewall)\n")
        else:
            then = settingscmd.SCHEMA[key][1]
            out.append(f"- **Change it with:** `om config set {key}=<value>`\n" + (f"- **Then run:** `{then}`\n" if then else ""))
    return "".join(out)


# ── LABELS.md ────────────────────────────────────────────────────────────────────────────────────

def labels_md() -> str:
    out = [NOTICE, "# Labels\n\n",
           "Labels are how a service tells om what it needs. They go in the service's `compose.yml`, under `labels:`, as "
           "a list (`- \"om.log=off\"`) or a map (`om.log: off`). `om add` writes the first table and offers every label "
           "in the second as a commented menu, so you uncomment what you need and run `om start`. `om edit` changes the "
           "dashboard ones for you.\n",
           "\n## Set by `om add`\n\n| Label | Example | What it does |\n| :--- | :--- | :--- |\n"]
    out += [f"| `{label}` | `{_cell(example)}` | {_cell(note)} |\n" for label, example, note in scaffold.ACTIVE_LABELS]
    for group, items in scaffold.LABEL_MENU:
        out.append(f"\n## {group}\n\n| Label | Example | What it does |\n| :--- | :--- | :--- |\n")
        out += [f"| `{label}` | `{_cell(example)}` | {_cell(note)} |\n" for label, example, note in items]
    return "".join(out)


# ── DOCTOR.md ────────────────────────────────────────────────────────────────────────────────────

def doctor_md() -> str:
    stages = (("Basics", "Always run. If these fail, the perimeter checks are skipped.", doctor.BASIC_CHECKS),
              ("Perimeter", "Need a running core; they attack the setup the way an outsider or a compromised container would.",
               doctor.PERIMETER_CHECKS),
              ("This machine", "Always run.", doctor.HOST_CHECKS))
    total = sum(len(s[2]) for s in stages)
    out = [NOTICE, "# What `om doctor` checks\n\n",
           f"`om doctor` runs {total} checks and prints one line each: **PASS**, **WARN** (works, but look at it) or **FAIL** "
           "(fix it; the line says how). It exits 1 when any check fails, and `om doctor --json` prints the same results for "
           "scripts. Run it after any change to the network or the core. For symptoms and their fixes, see "
           "[TROUBLESHOOTING.md](TROUBLESHOOTING.md).\n"]
    for title, blurb, checks in stages:
        out.append(f"\n## {title}\n\n{blurb}\n")
        for name, fn, _ in checks:
            text = " ".join(inspect.getdoc(fn).split())
            out.append(f"\n### {name}\n\n{text}\n")
    return "".join(out)


def render_all() -> dict:
    return {"docs/COMMANDS.md": commands_md(), "docs/SETTINGS.md": settings_md(),
            "docs/LABELS.md": labels_md(), "docs/DOCTOR.md": doctor_md()}


if __name__ == "__main__":
    for rel, text in render_all().items():
        (_env.REPO / rel).write_text(text, encoding="utf-8", newline="\n")
        print("wrote", rel)
