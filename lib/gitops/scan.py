#!/usr/bin/env python3
"""Image vulnerability counts (`om scan`) from a scanner already on the machine: trivy or grype.

om ships no scanner and no vulnerability database; a pinned digest never changes, so it also never
gets a security fix until `om update` moves it. This shows which pins to move first.
"""

import json
import shutil

SEVERITIES = ("CRITICAL", "HIGH")
TOOLS = ("trivy", "grype")


def scanner() -> str:
    return next((t for t in TOOLS if shutil.which(t)), "")


def command(tool: str, ref: str) -> list:
    if tool == "trivy":
        return ["trivy", "image", "--quiet", "--format", "json", "--severity", ",".join(SEVERITIES), ref]
    return ["grype", ref, "-o", "json", "--quiet"]


def count(tool: str, output: str) -> dict:
    """{'CRITICAL': n, 'HIGH': n} from the scanner's JSON; ValueError if it is not JSON."""
    data = json.loads(output)
    found = []
    if tool == "trivy":
        for res in data.get("Results") or []:
            found += [v.get("Severity", "") for v in res.get("Vulnerabilities") or []]
    else:
        found = [(m.get("vulnerability") or {}).get("severity", "") for m in data.get("matches") or []]
    found = [str(s).upper() for s in found]
    return {s: found.count(s) for s in SEVERITIES}
