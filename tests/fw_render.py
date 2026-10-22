"""Render om's host firewall for every OS with sample address rules, for CI's syntax checks
(nft -c on Linux, pfctl -nf on macOS, PowerShell parse + -WhatIf on Windows). Usage: fw_render.py <dir>"""
import sys
from pathlib import Path
from unittest import mock

import _env  # noqa: F401  (sandboxed OM_HOME and state before importing om)
from gitops import hostsetup as h

out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
POLICIES = {
    "ws/web": {"ports": [20001, 21001], "allow": ["vpn", "192.168.1.0/24", "fd7a:115c:a1e0::/48"], "deny": ["192.168.1.66/32"]},
    "ws/db": {"ports": [20002], "allow": None, "deny": ["10.0.0.0/8", "2001:db8::/32"]},
}
with mock.patch.object(h, "net_policies", return_value=POLICIES), mock.patch.object(h, "vpn_ips", return_value=["100.64.0.1"]), \
        mock.patch.object(h, "vpn_allow", return_value=["100.64.0.10/32", "100.107.0.0/16"]), \
        mock.patch.object(h, "no_log_ports", return_value=[20002]):
    (out / "om.nft").write_text(h.render_nft(["1714-1764"], ["1714-1764"]), encoding="utf-8", newline="\n")
    (out / "om.pf").write_text(h.render_pf(["1714-1764"], ["1714-1764"]), encoding="utf-8", newline="\n")
    (out / "om-firewall.ps1").write_text(h.render_windows(["1714-1764"], ["1714-1764"]), encoding="utf-8", newline="\n")
print(f"rendered om.nft, om.pf, om-firewall.ps1 into {out}")
