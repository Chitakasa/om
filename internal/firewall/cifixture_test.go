package firewall

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestWriteCIFixtures renders om's host firewall for every OS with sample address rules into $OM_CI_OUT, for CI's
// syntax checks (nft -c on Linux, pfctl -nf on macOS, PowerShell parse + -WhatIf on Windows). Without OM_CI_OUT it
// does nothing.
func TestWriteCIFixtures(t *testing.T) {
	out := os.Getenv("OM_CI_OUT")
	if out == "" {
		t.Skip("OM_CI_OUT not set")
	}
	const doc = `{"name": "ci",
	 "net": {"ws/web": {"ports": [20001, 21001], "allow": ["vpn", "192.168.1.0/24", "fd7a:115c:a1e0::/48"], "deny": ["192.168.1.66/32"]},
	         "ws/db": {"ports": [20002], "allow": null, "deny": ["10.0.0.0/8", "2001:db8::/32"]}},
	 "stream": {}, "no_log": [20002], "edge": [80, 443], "vpn_ips": ["100.64.0.1"],
	 "vpn_allow": ["100.64.0.10/32", "100.107.0.0/16"], "extra_tcp": "", "extra_udp": ""}`
	var fx map[string]any
	d := json.NewDecoder(bytes.NewReader([]byte(doc)))
	d.UseNumber()
	if err := d.Decode(&fx); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	ports := []string{"1714-1764"}
	for name, goos := range map[string]string{"om.nft": "linux", "om.pf": "darwin", "om-firewall.ps1": "windows"} {
		f := build(t, fx, goos)
		var text string
		switch goos {
		case "linux":
			text = f.RenderNft(ports, ports)
		case "darwin":
			text = f.RenderPf(ports, ports)
		default:
			text = f.RenderWindows(ports, ports)
		}
		if err := os.WriteFile(filepath.Join(out, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
