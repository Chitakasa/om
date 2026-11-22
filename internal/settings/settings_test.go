package settings

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Chitakasa/om/internal/state"
)

func dirs(t *testing.T) state.Dirs {
	t.Setenv("OM_HOME", filepath.Join(t.TempDir(), "home"))
	t.Setenv("OM_CONFIG_DIR", filepath.Join(t.TempDir(), "cfg"))
	t.Setenv("OM_STATE_DIR", filepath.Join(t.TempDir(), "state"))
	return state.NewDirs()
}

// Parity with Python's ipaddress.ip_network(x.strip(), strict=False) over a captured corpus.
func TestParseNetworkMatchesPython(t *testing.T) {
	b, err := os.ReadFile("../../testdata/golden/ip_network.json")
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]*string
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	for in, w := range want {
		got, ok := ParseNetwork(in)
		switch {
		case w == nil && ok:
			t.Errorf("%q: Go accepts %q, Python refuses", in, got)
		case w != nil && (!ok || got != *w):
			t.Errorf("%q: Go %q/%v, Python %q", in, got, ok, *w)
		}
	}
}

func TestTemplateDefaults(t *testing.T) {
	s := ParseText(UserEnvTemplate)
	for k, v := range map[string]string{"OM_LAN_IP": "auto", "OM_HTTP_PORT": "80", "OM_HTTPS_PORT": "443", "OM_POLICY": "enforce", "OM_SIGNED": "auto", "OM_NOTIFY": "auto", "OM_VPN": ""} {
		if got, ok := s[k]; !ok || got != v {
			t.Errorf("%s=%q (present %v), want %q", k, got, ok, v)
		}
	}
}

func TestLoadMergesAndLegacyName(t *testing.T) {
	d := dirs(t)
	os.MkdirAll(d.Config, 0o755)
	os.WriteFile(d.UserEnv, []byte("LAN_IP=192.168.1.5\nOM_HTTP_PORT=8080\nOM_POLICY=\n"), 0o644)
	s, err := Load(d)
	if err != nil {
		t.Fatal(err)
	}
	if s["OM_LAN_IP"] != "192.168.1.5" || s["OM_HTTP_PORT"] != "8080" || s["OM_POLICY"] != "enforce" {
		t.Fatalf("%v", s)
	}
}

func TestEdgePortsAndBaseURL(t *testing.T) {
	for _, c := range []struct {
		h, s     string
		wh, ws   int
		wantBase string
	}{
		{"80", "443", 80, 443, "http://x"}, {"8080", "8443", 8080, 8443, "http://x:8080"},
		{"0", "70000", 80, 443, "http://x"}, {"abc", "²", 80, 443, "http://x"}, {"65535", "1", 65535, 1, "http://x:65535"},
	} {
		s := Settings{"OM_HTTP_PORT": c.h, "OM_HTTPS_PORT": c.s}
		if h, hs := s.EdgePorts(); h != c.wh || hs != c.ws || s.BaseURL("x") != c.wantBase {
			t.Errorf("%+v -> %d %d %s", c, h, hs, s.BaseURL("x"))
		}
	}
}

func TestSetKeepsOtherLinesAndRefusesControlChars(t *testing.T) {
	d := dirs(t)
	os.MkdirAll(d.Config, 0o755)
	os.WriteFile(d.UserEnv, []byte("# keep\nA=1\nB=2\n"), 0o644)
	if err := Set(d, "A", "9"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(d.UserEnv)
	if string(b) != "# keep\nB=2\nA=9\n" {
		t.Fatalf("%q", b)
	}
	for _, bad := range []string{"x\ny", "x\ry", "x\x00", "x\x7f"} {
		if Set(d, "K", bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if Set(d, "K\n", "v") == nil {
		t.Error("newline in key accepted")
	}
	if st, _ := os.Stat(d.UserEnv); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
}

func TestEdgeTokenCreatedOnceThenStable(t *testing.T) {
	d := dirs(t)
	a, err := EdgeToken(d)
	if err != nil || len(a) != 64 {
		t.Fatal(a, err)
	}
	if b, _ := EdgeToken(d); a != b {
		t.Fatal("token changed")
	}
	os.WriteFile(d.TokenFile, []byte("not-a-token\n"), 0o600)
	if c, _ := EdgeToken(d); c == "not-a-token" || len(c) != 64 {
		t.Fatal("invalid token must be replaced")
	}
}

func TestVPNAllowDedupAndDrops(t *testing.T) {
	s := Settings{"OM_VPN_ALLOW": "100.64.0.1, 100.64.0.1/32,10.0.0.5/24,fe80::1%eth0,bogus,,2001:DB8::1"}
	got := strings.Join(s.VPNAllow(), " ")
	if got != "100.64.0.1/32 10.0.0.0/24 2001:db8::1/128" {
		t.Fatal(got)
	}
}

func TestVPNHostsSkipsInvalidNames(t *testing.T) {
	d := dirs(t)
	os.MkdirAll(d.State, 0o755)
	os.WriteFile(d.RuntimeEnv, []byte("VPN_HOSTS=100.64.0.1,host.ts.net,vpn.disabled.invalid\n"), 0o644)
	if got := strings.Join(VPNHosts(d), " "); got != "100.64.0.1 host.ts.net" {
		t.Fatal(got)
	}
}

func TestPortBases(t *testing.T) {
	cases := []struct {
		name    string
		s       Settings
		want    [3]int
		problem string // a substring; "" means valid
	}{
		{"defaults", Settings{}, [3]int{20000, 21000, 22000}, ""},
		{"moved", Settings{"OM_PRIVATE_PORT_BASE": "30000", "OM_PUBLIC_PORT_BASE": "31000", "OM_STREAM_PORT_BASE": "32000"}, [3]int{30000, 31000, 32000}, ""},
		{"one moved", Settings{"OM_PRIVATE_PORT_BASE": "40000"}, [3]int{40000, 21000, 22000}, ""},
		{"not a number", Settings{"OM_PRIVATE_PORT_BASE": "abc"}, [3]int{20000, 21000, 22000}, "must be a number"},
		{"too low", Settings{"OM_PUBLIC_PORT_BASE": "80"}, [3]int{20000, 21000, 22000}, "1024-65535"},
		{"block does not fit", Settings{"OM_STREAM_PORT_BASE": "65500"}, [3]int{20000, 21000, 22000}, "1024-65535"},
		{"overlap", Settings{"OM_PRIVATE_PORT_BASE": "20900"}, [3]int{20000, 21000, 22000}, "overlap"},
		{"holds a front-door port", Settings{"OM_PRIVATE_PORT_BASE": "7950"}, [3]int{20000, 21000, 22000}, "front-door port 8080"},
		{"holds the configured front door", Settings{"OM_HTTP_PORT": "20005"}, [3]int{20000, 21000, 22000}, "front-door port 20005"},
	}
	for _, c := range cases {
		p, u, s, problem := c.s.PortBases()
		if [3]int{p, u, s} != c.want {
			t.Errorf("%s: got %d %d %d, want %v", c.name, p, u, s, c.want)
		}
		if (c.problem == "") != (problem == "") || (c.problem != "" && !strings.Contains(problem, c.problem)) {
			t.Errorf("%s: problem %q, want one containing %q", c.name, problem, c.problem)
		}
	}
}
