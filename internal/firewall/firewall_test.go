package firewall

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/registry"
	"github.com/Chitakasa/om/internal/state"
)

func gold(t *testing.T) (m struct {
	Fixtures []map[string]any
	Pols     []struct {
		Key string
		Pol map[string]any
		Nft [][]string
		Pf  [][]string
		Win any
	}
	Complement map[string][]struct {
		In  []string
		Out []string
	}
	Ports   map[string][]string
	Enforce []struct {
		Name   string
		OS     string
		Text   string
		Result map[string]any
	}
}) {
	b, err := os.ReadFile("../../testdata/golden/firewall.json")
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return
}

func strs(v any) []string {
	var out []string
	l, _ := v.([]any)
	for _, x := range l {
		out = append(out, py.Str(x))
	}
	return out
}

func ints(v any) []int {
	var out []int
	l, _ := v.([]any)
	for _, x := range l {
		n, _ := x.(json.Number).Int64()
		out = append(out, int(n))
	}
	return out
}

// build makes a Firewall whose inputs are a golden fixture, with the registry files written to a temp state dir.
func build(t *testing.T, fx map[string]any, goos string) *Firewall {
	root := t.TempDir()
	t.Setenv("OM_STATE_DIR", "/state")
	t.Setenv("OM_CONFIG_DIR", "/cfg")
	d := state.NewDirs()
	d.State = "/state"
	d.Firewall = "/state/firewall"
	d.UserEnv = "/cfg/om.env"
	rd := state.NewDirs()
	rd.NetPolicy = filepath.Join(root, "net_policy.json")
	rd.StreamPorts = filepath.Join(root, "stream_ports.json")
	rd.NoLog = filepath.Join(root, "no_log.json")
	write := func(path string, v any) {
		b, _ := json.Marshal(v)
		os.WriteFile(path, b, 0o644)
	}
	write(rd.NetPolicy, fx["net"])
	write(rd.StreamPorts, fx["stream"])
	write(rd.NoLog, map[string]any{"all": fx["no_log"]})
	f := New(d, registry.New(rd), goos)
	edge := ints(fx["edge"])
	f.EdgePorts = func() (int, int) { return edge[0], edge[1] }
	f.VPNIPs = func() []string { return strs(fx["vpn_ips"]) }
	f.VPNAllow = func() []string { return strs(fx["vpn_allow"]) }
	s := func(k string) string { v, _ := fx[k].(string); return v }
	f.ExtraTCP = func() string { return s("extra_tcp") }
	f.ExtraUDP = func() string { return s("extra_udp") }
	return f
}

func eq(t *testing.T, what string, got, want any) {
	t.Helper()
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	if string(g) != string(w) {
		t.Errorf("%s:\n go     %s\n python %s", what, g, w)
	}
}

func nz(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

func TestRenderersMatchPython(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the goldens were recorded on POSIX and hold / paths")
	}
	g := gold(t)
	for _, fx := range g.Fixtures {
		name := fx["name"].(string)
		for _, osn := range []string{"linux", "darwin", "windows"} {
			f := build(t, fx, osn)
			tcp, udp := Ports(fxs(fx, "extra_tcp")), Ports(fxs(fx, "extra_udp"))
			var got string
			switch osn {
			case "linux":
				got = f.RenderNft(tcp, udp)
			case "darwin":
				got = f.RenderPf(tcp, udp)
			default:
				got = f.RenderWindows(tcp, udp)
			}
			want := fx[osn].(map[string]any)["render"].(string)
			if got != want {
				t.Errorf("%s/%s render differs:\n--- go\n%s\n--- python\n%s", name, osn, got, want)
			}
		}
		f := build(t, fx, "linux")
		eq(t, name+" om_ports", f.OMPorts(), fx["om_ports"])
		sp, su := f.StreamFirewallPorts()
		eq(t, name+" stream_ports", [][]string{nz(sp), nz(su)}, fx["stream_ports"])
		eq(t, name+" in_log", []string{f.NftInLog(false), f.NftInLog(true)}, fx["in_log"])
		var rs [][]any
		for _, r := range f.Restrictions() {
			rs = append(rs, []any{r.Key, normPol(r.Pol)})
		}
		eq(t, name+" restrictions", rs, normRestr(fx["restrictions"]))
		fb := fx["vpn_fallback"].(map[string]any)
		eq(t, name+" nft fallback", nz(f.NftVPNFallback()), fb["nft"])
		eq(t, name+" pf fallback", nz(f.PfVPNFallback()), fb["pf"])
		if got := [][]string{nz(Ports(fxs(fx, "extra_tcp"))), nz(Ports(fxs(fx, "extra_udp")))}; !reflect.DeepEqual(got, toStrs2(fx["ports_extra"])) {
			t.Errorf("%s ports %v want %v", name, got, fx["ports_extra"])
		}
	}
}

func fxs(fx map[string]any, k string) string { s, _ := fx[k].(string); return s }

func toStrs2(v any) [][]string {
	var out [][]string
	for _, x := range v.([]any) {
		out = append(out, nz(strs(x)))
	}
	return out
}

// normPol reduces a policy to JSON with sorted keys and plain values, so Go's and Python's can be compared.
func normPol(p Policy) any {
	b, _ := json.Marshal(p)
	var v any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	d.Decode(&v)
	return v
}

func normRestr(v any) [][]any {
	var out [][]any
	for _, x := range v.([]any) {
		p := x.([]any)
		b, _ := json.Marshal(p[1])
		var pv any
		d := json.NewDecoder(bytes.NewReader(b))
		d.UseNumber()
		d.Decode(&pv)
		out = append(out, []any{p[0], pv})
	}
	return out
}

func TestRulesMatchPython(t *testing.T) {
	g := gold(t)
	var fx map[string]any
	for _, f := range g.Fixtures {
		if f["name"] == "net_policies" {
			fx = f
		}
	}
	for _, c := range g.Pols {
		f := build(t, fx, "linux")
		eq(t, c.Key+" nft", [][]string{nz(f.NftNetRules(c.Key, c.Pol, false)), nz(f.NftNetRules(c.Key, c.Pol, true))}, c.Nft)
		tb, ru := f.PfNetRules(c.Key, c.Pol)
		eq(t, c.Key+" pf", [][]string{nz(tb), nz(ru)}, c.Pf)
		if s, ok := c.Win.(string); ok && strings.HasPrefix(s, "PYEXC") {
			continue
		}
		var win [][]string
		for _, w := range f.WinNetRules(c.Key, c.Pol) {
			win = append(win, []string{w.Name, w.Line})
		}
		if win == nil {
			win = [][]string{}
		}
		eq(t, c.Key+" win", win, c.Win)
	}
}

func TestComplementAndPortsMatchPython(t *testing.T) {
	g := gold(t)
	for _, c := range g.Complement["v4"] {
		eq(t, "complement v4 "+strings.Join(c.In, ","), nz(complement(c.In, 32)), nz(c.Out))
	}
	for _, c := range g.Complement["v6"] {
		eq(t, "complement v6 "+strings.Join(c.In, ","), nz(complement(c.In, 128)), nz(c.Out))
	}
	for in, want := range g.Ports {
		eq(t, "Ports("+in+")", nz(Ports(in)), nz(want))
	}
}

func TestEnforcementMatchesPython(t *testing.T) {
	g := gold(t)
	var fx map[string]any
	for _, f := range g.Fixtures {
		if f["name"] == "net_policies" {
			fx = f
		}
	}
	for _, c := range g.Enforce {
		f := build(t, fx, c.OS)
		text := c.Text
		f.ReadFile = func(string) (string, error) { return text, nil }
		f.Run = func(cmd []string) state.Result {
			if cmd[0] == "systemctl" {
				return state.Result{Stdout: "active\n"}
			}
			return state.Result{Stdout: text}
		}
		for key, pol := range fx["net"].(map[string]any) {
			want := c.Result[key].(bool)
			if got := f.NetPolicyEnforced(key, pol.(map[string]any)); got != want {
				t.Errorf("%s %s: enforced %v, python %v", c.Name, key, got, want)
			}
		}
		if got := f.VPNAllowEnforced(); got != c.Result["vpn"].(bool) {
			t.Errorf("%s: vpn enforced %v", c.Name, got)
		}
		applied, ok := f.LoggingApplied()
		switch want := c.Result["logging"].(type) {
		case nil:
			if ok {
				t.Errorf("%s: logging should be unknown", c.Name)
			}
		case bool:
			if !ok || applied != want {
				t.Errorf("%s: logging %v/%v want %v", c.Name, applied, ok, want)
			}
		}
		eq(t, c.Name+" stale", nz(f.StaleNetRules()), nz(strs(c.Result["stale"])))
		if got := f.VPNFallbackApplied(); got != c.Result["fallback"].(bool) {
			t.Errorf("%s: fallback applied %v want %v", c.Name, got, c.Result["fallback"])
		}
	}
}

func TestGenerateAndApply(t *testing.T) {
	g := gold(t)
	f := build(t, g.Fixtures[2], "linux")
	f.D.Firewall = t.TempDir()
	path, err := f.Generate()
	if err != nil || filepath.Base(path) != "om.nft" {
		t.Fatal(path, err)
	}
	if b, _ := os.ReadFile(path); string(b) != f.RenderNft(nil, nil) {
		t.Fatal("generated file differs from the rendering")
	}
	if b, _ := os.ReadFile(filepath.Join(f.D.Firewall, "om-firewall.service")); string(b) != SystemdUnit {
		t.Fatal("unit")
	}
	var out bytes.Buffer
	f.Out = &out
	var ran [][]string
	f.Sudo = func(c []string) bool { ran = append(ran, c); return true }
	f.LookPath = func(string) (string, error) { return "/usr/bin/nft", nil }
	if ok, err := f.Apply(); !ok || err != nil || len(ran) != 5 || ran[0][0] != "install" || ran[4][2] != "om-firewall" {
		t.Fatalf("%v %v %v", ok, err, ran)
	}
	f.LookPath = func(string) (string, error) { return "", os.ErrNotExist }
	if ok, _ := f.Apply(); ok || !strings.Contains(out.String(), "nftables (nft) is not installed") {
		t.Fatal("no nft")
	}
	// a failing sudo step stops the sequence
	f.LookPath = func(string) (string, error) { return "/usr/bin/nft", nil }
	n := 0
	f.Sudo = func([]string) bool { n++; return n < 2 }
	if ok, _ := f.Apply(); ok || n != 2 {
		t.Fatalf("steps after a failure must not run: %d", n)
	}
	f.OS = "darwin"
	f.Sudo = func(c []string) bool { return true }
	if ok, _ := f.Apply(); !ok || !strings.Contains(out.String(), `rdr-anchor "om"`) {
		t.Fatal("pf apply")
	}
	f.OS = "windows"
	if ok, _ := f.Apply(); !ok || !strings.Contains(out.String(), "elevated PowerShell") {
		t.Fatal("windows apply")
	}
	if !f.Remove() {
		t.Fatal("windows remove only prints")
	}
	f.OS = "linux"
	f.Run = func([]string) state.Result { return state.Result{Stdout: "inactive\n"} }
	if f.Status() != "inactive" || f.Installed() || !f.Remove() {
		t.Fatal("status")
	}
	f.OS = "darwin"
	if f.Status() != "unknown" {
		t.Fatal("pf status")
	}
	_ = py.Strip
}

// With nftables available, every generated ruleset must pass `nft -c` (syntax and semantics, nothing applied). An
// unprivileged user and network namespace gives nft the netlink access it needs.
func TestGeneratedNftPassesNftCheck(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare not installed")
	}
	probe := filepath.Join(t.TempDir(), "probe.nft")
	os.WriteFile(probe, []byte("table inet om_probe {\n}\n"), 0o644)
	if out, err := exec.Command("unshare", "-rn", "nft", "-c", "-f", probe).CombinedOutput(); err != nil {
		t.Skipf("cannot run nft in a user namespace: %v %s", err, out)
	}
	g := gold(t)
	for _, fx := range g.Fixtures {
		if strings.Contains(strings.Join(strs(fx["vpn_ips"]), ","), ":") {
			continue // VPN addresses are IPv4 by construction (netdetect.DetectVPN); nft refuses `ip daddr` with an IPv6 one
		}
		f := build(t, fx, "linux")
		file := filepath.Join(t.TempDir(), "om.nft")
		os.WriteFile(file, []byte(f.RenderNft(Ports(fxs(fx, "extra_tcp")), Ports(fxs(fx, "extra_udp")))), 0o644)
		if out, err := exec.Command("unshare", "-rn", "nft", "-c", "-f", file).CombinedOutput(); err != nil {
			t.Errorf("%s: nft rejects the ruleset: %v\n%s", fx["name"], err, out)
		}
	}
}
