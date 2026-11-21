package settings

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Chitakasa/om/internal/netdetect"
	"github.com/Chitakasa/om/internal/registry"
	"github.com/Chitakasa/om/internal/state"
)

type renderScenario struct {
	Name string `json:"name"`
	R    struct {
		LANIP         string   `json:"lan_ip"`
		VPNIPs        []string `json:"vpn_ips"`
		VPNNames      []string `json:"vpn_names"`
		WallpapersDir string   `json:"wallpapers_dir"`
		HTTPPort      int      `json:"http_port"`
		HTTPSPort     int      `json:"https_port"`
	} `json:"r"`
	VPNPrivate bool   `json:"vpn_private"`
	Local6     bool   `json:"local6"`
	Host       string `json:"host"`
	Stream     map[string]struct {
		HostPort int    `json:"host_port"`
		Scope    string `json:"scope"`
	} `json:"stream"`
	NetPol   map[string]map[string]any `json:"netpol"`
	Enforced map[string]bool           `json:"enforced"`
	Ports    string                    `json:"ports"`
	Runtime  string                    `json:"runtime_env"`
}

func TestRenderMatchesPython(t *testing.T) {
	var g struct {
		Scenarios   []renderScenario
		Tmp         string
		Mounts      string
		MountsEmpty string `json:"mounts_empty"`
	}
	b, err := os.ReadFile("../../testdata/golden/settings/render.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	cfg, st := "/tmp/om-render/cfg", "/tmp/om-render/state"
	t.Setenv("OM_CONFIG_DIR", cfg)
	t.Setenv("OM_STATE_DIR", st)
	d := state.NewDirs()
	for _, sc := range g.Scenarios {
		r := Resolved{LANIP: sc.R.LANIP, VPNIPs: sc.R.VPNIPs, VPNNames: sc.R.VPNNames, WallpapersDir: sc.R.WallpapersDir,
			HTTPPort: sc.R.HTTPPort, HTTPSPort: sc.R.HTTPSPort, VPNPrivate: sc.VPNPrivate}
		h := Hooks{
			IsLocal: func(ip string) bool { return ip != "::1" || sc.Local6 },
			StreamPorts: func() map[string]StreamPort {
				m := map[string]StreamPort{}
				for k, v := range sc.Stream {
					m[k] = StreamPort{v.HostPort, v.Scope}
				}
				return m
			},
			NetPolicies: func() map[string]map[string]any { return sc.NetPol },
			NetPolicyEnforced: func(key string, _ map[string]any) bool {
				v, ok := sc.Enforced[key]
				return !ok || v
			},
		}
		if got := strings.ReplaceAll(RenderPorts(d, r, h), cfg, "@CFG@"); got != sc.Ports {
			t.Errorf("%s ports:\n%s\npython:\n%s", sc.Name, got, sc.Ports)
		}
		in := RuntimeInputs{EdgeToken: strings.Repeat("t", 64), EgressImage: "om-egress:1", Hostname: sc.Host}
		if in.Hostname == "" {
			in.Hostname = "fallback.example"
		}
		got := RenderRuntimeEnv(d, RuntimeEnvPairs(d, r, in))
		got = strings.NewReplacer(cfg, "@CFG@", st, "@STATE@", g.Tmp, "@T@").Replace(got)
		want := strings.NewReplacer(filepath.ToSlash(g.Tmp), "@T@").Replace(sc.Runtime)
		if got != want {
			t.Errorf("%s runtime.env:\n%s\npython:\n%s", sc.Name, got, want)
		}
	}
	if got := RenderDashboardMounts([]DashDir{{"a", "/w/a/.om/dashboard"}, {"b", "/w/b/.om/dashboard"}}); got != g.Mounts {
		t.Errorf("mounts:\n%s\n%s", got, g.Mounts)
	}
	if RenderDashboardMounts(nil) != g.MountsEmpty {
		t.Error("empty mounts")
	}
}

func TestResolveDefaults(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OM_STATE_DIR", t.TempDir())
	d := state.NewDirs()
	det := &netdetect.Detector{OS: "linux", Run: func([]string) state.Result { return state.Result{Code: 127} },
		ResolvConf: "/nonexistent", Hostname: func() (string, error) { return "h", nil },
		PTR: func(string, string, time.Duration) string { return "" }, IsLocal: func(string) bool { return true }}
	s := Settings{"OM_LAN_IP": "OFF", "OM_VPN": "auto", "OM_WALLPAPERS_DIR": "auto", "OM_HTTP_PORT": "8080", "OM_FIREWALL_EXTRA_TCP": "1714-1764"}
	r := s.Resolve(d, det)
	if r.LANIP != "" || len(r.VPNIPs) != 0 || r.HTTPPort != 8080 || r.HTTPSPort != 443 || !r.VPNPrivate || r.FirewallExtraTCP != "1714-1764" {
		t.Fatalf("%+v", r)
	}
	if r.WallpapersDir != filepath.Join(d.Data, "wallpapers") {
		t.Fatal(r.WallpapersDir)
	}
	os.MkdirAll(filepath.Join(home, "Pictures", "Wallpapers"), 0o755)
	if r := s.Resolve(d, det); r.WallpapersDir != filepath.Join(home, "Pictures", "Wallpapers") {
		t.Fatal(r.WallpapersDir)
	}
	s["OM_LAN_IP"], s["OM_WALLPAPERS_DIR"] = "10.0.0.9", "~/pics"
	if r := s.Resolve(d, det); r.LANIP != "10.0.0.9" || r.WallpapersDir != filepath.Join(home, "pics") {
		t.Fatalf("%+v", r)
	}
}

func TestDashboardDirsAndMigration(t *testing.T) {
	t.Setenv("OM_STATE_DIR", t.TempDir())
	d := state.NewDirs()
	reg := registry.New(d)
	a, b, gone := t.TempDir(), t.TempDir(), filepath.Join(t.TempDir(), "x")
	reg.Update(func(w registry.Workspaces) error {
		w["b"] = map[string]any{"path": b}
		w["a"] = map[string]any{"path": a}
		w["gone"] = map[string]any{"path": gone}
		w["Bad Id"] = map[string]any{"path": a}
		return nil
	})
	dirs := WorkspaceDashboardDirs(reg)
	if len(dirs) != 2 || dirs[0].ID != "a" || dirs[1].ID != "b" || dirs[0].Path != filepath.Join(a, ".om", "dashboard") {
		t.Fatalf("%+v", dirs)
	}
	old := filepath.Join(d.Data, "dashboard", "workspaces", "a")
	os.MkdirAll(old, 0o755)
	os.WriteFile(filepath.Join(old, "settings.json"), []byte("{}"), 0o600)
	os.MkdirAll(filepath.Join(old, "sub"), 0o755)
	if err := MigrateDashboardData(d, dirs); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dirs[0].Path, "settings.json")); string(got) != "{}" {
		t.Fatal("not copied")
	}
	if _, err := os.Stat(filepath.Join(dirs[0].Path, "sub")); err == nil {
		t.Fatal("only files are copied")
	}
	os.WriteFile(filepath.Join(old, "late.txt"), []byte("x"), 0o644)
	MigrateDashboardData(d, dirs) // target no longer empty: left alone
	if _, err := os.Stat(filepath.Join(dirs[0].Path, "late.txt")); err == nil {
		t.Fatal("copied into a non-empty folder")
	}
	if _, err := os.Stat(filepath.Join(old, "settings.json")); err != nil {
		t.Fatal("the old copy stays")
	}
}

func peerDetector(routes, neigh string, nameservers []string, ptr map[string]string) *netdetect.Detector {
	rc := ""
	for _, n := range nameservers {
		rc += "nameserver " + n + "\n"
	}
	f := filepath.Join(os.TempDir(), "om-peers-resolv-"+strings.ReplaceAll(strings.Join(nameservers, "_"), ".", "-"))
	os.WriteFile(f, []byte(rc), 0o644)
	return &netdetect.Detector{
		OS: "linux", ResolvConf: f,
		Hostname: func() (string, error) { return "h", nil },
		IsLocal:  func(string) bool { return true },
		PTR:      func(ip, _ string, _ time.Duration) string { return ptr[ip] },
		Run: func(c []string) state.Result {
			switch strings.Join(c[:min(5, len(c))], " ") {
			case "ip -d -j link show":
				return state.Result{Stdout: `[{"ifname":"wg0","linkinfo":{"info_kind":"wireguard"}}]`}
			case "ip -j -4 addr show":
				return state.Result{Stdout: `[{"addr_info":[{"local":"100.64.0.1"}]}]`}
			case "ip -j -4 route show":
				return state.Result{Stdout: routes}
			case "ip -j -4 neigh show":
				return state.Result{Stdout: neigh}
			}
			return state.Result{Code: 127}
		},
	}
}

func TestVPNPeersMesh(t *testing.T) {
	routes := `[{"dst":"100.64.0.9","type":"unicast"},{"dst":"100.64.0.2"},{"dst":"100.64.0.1"},{"dst":"224.0.0.251"},
		{"dst":"100.64.0.77","type":"local"},{"dst":"100.64.0.0/10"},{"dst":"default"},{"dst":"100.100.100.100"}]`
	det := peerDetector(routes, `[{"dst":"100.64.0.30"}]`, []string{"100.100.100.100"}, nil)
	s := Settings{"OM_VPN": "wg0"}
	r := Resolved{VPNIPs: []string{"100.64.0.1"}}
	want := []string{"100.64.0.2", "100.64.0.9", "100.64.0.30", "224.0.0.251"}
	want = want[:3] // multicast dropped, own address and own nameserver dropped, numeric order
	if got := s.VPNPeers(det, r); !reflect.DeepEqual(got, want) {
		t.Fatalf("%v want %v", got, want)
	}
	if got := (Settings{"OM_VPN": "unknown0"}).VPNPeers(det, r); len(got) != 0 {
		t.Fatalf("untrusted interface: %v", got)
	}
	if got := s.VPNInterfaces(det); !reflect.DeepEqual(got, []string{"wg0"}) {
		t.Fatal(got)
	}
	if got := (Settings{"OM_VPN": "100.64.0.1"}).VPNInterfaces(det); !reflect.DeepEqual(got, []string{"wg0"}) {
		t.Fatalf("an address maps to its interface: %v", got)
	}
}

func TestVPNPeersHubScan(t *testing.T) {
	det := peerDetector(`[{"dst":"100.64.1.0/24"},{"dst":"10.0.0.0/8"}]`, `[]`, []string{"100.100.100.100"},
		map[string]string{"100.64.1.5": "a.net", "100.64.1.200": "b.net", "100.64.1.0": "network.net", "100.64.1.255": "bcast.net"})
	got := (Settings{"OM_VPN": "wg0"}).VPNPeers(det, Resolved{})
	if !reflect.DeepEqual(got, []string{"100.64.1.5", "100.64.1.200"}) {
		t.Fatalf("%v", got)
	}
}

func TestVPNPeersBrokenJSON(t *testing.T) {
	det := peerDetector(`not json`, `[{"dst":"100.64.0.4"}]`, nil, nil)
	if got := (Settings{"OM_VPN": "wg0"}).VPNPeers(det, Resolved{}); len(got) != 0 {
		t.Fatalf("bad route JSON gives no routes and the neighbours are not read: %v", got)
	}
	det = peerDetector(`[{"dst":"100.64.0.8"}]`, `nope`, nil, nil)
	if got := (Settings{"OM_VPN": "wg0"}).VPNPeers(det, Resolved{}); len(got) != 0 {
		t.Fatalf("bad neighbour JSON drops the routes too: %v", got)
	}
}

func TestHostAddrs(t *testing.T) {
	if got := hostAddrs(netip.MustParsePrefix("10.0.0.0/30")); !reflect.DeepEqual(got, []string{"10.0.0.1", "10.0.0.2"}) {
		t.Errorf("/30 %v", got)
	}
	if got := hostAddrs(netip.MustParsePrefix("10.0.0.4/31")); !reflect.DeepEqual(got, []string{"10.0.0.4", "10.0.0.5"}) {
		t.Errorf("/31 keeps both addresses: %v", got)
	}
	got := hostAddrs(netip.MustParsePrefix("10.0.0.7/29"))
	if len(got) != 6 || got[0] != "10.0.0.1" || got[5] != "10.0.0.6" {
		t.Errorf("/29 %v", got)
	}
	if got := hostAddrs(netip.MustParsePrefix("100.64.1.0/24")); len(got) != 254 || got[0] != "100.64.1.1" || got[253] != "100.64.1.254" {
		t.Errorf("/24 has %d", len(got))
	}
}
