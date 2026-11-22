package netdetect

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Chitakasa/om/internal/state"
)

func golden(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile("../../testdata/golden/netdetect/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

func TestParsePTRMatchesPython(t *testing.T) {
	var cases map[string]struct {
		IP      string `json:"ip"`
		RespHex string `json:"resp_hex"`
		PatchID bool   `json:"patch_id"`
		Want    string `json:"want"`
	}
	golden(t, "ptr.json", &cases)
	const qid = 0xBEEF
	for name, c := range cases {
		data, _ := hex.DecodeString(c.RespHex)
		if c.PatchID && len(data) >= 2 {
			binary.BigEndian.PutUint16(data, qid)
		}
		want := c.Want
		if strings.HasPrefix(want, "PYEXC:") {
			want = "" // Python raises IndexError on a truncated pointer; Go answers none
		}
		qnameLen := 0
		for _, p := range strings.Split(c.IP, ".") {
			qnameLen += 1 + len(p)
		}
		qnameLen += len("\x07in-addr\x04arpa\x00")
		if got := ParsePTR(qid, qnameLen, data); got != want {
			t.Errorf("%s: Go %q, Python %q", name, got, c.Want)
		}
	}
}

func TestPTRQueryUnreachableServer(t *testing.T) {
	if PTRQuery("1.2.3.4", "203.0.113.1", 20*time.Millisecond) != "" {
		t.Fatal("unreachable server must yield no name")
	}
}

func TestBSDRouteDestMatchesPython(t *testing.T) {
	var g struct{ BSD map[string]string }
	golden(t, "bsd.json", &g)
	for in, want := range g.BSD {
		if got := BSDRouteDest(in); got != want {
			t.Errorf("%q: %q want %q", in, got, want)
		}
	}
}

func TestMacOSRoutesMatchesPython(t *testing.T) {
	var g struct {
		Text, Utun3, En0, None, Nohdr json.RawMessage
	}
	var raw map[string]json.RawMessage
	golden(t, "macroutes.json", &raw)
	_ = g
	var text string
	json.Unmarshal(raw["text"], &text)
	for k, iface := range map[string]string{"utun3": "utun3", "en0": "en0", "none": "zz"} {
		var want []string
		json.Unmarshal(raw[k], &want)
		got := MacOSRoutes(iface, text)
		if !reflect.DeepEqual(got, want) && !(len(got) == 0 && len(want) == 0) {
			t.Errorf("%s: %q want %q", k, got, want)
		}
	}
	if got := MacOSRoutes("utun3", "x y\n"); len(got) != 0 {
		t.Error(got)
	}
}

func TestVPNItemsMatchesPython(t *testing.T) {
	var g map[string][]string
	golden(t, "items.json", &g)
	for spec, want := range g {
		got := VPNItems(spec)
		if !reflect.DeepEqual(got, want) && !(len(got) == 0 && len(want) == 0) {
			t.Errorf("%q: %q want %q", spec, got, want)
		}
	}
}

// fake builds a Detector whose commands answer from a table keyed by the command's text.
func fake(osName string, out map[string]string) *Detector {
	return &Detector{
		OS: osName,
		Run: func(c []string) state.Result {
			if v, ok := out[strings.Join(c, " ")]; ok {
				return state.Result{Stdout: v}
			}
			return state.Result{Code: 127, Stderr: "no such command"}
		},
		Hostname: func() (string, error) { return "MyHost.local", nil },
		PTR:      func(ip, server string, _ time.Duration) string { return "" },
		IsLocal:  func(string) bool { return true },
	}
}

const ipLink = `[{"ifname":"lo","linkinfo":null},{"ifname":"wg0","linkinfo":{"info_kind":"wireguard"}},{"ifname":"tun0","linkinfo":{"info_kind":"tun"}},{"ifname":"br0","linkinfo":{"info_kind":"bridge"}}]`

func TestVPNCandidatesLinux(t *testing.T) {
	d := fake("linux", map[string]string{
		"ip -d -j link show":          ipLink,
		"ip -j -4 addr show dev wg0":  `[{"addr_info":[{"local":"100.64.0.2"}]}]`,
		"ip -j -4 addr show dev tun0": `[{"addr_info":[]}]`,
		"ifconfig tun0":               "tun0: flags\n\tinet 10.8.0.6 netmask 0xffffffff\n",
	})
	want := []Adapter{{"wg0", "100.64.0.2"}, {"tun0", "10.8.0.6"}}
	if got := d.VPNCandidates(); !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
	// valid JSON with no tunnel: an empty list, not a fall-through to the macOS path
	d = fake("linux", map[string]string{"ip -d -j link show": `[{"ifname":"lo"}]`, "ifconfig": "utun9: flags\n\tinet 10.0.0.1 netmask x\n"})
	if got := d.VPNCandidates(); len(got) != 0 {
		t.Fatalf("%v", got)
	}
}

func TestVPNCandidatesMacOSFallback(t *testing.T) {
	d := fake("darwin", map[string]string{
		"networksetup -listallhardwareports": "Hardware Port: Wi-Fi\nDevice: en0\n",
		"ifconfig": "lo0: flags=8049<UP,LOOPBACK,RUNNING> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000\n" +
			"en0: flags=8863<UP> mtu 1500\n\tinet 192.168.1.5 netmask 0xffffff00\n" +
			"utun3: flags=8051<UP> mtu 1380\n\tinet 100.64.0.9 --> 100.64.0.9 netmask 0xffffffff\n" +
			"utun4: flags=8051<UP> mtu 1380\n\tinet6 fe80::1\n",
	})
	if got := d.VPNCandidates(); !reflect.DeepEqual(got, []Adapter{{"utun3", "100.64.0.9"}}) {
		t.Fatalf("%v", got)
	}
}

func TestNameserversAndReverseNames(t *testing.T) {
	rc := t.TempDir() + "/resolv.conf"
	os.WriteFile(rc, []byte("# c\nnameserver 100.100.100.100\n  nameserver 8.8.8.8  \nnameserver ::1\nnameserver 100.100.100.100\nsearch x\n"), 0o644)
	d := fake("linux", nil)
	d.ResolvConf = rc
	if got := d.Nameservers(); !reflect.DeepEqual(got, []string{"100.100.100.100", "8.8.8.8"}) {
		t.Fatalf("%v", got)
	}
	asked := ""
	d.PTR = func(ip, server string, _ time.Duration) string {
		asked += server + ";"
		if server == "100.100.100.100" {
			return "box.tail1.ts.net"
		}
		return ""
	}
	if got := d.ReverseNames("100.64.0.2"); !reflect.DeepEqual(got, []string{"box.tail1.ts.net", "box", "myhost"}) {
		t.Fatalf("%v", got)
	}
	if asked != "100.100.100.100;" {
		t.Fatalf("must stop at the first name: %s", asked)
	}
	d.PTR = func(string, string, time.Duration) string { return "evil.arpa" }
	if got := d.ReverseNames("1.1.1.1"); !reflect.DeepEqual(got, []string{"myhost"}) {
		t.Fatalf("%v", got)
	}
	d.PTR = func(string, string, time.Duration) string { return "bad name!" }
	if got := d.ReverseNames("1.1.1.1"); !reflect.DeepEqual(got, []string{"myhost"}) {
		t.Fatalf("%v", got)
	}
}

func TestDetectVPN(t *testing.T) {
	d := fake("linux", map[string]string{"ip -j -4 addr show dev wg0": `[{"addr_info":[{"local":"10.8.0.1"}]}]`})
	d.ResolvConf = "/nonexistent"
	d.IsLocal = func(ip string) bool { return ip != "10.9.9.9" }
	ips, names := d.DetectVPN("wg0, 10.9.9.9, 10.8.0.1, nope")
	if !reflect.DeepEqual(ips, []string{"10.8.0.1"}) || !reflect.DeepEqual(names, []string{"myhost"}) {
		t.Fatal(ips, names)
	}
	if ips, _ := d.DetectVPN("auto"); len(ips) != 0 {
		t.Fatal("auto trusts nothing")
	}
}

func TestSplitBlocksAndWindows(t *testing.T) {
	if got := splitBlocks("a: x\n\ty\nb: z\n"); !reflect.DeepEqual(got, []string{"a: x\n\ty", "b: z\n"}) {
		t.Fatalf("%q", got)
	}
	ps := "Wintun Tunnel\t10.1.1.2\nTAP\t\n"
	d := fake("windows", map[string]string{})
	d.Run = func(c []string) state.Result { return state.Result{Stdout: ps} }
	if got := d.VPNCandidates(); !reflect.DeepEqual(got, []Adapter{{"Wintun Tunnel", "10.1.1.2"}}) {
		t.Fatalf("%v", got)
	}
	if d.IfaceIPv4("wintun TUNNEL") != "10.1.1.2" {
		t.Fatal("case-insensitive name")
	}
}

func TestIsLocalAddressAndLAN(t *testing.T) {
	if !IsLocalAddress("127.0.0.1") || IsLocalAddress("203.0.113.9") {
		t.Fatal("IsLocalAddress")
	}
	d := Real()
	if ip := d.LANIP(); ip != "" && (strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "100.")) {
		t.Fatal(ip)
	}
}
