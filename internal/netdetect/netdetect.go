// Package netdetect finds addresses and VPNs: the LAN address, every tunnel interface by kernel kind (never by
// product name), the system's DNS servers, and the names a VPN's own DNS gives an address (a plain PTR query).
// Port of lib/gitops/vpndetect.py. Everything that touches the host goes through Detector, so tests can
// supply canned command output.
package netdetect

import (
	"encoding/json"
	"net"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/state"
)

// Detector reads the host. Use Real() outside tests.
type Detector struct {
	OS         string
	Run        func(cmd []string) state.Result
	ResolvConf string
	Hostname   func() (string, error)
	// PTR asks one DNS server for the name of ip ("" if none). Real() uses PTRQuery.
	PTR func(ip, server string, timeout time.Duration) string
	// IsLocal reports whether ip is assigned to this host.
	IsLocal func(ip string) bool
}

// Real is a Detector for this machine.
func Real() *Detector {
	return &Detector{
		OS:         runtime.GOOS,
		Run:        func(c []string) state.Result { return state.Run(c) },
		ResolvConf: "/etc/resolv.conf",
		Hostname:   os.Hostname,
		PTR:        PTRQuery,
		IsLocal:    IsLocalAddress,
	}
}

func (d *Detector) windows() bool { return d.OS == "windows" }
func (d *Detector) macos() bool   { return d.OS == "darwin" }

// IsLocalAddress is true if ip is assigned to this host (binding to it succeeds).
func IsLocalAddress(ip string) bool {
	network := "udp4"
	if strings.Contains(ip, ":") {
		network = "udp6"
	}
	c, err := net.ListenPacket(network, net.JoinHostPort(ip, "0"))
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// LANIP returns the address the default route would use ("" if none usable: loopback, CGNAT 100.x, or not local).
func (d *Detector) LANIP() string {
	c, err := net.Dial("udp4", "192.0.2.1:9") // TEST-NET-1: no packet is sent for UDP connect
	if err != nil {
		return ""
	}
	defer c.Close()
	host, _, err := net.SplitHostPort(c.LocalAddr().String())
	if err != nil {
		return ""
	}
	if !strings.HasPrefix(host, "127.") && !strings.HasPrefix(host, "100.") && d.IsLocal(host) {
		return host
	}
	return ""
}

// Powershell runs a script and returns its stdout ("" on failure). Exported for the host package.
func (d *Detector) Powershell(script string) string {
	r := d.Run([]string{"powershell", "-NoProfile", "-NonInteractive", "-Command", script})
	if r.Code == 0 {
		return r.Stdout
	}
	return ""
}

// Adapter is an interface name and its first IPv4 address.
type Adapter struct{ Name, IP string }

func (d *Detector) windowsVirtualAdapters() []Adapter {
	out := d.Powershell("Get-NetAdapter | Where-Object { -not $_.HardwareInterface -and $_.Status -eq 'Up' } | " +
		"ForEach-Object { $ip = (Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 " +
		"-ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress; \"$($_.Name)`t$ip\" }")
	var res []Adapter
	for _, line := range py.SplitLines(out) {
		n, ip, _ := strings.Cut(line, "\t")
		if py.Strip(n) != "" {
			res = append(res, Adapter{py.Strip(n), py.Strip(ip)})
		}
	}
	return res
}

var inetRE = regexp.MustCompile(`\binet (\d+\.\d+\.\d+\.\d+)`)

// IfaceIPv4 returns the first IPv4 address of a network interface ("" if none or unknown).
func (d *Detector) IfaceIPv4(name string) string {
	if d.windows() {
		for _, a := range d.windowsVirtualAdapters() {
			if strings.EqualFold(a.Name, name) {
				return a.IP
			}
		}
		return ""
	}
	if r := d.Run([]string{"ip", "-j", "-4", "addr", "show", "dev", name}); r.Code == 0 {
		var links []struct {
			AddrInfo []struct {
				Local string `json:"local"`
			} `json:"addr_info"`
		}
		if json.Unmarshal([]byte(orEmptyList(r.Stdout)), &links) == nil {
			for _, l := range links {
				for _, a := range l.AddrInfo {
					if a.Local != "" {
						return a.Local
					}
				}
			}
		}
	}
	if r := d.Run([]string{"ifconfig", name}); r.Code == 0 {
		if m := inetRE.FindStringSubmatch(r.Stdout); m != nil {
			return m[1]
		}
	}
	return ""
}

func orEmptyList(s string) string {
	if s == "" {
		return "[]"
	}
	return s
}

var hwDeviceRE = regexp.MustCompile(`(?m)^Device:\s*(\S+)`)
var ifaceHeadRE = regexp.MustCompile(`^([\w.-]+):`)

// VPNCandidates returns (interface, IPv4) of every interface that may be a VPN, whatever its product or name.
// Linux: tunnel devices by kernel kind (`tun`, also tap; `wireguard`). macOS: every interface with an address
// that is not loopback or a hardware port. Windows: every non-hardware adapter. Listing too much is harmless:
// none is trusted without `om vpn trust`.
func (d *Detector) VPNCandidates() []Adapter {
	if d.windows() {
		var out []Adapter
		for _, a := range d.windowsVirtualAdapters() {
			if a.IP != "" {
				out = append(out, a)
			}
		}
		return out
	}
	if r := d.Run([]string{"ip", "-d", "-j", "link", "show"}); r.Code == 0 {
		var links []map[string]any
		ok := json.Unmarshal([]byte(orEmptyList(r.Stdout)), &links) == nil
		var out []Adapter
		for _, l := range links {
			info, _ := l["linkinfo"].(map[string]any)
			kind, _ := info["info_kind"].(string)
			if kind != "tun" && kind != "wireguard" {
				continue
			}
			name, has := l["ifname"].(string)
			if !has {
				ok = false // Python's KeyError: fall through to the BSD path
				break
			}
			out = append(out, Adapter{name, d.IfaceIPv4(name)})
		}
		if ok {
			return out
		}
	}
	hw := map[string]bool{}
	for _, m := range hwDeviceRE.FindAllStringSubmatch(d.Run([]string{"networksetup", "-listallhardwareports"}).Stdout, -1) {
		hw[m[1]] = true
	}
	r := d.Run([]string{"ifconfig"})
	text := ""
	if r.Code == 0 {
		text = r.Stdout
	}
	var out []Adapter
	for _, block := range splitBlocks(text) {
		m := ifaceHeadRE.FindStringSubmatch(block)
		ip := inetRE.FindStringSubmatch(block)
		first, _, _ := strings.Cut(block, "\n")
		if m != nil && ip != nil && !hw[m[1]] && !strings.Contains(first, "LOOPBACK") {
			out = append(out, Adapter{m[1], ip[1]})
		}
	}
	return out
}

// splitBlocks splits ifconfig output where a line starts with a non-space character (Python: split on "\n(?=\S)").
func splitBlocks(s string) []string {
	var blocks []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' && i+1 < len(s) && !isSpaceByte(s[i+1]) {
			blocks = append(blocks, s[start:i])
			start = i + 1
		}
	}
	return append(blocks, s[start:])
}

func isSpaceByte(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f' || b == '\v'
}

// BSDRouteDest turns macOS netstat's abbreviated IPv4 destination ('100.64/10', '192.168.1', '10', 'default')
// into CIDR; "" when it is not one.
func BSDRouteDest(dst string) string {
	if dst == "default" {
		return "0.0.0.0/0"
	}
	head, _, _ := strings.Cut(dst, "%")
	addr, _, _ := strings.Cut(head, "/")
	plen := ""
	if i := strings.Index(head, "/"); i >= 0 {
		plen = head[i+1:]
	}
	octets := strings.Split(addr, ".")
	if len(octets) < 1 || len(octets) > 4 {
		return ""
	}
	for _, o := range octets {
		if o == "" || strings.Trim(o, "0123456789") != "" {
			return ""
		}
	}
	for len(octets) < 4 {
		octets = append(octets, "0")
	}
	if plen == "" {
		plen = itoa(8 * len(strings.Split(addr, ".")))
	}
	return strings.Join(octets, ".") + "/" + plen
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for ; n > 0; n /= 10 {
		s = string(rune('0'+n%10)) + s
	}
	return s
}

// MacOSRoutes returns the destinations routed via iface in `netstat -rn -f inet` output. The interface column is
// found by its header (Netif), since other columns (Refs, Use, Expire) come and go between macOS versions.
// An unparsable destination is kept as "" (callers skip it).
func MacOSRoutes(iface, text string) []string {
	lines := py.SplitLines(text)
	var hdr []string
	for _, ln := range lines {
		if strings.HasPrefix(ln, "Destination") {
			hdr = strings.Fields(ln)
			break
		}
	}
	col := -1
	for i, h := range hdr {
		if h == "Netif" {
			col = i
			break
		}
	}
	var out []string
	for _, ln := range lines {
		t := strings.Fields(ln)
		if col >= 0 && len(t) > col && t[col] == iface {
			out = append(out, BSDRouteDest(t[0]))
		}
	}
	return out
}

// VPNItems is OM_VPN as a list: the interfaces and addresses you trusted (`om vpn trust`). `auto` (before
// om vpn) trusts nothing by itself.
func VPNItems(spec string) []string {
	spec = py.Strip(spec)
	switch strings.ToLower(spec) {
	case "", "off", "auto":
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, x := range strings.Split(spec, ",") {
		x = py.Strip(x)
		if x == "" || strings.ToLower(x) == "off" || strings.ToLower(x) == "auto" || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	return out
}

var (
	resolvRE = regexp.MustCompile(`(?m)^\s*nameserver\s+(\d+\.\d+\.\d+\.\d+)\s*$`)
	scutilRE = regexp.MustCompile(`nameserver\[\d+\]\s*:\s*(\d+\.\d+\.\d+\.\d+)`)
	ip4RE    = regexp.MustCompile(`\d+\.\d+\.\d+\.\d+`)
)

// Nameservers returns the IPv4 DNS servers the system uses, including a VPN's own (scoped resolvers on macOS,
// per-adapter servers on Windows).
func (d *Detector) Nameservers() []string {
	var found []string
	switch {
	case d.windows():
		found = ip4RE.FindAllString(d.Powershell("(Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses"), -1)
	case d.macos():
		for _, m := range scutilRE.FindAllStringSubmatch(d.Run([]string{"scutil", "--dns"}).Stdout, -1) {
			found = append(found, m[1])
		}
	default:
		if b, err := os.ReadFile(d.ResolvConf); err == nil {
			for _, m := range resolvRE.FindAllStringSubmatch(string(b), -1) {
				found = append(found, m[1])
			}
		}
	}
	return unique(found)
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range in {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

var (
	nameOKRE = regexp.MustCompile(`^[a-z0-9.-]+$`)
	hostOKRE = regexp.MustCompile(`^[a-z0-9-]+$`)
	ipv4RE   = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)
)

// ReverseNames returns the names devices may use for this machine on a VPN: the VPN's own DNS name for the
// address (PTR, e.g. MagicDNS), its first label, and this machine's hostname.
func (d *Detector) ReverseNames(ip string) []string {
	var names []string
	for _, server := range d.Nameservers() {
		name := d.PTR(ip, server, 1500*time.Millisecond)
		if name != "" && nameOKRE.MatchString(name) && !strings.HasSuffix(name, ".arpa") && !strings.HasSuffix(name, "localhost") {
			first, _, _ := strings.Cut(name, ".")
			names = append(names, name, first)
			break
		}
	}
	if h, err := d.Hostname(); err == nil {
		first, _, _ := strings.Cut(h, ".")
		if first = strings.ToLower(first); hostOKRE.MatchString(first) {
			names = append(names, first)
		}
	}
	return unique(names)
}

// DetectVPN returns the addresses and names of the VPNs you trusted (OM_VPN). No VPN is trusted by itself: a
// tunnel may be a commercial or company VPN or a public network, and om cannot tell without root.
func (d *Detector) DetectVPN(spec string) (ips, names []string) {
	for _, item := range VPNItems(spec) {
		if ipv4RE.MatchString(item) {
			if d.IsLocal(item) {
				ips = append(ips, item)
			}
		} else if ip := d.IfaceIPv4(item); ip != "" && d.IsLocal(ip) {
			ips = append(ips, ip)
		}
	}
	ips = unique(ips)
	for _, ip := range ips {
		names = append(names, d.ReverseNames(ip)...)
	}
	return ips, unique(names)
}
