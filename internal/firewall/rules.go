// Package firewall is om's host firewall: per-service source-address rules (om.net.allow / om.net.deny), the VPN
// device allow-list, connection logging, and the nft (Linux), pf (macOS) and PowerShell (Windows) renderings of
// them. Port of the firewall half of lib/gitops/hostsetup.py.
//
// Per-service source addresses: the host firewall is the only place that sees who connects, so each service's own
// ports get their own rules. A refused address gets no answer at all: its packets are dropped before anything
// listens. This machine (loopback) is always allowed.
package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/registry"
	"github.com/Chitakasa/om/internal/state"
)

// Policy is one address rule, shaped like the dict Python passes around: "ports" (tcp), "udp", "daddr" (local
// addresses), "allow" (nil: no allow-list) and "deny".
type Policy = map[string]any

const (
	LogLimit   = "limit rate 20/minute burst 30 packets"
	InLogLimit = "limit rate 120/minute burst 240 packets"
)

// VPNPublicTCP is the public tier on VPN addresses (settings.RenderPorts).
var VPNPublicTCP = []string{"8080", "8443"}

// BaseUDP: VPN transports need no rule, their peers answer outgoing packets (conntrack).
var BaseUDP []string

// Firewall renders and applies the host firewall. Everything it reads from the rest of om comes in through the
// function fields, so tests can supply it.
type Firewall struct {
	D   state.Dirs
	Reg registry.Registry
	// EdgePorts are the front door's host ports (OM_HTTP_PORT, OM_HTTPS_PORT).
	EdgePorts func() (int, int)
	// VPNIPs are the trusted VPN addresses; VPNAllow is OM_VPN_ALLOW; Extra the user's extra ports (raw settings).
	VPNIPs   func() []string
	VPNAllow func() []string
	ExtraTCP func() string
	ExtraUDP func() string

	OS           string
	Run          func([]string) state.Result
	LookPath     func(string) (string, error)
	ReadFile     func(string) (string, error)
	NftInstalled string
	PfInstalled  string
	Out          io.Writer
	// Sudo runs a command as root and reports success; the default prints `$ sudo …` and runs it on the terminal.
	Sudo func(cmd []string) bool
}

// New returns a Firewall for this machine; the caller sets the settings-backed functions.
func New(d state.Dirs, reg registry.Registry, goos string) *Firewall {
	f := &Firewall{D: d, Reg: reg, OS: goos, Run: func(c []string) state.Result { return state.Run(c) },
		LookPath: exec.LookPath, NftInstalled: "/etc/om-firewall.nft", PfInstalled: "/etc/pf.anchors/om", Out: os.Stdout}
	f.ReadFile = py.ReadText
	f.Sudo = func(cmd []string) bool {
		fmt.Fprintf(f.Out, "  $ sudo %s\n", strings.Join(cmd, " "))
		c := exec.Command("sudo", cmd...)
		c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
		return c.Run() == nil
	}
	return f
}

func (f *Firewall) read(path string) string {
	s, err := f.ReadFile(path)
	if err != nil {
		return ""
	}
	return s
}

func (f *Firewall) linux() bool   { return f.OS == "linux" }
func (f *Firewall) macos() bool   { return f.OS == "darwin" }
func (f *Firewall) windows() bool { return f.OS == "windows" }

func list(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, len(x))
		for i, e := range x {
			out[i] = py.Str(e)
		}
		return out
	}
	return nil
}

func isNil(p Policy, key string) bool {
	v, ok := p[key]
	return !ok || v == nil
}

// IngressTCP is the front door's host ports.
func (f *Firewall) IngressTCP() []string {
	h, s := f.EdgePorts()
	return []string{strconv.Itoa(h), strconv.Itoa(s)}
}

// IngressUDP is HTTP/3.
func (f *Firewall) IngressUDP() []string {
	_, s := f.EdgePorts()
	return []string{strconv.Itoa(s)}
}

// ServicePortRanges are the per-service private (loopback, VPN) and public (LAN, VPN) port ranges.
func ServicePortRanges() (string, string) {
	return fmt.Sprintf("%d-%d", state.PrivatePortBase, state.PrivatePortBase+state.PortSlots-1),
		fmt.Sprintf("%d-%d", state.PublicPortBase, state.PublicPortBase+state.PortSlots-1)
}

// StreamFirewallPorts returns (private_ports, public_ports) for stream services. The default range 22000-22199 is
// private; explicit stream ports are private or public by their scope.
func (f *Firewall) StreamFirewallPorts() (priv, pub []string) {
	def := fmt.Sprintf("%d-%d", state.StreamPortBase, state.StreamPortBase+state.StreamPortSlots-1)
	priv = []string{def}
	ports := f.Reg.StreamPorts()
	keys := make([]string, 0, len(ports))
	for k := range ports {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	add := func(l *[]string, s string) {
		for _, x := range *l {
			if x == s {
				return
			}
		}
		*l = append(*l, s)
	}
	for _, k := range keys {
		info := ports[k]
		if info.HostPort == 0 {
			continue
		}
		scope := info.Scope
		if scope == "" {
			scope = "private"
		}
		s := strconv.Itoa(info.HostPort)
		inDefault := info.HostPort >= state.StreamPortBase && info.HostPort <= state.StreamPortBase+state.StreamPortSlots-1
		switch {
		case inDefault && scope == "public", !inDefault && scope == "public":
			add(&pub, s)
		case !inDefault:
			add(&priv, s)
		}
	}
	return priv, pub
}

var portSpecRE = regexp.MustCompile(`^[0-9]{1,5}(-[0-9]{1,5})?$`)

// Ports keeps the valid entries (`80` or `1714-1764`) of a comma list.
func Ports(spec string) []string {
	var out []string
	for _, p := range strings.Split(strings.ReplaceAll(spec, " ", ""), ",") {
		if portSpecRE.MatchString(p) {
			out = append(out, p)
		}
	}
	return out
}

// expand turns om.net.allow=vpn into the devices on the VPN allow-list now.
func (f *Firewall) expand(pol Policy) Policy {
	allow, ok := pol["allow"]
	if !ok || allow == nil {
		return pol
	}
	l := list(allow)
	has := false
	for _, a := range l {
		has = has || a == "vpn"
	}
	if !has {
		return pol
	}
	var merged []any
	seen := map[string]bool{}
	for _, a := range append(without(l, "vpn"), f.VPNAllow()...) {
		if !seen[a] {
			seen[a] = true
			merged = append(merged, a)
		}
	}
	out := Policy{}
	for k, v := range pol {
		out[k] = v
	}
	if merged == nil {
		merged = []any{}
	}
	out["allow"] = merged
	return out
}

func without(l []string, s string) []string {
	var out []string
	for _, x := range l {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}

func parseNet(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

func byFamily(nets []string) (v4, v6 []string) {
	for _, n := range nets {
		p, ok := parseNet(n)
		if !ok {
			continue
		}
		if p.Addr().Is4() {
			v4 = append(v4, p.String())
		} else {
			v6 = append(v6, p.String())
		}
	}
	return
}

func join(l []string, sep string) string { return strings.Join(l, sep) }

// NftNetRules returns the nft lines of one address rule. forward=true is the same rule for connections a rootful
// engine forwards to a container (DNAT): matched on the port and address the client connected to.
func (f *Firewall) NftNetRules(key string, pol Policy, forward bool) []string {
	pol = f.expand(pol)
	lines := []string{"# om.net: " + key}
	daddr := list(pol["daddr"])
	// Who opened the connection decides, and connections already open are cut too (these rules come before the
	// input chain's `established` accept): a removed device keeps nothing it had.
	src4, src6 := "ip saddr", "ip6 saddr"
	if forward {
		src4, src6 = "ct original ip saddr", "ct original ip6 saddr"
	}
	for _, pu := range []struct {
		l4    string
		ports []string
	}{{"tcp", list(pol["ports"])}, {"udp", list(pol["udp"])}} {
		if len(pu.ports) == 0 {
			continue
		}
		plist := join(pu.ports, ", ")
		var m string
		if forward {
			m = "meta l4proto " + pu.l4 + " ct status dnat "
			if len(daddr) > 0 {
				m += "ct original ip daddr { " + join(daddr, ", ") + " } "
			}
			m += "ct original proto-dst { " + plist + " }"
		} else {
			m = "ct direction original "
			if len(daddr) > 0 {
				m += "ip daddr { " + join(daddr, ", ") + " } "
			}
			m += pu.l4 + " dport { " + plist + " }"
		}
		if !isNil(pol, "allow") {
			a4, a6 := byFamily(list(pol["allow"]))
			if len(a4) > 0 {
				lines = append(lines, m+" "+src4+" != { "+join(a4, ", ")+" } drop")
			} else {
				lines = append(lines, m+" meta nfproto ipv4 drop")
			}
			if len(daddr) == 0 { // an IPv4 local address never sees IPv6 sources
				if len(a6) > 0 {
					lines = append(lines, m+" "+src6+" != { "+join(a6, ", ")+" } drop")
				} else {
					lines = append(lines, m+" meta nfproto ipv6 drop")
				}
			}
		}
		d4, d6 := byFamily(list(pol["deny"]))
		if len(d4) > 0 {
			lines = append(lines, m+" "+src4+" { "+join(d4, ", ")+" } drop")
		}
		if len(d6) > 0 && len(daddr) == 0 {
			lines = append(lines, m+" "+src6+" { "+join(d6, ", ")+" } drop")
		}
	}
	// Each drop is logged first, by its own rule: a `limit` on the drop itself would let packets over the rate fall
	// through to the accepts below.
	var out []string
	short := []rune(key)
	if len(short) > 96 {
		short = short[:96]
	}
	for _, ln := range lines {
		if strings.HasSuffix(ln, " drop") {
			out = append(out, strings.TrimSuffix(ln, " drop")+" "+LogLimit+` log prefix "om-refused `+string(short)+`: " level info`)
		}
		out = append(out, ln)
	}
	return out
}

// VPNRestriction is the VPN device allow-list (OM_VPN_ALLOW) as an address rule: on the VPN addresses, the private
// tier (front door and every service's private port) answers only the listed devices. The public tier stays. nil
// when there is no allow-list or no VPN address.
func (f *Firewall) VPNRestriction() Policy {
	allow, ips := f.VPNAllow(), f.VPNIPs()
	if len(allow) == 0 || len(ips) == 0 {
		return nil
	}
	h, s := f.EdgePorts()
	priv := []string{strconv.Itoa(h), strconv.Itoa(s), func() string { p, _ := ServicePortRanges(); return p }()}
	if len(f.Reg.StreamPorts()) > 0 {
		stPriv, _ := f.StreamFirewallPorts()
		for _, p := range stPriv {
			found := false
			for _, x := range priv {
				found = found || x == p
			}
			if !found {
				priv = append(priv, p)
			}
		}
	}
	return Policy{"daddr": ips, "ports": priv, "udp": []string{strconv.Itoa(s)}, "allow": allow, "deny": []string{}}
}

// vpnFallback returns the VPN's IPv4 addresses and the allowed IPv4 sources. A VPN device outside OM_VPN_ALLOW that
// opens the private tier's address (host 80/443) is sent to the public tier (8080/8443) at that address: it sees the
// public services instead of no answer. New connections only, so one opened while the device was allowed is still
// cut (input chain). Linux (nft dnat) and macOS (pf rdr); Windows Firewall cannot redirect.
func (f *Firewall) vpnFallback() (ips, a4 []string, ok bool) {
	rule := f.VPNRestriction()
	if rule == nil {
		return nil, nil, false
	}
	for _, ip := range list(rule["daddr"]) {
		if a, err := netip.ParseAddr(ip); err == nil && a.Is4() { // the VPN tiers bind IPv4 only
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return nil, nil, false
	}
	a4, _ = byFamily(list(rule["allow"]))
	return ips, a4, true
}

func (f *Firewall) edgePortStrings() []string { return f.IngressTCP() }

// NftVPNFallback is the dnat lines of the VPN fallback.
func (f *Firewall) NftVPNFallback() []string {
	ips, a4, ok := f.vpnFallback()
	if !ok {
		return nil
	}
	src := ""
	if len(a4) > 0 {
		src = "ip saddr != { " + join(a4, ", ") + " } "
	}
	var out []string
	ports := f.edgePortStrings()
	for _, ip := range ips {
		for i := 0; i < len(ports) && i < len(VPNPublicTCP); i++ {
			out = append(out, "ip daddr "+ip+" "+src+"tcp dport "+ports[i]+" dnat ip to "+ip+":"+VPNPublicTCP[i])
		}
	}
	return out
}

// PfVPNFallback is the rdr lines of the VPN fallback.
func (f *Firewall) PfVPNFallback() []string {
	ips, _, ok := f.vpnFallback()
	if !ok {
		return nil
	}
	var out []string
	ports := f.edgePortStrings()
	for _, ip := range ips {
		for i := 0; i < len(ports) && i < len(VPNPublicTCP); i++ {
			out = append(out, "rdr proto tcp from ! <"+PfTable("vpn", "allow")+"> to "+ip+" port "+ports[i]+" -> "+ip+" port "+VPNPublicTCP[i])
		}
	}
	return out
}

func (f *Firewall) lineSet(path string) map[string]bool {
	out := map[string]bool{}
	for _, ln := range py.SplitLines(f.read(path)) {
		out[py.Strip(ln)] = true
	}
	return out
}

// VPNFallbackApplied reports that the applied firewall sends VPN devices outside the allow-list to the public tier
// at the same address.
func (f *Firewall) VPNFallbackApplied() bool {
	var have map[string]bool
	var lines []string
	switch {
	case f.linux():
		have, lines = f.lineSet(f.NftInstalled), f.NftVPNFallback()
	case f.macos():
		have = map[string]bool{}
		for _, ln := range py.SplitLines(f.read(f.PfInstalled)) {
			have[ln] = true
		}
		lines = f.PfVPNFallback()
	default:
		return false
	}
	if len(lines) == 0 {
		return false
	}
	for _, ln := range lines {
		if !have[ln] {
			return false
		}
	}
	return true
}

// Restriction is a named address rule.
type Restriction struct {
	Key string
	Pol Policy
}

// Restrictions lists every address rule: per-service om.net policies (sorted), then the VPN device allow-list.
func (f *Firewall) Restrictions() []Restriction {
	pols := f.Reg.NetPolicies()
	keys := make([]string, 0, len(pols))
	for k := range pols {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []Restriction
	for _, k := range keys {
		out = append(out, Restriction{k, pols[k]})
	}
	if v := f.VPNRestriction(); v != nil {
		out = append(out, Restriction{"vpn", v})
	}
	return out
}

// OMPorts are the host ports om listens on: the front door, the VPN's public tier, every service's own ports.
func (f *Firewall) OMPorts() []string {
	priv, pub := ServicePortRanges()
	stPriv, stPub := f.StreamFirewallPorts()
	base := append(append(f.IngressTCP(), VPNPublicTCP...), priv, pub)
	for _, p := range append(append([]string{}, stPriv...), stPub...) {
		found := false
		for _, x := range base {
			found = found || x == p
		}
		if !found {
			base = append(base, p)
		}
	}
	return base
}

// NftInLog logs every new connection to om's ports (not to om.log=off services) with its real source.
func (f *Firewall) NftInLog(forward bool) string {
	ports := join(f.OMPorts(), ", ")
	var q []string
	for _, p := range f.Reg.NoLogPorts() {
		q = append(q, strconv.Itoa(p))
	}
	quiet := join(q, ", ")
	var m string
	if forward {
		m = "meta l4proto tcp ct state new ct status dnat ct original proto-dst { " + ports + " }"
		if quiet != "" {
			m += " ct original proto-dst != { " + quiet + " }"
		}
	} else {
		m = "ct state new tcp dport { " + ports + " }"
		if quiet != "" {
			m += " tcp dport != { " + quiet + " }"
		}
	}
	return m + " " + InLogLimit + ` log prefix "om-in: " level info`
}

func (f *Firewall) nftNetBlock(forward bool) string {
	var lines []string
	if rules := f.Restrictions(); len(rules) > 0 {
		lines = append(lines, "# Source addresses (om.net.allow / om.net.deny, OM_VPN_ALLOW): before every accept, open connections included")
		for _, r := range rules {
			lines = append(lines, f.NftNetRules(r.Key, r.Pol, forward)...)
		}
	}
	lines = append(lines, "# New connections to om's ports, with their real source (not om.log=off services)", f.NftInLog(forward))
	var b strings.Builder
	for _, ln := range lines {
		b.WriteString("        " + ln + "\n")
	}
	return b.String() + "\n"
}

// nftForwardChain: rootful engines (Docker, rootful Podman) publish ports by DNAT: those connections are forwarded
// to the container and never pass the input chain. The same rules (and logging) apply on that path; nothing else
// forwarded is touched.
func (f *Firewall) nftForwardChain() string {
	return "\n    chain forward {\n        type filter hook forward priority filter - 10; policy accept;\n\n" +
		strings.TrimRight(f.nftNetBlock(true), "\n") + "\n    }\n"
}

// nftVPNFallbackChain runs before the engine's own DNAT (a rootful engine's 8080 is then served by its userland
// proxy).
func (f *Firewall) nftVPNFallbackChain() string {
	lines := f.NftVPNFallback()
	if len(lines) == 0 {
		return ""
	}
	var b strings.Builder
	for _, ln := range lines {
		b.WriteString("        " + ln + "\n")
	}
	return "\n    # VPN devices not on OM_VPN_ALLOW that open the private tier's address get the public tier there\n" +
		"    chain vpn_public {\n        type nat hook prerouting priority dstnat - 10; policy accept;\n" + b.String() + "    }\n"
}

// PfTable is a pf table name (they are short).
func PfTable(key, kind string) string {
	sum := sha256.Sum256([]byte(key))
	return "om_" + hex.EncodeToString(sum[:])[:12] + "_" + kind
}

// PfNetRules returns the table definitions and the rules of one address rule. Tables, because pf expands
// `! { a b }` into rules that block everyone.
func (f *Firewall) PfNetRules(key string, pol Policy) (tables, rules []string) {
	pol = f.expand(pol)
	rules = []string{"# om.net: " + key}
	to := "to any"
	if d := list(pol["daddr"]); len(d) > 0 {
		to = "to { " + join(d, " ") + " }"
	}
	ta, td := PfTable(key, "allow"), PfTable(key, "deny")
	if !isNil(pol, "allow") {
		tables = append(tables, "table <"+ta+"> { "+join(list(pol["allow"]), " ")+" }")
	}
	if d := list(pol["deny"]); len(d) > 0 {
		tables = append(tables, "table <"+td+"> { "+join(d, " ")+" }")
	}
	for _, pr := range []struct {
		proto string
		ports []string
	}{{"tcp", list(pol["ports"])}, {"udp", list(pol["udp"])}} {
		if len(pr.ports) == 0 {
			continue
		}
		pl := make([]string, len(pr.ports))
		for i, p := range pr.ports {
			pl[i] = strings.ReplaceAll(p, "-", ":")
		}
		plist := join(pl, " ")
		if !isNil(pol, "allow") {
			rules = append(rules, "block drop in log quick proto "+pr.proto+" from ! <"+ta+"> "+to+" port { "+plist+" }")
		}
		if len(list(pol["deny"])) > 0 {
			rules = append(rules, "block drop in log quick proto "+pr.proto+" from <"+td+"> "+to+" port { "+plist+" }")
		}
	}
	return tables, rules
}
