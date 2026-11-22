package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Chitakasa/om/internal/py"
)

// complement returns every address of that IP version outside nets, as the fewest CIDR blocks, in ascending order
// (Windows block rules cannot say `not`).
func complement(nets []string, bits int) []string {
	type iv struct{ lo, hi *big.Int }
	var cov []iv
	for _, n := range nets {
		p, ok := parseNet(n)
		if !ok || p.Addr().BitLen() != bits {
			continue
		}
		lo := new(big.Int).SetBytes(p.Masked().Addr().AsSlice())
		size := new(big.Int).Lsh(big.NewInt(1), uint(bits-p.Bits()))
		hi := new(big.Int).Sub(new(big.Int).Add(lo, size), big.NewInt(1))
		cov = append(cov, iv{lo, hi})
	}
	sort.Slice(cov, func(i, j int) bool { return cov[i].lo.Cmp(cov[j].lo) < 0 })
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits)), big.NewInt(1))
	var free []iv
	next := big.NewInt(0)
	for _, c := range cov {
		if c.lo.Cmp(next) > 0 {
			free = append(free, iv{new(big.Int).Set(next), new(big.Int).Sub(c.lo, big.NewInt(1))})
		}
		if e := new(big.Int).Add(c.hi, big.NewInt(1)); e.Cmp(next) > 0 {
			next = e
		}
	}
	if next.Cmp(max) <= 0 {
		free = append(free, iv{next, max})
	}
	var out []string
	for _, f := range free {
		out = append(out, cidrs(f.lo, f.hi, bits)...)
	}
	return out
}

// cidrs splits [lo, hi] into the fewest aligned CIDR blocks.
func cidrs(lo, hi *big.Int, bits int) []string {
	var out []string
	one := big.NewInt(1)
	cur := new(big.Int).Set(lo)
	for cur.Cmp(hi) <= 0 {
		// the largest block that starts at cur (alignment) and still fits
		k := 0
		for k < bits {
			size := new(big.Int).Lsh(one, uint(k+1))
			if new(big.Int).Mod(cur, size).Sign() != 0 {
				break
			}
			end := new(big.Int).Sub(new(big.Int).Add(cur, size), one)
			if end.Cmp(hi) > 0 {
				break
			}
			k++
		}
		b := cur.FillBytes(make([]byte, bits/8))
		a, _ := netip.AddrFromSlice(b)
		out = append(out, netip.PrefixFrom(a, bits-k).String())
		cur.Add(cur, new(big.Int).Lsh(one, uint(k)))
	}
	return out
}

// WinNetRule is a Windows firewall rule: its display name and the PowerShell line that creates it.
type WinNetRule struct{ Name, Line string }

// WinNetRules returns the Windows rules of one address rule; the name carries a digest of the rule, so a stale one
// is seen.
func (f *Firewall) WinNetRules(key string, pol Policy) []WinNetRule {
	pol = f.expand(pol)
	sum := sha256.Sum256([]byte(py.DumpsCompact(map[string]any(pol))))
	digest := hex.EncodeToString(sum[:])[:8]
	local := ""
	if d := list(pol["daddr"]); len(d) > 0 {
		local = " -LocalAddress " + join(d, ",")
	}
	type block struct {
		kind  string
		addrs []string
	}
	var blocks []block
	if !isNil(pol, "allow") {
		a4, a6 := byFamily(list(pol["allow"]))
		addrs := complement(a4, 32)
		if len(local) == 0 {
			addrs = append(addrs, complement(a6, 128)...)
		}
		blocks = append(blocks, block{"allow-only", addrs})
	}
	if d := list(pol["deny"]); len(d) > 0 {
		blocks = append(blocks, block{"deny", d})
	}
	var out []WinNetRule
	for _, pr := range []struct {
		proto string
		ports []string
	}{{"TCP", list(pol["ports"])}, {"UDP", list(pol["udp"])}} {
		for _, b := range blocks {
			if len(pr.ports) == 0 || len(b.addrs) == 0 {
				continue
			}
			udp := ""
			if pr.proto != "TCP" {
				udp = " udp"
			}
			name := "om net " + key + " " + b.kind + udp + " " + digest
			out = append(out, WinNetRule{name, `New-NetFirewallRule -Group "om" -DisplayName "` + name + `" -Direction Inbound -Protocol ` + pr.proto +
				local + " -LocalPort " + join(pr.ports, ",") + " -RemoteAddress " + join(b.addrs, ",") + " -Action Block | Out-Null"})
		}
	}
	return out
}

// VPNAllowEnforced: no VPN allow-list, or the firewall in effect carries it.
func (f *Firewall) VPNAllowEnforced() bool {
	rule := f.VPNRestriction()
	return rule == nil || f.NetPolicyEnforced("vpn", rule)
}

// NetPolicyEnforced reports that the host firewall in effect carries exactly this service's om.net rules.
func (f *Firewall) NetPolicyEnforced(key string, pol Policy) bool {
	switch {
	case f.linux():
		// The drops decide; the log lines beside them do not, so a firewall applied before logging existed still
		// counts as enforcing (om doctor reports the missing logging on its own).
		active := f.Status() == "active" // asked first, like Python's `firewall_status() == "active" and …`
		have := f.lineSet(f.NftInstalled)
		for _, fwd := range []bool{false, true} {
			for _, ln := range f.NftNetRules(key, pol, fwd) {
				if strings.HasSuffix(ln, " drop") && !have[ln] {
					return false
				}
			}
		}
		return active
	case f.macos():
		tables, rules := f.PfNetRules(key, pol)
		norm := func(s string) string { return strings.ReplaceAll(s, " in log quick ", " in quick ") }
		have := map[string]bool{}
		for _, ln := range py.SplitLines(f.read(f.PfInstalled)) {
			have[norm(ln)] = true
		}
		for _, ln := range append(tables, rules...) {
			if !have[norm(ln)] {
				return false
			}
		}
		return true
	case f.windows():
		r := f.Run([]string{"powershell", "-NoProfile", "-NonInteractive", "-Command",
			"Get-NetFirewallRule -Group om -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName"})
		have := map[string]bool{}
		if r.Code == 0 {
			for _, l := range py.SplitLines(r.Stdout) {
				have[l] = true
			}
		}
		for _, w := range f.WinNetRules(key, pol) {
			if !have[w.Name] {
				return false
			}
		}
		return true
	}
	return false
}

// LoggingApplied reports that the applied firewall logs refusals and connections; ok=false where om cannot tell
// (Windows).
func (f *Firewall) LoggingApplied() (applied, ok bool) {
	switch {
	case f.linux():
		return strings.Contains(f.read(f.NftInstalled), `log prefix "om-in: "`), true
	case f.macos():
		return strings.Contains(f.read(f.PfInstalled), "block in log all"), true
	}
	return false, false
}

var omNetRE = regexp.MustCompile(`# om\.net: (\S+)`)

// StaleNetRules lists the rules the applied firewall still carries although their om.net labels or OM_VPN_ALLOW
// changed or are gone.
func (f *Firewall) StaleNetRules() []string {
	text := ""
	switch {
	case f.linux():
		text = f.read(f.NftInstalled)
	case f.macos():
		text = f.read(f.PfInstalled)
	}
	pols := map[string]Policy{}
	for _, r := range f.Restrictions() {
		pols[r.Key] = r.Pol
	}
	set := map[string]bool{}
	for _, m := range omNetRE.FindAllStringSubmatch(text, -1) {
		set[m[1]] = true
	}
	applied := make([]string, 0, len(set))
	for k := range set {
		applied = append(applied, k)
	}
	sort.Strings(applied)
	var out []string
	for _, k := range applied {
		if p, ok := pols[k]; !ok || !f.NetPolicyEnforced(k, p) {
			out = append(out, k)
		}
	}
	return out
}

// RenderNft is the nft ruleset (Linux): inbound default-drop, own table.
func (f *Firewall) RenderNft(extraTCP, extraUDP []string) string {
	tcp := join(append(f.IngressTCP(), extraTCP...), ", ")
	udp := join(append(append(f.IngressUDP(), BaseUDP...), extraUDP...), ", ")
	ips := f.VPNIPs()
	priv, pub := ServicePortRanges()
	var vpnRule string
	if len(ips) > 0 {
		vpnRule = "# Public tier and every service's private port on VPN addresses only\n" +
			"        ip daddr { " + join(ips, ", ") + " } tcp dport { " + join(VPNPublicTCP, ", ") + ", " + priv + " } accept\n"
	} else {
		vpnRule = "# No VPN address: the public tier is on the LAN only\n"
	}
	vpnRule += "        # Public services' own ports (bound only on the LAN and VPN addresses)\n        tcp dport " + pub + " accept"
	stPriv, stPub := f.StreamFirewallPorts()
	if len(ips) > 0 && len(stPriv) > 0 {
		vpnRule += "\n        # Stream tier private ports on VPN addresses only\n" +
			"        ip daddr { " + join(ips, ", ") + " } tcp dport { " + join(stPriv, ", ") + " } accept"
	}
	if len(stPub) > 0 {
		vpnRule += "\n        # Stream tier public ports (bound on LAN and VPN addresses)\n" +
			"        tcp dport { " + join(stPub, ", ") + " } accept"
	}
	return "#!/usr/sbin/nft -f\n" +
		"# GENERATED by `om firewall` — edit OM_FIREWALL_EXTRA_* in " + f.D.UserEnv + " instead.\n" +
		"# Inbound default-drop. Only om's front door (Caddy 80/443) and the listed system\n" +
		"# ports are reachable; anything else listening on this host is not.\n" +
		"# Own table: never touches a VPN's or the container engine's rules.\n\n" +
		"table inet om_guard\ndelete table inet om_guard\n\n" +
		"table inet om_guard {\n    chain input {\n        type filter hook input priority filter - 10; policy drop;\n\n" +
		"        iifname \"lo\" accept\n        ct state invalid drop\n\n" +
		f.nftNetBlock(false) + "        ct state { established, related } accept\n\n" +
		"        # IPv6 needs neighbor discovery; ICMP errors keep TCP healthy (PMTU)\n" +
		"        icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, packet-too-big, destination-unreachable, time-exceeded, parameter-problem } accept\n" +
		"        icmp type { destination-unreachable, time-exceeded, parameter-problem } accept\n\n" +
		"        # DHCP replies\n        udp sport 67 udp dport 68 accept\n        udp sport 547 udp dport 546 accept\n\n" +
		"        # mDNS (.local names) on Ethernet/Wi-Fi only, never over a tunnel\n        iiftype ether udp dport 5353 accept\n\n" +
		"        # Front door + user extras\n        tcp dport { " + tcp + " } accept\n        udp dport { " + udp + " } accept\n        " + vpnRule + "\n\n" +
		"        # Anything else unsolicited is dropped by the policy; log it first (unicast to this host only)\n" +
		"        meta pkttype host ct state new " + LogLimit + " log prefix \"om-refused: \" level info\n    }\n" +
		f.nftForwardChain() + f.nftVPNFallbackChain() + "}\n"
}

func pfPort(p string) string { return strings.ReplaceAll(p, "-", ":") }

// RenderPf is the macOS pf anchor.
func (f *Firewall) RenderPf(extraTCP, extraUDP []string) string {
	conv := func(l []string) string {
		o := make([]string, len(l))
		for i, p := range l {
			o[i] = pfPort(p)
		}
		return join(o, " ")
	}
	tcp := conv(append(f.IngressTCP(), extraTCP...))
	udp := conv(append(append(append(f.IngressUDP(), BaseUDP...), "5353"), extraUDP...))
	var tables, blocks, rdr strings.Builder
	var net [][2][]string
	for _, r := range f.Restrictions() {
		t, ru := f.PfNetRules(r.Key, r.Pol)
		net = append(net, [2][]string{t, ru})
	}
	for _, n := range net {
		for _, ln := range n[0] {
			tables.WriteString(ln + "\n")
		}
	}
	for _, n := range net {
		for _, ln := range n[1] {
			blocks.WriteString(ln + "\n")
		}
	}
	for _, ln := range f.PfVPNFallback() { // translation before filtering (pf's order)
		rdr.WriteString(ln + "\n")
	}
	stPriv, stPub := f.StreamFirewallPorts()
	stRules := ""
	if len(stPriv) > 0 {
		for _, ip := range f.VPNIPs() {
			stRules += "pass in proto tcp to " + ip + " port { " + conv(stPriv) + " } keep state\n"
		}
	}
	if len(stPub) > 0 {
		stRules += "pass in proto tcp to any port { " + conv(stPub) + " } keep state\n"
	}
	priv, pub := ServicePortRanges()
	out := "# GENERATED by `om firewall` (macOS pf anchor \"om\").\n" +
		"# Inbound default-block; only the om front door and listed ports are reachable.\n" +
		"set skip on lo0\n" +
		tables.String() + rdr.String() + "block in log all\n" +
		blocks.String() + "pass out all keep state\n" +
		"pass in inet proto icmp all icmp-type { unreach, timex, paramprob }\n" +
		"pass in inet6 proto ipv6-icmp all\n" +
		"pass in proto udp from any port 67 to any port 68\n" +
		"pass in proto tcp to any port { " + tcp + " } keep state\n" +
		"pass in proto udp to any port { " + udp + " } keep state\n"
	for _, ip := range f.VPNIPs() {
		out += "pass in proto tcp to " + ip + " port { " + join(VPNPublicTCP, " ") + " " + pfPort(priv) + " } keep state\n"
	}
	return out + "pass in proto tcp to any port " + pfPort(pub) + " keep state\n" + stRules
}

// RenderWindows is the PowerShell script of the Windows firewall rules.
func (f *Firewall) RenderWindows(extraTCP, extraUDP []string) string {
	tcp := join(append(f.IngressTCP(), extraTCP...), ",")
	udp := join(append(append(f.IngressUDP(), BaseUDP...), extraUDP...), ",")
	ips := f.VPNIPs()
	priv, pub := ServicePortRanges()
	vpnRule := ""
	if len(ips) > 0 {
		vpnRule = `New-NetFirewallRule -Group "om" -DisplayName "om public tier and service ports (VPN)" -Direction Inbound -Protocol TCP ` +
			"-LocalAddress " + join(ips, ",") + " -LocalPort " + join(VPNPublicTCP, ",") + "," + priv + " -Action Allow | Out-Null\n"
	}
	vpnRule += `New-NetFirewallRule -Group "om" -DisplayName "om public service ports" -Direction Inbound -Protocol TCP ` +
		"-LocalPort " + pub + " -Action Allow | Out-Null\n"
	stPriv, stPub := f.StreamFirewallPorts()
	if len(ips) > 0 && len(stPriv) > 0 {
		vpnRule += `New-NetFirewallRule -Group "om" -DisplayName "om stream ports (VPN)" -Direction Inbound -Protocol TCP ` +
			"-LocalAddress " + join(ips, ",") + " -LocalPort " + join(stPriv, ",") + " -Action Allow | Out-Null\n"
	}
	if len(stPub) > 0 {
		vpnRule += `New-NetFirewallRule -Group "om" -DisplayName "om public stream ports" -Direction Inbound -Protocol TCP ` +
			"-LocalPort " + join(stPub, ",") + " -Action Allow | Out-Null\n"
	}
	var net strings.Builder
	for _, r := range f.Restrictions() {
		for _, w := range f.WinNetRules(r.Key, r.Pol) {
			net.WriteString(w.Line + "\n")
		}
	}
	return "# GENERATED by `om firewall`. Run from an elevated PowerShell:\n" +
		"#   powershell -ExecutionPolicy Bypass -File \"" + filepath.Join(f.D.Firewall, "om-firewall.ps1") + "\"\n" +
		"# Blocks unsolicited inbound traffic on all profiles and allows only om's ports.\n" +
		"# Note: other programs' existing \"allow\" rules still apply; review them with\n" +
		"#   Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True\n" +
		"$ErrorActionPreference = \"Stop\"\n" +
		"Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow\n" +
		"Set-NetFirewallProfile -All -LogBlocked True -LogMaxSizeKilobytes 16384\n" +
		"Get-NetFirewallRule -Group \"om\" -ErrorAction SilentlyContinue | Remove-NetFirewallRule\n" +
		"New-NetFirewallRule -Group \"om\" -DisplayName \"om ingress (TCP)\" -Direction Inbound -Protocol TCP -LocalPort " + tcp + " -Action Allow | Out-Null\n" +
		"New-NetFirewallRule -Group \"om\" -DisplayName \"om ingress (UDP)\" -Direction Inbound -Protocol UDP -LocalPort " + udp + " -Action Allow | Out-Null\n" +
		vpnRule + net.String() + "Write-Host \"om firewall applied.\"\n"
}

// SystemdUnit is the unit that applies the nft ruleset at boot (Linux).
const SystemdUnit = `[Unit]
Description=om host firewall (inbound default-drop, only om ingress exposed)
Wants=network-pre.target
Before=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/env nft -f /etc/om-firewall.nft
ExecStop=/usr/bin/env nft delete table inet om_guard

[Install]
WantedBy=multi-user.target
`

// Generate writes the firewall file for this OS under the firewall folder and returns its path.
func (f *Firewall) Generate() (string, error) {
	tcp, udp := Ports(f.ExtraTCP()), Ports(f.ExtraUDP())
	if err := os.MkdirAll(f.D.Firewall, 0o755); err != nil {
		return "", err
	}
	var path, text string
	switch {
	case f.linux():
		path, text = filepath.Join(f.D.Firewall, "om.nft"), f.RenderNft(tcp, udp)
		if err := os.WriteFile(filepath.Join(f.D.Firewall, "om-firewall.service"), []byte(SystemdUnit), 0o644); err != nil {
			return "", err
		}
	case f.macos():
		path, text = filepath.Join(f.D.Firewall, "om.pf"), f.RenderPf(tcp, udp)
	default:
		path, text = filepath.Join(f.D.Firewall, "om-firewall.ps1"), f.RenderWindows(tcp, udp)
	}
	return path, os.WriteFile(path, []byte(text), 0o644)
}
