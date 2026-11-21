package settings

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Chitakasa/om/internal/netdetect"
	"github.com/Chitakasa/om/internal/state"
)

// Resolved is the settings turned into concrete values for this boot ('auto' and 'off' resolved).
type Resolved struct {
	LANIP            string
	VPNIPs           []string
	VPNNames         []string
	WallpapersDir    string
	HTTPPort         int
	HTTPSPort        int
	FirewallExtraTCP string
	FirewallExtraUDP string
	// VPNPrivate is false while an OM_VPN_ALLOW the firewall does not enforce yet leaves the VPN's private tier
	// unbound. Resolve sets it true; the caller (which knows the firewall) may clear it.
	VPNPrivate bool
}

// Resolve turns 'auto'/'off' settings into concrete values for this boot.
func (s Settings) Resolve(d state.Dirs, det *netdetect.Detector) Resolved {
	var r Resolved
	switch lan := strings.ToLower(s.Get("OM_LAN_IP", "auto")); lan {
	case "off":
		r.LANIP = ""
	case "auto":
		r.LANIP = det.LANIP()
	default:
		r.LANIP = lan
	}
	r.VPNIPs, r.VPNNames = det.DetectVPN(s.Get("OM_VPN", "auto"))
	wp := s.Get("OM_WALLPAPERS_DIR", "auto")
	if strings.ToLower(wp) == "auto" {
		cand := filepath.Join(homeDir(), "Pictures", "Wallpapers")
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			wp = cand
		} else {
			wp = filepath.Join(d.Data, "wallpapers")
		}
	}
	r.WallpapersDir = filepath.Clean(expandUser(wp))
	r.HTTPPort, r.HTTPSPort = s.EdgePorts()
	r.FirewallExtraTCP = s.Get("OM_FIREWALL_EXTRA_TCP", "")
	r.FirewallExtraUDP = s.Get("OM_FIREWALL_EXTRA_UDP", "")
	r.VPNPrivate = true
	return r
}

func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return h
}

// expandUser is os.path.expanduser for a leading "~" or "~/".
func expandUser(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		return homeDir() + p[1:]
	}
	return p
}

// Hooks are what rendering the edge's port bindings needs from the rest of om.
type Hooks struct {
	// IsLocal reports whether an address is assigned to this host (used for ::1).
	IsLocal func(ip string) bool
	// StreamPorts are the raw TCP reservations keyed "<ws>/<svc>"; NetPolicies the services with om.net.*.
	StreamPorts func() map[string]StreamPort
	NetPolicies func() map[string]map[string]any
	// NetPolicyEnforced reports whether the host firewall carries a service's address rule.
	NetPolicyEnforced func(key string, policy map[string]any) bool
}

// StreamPort is one stream reservation as far as port rendering needs it.
type StreamPort struct {
	HostPort int
	Scope    string
}

func unique(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, x := range in {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func portRange(base int) string {
	return strconv.Itoa(base) + "-" + strconv.Itoa(base+state.PortSlots-1)
}

// httpBinds are the edge (HTTP) bindings: loopback and VPN addresses give the private tier, the LAN the public
// tier, and VPN addresses also the public tier on 8080/8443.
func httpBinds(r Resolved, h Hooks) []string {
	ht, hs := strconv.Itoa(r.HTTPPort), strconv.Itoa(r.HTTPSPort)
	priv, pub := portRange(state.PrivatePortBase), portRange(state.PublicPortBase)
	// per-service ports (own origin each, see ServicePorts) beside the front door
	binds := []string{"127.0.0.1:" + ht + ":80", "127.0.0.1:" + hs + ":443", "127.0.0.1:" + priv + ":" + priv}
	if h.IsLocal("::1") {
		binds = append(binds, "[::1]:"+ht+":80", "[::1]:"+hs+":443", "[::1]:"+priv+":"+priv)
	}
	vh, vs := strconv.Itoa(state.VPNHTTPPort), strconv.Itoa(state.VPNHTTPSPort)
	for _, ip := range r.VPNIPs {
		private := []string{ip + ":" + ht + ":" + vh, ip + ":" + hs + ":" + vs, ip + ":" + hs + ":" + vs + "/udp", ip + ":" + priv + ":" + priv}
		if !r.VPNPrivate { // an OM_VPN_ALLOW the firewall does not enforce yet: not bound
			private = nil
		}
		binds = append(binds, head(private, 3)...)
		binds = append(binds, ip+":8080:8080", ip+":8443:8443")
		binds = append(binds, tail(private, 3)...)
		binds = append(binds, ip+":"+pub+":"+pub)
	}
	if r.LANIP != "" && !contains(r.VPNIPs, r.LANIP) {
		binds = append(binds, r.LANIP+":"+ht+":8080", r.LANIP+":"+hs+":8443", r.LANIP+":"+hs+":8443/udp", r.LANIP+":"+pub+":"+pub)
	}
	return binds
}

func head(l []string, n int) []string {
	if len(l) < n {
		return l
	}
	return l[:n]
}

func tail(l []string, n int) []string {
	if len(l) < n {
		return nil
	}
	return l[n:]
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// streamBindsFor are the bindings of one stream port (or range): loopback, trusted VPN addresses, and the LAN
// address if public.
func streamBindsFor(r Resolved, h Hooks, port string, public bool) []string {
	binds := []string{"127.0.0.1:" + port + ":" + port}
	if h.IsLocal("::1") {
		binds = append(binds, "[::1]:"+port+":"+port)
	}
	if r.VPNPrivate {
		for _, ip := range r.VPNIPs {
			binds = append(binds, ip+":"+port+":"+port)
		}
	}
	if public && r.LANIP != "" && !contains(r.VPNIPs, r.LANIP) {
		binds = append(binds, r.LANIP+":"+port+":"+port)
	}
	return binds
}

// streamBinds are the raw TCP stream bindings: the default range (22000-22199) on loopback and VPN, and on the
// LAN too; plus the explicit ports (e.g. 25565) reserved in stream_ports.json, whose LAN binding needs a public
// scope and whose address policy must be enforced by the firewall.
func streamBinds(r Resolved, h Hooks) []string {
	def := strconv.Itoa(state.StreamPortBase) + "-" + strconv.Itoa(state.StreamPortBase+state.StreamPortSlots-1)
	binds := streamBindsFor(r, h, def, true)
	ports := h.StreamPorts()
	keys := make([]string, 0, len(ports))
	for k := range ports {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, key := range keys {
		info := ports[key]
		hp := info.HostPort
		if hp == 0 || (hp >= state.StreamPortBase && hp <= state.StreamPortBase+state.StreamPortSlots-1) {
			continue
		}
		if pol := h.NetPolicies()[key]; len(pol) > 0 && !h.NetPolicyEnforced(key, pol) {
			continue
		}
		scope := info.Scope
		if scope == "" {
			scope = "private"
		}
		binds = append(binds, streamBindsFor(r, h, strconv.Itoa(hp), scope == "public")...)
	}
	return unique(binds)
}

// RenderPorts renders ports.yml: the edge port bindings. Loopback and VPN addresses reach the private tier
// (container :80/:443); the LAN the public tier (:8080/:8443) on the edge ports; VPN addresses also reach the
// public tier on 8080/8443, so a VPN's access rules can give a guest the public services only. Raw TCP stream
// ports: default range 22000-22199 on loopback and VPN (and LAN if public), plus explicit stream ports.
func RenderPorts(d state.Dirs, r Resolved, h Hooks) string {
	var lines, st strings.Builder
	for _, b := range httpBinds(r, h) {
		lines.WriteString("      - \"" + b + "\"\n")
	}
	for _, b := range streamBinds(r, h) {
		st.WriteString("      - \"" + b + "\"\n")
	}
	return "# GENERATED by `om core start` from " + d.UserEnv + " — do not edit.\n" +
		"services:\n  caddy:\n    ports:\n" + lines.String() +
		"  stream_edge:\n    ports:\n" + st.String()
}
