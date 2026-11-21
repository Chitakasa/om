// Package settings is om.env: the template, `auto`/`off`/value settings, the edge ports, the edge token and the
// VPN allow-list. Port of the pure part of lib/gitops/omsettings.py; address detection and the generated
// runtime files (runtime.env, ports.yml) arrive with the host package.
package settings

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Chitakasa/om/internal/state"
)

// UserEnvTemplate is the default om.env: every setting with its documented default.
//
//go:embed om.env.tmpl
var UserEnvTemplate string

// Settings is the merged view of the template defaults and the user's om.env.
type Settings map[string]string

// ParseText reads KEY=VALUE lines without unquoting (the template is trusted text).
func ParseText(text string) Settings {
	out := Settings{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") && strings.Contains(line, "=") {
			k, v, _ := strings.Cut(line, "=")
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

// Load merges the user's om.env over the template. Empty user values keep the default; the pre-1.0 name LAN_IP
// still maps to OM_LAN_IP.
func Load(d state.Dirs) (Settings, error) {
	raw, err := state.ParseEnvFile(d.UserEnv)
	if err != nil {
		return nil, err
	}
	if v, ok := raw["LAN_IP"]; ok {
		if _, has := raw["OM_LAN_IP"]; !has {
			raw["OM_LAN_IP"] = v
		}
	}
	s := ParseText(UserEnvTemplate)
	for k, v := range raw {
		if v != "" {
			s[k] = v
		}
	}
	return s, nil
}

// Get returns a setting or def when absent.
func (s Settings) Get(key, def string) string {
	if v, ok := s[key]; ok {
		return v
	}
	return def
}

// EdgePorts returns the (http, https) host ports of the edge. Invalid values fall back to 80/443.
func (s Settings) EdgePorts() (int, int) {
	pick := func(key string, def int) int {
		v := s.Get(key, strconv.Itoa(def))
		if state.IsNumber(v) {
			if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 65535 {
				return n
			}
		}
		return def
	}
	return pick("OM_HTTP_PORT", 80), pick("OM_HTTPS_PORT", 443)
}

// BaseURL is the http URL of a host on the private tier, with the port only when it is not 80.
func (s Settings) BaseURL(host string) string {
	if host == "" {
		host = "localhost"
	}
	h, _ := s.EdgePorts()
	if h == 80 {
		return "http://" + host
	}
	return "http://" + host + ":" + strconv.Itoa(h)
}

var tokenRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// EdgeToken is the shared secret proving a request came through the edge proxy. Created once.
func EdgeToken(d state.Dirs) (string, error) {
	if b, err := os.ReadFile(d.TokenFile); err == nil {
		if tok := strings.TrimSpace(string(b)); tokenRE.MatchString(tok) {
			return tok, nil
		}
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(buf)
	return tok, state.WritePrivate(d.TokenFile, tok+"\n")
}

// Set writes KEY=value into the user's om.env, keeping every other line. A setting is one line: a control
// character (a newline would add a setting) is refused. The file is 0600: OM_NOTIFY_URL is a bearer-like secret.
func Set(d state.Dirs, key, value string) error {
	for _, r := range key + value {
		if r < 32 || r == 127 {
			return fmt.Errorf("%s: a setting is one line, without control characters", key)
		}
	}
	var lines []string
	if b, err := os.ReadFile(d.UserEnv); err == nil {
		lines = splitLines(string(b))
	}
	kept := lines[:0:0]
	for _, ln := range lines {
		if !strings.HasPrefix(ln, key+"=") {
			kept = append(kept, ln)
		}
	}
	kept = append(kept, key+"="+value)
	return state.WritePrivate(d.UserEnv, strings.Join(kept, "\n")+"\n")
}

// splitLines splits like Python's str.splitlines for the separators a text file can hold (\n, \r\n, \r).
func splitLines(s string) []string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// VPNAllow returns OM_VPN_ALLOW as normalized, de-duplicated networks. Invalid entries are dropped
// (`om vpn allow` validates).
func (s Settings) VPNAllow() []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range strings.Split(s.Get("OM_VPN_ALLOW", ""), ",") {
		n, ok := ParseNetwork(x)
		if !ok || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// ParseNetwork normalizes an address or CIDR network like Python's ipaddress.ip_network(x, strict=False):
// host bits are cleared, a bare address is a /32 or /128, and an IPv4 netmask or hostmask is accepted as the
// prefix length. A scope id ("fe80::1%eth0") is refused: no firewall rule can carry it.
func ParseNetwork(x string) (string, bool) {
	x = strings.TrimSpace(x)
	if x == "" || strings.Contains(x, "%") {
		return "", false
	}
	addrPart, maskPart, hasMask := strings.Cut(x, "/")
	addr, err := netip.ParseAddr(addrPart)
	if err != nil {
		return "", false
	}
	bits := addr.BitLen()
	if hasMask {
		switch {
		case maskPart == "" || !addr.Is4() && strings.Contains(maskPart, "."):
			return "", false
		case strings.Contains(maskPart, "."):
			b, ok := v4MaskBits(maskPart)
			if !ok {
				return "", false
			}
			bits = b
		case state.IsNumber(maskPart):
			n, err := strconv.Atoi(maskPart)
			if err != nil || n > addr.BitLen() {
				return "", false
			}
			bits = n
		default:
			return "", false
		}
	}
	p, err := addr.Prefix(bits)
	if err != nil {
		return "", false
	}
	return p.String(), true
}

// v4MaskBits reads a dotted netmask (255.255.255.0) or hostmask (0.0.0.255) as a prefix length; a netmask wins
// when both fit (0.0.0.0 is /0), as in Python's ipaddress.
func v4MaskBits(m string) (int, bool) {
	a, err := netip.ParseAddr(m)
	if err != nil || !a.Is4() {
		return 0, false
	}
	b := a.As4()
	v := uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])
	for n := 0; n <= 32; n++ {
		if v == (uint64(0xFFFFFFFF)<<(32-n))&0xFFFFFFFF {
			return n, true
		}
	}
	for k := 0; k <= 32; k++ {
		if v == (uint64(1)<<k)-1 {
			return 32 - k, true
		}
	}
	return 0, false
}

// ComposePath renders a host path the way compose volume specs want it on every OS: forward slashes.
func ComposePath(p string) string { return filepath.ToSlash(p) }

// VPNHosts returns the VPN addresses and names the running core answers to (from runtime.env), names last.
func VPNHosts(d state.Dirs) []string {
	env, _ := state.ParseEnvFile(d.RuntimeEnv)
	var out []string
	for _, h := range strings.Split(env["VPN_HOSTS"], ",") {
		if h != "" && !strings.HasSuffix(h, ".invalid") {
			out = append(out, h)
		}
	}
	return out
}
