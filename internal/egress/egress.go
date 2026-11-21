// Package egress is the outbound allow-list proxy (om_egress, Squid): see docs/adr/0002-egress-proxy.md and
// 0006-source-ip-egress.md. Workspace networks are internal, so a service's only way out is om_egress, and only to
// the hosts its `om.egress` label lists. Identity is a deterministic static source IP assigned to the container on
// its project network:
//
//	squid.conf             fixed base: deny private ranges, CONNECT only to 443, no cache, deny all
//	acl/<ws>.conf          per-service rules: `acl s_<id> src <ip>/32` + `dstdomain` allow rules
//	ips/<ws>.json          allocated static IPs per service (0600)
//	learn/<ws>_<svc>.json  learned host records and TTL tracking (0600)
//
// Port of lib/gitops/egress.py.
package egress

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/state"
)

const (
	Container = "om_egress"
	Port      = 3128
	Internet  = "internet"
	Learn     = "learn" // allow any public host and record it, to find out what a service needs
	Audit     = "audit" // allow any public host permanently and continuously record it

	DefaultLearnTTL = 86400 // 24 hours
)

var hostRE = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$`)

// BaseConf is the fixed part of squid.conf, kept verbatim from the Python implementation.
//
//go:embed squid.base.conf
var BaseConf string

var jvmImageKeywords = []string{
	"openjdk", "temurin", "corretto", "zulu", "graalvm", "java",
	"suwayomi", "minecraft", "paper", "purpur", "spigot", "forge", "fabric",
	"elasticsearch", "logstash", "solr", "jenkins", "kafka", "spark", "trino", "hadoop",
}

// Egress works on the egress state under one set of directories.
type Egress struct {
	D   state.Dirs
	Run func([]string) state.Result
	Now func() time.Time
	// Notify tells the user something (title, body, de-duplication key). Optional.
	Notify func(title, body, key string)
}

// New returns an Egress for this machine.
func New(d state.Dirs) *Egress {
	return &Egress{D: d, Run: func(c []string) state.Result { return state.Run(c) }, Now: time.Now}
}

func (e *Egress) imageDir() string { return filepath.Join(e.D.Core, "egress") }
func (e *Egress) dir() string      { return filepath.Join(e.D.State, "egress") }
func (e *Egress) ipsDir() string   { return filepath.Join(e.dir(), "ips") }
func (e *Egress) learnDir() string { return filepath.Join(e.dir(), "learn") }

// Image is the local tag of the proxy image: a hash of core/egress/, so editing the Containerfile builds a new one.
func (e *Egress) Image() string {
	h := sha256.New()
	entries, _ := os.ReadDir(e.imageDir())
	for _, f := range entries { // sorted by name
		if b, err := os.ReadFile(filepath.Join(e.imageDir(), f.Name())); err == nil {
			if st, err := os.Stat(filepath.Join(e.imageDir(), f.Name())); err == nil && st.Mode().IsRegular() {
				h.Write([]byte(f.Name()))
				h.Write([]byte{0})
				h.Write(b)
			}
		}
	}
	return "localhost/om-egress:" + hex.EncodeToString(h.Sum(nil))[:12]
}

// EnsureImage builds the proxy image if this engine does not have it yet (Squid on Alpine, from core/egress/).
// The error text is what Python printed after "✗ could not build the egress proxy image: ".
func (e *Egress) EnsureImage(runtime string) (bool, string) {
	if e.Run([]string{runtime, "image", "inspect", e.Image()}).Code == 0 {
		return true, ""
	}
	r := e.Run([]string{runtime, "build", "-q", "-t", e.Image(), "-f", filepath.Join(e.imageDir(), "Containerfile"), e.imageDir()})
	if r.Code != 0 {
		out := r.Stderr
		if out == "" {
			out = r.Stdout
		}
		return false, lastRunes(py.Strip(out), 400)
	}
	return true, ""
}

func lastRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[len(r)-n:]
	}
	return string(r)
}

// ValidHost reports a hostname the proxy may be told to allow: `api.example.com` or `*.example.com`.
func ValidHost(h string) bool { return hostRE.MatchString(h) }

// Rule is what a service may reach: a list of hosts, or one of the modes Internet, Learn, Audit.
type Rule struct {
	Mode  string // "" for a host list
	Hosts []string
}

// Truthy is Python's truthiness of the rule (an empty host list is false).
func (r Rule) Truthy() bool { return r.Mode != "" || len(r.Hosts) > 0 }

func (r Rule) json() any {
	if r.Mode != "" {
		return r.Mode
	}
	l := make([]any, len(r.Hosts))
	for i, h := range r.Hosts {
		l[i] = h
	}
	return l
}

func ruleFromJSON(v any) (Rule, bool) {
	switch x := v.(type) {
	case string:
		return Rule{Mode: x}, true
	case []any:
		var hs []string
		for _, h := range x {
			hs = append(hs, py.Str(h))
		}
		return Rule{Hosts: hs}, true
	}
	return Rule{}, false
}

// ParseLabel reads `om.egress` into a Rule; ok=false means the label is absent. Invalid names are kept out.
func ParseLabel(value any) (Rule, bool) {
	if value == nil {
		return Rule{}, false
	}
	text := py.Str(value)
	if py.Strip(text) == "" {
		return Rule{}, false
	}
	items := items(text)
	has := func(s string) bool {
		for _, i := range items {
			if i == s {
				return true
			}
		}
		return false
	}
	switch {
	case has(Internet):
		return Rule{Mode: Internet}, true
	case has(Audit) || has("monitor"):
		return Rule{Mode: Audit}, true
	case has(Learn):
		return Rule{Mode: Learn}, true
	}
	hosts := []string{}
	for _, h := range items {
		if ValidHost(h) {
			hosts = append(hosts, h)
		}
	}
	return Rule{Hosts: hosts}, true
}

func items(text string) []string {
	var out []string
	for _, v := range strings.Split(text, ",") {
		if v = py.Strip(v); v != "" {
			out = append(out, strings.ToLower(v))
		}
	}
	return out
}

// Items is the lower-cased, trimmed, non-empty comma list of an om.egress value.
func Items(text string) []string { return items(text) }

// ParseTTL converts a human TTL ('24h', '30m', '7d', '3600s', 'never') into seconds (default 86400, 0 for never).
func ParseTTL(ttl any) int {
	if ttl == nil {
		return DefaultLearnTTL
	}
	text := py.Strip(py.Str(ttl))
	if text == "" {
		return DefaultLearnTTL
	}
	s := strings.ToLower(text)
	switch s {
	case "0", "never", "off", "none", "permanent", "infinite", "inf":
		return 0
	}
	mult := map[byte]float64{'d': 86400, 'h': 3600, 'm': 60, 's': 1}
	num := s
	m := 1.0
	if k, ok := mult[s[len(s)-1]]; ok {
		num, m = s[:len(s)-1], k
	}
	f, ok := pyFloat(num)
	if !ok {
		return DefaultLearnTTL
	}
	return int(f * m)
}

// pyFloat is Python's float(text): surrounding space is ignored, underscores are allowed between digits, hex
// floats are not, and inf/nan parse but make int() fail, so they are refused here too.
func pyFloat(text string) (float64, bool) {
	t := py.Strip(text)
	for i := 0; i < len(t); i++ {
		if t[i] == '_' {
			if i == 0 || i == len(t)-1 || !isDigit(t[i-1]) || !isDigit(t[i+1]) {
				return 0, false
			}
		}
	}
	t = strings.ReplaceAll(t, "_", "")
	if strings.Contains(strings.ToLower(t), "0x") {
		return 0, false
	}
	f, err := strconv.ParseFloat(t, 64)
	if err != nil || f != f || f > 1e300 || f < -1e300 {
		return 0, false
	}
	return f, true
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func aclID(ws, svc string) string {
	safe := regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(ws+"_"+svc, "_")
	sum := sha256.Sum256([]byte(ws + "/" + svc))
	return safe + "_" + hex.EncodeToString(sum[:])[:8]
}

// UserName is the identity of a service in the proxy's log.
func UserName(ws, svc string) string { return ws + "." + svc }

func (e *Egress) writeFile(path, text string, private bool) error {
	if private {
		return state.WritePrivate(path, text)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp" // path.with_suffix(path.suffix + ".tmp")
	if err := os.WriteFile(tmp, []byte(text), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readJSONObject(path string) map[string]any {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	v, err := py.LoadJSON(b)
	m, ok := v.(map[string]any)
	if err != nil || !ok {
		return nil
	}
	return m
}

func (e *Egress) loadIPs(ws string) map[string]string {
	out := map[string]string{}
	for k, v := range readJSONObject(filepath.Join(e.ipsDir(), ws+".json")) {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

func (e *Egress) saveIPs(ws string, ips map[string]string) error {
	m := map[string]any{}
	for k, v := range ips {
		m[k] = v
	}
	return e.writeFile(filepath.Join(e.ipsDir(), ws+".json"), py.Dumps(m)+"\n", true)
}

// AllServiceIPs maps client IP address -> "ws.svc" across all registered workspaces.
func (e *Egress) AllServiceIPs() map[string]string {
	out := map[string]string{}
	files, _ := filepath.Glob(filepath.Join(e.ipsDir(), "*.json"))
	sort.Strings(files)
	for _, f := range files {
		ws := strings.TrimSuffix(filepath.Base(f), ".json")
		svcs := make([]string, 0)
		ips := e.loadIPs(ws)
		for s := range ips {
			svcs = append(svcs, s)
		}
		sort.Strings(svcs)
		for _, svc := range svcs {
			if ip := ips[svc]; ip != "" {
				out[ip] = ws + "." + svc
			}
		}
	}
	return out
}

// strictNetwork is ipaddress.ip_network(text) with strict=True: host bits must be zero.
func strictNetwork(text string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(text)
	if err != nil || p.Addr() != p.Masked().Addr() || p.Addr().Zone() != "" {
		return netip.Prefix{}, false
	}
	return p, true
}

func numAddresses(p netip.Prefix) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(p.Addr().BitLen()-p.Bits()))
}

func addrAt(p netip.Prefix, i *big.Int) netip.Addr {
	b := p.Addr().AsSlice()
	v := new(big.Int).SetBytes(b)
	v.Add(v, i)
	out := v.FillBytes(make([]byte, len(b)))
	a, _ := netip.AddrFromSlice(out)
	return a
}

// AllocateServiceIP returns the deterministic static IP of svc in subnet (e.g. "10.89.12.0/24"), allocating one.
func (e *Egress) AllocateServiceIP(ws, svc, subnet string) (string, error) {
	ips := e.loadIPs(ws)
	var nw netip.Prefix
	ok := false
	if subnet != "" {
		nw, ok = strictNetwork(subnet)
	}
	if !ok {
		// Fallback when the subnet cannot be inspected (e.g. offline tests) or is unreadable.
		// Deterministic /24 based on hash of ws.
		sum := sha256.Sum256([]byte(ws))
		n, _ := strconv.ParseUint(hex.EncodeToString(sum[:])[:4], 16, 32)
		nw = netip.MustParsePrefix("10.89." + strconv.Itoa(int(n%200)+10) + ".0/24")
	}
	if cur := ips[svc]; cur != "" {
		if a, err := netip.ParseAddr(cur); err == nil && nw.Contains(a) {
			return cur, nil
		}
	}
	used := map[netip.Addr]bool{}
	for _, ip := range ips {
		if a, err := netip.ParseAddr(ip); err == nil && nw.Contains(a) {
			used[a] = true
		}
	}
	total := numAddresses(nw)
	start := new(big.Int).Sub(total, big.NewInt(10))
	if start.Cmp(big.NewInt(2)) < 0 {
		start.SetInt64(2)
	}
	if start.Cmp(big.NewInt(50)) > 0 {
		start.SetInt64(50)
	}
	end := new(big.Int).Sub(total, big.NewInt(2))
	alloc := ""
	for i := new(big.Int).Set(start); i.Cmp(end) < 0; i.Add(i, big.NewInt(1)) {
		if c := addrAt(nw, i); !used[c] {
			alloc = c.String()
			break
		}
	}
	if alloc == "" {
		alloc = addrAt(nw, end).String()
	}
	ips[svc] = alloc
	return alloc, e.saveIPs(ws, ips)
}

func (e *Egress) learnFile(ws, svc string) string {
	safe := regexp.MustCompile(`[^a-zA-Z0-9_-]`).ReplaceAllString(ws+"_"+svc, "_")
	return filepath.Join(e.learnDir(), safe+".json")
}

// LoadLearn reads a service's learn record ({} when none).
func (e *Egress) LoadLearn(ws, svc string) map[string]any {
	if m := readJSONObject(e.learnFile(ws, svc)); m != nil {
		return m
	}
	return map[string]any{}
}

// SaveLearn writes a service's learn record (0600).
func (e *Egress) SaveLearn(ws, svc string, data map[string]any) error {
	return e.writeFile(e.learnFile(ws, svc), py.Dumps(data)+"\n", true)
}

func num(v any) (float64, bool) {
	switch x := v.(type) {
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case float64:
		return x, true
	case interface{ Float64() (float64, error) }:
		f, err := x.Float64()
		return f, err == nil
	}
	return 0, false
}

func numOr(m map[string]any, k string, def float64) float64 {
	if f, ok := num(m[k]); ok {
		return f
	}
	return def
}

func (e *Egress) now() int64 { return e.Now().Unix() }

// InitLearn creates the learn record. updateTTL: the caller knows the service's label (write_override), so a
// changed TTL replaces the stored one and restarts the window; otherwise an existing record is kept.
func (e *Egress) InitLearn(ws, svc string, ttl int, updateTTL bool) (map[string]any, error) {
	data := e.LoadLearn(ws, svc)
	now := e.now()
	if len(data) == 0 || !py.Truthy(data["started_at"]) {
		data = map[string]any{"started_at": now, "ttl": ttl, "hosts": map[string]any{}}
		return data, e.SaveLearn(ws, svc, data)
	}
	if updateTTL && numOr(data, "ttl", DefaultLearnTTL) != float64(ttl) {
		data["ttl"], data["started_at"] = ttl, now
		return data, e.SaveLearn(ws, svc, data)
	}
	return data, nil
}

// IsLearnExpired reports whether a learning window has run out.
func (e *Egress) IsLearnExpired(ws, svc string) bool {
	data := e.LoadLearn(ws, svc)
	if len(data) == 0 || !py.Truthy(data["started_at"]) {
		return false
	}
	ttl := numOr(data, "ttl", DefaultLearnTTL)
	if ttl == 0 {
		return false
	}
	return float64(e.Now().UnixNano())/1e9 >= numOr(data, "started_at", 0)+ttl
}

// LearnRemaining is the seconds left in learn mode for svc, -1 if permanent, or 0 if expired or not learning.
func (e *Egress) LearnRemaining(ws, svc string) int64 {
	data := e.LoadLearn(ws, svc)
	if len(data) == 0 || !py.Truthy(data["started_at"]) {
		return 0
	}
	ttl := numOr(data, "ttl", DefaultLearnTTL)
	if ttl == 0 {
		return -1
	}
	rem := int64(numOr(data, "started_at", 0)+ttl) - e.now()
	if rem < 0 {
		return 0
	}
	return rem
}

// RecordLearnedHost counts one request to host. ts (a log timestamp, 0 for none) makes it idempotent: a log line
// already counted (the same log is read again) is skipped.
func (e *Egress) RecordLearnedHost(ws, svc, host string, ts float64) error {
	data := e.LoadLearn(ws, svc)
	stamp := func() int64 {
		if ts != 0 {
			return int64(ts)
		}
		return e.now()
	}
	if len(data) == 0 {
		data = map[string]any{"started_at": stamp(), "ttl": DefaultLearnTTL, "hosts": map[string]any{}}
	}
	hosts, ok := data["hosts"].(map[string]any)
	if !ok {
		hosts = map[string]any{}
		data["hosts"] = hosts
	}
	key := strings.ToLower(host)
	entry, ok := hosts[key].(map[string]any)
	if !ok {
		entry = map[string]any{"first_seen": stamp(), "count": 0}
		hosts[key] = entry
	}
	if ts != 0 {
		if last, _ := num(entry["last_ts"]); ts <= last {
			return nil
		}
		entry["last_ts"] = ts
	}
	c, _ := num(entry["count"])
	entry["count"] = int64(c) + 1
	return e.SaveLearn(ws, svc, data)
}

// IsJVMService reports whether a service runs Java/JVM and needs JAVA_TOOL_OPTIONS proxy injection.
func IsJVMService(svc map[string]any) bool {
	labels := svcLabels(svc)
	for _, key := range []string{"om.egress.jvm", "om.jvm"} {
		switch strings.ToLower(py.Strip(labels[key])) {
		case "true", "1", "yes":
			return true
		}
	}
	image := strings.ToLower(py.Str(orDefault(svc, "image", "")))
	for _, k := range jvmImageKeywords {
		if strings.Contains(image, k) {
			return true
		}
	}
	keys := map[string]bool{}
	switch env := svc["environment"].(type) {
	case map[string]any:
		for k := range env {
			keys[k] = true
		}
	case []any:
		for _, x := range env {
			if s := py.Str(x); strings.Contains(s, "=") {
				keys[strings.SplitN(s, "=", 2)[0]] = true
			}
		}
	}
	return keys["JAVA_TOOL_OPTIONS"] || keys["_JAVA_OPTIONS"] || keys["JAVA_OPTS"]
}

func orDefault(m map[string]any, k string, def any) any {
	if v, ok := m[k]; ok {
		return v
	}
	return def
}

// svcLabels is a service's labels with values as text, whichever form compose gave them in.
func svcLabels(svc map[string]any) map[string]string {
	out := map[string]string{}
	switch l := svc["labels"].(type) {
	case map[string]any:
		for k, v := range l {
			out[k] = py.Str(v)
		}
	case []any:
		for _, x := range l {
			if s, ok := x.(string); ok {
				k, v, _ := strings.Cut(s, "=")
				out[k] = v
			}
		}
	}
	return out
}

// MergeJavaProxyOpts merges JVM system properties for HTTP and HTTPS proxy into JAVA_TOOL_OPTIONS.
func MergeJavaProxyOpts(existing, host string, port int, nonProxy string) string {
	tokens := py.Strip(existing)
	needed := []string{
		"-Dhttp.proxyHost=" + host, "-Dhttp.proxyPort=" + strconv.Itoa(port),
		"-Dhttps.proxyHost=" + host, "-Dhttps.proxyPort=" + strconv.Itoa(port),
		"-Dhttp.nonProxyHosts=" + nonProxy,
	}
	var add []string
	for _, opt := range needed {
		if !strings.Contains(tokens, strings.SplitN(opt, "=", 2)[0]) {
			add = append(add, opt)
		}
	}
	if len(add) == 0 {
		return tokens
	}
	return py.Strip(tokens + " " + strings.Join(add, " "))
}

// RenderACL renders the Squid rules of one workspace: {svc: rule} using source IP identity. ips nil loads them;
// a service without an address gets one allocated (and saved).
func (e *Egress) RenderACL(ws string, services map[string]Rule, ips map[string]string) (string, error) {
	lines := []string{"# Generated by om for workspace " + ws + " — do not edit."}
	if ips == nil {
		ips = e.loadIPs(ws)
	}
	names := make([]string, 0, len(services))
	for s := range services {
		names = append(names, s)
	}
	sort.Strings(names)
	for _, svc := range names {
		hosts := services[svc]
		ip := ips[svc]
		if ip == "" {
			var err error
			if ip, err = e.AllocateServiceIP(ws, svc, ""); err != nil {
				return "", err
			}
		}
		id := aclID(ws, svc)
		lines = append(lines, "acl s_"+id+" src "+ip+"/32")
		switch {
		case hosts.Mode == Internet || hosts.Mode == Audit:
			lines = append(lines, "http_access allow s_"+id)
		case hosts.Mode == Learn:
			if e.IsLearnExpired(ws, svc) {
				lines = append(lines, "# learn mode expired for "+svc+" ("+ip+")")
				if e.Notify != nil {
					e.Notify("Egress learn mode expired: "+ws+"/"+svc,
						"Service '"+ws+"/"+svc+"' learn mode has expired and fallen back to deny-all. Run `om egress log "+svc+" --apply` to allow discovered hosts.",
						"egress-learn-expired:"+ws+":"+svc)
				}
			} else {
				lines = append(lines, "http_access allow s_"+id)
			}
		case len(hosts.Hosts) > 0:
			doms := make([]string, len(hosts.Hosts))
			for i, h := range hosts.Hosts {
				doms[i] = strings.TrimPrefix(h, "*") // *.x → .x (x and below)
				if !strings.HasPrefix(h, "*.") {
					doms[i] = h
				}
			}
			lines = append(lines, "acl d_"+id+" dstdomain "+strings.Join(doms, " "), "http_access allow s_"+id+" d_"+id)
		}
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// EnsureBase writes squid.conf and the folders the proxy reads.
func (e *Egress) EnsureBase() error {
	for _, d := range []string{filepath.Join(e.dir(), "acl"), e.ipsDir(), e.learnDir()} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	if err := e.writeFile(filepath.Join(e.dir(), "squid.conf"), BaseConf, false); err != nil {
		return err
	}
	placeholder := filepath.Join(e.dir(), "acl", "00-none.conf") // the include glob must match something
	if _, err := os.Stat(placeholder); err != nil {
		return e.writeFile(placeholder, "# placeholder\n", false)
	}
	return nil
}

// ProxyURL is the plain proxy URL without credentials (the source IP provides identity).
func ProxyURL() string { return "http://" + Container + ":" + strconv.Itoa(Port) }

// RenderWorkspace writes the source-IP rules of one workspace, reloads the proxy and returns {svc: proxy url}.
func (e *Egress) RenderWorkspace(runtime, ws string, services map[string]Rule, prune bool, subnets map[string]string) (map[string]string, error) {
	if err := e.EnsureBase(); err != nil {
		return nil, err
	}
	ips := e.loadIPs(ws)
	if prune {
		for svc := range ips {
			if _, ok := services[svc]; !ok {
				delete(ips, svc)
			}
		}
	} else {
		merged := e.loadRules(ws)
		for k, v := range services {
			merged[k] = v
		}
		services = merged
	}
	names := make([]string, 0, len(services))
	for s := range services {
		names = append(names, s)
	}
	sort.Strings(names)
	for _, svc := range names {
		if ips[svc] == "" {
			ip, err := e.AllocateServiceIP(ws, svc, subnets[svc])
			if err != nil {
				return nil, err
			}
			ips[svc] = ip
		}
		if m := services[svc].Mode; m == Learn || m == Audit {
			ttl := DefaultLearnTTL
			if m == Audit {
				ttl = 0
			}
			if _, err := e.InitLearn(ws, svc, ttl, false); err != nil {
				return nil, err
			}
		}
	}
	if err := e.saveIPs(ws, ips); err != nil {
		return nil, err
	}
	rules := map[string]any{}
	for k, v := range services {
		rules[k] = v.json()
	}
	if err := e.writeFile(filepath.Join(e.dir(), ws+".rules"), py.DumpsCompact(rules)+"\n", true); err != nil {
		return nil, err
	}
	acl := filepath.Join(e.dir(), "acl", ws+".conf")
	if len(services) > 0 {
		text, err := e.RenderACL(ws, services, ips)
		if err != nil {
			return nil, err
		}
		if err := e.writeFile(acl, text, false); err != nil {
			return nil, err
		}
	} else if err := os.Remove(acl); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	e.Reload(runtime)
	out := map[string]string{}
	for svc := range services {
		out[svc] = ProxyURL()
	}
	return out, nil
}

func (e *Egress) loadRules(ws string) map[string]Rule {
	out := map[string]Rule{}
	m := readJSONObject(filepath.Join(e.dir(), ws+".rules"))
	if m == nil { // backward compatibility
		m = readJSONObject(filepath.Join(e.dir(), "creds", ws+".rules"))
	}
	for k, v := range m {
		if r, ok := ruleFromJSON(v); ok {
			out[k] = r
		}
	}
	return out
}

// LoadRules returns the rules last written for a workspace.
func (e *Egress) LoadRules(ws string) map[string]Rule { return e.loadRules(ws) }

// Reload asks the running proxy to re-read its configuration.
func (e *Egress) Reload(runtime string) bool {
	return e.Run([]string{runtime, "exec", Container, "squid", "-k", "reconfigure", "-f", "/etc/om-egress/squid.conf"}).Code == 0
}

// Suggestion is the om.egress value that adds newHosts to what the service lists today.
func Suggestion(current Rule, has bool, newHosts []string) string {
	var have []string
	if has && current.Mode == "" {
		have = append(have, current.Hosts...)
	}
	seen := map[string]bool{}
	for _, h := range have {
		seen[h] = true
	}
	var add []string
	for _, h := range newHosts {
		if !seen[h] {
			add = append(add, h)
		}
	}
	sort.Strings(add)
	return strings.Join(append(have, add...), ",")
}
