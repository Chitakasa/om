// Package dashboard is the web dashboard served by the om_dashboard container (`om dashboard`). Port of
// core/dashboard/app/server.py; index.html is embedded.
package dashboard

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/Chitakasa/om/internal/py"
)

//go:embed index.html
var indexHTML []byte

// Config is where the dashboard finds things. FromEnv fills it the way the container sets it up.
type Config struct {
	Addr            string
	SocketPath      string
	WallpapersDir   string
	DataDir         string
	WorkspacesMount string
	Registry        string // GLOBAL_REGISTRY: the file; its directory also holds service_ports.json, updates/ and core_memory.json
	PrivateBase     int
	PublicBase      int
	VPNHosts        []string
	MeminfoPath     string
	Now             func() time.Time
}

// FromEnv reads the container's environment.
func FromEnv(getenv func(string) string) Config {
	def := func(k, d string) string {
		if v := getenv(k); v != "" {
			return v
		}
		return d
	}
	num := func(k string, d int) int {
		if n, err := strconv.Atoi(strings.TrimSpace(getenv(k))); err == nil {
			return n
		}
		return d
	}
	c := Config{
		Addr: ":80", SocketPath: def("OM_ENGINE_SOCKET_PATH", "/run/om-engine/engine.sock"), WallpapersDir: "/wallpapers",
		DataDir: "/data", WorkspacesMount: "/workspaces", Registry: def("GLOBAL_REGISTRY", "/etc/om/workspaces.json"),
		PrivateBase: num("OM_PRIVATE_PORT_BASE", 20000), PublicBase: num("OM_PUBLIC_PORT_BASE", 21000),
		MeminfoPath: "/proc/meminfo",
	}
	for _, h := range strings.Split(getenv("VPN_HOSTS"), ",") {
		h = strings.TrimSpace(h)
		if h != "" && !strings.HasSuffix(h, ".invalid") {
			c.VPNHosts = append(c.VPNHosts, strings.ToLower(h))
		}
	}
	return c
}

type memStat struct{ usage, limit int64 }

type statEntry struct {
	key string
	memStat
}

// Server holds the caches and background stats poller.
type Server struct {
	C      Config
	vpn    map[string]bool
	client *http.Client

	statsMu   sync.Mutex
	stats     []statEntry
	statsIdx  map[string]memStat
	lastUse   time.Time
	wake      chan struct{}
	statsIdle time.Duration

	svcMu   sync.Mutex
	svcAt   time.Time
	svcData []*Service

	updMu  sync.Mutex
	upd    map[string]updHit
	stop   chan struct{}
	stopMu sync.Once
}

type updHit struct {
	at  time.Time
	set map[string]bool
}

// New makes a Server; Run starts it.
func New(c Config) *Server {
	if c.Now == nil {
		c.Now = time.Now
	}
	s := &Server{C: c, vpn: map[string]bool{}, upd: map[string]updHit{}, wake: make(chan struct{}, 1),
		statsIdle: 30 * time.Second, statsIdx: map[string]memStat{}, stop: make(chan struct{})}
	for _, h := range c.VPNHosts {
		s.vpn[h] = true
	}
	s.client = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", c.SocketPath)
		}, DisableKeepAlives: true}}
	return s
}

// ---- engine ----

func (s *Server) engineGet(path string, timeout time.Duration) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://localhost"+path, nil)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return b, resp.StatusCode, err
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func (s *Server) listContainers() []map[string]any {
	if !fileExists(s.C.SocketPath) {
		return nil
	}
	b, code, err := s.engineGet("/containers/json?all=true", 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error querying podman socket: %v\n", err)
		return nil
	}
	if code != 200 {
		return nil
	}
	var out []map[string]any
	if json.Unmarshal(b, &out) != nil {
		return nil
	}
	return out
}

// ---- stats ----

func (s *Server) touchStats() {
	s.statsMu.Lock()
	s.lastUse = s.C.Now()
	s.statsMu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func asMap(v any) map[string]any { m, _ := v.(map[string]any); return m }
func asStr(v any) string         { s, _ := v.(string); return s }

func asInt(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case json.Number:
		n, _ := x.Int64()
		return n
	case int:
		return int64(x)
	case int64:
		return x
	}
	return 0
}

func containerName(c map[string]any) string {
	names, _ := c["Names"].([]any)
	if len(names) == 0 {
		return ""
	}
	return strings.TrimLeft(asStr(names[0]), "/")
}

func (s *Server) fetchStat(c map[string]any) (id, name string, st *memStat) {
	id, name = asStr(c["Id"]), containerName(c)
	b, code, err := s.engineGet("/containers/"+id+"/stats?stream=false", 3*time.Second)
	if err != nil || code != 200 {
		return
	}
	var doc map[string]any
	if json.Unmarshal(b, &doc) != nil {
		return
	}
	mem := asMap(doc["memory_stats"])
	lim := asInt(mem["limit"])
	if _, ok := mem["limit"]; !ok || lim < 1 {
		lim = 1
	}
	return id, name, &memStat{asInt(mem["usage"]), lim}
}

func (s *Server) pollStats() bool {
	if !fileExists(s.C.SocketPath) {
		return false
	}
	b, code, err := s.engineGet("/containers/json", 5*time.Second)
	if err != nil || code != 200 {
		return false
	}
	var cs []map[string]any
	if json.Unmarshal(b, &cs) != nil {
		return false
	}
	type res struct {
		id, name string
		st       *memStat
	}
	results := make([]res, len(cs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, c := range cs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, c map[string]any) {
			defer wg.Done()
			defer func() { <-sem }()
			id, name, st := s.fetchStat(c)
			results[i] = res{id, name, st}
		}(i, c)
	}
	wg.Wait()
	var list []statEntry
	idx := map[string]memStat{}
	for _, r := range results {
		if r.st == nil {
			continue
		}
		short := r.id
		if len(short) > 12 {
			short = short[:12]
		}
		for _, k := range []string{short, r.name} {
			if _, dup := idx[k]; !dup {
				list = append(list, statEntry{k, *r.st})
			} else {
				for i := range list {
					if list[i].key == k {
						list[i].memStat = *r.st
					}
				}
			}
			idx[k] = *r.st
		}
	}
	s.statsMu.Lock()
	s.stats, s.statsIdx = list, idx
	s.statsMu.Unlock()
	return true
}

func (s *Server) statsWorker() {
	backoff := 3 * time.Second
	for {
		s.statsMu.Lock()
		idle := s.C.Now().Sub(s.lastUse) > s.statsIdle
		s.statsMu.Unlock()
		if idle {
			select {
			case <-s.wake:
			case <-s.stop:
				return
			}
		}
		var wait time.Duration
		if s.pollStats() {
			backoff, wait = 3*time.Second, 3*time.Second
		} else {
			wait = backoff
			if backoff *= 2; backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
		}
		select {
		case <-time.After(wait):
		case <-s.stop:
			return
		}
	}
}

// FormatBytes is the dashboard's size text.
func FormatBytes(b int64) string {
	if b <= 0 {
		return "0 MB"
	}
	if b >= 1<<30 {
		return fmt.Sprintf("%.2f GB", float64(b)/(1<<30))
	}
	return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
}

func (s *Server) regDir() string { return filepath.Dir(s.C.Registry) }

func readJSONFile(p string) (map[string]any, bool) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil || m == nil {
		return nil, false
	}
	return m, true
}

func (s *Server) coreAnonMemory() map[string]int64 {
	out := map[string]int64{}
	snap, ok := readJSONFile(filepath.Join(s.regDir(), "core_memory.json"))
	if !ok {
		return out
	}
	ts, _ := snap["ts"].(float64)
	if float64(s.C.Now().Unix())-ts <= 600 {
		for k, v := range asMap(snap["anon"]) {
			out[k] = asInt(v)
		}
	}
	return out
}

var hex12 = regexp.MustCompile(`^[0-9a-f]{12}$`)

func (s *Server) systemStats() *py.Object {
	s.touchStats()
	anon := s.coreAnonMemory()
	var total, avail int64
	if b, err := os.ReadFile(s.C.MeminfoPath); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			n, _ := strconv.ParseInt(f[1], 10, 64)
			switch f[0] {
			case "MemTotal:":
				total = n * 1024
			case "MemAvailable:":
				avail = n * 1024
			}
		}
	}
	var platform, workload int64
	var containers []any
	cacheFree := true
	s.statsMu.Lock()
	items := append([]statEntry(nil), s.stats...)
	s.statsMu.Unlock()
	for _, it := range items {
		if hex12.MatchString(it.key) {
			continue
		}
		usage := it.usage
		if strings.HasPrefix(it.key, "om_") || strings.HasPrefix(it.key, "om-") {
			if v, ok := anon[it.key]; ok {
				usage = v
			} else {
				cacheFree = false
			}
			platform += usage
			o := py.NewObject()
			o.Set("name", it.key)
			o.Set("memory_usage", int(usage))
			o.Set("memory_str", FormatBytes(usage))
			containers = append(containers, o)
		} else {
			workload += usage
		}
	}
	used := total - avail
	if used < 0 || total == 0 {
		used = 0
	}
	o := py.NewObject()
	o.Set("platform_ram_bytes", int(platform))
	o.Set("platform_ram_str", FormatBytes(platform))
	o.Set("platform_ram_cache_free", cacheFree && len(containers) > 0)
	if containers == nil {
		containers = []any{}
	}
	o.Set("platform_containers", containers)
	o.Set("workload_ram_bytes", int(workload))
	o.Set("workload_ram_str", FormatBytes(workload))
	o.Set("host_total_bytes", int(total))
	o.Set("host_available_bytes", int(avail))
	o.Set("host_used_bytes", int(used))
	str := func(n int64, ok bool) string {
		if ok {
			return FormatBytes(n)
		}
		return ""
	}
	o.Set("host_total_str", str(total, total != 0))
	o.Set("host_available_str", str(avail, avail != 0))
	o.Set("host_used_str", str(used, total != 0))
	return o
}

// ---- registry, settings, wallpapers ----

func (s *Server) registry() *py.Object {
	b, err := os.ReadFile(s.C.Registry)
	if err != nil {
		return py.NewObject()
	}
	o, err := py.ParseObject(b)
	if err != nil {
		return py.NewObject()
	}
	return o
}

func (s *Server) serviceSlots() map[string]int {
	out := map[string]int{}
	m, ok := readJSONFile(filepath.Join(s.regDir(), "service_ports.json"))
	if !ok {
		return out
	}
	for k, v := range m {
		if f, ok := v.(float64); ok && f >= 0 && f == float64(int(f)) {
			out[k] = int(f)
		}
	}
	return out
}

var safeWSRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// ParseHost is the lowercase hostname of a Host/Origin authority, handling [IPv6]:port.
func ParseHost(v string) string {
	v = strings.ToLower(py.Strip(v))
	if strings.HasPrefix(v, "[") {
		if i := strings.Index(v, "]"); i >= 0 {
			return v[1:i]
		}
		return ""
	}
	if i := strings.Index(v, ":"); i >= 0 {
		return v[:i]
	}
	return v
}

func (s *Server) privateHostAllowed(host string) bool {
	if host == "localhost" || s.vpn[host] || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func (s *Server) resolveWorkspaceAlias(name string) (string, bool) {
	if name == "" || name == "all" {
		return "", false
	}
	name = strings.ToLower(py.Strip(name))
	if name == "core" {
		return "core", true
	}
	reg := s.registry()
	if _, ok := reg.Get(name); ok {
		return name, true
	}
	for _, wid := range reg.Keys() {
		if wid == name || strings.TrimRight(wid, "s") == strings.TrimRight(name, "s") {
			return wid, true
		}
	}
	if safeWSRe.MatchString(name) {
		return name, true
	}
	return "", false
}

type query map[string][]string

func parseQuery(raw string) query {
	vals, _ := url.ParseQuery(raw)
	q := query{}
	for k, v := range vals {
		var keep []string
		for _, x := range v {
			if x != "" {
				keep = append(keep, x)
			}
		}
		if len(keep) > 0 {
			q[k] = keep
		}
	}
	return q
}

func (q query) first(k string) string {
	if v := q[k]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func (s *Server) workspaceForRequest(host string, q query) (string, bool) {
	if wq := strings.ToLower(py.Strip(q.first("workspace"))); wq != "" && wq != "all" {
		return s.resolveWorkspaceAlias(wq)
	}
	parts := strings.Split(ParseHost(host), ".")
	if len(parts) >= 3 && parts[1] == "dashboard" && parts[2] == "localhost" {
		return s.resolveWorkspaceAlias(parts[0])
	}
	return "", false
}

func (s *Server) storageDir(ws string, create bool) string {
	d := s.C.DataDir
	if _, ok := s.registry().Get(ws); ws != "" && ws != "core" && ok && safeWSRe.MatchString(ws) {
		d = filepath.Join(s.C.WorkspacesMount, ws)
		if st, err := os.Stat(d); err != nil || !st.IsDir() {
			d = filepath.Join(s.C.DataDir, "workspaces", ws)
		}
	}
	if create {
		os.MkdirAll(d, 0o755)
	}
	return d
}

func orCore(ws string) string {
	if ws == "" {
		return "core"
	}
	return ws
}

func (s *Server) settings(ws string) *py.Object {
	sfile := filepath.Join(s.storageDir(ws, false), "settings.json")
	d := py.NewObject()
	d.Set("name", "wide_nebula.png")
	d.Set("blur", 0)
	d.Set("dim", 20)
	d.Set("card_blur", 16)
	d.Set("card_dim", 65)
	d.Set("timestamp", int(s.C.Now().Unix()))
	d.Set("workspace_id", orCore(ws))
	if b, err := os.ReadFile(sfile); err == nil {
		if saved, err := py.ParseObject(b); err == nil {
			for _, k := range saved.Keys() {
				v, _ := saved.Get(k)
				d.Set(k, v)
			}
		}
	} else if ws != "" && ws != "core" {
		core := s.settings("")
		for _, k := range core.Keys() {
			if k != "workspace_id" && k != "timestamp" {
				v, _ := core.Get(k)
				d.Set(k, v)
			}
		}
	}
	d.Set("workspace_id", orCore(ws))
	return d
}

func (s *Server) saveSettings(update *py.Object, ws string) *py.Object {
	dir := s.storageDir(ws, true)
	cur := s.settings(ws)
	for _, k := range update.Keys() {
		v, _ := update.Get(k)
		cur.Set(k, v)
	}
	cur.Set("timestamp", int(s.C.Now().Unix()))
	cur.Set("workspace_id", orCore(ws))
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(py.Dumps(cur)), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving settings for %s: %v\n", ws, err)
	}
	return cur
}

func nonEmptyFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Size() > 0
}

func (s *Server) wallpaperFile(ws string) string {
	sdir := s.storageDir(ws, false)
	if sdir != s.C.DataDir {
		if p := filepath.Join(sdir, "current_wallpaper"); nonEmptyFile(p) {
			return p
		}
	}
	if p := filepath.Join(s.C.DataDir, "current_wallpaper"); nonEmptyFile(p) {
		return p
	}
	return ""
}

func realpath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	a, _ := filepath.Abs(p)
	return a
}

func (s *Server) resolveHostPath(in string) string {
	base := filepath.Base(py.Strip(in))
	if in == "" || base == "" || base == "." || base == "/" || strings.HasPrefix(base, ".") {
		return ""
	}
	roots := []string{realpath(s.C.WallpapersDir), realpath(s.C.DataDir)}
	for _, p := range []string{filepath.Join(s.C.WallpapersDir, base), filepath.Join(s.C.DataDir, base)} {
		real := realpath(p)
		for _, r := range roots {
			if real == r || strings.HasPrefix(real, r+string(filepath.Separator)) {
				if st, err := os.Stat(real); err == nil && st.Mode().IsRegular() {
					return real
				}
			}
		}
	}
	return ""
}

var imageExts = map[string]bool{".jpg": true, ".jpeg": true, ".png": true, ".webp": true, ".bmp": true}

func (s *Server) listWallpapers() []string {
	out := []string{}
	ents, err := os.ReadDir(s.C.WallpapersDir)
	if err != nil {
		return out
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, n := range names {
		if imageExts[strings.ToLower(filepath.Ext(n))] && !strings.HasPrefix(n, ".") {
			out = append(out, n)
		}
	}
	return out
}

// DetectImageMime reads the file's magic bytes; never the extension (an SVG served from this origin would run script).
func DetectImageMime(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "application/octet-stream"
	}
	defer f.Close()
	h := make([]byte, 32)
	n, _ := io.ReadFull(f, h)
	h = h[:n]
	switch {
	case strings.HasPrefix(string(h), "\x89PNG\r\n\x1a\n"):
		return "image/png"
	case strings.HasPrefix(string(h), "\xff\xd8\xff"):
		return "image/jpeg"
	case strings.HasPrefix(string(h), "GIF87a"), strings.HasPrefix(string(h), "GIF89a"):
		return "image/gif"
	case len(h) >= 12 && strings.HasPrefix(string(h), "RIFF") && string(h[8:12]) == "WEBP":
		return "image/webp"
	case strings.HasPrefix(string(h), "BM"):
		return "image/bmp"
	}
	return "application/octet-stream"
}

func isImageStart(c []byte) bool {
	s := string(c)
	return strings.HasPrefix(s, "\x89PNG\r\n\x1a\n") || strings.HasPrefix(s, "\xff\xd8\xff") || strings.HasPrefix(s, "BM") ||
		strings.HasPrefix(s, "GIF87a") || strings.HasPrefix(s, "GIF89a") || (len(c) >= 12 && strings.HasPrefix(s, "RIFF") && string(c[8:12]) == "WEBP")
}

// ---- services ----

// Service is the dashboard's description of one container.
type Service struct {
	ID, Key, Name, Icon, Description string
	Port                             *int
	HasWeb                           bool
	Domain, Path                     string
	PortPrivate, PortPublic          *int
	Scope                            string
	IsSearch                         bool
	SearchURL, URL                   string
	State                            string
	ExitCode                         int
	Status, WorkspaceID              string
	UpdateAvailable                  bool
	Category                         string
	MemoryUsage                      int64
	MemoryStr, MemoryPercent         string
	StatusOverride                   bool
}

func (v *Service) running() bool { return v.State == "running" }
func (v *Service) public() bool  { return v.Scope == "public" }

func intp(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

// Object is the service as the API returns it, in Python's key order.
func (v *Service) Object() *py.Object {
	o := py.NewObject()
	o.Set("id", v.ID)
	o.Set("key", v.Key)
	o.Set("name", v.Name)
	o.Set("icon", v.Icon)
	o.Set("description", v.Description)
	o.Set("port", intp(v.Port))
	o.Set("has_web", v.HasWeb)
	o.Set("domain", v.Domain)
	o.Set("path", v.Path)
	o.Set("port_private", intp(v.PortPrivate))
	o.Set("port_public", intp(v.PortPublic))
	o.Set("scope", v.Scope)
	o.Set("is_public", v.public())
	o.Set("is_search", v.IsSearch)
	o.Set("search_url", v.SearchURL)
	o.Set("url", v.URL)
	o.Set("state", v.State)
	o.Set("exit_code", v.ExitCode)
	o.Set("status", v.Status)
	o.Set("workspace_id", v.WorkspaceID)
	o.Set("update_available", v.UpdateAvailable)
	o.Set("category", v.Category)
	o.Set("memory_usage", int(v.MemoryUsage))
	o.Set("memory_str", v.MemoryStr)
	o.Set("memory_percent", v.MemoryPercent)
	return o
}

// sanitized is what a LAN visitor may see: no container id, memory, crash status, exit code, workspace name,
// private port or internal domain.
func (v Service) sanitized() Service {
	v.ID, v.WorkspaceID, v.UpdateAvailable, v.MemoryUsage, v.MemoryStr, v.MemoryPercent = "", "", false, 0, "", ""
	v.Status = "stopped"
	if v.State == "running" {
		v.Status = "online"
	}
	v.ExitCode, v.PortPrivate, v.Domain = 0, nil, ""
	return v
}

var intStrRe = regexp.MustCompile(`^[+-]?[0-9]+(_[0-9]+)*$`)

func pyIntStr(s string) (int, bool) {
	s = py.Strip(s)
	if !intStrRe.MatchString(s) {
		return 0, false
	}
	n, err := strconv.Atoi(strings.ReplaceAll(s, "_", ""))
	return n, err == nil
}

func portOf(p map[string]any) int {
	if n := asInt(p["PublicPort"]); n != 0 {
		return int(n)
	}
	return int(asInt(p["PrivatePort"]))
}

func detectPort(labels map[string]string, ports []map[string]any) int {
	if v, ok := labels["dashboard.port"]; ok {
		if n, ok := pyIntStr(v); ok {
			return n
		}
	}
	for _, p := range ports {
		if n := portOf(p); n != 0 && n != 80 && n != 443 {
			return n
		}
	}
	if len(ports) > 0 {
		if n := portOf(ports[0]); n != 0 {
			return n
		}
		return 80
	}
	return 80
}

func containerState(c map[string]any) (string, int) {
	raw, has := c["State"]
	if !has {
		raw = "unknown"
	}
	if m, ok := raw.(map[string]any); ok {
		st := "unknown"
		if v, ok := m["Status"]; ok {
			st = py.Str(v)
		}
		return strings.ToLower(st), int(asInt(m["ExitCode"]))
	}
	status := asStr(c["Status"])
	code := 0
	if strings.Contains(strings.ToLower(status), "exited") {
		if i := strings.Index(status, "("); i >= 0 {
			rest := status[i+1:]
			if j := strings.Index(rest, ")"); j >= 0 {
				if n, ok := pyIntStr(rest[:j]); ok {
					code = n
				}
			}
		}
	}
	return strings.ToLower(py.Str(raw)), code
}

// Title is Python's str.title().
func Title(s string) string {
	var b strings.Builder
	prev := false
	for _, r := range s {
		if unicode.IsLetter(r) {
			if prev {
				b.WriteRune(unicode.ToLower(r))
			} else {
				b.WriteRune(unicode.ToUpper(r))
			}
			prev = true
		} else {
			b.WriteRune(r)
			prev = false
		}
	}
	return b.String()
}

func (s *Server) updatesFor(ws string) map[string]bool {
	if ws == "" || !regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(ws) {
		return nil
	}
	now := s.C.Now()
	s.updMu.Lock()
	defer s.updMu.Unlock()
	if h, ok := s.upd[ws]; ok && now.Sub(h.at) < 30*time.Second {
		return h.set
	}
	found := map[string]bool{}
	if m, ok := readJSONFile(filepath.Join(s.regDir(), "updates", ws+".json")); ok {
		if l, ok := m["services"].([]any); ok {
			for _, x := range l {
				found[py.Str(x)] = true
			}
		}
	}
	s.upd[ws] = updHit{now, found}
	return found
}

func (s *Server) serviceMemory(c map[string]any, raw string) (int64, string, string) {
	id := asStr(c["Id"])
	if len(id) > 12 {
		id = id[:12]
	}
	s.statsMu.Lock()
	st, ok := s.statsIdx[id]
	if !ok {
		st = s.statsIdx[raw]
	}
	s.statsMu.Unlock()
	lim := st.limit
	if lim < 1 {
		lim = 1
	}
	if st.usage > 0 {
		return st.usage, FormatBytes(st.usage), fmt.Sprintf("%.1f%%", float64(st.usage)/float64(lim)*100)
	}
	return st.usage, "—", "0%"
}

func labelMap(c map[string]any) map[string]string {
	out := map[string]string{}
	for k, v := range asMap(c["Labels"]) {
		out[k] = py.Str(v)
	}
	return out
}

func lbl(l map[string]string, k, d string) string {
	if v, ok := l[k]; ok {
		return v
	}
	return d
}

func portList(c map[string]any) []map[string]any {
	var out []map[string]any
	l, _ := c["Ports"].([]any)
	for _, p := range l {
		if m, ok := p.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func (s *Server) serviceEntry(c map[string]any, slots map[string]int) *Service {
	raw := containerName(c)
	labels := labelMap(c)
	if strings.ToLower(lbl(labels, "dashboard.hide", "")) == "true" || raw == "om_caddy" || raw == "om_dashboard" || raw == "om_router" {
		return nil
	}
	if strings.ToLower(lbl(labels, "om.core", "")) == "true" && labels["dashboard.name"] == "" {
		return nil
	}
	ws := labels["workspace.id"]
	if ws == "" {
		ws = labels["com.docker.compose.project"]
	}
	if ws == "" {
		if strings.Contains(raw, "_") {
			ws = strings.SplitN(raw, "_", 2)[0]
		} else {
			ws = "uncategorized"
		}
	}
	clean := raw
	if strings.HasPrefix(raw, ws+"_") {
		clean = raw[len(ws)+1:]
	}
	ports := portList(c)
	st, exit := containerState(c)
	hasWeb := strings.ToLower(lbl(labels, "dashboard.web", "")) != "false" && (len(ports) > 0 || labels["dashboard.port"] != "")
	sub := lbl(labels, "dashboard.path", "/")
	if !strings.HasPrefix(sub, "/") {
		sub = "/" + sub
	}
	scope := "private"
	if strings.ToLower(py.Strip(lbl(labels, "dashboard.scope", ""))) == "public" {
		scope = "public"
	}
	isSearch := strings.ToLower(lbl(labels, "dashboard.search", "")) == "true"
	var slotp *int
	if sl, ok := slots[ws+"/"+clean]; ok {
		slotp = &sl
	}
	def := Title(strings.NewReplacer("-", " ", "_", " ").Replace(clean))
	mb, ms, mp := s.serviceMemory(c, raw)
	v := &Service{
		ID: asStr(c["Id"]), Key: clean, Name: lbl(labels, "dashboard.name", def), Icon: lbl(labels, "dashboard.icon", "📦"),
		Description: lbl(labels, "dashboard.description", "Self-hosted Service"), HasWeb: hasWeb,
		Domain: ws + "." + clean + ".localhost", Path: sub, Scope: scope, IsSearch: isSearch, URL: labels["dashboard.url"],
		State: st, ExitCode: exit, Status: asStr(c["Status"]), WorkspaceID: ws,
		UpdateAvailable: s.updatesFor(ws)[lbl(labels, "com.docker.compose.service", clean)],
		MemoryUsage:     mb, MemoryStr: ms, MemoryPercent: mp,
	}
	if len(v.ID) > 12 {
		v.ID = v.ID[:12]
	}
	if hasWeb {
		p := detectPort(labels, ports)
		v.Port = &p
	}
	if slotp != nil {
		pp := s.C.PrivateBase + *slotp
		v.PortPrivate = &pp
		if scope == "public" {
			pu := s.C.PublicBase + *slotp
			v.PortPublic = &pu
		}
	}
	if isSearch {
		v.SearchURL = lbl(labels, "dashboard.search_url", "/search?q={searchTerms}")
	}
	if cat, ok := labels["workspace.category"]; ok {
		v.Category = cat
	} else if strings.Contains(clean, "project") {
		v.Category = "projects"
	} else {
		v.Category = "services"
	}
	return v
}

func (s *Server) runningServices() []Service {
	s.svcMu.Lock()
	defer s.svcMu.Unlock()
	if s.svcData == nil || s.C.Now().Sub(s.svcAt) >= 2*time.Second {
		s.touchStats()
		slots := s.serviceSlots()
		var list []*Service
		for _, c := range s.listContainers() {
			if e := s.serviceEntry(c, slots); e != nil {
				list = append(list, e)
			}
		}
		sort.SliceStable(list, func(i, j int) bool {
			ri, rj := list[i].running(), list[j].running()
			if ri != rj {
				return ri
			}
			return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name)
		})
		s.svcData, s.svcAt = list, s.C.Now()
	}
	out := make([]Service, len(s.svcData))
	for i, p := range s.svcData {
		out[i] = *p
	}
	return out
}

// ---- HTTP ----

const maxUpload, maxJSON = 20 * 1024 * 1024, 1024 * 1024

var inlineScriptRe = regexp.MustCompile(`(?s)<script>(.*?)</script>`)

// CSP allows only the page's own inline scripts (by hash).
func CSP(body []byte) string {
	var hashes []string
	for _, m := range inlineScriptRe.FindAllSubmatch(body, -1) {
		sum := sha256.Sum256(m[1])
		hashes = append(hashes, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'")
	}
	h := strings.Join(hashes, " ")
	if h == "" {
		h = "'none'"
	}
	return "default-src 'none'; script-src " + h + "; style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; " +
		"base-uri 'none'; form-action 'self'; frame-ancestors 'self'"
}

type req struct {
	s    *Server
	w    http.ResponseWriter
	r    *http.Request
	head bool
}

func (q *req) hdr(k string) string { return q.r.Header.Get(k) }
func (q *req) host() string        { return q.r.Host }

func (q *req) respond(status int, ctype string, body []byte, cache, etag string) {
	h := q.w.Header()
	h.Set("Content-Type", ctype)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "SAMEORIGIN")
	if strings.HasPrefix(ctype, "text/html") {
		h.Set("Content-Security-Policy", CSP(body))
	}
	if cache != "" {
		h.Set("Cache-Control", cache)
	}
	if etag != "" {
		h.Set("ETag", etag)
	}
	q.w.WriteHeader(status)
	if !q.head {
		q.w.Write(body)
	}
}

func (q *req) json(status int, v any, cache string) {
	q.respond(status, "application/json", []byte(py.DumpsCompact(v)), cache, "")
}

func obj(kv ...any) *py.Object {
	o := py.NewObject()
	for i := 0; i+1 < len(kv); i += 2 {
		o.Set(kv[i].(string), kv[i+1])
	}
	return o
}

func (q *req) forbidden(msg string) { q.json(403, obj("error", msg), "") }

// pyIPPrivate is ipaddress.ip_address(host).is_private (shared-address 100.64/10 is not private).
func pyIPPrivate(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsLoopback() {
		return true
	}
	for _, p := range []string{"0.0.0.0/8", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "240.0.0.0/4", "255.255.255.255/32", "2001:db8::/32", "2001::/23", "64:ff9b:1::/48", "100::/64"} {
		if netip.MustParsePrefix(p).Contains(ip) {
			return true
		}
	}
	return false
}

func (q *req) publicScope() bool {
	if strings.ToLower(py.Strip(q.hdr("X-Access-Scope"))) == "public" {
		return true
	}
	host := ParseHost(q.host())
	if q.s.vpn[host] {
		return false
	}
	if strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".home") {
		return true
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.IsLoopback() {
			return false
		}
		return pyIPPrivate(ip)
	}
	return false
}

func (q *req) rejectForeignHost() bool {
	if q.publicScope() || q.s.privateHostAllowed(ParseHost(q.host())) {
		return false
	}
	q.forbidden("Forbidden: unknown host")
	return true
}

func (q *req) rejectCrossOrigin() bool {
	origin, has := q.r.Header["Origin"]
	cross := strings.ToLower(q.hdr("Sec-Fetch-Site")) == "cross-site"
	if cross || (has && ParseHost(originNetloc(origin[0])) != ParseHost(q.host())) {
		q.forbidden("Forbidden: cross-origin request")
		return true
	}
	return false
}

func originNetloc(o string) string {
	u, err := url.Parse(o)
	if err != nil {
		return ""
	}
	return u.Host
}

func (q *req) contentLength() int64 {
	n, err := strconv.ParseInt(py.Strip(q.hdr("Content-Length")), 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// Handler is the whole HTTP surface.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := &req{s: s, w: w, r: r, head: r.Method == "HEAD"}
		switch r.Method {
		case "GET", "HEAD":
			q.handleGet()
		case "POST":
			q.handlePost()
		default:
			http.Error(w, "Unsupported method", http.StatusNotImplemented)
		}
	})
}

func (q *req) handleGet() {
	path := q.r.URL.Path
	if path != "/healthz" && path != "/api/health" && q.rejectForeignHost() {
		return
	}
	qs := parseQuery(q.r.URL.RawQuery)
	public := q.publicScope()
	ws := ""
	if !public {
		ws, _ = q.s.workspaceForRequest(q.host(), qs)
	}
	switch path {
	case "/api/scope":
		q.json(200, obj("is_public_scope", public), "")
	case "/healthz", "/api/health":
		q.respond(200, "text/plain", []byte("OK"), "", "")
	case "/api/workspaces":
		q.workspaces(ws, public)
	case "/api/services":
		q.services(qs, ws, public)
	case "/api/system":
		if public {
			q.forbidden("Forbidden: System metrics restricted to private ingress")
			return
		}
		q.json(200, q.s.systemStats(), "no-cache")
	case "/api/wallpaper/settings":
		if public {
			core := q.s.settings("")
			g := func(k string, d any) any {
				if v, ok := core.Get(k); ok {
					return v
				}
				return d
			}
			q.json(200, obj("name", "wallpaper.png", "blur", g("blur", 0), "dim", g("dim", 20), "card_blur", g("card_blur", 16),
				"card_dim", g("card_dim", 65), "timestamp", g("timestamp", 0)), "no-cache")
			return
		}
		q.json(200, q.s.settings(ws), "no-cache")
	case "/api/wallpapers":
		if public {
			q.forbidden("Forbidden: Wallpaper management restricted to private ingress")
			return
		}
		wp := q.s.listWallpapers()
		l := make([]any, len(wp))
		for i, n := range wp {
			l[i] = n
		}
		q.json(200, obj("wallpapers", l, "total", len(wp), "settings", q.s.settings(ws), "workspace_id", orCore(ws)), "no-cache")
	case "/api/wallpaper/current":
		q.wallpaperCurrent(ws)
	case "/api/wallpaper/preview_host":
		if public {
			q.forbidden("Forbidden: Host inspection restricted to private ingress")
			return
		}
		if p := q.s.resolveHostPath(qs.first("path")); p != "" && fileExists(p) {
			q.sendImage(p, "")
		} else {
			q.respond(404, "text/plain", []byte("Host image not found"), "", "")
		}
	case "/opensearch.xml":
		q.opensearch(public)
	default:
		if strings.HasPrefix(path, "/api/") {
			q.json(404, obj("error", "Endpoint not found"), "")
		} else {
			q.respond(200, "text/html; charset=utf-8", indexHTML, "no-cache", "")
		}
	}
}

func (q *req) workspaces(ws string, public bool) {
	all := q.s.runningServices()
	running := func(l []Service) int {
		n := 0
		for _, v := range l {
			if v.running() {
				n++
			}
		}
		return n
	}
	if public {
		var pub []Service
		for _, v := range all {
			if v.public() {
				pub = append(pub, v)
			}
		}
		q.json(200, obj("workspaces", []any{}, "current_workspace", nil, "total_workspaces", 0, "total_services", len(pub),
			"total_running", running(pub), "is_public_scope", true), "no-cache")
		return
	}
	reg := q.s.registry()
	entry := func(id, name string, port any) any {
		var mine []Service
		for _, v := range all {
			if v.WorkspaceID == id {
				mine = append(mine, v)
			}
		}
		return obj("id", id, "name", name, "path", "", "http_port", port, "total", len(mine), "running", running(mine))
	}
	list := []any{}
	seen := map[string]bool{}
	for _, id := range reg.Keys() {
		v, _ := reg.Get(id)
		var port any = 80
		if m, ok := v.(*py.Object); ok {
			if p, ok := m.Get("http_port"); ok {
				port = p
			}
		}
		list = append(list, entry(id, Title(strings.ReplaceAll(id, "-", " ")), port))
		seen[id] = true
	}
	for _, v := range all {
		if id := v.WorkspaceID; id != "" && !seen[id] {
			name := Title(strings.ReplaceAll(id, "-", " "))
			if id == "core" {
				name = "Platform Core"
			}
			list = append(list, entry(id, name, 80))
			seen[id] = true
		}
	}
	var cur any
	if ws != "" {
		cur = ws
	}
	q.json(200, obj("workspaces", list, "current_workspace", cur, "total_workspaces", len(list), "total_services", len(all),
		"total_running", running(all), "is_public_scope", false), "no-cache")
}

func (q *req) services(qs query, ws string, scopePublic bool) {
	public := strings.ToLower(qs.first("scope")) == "public" || scopePublic
	list := q.s.runningServices()
	filter := ""
	if ws != "" {
		filter = ws
	} else if !scopePublic {
		if w := qs.first("workspace"); w != "" && w != "all" {
			filter, _ = q.s.resolveWorkspaceAlias(w)
		}
	}
	out := []any{}
	for _, v := range list {
		if filter != "" && v.WorkspaceID != filter {
			continue
		}
		if public {
			if !v.public() {
				continue
			}
			v = v.sanitized()
		}
		out = append(out, v.Object())
	}
	q.json(200, out, "no-cache")
}

func (q *req) currentWallpaperPath(ws string) string {
	if t := q.s.wallpaperFile(ws); t != "" {
		return t
	}
	name := "wide_nebula.png"
	if v, ok := q.s.settings(ws).Get("name"); ok {
		name = py.Str(v)
	}
	if c := filepath.Join(q.s.C.WallpapersDir, name); fileExists(c) {
		return c
	}
	if l := q.s.listWallpapers(); len(l) > 0 {
		return filepath.Join(q.s.C.WallpapersDir, l[0])
	}
	return ""
}

func (q *req) wallpaperCurrent(ws string) {
	t := q.currentWallpaperPath(ws)
	st, err := os.Stat(t)
	if t == "" || err != nil {
		q.respond(404, "text/plain", []byte("No wallpaper found"), "", "")
		return
	}
	etag := fmt.Sprintf(`"%d-%d"`, st.ModTime().Unix(), st.Size())
	if q.hdr("If-None-Match") == etag {
		q.w.Header().Set("ETag", etag)
		q.w.Header().Set("Cache-Control", "private, max-age=86400")
		q.w.WriteHeader(304)
		return
	}
	q.sendImage(t, etag)
}

func (q *req) sendImage(path, etag string) {
	f, err := os.Open(path)
	if err != nil {
		q.respond(500, "text/plain", []byte("Internal Server Error"), "", "")
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	h := q.w.Header()
	h.Set("Content-Type", DetectImageMime(path))
	h.Set("Content-Length", strconv.FormatInt(st.Size(), 10))
	if etag != "" {
		h.Set("ETag", etag)
	}
	h.Set("Cache-Control", "private, max-age=86400")
	h.Set("X-Content-Type-Options", "nosniff")
	q.w.WriteHeader(200)
	if !q.head {
		io.Copy(q.w, f)
	}
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#x27;").Replace(s)
}

var portSuffix = regexp.MustCompile(`:\d{1,5}$`)

func (q *req) opensearch(public bool) {
	host := q.hdr("Host")
	if _, ok := q.r.Header["Host"]; !ok {
		host = q.r.Host
	}
	if host == "" {
		host = "localhost"
	}
	var svc *Service
	for _, v := range q.s.runningServices() {
		if v.IsSearch && (v.public() || !public) {
			v := v
			svc = &v
			break
		}
	}
	base := ""
	if svc != nil {
		hn := ParseHost(host)
		if !public && (hn == "localhost" || strings.HasSuffix(hn, ".localhost")) {
			base = "http://" + svc.Domain + portSuffix.FindString(host)
		} else {
			p := svc.PortPrivate
			if public {
				p = svc.PortPublic
			}
			if p != nil {
				h := hn
				if strings.Contains(hn, ":") {
					h = "[" + hn + "]"
				}
				base = fmt.Sprintf("http://%s:%d%s", h, *p, strings.TrimRight(svc.Path, "/"))
			}
		}
	}
	if base == "" {
		q.respond(404, "text/plain", []byte("No search service"), "", "")
		return
	}
	path := svc.SearchURL
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	name := htmlEscape(svc.Name)
	xml := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<OpenSearchDescription xmlns="http://a9.com/-/spec/opensearch/1.1/">
  <ShortName>%s</ShortName>
  <Description>%s via om</Description>
  <InputEncoding>UTF-8</InputEncoding>
  <Url type="text/html" method="get" template="%s"/>
</OpenSearchDescription>
`, name, name, htmlEscape(base+path))
	q.respond(200, "application/opensearchdescription+xml", []byte(xml), "", "")
}

// ---- POST ----

var settingKeys = []string{"blur", "dim", "card_blur", "card_dim"}

func (q *req) handlePost() {
	if q.publicScope() {
		q.forbidden("Forbidden: Wallpaper management is restricted to private ingress")
		return
	}
	if q.rejectForeignHost() || q.rejectCrossOrigin() {
		return
	}
	qs := parseQuery(q.r.URL.RawQuery)
	ws, _ := q.s.workspaceForRequest(q.host(), qs)
	if w := py.Strip(qs.first("workspace")); w != "" && w != "all" {
		ws, _ = q.s.resolveWorkspaceAlias(w)
	}
	switch q.r.URL.Path {
	case "/api/wallpaper/upload":
		q.upload(qs, ws)
	case "/api/wallpaper/set":
		q.withJSON(func(d *py.Object) { q.setWallpaper(d, ws) })
	case "/api/wallpaper/settings":
		q.withJSON(func(d *py.Object) { q.updateSettings(d, ws) })
	default:
		q.json(404, obj("error", "Not Found"), "")
	}
}

// savedWS: the workspace_id in a save response is the request's (null for core), as in the Python handler.
func (q *req) savedWS(st *py.Object, ws string) {
	ts, _ := st.Get("timestamp")
	var w any
	if ws != "" {
		w = ws
	}
	q.json(200, obj("success", true, "timestamp", ts, "workspace_id", w), "")
}

func (q *req) withJSON(work func(*py.Object)) {
	n := q.contentLength()
	if n > maxJSON {
		q.json(413, obj("error", "Payload too large"), "")
		return
	}
	body, _ := io.ReadAll(io.LimitReader(q.r.Body, n))
	d, err := py.ParseObject(body)
	if err != nil {
		q.json(400, obj("error", err.Error()), "")
		return
	}
	work(d)
}

// pyInt is int(v) for a decoded JSON value.
func pyInt(v any) (int, bool) {
	switch x := v.(type) {
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return int(n), true
		}
		if f, err := x.Float64(); err == nil {
			return int(f), true
		}
	case float64:
		return int(x), true
	case int:
		return x, true
	case string:
		return pyIntStr(x)
	}
	return 0, false
}

func numericSettings(raw map[string]any, cur *py.Object) *py.Object {
	out := py.NewObject()
	for _, k := range settingKeys {
		if v, ok := raw[k]; ok {
			if n, ok := pyInt(v); ok {
				out.Set(k, n)
			} else if c, ok := cur.Get(k); ok {
				out.Set(k, c)
			} else {
				out.Set(k, 0)
			}
		} else if c, ok := cur.Get(k); ok {
			out.Set(k, c)
		}
	}
	return out
}

func (q *req) upload(qs query, ws string) {
	n := q.contentLength()
	if n <= 0 {
		q.json(400, obj("error", "No file uploaded"), "")
		return
	}
	if n > maxUpload {
		q.json(413, obj("error", "Payload Too Large: Maximum upload size is 20MB"), "")
		return
	}
	name := filepath.Base(firstOr(qs.first("name"), "custom_wallpaper.png"))
	if !imageExts[strings.ToLower(filepath.Ext(name))] {
		name = "custom_wallpaper.png"
	}
	cur := q.s.settings(ws)
	raw := map[string]any{}
	for _, k := range settingKeys {
		if v := qs.first(k); v != "" {
			raw[k] = v
		}
	}
	toSave := obj("name", name)
	ns := numericSettings(raw, cur)
	for _, k := range ns.Keys() {
		v, _ := ns.Get(k)
		toSave.Set(k, v)
	}
	sdir := q.s.storageDir(ws, true)
	tmp, err := os.CreateTemp(sdir, ".upload-")
	if err != nil {
		q.json(500, obj("error", "Upload failed"), "")
		return
	}
	defer os.Remove(tmp.Name())
	remaining, valid, first := n, false, true
	buf := make([]byte, 65536)
	for remaining > 0 {
		m, err := q.r.Body.Read(buf[:min(int64(len(buf)), remaining)])
		if m > 0 {
			if first {
				first, valid = false, isImageStart(buf[:m])
			}
			tmp.Write(buf[:m])
			remaining -= int64(m)
		}
		if err != nil {
			break
		}
	}
	tmp.Close()
	if !valid || remaining > 0 {
		q.json(400, obj("error", "Invalid image format"), "")
		return
	}
	if err := os.Rename(tmp.Name(), filepath.Join(sdir, "current_wallpaper")); err != nil {
		q.json(500, obj("error", "Upload failed"), "")
		return
	}
	q.savedWS(q.s.saveSettings(toSave, ws), ws)
}

func firstOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (q *req) setWallpaper(d *py.Object, ws string) {
	if w, ok := d.Get("workspace"); ok && py.Truthy(w) {
		ws, _ = q.s.resolveWorkspaceAlias(py.Str(w))
	}
	cur := q.s.settings(ws)
	name := "wallpaper.png"
	if v, ok := cur.Get("name"); ok {
		name = py.Str(v)
	}
	if v, ok := d.Get("name"); ok {
		name = py.Str(v)
	}
	toSave := obj("name", filepath.Base(name))
	raw := map[string]any{}
	for _, k := range settingKeys {
		if v, ok := d.Get(k); ok && v != nil {
			raw[k] = v
		}
	}
	ns := numericSettings(raw, cur)
	for _, k := range ns.Keys() {
		v, _ := ns.Get(k)
		toSave.Set(k, v)
	}
	source := ""
	if p, ok := d.Get("path"); ok {
		source = q.s.resolveHostPath(py.Str(p))
		if source != "" {
			toSave.Set("name", filepath.Base(source))
		}
	} else if nv, ok := d.Get("name"); ok {
		source = q.s.resolveHostPath(py.Str(nv))
	}
	if source == "" || !fileExists(source) || !strings.HasPrefix(DetectImageMime(source), "image/") {
		q.json(404, obj("error", "Source image not found in allowed directories"), "")
		return
	}
	target := filepath.Join(q.s.storageDir(ws, true), "current_wallpaper")
	b, err := os.ReadFile(source)
	if err == nil {
		err = os.WriteFile(target+".tmp", b, 0o644)
	}
	if err == nil {
		err = os.Rename(target+".tmp", target)
	}
	if err != nil {
		q.json(400, obj("error", err.Error()), "")
		return
	}
	q.savedWS(q.s.saveSettings(toSave, ws), ws)
}

func (q *req) updateSettings(d *py.Object, ws string) {
	if w, ok := d.Get("workspace"); ok && py.Truthy(w) {
		ws, _ = q.s.resolveWorkspaceAlias(py.Str(w))
	}
	nv := py.NewObject()
	for _, k := range settingKeys {
		if v, ok := d.Get(k); ok && v != nil {
			if n, ok := pyInt(v); ok {
				nv.Set(k, n)
			}
		}
	}
	if v, ok := d.Get("name"); ok && py.Truthy(v) {
		nv.Set("name", filepath.Base(py.Str(v)))
	}
	q.savedWS(q.s.saveSettings(nv, ws), ws)
}

// Run serves until SIGTERM/SIGINT.
func (s *Server) Run() error {
	go s.statsWorker()
	srv := &http.Server{Addr: s.C.Addr, Handler: s.Handler()}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		fmt.Fprintln(os.Stderr, "\n🛑 Received signal, shutting down...")
		s.stopMu.Do(func() { close(s.stop) })
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()
	fmt.Printf("🚀 om dashboard running on %s...\n", s.C.Addr)
	err := srv.ListenAndServe()
	if err == http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "✓ Dashboard server stopped cleanly.")
		return nil
	}
	return err
}

// Health is the container healthcheck: GET /healthz on the local port; nil when it answers 200.
func Health(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "" {
		host = "127.0.0.1"
	}
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("healthz returned %d", resp.StatusCode)
	}
	return nil
}

// GetRoutes and PostRoutes are the API paths the dashboard answers (docs/ARCHITECTURE.md names each one; a test
// holds the docs to this list and the list to the handler).
var (
	GetRoutes = []string{"/api/scope", "/api/workspaces", "/api/services", "/api/system", "/api/wallpaper/settings",
		"/api/wallpaper/current", "/api/wallpaper/preview_host", "/api/wallpapers", "/opensearch.xml", "/healthz", "/api/health"}
	PostRoutes = []string{"/api/wallpaper/upload", "/api/wallpaper/set", "/api/wallpaper/settings"}
)
