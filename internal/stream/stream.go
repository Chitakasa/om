// Package stream is the raw TCP stream tier: label parsing, port validation, HAProxy config generation and the
// fragments of every workspace. Port of lib/gitops/stream.py.
package stream

import (
	_ "embed"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Chitakasa/om/internal/engine"
	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/state"
)

// Labels for raw TCP services.
const (
	LabelTCP     = "om.tcp"
	LabelTCPPort = "om.tcp.port"
)

// Ports and port ranges reserved by om core or the system.
const (
	httpPortStart      = 20000
	httpPortEnd        = 21199 // covers 20000-20199 (private) and 21000-21199 (public)
	streamDefaultStart = 22000
	streamDefaultEnd   = 22199 // 200 default stream slots
)

var reservedExactPorts = []int{80, 443, 8080, 8443}

// HAProxyImage is the pinned image the engine-based validation runs.
const HAProxyImage = "docker.io/library/haproxy:3.0-alpine@sha256:35114f41284747c8b460babd0c082d5d8e0268218b167240f47d15d0474b718b"

//go:embed edge.base.cfg
var baseEdge string

//go:embed router.base.cfg
var baseRouter string

// BaseEdgeConfig is the base HAProxy configuration for om_stream_edge.
func BaseEdgeConfig() string { return baseEdge }

// BaseRouterConfig is the base HAProxy configuration for om_stream_router.
func BaseRouterConfig() string { return baseRouter }

func bigPort(s string) *big.Int {
	n, _ := new(big.Int).SetString(s, 10)
	return n
}

// ValidateHostPort returns the problems of an explicit host port (empty = valid). Ports are big integers because
// Python's are unbounded and a label may hold any number of digits.
func ValidateHostPort(port *big.Int, edgeHTTP, edgeHTTPS int) []string {
	var problems []string
	p := port.String()
	if port.Cmp(big.NewInt(1024)) < 0 {
		problems = append(problems, fmt.Sprintf("host port %s is privileged (must be >= 1024)", p))
	}
	if port.Cmp(big.NewInt(65535)) > 0 {
		problems = append(problems, fmt.Sprintf("host port %s is invalid (must be <= 65535)", p))
	}
	set := map[int]bool{}
	for _, r := range reservedExactPorts {
		set[r] = true
	}
	set[edgeHTTP], set[edgeHTTPS] = true, true
	var names []string
	for r := range set {
		names = append(names, strconv.Itoa(r))
	}
	sort.Strings(names) // sorted as text, as Python does
	if port.IsInt64() && set[int(port.Int64())] {
		problems = append(problems, fmt.Sprintf("host port %s clashes with core HTTP/HTTPS ports (%s)", p, strings.Join(names, ", ")))
	}
	inRange := func(lo, hi int) bool {
		return port.Cmp(big.NewInt(int64(lo))) >= 0 && port.Cmp(big.NewInt(int64(hi))) <= 0
	}
	if inRange(httpPortStart, httpPortEnd) {
		problems = append(problems, fmt.Sprintf("host port %s clashes with HTTP per-service port range (%d-%d)", p, httpPortStart, httpPortEnd))
	}
	if inRange(streamDefaultStart, streamDefaultEnd) {
		problems = append(problems, fmt.Sprintf("host port %s clashes with default stream port range (%d-%d)", p, streamDefaultStart, streamDefaultEnd))
	}
	return problems
}

// Meta is a service's stream routing configuration.
type Meta struct {
	ContainerPort int
	HostPort      *int // nil: a slot of the default range
	Scope         string
	Log           string
}

func unquote(s string) string { return strings.Trim(strings.Trim(py.Strip(s), `"`), `'`) }

// ParseMeta extracts stream routing configuration from compose labels:
//
//	om.tcp=<container-port>
//	om.tcp.port=<host-port>  (optional)
//	dashboard.scope=public   (optional; default private)
//	om.log=off               (optional; default on)
//
// Fail closed: an invalid or unreadable label returns (nil, problems). When om.tcp is not set at all it returns
// (nil, nil).
func ParseMeta(labels map[string]string, sname string, edgeHTTP, edgeHTTPS int) (*Meta, []string) {
	rawTCP, ok := labels[LabelTCP]
	if !ok || py.Strip(rawTCP) == "" {
		return nil, nil
	}
	val := unquote(rawTCP)
	if !state.IsNumber(val) {
		return nil, []string{fmt.Sprintf("%s: %s must be an integer port number (got '%s')", sname, LabelTCP, rawTCP)}
	}
	cp := bigPort(val)
	if cp.Cmp(big.NewInt(1)) < 0 || cp.Cmp(big.NewInt(65535)) > 0 {
		return nil, []string{fmt.Sprintf("%s: %s port %s out of range (1-65535)", sname, LabelTCP, cp.String())}
	}
	m := &Meta{ContainerPort: int(cp.Int64())}
	if raw, ok := labels[LabelTCPPort]; ok && py.Strip(raw) != "" {
		hp := unquote(raw)
		if !state.IsNumber(hp) {
			return nil, []string{fmt.Sprintf("%s: %s must be an integer port number (got '%s')", sname, LabelTCPPort, raw)}
		}
		port := bigPort(hp)
		if probs := ValidateHostPort(port, edgeHTTP, edgeHTTPS); len(probs) > 0 {
			out := make([]string, len(probs))
			for i, p := range probs {
				out[i] = sname + ": " + p
			}
			return nil, out
		}
		h := int(port.Int64())
		m.HostPort = &h
	}
	m.Scope = "private"
	if strings.ToLower(py.Strip(labels["dashboard.scope"])) == "public" {
		m.Scope = "public"
	}
	m.Log = "on"
	if strings.ToLower(py.Strip(labels["om.log"])) == "off" {
		m.Log = "off"
	}
	return m, nil
}

// RenderEdgeFragment renders the HAProxy fragment for om_stream_edge forwarding hostPort to the unix socket.
func RenderEdgeFragment(ws, sname string, hostPort int, log string) string {
	logOpt := ""
	if log != "off" {
		logOpt = "    log global\n    option tcplog\n"
	}
	hp := strconv.Itoa(hostPort)
	return "# Service: " + sname + " (" + ws + ")\n" +
		"frontend stream_" + hp + "\n    bind :" + hp + "\n" + logOpt + "    default_backend sock_" + hp + "\n\n" +
		"backend sock_" + hp + "\n    server s1 /run/om-stream/" + hp + ".sock\n"
}

// RenderRouterFragment renders the HAProxy fragment for om_stream_router connecting the unix socket to the target
// container.
func RenderRouterFragment(ws, sname string, hostPort, containerPort int) string {
	hp := strconv.Itoa(hostPort)
	return "# Service: " + sname + " (" + ws + ")\n" +
		"frontend sock_" + hp + "\n    bind /run/om-stream/" + hp + ".sock mode 660\n    default_backend target_" + hp + "\n\n" +
		"backend target_" + hp + "\n    server s1 " + ws + "_" + sname + ":" + strconv.Itoa(containerPort) + " resolvers docker init-addr libc,none check inter 5s\n"
}

// What the structural check allows in each section: what om's own generated configs use.
var sectionDirectives = map[string]map[string]bool{
	"global":    set("log", "stats", "maxconn", "user", "group", "chroot", "daemon", "master-worker", "pidfile"),
	"defaults":  set("mode", "log", "option", "no", "timeout", "retries", "maxconn"),
	"resolvers": set("nameserver", "parse-resolv-conf", "resolve_retries", "timeout", "hold", "accepted_payload_size"),
	"frontend":  set("bind", "mode", "default_backend", "use_backend", "log", "option", "no", "timeout", "monitor-uri", "maxconn"),
	"backend":   set("server", "mode", "balance", "timeout", "log", "option", "no", "default-server"),
}

func set(items ...string) map[string]bool {
	m := map[string]bool{}
	for _, i := range items {
		m[i] = true
	}
	return m
}

// CheckStructure is the fallback validation: known sections and directives, and a backend for every frontend
// (stream_N → sock_N, sock_N → target_N). Problems about missing backends come out sorted.
func CheckStructure(content string) []string {
	var problems []string
	frontends, backends := map[string]bool{}, map[string]bool{}
	current := ""
	for i, raw := range py.SplitLines(content) {
		n := i + 1
		line := py.Strip(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tokens := py.Fields(line)
		head := tokens[0]
		if _, isSection := sectionDirectives[head]; isSection {
			current = head
			name := ""
			if len(tokens) > 1 {
				name = tokens[1]
			}
			switch head {
			case "frontend":
				frontends[name] = true
			case "backend":
				backends[name] = true
			}
		} else if current == "" {
			problems = append(problems, fmt.Sprintf("line %d: directive '%s' outside any section", n, head))
		} else if !sectionDirectives[current][head] {
			problems = append(problems, fmt.Sprintf("line %d: unknown or invalid directive '%s' in section '%s'", n, head, current))
		}
	}
	var fes []string
	for fe := range frontends {
		if fe != "health" {
			fes = append(fes, fe)
		}
	}
	sort.Strings(fes)
	for _, fe := range fes {
		var expected string
		if strings.HasPrefix(fe, "stream_") {
			expected = strings.ReplaceAll(fe, "stream_", "sock_")
		} else {
			expected = strings.ReplaceAll(fe, "sock_", "target_")
		}
		if !backends[expected] {
			problems = append(problems, fmt.Sprintf("frontend '%s' has no matching backend '%s'", fe, expected))
		}
	}
	return problems
}

var fragmentOwnerRE = regexp.MustCompile(`^# Service: ([a-z0-9-]+) \(([a-z0-9-]+)\)`)

// FragmentName is the file of one service's fragment. '.' cannot occur in either id, so two (workspace, service)
// pairs never share a name (`a`+`b-web` and `a-b`+`web` both gave `a-b-web.cfg`). Ownership is read from the header.
func FragmentName(ws, sname string) string { return ws + "." + sname + ".cfg" }

// Stream works on the stream state of one set of directories.
type Stream struct {
	D        state.Dirs
	Run      func([]string) state.Result
	LookPath func(string) (string, error)
	Eng      *engine.Engine
}

// New returns a Stream for this machine.
func New(d state.Dirs, eng *engine.Engine) *Stream {
	return &Stream{D: d, Run: func(c []string) state.Result { return state.Run(c) }, LookPath: exec.LookPath, Eng: eng}
}

func (s *Stream) dir() string             { return filepath.Join(s.D.State, "stream") }
func (s *Stream) edgeFragments() string   { return filepath.Join(s.dir(), "fragments", "edge") }
func (s *Stream) routerFragments() string { return filepath.Join(s.dir(), "fragments", "router") }

// EdgeConfigFile and RouterConfigFile are the assembled configs the containers mount.
func (s *Stream) EdgeConfigFile() string   { return filepath.Join(s.dir(), "edge.cfg") }
func (s *Stream) RouterConfigFile() string { return filepath.Join(s.dir(), "router.cfg") }

// withConfigFile writes the config to a world-readable temporary file (an engine's haproxy user must read it),
// runs f with its path and removes it afterwards.
func withConfigFile(content string, f func(path string) state.Result) (state.Result, error) {
	tf, err := os.CreateTemp("", "*.cfg")
	if err != nil {
		return state.Result{}, err
	}
	path := tf.Name()
	defer os.Remove(path)
	if _, err := tf.WriteString(content); err != nil {
		tf.Close()
		return state.Result{}, err
	}
	if err := tf.Close(); err != nil {
		return state.Result{}, err
	}
	if err := os.Chmod(path, 0o644); err != nil {
		return state.Result{}, err
	}
	return f(path), nil
}

func outputOf(r state.Result) string {
	o := r.Stderr
	if o == "" {
		o = r.Stdout
	}
	return py.Strip(o)
}

// ValidateSyntax validates HAProxy configuration syntax with the host's haproxy if there is one, else a container
// engine, else the strict structural check.
func (s *Stream) ValidateSyntax(content, runtime string) []string {
	if bin, err := s.LookPath("haproxy"); err == nil {
		r, err := withConfigFile(content, func(p string) state.Result { return s.Run([]string{bin, "-c", "-f", p}) })
		if err != nil {
			return []string{"HAProxy validation error: " + err.Error()}
		}
		if r.Code == 0 || r.Code == 2 {
			return nil
		}
		return []string{"HAProxy validation error: " + outputOf(r)}
	}
	if runtime != "" && runtime != "om-test-no-engine" {
		if _, err := s.LookPath(runtime); err == nil {
			r, err := withConfigFile(content, func(p string) state.Result {
				abs, _ := filepath.Abs(p)
				return s.Run([]string{runtime, "run", "--rm", "-v", abs + ":/tmp/check.cfg:ro,Z", HAProxyImage, "/usr/local/sbin/haproxy", "-c", "-f", "/tmp/check.cfg"})
			})
			if err != nil {
				return []string{"HAProxy engine validation error: " + err.Error()}
			}
			if r.Code == 0 || r.Code == 2 {
				return nil
			}
			return []string{"HAProxy engine validation error: " + outputOf(r)}
		}
	}
	return CheckStructure(content)
}

type owned struct{ path, svc string }

// ownedFragments lists the fragments owned by ws, by the header inside the file. Never by file name: workspace ids
// contain '-', so `a-*.cfg` would also match the fragments of workspace `a-b`.
func ownedFragments(dir, ws string) []owned {
	files, _ := filepath.Glob(filepath.Join(dir, "*.cfg"))
	sort.Strings(files)
	var out []owned
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		first, _, _ := strings.Cut(py.UniversalNewlines(string(b)), "\n")
		if m := fragmentOwnerRE.FindStringSubmatch(first); m != nil && m[2] == ws {
			out = append(out, owned{p, m[1]})
		}
	}
	return out
}

// EnsureConfigs makes the stream folders and the base edge.cfg / router.cfg exist.
func (s *Stream) EnsureConfigs() error {
	for _, d := range []string{s.dir(), s.edgeFragments(), s.routerFragments()} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	for _, f := range []struct{ path, text string }{{s.EdgeConfigFile(), BaseEdgeConfig()}, {s.RouterConfigFile(), BaseRouterConfig()}} {
		st, err := os.Stat(f.path)
		if err == nil && !st.IsDir() {
			continue
		}
		if err == nil && st.IsDir() {
			if err := os.RemoveAll(f.path); err != nil {
				return err
			}
		}
		if err := os.WriteFile(f.path, []byte(f.text), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func assemble(base string, dir string) (string, error) {
	parts := []string{py.Strip(base)}
	files, _ := filepath.Glob(filepath.Join(dir, "*.cfg"))
	sort.Strings(files)
	for _, p := range files {
		t, err := py.ReadText(p)
		if err != nil {
			return "", err
		}
		if t = py.Strip(t); t != "" {
			parts = append(parts, t)
		}
	}
	return strings.Join(parts, "\n\n") + "\n", nil
}

// Assemble builds the full edge and router configs from the base and all fragments and validates them.
func (s *Stream) Assemble(runtime string) (edge, router string, problems []string, err error) {
	if err = s.EnsureConfigs(); err != nil {
		return
	}
	if edge, err = assemble(BaseEdgeConfig(), s.edgeFragments()); err != nil {
		return
	}
	if router, err = assemble(BaseRouterConfig(), s.routerFragments()); err != nil {
		return
	}
	problems = append(problems, s.ValidateSyntax(edge, runtime)...)
	problems = append(problems, s.ValidateSyntax(router, runtime)...)
	return
}

// Reload asks the running om_stream_edge and om_stream_router to re-read their config (SIGUSR2).
func (s *Stream) Reload(runtime string) bool {
	ok := true
	for _, c := range []string{state.StreamEdge, state.StreamRouter} {
		if s.Eng.ContainerRunning(runtime, c) {
			if s.Run([]string{runtime, "kill", "-s", "USR2", c}).Code != 0 {
				ok = false
			}
		}
	}
	return ok
}

// Service is what a fragment needs to know about one stream service.
type Service struct {
	HostPort, ContainerPort int
	Log                     string // "" means on
}

// SyncRoutes updates the stream fragments of workspace ws, assembles and validates the candidate configs. If valid
// it writes the configs atomically and reloads the running stream containers; if invalid the live configs stay
// untouched. The problems are what Python printed as "✗ Stream config validation failed: …".
func (s *Stream) SyncRoutes(ws string, services map[string]Service, runtime string) (bool, []string, error) {
	if err := s.EnsureConfigs(); err != nil {
		return false, nil, err
	}
	unlock, err := state.FileLock(filepath.Join(s.dir(), "stream.lock"))
	if err != nil {
		return false, nil, err
	}
	defer unlock()
	for sname, m := range services {
		log := m.Log
		if log == "" {
			log = "on"
		}
		name := FragmentName(ws, sname)
		if err := os.WriteFile(filepath.Join(s.edgeFragments(), name), []byte(RenderEdgeFragment(ws, sname, m.HostPort, log)), 0o644); err != nil {
			return false, nil, err
		}
		if err := os.WriteFile(filepath.Join(s.routerFragments(), name), []byte(RenderRouterFragment(ws, sname, m.HostPort, m.ContainerPort)), 0o644); err != nil {
			return false, nil, err
		}
	}
	// Prune fragments of ws for services that no longer declare om.tcp
	for _, d := range []string{s.edgeFragments(), s.routerFragments()} {
		for _, o := range ownedFragments(d, ws) {
			// also fragments under the old `<ws>-<svc>.cfg` name: they would define the frontend twice
			if _, ok := services[o.svc]; !ok || filepath.Base(o.path) != FragmentName(ws, o.svc) {
				os.Remove(o.path)
			}
		}
	}
	edge, router, problems, err := s.Assemble(runtime)
	if err != nil {
		return false, nil, err
	}
	if len(problems) > 0 {
		return false, problems, nil // fail closed: the live configs stay untouched
	}
	if err := state.WriteAtomic(s.EdgeConfigFile(), edge); err != nil {
		return false, nil, err
	}
	if err := state.WriteAtomic(s.RouterConfigFile(), router); err != nil {
		return false, nil, err
	}
	s.Reload(runtime)
	return true, nil, nil
}

// PruneFragments removes the fragments of workspace ws, rebuilds and reloads the stream configs. It reports
// whether anything was removed.
func (s *Stream) PruneFragments(ws, runtime string) (bool, error) {
	if err := s.EnsureConfigs(); err != nil {
		return false, err
	}
	unlock, err := state.FileLock(filepath.Join(s.dir(), "stream.lock"))
	if err != nil {
		return false, err
	}
	defer unlock()
	changed := false
	for _, d := range []string{s.edgeFragments(), s.routerFragments()} {
		for _, o := range ownedFragments(d, ws) {
			os.Remove(o.path)
			changed = true
		}
	}
	if !changed {
		return false, nil
	}
	edge, router, problems, err := s.Assemble(runtime)
	if err != nil {
		return true, err
	}
	if len(problems) == 0 {
		if err := state.WriteAtomic(s.EdgeConfigFile(), edge); err != nil {
			return true, err
		}
		if err := state.WriteAtomic(s.RouterConfigFile(), router); err != nil {
			return true, err
		}
		s.Reload(runtime)
	}
	return true, nil
}
