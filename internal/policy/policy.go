// Package policy is the deploy-time gate: it refuses compose services that could escape their sandbox. Checks run
// on the normalized output of `compose config --format json`, so they see what the engine will actually run (env
// vars expanded, short syntax resolved). OM_POLICY in om.env picks the mode: `enforce` (default; refuse) or `warn`
// (report and continue). Port of lib/gitops/policy.py.
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Chitakasa/om/internal/egress"
	"github.com/Chitakasa/om/internal/labels"
	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/settings"
	"github.com/Chitakasa/om/internal/state"
)

// A service may add back only capabilities the engine grants every container by default (useful after
// `cap_drop: ALL`); anything beyond that set is a privilege escalation.
var defaultCaps = setOf("CHOWN", "DAC_OVERRIDE", "FSETID", "FOWNER", "MKNOD", "NET_RAW", "SETGID", "SETUID",
	"SETFCAP", "SETPCAP", "NET_BIND_SERVICE", "SYS_CHROOT", "KILL", "AUDIT_WRITE")

var hostNamespaces = []string{"network_mode", "pid", "ipc", "uts", "userns_mode", "cgroup"}

var unconfined = setOf("seccomp=unconfined", "seccomp:unconfined", "apparmor=unconfined", "apparmor:unconfined",
	"label=disable", "label:disable", "systempaths=unconfined",
	"no-new-privileges=false", "no-new-privileges:false")

var sensitivePaths = []string{"/", "/etc", "/proc", "/sys", "/dev", "/boot", "/root", "/run", "/var/run",
	"/var/lib/docker", "/var/lib/containers", "/usr", "/bin", "/sbin", "/lib"}

// Removable drives mount here; they hold user data, not system state.
var userMedia = []string{"/run/media", "/media", "/mnt"}

var sensitiveHome = []string{"", ".ssh", ".gnupg", ".config", ".local/share/containers", ".local/state/om", ".om",
	".docker", ".kube", ".aws"}

// Rules a service may waive for itself with `om.policy.allow=<rule>,…`. The label is part of the compose file, so
// the exception is reviewed (and signed) like any change, and `om policy check` keeps listing it. `privileged`
// and `ports` are laws: never waivable.
const AllowLabel = "om.policy.allow"

var (
	Waivable = []string{"host-namespace", "caps", "devices", "unconfined", "mounts", "networks", "egress", "egress-caps"}
	Laws     = []string{"privileged", "ports", "core-names"}
)

func setOf(items ...string) map[string]bool {
	m := map[string]bool{}
	for _, i := range items {
		m[i] = true
	}
	return m
}

func has(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// Mode is `warn` or `enforce` (fail closed: anything but `warn` enforces).
func Mode(s settings.Settings) string {
	if strings.ToLower(s.Get("OM_POLICY", "enforce")) == "warn" {
		return "warn"
	}
	return "enforce"
}

// norm compares paths as forward-slash, lower-case, so Windows (C:/Users/..) and case-insensitive macOS volumes
// match the same rules as Linux.
//
// Python's posixpath.normpath keeps exactly two leading slashes ("//etc" stays "//etc"), so a bind mount of
// `//etc` slips past the `/etc` rule although POSIX resolves it to /etc. Here a leading "//" collapses to "/": the
// one deliberate difference from the Python implementation, in the stricter direction.
func norm(path string) string {
	p := py.Normpath(strings.ReplaceAll(path, `\`, "/"))
	if strings.HasPrefix(p, "//") && !strings.HasPrefix(p, "///") {
		p = p[1:]
	}
	return strings.ToLower(p)
}

var winPathRE = regexp.MustCompile(`^[A-Za-z]:[\\/]`)

func sensitiveSource(src, home string) bool {
	if !(strings.HasPrefix(src, "/") || winPathRE.MatchString(src)) {
		return false // named volume
	}
	src, home = norm(src), norm(home)
	if strings.HasSuffix(src, ".sock") {
		return true
	}
	for _, m := range userMedia {
		if src == m || strings.HasPrefix(src, m+"/") {
			return false
		}
	}
	for _, r := range sensitivePaths {
		r = norm(r)
		// Whole system trees are off limits, including everything below them ("/" itself only exactly).
		if src == r || (r != "/" && strings.HasPrefix(src, r+"/")) {
			return true
		}
	}
	for _, sub := range sensitiveHome {
		r := py.Normpath(py.PosixJoin(home, sub))
		// $HOME itself only exactly; the listed dot-dirs including everything below them.
		if src == r || (sub != "" && strings.HasPrefix(src, r+"/")) {
			return true
		}
	}
	return false
}

// SensitiveSource reports a bind source that is an engine socket or a sensitive host path.
func SensitiveSource(src, home string) bool { return sensitiveSource(src, home) }

type finding struct{ kind, msg string }

func getList(m map[string]any, k string) []any { l, _ := m[k].([]any); return l }
func getMap(m map[string]any, k string) map[string]any {
	v, _ := m[k].(map[string]any)
	return v
}

func capSet(svc map[string]any, key string) map[string]bool {
	out := map[string]bool{}
	for _, c := range getList(svc, key) {
		out[strings.TrimPrefix(strings.ToUpper(py.Str(c)), "CAP_")] = true
	}
	return out
}

// writes: any bind or named volume not mounted read-only means the service can change data.
func writes(svc map[string]any) bool {
	for _, vol := range getList(svc, "volumes") {
		if v, ok := vol.(map[string]any); ok {
			t := "volume"
			if x, has := v["type"]; has {
				t = py.Str(x)
			}
			if (t == "bind" || t == "volume") && !py.Truthy(v["read_only"]) {
				return true
			}
		} else if s := py.Str(vol); !strings.HasSuffix(s, ":ro") && !strings.Contains(s, ":ro,") {
			return true
		}
	}
	return false
}

func egressFindings(name string, svc map[string]any) []finding {
	rawV, present := labels.Service(svc)["om.egress"]
	if !present || rawV == nil || py.Strip(py.Str(rawV)) == "" {
		return nil
	}
	list := egress.Items(py.Str(rawV))
	hasItem := func(s string) bool { return has(list, s) }
	if hasItem(egress.Learn) && len(list) > 1 {
		return []finding{{"egress", name + ": om.egress: `learn` cannot be combined with hosts"}}
	}
	if hasItem(egress.Audit) && len(list) > 1 {
		return []finding{{"egress", name + ": om.egress: `audit` cannot be combined with hosts"}}
	}
	var out []finding
	for _, h := range list {
		if h != egress.Internet && h != egress.Learn && h != egress.Audit && !egress.ValidHost(h) {
			out = append(out, finding{"egress", name + ": om.egress: `" + h + "` is not a hostname (use api.example.com or *.example.com)"})
		}
	}
	// Anti-spoofing checks: prevent source-IP spoofing on egress
	capDrop, capAdd := capSet(svc, "cap_drop"), capSet(svc, "cap_add")
	switch {
	case capAdd["NET_RAW"] || capAdd["NET_ADMIN"]:
		out = append(out, finding{"egress-caps", name + ": om.egress refuses cap_add with NET_RAW or NET_ADMIN (prevents source-IP spoofing)"})
	case !capDrop["ALL"] && !capDrop["NET_RAW"]:
		out = append(out, finding{"egress-caps", name + ": om.egress requires cap_drop: [NET_RAW] (or cap_drop: [ALL]) to prevent source-IP spoofing"})
	}
	switch {
	case hasItem(egress.Internet):
		if len(list) > 1 {
			out = append(out, finding{"egress", name + ": om.egress: `internet` cannot be combined with hosts"})
		}
		out = append(out, modeFindings(name, "internet", svc)...)
	case hasItem(egress.Audit):
		out = append(out, modeFindings(name, "audit", svc)...)
	case hasItem(egress.Learn):
		out = append(out, modeFindings(name, "learn", svc)...)
	}
	return out
}

func modeFindings(name, mode string, svc map[string]any) []finding {
	var out []finding
	if writes(svc) {
		out = append(out, finding{"egress", name + ": om.egress=" + mode + " but it can write data (a volume without :ro) — list the hosts it needs instead"})
	}
	if py.Truthy(svc["secrets"]) {
		out = append(out, finding{"egress", name + ": om.egress=" + mode + " but it receives secrets — list the hosts it needs instead"})
	}
	return out
}

func findings(name string, svc map[string]any, home string) []finding {
	out := egressFindings(name, svc)
	if py.Truthy(svc["privileged"]) {
		out = append(out, finding{"privileged", name + ": privileged: true — remove it"})
	}
	for _, key := range hostNamespaces {
		v := ""
		if py.Truthy(svc[key]) {
			v = py.Str(svc[key])
		}
		if v == "host" || (key == "network_mode" && strings.HasPrefix(v, "container:")) {
			out = append(out, finding{"host-namespace", name + ": " + key + ": " + v + " — joins a host/other namespace"})
		}
	}
	if cn := ""; py.Truthy(svc["container_name"]) {
		cn = py.Str(svc["container_name"])
		if strings.HasPrefix(cn, "om_") {
			out = append(out, finding{"core-names", name + ": container_name: " + cn + " — om_* names belong to the core"})
		}
	}
	if py.Truthy(svc["ports"]) {
		out = append(out, finding{"ports", name + ": ports: publishes host ports — use `expose:`; the edge routes to it"})
	}
	var caps []string
	for c := range capSet(svc, "cap_add") {
		if !defaultCaps[c] {
			caps = append(caps, c)
		}
	}
	if len(caps) > 0 {
		sort.Strings(caps)
		out = append(out, finding{"caps", name + ": cap_add: " + strings.Join(caps, ", ") + " — beyond the engine's default capability set"})
	}
	if py.Truthy(svc["devices"]) {
		out = append(out, finding{"devices", name + ": devices: passes host devices into the container"})
	}
	for _, opt := range getList(svc, "security_opt") {
		if unconfined[strings.ReplaceAll(py.Str(opt), " ", "")] {
			out = append(out, finding{"unconfined", name + ": security_opt: " + py.Str(opt) + " — removes a kernel confinement layer"})
		}
	}
	for _, vol := range getList(svc, "volumes") {
		src, vtype := "", "bind"
		if v, ok := vol.(map[string]any); ok {
			if x, has := v["source"]; has {
				src = py.Str(x)
			}
			if x, has := v["type"]; has {
				vtype = py.Str(x)
			}
		} else {
			src = strings.SplitN(py.Str(vol), ":", 2)[0]
		}
		if vtype == "bind" && sensitiveSource(src, home) {
			out = append(out, finding{"mounts", name + ": volume " + src + " — engine socket or sensitive host path"})
		}
	}
	return out
}

// allowed returns the rules waived by the service's label, plus violations for unreadable or non-waivable entries.
func allowed(name string, svc map[string]any) (map[string]bool, []string) {
	raw := ""
	if v := labels.Service(svc)[AllowLabel]; py.Truthy(v) {
		raw = py.Str(v)
	}
	ok := map[string]bool{}
	var bad []string
	for _, r := range strings.Split(raw, ",") {
		rule := strings.ToLower(py.Strip(r))
		switch {
		case rule == "":
		case has(Waivable, rule):
			ok[rule] = true
		case has(Laws, rule):
			bad = append(bad, name+": "+AllowLabel+"="+rule+" — `"+rule+"` is a law and cannot be waived")
		default:
			bad = append(bad, name+": "+AllowLabel+"="+rule+" — unknown rule (one of: "+strings.Join(Waivable, ", ")+")")
		}
	}
	return ok, bad
}

// networkFindings: joining another stack's network (external, not the workspace's) would bridge this folder's own
// isolated network to it; om.link is the way to reach one other service.
func networkFindings(name string, svc, cfg map[string]any, wsNet string) []finding {
	if wsNet == "" {
		return nil
	}
	nets := getMap(cfg, "networks")
	var keys []string
	switch v := svc["networks"].(type) {
	case map[string]any:
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
	case []any:
		for _, k := range v {
			keys = append(keys, py.Str(k))
		}
	}
	var out []finding
	for _, key := range keys {
		n := getMap(nets, key)
		nm, hasName := n["name"]
		if py.Truthy(n["external"]) && hasName && nm != nil && py.Str(nm) != wsNet {
			out = append(out, finding{"networks", name + ": joins network " + py.Str(nm) + " of another stack — every folder gets its own; reach another service with om.link"})
		}
	}
	return out
}

// EvaluateService returns (violations, waived findings) for one normalized compose service. extra are findings
// from checks that need the whole config.
func evaluateService(name string, svc map[string]any, home string, extra []finding) ([]string, []string) {
	ok, bad := allowed(name, svc)
	found := append(findings(name, svc, home), extra...)
	viol := append([]string{}, bad...)
	waived := []string{}
	for _, f := range found {
		if ok[f.kind] {
			waived = append(waived, f.msg)
		} else {
			viol = append(viol, f.msg)
		}
	}
	return viol, waived
}

// CheckService returns the violations of one normalized compose service.
func CheckService(name string, svc map[string]any, home string) []string {
	if home == "" {
		home = homeDir()
	}
	v, _ := evaluateService(name, svc, home, nil)
	return v
}

func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return h
}

// mountFindings: ways to put host files into a container other than a bind mount in the service's own
// `volumes:`: a named volume whose driver options bind a host path, configs and secrets whose file is a sensitive
// host path, and `volumes_from` a container that is not a service of this file (it hands over that container's
// mounts).
func mountFindings(name string, svc, cfg map[string]any, home string) []finding {
	var out []finding
	volumes := getMap(cfg, "volumes")
	for _, vol := range getList(svc, "volumes") {
		v, ok := vol.(map[string]any)
		if !ok || py.Str(v["type"]) != "volume" || v["type"] == nil {
			continue
		}
		opts := getMap(getMap(volumes, py.Str(v["source"])), "driver_opts")
		device := ""
		if x, has := opts["device"]; has {
			device = py.Str(x)
		}
		if strings.Contains(py.Str(orEmpty(opts, "o")), "bind") && device != "" && sensitiveSource(device, home) {
			out = append(out, finding{"mounts", name + ": volume " + py.Str(v["source"]) + " binds " + device + " through driver_opts — engine socket or sensitive host path"})
		}
	}
	for _, kind := range []string{"configs", "secrets"} {
		defined := getMap(cfg, kind)
		for _, ref := range getList(svc, kind) {
			var key any = ref
			if r, ok := ref.(map[string]any); ok {
				key = r["source"]
			}
			source := ""
			if f := getMap(defined, py.Str(key))["file"]; py.Truthy(f) {
				source = py.Str(f)
			}
			if source != "" && sensitiveSource(source, home) {
				out = append(out, finding{"mounts", name + ": " + strings.TrimSuffix(kind, "s") + " " + py.Str(key) + " is " + source + " — sensitive host path"})
			}
		}
	}
	own := getMap(cfg, "services")
	for _, ref := range getList(svc, "volumes_from") {
		r := py.Str(ref)
		target := strings.SplitN(r, ":", 2)[0]
		if strings.HasPrefix(r, "container:") {
			target = r
		}
		if _, ok := own[target]; !ok {
			out = append(out, finding{"mounts", name + ": volumes_from " + r + " — inherits the mounts of a container that is not a service of this file"})
		}
	}
	return out
}

func orEmpty(m map[string]any, k string) any {
	if v, ok := m[k]; ok {
		return v
	}
	return ""
}

// EvaluateConfig returns (violations, waived findings) for a whole normalized config. wsNet is the workspace
// network name ("" skips the network rule); home "" means the user's home.
func EvaluateConfig(cfg map[string]any, home, wsNet string) ([]string, []string) {
	if home == "" {
		home = homeDir()
	}
	violations := SecretFindings(cfg)
	waived := []string{}
	services := getMap(cfg, "services")
	names := make([]string, 0, len(services))
	for n := range services {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		svc, _ := services[name].(map[string]any)
		extra := append(networkFindings(name, svc, cfg, wsNet), mountFindings(name, svc, cfg, home)...)
		v, w := evaluateService(name, svc, home, extra)
		violations = append(violations, v...)
		waived = append(waived, w...)
	}
	return violations, waived
}

// CheckConfig returns the violations of a whole normalized config.
func CheckConfig(cfg map[string]any, home string) []string {
	v, _ := EvaluateConfig(cfg, home, "")
	return v
}

// SecretFindings: no secrets in configuration. A declared secret must not exist as plaintext next to the
// compose file.
func SecretFindings(cfg map[string]any) []string {
	out := []string{}
	secrets := getMap(cfg, "secrets")
	names := make([]string, 0, len(secrets))
	for n := range secrets {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		spec, _ := secrets[name].(map[string]any)
		file := ""
		if f := spec["file"]; py.Truthy(f) {
			file = py.Str(f)
		}
		// Python: str(Path("")) is "." (never a file); a path we may not stat (e.g. an engine socket in /run)
		// holds no plaintext secret of ours.
		if file != "" {
			if st, err := os.Stat(file); err == nil && st.Mode().IsRegular() {
				out = append(out, "secret "+name+": "+filepath.Base(file)+" is plaintext in the workspace — `om secrets set <project>/"+name+"`, then delete it")
			}
		}
	}
	return out
}

// RunFunc runs a command in a directory with an environment (state.Run with options, or a test double).
type RunFunc func(cmd []string, dir string, env []string) state.Result

// ComposeConfig returns the engine's own normalized `compose config` for a file, or an error message.
func ComposeConfig(run RunFunc, runtime, composeFile string, env []string) (map[string]any, string) {
	r := run([]string{runtime, "compose", "-f", composeFile, "config", "--format", "json"}, filepath.Dir(composeFile), env)
	if r.Code != 0 {
		out := r.Stderr
		if out == "" {
			out = r.Stdout
		}
		return nil, fmt.Sprintf("%s: `compose config` failed: %s", composeFile, lastRunes(py.Strip(out), 300))
	}
	var cfg map[string]any
	if json.Unmarshal([]byte(r.Stdout), &cfg) != nil || cfg == nil {
		return nil, composeFile + ": `compose config` did not return JSON"
	}
	return cfg, ""
}

func lastRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[len(r)-n:]
	}
	return string(r)
}

// EvaluateCompose checks a config (or reports why there is none).
func EvaluateCompose(cfg map[string]any, errMsg, wsNet string) ([]string, []string) {
	if cfg == nil {
		return []string{errMsg}, []string{}
	}
	return EvaluateConfig(cfg, "", wsNet)
}

// EgressServices returns {svc: rule} for services with a usable om.egress label.
func EgressServices(cfg map[string]any) map[string]egress.Rule {
	out := map[string]egress.Rule{}
	for name, v := range getMap(cfg, "services") {
		svc, _ := v.(map[string]any)
		if r, ok := egress.ParseLabel(labels.Service(svc)["om.egress"]); ok && r.Truthy() {
			out[name] = r
		}
	}
	return out
}

// DefaultRun is the RunFunc backed by state.Run.
func DefaultRun(cmd []string, dir string, env []string) state.Result {
	return state.Run(cmd, state.WithDir(dir), state.WithEnv(env))
}
