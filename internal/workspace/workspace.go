// Package workspace holds workspace helpers: names, ids, config files, the registry entry, compose-folder
// discovery and the environment compose runs with. Port of lib/gitops/workspace.py. Where Python calls die(),
// these functions return an error whose text is the message.
package workspace

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/registry"
	"github.com/Chitakasa/om/internal/state"
)

var ComposeNames = []string{"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}

// Go's `$` matches only at the end of the text (Python needs `\Z` for that), so "web\n" is refused.
var (
	SafeNameRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	SafeDomainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
)

// ReservedWorkspaceIDs: 'core' owns the platform's own routes; 'om' owns the container names om_* that a
// workspace called `om` would give to its own services.
var ReservedWorkspaceIDs = []string{"core", "om"}

func IsSafeName(name string) bool { return name != "" && SafeNameRE.MatchString(name) }

func IsValidWorkspaceID(id string) bool {
	if !IsSafeName(id) {
		return false
	}
	for _, r := range ReservedWorkspaceIDs {
		if id == r {
			return false
		}
	}
	return true
}

func isFile(p string) bool { st, err := os.Stat(p); return err == nil && st.Mode().IsRegular() }
func isDir(p string) bool  { st, err := os.Stat(p); return err == nil && st.IsDir() }
func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// FindComposeFile returns the first compose file of dir.
func FindComposeFile(dir string) (string, bool) {
	for _, n := range ComposeNames {
		if p := filepath.Join(dir, n); isFile(p) {
			return p, true
		}
	}
	return "", false
}

// FindWorkspaceRoot walks up from cwd to the folder that holds .om/config.json.
func FindWorkspaceRoot() (string, bool) {
	wd, err := os.Getwd()
	if err != nil {
		return "", false
	}
	cur, err := filepath.EvalSymlinks(wd)
	if err != nil {
		cur = wd
	}
	for {
		if exists(filepath.Join(cur, ".om", "config.json")) {
			return cur, true
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", false
		}
		cur = parent
	}
}

func readObject(path string) *py.Object {
	b, err := os.ReadFile(path)
	if err != nil {
		return py.NewObject()
	}
	o, err := py.ParseObject(b)
	if err != nil {
		return py.NewObject()
	}
	return o
}

// ReadConfig reads .om/config.json (empty when missing or unreadable). Key order is kept.
func ReadConfig(root string) *py.Object { return readObject(filepath.Join(root, ".om", "config.json")) }

// WriteConfig replaces .om/config.json atomically. The file is tracked in git, so the order of keys is kept.
func WriteConfig(root string, cfg *py.Object) error {
	p := filepath.Join(root, ".om", "config.json")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(py.Dumps(cfg)+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// LocalFiles are om's machine-local files, kept out of git.
var LocalFiles = []string{".om/local.json", ".om/state.json", ".om/trash/"}

// HideLocalFiles keeps om's machine-local files out of git through .git/info/exclude, without touching the
// tracked .gitignore (editing it would itself dirty the tree and block `om sync`).
func HideLocalFiles(root string) error {
	r := state.Run([]string{"git", "-C", root, "rev-parse", "--git-path", "info/exclude"})
	out := py.Strip(r.Stdout)
	if r.Code != 0 || out == "" {
		return nil
	}
	exclude := out
	if !filepath.IsAbs(exclude) {
		exclude = filepath.Join(root, exclude)
	}
	if err := os.MkdirAll(filepath.Dir(exclude), 0o755); err != nil {
		return err
	}
	have := map[string]bool{}
	if b, err := os.ReadFile(exclude); err == nil {
		for _, l := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
			have[l] = true
		}
	}
	var add strings.Builder
	for _, p := range LocalFiles {
		if !have[p] {
			add.WriteString(p + "\n")
		}
	}
	if add.Len() == 0 {
		return nil
	}
	f, err := os.OpenFile(exclude, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(add.String())
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// ReadLocal reads machine-local workspace settings (never committed), e.g. whether this machine auto-syncs.
func ReadLocal(root string) *py.Object { return readObject(filepath.Join(root, ".om", "local.json")) }

// WriteLocal writes .om/local.json (and hides it from git first).
func WriteLocal(root string, data *py.Object) error {
	if err := HideLocalFiles(root); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, ".om", "local.json"), []byte(py.Dumps(data)+"\n"), 0o644)
}

// GitopsSettings are the shared defaults from .om/config.json, overridden by this machine's .om/local.json.
func GitopsSettings(root string) map[string]any {
	g := map[string]any{"auto_sync": false, "auto_rollback": true, "interval_seconds": 300}
	for _, o := range []*py.Object{ReadConfig(root), ReadLocal(root)} {
		if v, ok := o.Get("gitops"); ok {
			if sub, ok := v.(*py.Object); ok {
				for _, k := range sub.Keys() {
					val, _ := sub.Get(k)
					g[k] = val
				}
			}
		}
	}
	return g
}

// WorkspaceID returns the workspace's id. A preview's own id lives in its machine-local .om/local.json (the
// checked-out config is the original's).
func WorkspaceID(root string) (string, error) {
	var id any
	if v, ok := ReadLocal(root).Get("workspace_id"); ok && truthy(v) {
		id = v
	} else if v, ok := ReadConfig(root).Get("workspace_id"); ok {
		id = v
	} else {
		id = strings.ToLower(filepath.Base(root))
	}
	if s, ok := id.(string); ok && IsValidWorkspaceID(s) {
		return s, nil
	}
	return "", fmt.Errorf("fatal: invalid workspace id '%s' (allowed: lowercase letters, digits, '-'; 'core' and 'om' are reserved)", py.Str(id))
}

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return x != ""
	case bool:
		return x
	case interface{ String() string }: // json.Number
		f, err := strconv.ParseFloat(x.String(), 64)
		return err != nil || f != 0
	case []any:
		return len(x) > 0
	case *py.Object:
		return x.Len() > 0
	}
	return true
}

func resolve(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

// Register records the workspace in the registry. An id already used by another existing folder is refused.
func Register(reg registry.Registry, root, id string) error {
	return reg.Update(func(w registry.Workspaces) error {
		if prev, ok := w[id]; ok {
			if pp, _ := prev["path"].(string); pp != "" && resolve(pp) != resolve(root) && exists(pp) {
				return fmt.Errorf("Workspace id '%s' is already used by %s. Pick another id in .om/config.json.", id, pp)
			}
		}
		w[id] = map[string]any{"id": id, "path": resolve(root), "last_active": time.Now().Unix()}
		return nil
	})
}

// KnownWorkspaces lists the registered workspace ids, sorted.
func KnownWorkspaces(reg registry.Registry) []string {
	var out []string
	for k := range reg.Read() {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Env is the environment compose runs with: the process environment plus the workspace's variables.
// socket is the engine socket ("" falls back to /var/run/docker.sock).
func Env(root, id, socket string) map[string]string {
	env := map[string]string{}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			env[k] = v
		}
	}
	data := composePath(filepath.Join(root, "data"))
	env["WORKSPACE_ID"] = id
	env["COMPOSE_PROJECT_NAME"] = id
	env["WORKSPACE_ROOT"] = composePath(root)
	env["DATA_DIR"] = data
	env["WORKSPACE_DATA"] = data
	env["WORKSPACE_NET"] = id + "_net"
	if socket == "" {
		socket = "/var/run/docker.sock"
	}
	env["DOCKER_SOCK"] = socket
	return env
}

func composePath(p string) string { return filepath.ToSlash(p) }

// EnvList turns Env's map into the KEY=VALUE list exec wants.
func EnvList(env map[string]string) []string {
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

// Folders never searched for compose projects.
var ignoredDirs = map[string]bool{"data": true, ".om": true, ".git": true, "docs": true, "scripts": true, "overrides": true, "__pycache__": true, "node_modules": true}

// Project is a compose folder and its '# priority: N'.
type Project struct {
	Priority int
	Dir      string
}

// priority reads the first '# priority: N' line of a folder's compose file (50 when there is none).
// Only ASCII digits count; Python's isdigit also accepts other scripts, which no compose file uses here.
func priority(dir string) int {
	cf, ok := FindComposeFile(dir)
	if !ok {
		return 50
	}
	b, err := os.ReadFile(cf)
	if err != nil {
		return 50
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		if !strings.Contains(strings.ToLower(line), "priority:") {
			continue
		}
		_, rest, _ := strings.Cut(line, ":")
		var digits strings.Builder
		for _, r := range rest {
			if r >= '0' && r <= '9' {
				digits.WriteRune(r)
			}
		}
		if digits.Len() > 0 {
			n, err := strconv.Atoi(digits.String())
			if err != nil {
				return math.MaxInt
			}
			return n
		}
	}
	return 50
}

func readDirSorted(dir string) ([]os.DirEntry, error) { return os.ReadDir(dir) } // sorted by name

func hasOmignore(dir string) bool { return exists(filepath.Join(dir, ".omignore")) }

// DiscoverComposeDirs finds the compose folders of a workspace (its root, depth 1 and 2), ordered by priority
// then name. target (case-insensitive folder name, or "root") narrows the result.
func DiscoverComposeDirs(root, target string) []Project {
	var found []Project
	lt := strings.ToLower(target)
	if _, ok := FindComposeFile(root); ok && (target == "" || lt == strings.ToLower(filepath.Base(root)) || lt == "root") {
		found = append(found, Project{priority(root), root})
	}
	seen := map[string]bool{root: true}
	children, _ := readDirSorted(root) // an unreadable root yields what was found so far
	for _, c := range children {
		child := filepath.Join(root, c.Name())
		// A folder with an .omignore file (and everything below it) is not part of the workspace.
		if !isDir(child) || ignoredDirs[c.Name()] || strings.HasPrefix(c.Name(), ".") || hasOmignore(child) {
			continue
		}
		if _, ok := FindComposeFile(child); ok && !seen[child] {
			if target == "" || lt == strings.ToLower(c.Name()) {
				found = append(found, Project{priority(child), child})
			}
			seen[child] = true
		}
		subs, err := readDirSorted(child)
		if err != nil {
			continue
		}
		for _, s := range subs {
			sub := filepath.Join(child, s.Name())
			if !isDir(sub) || strings.HasPrefix(s.Name(), ".") || ignoredDirs[s.Name()] || hasOmignore(sub) || seen[sub] {
				continue
			}
			if _, ok := FindComposeFile(sub); !ok {
				continue
			}
			if target == "" || lt == strings.ToLower(s.Name()) {
				found = append(found, Project{priority(sub), sub})
			}
			seen[sub] = true
		}
	}
	sort.SliceStable(found, func(i, j int) bool {
		if found[i].Priority != found[j].Priority {
			return found[i].Priority < found[j].Priority
		}
		return filepath.Base(found[i].Dir) < filepath.Base(found[j].Dir)
	})
	return found
}

// IgnoredComposeDirs lists folders with a compose file that DiscoverComposeDirs skips because they hold an
// .omignore (om does not manage them).
func IgnoredComposeDirs(root string) []string {
	var out []string
	children, err := readDirSorted(root)
	if err != nil {
		return out
	}
	for _, c := range children {
		child := filepath.Join(root, c.Name())
		if !isDir(child) || ignoredDirs[c.Name()] || strings.HasPrefix(c.Name(), ".") {
			continue
		}
		if hasOmignore(child) {
			if _, ok := FindComposeFile(child); ok {
				out = append(out, child)
			}
			continue
		}
		subs, err := readDirSorted(child)
		if err != nil {
			return out // Python's single try block ends the whole scan here
		}
		for _, s := range subs {
			sub := filepath.Join(child, s.Name())
			if _, ok := FindComposeFile(sub); isDir(sub) && !strings.HasPrefix(s.Name(), ".") && !ignoredDirs[s.Name()] && hasOmignore(sub) && ok {
				out = append(out, sub)
			}
		}
	}
	return out
}

// ResolveTarget returns the compose folder named target.
func ResolveTarget(root, target string) (string, error) {
	t := DiscoverComposeDirs(root, target)
	if len(t) == 0 {
		return "", fmt.Errorf("No service or project named '%s' in this workspace. See `om status`.", target)
	}
	return t[0].Dir, nil
}

var (
	containerNameRE = regexp.MustCompile(`container_name:\s*["']?([^\s"']+)`)
	wsIDVarRE       = regexp.MustCompile(`\$\{WORKSPACE_ID(:-[^}]*)?\}`)
)

// ServiceContainers lists the container names created from a compose folder (compose labels, then the
// container_name fallback, then <ws>_<folder>).
func ServiceContainers(runtime, root, dir string) ([]string, error) {
	r := state.Run([]string{runtime, "ps", "-a", "--filter", "label=com.docker.compose.project.working_dir=" + dir, "--format", "{{.Names}}"})
	if names := strings.Fields(r.Stdout); len(names) > 0 {
		return names, nil
	}
	id, err := WorkspaceID(root)
	if err != nil {
		return nil, err
	}
	var out []string
	if cf, ok := FindComposeFile(dir); ok {
		b, err := os.ReadFile(cf)
		if err != nil {
			return nil, err
		}
		for _, m := range containerNameRE.FindAllStringSubmatch(string(b), -1) {
			out = append(out, wsIDVarRE.ReplaceAllLiteralString(m[1], id))
		}
	}
	if len(out) == 0 {
		out = []string{id + "_" + filepath.Base(dir)}
	}
	return out, nil
}

// Compose is the command line for `<runtime> compose -f <file> args...`.
func Compose(runtime, file string, args ...string) []string {
	return append([]string{runtime, "compose", "-f", file}, args...)
}

// ProjectRel is a compose folder's path inside the workspace ("" for the workspace root), with forward slashes.
func ProjectRel(root, dir string) string {
	if dir == root {
		return ""
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return dir
	}
	return filepath.ToSlash(rel)
}

var buildRE = regexp.MustCompile(`(?m)^\s+build\s*:`)

// HasBuild reports whether a compose file builds an image (any Dockerfile/Containerfile name), not just pulls one.
func HasBuild(composeFile string) (bool, error) {
	b, err := os.ReadFile(composeFile)
	if err != nil {
		return false, err
	}
	return buildRE.Match(b), nil
}
