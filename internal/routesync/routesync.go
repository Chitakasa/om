// Package routesync generates a workspace's route files: compose files → Caddy route files in the state dir, and
// pruning of routes whose workspace is gone. Port of lib/gitops/routesync.py.
//
// Python prints as it goes; here every message goes to Out (the CLI passes stdout).
package routesync

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Chitakasa/om/internal/engine"
	"github.com/Chitakasa/om/internal/policy"
	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/registry"
	"github.com/Chitakasa/om/internal/routes"
	"github.com/Chitakasa/om/internal/state"
	"github.com/Chitakasa/om/internal/stream"
	"github.com/Chitakasa/om/internal/workspace"
)

// RouteSuffixes of generated route files. The *_subpath ones are routes of om before per-service ports; they are
// still listed so a sync prunes them.
var RouteSuffixes = []string{".caddy", ".private_alias", ".public_alias", ".public_subpath", ".private_subpath"}

var ownerRE = regexp.MustCompile(`^# (?:Service|Public Alias|Private Alias|Public Subpath|Private Subpath): [a-z0-9-]+ \(([a-z0-9-]+)\)`)

// Syncer carries what route generation needs from the rest of om.
type Syncer struct {
	D      state.Dirs
	Reg    registry.Registry
	Eng    *engine.Engine
	Stream *stream.Stream
	Out    io.Writer
	// Run runs `compose config` (policy.DefaultRun, or a double).
	Run policy.RunFunc
	// VPNAllow is OM_VPN_ALLOW (what `om.net.allow=vpn` means).
	VPNAllow func() []string
	// NetPolicyEnforced reports whether the host firewall carries a service's address rule.
	NetPolicyEnforced func(key string, pol map[string]any) bool
	// ReloadCaddy hot-reloads the edge's route table.
	ReloadCaddy func(runtime, workspaceID string, quiet bool) bool
}

func (s *Syncer) confD() string { return s.D.Routes }

func (s *Syncer) println(line string) { fmt.Fprintln(s.Out, line) }
func (s *Syncer) warn(text string)    { s.println("  \033[33m⚠ " + text + "\033[0m") }
func (s *Syncer) refuse(text string, problems []string) {
	s.println("  \033[31m✗ " + text + "\033[0m")
	if len(problems) > 5 {
		problems = problems[:5]
	}
	for _, p := range problems {
		s.println("      " + p)
	}
}

func hasSuffix(name string) bool {
	ext := filepath.Ext(name)
	for _, s := range RouteSuffixes {
		if ext == s {
			return true
		}
	}
	return false
}

// RouteOwner returns the workspace id recorded in a generated route file's header ("" if none).
func RouteOwner(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.SplitN(py.UniversalNewlines(strings.ToValidUTF8(string(b), "�")), "\n", 5)
	for i := 0; i < 4 && i < len(lines); i++ {
		if m := ownerRE.FindStringSubmatch(lines[i]); m != nil {
			return m[1]
		}
	}
	return ""
}

func sortedDir(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, filepath.Join(dir, e.Name()))
	}
	return out
}

// FindAliasConflict returns the route file of another workspace that already redirects one of these paths.
func (s *Syncer) FindAliasConflict(paths []string, wsID string) string {
	files, _ := filepath.Glob(filepath.Join(s.confD(), "*_alias"))
	sort.Strings(files)
	for _, f := range files {
		if RouteOwner(f) == wsID {
			continue
		}
		text, err := py.ReadText(f)
		if err != nil {
			continue
		}
		for _, p := range paths {
			if regexp.MustCompile(`(?m)^redir ` + regexp.QuoteMeta(p) + ` `).MatchString(text) {
				return filepath.Base(f)
			}
		}
	}
	return ""
}

// Orphans are route files of a workspace that is gone.
type Orphans struct {
	Owners []string
	Files  map[string][]string
}

// OrphanRouteOwners splits the route files whose workspace is gone into (prunable, stillRunning). A workspace is
// gone when it is unregistered or its folder no longer has .om/config.json (deleted without `om remove`, or on an
// unplugged drive). Workspaces that still have running containers are never pruned: their routes may be the only
// way in.
func (s *Syncer) OrphanRouteOwners(runtime string) (prunable, running Orphans) {
	reg := s.Reg.Read()
	byOwner := map[string][]string{}
	var order []string
	for _, f := range sortedDir(s.confD()) {
		if !hasSuffix(f) {
			continue
		}
		owner := RouteOwner(f)
		if owner != "" && owner != "core" {
			if _, seen := byOwner[owner]; !seen {
				order = append(order, owner)
			}
			byOwner[owner] = append(byOwner[owner], f)
		}
	}
	prunable.Files, running.Files = map[string][]string{}, map[string][]string{}
	for _, ws := range order {
		if p, _ := reg[ws]["path"].(string); p != "" {
			if st, err := os.Stat(filepath.Join(p, ".om", "config.json")); err == nil && st.Mode().IsRegular() {
				continue
			}
		}
		r := s.Eng.Run([]string{runtime, "ps", "-q", "--filter", "label=workspace.id=" + ws})
		// Engine unreachable = can't prove nothing runs: keep the routes
		if r.Code != 0 || py.Strip(r.Stdout) != "" {
			running.Owners = append(running.Owners, ws)
			running.Files[ws] = byOwner[ws]
		} else {
			prunable.Owners = append(prunable.Owners, ws)
			prunable.Files[ws] = byOwner[ws]
		}
	}
	return
}

// PruneOrphanRoutes deletes routes of workspaces that no longer exist (see OrphanRouteOwners). It keeps the
// registry entry, so a workspace that comes back is re-routed by its next `om start`. force (an explicit
// `om list --prune`) also drops workspaces whose containers may still run.
func (s *Syncer) PruneOrphanRoutes(runtime string, reload, quiet, force bool) ([]string, error) {
	prunable, running := s.OrphanRouteOwners(runtime)
	if force {
		for _, ws := range running.Owners {
			prunable.Owners = append(prunable.Owners, ws)
			prunable.Files[ws] = running.Files[ws]
		}
		running = Orphans{Files: map[string][]string{}}
	}
	removed := []string{}
	for _, ws := range prunable.Owners {
		files := prunable.Files[ws]
		for _, f := range files {
			if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
				return removed, err
			}
			removed = append(removed, f)
		}
		if err := s.Reg.ReleaseSlots(ws); err != nil {
			return removed, err
		}
		if _, err := s.Stream.PruneFragments(ws, runtime); err != nil {
			return removed, err
		}
		if !quiet {
			s.println("  \033[36m- Pruned " + strconv.Itoa(len(files)) + " route file(s) of missing workspace '" + ws + "'\033[0m")
		}
	}
	if !quiet {
		for _, ws := range running.Owners {
			s.println("  \033[33m⚠ Workspace '" + ws + "' folder is missing but its containers may still run; routes kept." +
				" Stop them, then `om core reload`.\033[0m")
		}
	}
	if len(removed) > 0 && reload {
		s.ReloadCaddy(runtime, "", true)
	}
	return removed, nil
}

// SyncCaddyRoutes regenerates this workspace's route files from its compose files and prunes stale ones. It is
// serialized: two `om` processes (a scheduled sync and a manual start) never write routes at once. configs holds
// the normalized config of compose dirs the caller already read (saves a `compose config` each).
func (s *Syncer) SyncCaddyRoutes(root, runtime string, reload bool, configs map[string]map[string]any) (bool, error) {
	unlock, err := state.FileLock(filepath.Join(s.D.State, "routes.lock"))
	if err != nil {
		return false, err
	}
	defer unlock()
	return s.sync(root, runtime, reload, configs)
}

type service struct {
	name     string
	port     int
	public   bool
	opts     routes.Options
	hasLabel func(string) bool
}

type read struct {
	port          int
	public, noWeb bool
	labels        map[string]string
	opts          routes.Options
	warnings      []routes.Warning
}

// readService returns (port, public, no_web, labels, options) of one compose folder from the engine's normalized
// config, or from the file itself when there is no engine. ok=false when it cannot be read.
func (s *Syncer) readService(root, dir, runtime, wsID string, configs map[string]map[string]any) (r read, ok bool) {
	sname := filepath.Base(dir)
	cf, found := workspace.FindComposeFile(dir)
	if !found {
		s.warn("Skipping routes for '" + sname + "': no compose file")
		return read{}, false
	}
	cfg, have := configs[dir]
	if !have {
		var msg string
		env := workspace.EnvList(workspace.Env(root, wsID, s.Eng.Info(runtime).Socket))
		cfg, msg = policy.ComposeConfig(s.Run, runtime, cf, env)
		_ = msg
	}
	vpn := s.VPNAllow()
	if len(cfg) > 0 {
		port, public, noWeb, labels := routes.ConfigMeta(cfg, sname)
		opts, w := routes.RouteOptions("", sname, labels, vpn)
		return read{port, public, noWeb, labels, opts, w}, true
	}
	content, err := py.ReadText(cf)
	if err != nil {
		s.warn("Skipping routes for '" + sname + "': " + err.Error())
		return read{}, false
	}
	port, public, noWeb := routes.ParseServiceMeta(content, sname)
	opts, w := routes.RouteOptions(content, sname, nil, vpn)
	return read{port, public, noWeb, routes.ComposeLabels(content), opts, w}, true
}

// loadSnippet adds the folder's om.caddy to opts. False (no route) when it is refused: fail closed, because the
// snippet may be what protects the service (e.g. basic_auth).
func (s *Syncer) loadSnippet(dir string, opts *routes.Options) bool {
	file := filepath.Join(dir, routes.SnippetFile)
	if st, err := os.Stat(file); err != nil || !st.Mode().IsRegular() {
		return true
	}
	snippet, err := py.ReadText(file)
	if err != nil {
		s.warn("Skipping routes for '" + filepath.Base(dir) + "': " + err.Error())
		return false
	}
	if problems := routes.ValidateSnippet(snippet); len(problems) > 0 {
		s.refuse(filepath.Base(dir)+": "+routes.SnippetFile+" refused — no route until fixed:", problems)
		return false
	}
	opts.Snippet = strings.Trim(snippet, "\n") + "\n"
	return true
}

// Candidate is a stream service the labels ask for.
type Candidate struct {
	stream.Meta
	Net *routes.NetPolicy
}

func (s *Syncer) collectServices(root, runtime, wsID string, configs map[string]map[string]any) ([]service, map[string]Candidate, []string) {
	var services []service
	cands := map[string]Candidate{}
	var candOrder []string
	for _, p := range workspace.DiscoverComposeDirs(root, "") {
		sname := filepath.Base(p.Dir)
		if !workspace.IsSafeName(sname) {
			s.warn("Skipping routes for '" + sname + "': name must match ^[a-z0-9][a-z0-9-]{0,62}\\Z")
			continue
		}
		r, ok := s.readService(root, p.Dir, runtime, wsID, configs)
		if !ok {
			continue
		}
		for _, w := range r.warnings {
			s.println(w.String())
		}
		opts, noWeb := r.opts, r.noWeb
		if len(opts.NetProblems) > 0 {
			// Fail closed, for the web route and the raw TCP route alike: an address rule that cannot be read
			// must not leave the service open to everyone.
			s.refuse(sname+": om.net labels refused — no route until fixed:", opts.NetProblems)
			continue
		}
		meta, probs := stream.ParseMeta(r.labels, sname, 80, 443)
		if len(probs) > 0 {
			s.refuse(sname+": om.tcp labels refused — no stream route until fixed:", probs)
			meta = nil
		}
		if meta != nil {
			if _, seen := cands[sname]; !seen {
				candOrder = append(candOrder, sname)
			}
			cands[sname] = Candidate{*meta, opts.Net}
			if _, has := r.labels["dashboard.port"]; !has && strings.ToLower(r.labels["dashboard.web"]) != "true" {
				noWeb = true
			}
		}
		if !s.loadSnippet(p.Dir, &opts) {
			delete(cands, sname) // a refused om.caddy is a refused service: no web route and no TCP route either
			continue
		}
		if !noWeb {
			services = append(services, service{name: sname, port: r.port, public: r.public, opts: opts})
		}
	}
	return services, cands, candOrder
}

func (s *Syncer) assignPorts(wsID string, services []service, cands map[string]Candidate) (map[string]int, map[string]registry.StreamEntry) {
	names := make([]string, len(services))
	for i, sv := range services {
		names[i] = sv.name
	}
	slots, err := s.Reg.AssignSlots(wsID, names)
	if err != nil {
		s.warn(err.Error() + "; services without one are reachable on this machine only")
		slots = s.Reg.ServiceSlots()
	}
	var assigned map[string]registry.StreamEntry
	if len(cands) > 0 {
		metas := map[string]registry.StreamMeta{}
		for n, c := range cands {
			metas[n] = registry.StreamMeta{HostPort: c.HostPort, ContainerPort: c.ContainerPort, Scope: c.Scope, Log: c.Log}
		}
		assigned, err = s.Reg.AssignStreamSlots(wsID, metas)
		if err != nil {
			s.warn(err.Error() + "; stream services not routed")
		}
	} else if err := s.Reg.ReleaseStreamSlots(wsID); err != nil {
		s.warn(err.Error())
	}
	return slots, assigned
}

func toAnyInts(l []int) []any {
	out := make([]any, len(l))
	for i, x := range l {
		out[i] = x
	}
	return out
}

func toAnyStrs(l []string) any {
	if l == nil {
		return nil
	}
	out := make([]any, len(l))
	for i, x := range l {
		out[i] = x
	}
	return out
}

func policyMap(ports []int, n *routes.NetPolicy) map[string]any {
	return map[string]any{"ports": toAnyInts(ports), "allow": toAnyStrs(n.Allow), "deny": toAnyStrs(n.Deny)}
}

// httpRoutes returns {file name: content}, the address policies and the ports that are not logged of the web
// services.
func (s *Syncer) httpRoutes(wsID string, services []service, slots map[string]int) (map[string]string, map[string]map[string]any, map[string][]int) {
	expected := map[string]string{}
	netPolicies := map[string]map[string]any{}
	noLog := map[string][]int{}
	for _, sv := range services {
		slot, hasSlot := slots[wsID+"/"+sv.name]
		var own []int
		if hasSlot {
			own = []int{state.PrivatePortBase + slot}
			if sv.public {
				own = append(own, state.PublicPortBase+slot)
			}
		}
		if sv.opts.Log == "off" && hasSlot {
			noLog[sv.name] = append([]int{}, own...)
		}
		if sv.opts.Net != nil && hasSlot {
			pol := policyMap(own, sv.opts.Net)
			netPolicies[sv.name] = pol
			if !s.NetPolicyEnforced(wsID+"/"+sv.name, pol) {
				// Fail closed: until the host firewall carries its rules, the service has no port of its own (it
				// stays reachable on this machine through <ws>.<svc>.localhost).
				s.refuse(sv.name+": its om.net rules are not in the host firewall yet; its own ports stay closed until `om firewall apply`.", nil)
				hasSlot = false
			}
		}
		slotArg := -1
		if hasSlot {
			slotArg = slot
		}
		expected[wsID+"-"+sv.name+".caddy"] = routes.RenderVhost(wsID, sv.name, sv.port, sv.opts, slotArg, sv.public)
		if !hasSlot {
			continue
		}
		if routes.AliasIsReserved("/" + sv.name) {
			s.warn("/" + sv.name + " is a path of the dashboard itself; no /" + sv.name + " redirect for " + wsID + "/" + sv.name + " (its own ports still work).")
			continue
		}
		if conflict := s.FindAliasConflict(append([]string{"/" + sv.name}, sv.opts.Aliases...), wsID); conflict != "" {
			s.warn("/" + sv.name + " or an alias is already redirected by " + conflict + "; no redirects for " + wsID + "/" + sv.name + " (its own ports still work).")
			continue
		}
		expected[wsID+"-"+sv.name+".private_alias"] = routes.RenderAlias(wsID, sv.name, state.PrivatePortBase+slot, false, sv.opts)
		if sv.public {
			expected[wsID+"-"+sv.name+".public_alias"] = routes.RenderAlias(wsID, sv.name, state.PublicPortBase+slot, true, sv.opts)
		}
	}
	return expected, netPolicies, noLog
}

// streamRoutes returns the stream services that get a route; it fills netPolicies and noLog with their ports.
func (s *Syncer) streamRoutes(wsID string, cands map[string]Candidate, assigned map[string]registry.StreamEntry,
	netPolicies map[string]map[string]any, noLog map[string][]int) map[string]stream.Service {
	active := map[string]stream.Service{}
	names := make([]string, 0, len(cands))
	for n := range cands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, sname := range names {
		meta := cands[sname]
		key := wsID + "/" + sname
		entry, ok := assigned[key]
		if !ok {
			continue
		}
		hp := entry.HostPort
		if meta.Log == "off" {
			noLog[sname] = append(noLog[sname], hp)
		}
		if meta.Net != nil {
			pol, ok := netPolicies[sname]
			if !ok {
				pol = map[string]any{"ports": []any{}}
				netPolicies[sname] = pol
			}
			ports := map[int]bool{hp: true}
			for _, p := range pol["ports"].([]any) {
				ports[p.(int)] = true
			}
			var plist []int
			for p := range ports {
				plist = append(plist, p)
			}
			sort.Ints(plist)
			pol["ports"] = toAnyInts(plist)
			if meta.Net.Allow != nil { // an empty allow-list means nobody, not "no rule"
				pol["allow"] = toAnyStrs(meta.Net.Allow)
			}
			if meta.Net.Deny != nil {
				pol["deny"] = toAnyStrs(meta.Net.Deny)
			}
			if !s.NetPolicyEnforced(key, policyMap([]int{hp}, meta.Net)) {
				s.refuse(sname+": its om.net rules are not in the host firewall yet; stream port "+strconv.Itoa(hp)+" stays closed until `om firewall apply`.", nil)
				continue
			}
		}
		active[sname] = stream.Service{HostPort: hp, ContainerPort: meta.ContainerPort, Log: meta.Log}
	}
	return active
}

// writeRoutes writes the changed route files and removes this workspace's stale ones; true if anything changed.
func (s *Syncer) writeRoutes(wsID string, expected map[string]string) (bool, error) {
	changed := false
	names := make([]string, 0, len(expected))
	for n := range expected {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, fname := range names {
		content := expected[fname]
		target := filepath.Join(s.confD(), fname)
		owner := ""
		_, statErr := os.Stat(target)
		exists := statErr == nil
		if exists {
			owner = RouteOwner(target)
		}
		if owner != "" && owner != wsID {
			// `<ws>-<svc>` is ambiguous ('-' is in both ids): never overwrite another workspace's route
			s.refuse(fname+" already belongs to workspace '"+owner+"' (same <workspace>-<service> name);"+
				" no route for "+wsID+" until one of them is renamed.", nil)
			continue
		}
		same := false
		if exists {
			if cur, err := py.ReadText(target); err == nil && cur == content {
				same = true
			}
		}
		if !same {
			if err := state.WriteAtomic(target, content); err != nil {
				return changed, err
			}
			changed = true
		}
	}
	// Prune routes for removed services and flipped tiers (a stale public route keeps a service on the LAN)
	for _, f := range sortedDir(s.confD()) {
		name := filepath.Base(f)
		if _, keep := expected[name]; hasSuffix(name) && !keep && RouteOwner(f) == wsID {
			if err := os.Remove(f); err != nil {
				return changed, err
			}
			s.println("  \033[36m- Removed stale route " + name + "\033[0m")
			changed = true
		}
	}
	return changed, nil
}

func (s *Syncer) sync(root, runtime string, reload bool, configs map[string]map[string]any) (bool, error) {
	wsID, err := workspace.WorkspaceID(root)
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(s.confD(), 0o755); err != nil {
		return false, err
	}
	services, cands, _ := s.collectServices(root, runtime, wsID, configs)
	slots, assigned := s.assignPorts(wsID, services, cands)
	expected, netPolicies, noLog := s.httpRoutes(wsID, services, slots)
	active := s.streamRoutes(wsID, cands, assigned, netPolicies, noLog)
	if ok, problems, err := s.Stream.SyncRoutes(wsID, active, runtime); err != nil {
		return false, err
	} else if !ok {
		for _, p := range problems {
			s.println("  \033[31m✗ Stream config validation failed: " + p + "\033[0m")
		}
	}
	pol := map[string]any{}
	for k, v := range netPolicies {
		pol[k] = v
	}
	if err := s.Reg.SetNetPolicies(wsID, pol); err != nil {
		return false, err
	}
	nl := map[string]any{}
	for k, v := range noLog {
		nl[k] = toAnyInts(v)
	}
	if err := s.Reg.SetNoLog(wsID, nl); err != nil {
		return false, err
	}
	changed, err := s.writeRoutes(wsID, expected)
	if err != nil {
		return false, err
	}
	if removed, err := s.PruneOrphanRoutes(runtime, false, false, false); err != nil {
		return changed, err
	} else if len(removed) > 0 {
		changed = true
	}
	if changed && reload {
		s.ReloadCaddy(runtime, wsID, false)
	}
	return changed, nil
}
