// Package registry is the workspace registry and the other per-workspace state files: stable port slots for web
// and raw TCP stream services, address policies (om.net.*), services whose connections are not logged, and the
// networks om_egress joins. Port of lib/gitops/wsregistry.py.
//
// The files are shared with the Python implementation while both exist, so the lock files, file names and JSON
// shapes are the same; keys come out sorted (Go's rule), which is equal as JSON though not byte for byte.
package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/state"
)

// Registry reads and writes the state files under one set of directories.
type Registry struct{ D state.Dirs }

// New returns a Registry for d.
func New(d state.Dirs) Registry { return Registry{D: d} }

// withSuffix is pathlib's with_suffix: the last extension is replaced.
func withSuffix(path, suffix string) string {
	return strings.TrimSuffix(path, filepath.Ext(path)) + suffix
}

// writeJSON replaces a JSON state file in one step (a reader never sees half of it), keys sorted, newline-ended.
func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := py.DumpIndent2(v)
	if err != nil {
		return err
	}
	tmp := withSuffix(path, ".tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func lockFor(path string) (func(), error) { return state.FileLock(withSuffix(path, ".lock")) }

func wsOf(key string) string  { w, _, _ := strings.Cut(key, "/"); return w }
func svcOf(key string) string { _, s, _ := strings.Cut(key, "/"); return s }

func readObject(path string) map[string]any {
	b, err := os.ReadFile(path)
	if err != nil {
		return map[string]any{}
	}
	v, err := py.LoadJSON(b)
	m, ok := v.(map[string]any)
	if err != nil || !ok {
		return map[string]any{}
	}
	return m
}

// ---- web service slots ----

func (r Registry) readSlots() map[string]int {
	out := map[string]int{}
	for k, v := range readObject(r.D.ServicePorts) {
		if n, ok := v.(json.Number); ok {
			if i, err := n.Int64(); err == nil && i >= 0 && i < state.PortSlots {
				out[k] = int(i)
			}
		}
	}
	return out
}

// ServiceSlots returns {"<ws>/<svc>": slot} for every web service that has a port.
func (r Registry) ServiceSlots() map[string]int { return r.readSlots() }

// AssignSlots gives each of the workspace's web services a stable slot (kept across restarts; the lowest free one
// for a new service) and releases the slots of its services that are gone. It returns this workspace's slots.
func (r Registry) AssignSlots(ws string, services []string) (map[string]int, error) {
	unlock, err := lockFor(r.D.ServicePorts)
	if err != nil {
		return nil, err
	}
	defer unlock()
	want := map[string]bool{}
	for _, s := range services {
		want[s] = true
	}
	slots := map[string]int{}
	used := map[int]bool{}
	for k, v := range r.readSlots() {
		if wsOf(k) != ws || want[svcOf(k)] {
			slots[k] = v
			used[v] = true
		}
	}
	for _, svc := range services {
		key := ws + "/" + svc
		if _, ok := slots[key]; ok {
			continue
		}
		free := -1
		for i := 0; i < state.PortSlots; i++ {
			if !used[i] {
				free = i
				break
			}
		}
		if free < 0 {
			return nil, fmt.Errorf("all %d service ports are in use", state.PortSlots)
		}
		slots[key] = free
		used[free] = true
	}
	if err := writeJSON(r.D.ServicePorts, slots); err != nil {
		return nil, err
	}
	mine := map[string]int{}
	for k, v := range slots {
		if wsOf(k) == ws {
			mine[k] = v
		}
	}
	return mine, nil
}

// ReleaseSlots frees every slot of a workspace (its routes were pruned) and drops its address policies.
func (r Registry) ReleaseSlots(ws string) error {
	if _, err := r.AssignSlots(ws, nil); err != nil {
		return err
	}
	if err := r.ReleaseStreamSlots(ws); err != nil {
		return err
	}
	if err := r.SetNetPolicies(ws, nil); err != nil {
		return err
	}
	return r.SetNoLog(ws, nil)
}

// ---- raw TCP stream ports ----

// StreamEntry is one stream service's reservation. Field order is the order Python writes.
type StreamEntry struct {
	HostPort      int    `json:"host_port"`
	ContainerPort int    `json:"container_port"`
	Slot          *int   `json:"slot"`
	Scope         string `json:"scope"`
	Log           string `json:"log"`
}

// StreamMeta is what route generation knows about a stream service. HostPort is nil for a default-range slot.
type StreamMeta struct {
	HostPort      *int
	ContainerPort int
	Scope, Log    string // "" means private / on
}

func intField(m map[string]any, k string) (int, bool) {
	n, ok := m[k].(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	return int(i), err == nil
}

func strField(m map[string]any, k, def string) string {
	if s, ok := m[k].(string); ok {
		return s
	}
	return def
}

func (r Registry) readStream() map[string]StreamEntry {
	out := map[string]StreamEntry{}
	for k, v := range readObject(r.D.StreamPorts) {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		hp, ok1 := intField(m, "host_port")
		cp, ok2 := intField(m, "container_port")
		if !ok1 || !ok2 {
			continue
		}
		e := StreamEntry{HostPort: hp, ContainerPort: cp, Scope: strField(m, "scope", "private"), Log: strField(m, "log", "on")}
		if s, ok := intField(m, "slot"); ok {
			e.Slot = &s
		}
		out[k] = e
	}
	return out
}

// StreamPorts returns every stream reservation keyed "<ws>/<svc>".
func (r Registry) StreamPorts() map[string]StreamEntry { return r.readStream() }

// StreamSlots returns {"<ws>/<svc>": host_port}.
func (r Registry) StreamSlots() map[string]int {
	out := map[string]int{}
	for k, v := range r.readStream() {
		out[k] = v.HostPort
	}
	return out
}

func newEntry(hostPort int, m StreamMeta, slot *int) StreamEntry {
	e := StreamEntry{HostPort: hostPort, ContainerPort: m.ContainerPort, Slot: slot, Scope: m.Scope, Log: m.Log}
	if e.Scope == "" {
		e.Scope = "private"
	}
	if e.Log == "" {
		e.Log = "on"
	}
	return e
}

// AssignStreamSlots gives each raw TCP service of the workspace a stable slot (default 22000+n) or reserves an
// explicit host port, releasing slots and ports of services that are gone. Services are handled in sorted order
// (Python uses the order of the dict it is given).
func (r Registry) AssignStreamSlots(ws string, services map[string]StreamMeta) (map[string]StreamEntry, error) {
	unlock, err := lockFor(r.D.StreamPorts)
	if err != nil {
		return nil, err
	}
	defer unlock()
	reg := map[string]StreamEntry{}
	for k, v := range r.readStream() {
		if _, keep := services[svcOf(k)]; wsOf(k) != ws || keep {
			reg[k] = v
		}
	}
	usedSlots := map[int]bool{}
	usedPorts := map[int]string{}
	for k, v := range reg {
		if v.Slot != nil {
			usedSlots[*v.Slot] = true
		}
		usedPorts[v.HostPort] = k
	}
	names := make([]string, 0, len(services))
	for n := range services {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, svc := range names {
		meta, key := services[svc], ws+"/"+svc
		if meta.HostPort != nil {
			port := *meta.HostPort
			if o, taken := usedPorts[port]; taken && o != key {
				return nil, fmt.Errorf("stream port %d is already reserved by %s", port, o)
			}
			reg[key] = newEntry(port, meta, nil)
			usedPorts[port] = key
			continue
		}
		if cur, ok := reg[key]; ok && cur.Slot != nil {
			s := *cur.Slot
			reg[key] = newEntry(state.StreamPortBase+s, meta, &s)
			continue
		}
		slot := -1
		for i := 0; i < state.StreamPortSlots; i++ {
			if !usedSlots[i] {
				slot = i
				break
			}
		}
		if slot < 0 {
			return nil, fmt.Errorf("all %d stream ports are in use", state.StreamPortSlots)
		}
		port := state.StreamPortBase + slot
		if o, taken := usedPorts[port]; taken && o != key {
			return nil, fmt.Errorf("default stream port %d clashes with explicit reservation by %s", port, o)
		}
		reg[key] = newEntry(port, meta, &slot)
		usedSlots[slot] = true
		usedPorts[port] = key
	}
	if err := writeJSON(r.D.StreamPorts, reg); err != nil {
		return nil, err
	}
	mine := map[string]StreamEntry{}
	for k, v := range reg {
		if wsOf(k) == ws {
			mine[k] = v
		}
	}
	return mine, nil
}

// ReleaseStreamSlots frees every stream slot and port of a workspace.
func (r Registry) ReleaseStreamSlots(ws string) error {
	_, err := r.AssignStreamSlots(ws, nil)
	return err
}

// ---- address policies, unlogged ports, egress networks ----

func replaceWSEntries(path, ws string, entries map[string]any) error {
	unlock, err := lockFor(path)
	if err != nil {
		return err
	}
	defer unlock()
	data := map[string]any{}
	for k, v := range readObject(path) {
		if wsOf(k) != ws {
			data[k] = v
		}
	}
	for svc, v := range entries {
		data[ws+"/"+svc] = v
	}
	if len(data) == 0 {
		if _, err := os.Stat(path); err != nil {
			return nil
		}
	}
	return writeJSON(path, data)
}

// NetPolicies returns {"<ws>/<svc>": policy} for services with om.net.* (a policy is {"ports": [...],
// "allow": [...] | null, "deny": [...]}); entries without ports are ignored.
func (r Registry) NetPolicies() map[string]map[string]any {
	out := map[string]map[string]any{}
	for k, v := range readObject(r.D.NetPolicy) {
		if m, ok := v.(map[string]any); ok {
			if ports, _ := m["ports"].([]any); len(ports) > 0 {
				out[k] = m
			}
		}
	}
	return out
}

// SetNetPolicies replaces one workspace's address policies ({svc: policy}), keeping every other workspace's.
func (r Registry) SetNetPolicies(ws string, policies map[string]any) error {
	return replaceWSEntries(r.D.NetPolicy, ws, policies)
}

// NoLogPorts returns the own ports of every service with om.log=off, sorted and unique.
func (r Registry) NoLogPorts() []int {
	set := map[int]bool{}
	for _, v := range readObject(r.D.NoLog) {
		list, _ := v.([]any)
		for _, p := range list {
			if n, ok := p.(json.Number); ok {
				if i, err := n.Int64(); err == nil {
					set[int(i)] = true
				}
			}
		}
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// SetNoLog replaces one workspace's om.log=off services ({svc: [ports]}).
func (r Registry) SetNoLog(ws string, services map[string]any) error {
	return replaceWSEntries(r.D.NoLog, ws, services)
}

// EgressNetworks returns the workspace's networks om_egress belongs on; ok=false if unknown yet (then: all).
func (r Registry) EgressNetworks(ws string) (nets []string, ok bool) {
	list, isList := readObject(r.D.EgressNets)[ws].([]any)
	if !isList {
		return nil, false
	}
	nets = []string{}
	for _, v := range list {
		nets = append(nets, py.Str(v))
	}
	return nets, true
}

// SetEgressNetworks records the networks om_egress joins for a workspace; nil forgets the entry.
func (r Registry) SetEgressNetworks(ws string, nets []string) error {
	unlock, err := lockFor(r.D.EgressNets)
	if err != nil {
		return err
	}
	defer unlock()
	data := readObject(r.D.EgressNets)
	if nets == nil {
		delete(data, ws)
	} else {
		set := map[string]bool{}
		for _, n := range nets {
			set[n] = true
		}
		sorted := make([]string, 0, len(set))
		for n := range set {
			sorted = append(sorted, n)
		}
		sort.Strings(sorted)
		data[ws] = sorted
	}
	return writeJSON(r.D.EgressNets, data)
}

// ---- the workspace registry ----

// Workspaces is the registry file: {id: {"id", "path", "last_active", ...}}. Unknown fields are preserved.
type Workspaces map[string]map[string]any

// Read returns the registry; a missing or unreadable file is an empty registry.
func (r Registry) Read() Workspaces {
	out := Workspaces{}
	for k, v := range readObject(r.D.Registry) {
		if m, ok := v.(map[string]any); ok {
			out[k] = m
		} else {
			out[k] = map[string]any{}
		}
	}
	return out
}

// Update applies mutate under the registry lock and writes atomically. If mutate fails nothing is written.
func (r Registry) Update(mutate func(Workspaces) error) error {
	unlock, err := state.FileLock(filepath.Join(r.D.State, "workspaces.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	reg := r.Read()
	if err := mutate(reg); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(r.D.Registry), 0o755); err != nil {
		return err
	}
	b, err := py.DumpIndent2(reg)
	if err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(r.D.Registry), "workspaces.json.tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, r.D.Registry)
}
