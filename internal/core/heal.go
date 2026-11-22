package core

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Chitakasa/om/internal/links"
	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/state"
)

// Heal brings the core back to the desired state without user action (run at boot and periodically). It returns a
// short description of what was done ("" if nothing was needed). It never starts a core the user deliberately stopped.
func (c *Core) Heal(runtime string) (string, error) {
	if _, err := os.Stat(c.D.StopMarker); err == nil {
		return "", nil
	}
	if !c.Eng.Info(runtime).OK {
		return "", nil
	}
	var notes []string
	revived, dead := c.Eng.ReviveZombies(runtime)
	if len(revived) > 0 {
		notes = append(notes, "restarted "+strings.Join(revived, ", ")+" (process had died unseen by the engine)")
	}
	var stuck []string
	for _, n := range dead {
		core := false
		for _, cn := range state.CoreContainers {
			core = core || cn == n
		}
		if !core {
			stuck = append(stuck, n)
		}
	}
	if len(stuck) > 0 {
		notes = append(notes, "could not restart "+strings.Join(stuck, ", ")+": run `om start`")
	}
	drift, running := c.RuntimeDrift(), c.Running(runtime)
	seen := filepath.Join(c.D.Data, "heal-drift-seen")
	_, seenErr := os.Stat(seen)
	switch {
	case len(drift) > 0 && running && seenErr != nil:
		// A flapping LAN/VPN address must not recreate the edge every run: act when it persists to the next one.
		if err := os.MkdirAll(filepath.Dir(seen), 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(seen, []byte("drift seen once; the next heal run recreates the edge if it persists\n"), 0o644); err != nil {
			return "", err
		}
		notes = append(notes, "ingress addresses changed; waiting one more run before restarting the core")
		drift = nil
	case len(drift) == 0:
		os.Remove(seen)
	}
	if len(drift) > 0 || !running {
		reason := "core was not running"
		if len(drift) > 0 {
			reason = "ingress addresses changed"
		}
		ok, err := c.Up(runtime, len(drift) > 0, true)
		if err != nil {
			return "", err
		}
		res := "restarted"
		if !ok {
			res = "FAILED to restart"
		}
		return strings.Join(append(notes, reason+"; core "+res), "; "), nil
	}
	var ids []string
	for id := range c.Reg.Read() {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	failed := c.Eng.ConnectRouter(runtime, ids)
	links.Sync(c.LinksRunner(), runtime) // recreated containers lose their link networks; put them back
	c.Egress.Reload(runtime)
	sick, err := c.RestartUnhealthy(runtime, 0)
	if err != nil {
		return "", err
	}
	if len(sick) > 0 {
		notes = append(notes, "restarted unhealthy "+strings.Join(sick, ", "))
	}
	if len(failed) > 0 {
		notes = append(notes, "router re-attach failed for "+strings.Join(failed, ", "))
	}
	c.WriteMemorySnapshot(runtime)
	return strings.Join(notes, "; "), nil
}

// A service opts in with the label om.heal=restart: if its healthcheck stays unhealthy for UnhealthyAfter seconds,
// Heal restarts it, at most once per RestartCooldown.
const (
	UnhealthyAfter  = 600
	RestartCooldown = 3600
)

func fnum(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case interface{ Float64() (float64, error) }:
		f, err := x.Float64()
		return f, err == nil
	}
	return 0, false
}

// RestartUnhealthy restarts opted-in services that have been unhealthy for too long. now is a Unix time (0 means
// the current time).
func (c *Core) RestartUnhealthy(runtime string, now float64) ([]string, error) {
	if now == 0 {
		t := c.Now()
		now = float64(t.Unix()) + float64(t.Nanosecond())/1e9
	}
	r := c.Run([]string{runtime, "ps", "--filter", "health=unhealthy", "--filter", "label=om.heal=restart", "--format", "{{.Names}}"})
	var unhealthy []string
	if r.Code == 0 {
		unhealthy = strings.Fields(r.Stdout)
	}
	file := filepath.Join(c.D.Data, "heal-state.json")
	st := py.NewObject()
	if b, err := os.ReadFile(file); err == nil {
		if o, err := py.ParseObject(b); err == nil {
			st = o
		}
	}
	entry := func(name string) *py.Object {
		v, _ := st.Get(name)
		o, ok := v.(*py.Object)
		if !ok {
			o = py.NewObject()
			st.Set(name, o)
		}
		return o
	}
	isUnhealthy := func(n string) bool {
		for _, u := range unhealthy {
			if u == n {
				return true
			}
		}
		return false
	}
	var restarted []string
	for _, name := range st.Keys() { // forget healthy ones once their restart cooldown has passed
		if isUnhealthy(name) {
			continue
		}
		e := entry(name)
		e.Delete("since")
		last, has := e.Get("restarted")
		lf, _ := fnum(last)
		if !has || now-lf >= RestartCooldown {
			st.Delete(name)
		}
	}
	for _, name := range unhealthy {
		e := entry(name)
		if _, ok := e.Get("since"); !ok {
			e.Set("since", now)
		}
		since, _ := e.Get("since")
		sf, _ := fnum(since)
		last, has := e.Get("restarted")
		lf, _ := fnum(last)
		if now-sf >= UnhealthyAfter && (!has || now-lf >= RestartCooldown) {
			if c.Run(c.Eng.Lifecycle(runtime, "restart", name)).Code == 0 {
				restarted = append(restarted, name)
			}
			e.Set("restarted", now)
			e.Set("since", now)
		}
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err == nil {
		os.WriteFile(file, []byte(py.DumpsCompact(st)), 0o644)
	}
	return restarted, nil
}

// WriteMemorySnapshot records the anonymous memory per core container, for the dashboard's RAM tile. The engine API
// reports cgroup usage including shared file cache, which swings by tens of MB on a recreate; memory.stat splits it.
// Linux with a local engine only; elsewhere the dashboard keeps the engine figure.
func (c *Core) WriteMemorySnapshot(runtime string) {
	if !c.Eng.LocalEngine(runtime) {
		return
	}
	anon := map[string]any{}
	pids := c.Eng.OMPids(runtime)
	keys := make([]int, 0, len(pids))
	for p := range pids {
		keys = append(keys, p)
	}
	sort.Ints(keys)
	for _, pid := range keys {
		name := pids[pid]
		core := false
		for _, cn := range state.CoreContainers {
			core = core || cn == name
		}
		if !core {
			continue
		}
		text, err := py.ReadText(filepath.Join(c.ProcRoot, strconv.Itoa(pid), "cgroup"))
		if err != nil {
			continue
		}
		line := ""
		for _, ln := range py.SplitLines(text) {
			if strings.HasPrefix(ln, "0::") {
				line = ln
				break
			}
		}
		if line == "" {
			continue
		}
		parts := strings.Split(strings.Trim(line[3:], "/ \t\n"), "/")
		end := len(parts) - 1
		for i, p := range parts {
			if strings.HasSuffix(p, ".scope") {
				end = i
				break
			}
		}
		stat, err := py.ReadText(filepath.Join(append([]string{c.CgroupRoot}, append(parts[:end+1], "memory.stat")...)...))
		if err != nil {
			continue
		}
		for _, ln := range py.SplitLines(stat) {
			if f := py.Fields(ln); len(f) == 2 && f[0] == "anon" {
				if n, err := strconv.ParseInt(f[1], 10, 64); err == nil {
					anon[name] = n
				}
			}
		}
	}
	if len(anon) == 0 {
		return
	}
	file := filepath.Join(c.D.State, "registry", "core_memory.json")
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return
	}
	t := c.Now()
	ts := float64(t.Unix()) + float64(t.Nanosecond())/1e9
	body := py.NewObject()
	body.Set("ts", ts)
	body.Set("anon", anon)
	tmp := strings.TrimSuffix(file, ".json") + ".tmp"
	if os.WriteFile(tmp, []byte(py.DumpsCompact(body)+"\n"), 0o644) == nil {
		os.Rename(tmp, file)
	}
}
