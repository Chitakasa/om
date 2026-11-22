package settings

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Chitakasa/om/internal/state"
)

// The front door's host ports are OM_HTTP_PORT and OM_HTTPS_PORT. Either may be `auto`: `om core start` then picks a
// port that is free on this machine and remembers it (<state>/registry/edge_ports.json), so URLs stay the same from
// one start to the next. Before the first start, and for any command that only reads the settings, `auto` is the
// default (80 and 443).

// edgeCandidates are tried in order. They avoid 8080 and 8443 (the public tier's host ports) and 81 and 444 (the VPN
// fallback), which the core binds on VPN addresses.
var edgeCandidates = map[string][]int{
	"OM_HTTP_PORT":  {80, 8000, 8888, 9080},
	"OM_HTTPS_PORT": {443, 8444, 9443, 9444},
}

func edgePortsFile(d state.Dirs) string { return filepath.Join(d.State, "registry", "edge_ports.json") }

func readEdgePorts(d state.Dirs) map[string]int {
	out := map[string]int{}
	b, err := os.ReadFile(edgePortsFile(d))
	if err != nil {
		return out
	}
	json.Unmarshal(b, &out)
	return out
}

// applyAutoPorts replaces an `auto` front-door port by the remembered one, or the default.
func applyAutoPorts(d state.Dirs, s Settings) {
	stored := readEdgePorts(d)
	for key, cands := range edgeCandidates {
		if !strings.EqualFold(s[key], "auto") {
			continue
		}
		port := cands[0]
		if p := stored[key]; p >= 1 && p <= 65535 {
			port = p
		}
		s[key] = fmt.Sprint(port)
	}
}

// ResolveEdgePorts settles the front-door ports that are `auto` in the user's settings and returns a line for each
// one it moved off the default. A remembered port is kept while it is free or while this core's own edge holds it
// (ownEdge, asked only when a remembered port is not free); otherwise the first free candidate is taken. free reports
// whether a port can be bound. Nothing is asked of the engine when no port is `auto`.
func ResolveEdgePorts(d state.Dirs, free func(int) bool, ownEdge func() bool) ([]string, error) {
	raw, err := state.ParseEnvFile(d.UserEnv)
	if err != nil {
		return nil, err
	}
	stored := readEdgePorts(d)
	next := map[string]int{}
	for k, v := range stored {
		next[k] = v
	}
	var notes []string
	taken := map[int]bool{}
	for _, key := range []string{"OM_HTTP_PORT", "OM_HTTPS_PORT"} {
		if !strings.EqualFold(raw[key], "auto") {
			delete(next, key)
			continue
		}
		cands := edgeCandidates[key]
		keep := stored[key]
		if keep >= 1 && !taken[keep] && (free(keep) || ownEdge()) {
			taken[keep] = true
			continue
		}
		chosen := 0
		for _, p := range cands {
			if !taken[p] && free(p) {
				chosen = p
				break
			}
		}
		if chosen == 0 {
			return nil, fmt.Errorf("%s is auto but none of the ports %v is free: free one, or set %s to a port", key, cands, key)
		}
		taken[chosen] = true
		next[key] = chosen
		if chosen != cands[0] {
			notes = append(notes, fmt.Sprintf("%s is auto: port %d is not free here, using %d", key, cands[0], chosen))
		}
	}
	b, _ := json.Marshal(next)
	if string(b) != "{}" || len(stored) > 0 {
		if err := state.WriteAtomic(edgePortsFile(d), string(b)+"\n"); err != nil {
			return nil, err
		}
	}
	return notes, nil
}
