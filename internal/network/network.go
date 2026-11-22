// Package network is workspace networking: the per-project internal networks, validated edge reloads and the
// compose override that isolates each folder. Port of lib/gitops/network.py.
package network

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Chitakasa/om/internal/engine"
	"github.com/Chitakasa/om/internal/labels"
	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/state"
)

// ServiceProjectNetworkKey returns the project network key a service uses to connect to its project network
// ("om_project" when nothing in the file maps to it). cfg is the engine's normalized `compose config`.
func ServiceProjectNetworkKey(cfg map[string]any, svcName string) string {
	nets, _ := cfg["networks"].(map[string]any)
	services, _ := cfg["services"].(map[string]any)
	svc, _ := services[svcName].(map[string]any)
	var mapped []string
	for k, v := range nets {
		n, _ := v.(map[string]any)
		external := truthy(n["external"])
		if truthy(n["name"]) || (k == "default" && !external) {
			mapped = append(mapped, k)
		}
	}
	sort.Strings(mapped)
	var svcNets []string
	switch v := svc["networks"].(type) {
	case map[string]any:
		for k := range v {
			svcNets = append(svcNets, k)
		}
		// dict key order: compose prints sorted keys
		sort.Strings(svcNets)
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok {
				svcNets = append(svcNets, s)
			}
		}
	}
	for _, k := range svcNets {
		for _, m := range mapped {
			if k == m {
				return k
			}
		}
	}
	if len(svcNets) == 0 && contains(mapped, "default") {
		return "default"
	}
	return "om_project"
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// Every service folder (compose project) gets its own internal network, so a compromised service cannot reach the
// services of another folder in the same workspace. om points the folder's workspace network at it with a compose
// override; the router and om_egress are attached to each (engine.ConnectRouter). `om.network=shared` on a service
// keeps its folder on the workspace network; om.link joins two services.
const (
	WSLabel      = "om.workspace"
	ProjectLabel = "om.project"
	SharedLabel  = "om.network"
)

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// ProjectNetworkName is `<ws>_<folder>_net` from the folder's path in the workspace (`services/web` →
// `services-web`).
func ProjectNetworkName(ws, rel string) string {
	slug := strings.Trim(nonAlnum.ReplaceAllString(strings.ToLower(rel), "-"), "-")
	if slug == "" {
		slug = "root"
	}
	return ws + "_" + slug + "_net"
}

func servicesOf(cfg map[string]any) map[string]any {
	m, _ := cfg["services"].(map[string]any)
	return m
}
func networksOf(cfg map[string]any) map[string]any {
	m, _ := cfg["networks"].(map[string]any)
	return m
}

// SharesWorkspaceNetwork reports whether any service asks for `om.network=shared`.
func SharesWorkspaceNetwork(cfg map[string]any) bool {
	for _, v := range servicesOf(cfg) {
		svc, _ := v.(map[string]any)
		if strings.ToLower(py.Strip(py.Str(orEmptyStr(labels.Service(svc), SharedLabel)))) == "shared" {
			return true
		}
	}
	return false
}

func orEmptyStr(m map[string]any, k string) any {
	if v, ok := m[k]; ok {
		return v
	}
	return ""
}

// WorkspaceNetworkKeys returns the project's compose network keys that name the workspace network.
func WorkspaceNetworkKeys(cfg map[string]any, ws string) []string {
	var out []string
	for k, v := range networksOf(cfg) {
		n, _ := v.(map[string]any)
		if s, ok := n["name"].(string); ok && s == ws+"_net" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// Net works on the networks of one engine and one set of directories.
type Net struct {
	D   state.Dirs
	Eng *engine.Engine
}

func (n Net) overridePath(ws, projectDir string) string {
	sum := sha256.Sum256([]byte(projectDir))
	return filepath.Join(n.D.State, "networks", "overrides", ws+"-"+hex.EncodeToString(sum[:])[:12]+".yml")
}

func nameSlug(k string) string {
	return strings.Trim(nonAlnum.ReplaceAllString(strings.ToLower(k), "-"), "-")
}

// ProjectNetwork returns the network and the compose override that isolate this project, however its compose
// file is written:
//   - the workspace network and the implicit `default` network become the project's own internal network
//     `<ws>_<folder>_net` (the router and, if needed, om_egress are attached to it);
//   - networks the file defines itself become internal and get a per-folder name (compose would name them after
//     the workspace, so two folders defining `backend` would share it);
//   - every service not on the project network yet joins it, so the edge can reach it.
//
// Another stack's external network is left alone here; the policy gate refuses it (`networks`). It returns
// ("", "", nil) with om.network=shared, without a readable config, or when nothing joins a network. An error means
// the network cannot be made internal: the project is then not started.
func (n Net) ProjectNetwork(runtime, ws, rel, projectDir string, cfg map[string]any) (string, string, error) {
	path := n.overridePath(ws, projectDir)
	drop := func() error {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if cfg == nil || SharesWorkspaceNetwork(cfg) {
		return "", "", drop()
	}
	nets, services := networksOf(cfg), servicesOf(cfg)
	var mapped, own []string
	for k, v := range nets {
		nv, _ := v.(map[string]any)
		if nm, ok := nv["name"].(string); (ok && nm == ws+"_net") || (k == "default" && !py.Truthy(nv["external"])) {
			mapped = append(mapped, k)
		}
	}
	sort.Strings(mapped)
	for k, v := range nets {
		nv, _ := v.(map[string]any)
		if !contains(mapped, k) && !py.Truthy(nv["external"]) {
			own = append(own, k)
		}
	}
	sort.Strings(own)
	var names []string
	for s := range services {
		names = append(names, s)
	}
	sort.Strings(names)
	var joins []string
	for _, s := range names {
		svc, _ := services[s].(map[string]any)
		if py.Truthy(svc["network_mode"]) {
			continue
		}
		on := false
		switch sn := svc["networks"].(type) {
		case map[string]any:
			for k := range sn {
				on = on || contains(mapped, k)
			}
		case []any:
			for _, k := range sn {
				on = on || contains(mapped, py.Str(k))
			}
		}
		if !on {
			joins = append(joins, s)
		}
	}
	if len(mapped) == 0 && len(own) == 0 && len(joins) == 0 {
		return "", "", drop()
	}
	net := ProjectNetworkName(ws, rel)
	if n.Eng.Run([]string{runtime, "network", "inspect", net}).Code != 0 {
		relLabel := rel
		if relLabel == "" {
			relLabel = "."
		}
		r := n.Eng.Run([]string{runtime, "network", "create", "--internal", "--label", WSLabel + "=" + ws, "--label", ProjectLabel + "=" + relLabel, net})
		if r.Code != 0 {
			out := r.Stderr
			if out == "" {
				out = r.Stdout
			}
			return "", "", fmt.Errorf("cannot create %s: %s", net, lastRunes(py.Strip(out), 200))
		}
	}
	if !n.Eng.NetworkIsInternal(runtime, net) || !contains(n.Eng.ProjectNetworks(runtime, ws), net) {
		return "", "", fmt.Errorf("%s exists but is not an internal om project network (remove it: %s network rm %s)", net, runtime, net)
	}
	stem := strings.TrimSuffix(net, "_net")
	lines := []string{"# Generated by om — this project's own internal network(s). Do not edit.", "networks:"}
	for _, k := range mapped {
		lines = append(lines, "  "+py.JSONString(k)+":", "    name: "+py.JSONString(net), "    external: true")
	}
	for _, k := range own {
		lines = append(lines, "  "+py.JSONString(k)+":", "    name: "+py.JSONString(stem+"_"+nameSlug(k)), "    internal: true")
	}
	if len(joins) > 0 {
		lines = append(lines, `  "om_project":`, "    name: "+py.JSONString(net), "    external: true", "services:")
		for _, s := range joins {
			lines = append(lines, "  "+py.JSONString(s)+":", "    networks:", "      om_project: {}")
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", "", err
	}
	return net, path, os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func lastRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[len(r)-n:]
	}
	return string(r)
}

// PruneProjectNetworks removes the workspace's project networks not in keep (their folder is gone) and returns
// the names removed.
func (n Net) PruneProjectNetworks(runtime, ws string, keep map[string]bool) []string {
	removed := []string{}
	for _, net := range n.Eng.ProjectNetworks(runtime, ws) {
		if keep[net] {
			continue
		}
		for _, c := range []string{state.Router, state.Egress} {
			n.Eng.Run([]string{runtime, "network", "disconnect", "-f", net, c})
		}
		if n.Eng.Run([]string{runtime, "network", "rm", net}).Code == 0 {
			removed = append(removed, net)
		}
	}
	return removed
}

// EnsureWorkspaceNetwork makes sure the workspace's dedicated bridge network exists; new ones are internal (no
// way out except om_egress). An existing open network is reported, never changed: `om network harden`. The
// returned lines are what Python printed (already coloured).
func (n Net) EnsureWorkspaceNetwork(workspaceID, runtime string) (string, []string) {
	name := workspaceID + "_net"
	var out []string
	if !n.Eng.EnsureNetwork(runtime, name, true) {
		out = append(out, "\033[33mWarning: failed to create network "+name+"\033[0m")
	} else if !n.Eng.NetworkIsInternal(runtime, name) {
		out = append(out, "\033[33m⚠ "+name+" still has open internet access. Run `om network harden` "+
			"(services then reach only the hosts in their om.egress label).\033[0m")
	}
	return name, out
}
