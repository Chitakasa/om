// Package links implements cross-workspace links: one service may reach one service of another workspace, any
// protocol.
//
//	consumer labels:  om.link=perso/db            (comma list of <workspace>/<service>)
//	provider labels:  om.link.allow=containers/app (comma list; <ws>/* allows a whole workspace)
//
// A link exists only when both sides declare it. om then puts exactly those two containers on a private internal
// network of their own (`omlink-<hash>`, nothing else attached, no route out) and gives the provider the alias
// `<ws>-<svc>` there, so the consumer reaches it as `perso-db:5432`. Neither workspace becomes reachable
// otherwise. Containers are read from the engine (their labels), so a link works whichever workspace starts first;
// `om start` and the heal timer keep it attached after a container is recreated, and remove links nobody declares
// any more. Port of lib/gitops/links.py.
package links

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/state"
)

const (
	LinkLabel  = "om.link"
	AllowLabel = "om.link.allow"
	NetPrefix  = "omlink-"
)

// Container is an om workspace container as the engine reports it.
type Container struct {
	Name, WS, Svc string
	Labels        map[string]string
	Running       bool
	Networks      []string
}

// ID is "<workspace>/<service>".
func (c Container) ID() string { return c.WS + "/" + c.Svc }

// Link is one declared, allowed link.
type Link struct{ Net, Consumer, Provider string }

// Runner runs an engine command.
type Runner func([]string) state.Result

func split(value string) []string {
	var out []string
	for _, x := range strings.Split(value, ",") {
		if x = py.Strip(x); x != "" {
			out = append(out, strings.ToLower(x))
		}
	}
	return out
}

// Containers lists the om workspace containers (running or not).
func Containers(run Runner, runtime string) []Container {
	ids := strings.Fields(run([]string{runtime, "ps", "-aq", "--filter", "label=workspace.id"}).Stdout)
	if len(ids) == 0 {
		return nil
	}
	r := run(append([]string{runtime, "inspect"}, ids...))
	text := r.Stdout
	if text == "" {
		text = "[]"
	}
	var data []struct {
		Name            string
		Config          struct{ Labels map[string]string }
		State           struct{ Running bool }
		NetworkSettings struct{ Networks map[string]any }
	}
	if json.Unmarshal([]byte(text), &data) != nil {
		return nil
	}
	var out []Container
	for _, c := range data {
		name := strings.TrimLeft(c.Name, "/")
		ws := c.Config.Labels["workspace.id"]
		if ws == "" || !strings.HasPrefix(name, ws+"_") {
			continue
		}
		var nets []string
		for n := range c.NetworkSettings.Networks {
			nets = append(nets, n)
		}
		sort.Strings(nets)
		lbl := c.Config.Labels
		if lbl == nil {
			lbl = map[string]string{}
		}
		out = append(out, Container{Name: name, WS: ws, Svc: name[len(ws)+1:], Labels: lbl, Running: c.State.Running, Networks: nets})
	}
	return out
}

// Allowed reports whether the provider's allow list lets the consumer in (itself, or its whole workspace).
func Allowed(allow []string, consumer string) bool {
	ws, _, _ := strings.Cut(consumer, "/")
	for _, a := range allow {
		if a == consumer || a == ws+"/*" {
			return true
		}
	}
	return false
}

// NetworkName is the name of the link network of a consumer/provider pair.
func NetworkName(consumer, provider string) string {
	sum := sha256.Sum256([]byte(consumer + ">" + provider))
	return NetPrefix + hex.EncodeToString(sum[:])[:12]
}

// Alias is the name the provider has on the link network.
func Alias(provider string) string { return strings.ReplaceAll(provider, "/", "-") }

// Desired returns the links the containers' labels declare (in container order) and the problems.
func Desired(conts []Container) ([]Link, []string) {
	byID := map[string]Container{}
	for _, c := range conts {
		byID[c.ID()] = c
	}
	var links []Link
	index := map[string]int{}
	var problems []string
	for _, c := range conts {
		me := c.ID()
		for _, target := range split(c.Labels[LinkLabel]) {
			p, found := byID[target]
			switch {
			case !strings.Contains(target, "/"):
				problems = append(problems, fmt.Sprintf("%s: om.link=%s — use <workspace>/<service>", me, target))
			case !found:
				problems = append(problems, fmt.Sprintf("%s: om.link=%s — no such service (not created yet?)", me, target))
			case !Allowed(split(p.Labels[AllowLabel]), me):
				problems = append(problems, fmt.Sprintf("%s: om.link=%s — %s does not allow it; add to its labels: om.link.allow=%s", me, target, target, me))
			default:
				l := Link{NetworkName(me, target), me, target}
				if i, dup := index[l.Net]; dup {
					links[i] = l // a dict keeps the first position and the last value
				} else {
					index[l.Net] = len(links)
					links = append(links, l)
				}
			}
		}
	}
	return links, problems
}

func connect(run Runner, runtime, net, container string, extra ...string) bool {
	cmd := append([]string{runtime, "network", "connect"}, extra...)
	r := run(append(cmd, net, container))
	out := strings.ToLower(r.Stdout + r.Stderr)
	return r.Code == 0 || strings.Contains(out, "already") || strings.Contains(out, "exists")
}

// Sync makes the link networks match the declarations. It returns the problems (one-sided or broken links).
func Sync(run Runner, runtime string) []string {
	conts := Containers(run, runtime)
	want, problems := Desired(conts)
	byID := map[string]Container{}
	for _, c := range conts {
		byID[c.ID()] = c
	}
	have := map[string]bool{}
	for _, n := range strings.Fields(run([]string{runtime, "network", "ls", "--filter", "label=om.link=true", "--format", "{{.Name}}"}).Stdout) {
		have[n] = true
	}
	for _, l := range want {
		if !have[l.Net] {
			run([]string{runtime, "network", "create", "--internal", "--label", "om.link=true", "--label", "om.link.pair=" + l.Consumer + ">" + l.Provider, l.Net})
		}
		if !connect(run, runtime, l.Net, byID[l.Provider].Name, "--alias", Alias(l.Provider)) {
			problems = append(problems, l.Consumer+" → "+l.Provider+": could not attach "+l.Provider)
		}
		if !connect(run, runtime, l.Net, byID[l.Consumer].Name) {
			problems = append(problems, l.Consumer+" → "+l.Provider+": could not attach "+l.Consumer)
		}
		// Anything else on a link network does not belong there.
		for _, c := range conts {
			if hasNet(c, l.Net) && c.ID() != l.Consumer && c.ID() != l.Provider {
				run([]string{runtime, "network", "disconnect", l.Net, c.Name})
			}
		}
	}
	if len(conts) == 0 { // nothing listed (engine hiccup?): never mistake that for "nobody declares a link any more"
		return problems
	}
	wanted := map[string]bool{}
	for _, l := range want {
		wanted[l.Net] = true
	}
	var stale []string
	for n := range have {
		if !wanted[n] {
			stale = append(stale, n)
		}
	}
	sort.Strings(stale)
	for _, net := range stale {
		for _, c := range conts {
			if hasNet(c, net) {
				run([]string{runtime, "network", "disconnect", net, c.Name})
			}
		}
		run([]string{runtime, "network", "rm", net})
	}
	return problems
}

func hasNet(c Container, net string) bool {
	for _, n := range c.Networks {
		if n == net {
			return true
		}
	}
	return false
}

// Described is one link and the name the consumer reaches the provider by.
type Described struct{ Consumer, Provider, As string }

// Describe lists the declared links without changing anything, sorted by consumer then provider.
func Describe(run Runner, runtime string) ([]Described, []string) {
	want, problems := Desired(Containers(run, runtime))
	sort.Slice(want, func(i, j int) bool {
		if want[i].Consumer != want[j].Consumer {
			return want[i].Consumer < want[j].Consumer
		}
		return want[i].Provider < want[j].Provider
	})
	out := []Described{}
	for _, l := range want {
		out = append(out, Described{l.Consumer, l.Provider, Alias(l.Provider)})
	}
	return out, problems
}
