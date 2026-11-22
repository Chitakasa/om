package cli

import (
	"bytes"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/state"
)

var klogRE = regexp.MustCompile(`kernel: (om-(?:refused|in))(?: ([^:]*))?: .*?\bSRC=(\S+) .*?\bPROTO=(\S+)(?: .*?\bDPT=(\d+))?`)

func (a *App) portNames() map[int]string {
	h, s := a.Settings().EdgePorts()
	names := map[int]string{h: "front door (http)", s: "front door (https)"}
	names[8080], names[8443] = "public tier (VPN)", "public tier https (VPN)"
	slots := a.Reg.ServiceSlots()
	for _, key := range sortedKeys(slots) {
		names[state.PrivatePortBase+slots[key]] = key + " (private)"
		names[state.PublicPortBase+slots[key]] = key + " (public)"
	}
	return names
}

type fwCount struct {
	key []string
	n   int
}

func countSorted(m map[string]*fwCount, order []string) []*fwCount {
	out := make([]*fwCount, 0, len(order))
	for _, k := range order {
		out = append(out, m[k])
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].n > out[j].n })
	return out
}

func (a *App) firewallEvents(text string) (refused, connected []*fwCount) {
	names := a.portNames()
	rm, cm := map[string]*fwCount{}, map[string]*fwCount{}
	var ro, co []string
	for _, m := range klogRE.FindAllStringSubmatch(text, -1) {
		kind, rule, src, proto, dpt := m[1], m[2], m[3], m[4], m[5]
		target := strings.ToLower(proto)
		if dpt != "" {
			p, _ := strconv.Atoi(dpt)
			if n, ok := names[p]; ok {
				target = n
			} else {
				target = "port " + dpt
			}
		}
		if kind == "om-in" {
			k := src + "\x00" + target
			if cm[k] == nil {
				cm[k] = &fwCount{key: []string{src, target}}
				co = append(co, k)
			}
			cm[k].n++
		} else {
			if rule == "" {
				rule = "not an om port"
			}
			k := rule + "\x00" + src + "\x00" + target
			if rm[k] == nil {
				rm[k] = &fwCount{key: []string{rule, src, target}}
				ro = append(ro, k)
			}
			rm[k].n++
		}
	}
	return countSorted(rm, ro), countSorted(cm, co)
}

type edgeStat struct {
	requests, c4, c5 int
	logins           map[string]bool
}

func edgeEvents(text string) (map[string]*edgeStat, []string) {
	out := map[string]*edgeStat{}
	var order []string
	for _, line := range py.SplitLines(text) {
		if !strings.Contains(line, `"handled request"`) {
			continue
		}
		var e map[string]any
		d := json.NewDecoder(bytes.NewReader([]byte(line[strings.Index(line, "{"):])))
		d.UseNumber()
		if d.Decode(&e) != nil || e == nil {
			continue
		}
		site := "?"
		if r, ok := e["request"].(map[string]any); ok && py.Truthy(r["host"]) {
			site = py.Str(r["host"])
		}
		st := out[site]
		if st == nil {
			st = &edgeStat{logins: map[string]bool{}}
			out[site] = st
			order = append(order, site)
		}
		st.requests++
		code := int(num(e["status"]))
		if code >= 400 && code < 500 {
			st.c4++
		}
		if code >= 500 {
			st.c5++
		}
		if u := e["user_id"]; py.Truthy(u) {
			st.logins[py.Str(u)] = true
		}
	}
	return out, order
}

var sinceRE = regexp.MustCompile(`^\d+[smhd]$`)

func (a *App) cmdFirewallLog(ns Namespace) error {
	since := ns.Str("since")
	if !sinceRE.MatchString(since) {
		since = "24h"
	}
	a.p("\n\033[1mFIREWALL LOG\033[0m  (last %s; real source addresses)", since)
	a.p("%s", strings.Repeat("═", 78))
	switch a.GOOS {
	case "linux":
		r := a.Run([]string{"journalctl", "-k", "--no-pager", "-o", "short-iso", "--since", "-" + since, "--grep", "om-(refused|in)"})
		if (r.Code != 0 && r.Code != 1) || strings.Contains(r.Stderr, "No journal files") || (strings.Contains(strings.ToLower(r.Stderr), "permission") && r.Stdout == "") {
			a.p("  The kernel log is not readable for this account (it needs the wheel, adm or systemd-journal group):")
			a.p("    sudo journalctl -k --since -%s --grep 'om-(refused|in)'", since)
		} else {
			refused, connected := a.firewallEvents(r.Stdout)
			tail := ""
			if len(refused) == 0 {
				tail = "  — none"
			}
			a.p("  \033[31mRefused\033[0m%s", tail)
			for i, c := range refused {
				if i >= 20 {
					break
				}
				a.p("    %s×  %s → %s (%s)", rjust(strconv.Itoa(c.n), 5), ljust(c.key[1], 40), ljust(c.key[2], 34), c.key[0])
			}
			tail = ""
			if len(connected) == 0 {
				tail = "  — none"
			}
			a.p("  \033[32mConnected\033[0m%s", tail)
			for i, c := range connected {
				if i >= 20 {
					break
				}
				a.p("    %s×  %s → %s", rjust(strconv.Itoa(c.n), 5), ljust(c.key[0], 40), c.key[1])
			}
		}
	case "darwin":
		a.p("  pf logs refused packets to pflog0:  sudo tcpdump -n -e -ttt -i pflog0")
	default:
		a.p(`  Windows Firewall logs dropped packets to %%SystemRoot%%\System32\LogFiles\Firewall\pfirewall.log`)
	}
	rt := a.Runtime()
	edge, order := edgeEvents(a.Run([]string{rt, "logs", "--since", since, state.Edge}).Stdout)
	a.p("\n\033[1mEDGE\033[0m  (what happened, never what was asked: no URLs; om.log=off services absent)")
	a.p("%s", strings.Repeat("═", 78))
	if len(edge) == 0 {
		a.p("  no requests logged")
	}
	sites := append([]string(nil), order...)
	sort.SliceStable(sites, func(i, j int) bool { return edge[sites[i]].requests > edge[sites[j]].requests })
	for _, site := range sites {
		st := edge[site]
		logins := ""
		if len(st.logins) > 0 {
			logins = "  logins: " + strings.Join(sortedSet(st.logins), ", ")
		}
		a.p("  %s requests  %s 4xx  %s 5xx   %s%s", rjust(strconv.Itoa(st.requests), 6), rjust(strconv.Itoa(st.c4), 4), rjust(strconv.Itoa(st.c5), 4), site, logins)
	}
	a.p("")
	return nil
}
