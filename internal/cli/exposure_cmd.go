package cli

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Chitakasa/om/internal/egress"
	"github.com/Chitakasa/om/internal/netdetect"
	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/routes"
	"github.com/Chitakasa/om/internal/secrets"
	"github.com/Chitakasa/om/internal/workspace"
)

// otherLoginUsers lists other human accounts (passwd entries with uid 1000..59999 and a login shell).
func (a *App) otherLoginUsers() []string {
	if a.OtherLoginUsers != nil {
		return a.OtherLoginUsers()
	}
	b, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return []string{}
	}
	me := os.Getuid()
	out := []string{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		if err != nil || uid < 1000 || uid == me || uid >= 60000 {
			continue
		}
		if strings.HasSuffix(f[6], "nologin") || strings.HasSuffix(f[6], "false") {
			continue
		}
		out = append(out, f[0])
	}
	sort.Strings(out)
	return out
}

func (a *App) trustedUsers() map[string]bool {
	out := map[string]bool{}
	for _, u := range commaItems(a.Settings()["OM_TRUSTED_USERS"]) {
		out[u] = true
	}
	return out
}

func (a *App) tiers() map[string]any {
	s := a.Settings()
	res := s.Resolve(a.D, a.Det)
	trusted := netdetect.VPNItems(s["OM_VPN"])
	allow := s.VPNAllow()
	others := a.otherLoginUsers()
	tu := a.trustedUsers()
	var tr []string
	for _, o := range others {
		if tu[o] {
			tr = append(tr, o)
		}
	}
	var al, enf, lan any
	if len(allow) > 0 {
		al = strList(allow)
		enf = a.FW.VPNAllowEnforced()
	}
	if res.LANIP != "" {
		lan = res.LANIP
	}
	return map[string]any{
		"this_machine": map[string]any{"you": true, "other_accounts": strList(others), "trusted_accounts": strList(tr)},
		"vpn":          map[string]any{"trusted": strList(trusted), "addresses": strList(res.VPNIPs), "allow_list": al, "allow_list_enforced": enf},
		"lan":          map[string]any{"address": lan},
		"login":        strList(sortedKeys(secrets.ReadAuthUsers(filepath.Join(a.D.Auth, "private.conf")))),
	}
}

func isLoopbackNet(n string) bool {
	if p, err := netip.ParsePrefix(n); err == nil {
		return p.Masked().Addr().IsLoopback()
	}
	if ip, err := netip.ParseAddr(n); err == nil {
		return ip.IsLoopback()
	}
	return false
}

func (a *App) egressSummary(ws, svc string) string {
	rule, ok := a.Egress.LoadRules(ws)[svc]
	switch {
	case !ok:
		return "none (no way out)"
	case rule.Mode == "":
		s := "s"
		if len(rule.Hosts) == 1 {
			s = ""
		}
		return fmt.Sprintf("%d host%s", len(rule.Hosts), s)
	case rule.Mode == egress.Internet:
		return "ANY public host"
	case rule.Mode == egress.Learn:
		return "ANY public host (learning)"
	case rule.Mode == egress.Audit:
		return "ANY public host (audit)"
	}
	return rule.Mode
}

func (a *App) audience(entry map[string]any, t map[string]any) []string {
	lines := []string{"this machine: yes"}
	net, _ := entry["net"].(map[string]any)
	allow := net["allow"]
	deny := anyStrings(net["deny"])
	vpn := t["vpn"].(map[string]any)
	vpnAllow := anyStrings(vpn["allow_list"])
	public := entry["scope"] == "public"
	narrowed := func(devices []string) string {
		if allow != nil {
			devices = nil
			for _, x := range anyStrings(allow) {
				if x == "vpn" {
					if len(vpnAllow) > 0 {
						devices = append(devices, vpnAllow...)
					} else {
						devices = append(devices, "(the VPN allow-list)")
					}
				} else {
					devices = append(devices, x)
				}
			}
			all := true
			for _, d := range devices {
				all = all && isLoopbackNet(d)
			}
			if all {
				return "no one (the service's address rule allows only " + strings.Join(devices, ", ") + ")"
			}
		}
		text := strings.Join(devices, ", ")
		if len(deny) > 0 {
			text += ", except " + strings.Join(deny, ", ")
		}
		return text
	}
	if len(net) > 0 && net["enforced"] != true {
		lines = append(lines, "address rules: NOT in the host firewall yet; the service's own ports stay closed until `om firewall apply`")
	}
	trusted := anyStrings(vpn["trusted"])
	if len(trusted) > 0 {
		if public {
			lines = append(lines, "VPN: "+narrowed([]string{"every device on " + strings.Join(trusted, "/") + " (public port)"}))
		} else {
			devices := vpnAllow
			if len(devices) == 0 {
				devices = []string{"every device on " + strings.Join(trusted, "/")}
			}
			lines = append(lines, "VPN: "+narrowed(devices))
		}
	}
	if public {
		lan := t["lan"].(map[string]any)["address"]
		d := "every device on your network"
		if lan != nil {
			d = fmt.Sprintf("every device on your network (%s)", py.Str(lan))
		}
		lines = append(lines, "LAN: "+narrowed([]string{d}))
	}
	return lines
}

func (a *App) exposureData() map[string]any {
	t := a.tiers()
	services := []any{}
	for _, ws := range sortedKeys(a.Reg.Read()) {
		for _, e := range a.routesData(ws) {
			svc := py.Str(e["service"])
			b, err := os.ReadFile(filepath.Join(a.D.Routes, ws+"-"+svc+".caddy"))
			hasLogin := err == nil && strings.Contains(string(b), "basic_auth")
			proto := "http"
			if p, ok := e["protocol"]; ok {
				proto = py.Str(p)
			}
			services = append(services, map[string]any{"workspace": ws, "service": svc, "scope": e["scope"], "protocol": proto,
				"reachable_by": strList(a.audience(e, t)), "egress": a.egressSummary(ws, svc), "logged": e["logged"], "own_login": hasLogin})
		}
	}
	data := map[string]any{"audiences": t, "services": services}
	if nn := a.noNetwork(); len(nn) > 0 {
		data["no_network"] = nn
	}
	return data
}

// noNetwork lists "workspace/service" for the services of the registered workspaces that run with
// `network_mode: none`: nothing can reach them, so the report names no route for them.
func (a *App) noNetwork() []any {
	out := []any{}
	reg := a.Reg.Read()
	for _, ws := range sortedKeys(reg) {
		root, _ := reg[ws]["path"].(string)
		if st, err := os.Stat(root); root == "" || err != nil || !st.IsDir() {
			continue
		}
		for _, t := range workspace.DiscoverComposeDirs(root, "") {
			cf, _ := workspace.FindComposeFile(t.Dir)
			b, err := os.ReadFile(cf)
			if err != nil {
				continue
			}
			for _, svc := range routes.NoNetworkServices(string(b)) {
				out = append(out, ws+"/"+svc)
			}
		}
	}
	return out
}

func (a *App) printExposure(data map[string]any) {
	t := data["audiences"].(map[string]any)
	a.p("\n\033[1mEXPOSURE\033[0m  (who can reach what, from the settings and the registries)")
	a.p("%s", strings.Repeat("═", 78))
	tm := t["this_machine"].(map[string]any)
	others, trusted := anyStrings(tm["other_accounts"]), setOf(anyStrings(tm["trusted_accounts"]))
	var untrusted []string
	for _, u := range others {
		if !trusted[u] {
			untrusted = append(untrusted, u)
		}
	}
	line := "  this machine   you"
	if len(trusted) > 0 {
		line += ", " + strings.Join(sortedSet(trusted), ", ") + " (yours)"
	}
	if len(untrusted) > 0 {
		line += fmt.Sprintf("; \033[31mother accounts: %s\033[0m", strings.Join(untrusted, ", "))
	}
	a.p("%s", line)
	vpn := t["vpn"].(map[string]any)
	if vt := anyStrings(vpn["trusted"]); len(vt) > 0 {
		al := anyStrings(vpn["allow_list"])
		who := "\033[33mevery device on it\033[0m"
		if len(al) > 0 {
			who = strings.Join(al, ", ")
		}
		enforced := ""
		if len(al) > 0 {
			if vpn["allow_list_enforced"] == true {
				enforced = " (enforced by the firewall)"
			} else {
				enforced = " \033[31m(not in the firewall: closed until om firewall apply)\033[0m"
			}
		}
		a.p("  VPN %s   private tier: %s%s", strings.Join(vt, "/"), who, enforced)
	} else {
		a.p("  VPN            none trusted: nothing arrives from a VPN")
	}
	lan := "not bound"
	if v := t["lan"].(map[string]any)["address"]; v != nil {
		lan = py.Str(v)
	}
	a.p("  LAN            %s: public tier only", lan)
	if lg := anyStrings(t["login"]); len(lg) > 0 {
		a.p("  private login  on (%s)", strings.Join(lg, ", "))
	} else {
		a.p("  private login  \033[33moff\033[0m: anyone who reaches the private tier sees every private service")
	}
	svcs := data["services"].([]any)
	noNet := func() {
		if nn := anyStrings(data["no_network"]); len(nn) > 0 {
			a.p("  No network (nothing can reach them or be reached, so they have no route above):")
			for _, n := range nn {
				a.p("    %s", n)
			}
			a.p("")
		}
	}
	if len(svcs) == 0 {
		a.p("\n  No routed services yet.\n")
		noNet()
		return
	}
	for _, x := range svcs {
		s := x.(map[string]any)
		tag := "private"
		if s["scope"] == "public" {
			tag = "\033[36mpublic \033[0m"
		}
		var extra []string
		if s["own_login"] == true {
			extra = append(extra, "own login")
		}
		if s["logged"] == false {
			extra = append(extra, "not logged")
		}
		tail := ""
		if len(extra) > 0 {
			tail = "  [" + strings.Join(extra, ", ") + "]"
		}
		a.p("\n  \033[1m%s/%s\033[0m  %s %s%s", py.Str(s["workspace"]), py.Str(s["service"]), tag, py.Str(s["protocol"]), tail)
		for _, l := range anyStrings(s["reachable_by"]) {
			a.p("    %s", l)
		}
		a.p("    outbound: %s", py.Str(s["egress"]))
	}
	a.p("")
	noNet()
}

func (a *App) cmdExposure(ns Namespace) error {
	data := a.exposureData()
	if ns.Bool("json") {
		a.EmitJSON(data)
	} else {
		a.printExposure(data)
	}
	return nil
}
