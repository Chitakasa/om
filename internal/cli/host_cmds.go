package cli

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Chitakasa/om/internal/netdetect"
	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/settings"
)

// vpnDevice returns (network, how to show it) for an address, a range, or a VPN device name this machine resolves.
func (a *App) vpnDevice(name string) (string, string, error) {
	if !strings.Contains(name, "%") {
		if n, ok := settings.ParseNetwork(name); ok {
			return n, n, nil
		}
	}
	ip := ""
	if addrs, err := net.LookupIP(name); err == nil {
		for _, x := range addrs {
			if v4 := x.To4(); v4 != nil {
				ip = v4.String()
				break
			}
		}
	}
	if ip == "" {
		return "", "", Die("'%s' is not an address, a range, or a name this machine can resolve.", name)
	}
	return ip + "/32", fmt.Sprintf("%s (%s)", name, ip), nil
}

func (a *App) vpnPublicURL() string {
	h := "<vpn address>"
	if hosts := a.vpnHosts(); len(hosts) > 0 {
		h = hosts[len(hosts)-1]
	}
	return "http://" + h + ":8080/"
}

func (a *App) vpnOthers() string {
	if a.FW.VPNFallbackApplied() {
		return fmt.Sprintf("the others get the public tier, at the same address (or %s)", a.vpnPublicURL())
	}
	return fmt.Sprintf("the others get the public tier only, at %s (the private address gives them no answer)", a.vpnPublicURL())
}

func (a *App) cmdVPNAllow(ns Namespace) error {
	action := ns.Str("action")
	name := py.Strip(ns.Str("name"))
	if name == "" {
		return Die("Usage: om vpn %s <device address, range or VPN name>", action)
	}
	netw, shown, err := a.vpnDevice(name)
	if err != nil {
		return err
	}
	allowed := a.Settings().VPNAllow()
	idx := -1
	for i, x := range allowed {
		if x == netw {
			idx = i
		}
	}
	if action == "allow" {
		if idx >= 0 {
			a.p("  %s is already allowed.", shown)
			return nil
		}
		allowed = append(allowed, netw)
	} else {
		if idx < 0 {
			l := strings.Join(allowed, ", ")
			if l == "" {
				l = "empty"
			}
			return Die("%s is not on the VPN allow-list (%s).", shown, l)
		}
		allowed = append(allowed[:idx], allowed[idx+1:]...)
	}
	if err := settings.Set(a.D, "OM_VPN_ALLOW", strings.Join(allowed, ",")); err != nil {
		return Die("%s", err)
	}
	list := strings.Join(allowed, ",")
	if list == "" {
		list = "(none)"
	}
	a.p("\033[32m✓ OM_VPN_ALLOW=%s\033[0m", list)
	rt := a.Runtime()
	applied := false
	if !ns.Bool("no_apply") && a.FW.Installed() {
		a.p("  Updating the host firewall now, so the change is in effect at once (sudo):")
		applied = a.applyFirewall(rt) && a.FW.VPNAllowEnforced()
	}
	if !applied {
		// Fail closed: a stale firewall must not keep a removed device in.
		for _, p := range a.Reg.NetPolicies() {
			if containsStr(anyStrings(p["allow"]), "vpn") {
				a.resyncAllRoutes(rt)
				break
			}
		}
		if a.Core.Running(rt) && len(a.Core.RuntimeDrift()) > 0 {
			a.Core.Up(rt, true, true)
		}
	}
	switch {
	case len(allowed) == 0:
		tail := ""
		if len(a.FW.StaleNetRules()) > 0 {
			tail = " Run `om firewall apply` to drop the old firewall rule."
		}
		a.p("  Every device on a trusted VPN reaches the private tier again.%s", tail)
	case a.FW.VPNAllowEnforced():
		a.p("  Only these VPN devices reach the private tier; %s.", a.vpnOthers())
	default:
		a.p("  \033[33mThe VPN's private tier stays closed until the firewall carries the list: om firewall apply\033[0m")
	}
	return nil
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func isTrusted(trusted []string, iface, address string) bool {
	return containsStr(trusted, iface) || containsStr(trusted, address)
}

type vpnDev struct {
	Address, Name      string
	Allowed            bool
	Connected, Refused int
	Last               string
}

var devRE = regexp.MustCompile(`^(\S+) .*?kernel: (om-in|om-refused)[^:]*: .*?\bSRC=(\S+) DST=(\S+)`)

func vpnDeviceEvents(text string, local map[string]bool) map[string]*vpnDev {
	out := map[string]*vpnDev{}
	for _, line := range py.SplitLines(text) {
		m := devRE.FindStringSubmatch(line)
		if m == nil || !local[m[4]] {
			continue
		}
		d := out[m[3]]
		if d == nil {
			d = &vpnDev{Address: m[3]}
			out[m[3]] = d
		}
		if m[2] == "om-in" {
			d.Connected++
		} else {
			d.Refused++
		}
		if m[1] > d.Last {
			d.Last = m[1]
		}
	}
	return out
}

func (a *App) vpnDevices() []vpnDev {
	s := a.Settings()
	var allowed []netip.Prefix
	for _, n := range s.VPNAllow() {
		if p, err := netip.ParsePrefix(n); err == nil {
			allowed = append(allowed, p)
		}
	}
	res := s.Resolve(a.D, a.Det)
	local := setOf(res.VPNIPs)
	events := map[string]*vpnDev{}
	if a.GOOS == "linux" && len(local) > 0 {
		r := a.Run([]string{"journalctl", "-k", "--no-pager", "-o", "short-iso", "--since", "-7d", "--grep", "om-(refused|in)"})
		events = vpnDeviceEvents(r.Stdout, local)
	}
	set := map[string]bool{}
	for k := range events {
		set[k] = true
	}
	for _, p := range allowed {
		if p.IsSingleIP() {
			set[p.Addr().String()] = true
		}
	}
	for _, p := range s.VPNPeers(a.Det, res) {
		set[p] = true
	}
	addrs := sortedSet(set)
	sort.SliceStable(addrs, func(i, j int) bool {
		x, _ := netip.ParseAddr(addrs[i])
		y, _ := netip.ParseAddr(addrs[j])
		return x.Less(y)
	})
	servers := a.Det.Nameservers()
	names := make([]string, len(addrs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for i, ip := range addrs {
		wg.Add(1)
		go func(i int, ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			for _, srv := range servers {
				if n := netdetect.PTRQuery(ip, srv, 2*time.Second); n != "" {
					names[i] = strings.SplitN(n, ".", 2)[0]
					return
				}
			}
		}(i, ip)
	}
	wg.Wait()
	var out []vpnDev
	for i, ip := range addrs {
		d := vpnDev{Address: ip, Name: names[i]}
		if e := events[ip]; e != nil {
			d.Connected, d.Refused, d.Last = e.Connected, e.Refused, e.Last
		}
		addr, _ := netip.ParseAddr(ip)
		d.Allowed = len(allowed) == 0
		for _, p := range allowed {
			d.Allowed = d.Allowed || p.Contains(addr)
		}
		out = append(out, d)
	}
	return out
}

func devJSON(devs []vpnDev) []any {
	out := []any{}
	for _, d := range devs {
		out = append(out, map[string]any{"address": d.Address, "name": d.Name, "allowed": d.Allowed, "connected": d.Connected, "refused": d.Refused, "last": d.Last})
	}
	return out
}

func strList(l []string) []any {
	out := []any{}
	for _, x := range l {
		out = append(out, x)
	}
	return out
}

func (a *App) printVPNDevices(devs []vpnDev) {
	if len(a.Settings().VPNAllow()) > 0 {
		st := "\033[32menforced by the firewall\033[0m"
		if !a.FW.VPNAllowEnforced() {
			st = "\033[31mnot in the firewall: the VPN's private tier is closed until `om firewall apply`\033[0m"
		}
		a.p("\n  Private tier over the VPN: only the allowed devices (%s);\n  %s", st, a.vpnOthers())
	} else {
		a.p("\n  Private tier over the VPN: every device on it (`om vpn allow <device>` to keep it to yours)")
	}
	if len(devs) == 0 {
		a.p("  No other device found on the trusted VPNs.")
		return
	}
	a.p("")
	for _, d := range devs {
		st := "\033[32mallowed    \033[0m"
		if !d.Allowed {
			st = "\033[31mnot allowed\033[0m"
		}
		seen := "no contact in 7 days"
		if d.Last != "" {
			l := []rune(d.Last)
			if len(l) > 16 {
				l = l[:16]
			}
			seen = "last seen " + strings.ReplaceAll(string(l), "T", " ")
		}
		var counts []string
		if d.Connected > 0 {
			counts = append(counts, fmt.Sprintf("%d connected", d.Connected))
		}
		if d.Refused > 0 {
			counts = append(counts, fmt.Sprintf("%d refused", d.Refused))
		}
		name := d.Name
		if name == "" {
			name = "?"
		}
		a.p("  %s %s %s  %s %s", ljust(name, 20), ljust(d.Address, 16), st, ljust(seen, 27), strings.Join(counts, ", "))
	}
	a.p("\n  Change it: om vpn allow|disallow <device> (updates the firewall at once).")
}

func (a *App) cmdVPNDevices(ns Namespace) error {
	devs := a.vpnDevices()
	if ns.Bool("json") {
		var al any
		if v := a.Settings().VPNAllow(); len(v) > 0 {
			al = strList(v)
		}
		a.EmitJSON(map[string]any{"allow_list": al, "devices": devJSON(devs)})
		return nil
	}
	a.p("\n\033[1mVPN DEVICES\033[0m")
	a.printVPNDevices(devs)
	a.p("")
	return nil
}

func (a *App) cmdVPN(ns Namespace) error {
	switch ns.Str("action") {
	case "allow", "disallow":
		return a.cmdVPNAllow(ns)
	case "devices":
		return a.cmdVPNDevices(ns)
	}
	s := a.Settings()
	spec := s["OM_VPN"]
	trusted := netdetect.VPNItems(spec)
	cands := a.Det.VPNCandidates()
	if ns.Str("action") != "list" {
		return a.changeVPNTrust(ns, trusted, cands)
	}
	if !ns.Bool("json") {
		a.printVPNList(spec, trusted, cands)
		return nil
	}
	ifs := []any{}
	for _, c := range cands {
		ifs = append(ifs, map[string]any{"name": c.Name, "address": c.IP, "trusted": isTrusted(trusted, c.Name, c.IP)})
	}
	var al any
	if v := s.VPNAllow(); len(v) > 0 {
		al = strList(v)
	}
	devs := []any{}
	if len(trusted) > 0 {
		devs = devJSON(a.vpnDevices())
	}
	a.EmitJSON(map[string]any{"trusted": strList(trusted), "names": strList(a.vpnHosts()), "interfaces": ifs, "allowed_devices": al,
		"allow_enforced": a.FW.VPNAllowEnforced(), "devices": devs})
	return nil
}

func (a *App) printVPNList(spec string, trusted []string, cands []netdetect.Adapter) {
	shown := spec
	if shown == "" {
		shown = "(none)"
	}
	a.p("\n\033[1mVPN\033[0m  (OM_VPN=%s)", shown)
	if len(cands) == 0 && len(trusted) == 0 {
		a.p("  No VPN on this machine. Install one whose members are your own devices, then `om vpn`.\n")
		return
	}
	present := map[string]bool{}
	for _, c := range cands {
		mark := "\033[33mnot trusted\033[0m"
		if isTrusted(trusted, c.Name, c.IP) {
			mark = "\033[32mtrusted\033[0m"
		}
		ip := c.IP
		if ip == "" {
			ip = "-"
		}
		a.p("  %s %s %s", ljust(c.Name, 14), ljust(ip, 16), mark)
		present[c.Name], present[c.IP] = true, true
	}
	for _, t := range trusted {
		if !present[t] {
			a.p("  %s %s \033[32mtrusted\033[0m (not present now)", ljust(t, 14), ljust("-", 16))
		}
	}
	if len(trusted) > 0 {
		a.printVPNDevices(a.vpnDevices())
	}
	var untrusted []string
	for _, c := range cands {
		if !isTrusted(trusted, c.Name, c.IP) {
			untrusted = append(untrusted, c.Name)
		}
	}
	if len(untrusted) > 0 {
		a.p("\n  Trust a VPN only if every member is your own device (not a commercial or company VPN,")
		a.p("  not a public network):")
		for _, i := range untrusted {
			a.p("    om vpn trust %s", i)
		}
	}
	a.p("")
}

var ipv4RE = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)

func (a *App) changeVPNTrust(ns Namespace, trusted []string, cands []netdetect.Adapter) error {
	action := ns.Str("action")
	name := py.Strip(ns.Str("name"))
	if name == "" {
		return Die("Usage: om vpn %s <interface or address>", action)
	}
	found := false
	for _, c := range cands {
		if strings.EqualFold(c.Name, name) {
			name, found = c.Name, true
			break
		}
	}
	if !found {
		for _, t := range trusted {
			if strings.EqualFold(t, name) {
				name = t
				break
			}
		}
	}
	if action == "trust" {
		isIface := false
		for _, c := range cands {
			isIface = isIface || c.Name == name
		}
		if !isIface && !ipv4RE.MatchString(name) {
			return Die("No VPN interface '%s'. `om vpn` lists them.", name)
		}
		if containsStr(trusted, name) {
			a.p("  %s is already trusted.", name)
			return nil
		}
		trusted = append(trusted, name)
	} else {
		idx := -1
		for i, t := range trusted {
			if t == name {
				idx = i
			}
		}
		if idx < 0 {
			return Die("%s is not trusted. `om vpn` shows the trusted ones.", name)
		}
		trusted = append(trusted[:idx], trusted[idx+1:]...)
	}
	n := strings.Join(trusted, ",")
	if err := settings.Set(a.D, "OM_VPN", n); err != nil {
		return Die("%s", err)
	}
	shown := n
	if shown == "" {
		shown = "(none)"
	}
	a.p("\033[32m✓ OM_VPN=%s\033[0m", shown)
	rt := a.Runtime()
	if a.Core.Running(rt) {
		if ok, _ := a.Core.Up(rt, true, true); !ok {
			return Die("The core did not come back; `om doctor` shows why.")
		}
	}
	a.p("  Run `om firewall apply` so the firewall follows the new VPN addresses.")
	return nil
}

// applyFirewall writes and loads the host firewall, then lets the core and the routes follow it.
func (a *App) applyFirewall(rt string) bool {
	ok, _ := a.FW.Apply()
	if ok && a.Core.Running(rt) && len(a.Core.RuntimeDrift()) > 0 {
		a.p("  Restarting the core: the VPN's private tier follows the firewall's allow-list...")
		a.Core.Up(rt, true, true)
	}
	if ok && len(a.Reg.NetPolicies()) > 0 {
		a.resyncAllRoutes(rt)
		if a.GOOS == "windows" {
			a.p("  After running the script above, run `om reload` in each workspace whose services use om.net.")
		}
	}
	return ok
}

func (a *App) resyncAllRoutes(rt string) {
	reg := a.Reg.Read()
	for _, id := range sortedKeys(reg) {
		p, _ := reg[id]["path"].(string)
		if st, err := os.Stat(filepath.Join(p, ".om", "config.json")); err == nil && !st.IsDir() {
			a.Syncer.SyncCaddyRoutes(p, rt, true, nil)
		}
	}
}

func (a *App) cmdFirewall(ns Namespace) error {
	switch ns.Str("action") {
	case "log":
		return a.cmdFirewallLog(ns)
	case "show":
		path, err := a.FW.Generate()
		if err != nil {
			return Die("%s", err)
		}
		text, _ := py.ReadText(path)
		a.p("%s", text)
		a.p("# written to %s", path)
	case "apply":
		a.p("\033[1m🛡  Applying host firewall (inbound default-drop; only om ingress open)...\033[0m")
		if a.applyFirewall(a.Runtime()) {
			return Exit(0)
		}
		return Exit(1)
	case "remove":
		a.FW.Remove()
	default:
		a.p("  Host firewall: %s", a.FW.Status())
	}
	return nil
}

func (a *App) cmdBoot(ns Namespace) error {
	rt := a.Runtime()
	switch ns.Str("action") {
	case "enable":
		if ok, _ := a.Sched.BootEnable(rt); ok {
			a.p("\033[32m✓ Containers restart at boot; self-heal re-applies the network every 2 minutes.\033[0m")
		} else {
			a.p("\033[31m✗ Could not fully enable start at boot (see messages above).\033[0m")
		}
	case "disable":
		a.Sched.BootDisable()
		a.p("\033[32m✓ Self-heal disabled.\033[0m (Engine restart policy unchanged.)")
	default:
		a.p("  Start at boot: %s", a.Sched.BootStatus(rt))
	}
	return nil
}
