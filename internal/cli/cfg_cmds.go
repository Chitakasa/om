package cli

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Chitakasa/om/internal/notify"
	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/routes"
	"github.com/Chitakasa/om/internal/settings"
	"github.com/Chitakasa/om/internal/state"
)

var (
	portRE = regexp.MustCompile(`^\d{1,5}(?:-\d{1,5})?$`)
	userRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}\$?$`)
)

func parsePort(v string) (int, error) {
	n, err := strconv.Atoi(v)
	if err != nil || strings.TrimLeft(v, "0123456789") != "" || n < 1 || n > 65535 {
		return 0, fmt.Errorf("`%s` is not a port (1-65535)", v)
	}
	return n, nil
}

func oneOf(words ...string) func(string) error {
	return func(v string) error {
		for _, w := range words {
			if strings.ToLower(v) == w {
				return nil
			}
		}
		return fmt.Errorf("must be one of: %s", strings.Join(words, ", "))
	}
}

func commaItems(v string) []string {
	var out []string
	for _, i := range strings.Split(v, ",") {
		if i = py.Strip(i); i != "" {
			out = append(out, i)
		}
	}
	return out
}

func portList(v string) error {
	for _, item := range commaItems(v) {
		if !portRE.MatchString(item) {
			return fmt.Errorf("`%s` is not a port or a range like 1714-1764", item)
		}
		lo, hi, _ := strings.Cut(item, "-")
		l, err := parsePort(lo)
		if err != nil {
			return err
		}
		h := l
		if hi != "" {
			if h, err = parsePort(hi); err != nil {
				return err
			}
		}
		if l > h {
			return fmt.Errorf("`%s`: the range runs backwards", item)
		}
	}
	return nil
}

func lanIP(v string) error {
	if l := strings.ToLower(v); l == "auto" || l == "off" {
		return nil
	}
	if ip, err := netip.ParseAddr(v); err == nil && ip.Is4() && !strings.Contains(v, "%") {
		return nil
	}
	return fmt.Errorf("must be auto, off or an IPv4 address")
}

func notifyCheck(v string) error {
	if l := strings.ToLower(v); l == "auto" || l == "off" {
		return nil
	}
	words := []string{}
	for _, w := range strings.Split(strings.ReplaceAll(strings.ToLower(v), " ", ""), ",") {
		if w != "" {
			words = append(words, w)
		}
	}
	ok := len(words) > 0
	for _, w := range words {
		ok = ok && (w == "desktop" || w == "webhook")
	}
	if !ok {
		return fmt.Errorf("must be auto, off or a comma list of: desktop, webhook")
	}
	return nil
}

type schemaEntry struct {
	check func(string) error
	then  string
}

// portOrAuto checks a front-door port: a port number, or `auto` (om picks a free one at `om core start`).
func portOrAuto(v string) error {
	if strings.EqualFold(strings.TrimSpace(v), "auto") {
		return nil
	}
	_, e := parsePort(v)
	return e
}

// portBase checks one block's first port: the block of state.PortSlots ports must fit within 1024-65535 (that the three
// blocks do not overlap or hold a front-door port is settings.PortBases' and `om doctor`'s to say, it needs all three).
func portBase(v string) error {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || !state.IsNumber(strings.TrimSpace(v)) {
		return fmt.Errorf("must be a port number")
	}
	if n < 1024 || n+state.PortSlots-1 > 65535 {
		return fmt.Errorf("the block of %d ports must lie within 1024-65535", state.PortSlots)
	}
	return nil
}

var configSchema = map[string]schemaEntry{
	"OM_LAN_IP": {lanIP, "om core restart"},
	"OM_NOTIFY": {notifyCheck, ""},
	"OM_NOTIFY_URL": {func(v string) error {
		if v != "" && !notify.WebhookURLOK(v) {
			return fmt.Errorf("must be https:// (or http:// to this machine or a private address)")
		}
		return nil
	}, ""},
	"OM_TRUSTED_USERS": {func(v string) error {
		for _, u := range commaItems(v) {
			if !userRE.MatchString(u) {
				return fmt.Errorf("`%s` is not an account name", u)
			}
		}
		return nil
	}, ""},
	"OM_WALLPAPERS_DIR": {func(v string) error {
		if py.Strip(v) == "" {
			return fmt.Errorf("must be auto or a folder path")
		}
		return nil
	}, "om core restart"},
	"OM_HTTP_PORT":          {portOrAuto, "om core restart, then om firewall apply"},
	"OM_HTTPS_PORT":         {portOrAuto, "om core restart, then om firewall apply"},
	"OM_PRIVATE_PORT_BASE":  {portBase, "om core restart, then om firewall apply"},
	"OM_PUBLIC_PORT_BASE":   {portBase, "om core restart, then om firewall apply"},
	"OM_STREAM_PORT_BASE":   {portBase, "om core restart, then om firewall apply"},
	"OM_FIREWALL_EXTRA_TCP": {portList, "om firewall apply"},
	"OM_FIREWALL_EXTRA_UDP": {portList, "om firewall apply"},
	"OM_POLICY":             {oneOf("enforce", "warn"), ""},
	"OM_SIGNED":             {oneOf("auto", "warn", "enforce"), ""},
}

var ownCommand = map[string]string{"OM_VPN": "om vpn trust|untrust <interface>", "OM_VPN_ALLOW": "om vpn allow|disallow <device>"}

func configKey(name string) (string, error) {
	key := strings.ToUpper(py.Strip(name))
	if c, ok := ownCommand[key]; ok {
		return "", Die("%s has its own command, which also updates the firewall: %s", key, c)
	}
	if _, ok := configSchema[key]; !ok {
		msg := fmt.Sprintf("Unknown setting %s.", py.Repr(name))
		if near := closeMatch(key, sortedKeys(configSchema)); near != "" {
			msg += " Did you mean " + near + "?"
		} else {
			msg += " `om config show` lists them."
		}
		return "", Die("%s", msg)
	}
	return key, nil
}

func checkValue(key, value string) string {
	for _, c := range value {
		if c < 32 || c == 127 {
			return "must be one line, without control characters"
		}
	}
	if err := configSchema[key].check(py.Strip(value)); err != nil {
		return err.Error()
	}
	return ""
}

func (a *App) currentSettings(reveal bool) ([]string, map[string]string) {
	s := a.Settings()
	out := map[string]string{}
	var keys []string
	for k, v := range s {
		_, own := ownCommand[k]
		if _, ok := configSchema[k]; !ok && !own {
			continue
		}
		if k == "OM_NOTIFY_URL" && v != "" && !reveal {
			v = "***"
		}
		out[k] = v
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, out
}

func (a *App) cmdConfig(ns Namespace) error {
	action, arg := ns.Str("action"), ns.Str("arg")
	switch action {
	case "show":
		keys, vals := a.currentSettings(ns.Bool("reveal"))
		if ns.Bool("json") {
			m := map[string]any{}
			for _, k := range keys {
				m[k] = vals[k]
			}
			a.EmitJSON(m)
			return nil
		}
		a.p("\n\033[1mSETTINGS\033[0m  (%s)\n", a.D.UserEnv)
		for _, k := range keys {
			v := vals[k]
			if v == "" {
				v = "(empty)"
			}
			a.p("  %s %s", ljust(k, 24), v)
		}
		a.p("\n  Change one: om config set KEY=value   (OM_VPN / OM_VPN_ALLOW: om vpn …)\n")
	case "get":
		if arg == "" {
			return Die("Usage: om config get <KEY>")
		}
		key := strings.ToUpper(py.Strip(arg))
		_, own := ownCommand[key]
		if _, ok := configSchema[key]; !ok && !own {
			_, err := configKey(arg)
			return err
		}
		_, vals := a.currentSettings(ns.Bool("reveal"))
		a.p("%s", vals[key])
	case "set":
		k, v, found := strings.Cut(arg, "=")
		if !found {
			return Die("Usage: om config set KEY=value")
		}
		key, err := configKey(k)
		if err != nil {
			return err
		}
		v = py.Strip(v)
		if why := checkValue(key, v); why != "" {
			return Die("%s=%s: %s", key, v, why)
		}
		if err := settings.Set(a.D, key, v); err != nil {
			return Die("%s", err)
		}
		shown := v
		if key == "OM_NOTIFY_URL" && v != "" {
			shown = "***"
		}
		a.p("\033[32m✓ %s=%s\033[0m", key, shown)
		if t := configSchema[key].then; t != "" {
			a.p("  Then run: %s", t)
		}
	case "unset":
		if arg == "" {
			return Die("Usage: om config unset <KEY>")
		}
		key, err := configKey(arg)
		if err != nil {
			return err
		}
		if err := settings.Set(a.D, key, ""); err != nil {
			return Die("%s", err)
		}
		a.p("\033[32m✓ %s back to its default\033[0m", key)
		if t := configSchema[key].then; t != "" {
			a.p("  Then run: %s", t)
		}
	default:
		return Die("Unknown action %s.", py.Repr(action))
	}
	return nil
}

var docSuffixRE = regexp.MustCompile(`_(guide|architecture)$`)

type docEntry struct{ name, path string }

func (a *App) docFiles() []docEntry {
	var files []string
	if m, _ := filepath.Glob(filepath.Join(a.D.Home, "docs", "*.md")); m != nil {
		sort.Strings(m)
		files = m
	}
	files = append(files, filepath.Join(a.D.Home, "README.md"), filepath.Join(a.D.Home, "CHANGELOG.md"))
	var out []docEntry
	idx := map[string]int{}
	for _, f := range files {
		if st, err := os.Stat(f); err != nil || st.IsDir() {
			continue
		}
		stem := strings.TrimSuffix(filepath.Base(f), filepath.Ext(f))
		name := strings.ReplaceAll(docSuffixRE.ReplaceAllString(strings.ToLower(stem), ""), "_", "-")
		if i, ok := idx[name]; ok {
			out[i].path = f
			continue
		}
		idx[name] = len(out)
		out = append(out, docEntry{name, f})
	}
	return out
}

func (a *App) cmdDocs(ns Namespace) error {
	docs := a.docFiles()
	name := ns.Str("name")
	if name == "" {
		a.p("\n\033[1mom docs\033[0m  (om docs <name>)")
		for _, d := range docs {
			title := ""
			if b, err := os.ReadFile(d.path); err == nil {
				for _, ln := range py.SplitLines(string(b)) {
					if strings.HasPrefix(ln, "# ") {
						title = py.Strip(strings.TrimLeft(ln, "# "))
						break
					}
				}
			}
			a.p("  \033[36m%s\033[0m %s", ljust(d.name, 12), title)
		}
		a.p("")
		return nil
	}
	low := strings.ToLower(name)
	var matches []docEntry
	for _, d := range docs {
		if d.name == low {
			matches = append(matches, d)
		}
	}
	if len(matches) == 0 {
		for _, d := range docs {
			if strings.HasPrefix(d.name, low) {
				matches = append(matches, d)
			}
		}
	}
	if len(matches) != 1 {
		var names []string
		for _, d := range docs {
			names = append(names, d.name)
		}
		return Die("No single doc matches '%s'. Available: %s", name, strings.Join(names, ", "))
	}
	f := matches[0].path
	if ns.Bool("path") {
		a.p("%s", f)
		return nil
	}
	b, err := os.ReadFile(f)
	if err != nil {
		return Die("%s", err)
	}
	pager := a.Getenv("PAGER")
	if pager == "" {
		for _, p := range []string{"less", "more"} {
			if _, err := a.LookPath(p); err == nil {
				pager = p
				break
			}
		}
	}
	if !isTerminal(os.Stdout) || pager == "" {
		a.print(string(b))
		return nil
	}
	fields := strings.Fields(pager)
	cmd := exec.Command(fields[0], fields[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = strings.NewReader(string(b)), os.Stdout, os.Stderr
	cmd.Env = os.Environ()
	if a.Getenv("LESS") == "" {
		cmd.Env = append(cmd.Env, "LESS=-FRX")
	}
	if err := cmd.Run(); err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			a.print(string(b))
		}
	}
	return nil
}

func (a *App) cmdCompletion(shell string) error {
	var cmds []string
	for _, c := range a.Parser.Commands {
		for _, name := range append([]string{c.Name}, c.Aliases...) { // `rm` is listed, the hidden `script` is not
			if name != "script" {
				cmds = append(cmds, name)
			}
		}
	}
	sort.Strings(cmds)
	words := strings.Join(cmds, " ")
	switch shell {
	case "bash":
		a.p(`complete -W "%s" om`, words)
	case "zsh":
		a.p("#compdef om\n_arguments '1:command:(%s)'", words)
	default:
		a.p("complete -c om -f -n '__fish_use_subcommand' -a '%s'", words)
	}
	return nil
}

// routeEntry is one row of `om routes`.
type routeEntry struct {
	Service, Scope, Protocol, Upstream string
	CustomCaddy                        bool
	URLs                               map[string]any
	Logged                             bool
	Net                                map[string]any
}

func (a *App) routesData(wsID string) []map[string]any {
	env, _ := state.ParseEnvFile(a.D.RuntimeEnv)
	lan := env["LAN_IP"]
	if strings.HasSuffix(lan, ".invalid") {
		lan = ""
	}
	vpn := a.vpnHosts()
	if len(vpn) > 1 {
		vpn = vpn[len(vpn)-1:]
	}
	slots := a.Reg.ServiceSlots()
	pols := a.Reg.NetPolicies()
	var out []map[string]any
	files, _ := filepath.Glob(filepath.Join(a.D.Routes, wsID+"-*.caddy"))
	sort.Strings(files)
	upRE := regexp.MustCompile(`to_workspace\s+(\S+)`)
	for _, f := range files {
		svc := strings.TrimSuffix(filepath.Base(f), ".caddy")[len(wsID)+1:]
		b, _ := os.ReadFile(f)
		text := py.UniversalNewlines(string(b))
		var upstream any
		if m := upRE.FindStringSubmatch(text); m != nil {
			upstream = m[1]
		}
		_, perr := os.Stat(filepath.Join(a.D.Routes, wsID+"-"+svc+".public_alias"))
		public := perr == nil
		urls := map[string]any{"this_machine": a.BaseURL(wsID+"."+svc+".localhost") + "/"}
		if slot, ok := slots[wsID+"/"+svc]; ok {
			var v, g []any
			for _, h := range vpn {
				v = append(v, fmt.Sprintf("http://%s:%d/", h, state.PrivatePortBase+slot))
				g = append(g, fmt.Sprintf("http://%s:%d/", h, state.PublicPortBase+slot))
			}
			urls["vpn"] = orEmpty(v)
			if public {
				l := []any{}
				if lan != "" {
					l = append(l, fmt.Sprintf("http://%s:%d/", lan, state.PublicPortBase+slot))
				}
				urls["lan"] = l
				urls["vpn_guests"] = orEmpty(g)
			}
		}
		scope := "private"
		if public {
			scope = "public"
		}
		out = append(out, map[string]any{"service": svc, "scope": scope, "upstream": upstream, "custom_caddy": strings.Contains(text, "# custom:"),
			"urls": urls, "logged": !strings.Contains(text, "log_skip"), "net": a.netView(wsID+"/"+svc, pols)})
	}
	sp := a.Reg.StreamPorts()
	for _, key := range sortedKeys(sp) {
		if !strings.HasPrefix(key, wsID+"/") {
			continue
		}
		st := sp[key]
		svc := key[len(wsID)+1:]
		scope := st.Scope
		if scope == "" {
			scope = "private"
		}
		urls := map[string]any{"this_machine": fmt.Sprintf("tcp://127.0.0.1:%d", st.HostPort)}
		var v []any
		for _, h := range vpn {
			v = append(v, fmt.Sprintf("tcp://%s:%d", h, st.HostPort))
		}
		if len(vpn) > 0 {
			urls["vpn"] = v
		}
		if scope == "public" {
			if lan != "" {
				urls["lan"] = []any{fmt.Sprintf("tcp://%s:%d", lan, st.HostPort)}
			}
			if len(vpn) > 0 {
				urls["vpn_guests"] = v
			}
		}
		out = append(out, map[string]any{"service": svc, "scope": scope, "protocol": "tcp", "upstream": fmt.Sprintf("%s_%s:%d", wsID, svc, st.ContainerPort),
			"custom_caddy": false, "urls": urls, "logged": st.Log != "off", "net": a.netView(key, pols)})
	}
	return out
}

func orEmpty(l []any) []any {
	if l == nil {
		return []any{}
	}
	return l
}

func (a *App) netView(key string, pols map[string]map[string]any) any {
	net, ok := pols[key]
	if !ok || len(net) == 0 {
		return nil
	}
	deny := net["deny"]
	if deny == nil {
		deny = []any{}
	}
	return map[string]any{"allow": net["allow"], "deny": deny, "enforced": a.FW.NetPolicyEnforced(key, net)}
}

func anyStrings(v any) []string {
	var out []string
	switch l := v.(type) {
	case []any:
		for _, x := range l {
			out = append(out, py.Str(x))
		}
	case []string:
		out = l
	}
	return out
}

func (a *App) cmdRoutes(root string, ns Namespace) error {
	wsID, err := a.wsID(root)
	if err != nil {
		return err
	}
	data := a.routesData(wsID)
	if ns.Bool("json") {
		a.EmitJSON(map[string]any{"workspace": wsID, "routes": data})
		return nil
	}
	a.p("\n\033[1mROUTES: %s\033[0m", wsID)
	a.p("%s", strings.Repeat("═", 78))
	if len(data) == 0 {
		a.p("  No routes. Add a web service with `om add` and run `om start`.\n")
		return nil
	}
	labels := map[string]string{"vpn": "your VPN devices", "lan": "LAN", "vpn_guests": "VPN guests"}
	for _, r := range data {
		tier := "\033[33mPRIVATE\033[0m"
		if r["scope"] == "public" {
			tier = "\033[36mPUBLIC\033[0m"
		}
		proto := ""
		if r["protocol"] == "tcp" {
			proto = " (tcp)"
		}
		custom := ""
		if r["custom_caddy"] == true {
			custom = fmt.Sprintf("  \033[35m+ custom %s\033[0m", routes.SnippetFile)
		}
		up := "?"
		if r["upstream"] != nil {
			up = py.Str(r["upstream"])
		}
		a.p("  \033[1m%s\033[0m  (%s%s) → %s%s", py.Str(r["service"]), tier, proto, up, custom)
		urls := r["urls"].(map[string]any)
		a.p("    %s", py.Str(urls["this_machine"]))
		for _, k := range []string{"vpn", "lan", "vpn_guests"} {
			for _, u := range anyStrings(urls[k]) {
				a.p("    %s   (%s)", u, labels[k])
			}
		}
		if r["logged"] == false {
			a.p("    \033[36m🔇 om.log=off: no access log at the edge, no connection log in the firewall\033[0m")
		}
		if n, ok := r["net"].(map[string]any); ok {
			var allow []string
			for _, x := range anyStrings(n["allow"]) {
				if x == "vpn" {
					v := strings.Join(a.Settings().VPNAllow(), ", ")
					if v == "" {
						v = "empty"
					}
					x = fmt.Sprintf("VPN allow-list (%s)", v)
				}
				allow = append(allow, x)
			}
			var rule []string
			if n["allow"] != nil {
				rule = append(rule, "only "+strings.Join(allow, ", "))
			}
			if d := anyStrings(n["deny"]); len(d) > 0 {
				rule = append(rule, "never "+strings.Join(d, ", "))
			}
			if n["enforced"] == true {
				a.p("    \033[36m🔒 om.net: %s (and this machine)\033[0m", strings.Join(rule, "; "))
			} else {
				a.p("    \033[31m🔒 om.net: %s — not in the host firewall yet: the ports above stay closed until `om firewall apply`\033[0m", strings.Join(rule, "; "))
			}
		}
	}
	a.p("")
	return nil
}

func (a *App) cmdPorts(ns Namespace) error {
	rt := a.Runtime()
	a.p("\n\033[1mHOST PORTS\033[0m")
	a.p("%s", strings.Repeat("═", 78))
	r := a.Run([]string{rt, "ps", "--format", "{{.Names}}\t{{.Ports}}"})
	type leak struct {
		name  string
		binds []string
	}
	var leaks []leak
	for _, line := range py.SplitLines(r.Stdout) {
		name, ports, _ := strings.Cut(line, "\t")
		var binds []string
		for _, p := range strings.Split(ports, ",") {
			if strings.Contains(p, "->") {
				binds = append(binds, py.Strip(p))
			}
		}
		switch {
		case name == state.Edge || name == state.StreamEdge:
			for _, b := range binds {
				tier := "private"
				if name == state.StreamEdge {
					tier = "stream"
				} else if strings.Contains(b, "->8080") || strings.Contains(b, "->8443") {
					tier = "public (LAN)"
				}
				a.p("  %s %s", ljust(b, 44), tier)
			}
		case len(binds) > 0:
			leaks = append(leaks, leak{name, binds})
		}
	}
	if len(leaks) > 0 {
		a.p("\n  \033[31mOther containers publishing host ports (bypass the proxy):\033[0m")
		for _, l := range leaks {
			a.p("    %s: %s", l.name, strings.Join(l.binds, ", "))
		}
	} else {
		a.p("\n  \033[32mNo other container publishes host ports.\033[0m")
	}
	a.p("")
	return nil
}
