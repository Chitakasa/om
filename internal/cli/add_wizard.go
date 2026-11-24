package cli

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Chitakasa/om/internal/egress"
	"github.com/Chitakasa/om/internal/routes"
	"github.com/Chitakasa/om/internal/scaffold"
	"github.com/Chitakasa/om/internal/wizard"
	"github.com/Chitakasa/om/internal/workspace"
)

// The interactive `om add`: three questions (what, which image, which port) and a summary; "customise more" opens the
// rest (who can reach it, outbound traffic, limits, updates, logging, the dashboard card). Every answer shows the label
// it writes, so the labels are learned by using them, and the result is an ordinary compose file. Nothing is written
// until the summary is confirmed.

// addAnswers are what the questions collect beyond what scaffold.AddArgs already holds.
type addAnswers struct {
	kind      string // web, tcp, worker or project
	allow     string // om.net.allow, "" for no restriction
	egress    string // "" (none), "learn", "internet", or a comma list of hosts
	mem, cpus string
	update    string // "", "hold" or "auto"
	logOff    bool
	tcpPort   int
}

// labels are the extra labels the answers write (scope and the dashboard card go through AddArgs).
func (w addAnswers) labels() []scaffold.KV {
	var kv []scaffold.KV
	add := func(k, v string) {
		if v != "" {
			kv = append(kv, scaffold.KV{Key: k, Value: v})
		}
	}
	if w.kind == "tcp" {
		add("om.tcp", strconv.Itoa(w.tcpPort))
	}
	add("om.net.allow", w.allow)
	add("om.egress", w.egress)
	add("om.mem", w.mem)
	add("om.cpus", w.cpus)
	add("om.update", w.update)
	if w.logOff {
		add("om.log", "off")
	}
	return kv
}

func pick(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}

func portCheck(s string) string {
	if n, err := strconv.Atoi(s); err != nil || n < 1 || n > 65535 {
		return "Type a port number from 1 to 65535."
	}
	return ""
}

func (a *App) addWizard(root, wsID string, args scaffold.AddArgs) (scaffold.AddArgs, error) {
	p := &wizard.Prompter{In: a.In, Out: a.Out}
	var w addAnswers
	taken := func(name string) bool {
		for _, kind := range []string{"services", "projects"} {
			if _, err := os.Stat(filepath.Join(root, kind, name)); err == nil {
				return true
			}
		}
		return false
	}
	a.p("\033[1mAdd a service\033[0m  (Enter takes the [default]; Ctrl-D cancels; nothing is written until you confirm)\n")

	if args.Name == "" {
		name, err := p.Ask("Name (lowercase letters, digits and -)", "", func(s string) string {
			n := strings.ReplaceAll(strings.ToLower(s), " ", "-")
			switch {
			case !workspace.IsSafeName(n):
				return "Use lowercase letters, digits and - only."
			case taken(n):
				return n + " already exists here."
			}
			return ""
		})
		if err != nil {
			return args, err
		}
		args.Name = name
	}

	switch {
	case args.Project:
		w.kind = "project"
	case args.NoWeb && args.Image != "" && args.Port == 0:
		w.kind = "worker"
	case args.Image != "" || args.Port != 0:
		w.kind = "web"
	default:
		i, err := p.Choose("\nWhat are you adding?", []wizard.Option{
			{Label: "A web app or site", Hint: "reached in the browser; a small nginx to try, or an image you pick"},
			{Label: "A TCP server", Hint: "a game server or database that other devices connect to"},
			{Label: "A background service", Hint: "runs on its own, with no network address"},
			{Label: "A Node.js project to develop here", Hint: "live reload, in projects/"},
		}, 0)
		if err != nil {
			return args, err
		}
		w.kind = []string{"web", "tcp", "worker", "project"}[i]
	}

	if w.kind != "project" && args.Image == "" {
		def, required := "", w.kind != "web"
		img, err := p.Ask("\nImage"+pick(required, "", " (Enter: a small nginx to try)"), def, func(s string) string {
			switch {
			case s == "" && required:
				return "Type an image, for example docker.io/library/redis:7."
			case strings.ContainsAny(s, " \t") || !scaffold.YAMLLabelSafe(s):
				return "An image has no spaces, quotes or backslashes."
			}
			return ""
		})
		if err != nil {
			return args, err
		}
		args.Image = img
	}
	if (w.kind == "web" && args.Image != "" || w.kind == "tcp") && args.Port == 0 {
		port, err := p.Ask("Port it listens on inside the container", "", func(s string) string { return portCheck(s) })
		if err != nil {
			return args, err
		}
		args.Port, _ = strconv.Atoi(port)
	}
	switch w.kind {
	case "tcp":
		args.NoWeb = true
		w.tcpPort = args.Port
	case "worker":
		args.NoWeb = true
	case "project":
		args.Project = true
	}

	for {
		a.addSummary(wsID, args, w)
		i, err := p.Choose("What next?", []wizard.Option{
			{Label: "Create it"},
			{Label: "Customise more", Hint: "who can reach it, outbound traffic, limits, updates, logging, the dashboard card"},
			{Label: "Cancel"},
		}, 0)
		if err != nil {
			return args, err
		}
		switch i {
		case 0:
			args.Extra = w.labels()
			return args, nil
		case 2:
			return args, wizard.ErrCancelled
		}
		if err := a.addCustomise(p, &args, &w); err != nil {
			return args, err
		}
	}
}

func (a *App) addSummary(wsID string, args scaffold.AddArgs, w addAnswers) {
	scope, label := "this machine and your VPN devices", "dashboard.scope=private"
	if args.Public {
		scope, label = "this machine, your VPN devices and your local network", "dashboard.scope=public"
	}
	row := func(what, value, lbl string) {
		if lbl != "" {
			lbl = "   [" + lbl + "]"
		}
		a.p("  %-12s %s%s", what, value, lbl)
	}
	a.p("\n\033[1mAbout to create\033[0m")
	kind := "services"
	if args.Project {
		kind = "projects"
	}
	row("Folder", kind+"/"+args.Name, "")
	switch {
	case args.Project:
		row("Runs", "a Node.js dev project with live reload", "")
	case args.Image == "":
		row("Runs", "a small nginx", "")
	default:
		row("Runs", args.Image, "")
	}
	if !args.NoWeb {
		row("Address", "http://"+wsID+"."+strings.ToLower(args.Name)+".localhost", "")
	}
	row("Reached by", scope, label)
	if w.allow != "" {
		row("  only from", w.allow, "om.net.allow="+w.allow)
	}
	if w.kind == "tcp" {
		row("TCP port", strconv.Itoa(w.tcpPort), "om.tcp="+strconv.Itoa(w.tcpPort))
	}
	out := "nothing (it cannot reach the internet)"
	switch w.egress {
	case "":
	case "learn":
		out = "om records what it uses, then you allow it"
	case "internet":
		out = "anything on the internet"
	default:
		out = "only " + w.egress
	}
	row("Outbound", out, pick(w.egress != "", "om.egress="+w.egress, ""))
	if w.mem != "" || w.cpus != "" {
		var parts []string
		if w.mem != "" {
			parts = append(parts, "memory "+w.mem)
		}
		if w.cpus != "" {
			parts = append(parts, "cpus "+w.cpus)
		}
		row("Limits", strings.Join(parts, ", "), "")
	}
	if w.update != "" {
		row("Updates", map[string]string{"hold": "hold (never changes unless you say)", "auto": "automatic, reverted if the health check fails"}[w.update], "om.update="+w.update)
	}
	if w.logOff {
		row("Logging", "leaves no trace", "om.log=off")
	}
	a.p("")
}

// addCustomise is the "Customise" menu: one category at a time until Done.
func (a *App) addCustomise(p *wizard.Prompter, args *scaffold.AddArgs, w *addAnswers) error {
	for {
		i, err := p.Choose("\nCustomise", []wizard.Option{
			{Label: "Who can reach it"},
			{Label: "Outbound traffic", Hint: "what the service may connect to"},
			{Label: "Limits", Hint: "memory and CPU"},
			{Label: "Updates"},
			{Label: "Logging"},
			{Label: "Dashboard card", Hint: "icon and description"},
			{Label: "Done"},
		}, 6)
		if err != nil || i == 6 {
			return err
		}
		if err := a.addCategory(p, args, w, i); err != nil {
			return err
		}
	}
}

func (a *App) addCategory(p *wizard.Prompter, args *scaffold.AddArgs, w *addAnswers, i int) error {
	switch i {
	case 0:
		def := 0
		if args.Public {
			def = 1
		}
		j, err := p.Choose("Who can reach it?", []wizard.Option{
			{Label: "This machine and your VPN devices", Hint: "private (dashboard.scope=private)"},
			{Label: "Also your local network", Hint: "public (dashboard.scope=public)"},
		}, def)
		if err != nil {
			return err
		}
		args.Public = j == 1
		allow, err := p.Ask("Only from these addresses? (vpn, or addresses and ranges like 10.0.0.5, 192.168.1.0/24; Enter: no restriction)", w.allow, func(s string) string {
			if s == "" {
				return ""
			}
			_, problems := routes.ParseNetPolicy(map[string]string{routes.NetAllow: s}, a.Settings().VPNAllow())
			if len(problems) > 0 {
				return problems[0]
			}
			return ""
		})
		if err != nil {
			return err
		}
		w.allow = allow
	case 1:
		j, err := p.Choose("Outbound traffic", []wizard.Option{
			{Label: "Nothing", Hint: "the default: no route out"},
			{Label: "Let om learn what it uses", Hint: "om.egress=learn, then `om egress log --apply` writes the list"},
			{Label: "Only these hosts", Hint: "om.egress=host,host"},
			{Label: "Anything on the internet", Hint: "om.egress=internet; only for services that hold no secrets"},
		}, 0)
		if err != nil {
			return err
		}
		switch j {
		case 0:
			w.egress = ""
		case 1:
			w.egress = "learn"
		case 3:
			w.egress = "internet"
		case 2:
			hosts, err := p.Ask("Hosts, separated by commas (for example api.example.org,*.example.org)", "", func(s string) string {
				for _, h := range strings.Split(s, ",") {
					if h = strings.ToLower(strings.TrimSpace(h)); !egress.ValidHost(h) {
						return "'" + h + "' is not a host name (a leading *. is allowed)."
					}
				}
				return ""
			})
			if err != nil {
				return err
			}
			var clean []string
			for _, h := range strings.Split(hosts, ",") {
				clean = append(clean, strings.ToLower(strings.TrimSpace(h)))
			}
			w.egress = strings.Join(clean, ",")
		}
	case 2:
		mem, err := p.Ask("Memory limit (for example 256m or 2g; Enter: none)", w.mem, func(s string) string {
			if s == "" {
				return ""
			}
			if n := len(s); n < 2 || !strings.ContainsRune("kKmMgG", rune(s[n-1])) {
				return "Use a number with k, m or g, for example 256m."
			} else if _, err := strconv.Atoi(s[:n-1]); err != nil {
				return "Use a number with k, m or g, for example 256m."
			}
			return ""
		})
		if err != nil {
			return err
		}
		w.mem = strings.ToLower(mem)
		cpus, err := p.Ask("CPU limit (for example 0.5 or 2; Enter: none)", w.cpus, func(s string) string {
			if f, err := strconv.ParseFloat(s, 64); s != "" && (err != nil || f <= 0) {
				return "Type a number above 0, for example 0.5."
			}
			return ""
		})
		if err != nil {
			return err
		}
		w.cpus = cpus
	case 3:
		j, err := p.Choose("Updates", []wizard.Option{
			{Label: "Keep the default", Hint: "you run `om update` when you want"},
			{Label: "Hold", Hint: "om.update=hold: the image never changes unless you say"},
			{Label: "Automatic", Hint: "om.update=auto: the scheduled sync updates it and reverts if the health check fails"},
		}, 0)
		if err != nil {
			return err
		}
		w.update = []string{"", "hold", "auto"}[j]
	case 4:
		j, err := p.Choose("Logging", []wizard.Option{
			{Label: "Keep the default", Hint: "access logs hold no URLs or client addresses"},
			{Label: "Leave no trace", Hint: "om.log=off: no access or connection log, no output kept"},
		}, 0)
		if err != nil {
			return err
		}
		w.logOff = j == 1
	case 5:
		icon, err := p.Ask("Icon (an emoji)", pick(args.Icon != "", args.Icon, "📦"), func(s string) string {
			if !scaffold.YAMLLabelSafe(s) {
				return "No quotes, backslashes or line breaks."
			}
			return ""
		})
		if err != nil {
			return err
		}
		desc, err := p.Ask("Description", args.Desc, func(s string) string {
			if !scaffold.YAMLLabelSafe(s) {
				return "No quotes, backslashes or line breaks."
			}
			return ""
		})
		if err != nil {
			return err
		}
		args.Icon, args.Desc = icon, desc
	}
	return nil
}
