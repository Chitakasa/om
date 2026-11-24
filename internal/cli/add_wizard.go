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
	waive     string // om.policy.allow, set when the choices need an explicit waiver
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
	add("om.policy.allow", w.waive)
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
	var info imageInfo
	if w.kind != "project" && args.Image != "" {
		var err error
		if info, _, err = a.imageHints(p, args.Image); err != nil {
			return args, err
		}
	}
	if (w.kind == "web" && args.Image != "" || w.kind == "tcp") && args.Port == 0 {
		def := ""
		if len(info.Ports) > 0 {
			def = strconv.Itoa(info.Ports[0])
		}
		port, err := p.Ask("Port it listens on inside the container", def, func(s string) string { return portCheck(s) })
		if err != nil {
			return args, err
		}
		args.Port, _ = strconv.Atoi(port)
	}
	if len(info.Volumes) > 0 && len(args.Volumes) == 0 {
		yes, err := p.Confirm("The image keeps data in "+strings.Join(info.Volumes, ", ")+". Store it in managed volumes so it survives updates?", true)
		if err != nil {
			return args, err
		}
		if yes {
			for _, v := range info.Volumes {
				args.Volumes = append(args.Volumes, volumeName(args.Name, args.Volumes)+":"+v)
			}
		}
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
		w.waive = ""
		if (len(args.Volumes) > 0 || len(args.Secrets) > 0) && (w.egress == "learn" || w.egress == "internet") {
			w.waive = "egress" // keeping data and reaching the whole internet needs the operator's explicit waiver
		}
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
			for _, kv := range w.labels() {
				args.Extra = mergeKV(args.Extra, kv)
			}
			return args, nil
		case 2:
			return args, wizard.ErrCancelled
		}
		if err := a.addCustomise(p, &args, &w, true); err != nil {
			return args, err
		}
	}
}

func (a *App) summaryRow(what, value, lbl string) {
	if lbl != "" {
		lbl = "   [" + lbl + "]"
	}
	a.p("  %-12s %s%s", what, value, lbl)
}

// summaryChoices prints the answers that become labels, in words, each with the label it writes.
func (a *App) summaryChoices(args scaffold.AddArgs, w addAnswers) {
	scope, label := "this machine and your VPN devices", "dashboard.scope=private"
	if args.Public {
		scope, label = "this machine, your VPN devices and your local network", "dashboard.scope=public"
	}
	a.summaryRow("Reached by", scope, label)
	if w.allow != "" {
		a.summaryRow("  only from", w.allow, "om.net.allow="+w.allow)
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
	a.summaryRow("Outbound", out, pick(w.egress != "", "om.egress="+w.egress, ""))
	if w.mem != "" || w.cpus != "" {
		var parts []string
		if w.mem != "" {
			parts = append(parts, "memory "+w.mem)
		}
		if w.cpus != "" {
			parts = append(parts, "cpus "+w.cpus)
		}
		a.summaryRow("Limits", strings.Join(parts, ", "), "")
	}
	if w.update != "" {
		a.summaryRow("Updates", map[string]string{"hold": "hold (never changes unless you say)", "auto": "automatic, reverted if the health check fails"}[w.update], "om.update="+w.update)
	}
	if w.logOff {
		a.summaryRow("Logging", "leaves no trace", "om.log=off")
	}
}

func (a *App) addSummary(wsID string, args scaffold.AddArgs, w addAnswers) {
	a.p("\n\033[1mAbout to create\033[0m")
	kind := "services"
	if args.Project {
		kind = "projects"
	}
	a.summaryRow("Folder", kind+"/"+args.Name, "")
	switch {
	case args.Project:
		a.summaryRow("Runs", "a Node.js dev project with live reload", "")
	case args.Image == "":
		a.summaryRow("Runs", "a small nginx", "")
	default:
		a.summaryRow("Runs", args.Image, "")
	}
	if !args.NoWeb {
		a.summaryRow("Address", "http://"+wsID+"."+strings.ToLower(args.Name)+".localhost", "")
	}
	a.summaryChoices(args, w)
	if len(args.Volumes) > 0 {
		a.summaryRow("Data", strings.Join(args.Volumes, ", "), "managed volumes")
	}
	if len(args.Env) > 0 {
		var keys []string
		for _, kv := range args.Env {
			keys = append(keys, kv.Key)
		}
		a.summaryRow("Settings", strings.Join(keys, ", "), "")
	}
	if len(args.Secrets) > 0 {
		a.summaryRow("Secrets", strings.Join(args.Secrets, ", "), "om secrets set "+args.Name+"/<name>")
	}
	if args.Health != "" {
		a.summaryRow("Health check", args.Health, "")
	}
	if w.waive != "" {
		a.summaryRow("Waiver", "it keeps data and may reach the internet, which om asks you to allow on purpose", "om.policy.allow=egress")
	}
	if w.kind == "tcp" {
		a.summaryRow("TCP port", strconv.Itoa(w.tcpPort), "om.tcp="+strconv.Itoa(w.tcpPort))
	}
	a.p("")
}

// addCustomise is the "Customise" menu: one category at a time until Done.
func (a *App) addCustomise(p *wizard.Prompter, args *scaffold.AddArgs, w *addAnswers, own bool) error {
	opts := []wizard.Option{
		{Label: "Who can reach it"},
		{Label: "Outbound traffic", Hint: "what the service may connect to"},
		{Label: "Limits", Hint: "memory and CPU"},
		{Label: "Updates"},
		{Label: "Logging"},
		{Label: "Dashboard card", Hint: "icon and description"},
	}
	if own { // a service om writes: its data, settings and health check are asked here; an imported file has its own
		opts = append(opts, wizard.Option{Label: "Data it keeps", Hint: "folders that survive updates"},
			wizard.Option{Label: "Settings and secrets", Hint: "environment variables, passwords, tokens"},
			wizard.Option{Label: "Health check", Hint: "how om tells it is working"})
	}
	opts = append(opts, wizard.Option{Label: "Done"})
	done := len(opts) - 1
	for {
		i, err := p.Choose("\nCustomise", opts, done)
		if err != nil || i == done {
			return err
		}
		switch i {
		case 6:
			err = a.addData(p, args)
		case 7:
			err = a.addSettings(p, args)
		case 8:
			err = a.addHealth(p, args)
		default:
			err = a.addCategory(p, args, w, i)
		}
		if err != nil {
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
