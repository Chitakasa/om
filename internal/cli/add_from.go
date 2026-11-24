package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Chitakasa/om/internal/composefix"
	"github.com/Chitakasa/om/internal/policy"
	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/scaffold"
	"github.com/Chitakasa/om/internal/wizard"
	"github.com/Chitakasa/om/internal/workspace"
)

// `om add --from <compose file or folder>` brings a compose file you already have into the workspace. The folder (or the
// file) is copied to services/<name>, and om makes only the small edits it needs, shown as a diff before anything is
// kept: `ports:` becomes `expose:` (the edge routes to the service) and the labels you choose are added. Comments,
// layout and everything else stay as you wrote them. A copy is staged first, so cancelling removes it.

const (
	maxImportFiles = 5000
	maxImportBytes = 200 << 20
)

var relativeRefRE = regexp.MustCompile(`(?m)^\s*(build:|env_file:|include:|extends:|- +\.\.?/|- +\./)`)

// importSpec is what is known about the compose file being brought in.
type importSpec struct {
	name, dest, composeFile string // composeFile is the path inside dest
	proj                    *project
	bases                   map[string]bool       // services another service extends: they cannot carry the container name
	others                  map[string]addAnswers // per-service choices for the services that are not the web page
	problems                []string              // what the deploy gate would still refuse
	label                   string                // how to describe the source, when it is not a path
	cfg0                    map[string]any        // the engine's resolved config of the original, nil without an engine
	cfgErr                  string
	services                []string
	main                    string // the service that carries the labels and the web address
	web                     bool
	port                    string // the web service's container port, when it is a plain number
	files                   int
	from                    string
}

// resolveComposeSource finds the compose file for --from: a folder holding one, or the file itself.
func resolveComposeSource(from string) (dir, file string, isDir bool, err error) {
	st, err := os.Stat(from)
	if err != nil {
		return "", "", false, fmt.Errorf("%s: no such file or folder", from)
	}
	if st.IsDir() {
		cf, ok := workspace.FindComposeFile(from)
		if !ok {
			return "", "", false, fmt.Errorf("%s has no compose file (compose.yml, compose.yaml, docker-compose.yml or docker-compose.yaml)", from)
		}
		return from, cf, true, nil
	}
	return filepath.Dir(from), from, false, nil
}

// defaultServiceName turns the folder (or the file's folder) name into a valid service name.
func defaultServiceName(dir string) string {
	n := strings.ToLower(filepath.Base(filepath.Clean(dir)))
	n = strings.Trim(regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(n, "-"), "-")
	if !workspace.IsSafeName(n) {
		return "service"
	}
	return n
}

// copyComposeSource stages the compose folder (or file) at dest and returns the compose file's path there and notes
// about what it left out. It never follows symlinks and refuses a folder that is too big or is itself a workspace.
func copyComposeSource(dir, file string, isDir bool, dest string) (composePath string, files int, notes []string, err error) {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return "", 0, nil, err
	}
	if !isDir {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", 0, nil, err
		}
		composePath = filepath.Join(dest, "compose.yml")
		if relativeRefRE.Match(b) {
			notes = append(notes, "it refers to files next to it (a build context, an env file or a ./ mount): copy the folder instead (om add --from <folder>)")
		}
		return composePath, 1, notes, os.WriteFile(composePath, b, 0o644)
	}
	if _, err := os.Stat(filepath.Join(dir, ".om", "config.json")); err == nil {
		return "", 0, nil, fmt.Errorf("%s is itself an om workspace; point --from at a service folder", dir)
	}
	var total int64
	skipped := 0
	err = filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if rel == "." {
			return nil
		}
		if e.IsDir() && (e.Name() == ".git" || e.Name() == "node_modules") {
			skipped++
			return fs.SkipDir
		}
		if e.Type()&fs.ModeSymlink != 0 {
			skipped++
			return nil
		}
		if e.IsDir() {
			return os.MkdirAll(filepath.Join(dest, rel), 0o755)
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		if files++; files > maxImportFiles || total+info.Size() > maxImportBytes {
			return fmt.Errorf("%s is too big to copy (over %d files or %d MB): point --from at the compose folder only", dir, maxImportFiles, maxImportBytes>>20)
		}
		total += info.Size()
		return copyFile(p, filepath.Join(dest, rel), info.Mode().Perm())
	})
	if err != nil {
		return "", 0, nil, err
	}
	if skipped > 0 {
		notes = append(notes, fmt.Sprintf("left out %d .git, node_modules or symlink entries", skipped))
	}
	rel, _ := filepath.Rel(dir, file)
	return filepath.Join(dest, rel), files, notes, nil
}

func copyFile(src, dst string, mode fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// discover reads the original once: the services and the container ports each one publishes. The engine's resolved
// config is used when there is one (it knows anchors, merge keys, extends and includes); the text is read otherwise.
func (a *App) discover(s *importSpec, root, wsID, rt string) (map[string][]string, error) {
	proj, err := loadProject(filepath.Dir(s.composeFile), s.composeFile)
	if err != nil {
		return nil, err
	}
	s.proj = proj
	main, err := composefix.Parse(proj.orig[proj.files[0]])
	if err != nil {
		return nil, err
	}
	ports := map[string][]string{}
	s.bases = map[string]bool{}
	for _, f := range proj.files {
		if d, err := composefix.Parse(proj.orig[f]); err == nil {
			for _, svc := range d.Services() {
				if _, base, ok := d.Extends(svc); ok {
					s.bases[base] = true
				}
			}
		}
	}
	res := a.composeConfig(rt, s.composeFile, a.wsEnv(root, wsID, rt))
	s.cfg0, s.cfgErr = res.cfg, res.err
	if res.cfg != nil {
		resolved := cfgServices(res.cfg)
		for name, sv := range resolved {
			ports[name] = append(cfgPorts(sv), cfgExpose(sv)...)
		}
		for _, f := range proj.files {
			if d, err := composefix.Parse(proj.orig[f]); err == nil {
				for _, svc := range d.Services() {
					if _, ok := resolved[svc]; ok {
						s.services = append(s.services, svc)
					}
				}
			}
		}
		return ports, nil
	}
	for _, f := range proj.files {
		d, err := composefix.Parse(proj.orig[f])
		if err != nil {
			continue
		}
		for _, svc := range d.Services() {
			s.services = append(s.services, svc)
			if _, p, _, err := d.PortsToExpose(svc); err == nil {
				ports[svc] = p
			}
		}
	}
	_ = main
	return ports, nil
}

// labelSets are the labels the main service gets: defaults (kept when the author already wrote the label) and the
// user's choices (which replace).
func (s *importSpec) labelSets(wsID string, args scaffold.AddArgs, w addAnswers) (defaults, chosen []composefix.KV) {
	icon, desc := pick(args.Icon != "", args.Icon, "📦"), pick(args.Desc != "", args.Desc, "Imported service: "+s.name)
	defaults = []composefix.KV{{Key: "workspace.id", Value: "${WORKSPACE_ID:-" + wsID + "}"}, {Key: "dashboard.name", Value: py.Title(s.name)},
		{Key: "dashboard.icon", Value: icon}, {Key: "dashboard.description", Value: desc}}
	if s.web && s.port != "" {
		defaults = append(defaults, composefix.KV{Key: "dashboard.port", Value: s.port})
	}
	if !s.web {
		defaults = append(defaults, composefix.KV{Key: "dashboard.web", Value: "false"})
	}
	if args.Public {
		chosen = append(chosen, composefix.KV{Key: "dashboard.scope", Value: "public"})
	} else {
		defaults = append(defaults, composefix.KV{Key: "dashboard.scope", Value: "private"})
	}
	if args.Icon != "" {
		chosen = append(chosen, composefix.KV{Key: "dashboard.icon", Value: args.Icon})
	}
	if args.Desc != "" {
		chosen = append(chosen, composefix.KV{Key: "dashboard.description", Value: args.Desc})
	}
	for _, kv := range w.labels() {
		chosen = append(chosen, composefix.KV{Key: kv.Key, Value: kv.Value})
	}
	return defaults, chosen
}

// build applies the edits to the original text of every file: ports to expose on every service, then the labels on
// the main one.
func (s *importSpec) build(wsID string, args scaffold.AddArgs, w addAnswers) (texts map[string]string, changes, advice []string, chosen []composefix.KV, err error) {
	defaults, chosen := s.labelSets(wsID, args, w)
	others := map[string][]composefix.KV{}
	for svc, ow := range s.others {
		for _, kv := range ow.labels() {
			others[svc] = append(others[svc], composefix.KV{Key: kv.Key, Value: kv.Value})
		}
	}
	texts, changes, advice, err = s.proj.apply(s.cfg0, s.main, wsID, s.name, defaults, chosen, others)
	return texts, changes, advice, chosen, err
}

// importPolicy runs the deploy gate on the staged file: the resolved config (nil without an engine), what `om start`
// would refuse, and why the check was skipped, if it was.
func (a *App) importPolicy(root, wsID, rt, file string) (cfg map[string]any, problems []string, skipped string) {
	res := a.composeConfig(rt, file, a.wsEnv(root, wsID, rt))
	if res.cfg == nil {
		return nil, nil, res.err
	}
	violations, _ := policy.EvaluateCompose(res.cfg, res.err, wsID+"_net")
	return res.cfg, violations, ""
}

func numericPort(ports []string) string {
	for _, p := range ports {
		if _, err := strconv.Atoi(p); err == nil {
			return p
		}
	}
	return ""
}

// pickMain chooses the service that carries the labels and the web address.
func (a *App) pickMain(p *wizard.Prompter, s *importSpec, ports map[string][]string) error {
	cands := make([]string, 0, len(s.services)) // a service another one extends cannot carry the container name
	for _, svc := range s.services {
		if !s.bases[svc] {
			cands = append(cands, svc)
		}
	}
	if len(cands) == 0 {
		cands = s.services
	}
	for _, svc := range cands {
		if len(ports[svc]) > 0 {
			s.main, s.web = svc, true
			break
		}
	}
	if s.main == "" {
		s.main = cands[0]
	}
	if a.Interactive && len(cands) > 1 {
		opts := make([]wizard.Option, 0, len(cands)+1)
		def := 0
		for i, svc := range cands {
			hint := "no published port"
			if len(ports[svc]) > 0 {
				hint = "port " + strings.Join(ports[svc], ", ")
			}
			if svc == s.main {
				def = i
			}
			opts = append(opts, wizard.Option{Label: svc, Hint: hint})
		}
		opts = append(opts, wizard.Option{Label: "None of them", Hint: "they all run in the background"})
		i, err := p.Choose("\nWhich service has the web page?", opts, def)
		if err != nil {
			return err
		}
		if i == len(cands) {
			s.main, s.web = cands[0], false
		} else {
			s.main, s.web = cands[i], true
		}
	} else if a.Interactive && !s.web {
		yes, err := p.Confirm("\n"+s.main+" publishes no port. Does it have a web page?", false)
		if err != nil {
			return err
		}
		s.web = yes
	}
	if s.web {
		if s.port = numericPort(ports[s.main]); s.port == "" {
			if !a.Interactive {
				s.web = false
				s.proj.notes = append(s.proj.notes, s.main+" has no port om can read, so it is added as a background service; give it one with om edit "+s.name+" --port N")
			} else {
				port, err := p.Ask("Port "+s.main+" listens on inside the container", "", portCheck)
				if err != nil {
					return err
				}
				s.port = port
			}
		}
	}
	return nil
}

// importCompose stages the copy, asks what is left to decide and shows what it will change. On an error or a cancel the
// staged copy is removed; on success it is in place with the edits applied.
func (a *App) importCompose(root, wsID string, ns Namespace, args scaffold.AddArgs, from string) (s *importSpec, err error) {
	rt := a.Runtime()
	dir, file, isDir, err := resolveComposeSource(from)
	if err != nil {
		return nil, err
	}
	p := &wizard.Prompter{In: a.In, Out: a.Out}
	taken := func(n string) bool { _, e := os.Stat(filepath.Join(root, "services", n)); return e == nil }
	name := strings.ToLower(args.Name)
	if name == "" {
		name = defaultServiceName(dir)
		if a.Interactive {
			a.p("\033[1mAdd a compose file\033[0m  (Enter takes the [default]; Ctrl-D cancels; nothing is kept until you confirm)\n")
			if name, err = p.Ask("Name for it here", name, func(v string) string {
				switch {
				case !workspace.IsSafeName(v):
					return "Use lowercase letters, digits and - only."
				case taken(v):
					return v + " already exists here."
				}
				return ""
			}); err != nil {
				return nil, err
			}
		}
	}
	if !workspace.IsSafeName(name) || taken(name) {
		return nil, fmt.Errorf("the name '%s' is not usable (lowercase letters, digits and -, and not already in services/)", name)
	}
	dest := filepath.Join(root, "services", name)
	s = &importSpec{name: name, dest: dest, from: from, label: ns.Str("from_label")}
	done := false
	defer func() {
		if !done {
			os.RemoveAll(dest) // a failed or cancelled import leaves nothing behind
		}
	}()
	composePath, files, notes, err := copyComposeSource(dir, file, isDir, s.dest)
	if err != nil {
		return nil, err
	}
	s.composeFile, s.files = composePath, files
	ports, err := a.discover(s, root, wsID, rt)
	if err != nil {
		return nil, fmt.Errorf("%s: %v (om reads a compose file with a top-level services: mapping)", from, err)
	}
	if err := a.pickMain(p, s, ports); err != nil {
		return nil, err
	}
	var w addAnswers
	w.kind = "web"
	args.Name = name
	for {
		texts, changes, advice, chosen, err := s.build(wsID, args, w)
		if err != nil {
			return nil, err
		}
		for f, t := range texts {
			if err := os.WriteFile(filepath.Join(filepath.Dir(composePath), filepath.FromSlash(f)), []byte(t), 0o644); err != nil {
				return nil, err
			}
		}
		cfg1, problems, skipped := a.importPolicy(root, wsID, rt, composePath)
		s.problems = problems
		if cfg1 != nil && s.cfg0 != nil {
			if bad := verifyImport(s.cfg0, cfg1, chosen, s.main, wsID, s.name); len(bad) > 0 {
				return nil, fmt.Errorf("the compose engine reads the edited file differently from yours, so nothing was added:\n    - %s\n  Bring it in by hand: change `ports:` to `expose:` and add the labels from `om docs labels`", strings.Join(bad, "\n    - "))
			}
		}
		a.importSummary(wsID, s, args, w, changes, advice, append(notes, s.proj.notes...), problems, skipped, texts)
		if !a.Interactive {
			if !ns.Bool("yes") {
				return nil, errors.New("nothing was added: run again with --yes to apply these changes (or without it on a terminal to be asked)")
			}
			done = true
			return s, nil
		}
		opts := []wizard.Option{
			{Label: "Add it"},
			{Label: "Customise more", Hint: "who can reach it, outbound traffic, limits, updates, logging, the dashboard card"},
		}
		if len(s.services) > 1 {
			opts = append(opts, wizard.Option{Label: "Customise another service", Hint: "limits, outbound traffic, updates and logging are per container"})
		}
		opts = append(opts, wizard.Option{Label: "Cancel"})
		i, err := p.Choose("What next?", opts, 0)
		if err != nil {
			return nil, err
		}
		switch {
		case i == 0:
			done = true
			return s, nil
		case i == len(opts)-1:
			return nil, wizard.ErrCancelled
		case i == 1:
			if err := a.addCustomise(p, &args, &w, false); err != nil {
				return nil, err
			}
		default:
			if err := a.customiseOther(p, s); err != nil {
				return nil, err
			}
		}
	}
}

func (a *App) importSummary(wsID string, s *importSpec, args scaffold.AddArgs, w addAnswers, changes, advice, notes, problems []string, skipped string, texts map[string]string) {
	a.p("\n\033[1mAbout to add\033[0m")
	a.summaryRow("From", pick(s.label != "", s.label, s.from), "")
	a.summaryRow("Folder", "services/"+s.name+pick(s.files > 1, fmt.Sprintf("  (%d files copied)", s.files), ""), "")
	a.summaryRow("Services", strings.Join(s.services, ", "), "")
	if s.web {
		a.summaryRow("Web page", s.main+pick(s.port != "", ", port "+s.port, ""), "")
		a.summaryRow("Address", "http://"+wsID+"."+s.name+".localhost", "")
	} else {
		a.summaryRow("Web page", "none (runs in the background)", "dashboard.web=false")
	}
	a.summaryChoices(args, w)
	for _, svc := range s.services {
		if ow, ok := s.others[svc]; ok && len(ow.labels()) > 0 {
			a.p("  %s:", svc)
			a.summaryChoices(scaffold.AddArgs{}, ow)
		}
	}
	if len(changes) > 0 {
		a.p("\n  Changed in your compose file so om can route to it:")
		for _, c := range changes {
			a.p("    • %s", c)
		}
	}
	for _, f := range s.proj.files {
		if d := composefix.Diff(s.proj.orig[f], texts[f]); d != "" {
			a.p("\n  The edit to %s, line by line:", f)
			for _, l := range strings.Split(strings.TrimRight(d, "\n"), "\n") {
				a.p("    %s", l)
			}
		}
	}
	for _, n := range notes {
		a.p("\n  \033[33mNote:\033[0m %s", n)
	}
	for _, n := range plainSecrets(s.cfg0, s.name) {
		a.p("\n  \033[33mNote:\033[0m %s", n)
	}
	for _, adv := range advice {
		a.p("\n  \033[33mNot changed:\033[0m %s", adv)
	}
	switch {
	case skipped != "":
		a.p("\n  \033[33mPolicy check skipped:\033[0m %s", firstLine(skipped))
	case len(problems) == 0:
		a.p("\n  \033[32mPolicy check: nothing om would refuse.\033[0m")
	default:
		a.p("\n  \033[31mom start would refuse this until you fix:\033[0m")
		for _, pr := range problems {
			a.p("    - %s", pr)
		}
		a.p("    (fix the file; most rules can be waived for one service with the om.policy.allow label, but `privileged` and `ports` never can: `om docs labels`)")
	}
	a.p("")
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func (a *App) cmdAddFrom(root, wsID string, ns Namespace, args scaffold.AddArgs, from string) error {
	rt := a.Runtime()
	s, err := a.importCompose(root, wsID, ns, args, from)
	if err != nil {
		if errors.Is(err, wizard.ErrCancelled) {
			a.p("Cancelled: nothing was added.")
			return Exit(1)
		}
		return Die("%s", err)
	}
	a.ensureNet(wsID, rt)
	a.Syncer.SyncCaddyRoutes(root, rt, true, nil)
	rel, _ := filepath.Rel(root, s.dest)
	a.p("\033[32m✓ Added %s at %s\033[0m", s.name, rel)
	if s.web {
		a.p("  • URL: \033[36m%s\033[0m", a.BaseURL(wsID+"."+s.name+".localhost"))
	}
	if cf, ok := workspace.FindComposeFile(s.dest); ok {
		if hb, _ := workspace.HasBuild(cf); !hb {
			a.lockWorkspace(root, s.name, false, nil) // pinned from the start; commit .om/lock.json with the service
		}
	}
	a.p("\n  Run '\033[1mom start %s\033[0m' to launch.", s.name)
	return nil
}
