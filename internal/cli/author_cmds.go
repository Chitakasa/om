package cli

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Chitakasa/om/internal/composefix"
	"github.com/Chitakasa/om/internal/generations"
	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/runcmd"
	"github.com/Chitakasa/om/internal/scaffold"
	"github.com/Chitakasa/om/internal/scripts"
	"github.com/Chitakasa/om/internal/state"
	"github.com/Chitakasa/om/internal/wizard"
	"github.com/Chitakasa/om/internal/workspace"
)

type scriptRow struct {
	name string
	desc *string
}

func lowerLess(a, b string) bool { return strings.ToLower(a) < strings.ToLower(b) }

func (a *App) cmdScripts(root string, ns Namespace) error {
	dir := filepath.Join(root, "scripts")
	groups := map[string][]scriptRow{}
	if st, err := os.Stat(dir); err == nil && st.IsDir() {
		var files []string
		filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				files = append(files, p)
			}
			return nil
		})
		for _, f := range files {
			base := filepath.Base(f)
			st, err := os.Stat(f)
			if err != nil || !st.Mode().IsRegular() || strings.HasPrefix(base, ".") {
				continue
			}
			ext := filepath.Ext(base)
			if !scripts.ScriptExts[ext] && st.Mode()&0o111 == 0 {
				continue
			}
			fh, err := os.Open(f)
			if err != nil {
				continue
			}
			head := make([]byte, 4096)
			n, _ := fh.Read(head)
			fh.Close()
			head = head[:n]
			if !scripts.ScriptExts[ext] {
				ok := false
				for _, m := range scripts.ExecMagic {
					ok = ok || strings.HasPrefix(string(head), string(m))
				}
				if !ok {
					continue
				}
			}
			rel, _ := filepath.Rel(dir, f)
			folder := filepath.ToSlash(filepath.Dir(rel))
			var desc *string
			if !strings.Contains(string(head), "\x00") {
				d := scripts.Description(head, base)
				desc = &d
			}
			groups[folder] = append(groups[folder], scriptRow{strings.TrimSuffix(base, ext), desc})
		}
	}
	if len(groups) == 0 {
		a.p("\033[33mNo scripts found in %s\033[0m", dir)
		return nil
	}
	count, nameW := 0, 0
	for _, g := range groups {
		count += len(g)
		for _, r := range g {
			nameW = max(nameW, runeLen(r.name))
		}
	}
	descCol := nameW + 6
	descW := max(termCols()-descCol-1, 20)
	wsID, _ := workspace.WorkspaceID(root)
	a.p("\n\033[1mSCRIPTS [%s]\033[0m  \033[2m%d in scripts/\033[0m", wsID, count)
	a.p("%s", strings.Repeat("═", 78))
	folders := sortedKeys(groups)
	sort.SliceStable(folders, func(i, j int) bool {
		fi, fj := folders[i] != ".", folders[j] != "."
		if fi != fj {
			return !fi
		}
		return strings.ToLower(folders[i]) < strings.ToLower(folders[j])
	})
	for _, folder := range folders {
		indent := "  "
		if folder != "." {
			a.p("  \033[36m%s/\033[0m", folder)
			indent = "    "
		}
		rows := groups[folder]
		sort.SliceStable(rows, func(i, j int) bool { return lowerLess(rows[i].name, rows[j].name) })
		for _, r := range rows {
			desc := "\033[2mbinary\033[0m"
			if r.desc != nil {
				desc = *r.desc
				if rs := []rune(desc); len(rs) > descW {
					desc = strings.TrimRightFunc(string(rs[:descW-1]), py.IsSpace) + "…"
				}
			}
			a.p("%s\033[1m%s\033[0m%s%s", indent, r.name, strings.Repeat(" ", max(descCol-len(indent)-runeLen(r.name), 0)), desc)
		}
		if folder == "." && len(groups) > 1 {
			a.p("")
		}
	}
	a.p("\n  \033[2mRun one: om run <folder>/<name> [args…]\033[0m\n")
	return nil
}

func (a *App) cmdRun(root string, ns Namespace) error {
	scriptsDir, err := filepath.EvalSymlinks(filepath.Join(root, "scripts"))
	if err != nil {
		scriptsDir = filepath.Join(root, "scripts")
	}
	target := ns.Str("script")
	exts := []string{"", ".py", ".sh", ".bash", ".ps1"}
	isFile := func(p string) bool { st, err := os.Stat(p); return err == nil && st.Mode().IsRegular() }
	script := ""
	for _, e := range exts {
		if c := filepath.Join(scriptsDir, target+e); isFile(c) {
			script = c
			break
		}
	}
	if script == "" {
		want := map[string]bool{target: true}
		for e := range scripts.ScriptExts {
			want[target+e] = true
		}
		filepath.WalkDir(scriptsDir, func(p string, d fs.DirEntry, err error) error {
			if script == "" && err == nil && !d.IsDir() && want[d.Name()] && isFile(p) {
				script = p
			}
			return nil
		})
	}
	if script == "" {
		return Die("Script '%s' not found in %s. Run `om scripts`.", target, scriptsDir)
	}
	real, _ := filepath.EvalSymlinks(script)
	if rel, err := filepath.Rel(scriptsDir, real); err != nil || strings.HasPrefix(rel, "..") {
		return Die("Security violation: script path escapes the scripts directory.")
	}
	wsID, _ := workspace.WorkspaceID(root)
	env := a.wsEnv(root, wsID, a.Runtime())
	var cmd []string
	switch strings.ToLower(filepath.Ext(script)) {
	case ".py":
		py3, err := a.LookPath("python3")
		if err != nil {
			py3, err = a.LookPath("python")
		}
		if err != nil {
			return Die("This script needs python (python3 is not installed).")
		}
		cmd = []string{py3, script}
	case ".ps1":
		cmd = []string{"powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script}
	default:
		if st, _ := os.Stat(script); a.GOOS != "windows" && st != nil && st.Mode()&0o111 != 0 {
			cmd = []string{script}
		} else {
			bash, err := a.LookPath("bash")
			if err != nil {
				return Die("This script needs bash (on Windows: Git Bash or WSL).")
			}
			cmd = []string{bash, script}
		}
	}
	rel, _ := filepath.Rel(root, script)
	a.p("\033[36m▶ Running %s\033[0m\n", rel)
	return Exit(a.Passthrough(append(cmd, ns.List("args")...), root, env))
}

func (a *App) cmdAdd(root string, ns Namespace) error {
	wsID, err := a.wsID(root)
	if err != nil {
		return err
	}
	rt := a.Runtime()
	args := scaffold.AddArgs{Name: ns.Str("name"), Image: ns.Str("image"), Domain: ns.Str("domain"), Icon: ns.Str("icon"), Desc: ns.Str("desc"),
		Port: ns.Int("port"), Project: ns.Bool("project"), NoWeb: ns.Bool("no_web"), Public: ns.Bool("public")}
	if err := a.addFlagArgs(&args, ns); err != nil {
		return Die("%s", err)
	}
	if run := ns.Str("run"); run != "" {
		if ns.Str("from") != "" {
			return Die("--run and --from are two ways to bring something in; use one")
		}
		svc, err := runcmd.Parse(run)
		if err != nil {
			return Die("--run: %s", err)
		}
		tmp, err := os.MkdirTemp("", "om-run-")
		if err != nil {
			return Die("%s", err)
		}
		defer os.RemoveAll(tmp)
		if err := os.WriteFile(filepath.Join(tmp, "compose.yml"), []byte(svc.Compose()), 0o644); err != nil {
			return Die("%s", err)
		}
		if args.Name == "" {
			args.Name = svc.Name
		}
		ns["from_label"] = "your " + strings.Fields(run)[0] + " run command"
		ns["from"] = tmp
	}
	if from := ns.Str("from"); from != "" {
		if args.Image != "" || args.Project || args.NoWeb {
			return Die("--from and --run cannot be combined with --image, --project or --no-web: the compose file says what runs")
		}
		return a.cmdAddFrom(root, wsID, ns, args, from)
	}
	if ns.Bool("interactive") || args.Name == "" {
		if !a.Interactive {
			return Die("Usage: om add <name> [options]   (run `om add` in a terminal to be asked instead)")
		}
		if args, err = a.addWizard(root, wsID, args); err != nil {
			if errors.Is(err, wizard.ErrCancelled) {
				a.p("Cancelled: nothing was written.")
				return Exit(1)
			}
			return Die("%s", err)
		}
	}
	asked := ns.Bool("interactive") || ns.Str("name") == ""
	p, err := scaffold.MakePlan(args, wsID, root, func(s string) bool { _, e := os.Stat(s); return e == nil })
	if err != nil {
		return Die("%s", err)
	}
	if err := os.MkdirAll(p.Dest, 0o755); err != nil {
		return Die("%s", err)
	}
	files := scaffold.ProjectFiles(p)
	for _, f := range sortedKeys(files) {
		os.WriteFile(filepath.Join(p.Dest, f), []byte(files[f]), 0o644)
	}
	os.WriteFile(filepath.Join(p.Dest, "compose.yml"), []byte(scaffold.RenderCompose(p)), 0o644)
	a.ensureNet(wsID, rt)
	a.Syncer.SyncCaddyRoutes(root, rt, true, nil)
	badge := "\033[33m[PRIVATE]\033[0m"
	if p.Public {
		badge = "\033[36m[PUBLIC / LAN]\033[0m"
	}
	kind := "service"
	if p.IsProject {
		kind = "project"
	}
	rel, _ := filepath.Rel(root, p.Dest)
	a.p("\033[32m✓ Scaffolded %s at %s\033[0m %s", kind, rel, badge)
	if !p.NoWeb {
		a.p("  • URL:      \033[36m%s\033[0m  (and /%s/ on the dashboard host)", a.BaseURL(wsID+"."+p.Name+".localhost"), p.Name)
		a.p("  • Upstream: \033[1m%s_%s:%d\033[0m (via om_router)", wsID, p.Name, p.Port)
	}
	if cf, ok := workspace.FindComposeFile(p.Dest); ok {
		if hb, _ := workspace.HasBuild(cf); !hb {
			a.lockWorkspace(root, p.Name, false, nil) // pinned from the start; commit .om/lock.json with the service
		}
	}
	for _, sec := range p.Secrets {
		a.p("  • Secret:   set its value with  om secrets set %s/%s   (om secrets init, once per workspace)", p.Name, sec)
	}
	a.p("\n  Run '\033[1mom start %s\033[0m' to launch.", p.Name)
	if asked {
		a.p("  The same without questions:  %s", equivalentAdd(args))
	}
	return nil
}

func (a *App) cmdEdit(root string, ns Namespace) error {
	sname := strings.ToLower(py.Strip(ns.Str("service")))
	dir, err := workspace.ResolveTarget(root, sname)
	if err != nil {
		return Die("%s", err)
	}
	wsID, err := a.wsID(root)
	if err != nil {
		return err
	}
	flagged := ns.Str("scope") != "" || ns.Int("port") != 0 || ns.Str("icon") != "" || ns.Str("desc") != "" || ns.Str("name") != ""
	var set []composefix.KV
	if flagged {
		updates, err := scaffold.LabelUpdates(scaffold.EditArgs{Scope: ns.Str("scope"), Icon: ns.Str("icon"), Desc: ns.Str("desc"), Name: ns.Str("name"), Port: ns.Int("port")})
		if err != nil {
			return Die("%s", err)
		}
		for _, u := range updates {
			set = append(set, composefix.KV{Key: u.Key, Value: u.Value})
		}
	}
	for _, l := range ns.List("label") {
		k, v, ok := strings.Cut(l, "=")
		if !ok || k == "" || v == "" || !scaffold.KnownLabel(k) || !scaffold.YAMLLabelSafe(v) {
			return Die("--label %q: write it as KEY=VALUE with a label om knows (om docs labels), and a value without quotes, backslashes or line breaks", l)
		}
		set = append(set, composefix.KV{Key: k, Value: v})
	}
	unset := ns.List("unset")
	for _, k := range unset {
		if !scaffold.KnownLabel(k) {
			return Die("--unset %q: that is not a label om knows (om docs labels)", k)
		}
	}
	svc, asked := "", false
	if len(set) == 0 && len(unset) == 0 {
		if !a.Interactive {
			return Die("No edits specified. Use --scope, --port, --icon, --desc, --name, --label or --unset (or run `om edit %s` in a terminal to be asked).", sname)
		}
		asked = true
		if set, unset, svc, err = a.editInteractive(root, wsID, ns, dir, sname); err != nil {
			if errors.Is(err, wizard.ErrCancelled) {
				a.p("Cancelled: nothing was changed.")
				return Exit(1)
			}
			return Die("%s", err)
		}
		if len(set) == 0 && len(unset) == 0 {
			a.p("Nothing to change.")
			return nil
		}
		a.p("\n  Changes:")
		for _, kv := range set {
			a.p("    set    %s=%s", kv.Key, kv.Value)
		}
		for _, k := range unset {
			a.p("    clear  %s", k)
		}
		p := &wizard.Prompter{In: a.In, Out: a.Out}
		yes, err := p.Confirm("Save and apply?", true)
		if err != nil || !yes {
			a.p("Cancelled: nothing was changed.")
			return Exit(1)
		}
	}
	if err := a.applyLabelEdit(root, wsID, dir, svc, set, unset); err != nil {
		return Die("%s", err)
	}
	var kv []string
	for _, u := range set {
		kv = append(kv, u.Key+"="+u.Value)
	}
	for _, k := range unset {
		kv = append(kv, k+" cleared")
	}
	a.p("\n\033[1m⚙️  Updated %s:\033[0m %s", sname, strings.Join(kv, ", "))
	if asked {
		a.p("  The same without questions:  %s", equivalentEdit(sname, set, unset))
	}
	ok, err := a.startWorkspace(root, filepath.Base(dir), false, "edit")
	if err != nil {
		return err
	}
	if !ok {
		return Exit(1)
	}
	a.p("\033[32m✓ %s updated; routes live.\033[0m\n", sname)
	return nil
}

func (a *App) cmdInit(ns Namespace) error {
	wd, err := os.Getwd()
	if err != nil {
		return Die("%s", err)
	}
	if r, err := filepath.EvalSymlinks(wd); err == nil {
		wd = r
	}
	name := ns.Str("name")
	if name == "" {
		name = filepath.Base(wd)
	}
	name = strings.ToLower(name)
	if !workspace.IsValidWorkspaceID(name) {
		return Die("Error: invalid workspace id '%s' (allowed: lowercase letters, digits, '-'; 'core' is reserved). Pass one: om init <name>", name)
	}
	if st, err := os.Stat(filepath.Join(wd, ".om", "config.json")); err == nil && !st.IsDir() {
		a.p("\033[33mWorkspace already initialized at %s\033[0m", wd)
		return nil
	}
	reg := a.Reg.Read()
	if p, _ := reg[name]["path"].(string); p != "" {
		if _, err := os.Stat(p); err == nil {
			return Die("Workspace id '%s' is already used by %s. Choose another: om init <name>", name, p)
		}
	}
	a.p("\033[1m🚀 Initializing workspace: %s\033[0m", name)
	for _, d := range []string{"services", "projects", "scripts", "data", "docs", ".om"} {
		os.MkdirAll(filepath.Join(wd, d), 0o755)
	}
	gitops := py.NewObject()
	gitops.Set("auto_sync", false)
	gitops.Set("auto_rollback", true)
	gitops.Set("interval_seconds", 300)
	cfg := py.NewObject()
	cfg.Set("workspace_id", name)
	cfg.Set("version", state.Version)
	cfg.Set("tracked_branch", "main")
	cfg.Set("gitops", gitops)
	cfg.Set("created_at", a.Now().UTC().Format("2006-01-02T15:04:05Z"))
	if err := workspace.WriteConfig(wd, cfg); err != nil {
		return Die("%s", err)
	}
	gi := filepath.Join(wd, ".gitignore")
	if _, err := os.Stat(gi); err != nil {
		os.WriteFile(gi, []byte("data/\n.om/trash/\n.om/state.json\n.om/local.json\n*.log\n.env\n.env.local\n__pycache__/\nnode_modules/\n.DS_Store\n"), 0o644)
	}
	signers := filepath.Join(wd, filepath.FromSlash(generations.SignersName))
	if _, err := os.Stat(signers); err != nil {
		if line := a.mySignerLine(); line != "" {
			os.WriteFile(signers, []byte(line+"\n"), 0o644)
			a.p("  ✓ %s: your git signing key may deploy this workspace", generations.SignersName)
		} else {
			a.p("  \033[33m⚠ git has no SSH signing key (gpg.format=ssh, user.signingkey): deploys stay unsigned until you add one to %s\033[0m", generations.SignersName)
		}
	}
	workspace.Register(a.Reg, wd, name)
	a.ensureNet(name, a.Runtime())
	a.p("\033[32m✓ Workspace ready at %s\033[0m", wd)
	a.p("  Next: '\033[1mom add <service>\033[0m' then '\033[1mom start\033[0m'.")
	return nil
}
