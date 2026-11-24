package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Chitakasa/om/internal/composefix"
	"github.com/Chitakasa/om/internal/scaffold"
	"github.com/Chitakasa/om/internal/wizard"
	"github.com/Chitakasa/om/internal/workspace"
)

// managedLabels are the labels the interactive edit asks about; the ones it clears when you answer "none".
var managedLabels = []string{"dashboard.scope", "dashboard.icon", "dashboard.description", "om.net.allow", "om.egress", "om.mem", "om.cpus", "om.update", "om.log"}

// setLabels changes one service's labels in the project's files (set replaces, unset removes), whatever layout the
// file uses: flow style, anchors and merge keys are rewritten so the service carries its own labels.
func (p *project) setLabels(cfg map[string]any, svc string, set []composefix.KV, unset []string) (map[string]string, error) {
	docs := map[string]*composefix.Doc{}
	owner := ""
	for _, f := range p.files {
		d, err := composefix.Parse(p.orig[f])
		if err != nil {
			continue
		}
		docs[f] = d
		for _, s := range d.Services() {
			if s == svc {
				owner = f
			}
		}
	}
	doc := docs[owner]
	if doc == nil {
		return nil, fmt.Errorf("service %s was not found in the compose files", svc)
	}
	inh, err := doc.Inherits(svc)
	if err != nil {
		return nil, err
	}
	if inh.Alias {
		if err := doc.ExpandAlias(svc); err != nil {
			return nil, err
		}
		inh.Merge = true
	}
	if _, err := doc.Blockify(svc); err != nil {
		return nil, err
	}
	if inh.Merge && !doc.HasField(svc, "labels") || contains(inh.AliasFields, "labels") {
		if cfg == nil {
			return nil, errors.New("its labels come from an alias or merge key, which needs the compose engine to resolve")
		}
		if err := doc.ReplaceLabels(svc, cfgLabels(cfgServices(cfg)[svc])); err != nil {
			return nil, err
		}
	}
	if err := doc.RemoveLabels(svc, unset); err != nil {
		return nil, err
	}
	if err := doc.AddLabels(svc, set, true); err != nil {
		return nil, err
	}
	texts := map[string]string{}
	for f, t := range p.orig {
		texts[f] = t
	}
	texts[owner] = doc.String()
	return texts, nil
}

// labelCarrier is the service that holds a folder's dashboard labels: the one that already has them, else the first.
func labelCarrier(cfg map[string]any, order []string) string {
	resolved := cfgServices(cfg)
	for _, key := range []string{"dashboard.port", "dashboard.name", "workspace.id"} {
		for _, s := range order {
			if _, ok := cfgLabelMap(resolved[s])[key]; ok {
				return s
			}
		}
	}
	if len(order) > 0 {
		return order[0]
	}
	return ""
}

// editAnswers reads the current labels back into the wizard's answers.
func editAnswers(labels map[string]string) (scaffold.AddArgs, addAnswers) {
	args := scaffold.AddArgs{Public: labels["dashboard.scope"] == "public", Icon: labels["dashboard.icon"], Desc: labels["dashboard.description"]}
	w := addAnswers{kind: "web", allow: labels["om.net.allow"], egress: labels["om.egress"], mem: labels["om.mem"], cpus: labels["om.cpus"],
		update: labels["om.update"], logOff: labels["om.log"] == "off", waive: labels["om.policy.allow"]}
	return args, w
}

// editChanges compares the answers with the labels the service had: what to set and what to clear.
func editChanges(old map[string]string, args scaffold.AddArgs, w addAnswers) (set []composefix.KV, unset []string) {
	want := map[string]string{"dashboard.scope": pick(args.Public, "public", "private"), "dashboard.icon": args.Icon, "dashboard.description": args.Desc,
		"om.net.allow": w.allow, "om.egress": w.egress, "om.mem": w.mem, "om.cpus": w.cpus, "om.update": w.update, "om.log": pick(w.logOff, "off", "")}
	for _, k := range managedLabels {
		switch cur, had := old[k]; {
		case want[k] != "" && want[k] != cur:
			set = append(set, composefix.KV{Key: k, Value: want[k]})
		case want[k] == "" && had:
			unset = append(unset, k)
		}
	}
	return set, unset
}

func equivalentEdit(name string, set []composefix.KV, unset []string) string {
	parts := []string{"om", "edit", shellQuote(name)}
	for _, kv := range set {
		parts = append(parts, "--label", shellQuote(kv.Key+"="+kv.Value))
	}
	for _, k := range unset {
		parts = append(parts, "--unset", shellQuote(k))
	}
	return strings.Join(parts, " ")
}

func (a *App) editInteractive(root, wsID string, ns Namespace, dir, name string) (set []composefix.KV, unset []string, svc string, err error) {
	rt := a.Runtime()
	cf, _ := workspace.FindComposeFile(dir)
	proj, err := loadProject(dir, cf)
	if err != nil {
		return nil, nil, "", err
	}
	res := a.composeConfig(rt, cf, a.wsEnv(root, wsID, rt))
	if res.cfg == nil {
		return nil, nil, "", fmt.Errorf("the compose file cannot be read by the engine, so its settings cannot be shown: %s", firstLine(res.err))
	}
	var order []string
	for _, f := range proj.files {
		if d, e := composefix.Parse(proj.orig[f]); e == nil {
			order = append(order, d.Services()...)
		}
	}
	resolved := cfgServices(res.cfg)
	svc = labelCarrier(res.cfg, order)
	p := &wizard.Prompter{In: a.In, Out: a.Out}
	a.p("\033[1mEdit %s\033[0m  (Enter keeps what is shown; Ctrl-D cancels; nothing is written until you confirm)", name)
	if len(order) > 1 {
		opts := make([]wizard.Option, len(order))
		def := 0
		for i, s := range order {
			opts[i] = wizard.Option{Label: s, Hint: fmt.Sprintf("%d labels", len(cfgLabelMap(resolved[s])))}
			if s == svc {
				def = i
			}
		}
		i, err := p.Choose("\nWhich service?", opts, def)
		if err != nil {
			return nil, nil, "", err
		}
		svc = order[i]
	}
	old := cfgLabelMap(resolved[svc])
	args, w := editAnswers(old)
	args.Name = name
	a.p("\n\033[1mNow\033[0m")
	a.summaryChoices(args, w)
	if err := a.addCustomise(p, &args, &w, false); err != nil {
		return nil, nil, "", err
	}
	set, unset = editChanges(old, args, w)
	return set, unset, svc, nil
}

// applyLabelEdit writes the change to the service's compose files, checks with the engine that nothing but those
// labels changed, and puts the files back if it did.
func (a *App) applyLabelEdit(root, wsID, dir, svc string, set []composefix.KV, unset []string) error {
	rt := a.Runtime()
	cf, _ := workspace.FindComposeFile(dir)
	proj, err := loadProject(dir, cf)
	if err != nil {
		return err
	}
	env := a.wsEnv(root, wsID, rt)
	before := a.composeConfig(rt, cf, env)
	if svc == "" {
		var order []string
		for _, f := range proj.files {
			if d, e := composefix.Parse(proj.orig[f]); e == nil {
				order = append(order, d.Services()...)
			}
		}
		svc = labelCarrier(before.cfg, order)
	}
	texts, err := proj.setLabels(before.cfg, svc, set, unset)
	if err != nil {
		return err
	}
	write := func(t map[string]string) error {
		for f, text := range t {
			if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(f)), []byte(text), 0o644); err != nil {
				return err
			}
		}
		return nil
	}
	if err := write(texts); err != nil {
		return err
	}
	if before.cfg != nil {
		after := a.composeConfig(rt, cf, env)
		if after.cfg == nil {
			write(proj.orig)
			return fmt.Errorf("the edited file no longer loads, so it was put back: %s", firstLine(after.err))
		}
		if bad := verifyEdit(before.cfg, after.cfg, set, unset); len(bad) > 0 {
			write(proj.orig)
			sort.Strings(bad)
			return fmt.Errorf("the engine reads the edited file differently from what was asked, so it was put back:\n    - %s", strings.Join(bad, "\n    - "))
		}
	}
	return nil
}

// verifyEdit is verifyImport for an edit: only the named labels may differ.
func verifyEdit(before, after map[string]any, set []composefix.KV, unset []string) []string {
	var bad []string
	b, a := cfgServices(before), cfgServices(after)
	touched := map[string]bool{}
	for _, kv := range set {
		touched[kv.Key] = true
	}
	for _, k := range unset {
		touched[k] = true
	}
	for name, sb := range b {
		sa, ok := a[name]
		if !ok {
			bad = append(bad, name+": the service is missing after the edit")
			continue
		}
		for k := range sb {
			if k != "labels" && fmt.Sprint(sb[k]) != fmt.Sprint(sa[k]) {
				bad = append(bad, fmt.Sprintf("%s: %s changed", name, k))
			}
		}
		lb, la := cfgLabelMap(sb), cfgLabelMap(sa)
		for k, v := range lb {
			if la[k] != v && !touched[k] {
				bad = append(bad, fmt.Sprintf("%s: label %s changed", name, k))
			}
		}
		for k := range la {
			if _, had := lb[k]; !had && !touched[k] {
				bad = append(bad, fmt.Sprintf("%s: label %s appeared", name, k))
			}
		}
	}
	return bad
}
