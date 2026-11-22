package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Chitakasa/om/internal/scaffold"
	"github.com/Chitakasa/om/internal/settings"
)

// The reference docs (docs/COMMANDS.md, SETTINGS.md, LABELS.md, DOCTOR.md) are generated from the code so they
// cannot go stale: TestReferenceDocs fails when a file differs from RenderReference, and
// `go test ./internal/cli -run TestReferenceDocs -update` rewrites them.

const refNotice = "<!-- Generated from the code (internal/cli/refdocs.go): do not edit. Run `go test ./internal/cli -run TestReferenceDocs -update` after a change. -->\n"

// RenderReference returns the four generated docs by path relative to the repository.
func RenderReference(a *App) map[string]string {
	return map[string]string{"docs/COMMANDS.md": a.commandsMD(), "docs/SETTINGS.md": a.settingsMD(),
		"docs/LABELS.md": labelsMD(), "docs/DOCTOR.md": a.doctorMD()}
}

// neutral shows a path of this machine as its default location, so the files are the same everywhere.
func (a *App) neutral(text string) string {
	for _, p := range [][2]string{{a.D.State, "~/.local/state/om"}, {a.D.UserEnv, "~/.config/om/om.env"}, {a.D.Home, "~/.om"}} {
		text = strings.ReplaceAll(text, p[0], p[1])
	}
	return text
}

func (a *App) cell(text string) string {
	t := strings.Join(strings.Fields(strings.ReplaceAll(a.neutral(text), "%%", "%")), " ")
	return strings.ReplaceAll(t, "|", `\|`)
}

func refFlag(g Arg) string {
	for _, f := range g.Flags {
		if strings.HasPrefix(f, "--") {
			return f
		}
	}
	return g.Flags[0]
}

func metavar(g Arg) string {
	if g.Metavar != "" {
		return g.Metavar
	}
	return g.Dest
}

func refUsage(c *Command) string {
	parts := []string{"om", c.Name}
	for _, g := range c.Args {
		switch {
		case g.isOption() && !g.takesValue():
			parts = append(parts, "["+refFlag(g)+"]")
		case g.isOption():
			parts = append(parts, "["+refFlag(g)+" "+strings.ToUpper(metavar(g))+"]")
		case g.Nargs == "...":
			parts = append(parts, "["+metavar(g)+"…]")
		case g.Nargs == "?" || g.Nargs == "*":
			parts = append(parts, "["+metavar(g)+"]")
		default:
			parts = append(parts, "<"+metavar(g)+">")
		}
	}
	return strings.Join(parts, " ")
}

func (a *App) argumentRows(c *Command) [][2]string {
	var rows [][2]string
	for _, g := range c.Args {
		label := metavar(g)
		if g.isOption() {
			label = strings.Join(g.Flags, ", ")
			if g.takesValue() {
				label += " " + strings.ToUpper(metavar(g))
			}
		}
		note := a.cell(g.Help)
		if len(g.Choices) > 0 {
			note += " One of: " + strings.Join(g.Choices, ", ") + "."
		}
		if g.isOption() && g.Default != nil && g.Default != false && g.Default != 0 { // like Python, 0 counts as False
			note += fmt.Sprintf(" Default: %v.", g.Default)
		}
		rows = append(rows, [2]string{label, strings.TrimSpace(note)})
	}
	return rows
}

func (a *App) commandsMD() string {
	byName := map[string]*Command{}
	for _, c := range a.Parser.Commands {
		byName[c.Name] = c
	}
	var b strings.Builder
	b.WriteString(refNotice + "# Commands\n\n")
	b.WriteString("Every `om` command, grouped as in `om --help`. A workspace command needs a folder with `.om/config.json` " +
		"(`om init` makes one); the others work anywhere. New to om? Start with [START.md](START.md); for how to do a task, see [GUIDE.md](GUIDE.md).\n")
	for _, g := range a.Parser.Groups {
		fmt.Fprintf(&b, "\n## %s\n", g.Title)
		for _, name := range g.Names {
			c := byName[name]
			fmt.Fprintf(&b, "\n### `om %s`\n\n", name)
			b.WriteString(a.cell(c.Help))
			if len(c.Aliases) > 0 {
				var al []string
				for _, x := range c.Aliases {
					al = append(al, "`om "+x+"`")
				}
				b.WriteString(" (alias: " + strings.Join(al, ", ") + ")")
			}
			b.WriteString("\n")
			fmt.Fprintf(&b, "\n```text\n%s\n```\n", refUsage(c))
			if c.Description != "" {
				fmt.Fprintf(&b, "\n```text\n%s\n```\n", strings.TrimRight(c.Description, " \t\r\n"))
			}
			if rows := a.argumentRows(c); len(rows) > 0 {
				b.WriteString("\n| Argument | Meaning |\n| :--- | :--- |\n")
				for _, r := range rows {
					fmt.Fprintf(&b, "| `%s` | %s |\n", r[0], r[1])
				}
			}
		}
	}
	return b.String()
}

func (a *App) settingsMD() string {
	defaults := settings.ParseText(settings.UserEnvTemplate)
	var b strings.Builder
	b.WriteString(refNotice + "# Settings\n\n")
	b.WriteString("Machine settings live in `~/.config/om/om.env` (`$OM_CONFIG_DIR/om.env`), one `KEY=value` per line, written " +
		"readable by you only. Read and change them with `om config show`, `om config set KEY=value` and " +
		"`om config unset KEY`: every value is checked, and `OM_NOTIFY_URL` is shown as `***` unless you ask. " +
		"`auto` means \"detect it\"; `off` means \"switch it off\". Most changes take effect after the command named " +
		"under *Then run*.\n")
	keys := make([]string, 0, len(settingAbout))
	for k := range settingAbout {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		accepts, about := settingAbout[key][0], settingAbout[key][1]
		shown := "(empty)"
		if d := defaults[key]; d != "" {
			shown = "`" + d + "`"
		}
		fmt.Fprintf(&b, "\n## `%s`\n\n%s\n\n- **Default:** %s\n- **Accepts:** %s\n", key, about, shown, accepts)
		if own, ok := ownCommand[key]; ok {
			fmt.Fprintf(&b, "- **Change it with:** `%s` (it also updates the firewall)\n", own)
		} else {
			fmt.Fprintf(&b, "- **Change it with:** `om config set %s=<value>`\n", key)
			if then := configSchema[key].then; then != "" {
				fmt.Fprintf(&b, "- **Then run:** `%s`\n", then)
			}
		}
	}
	return b.String()
}

func labelsMD() string {
	cell := func(s string) string {
		return strings.ReplaceAll(strings.Join(strings.Fields(strings.ReplaceAll(s, "%%", "%")), " "), "|", `\|`)
	}
	var b strings.Builder
	b.WriteString(refNotice + "# Labels\n\n")
	b.WriteString("Labels are how a service tells om what it needs. They go in the service's `compose.yml`, under `labels:`, as " +
		"a list (`- \"om.log=off\"`) or a map (`om.log: off`). `om add` writes the first table and offers every label " +
		"in the second as a commented menu, so you uncomment what you need and run `om start`. `om edit` changes the " +
		"dashboard ones for you.\n")
	b.WriteString("\n## Set by `om add`\n\n| Label | Example | What it does |\n| :--- | :--- | :--- |\n")
	for _, l := range scaffold.ActiveLabels {
		fmt.Fprintf(&b, "| `%s` | `%s` | %s |\n", l.Name, cell(l.Example), cell(l.Note))
	}
	for _, g := range scaffold.LabelMenu {
		fmt.Fprintf(&b, "\n## %s\n\n| Label | Example | What it does |\n| :--- | :--- | :--- |\n", g.Name)
		for _, l := range g.Items {
			fmt.Fprintf(&b, "| `%s` | `%s` | %s |\n", l.Name, cell(l.Example), cell(l.Note))
		}
	}
	return b.String()
}

func (a *App) doctorMD() string {
	type stage struct {
		title, blurb string
		checks       []docCheck
	}
	stages := []stage{
		{"Basics", "Always run. If these fail, the perimeter checks are skipped.", a.docBasic()},
		{"Perimeter", "Need a running core; they attack the setup the way an outsider or a compromised container would.", a.docPerimeter()},
		{"This machine", "Always run.", a.docHost()},
	}
	total := 0
	for _, s := range stages {
		total += len(s.checks)
	}
	var b strings.Builder
	b.WriteString(refNotice + "# What `om doctor` checks\n\n")
	fmt.Fprintf(&b, "`om doctor` runs %d checks and prints one line each: **PASS**, **WARN** (works, but look at it) or **FAIL** "+
		"(fix it; the line says how). It exits 1 when any check fails, and `om doctor --json` prints the same results for "+
		"scripts. Run it after any change to the network or the core. For symptoms and their fixes, see "+
		"[TROUBLESHOOTING.md](TROUBLESHOOTING.md).\n", total)
	for _, s := range stages {
		fmt.Fprintf(&b, "\n## %s\n\n%s\n", s.title, s.blurb)
		for _, c := range s.checks {
			fmt.Fprintf(&b, "\n### %s\n\n%s\n", c.title, doctorDocs[c.title])
		}
	}
	return b.String()
}
