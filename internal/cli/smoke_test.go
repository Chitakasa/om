package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// unlisted commands are aliases kept out of `om --help`.
var unlisted = map[string]bool{"script": true, "rm": true}

func TestEveryCommandAnswersHelpCleanly(t *testing.T) {
	a := sandboxApp(t)
	for _, c := range a.Parser.Commands {
		text := a.Parser.Help(c.Name)
		if !strings.HasPrefix(text, "usage:") || strings.Contains(text, "==") {
			t.Errorf("om %s --help:\n%s", c.Name, text)
		}
	}
	if top := a.Parser.Help(""); strings.Contains(top, "==SUPPRESS==") {
		t.Error("the command list has an internal marker")
	}
}

func TestNoArgumentLacksHelp(t *testing.T) {
	a := sandboxApp(t)
	for _, c := range a.Parser.Commands {
		if unlisted[c.Name] {
			continue
		}
		for _, g := range c.Args {
			if strings.TrimSpace(g.Help) == "" {
				t.Errorf("om %s: argument %s has no help", c.Name, strings.Join(append(g.Flags, g.Dest), " "))
			}
		}
	}
}

func TestEveryCommandIsInExactlyOneGroup(t *testing.T) {
	a := sandboxApp(t)
	seen := map[string]int{}
	for _, g := range a.Parser.Groups {
		for _, n := range g.Names {
			seen[n]++
		}
	}
	for n, c := range seen {
		if c != 1 {
			t.Errorf("%s is in %d groups", n, c)
		}
	}
	for _, c := range a.Parser.Commands {
		if !unlisted[c.Name] && seen[c.Name] == 0 {
			t.Errorf("%s is in no group", c.Name)
		}
		if unlisted[c.Name] && seen[c.Name] != 0 {
			t.Errorf("%s is unlisted but grouped", c.Name)
		}
	}
}

func TestTopLevelHelpShowsTheGroupsAndEveryCommand(t *testing.T) {
	a := sandboxApp(t)
	text := a.Parser.Help("")
	for _, g := range a.Parser.Groups {
		if !strings.Contains(text, g.Title+":") {
			t.Errorf("group %s is missing", g.Title)
		}
		for _, n := range g.Names {
			if !regexp.MustCompile(`(?m)^  ` + regexp.QuoteMeta(n) + `\s+\S`).MatchString(text) {
				t.Errorf("%s is not listed with a description", n)
			}
		}
	}
	if strings.Index(text, "Everyday:") > strings.Index(text, "Platform and upkeep:") {
		t.Error("groups are out of order")
	}
	if !strings.Contains(a.Parser.Help("start"), "usage: om start") {
		t.Error("om start --help")
	}
}

// Every command the parser accepts has a handler in Dispatch, and every handler a command (read from the source:
// calling the commands would run them).
func TestEveryParserCommandHasAHandler(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	handled := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Dispatch" {
			return true
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if cc, ok := n.(*ast.CaseClause); ok {
				for _, e := range cc.List {
					if lit, ok := e.(*ast.BasicLit); ok {
						s, _ := strconv.Unquote(lit.Value)
						handled[s] = true
					}
				}
			}
			return true
		})
		return false
	})
	delete(handled, "")
	a := sandboxApp(t)
	known := map[string]bool{}
	for _, c := range a.Parser.Commands {
		known[c.Name] = true
		for _, al := range c.Aliases {
			known[al] = true
		}
	}
	for n := range known {
		if !handled[n] && n != "status" {
			t.Errorf("command %s has no handler", n)
		}
	}
	for n := range handled {
		if !known[n] {
			t.Errorf("handler %s has no command", n)
		}
	}
}

func TestEveryCoreActionHasAFunction(t *testing.T) {
	a := sandboxApp(t)
	for _, c := range a.Parser.Commands {
		if c.Name != "core" {
			continue
		}
		for _, g := range c.Args {
			if g.Dest == "action" {
				want := []string{"start", "stop", "restart", "update", "reload", "watch", "heal", "status"}
				got := append([]string(nil), g.Choices...)
				sort.Strings(got)
				sort.Strings(want)
				if strings.Join(got, ",") != strings.Join(want, ",") {
					t.Errorf("core actions %v, handled %v", got, want)
				}
			}
		}
	}
}

// ---- hostile settings: a validator refuses, never crashes, and nothing accepted writes a second line ----

func TestAnAcceptedSettingIsOneCleanLine(t *testing.T) {
	r := rand.New(rand.NewPCG(20261121, 5))
	good := map[string]string{"OM_HTTP_PORT": "8080", "OM_POLICY": "warn", "OM_NOTIFY_URL": "https://ntfy.sh/topic", "OM_WALLPAPERS_DIR": "~/Pictures",
		"OM_TRUSTED_USERS": "alice", "OM_FIREWALL_EXTRA_TCP": "22,1714-1764", "OM_LAN_IP": "192.168.1.5", "OM_NOTIFY": "desktop"}
	keys := sortedKeys(configSchema)
	atoms := []string{"a", "0", "\n", "\r", "\t", "\x00", "\x1b", "OM_POLICY=warn", ",", "/", ":", "https://", "ntfy.sh/", "10.0.0.1", " "}
	control := regexp.MustCompile(`[\x00-\x1f\x7f]`)
	for i := 0; i < 2500; i++ {
		key := keys[r.IntN(len(keys))]
		var value string
		if r.Float64() < 0.5 {
			g := good[key]
			if g == "" {
				g = "x"
			}
			at := r.IntN(len(g) + 1)
			value = g[:at] + atoms[r.IntN(len(atoms))] + g[at:]
		} else {
			for n := 1 + r.IntN(9); n > 0; n-- {
				value += atoms[r.IntN(len(atoms))]
			}
		}
		if why := checkValue(key, value); why == "" && control.MatchString(value) {
			t.Fatalf("%s=%q was accepted but would write more than one line to om.env", key, value)
		}
	}
}

func TestASettingCannotSmuggleInASecondLine(t *testing.T) {
	for _, c := range [][2]string{{"OM_WALLPAPERS_DIR", "a\nOM_POLICY=warn"}, {"OM_NOTIFY_URL", "https://ntfy.sh/x\nOM_POLICY=warn"}} {
		if checkValue(c[0], c[1]) == "" {
			t.Errorf("%s accepted %q", c[0], c[1])
		}
	}
}

// ---- the tracked branch in the workspace config is validated ----

func TestTheTrackedBranchInTheWorkspaceConfigIsValidated(t *testing.T) {
	a := sandboxApp(t)
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, ".om"), 0o755)
	for value, want := range map[string]string{"--upload-pack=evil": "main", "-x": "main", "feat/ok": "feat/ok", "a b": "main", "a\\nb": "main"} {
		os.WriteFile(filepath.Join(root, ".om", "config.json"), []byte(`{"tracked_branch": "`+value+`"}`), 0o644)
		if got := a.trackedBranch(root); got != want {
			t.Errorf("tracked_branch %q -> %q, want %q", value, got, want)
		}
	}
}
