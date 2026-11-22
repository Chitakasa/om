// Package repocheck holds the tests that keep the repository's own files honest: the docs against the code, the CI
// workflow's supply-chain hygiene, the package layering and the installers. It has no code, only tests.
package repocheck

import (
	"go/parser"
	"go/token"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/Chitakasa/om/internal/cli"
	"github.com/Chitakasa/om/internal/dashboard"
	"github.com/Chitakasa/om/internal/scaffold"
	"github.com/Chitakasa/om/internal/settings"
	"github.com/Chitakasa/om/internal/state"
)

func root(t testing.TB) string {
	t.Helper()
	dir, _ := os.Getwd()
	for d := dir; d != filepath.Dir(d); d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
	}
	t.Fatal("no go.mod above " + dir)
	return ""
}

func read(t testing.TB, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root(t), rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func docFiles(t testing.TB) []string {
	r := root(t)
	files := []string{"README.md", "CONTRIBUTING.md", "SECURITY.md", "CODE_OF_CONDUCT.md", "CHANGELOG.md"}
	var out []string
	for _, f := range files {
		if _, err := os.Stat(filepath.Join(r, f)); err == nil {
			out = append(out, f)
		}
	}
	filepath.Walk(filepath.Join(r, "docs"), func(p string, info os.FileInfo, err error) error {
		if err == nil && strings.HasSuffix(p, ".md") {
			rel, _ := filepath.Rel(r, p)
			out = append(out, rel)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

// ---- docs links ----

var (
	linkRE    = regexp.MustCompile(`(?:^|[^!])\[[^\]]*\]\(([^)\s]+)\)`)
	fenceRE   = regexp.MustCompile("(?s)```.*?```")
	headingRE = regexp.MustCompile(`^#{1,6}\s+(.*?)\s*#*\s*$`)
	schemeRE  = regexp.MustCompile(`^[a-z][a-z0-9+.-]*:`)
	mdLinkRE  = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`)
	codeRE    = regexp.MustCompile("`([^`]*)`")
)

// slug is GitHub's anchor for a heading: lowercase, keep letters, marks, numbers, `_`, `-` and spaces; spaces become `-`.
func slug(h string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(strings.TrimSpace(h)) {
		switch {
		case c == ' ' || c == '-' || c == '_':
			b.WriteRune(c)
		case unicode.IsLetter(c) || unicode.IsMark(c) || unicode.IsNumber(c):
			b.WriteRune(c)
		}
	}
	return strings.ReplaceAll(b.String(), " ", "-")
}

func anchors(text string) map[string]bool {
	out, seen, inCode := map[string]bool{}, map[string]int{}, false
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "```") {
			inCode = !inCode
		}
		if inCode {
			continue
		}
		if m := headingRE.FindStringSubmatch(line); m != nil {
			base := slug(codeRE.ReplaceAllString(mdLinkRE.ReplaceAllString(m[1], "$1"), "$1"))
			n := seen[base]
			seen[base]++
			if n == 0 {
				out[base] = true
			} else {
				out[base+"-"+strconv.Itoa(n)] = true
			}
		}
	}
	return out
}

func TestEveryRelativeDocLinkAndAnchorResolves(t *testing.T) {
	r := root(t)
	var bad []string
	for _, rel := range docFiles(t) {
		path := filepath.Join(r, rel)
		text := fenceRE.ReplaceAllString(read(t, rel), "")
		for _, m := range linkRE.FindAllStringSubmatch(text, -1) {
			target := m[1]
			if schemeRE.MatchString(target) {
				continue
			}
			name, frag, _ := strings.Cut(target, "#")
			dest := path
			if name != "" {
				n, _ := url.PathUnescape(name)
				dest = filepath.Join(filepath.Dir(path), n)
			}
			st, err := os.Stat(dest)
			if err != nil {
				bad = append(bad, rel+": "+target+" (no such file)")
				continue
			}
			if f, _ := url.PathUnescape(frag); frag != "" && !st.IsDir() && strings.HasSuffix(dest, ".md") {
				b, _ := os.ReadFile(dest)
				if !anchors(string(b))[strings.ToLower(f)] {
					bad = append(bad, rel+": "+target+" (no such heading)")
				}
			}
		}
	}
	if len(bad) > 0 {
		t.Errorf("broken links:\n  %s", strings.Join(bad, "\n  "))
	}
}

func TestTheAnchorRuleMatchesGitHub(t *testing.T) {
	if got := slug("🖥️ Supported Platforms"); got != "️-supported-platforms" {
		t.Errorf("%q", got)
	}
	if got := slug("Tier 1 — Private (container ports)"); got != "tier-1--private-container-ports" {
		t.Errorf("%q", got)
	}
}

// ---- docs match code ----

func TestDoctorCheckCountIsTheOneInTheDocs(t *testing.T) {
	m := regexp.MustCompile(`runs (\d+) checks`).FindStringSubmatch(read(t, "docs/DOCTOR.md"))
	if m == nil {
		t.Fatal("docs/DOCTOR.md names no check count")
	}
	for _, name := range []string{"README.md", "docs/ARCHITECTURE.md"} {
		counts := map[string]bool{}
		for _, c := range regexp.MustCompile(`\((\d+) checks\)`).FindAllStringSubmatch(read(t, name), -1) {
			counts[c[1]] = true
		}
		if len(counts) != 1 || !counts[m[1]] {
			t.Errorf("%s names doctor check counts %v, the code has %s", name, counts, m[1])
		}
	}
}

func TestTheChangelogHasAnEntryForTheCurrentVersion(t *testing.T) {
	log := read(t, "CHANGELOG.md")
	if !regexp.MustCompile(`(?m)^## ` + regexp.QuoteMeta(state.Version) + `\b`).MatchString(log) {
		t.Errorf("no `## %s` entry for state.Version", state.Version)
	}
	first := regexp.MustCompile(`(?m)^## (.+)$`).FindStringSubmatch(log)[1]
	if first != "Unreleased" && !strings.HasPrefix(first, state.Version) {
		t.Errorf("the newest entry is `%s`", first)
	}
}

func TestEveryEverydayCommandIsInTheReadme(t *testing.T) {
	readme := read(t, "README.md")
	if !strings.Contains(readme, "docs/COMMANDS.md") {
		t.Error("README does not link docs/COMMANDS.md")
	}
	p := cli.NewParser(state.Version, state.NewDirs())
	for _, g := range p.Groups {
		if g.Title != "Everyday" {
			continue
		}
		for _, name := range g.Names {
			if !regexp.MustCompile(`om ` + name + `\b`).MatchString(readme) {
				t.Errorf("README does not mention `om %s`", name)
			}
		}
	}
}

func TestEverySettingIsInTheArchitectureDoc(t *testing.T) {
	arch := read(t, "docs/ARCHITECTURE.md")
	for _, m := range regexp.MustCompile(`(?m)^(OM_[A-Z_]+)=`).FindAllStringSubmatch(settings.UserEnvTemplate, -1) {
		if !strings.Contains(arch, m[1]) {
			t.Errorf("%s is not in docs/ARCHITECTURE.md", m[1])
		}
	}
}

func TestEveryDashboardRouteIsInTheArchitectureDoc(t *testing.T) {
	arch := read(t, "docs/ARCHITECTURE.md")
	for _, p := range append(append([]string{}, dashboard.GetRoutes...), dashboard.PostRoutes...) {
		if !strings.Contains(arch, p) {
			t.Errorf("%s is not in docs/ARCHITECTURE.md", p)
		}
	}
}

func TestEveryPackageIsInClaudeMd(t *testing.T) {
	ents, _ := os.ReadDir(filepath.Join(root(t), "internal"))
	doc := read(t, "CLAUDE.md")
	for _, e := range ents {
		if e.IsDir() && !strings.Contains(doc, "internal/"+e.Name()) && !strings.Contains(doc, "`"+e.Name()+"`") {
			t.Errorf("CLAUDE.md does not name the package internal/%s (as `%s` or internal/%s)", e.Name(), e.Name(), e.Name())
		}
	}
}

// the labels a user puts on a service (the others are om's own bookkeeping labels on networks, or file names)
var userLabels = []string{"om.egress", "om.egress.learn_ttl", "om.egress.jvm", "om.net.allow", "om.net.deny", "om.link", "om.link.allow",
	"om.log", "om.mem", "om.pids", "om.cpus", "om.update", "om.tcp", "om.tcp.port", "om.policy.allow", "om.network",
	"om.route.keep_prefix", "om.route.aliases", "om.route.dashboard_paths", "dashboard.port", "dashboard.scope",
	"dashboard.url", "dashboard.search_url", "workspace.category"}

func allDocs(t testing.TB) string {
	var b strings.Builder
	for _, rel := range append(docFiles(t), "CLAUDE.md") {
		b.WriteString(read(t, rel))
	}
	return b.String()
}

func TestUserLabelsAreDocumentedAndOfferedByTheScaffold(t *testing.T) {
	all := allDocs(t)
	for _, l := range userLabels {
		if !strings.Contains(all, l) {
			t.Errorf("label %s is in no doc", l)
		}
	}
	for _, g := range scaffold.LabelMenu {
		for _, l := range g.Items {
			if !strings.Contains(all, l.Name) {
				t.Errorf("scaffold menu label %s is in no doc", l.Name)
			}
		}
	}
	text := scaffold.RenderCompose(scaffold.Plan{WSID: "w", Name: "svc", Port: 8080, Image: "x", Icon: "i", Desc: "d", Domain: "svc.w.localhost"})
	for _, l := range userLabels {
		if !strings.Contains(text, `"`+l+`=`) {
			t.Errorf("`om add` does not offer %s", l)
		}
	}
}

func TestCoreImagesAreDigestPinned(t *testing.T) {
	compose := read(t, "core/compose.yml")
	for _, m := range regexp.MustCompile(`image: (docker\.io/\S+)`).FindAllStringSubmatch(compose, -1) {
		if !regexp.MustCompile(`:\S+@sha256:[0-9a-f]{64}$`).MatchString(m[1]) {
			t.Errorf("%s is not pinned by digest", m[1])
		}
	}
	if regexp.MustCompile(`image: \S+:latest`).MatchString(compose) {
		t.Error("an image uses :latest")
	}
	for _, f := range []string{"core/egress/Containerfile", "core/tools/Containerfile"} {
		for _, line := range strings.Split(read(t, f), "\n") {
			if strings.HasPrefix(line, "FROM ") && !strings.Contains(line, "@sha256:") {
				t.Errorf("%s: %q is not pinned by digest", f, line)
			}
		}
	}
}

// ---- CI hygiene ----

func workflows(t testing.TB) map[string]string {
	files, _ := filepath.Glob(filepath.Join(root(t), ".github", "workflows", "*.yml"))
	if len(files) == 0 {
		t.Fatal("no workflows")
	}
	out := map[string]string{}
	for _, f := range files {
		b, _ := os.ReadFile(f)
		out[filepath.Base(f)] = string(b)
	}
	return out
}

func jobs(wf string) map[string]string {
	_, body, _ := strings.Cut(wf, "\njobs:\n")
	out, name := map[string]string{}, ""
	jobRE := regexp.MustCompile(`^  ([a-z0-9-]+):\s*$`)
	for _, line := range strings.Split(body, "\n") {
		if m := jobRE.FindStringSubmatch(line); m != nil {
			name = m[1]
			out[name] = ""
		} else if name != "" {
			out[name] += line + "\n"
		}
	}
	return out
}

func TestEveryActionIsPinnedToACommitSHAWithItsVersion(t *testing.T) {
	use := regexp.MustCompile(`(?m)^\s*-?\s*uses:\s*(\S+)(.*)$`)
	pin := regexp.MustCompile(`^[\w.-]+/[\w./-]+@[0-9a-f]{40}$`)
	n := 0
	for name, wf := range workflows(t) {
		for _, m := range use.FindAllStringSubmatch(wf, -1) {
			n++
			if !pin.MatchString(m[1]) {
				t.Errorf("%s: %s is not pinned to a full commit SHA", name, m[1])
			}
			if !regexp.MustCompile(`#\s*v\d`).MatchString(m[2]) {
				t.Errorf("%s: %s has no version comment (Dependabot and readers need it)", name, m[1])
			}
		}
	}
	if n == 0 {
		t.Error("no actions found")
	}
}

func TestTheTokenIsReadOnlyAndCheckoutsKeepNoCredentials(t *testing.T) {
	for name, wf := range workflows(t) {
		if !regexp.MustCompile(`(?m)^permissions:\n  contents: (read|write)\n`).MatchString(wf) {
			t.Errorf("%s has no top-level permissions", name)
		}
		if name == "ci.yml" && strings.Contains(wf, "contents: write") {
			t.Error("ci.yml may not write to the repository")
		}
		if strings.Count(wf, "persist-credentials: false") != strings.Count(wf, "actions/checkout@") {
			t.Errorf("%s: a checkout keeps its credentials", name)
		}
	}
}

func TestEveryJobHasATimeoutAndSecretsAreScanned(t *testing.T) {
	for name, wf := range workflows(t) {
		for job, block := range jobs(wf) {
			if !strings.Contains(block, "timeout-minutes:") {
				t.Errorf("%s: job %s has no timeout", name, job)
			}
		}
	}
	if !strings.Contains(jobs(workflows(t)["ci.yml"])["secrets"], "gitleaks") {
		t.Error("ci.yml does not scan for secrets")
	}
}

func TestTheCoverageFloorIsEnforced(t *testing.T) {
	ci := workflows(t)["ci.yml"]
	if !regexp.MustCompile(`COVER_FLOOR: \d+`).MatchString(ci) || !strings.Contains(ci, "go test -race") || !strings.Contains(ci, "-coverprofile") {
		t.Error("ci.yml does not run `go test -race -coverprofile` against a COVER_FLOOR")
	}
}

func TestDependabotKeepsActionsAndModulesCurrent(t *testing.T) {
	text := read(t, ".github/dependabot.yml")
	for _, eco := range []string{"github-actions", "gomod"} {
		if !strings.Contains(text, "package-ecosystem: "+eco) {
			t.Errorf("dependabot does not watch %s", eco)
		}
	}
}

// ---- layering ----

// internalImports lists the internal packages a package's non-test files import.
func internalImports(t testing.TB, dir string) map[string]bool {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, p := range pkgs {
		for _, f := range p.Files {
			for _, imp := range f.Imports {
				path, _ := strconv.Unquote(imp.Path.Value)
				if rest, ok := strings.CutPrefix(path, "github.com/Chitakasa/om/internal/"); ok {
					out[strings.Split(rest, "/")[0]] = true
				}
			}
		}
	}
	return out
}

// mayImport: the packages each package may use. A package not listed may use anything below the command layer.
// The base packages use nothing; the command layer (cli) and the programs that run in containers (dashboard, probe)
// are never imported by a library.
var mayImport = map[string]map[string]bool{
	"py":        {},
	"state":     {"py": true},
	"labels":    {"py": true, "state": true},
	"dashboard": {"py": true},
	"probe":     {},
}

var commandLayer = map[string]bool{"cli": true, "dashboard": true, "probe": true, "repocheck": true}

func TestPackagesImportOnlyDownward(t *testing.T) {
	r := root(t)
	ents, _ := os.ReadDir(filepath.Join(r, "internal"))
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		got := internalImports(t, filepath.Join(r, "internal", e.Name()))
		if allowed, ok := mayImport[e.Name()]; ok {
			for imp := range got {
				if !allowed[imp] {
					t.Errorf("internal/%s imports internal/%s", e.Name(), imp)
				}
			}
		}
		if !commandLayer[e.Name()] {
			for imp := range got {
				if commandLayer[imp] {
					t.Errorf("library internal/%s imports the command layer internal/%s", e.Name(), imp)
				}
			}
		}
	}
}

// ---- installers ----

func TestInstallersCallOnlyCommandsThatExist(t *testing.T) {
	p := cli.NewParser(state.Version, state.NewDirs())
	known := map[string]bool{}
	for _, c := range p.Commands {
		known[c.Name] = true
		for _, a := range c.Aliases {
			known[a] = true
		}
	}
	checked := 0
	for _, name := range []string{"install.sh", "install.ps1"} {
		text := read(t, name)
		for _, m := range regexp.MustCompile(`(?m)(?:"\$WRAPPER"|"\$OM_BIN"|& \$omBin) ([a-z][a-z-]+)`).FindAllStringSubmatch(text, -1) {
			checked++
			if !known[m[1]] {
				t.Errorf("%s runs `om %s`, which is no command", name, m[1])
			}
		}
	}
	if checked < 4 {
		t.Errorf("only %d om commands found in the installers", checked)
	}
}

func TestInstallShIsValidBash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	if out, err := exec.Command(bash, "-n", filepath.Join(root(t), "install.sh")).CombinedOutput(); err != nil {
		t.Fatalf("bash -n install.sh: %v\n%s", err, out)
	}
}

// ---- docs name real commands ----

func TestBacktickedOmCommandsExist(t *testing.T) {
	p := cli.NewParser(state.Version, state.NewDirs())
	known := map[string]bool{"help": true, "dashboard": true, "probe": true} // the last two are run by containers
	for _, c := range p.Commands {
		known[c.Name] = true
		for _, a := range c.Aliases {
			known[a] = true
		}
	}
	ideas := regexp.MustCompile(`(?ms)^## (?:Horizons|\d+\. Ideas).*?(?:^## |\z)`) // ideas are not commands yet
	cmdRE := regexp.MustCompile("`om ([a-z][a-z-]*)\\b")
	var bad []string
	for _, rel := range append(docFiles(t), "CLAUDE.md") {
		if rel == "CHANGELOG.md" || strings.HasPrefix(filepath.ToSlash(rel), "docs/adr/") { // history names commands that were dropped
			continue
		}
		for _, m := range cmdRE.FindAllStringSubmatch(ideas.ReplaceAllString(read(t, rel), ""), -1) {
			if !known[m[1]] {
				bad = append(bad, rel+": om "+m[1])
			}
		}
	}
	if len(bad) > 0 {
		t.Errorf("docs name commands that do not exist:\n  %s", strings.Join(bad, "\n  "))
	}
}
