// Package scaffold is the scaffolding for `om add`: validate the request, then render the compose file and project
// files. Pure functions (no engine, no registry); the CLI applies them and starts the routes. It also holds the label
// editing of `om edit`. Port of lib/gitops/scaffold.py.
package scaffold

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/workspace"
)

// ProjectServerJS is the minimal dev server scaffolded by `om add --project`.
const ProjectServerJS = "// Minimal dev server scaffolded by `om add --project`. Edit freely: `node --watch` restarts on save.\n" +
	"const http = require(\"http\");\n" +
	"const port = Number(process.env.PORT || 3000);\n" +
	"http.createServer((req, res) => {\n" +
	"  res.writeHead(200, { \"Content-Type\": \"text/html; charset=utf-8\" });\n" +
	"  res.end(`<h1>${process.env.PROJECT_NAME} is running</h1><p>Edit server.js — it reloads automatically.</p>`);\n" +
	"}).listen(port, () => console.log(`listening on :${port}`));\n"

// Non-root images that run with no capabilities and a read-only filesystem.
const (
	DefaultServiceImage = "docker.io/nginxinc/nginx-unprivileged:1.31-alpine" // listens on 8080
	DefaultProjectImage = "docker.io/library/node:24-alpine"
)

// Label is a label, an example value and what it does.
type Label struct{ Name, Example, Note string }

// ActiveLabels are the labels every scaffold sets; docs/LABELS.md lists them with LabelMenu.
var ActiveLabels = []Label{
	{"workspace.id", "my-workspace", "the workspace the service belongs to; keeps names unique across workspaces"},
	{"dashboard.name", "Web", "the card's title on the dashboard"},
	{"dashboard.icon", "🌐", "the card's icon"},
	{"dashboard.description", "A small web server", "the card's description"},
	{"dashboard.port", "8080", "the container port om routes to"},
	{"dashboard.domain", "web.my-workspace.localhost", "the address shown for the service (informational)"},
	{"dashboard.scope", "private", "`private` (this machine and your VPN) or `public` (the LAN too)"},
	{"dashboard.web", "true", "`false` for a background service with no web address"},
}

// LabelGroup is a heading of the label menu.
type LabelGroup struct {
	Name  string
	Items []Label
}

// LabelMenu lists the labels a user can add to a service beyond the ones every scaffold sets. RenderCompose writes
// them as a commented menu; a test holds this table to the labels om documents, so a label cannot be added to om
// without appearing here.
var LabelMenu = []LabelGroup{
	{"Routing", []Label{
		{"om.route.aliases", "/a,/b", "redirect these top-level paths on the dashboard's address to this service"},
		{"om.route.keep_prefix", "true", "the app serves itself under /<service>/"},
		{"om.route.dashboard_paths", "/api/x*", "paths on this service's address answered by the dashboard"},
		{"om.tcp", "5432", "publish this container port as a raw TCP route"},
		{"om.tcp.port", "15432", "the host port for om.tcp (default: a free slot)"},
	}},
	{"Who can reach it", []Label{
		{"om.net.allow", "vpn", "only these addresses reach its own ports (vpn = your VPN allow-list)"},
		{"om.net.deny", "203.0.113.0/24", "never these addresses"},
		{"om.link", "<ws>/<svc>", "a private network with exactly one other service"},
		{"om.link.allow", "<ws>/<svc>", "who may link to this service (both sides must agree)"},
		{"om.network", "shared", "join the workspace-wide network instead of this folder's own"},
	}},
	{"Outbound traffic", []Label{
		{"om.egress", "audit", "audit | learn | internet | host,*.host: where it may connect out (default: nowhere)"},
		{"om.egress.learn_ttl", "24h", "how long learn mode records"},
		{"om.egress.jvm", "true", "hand the proxy settings to a JVM service"},
	}},
	{"Resources and updates", []Label{
		{"om.mem", "256m", "memory limit"},
		{"om.pids", "200", "process limit"},
		{"om.cpus", "0.5", "CPU limit"},
		{"om.update", "hold", "hold: keep the image's pin; auto: the scheduled sync updates it"},
	}},
	{"Logging and policy", []Label{
		{"om.log", "off", "leave no trace: no access or connection log, no output kept"},
		{"om.policy.allow", "mounts", "waive these deploy-gate rules for this service (om policy check)"},
	}},
	{"Dashboard", []Label{
		{"dashboard.hide", "true", "keep it off the dashboard"},
		{"dashboard.path", "/x/", "where the dashboard link opens on the service's address"},
		{"dashboard.url", "https://example.org/", "open this address instead of the service's own port"},
		{"dashboard.search", "true", "the service is the browser's search engine"},
		{"dashboard.search_url", "/search?q={searchTerms}", "its search address"},
		{"workspace.category", "tools", "reported by /api/services"},
	}},
}

func runeLen(s string) int { return len([]rune(s)) }

func ljust(s string, w int) string {
	if n := runeLen(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}

// MenuText is LabelMenu as commented compose list entries, one line each, grouped under a heading.
func MenuText(indent string) string {
	type entry struct{ text, note, group string }
	var entries []entry
	width := 0
	for _, g := range LabelMenu {
		for _, l := range g.Items {
			t := `- "` + l.Name + "=" + l.Example + `"`
			entries = append(entries, entry{t, l.Note, g.Name})
			if n := runeLen(t); n > width {
				width = n
			}
		}
	}
	out := []string{indent + "# More om labels, uncomment what you need (om docs guide):"}
	last := ""
	for _, e := range entries {
		if e.group != last {
			out = append(out, indent+"# "+e.group)
			last = e.group
		}
		out = append(out, indent+"# "+ljust(e.text, width)+"  # "+e.note)
	}
	return strings.Join(out, "\n") + "\n"
}

// YAMLLabelSafe reports a value that can sit inside a double-quoted compose label.
func YAMLLabelSafe(v string) bool { return !strings.ContainsAny(v, "\"\\\n\r") }

// AddArgs are the `om add` options.
type AddArgs struct {
	Name, Image, Domain, Icon, Desc string
	Port                            int // 0: not given
	Project, NoWeb, Public          bool
	Extra                           []KV // more labels to write as active ones (the interactive `om add` chooses them); each key must be a known label
}

// Plan is the validated `om add` request.
type Plan struct {
	WSID, Name, Dest, Image, Domain, Icon, Desc string
	Port                                        int
	IsProject, CustomImage, Public, NoWeb       bool
	Extra                                       []KV
}

// MakePlan validates the request. The error text is what to show.
func MakePlan(a AddArgs, wsID, root string, exists func(string) bool) (Plan, error) {
	name := strings.ReplaceAll(strings.ToLower(a.Name), " ", "-")
	if !workspace.IsSafeName(name) {
		return Plan{}, fmt.Errorf("Error: invalid name '%s' (allowed: lowercase letters, digits, '-')", name)
	}
	kind := "services"
	if a.Project {
		kind = "projects"
	}
	dest := filepath.Join(root, kind, name)
	if exists(dest) {
		return Plan{}, fmt.Errorf("Error: '%s' already exists at %s", name, dest)
	}
	if a.Image != "" && a.Port == 0 && !a.NoWeb {
		return Plan{}, fmt.Errorf("Error: with --image, also pass --port (the port that image listens on inside the container).")
	}
	image, port := a.Image, a.Port
	if a.Project {
		if image == "" {
			image = DefaultProjectImage
		}
		if port == 0 {
			port = 3000
		}
	} else {
		if image == "" {
			image = DefaultServiceImage
		}
		if port == 0 {
			port = 8080
		}
	}
	domain := a.Domain
	if domain == "" {
		domain = wsID + "." + name + ".localhost"
	}
	domain = strings.ToLower(domain)
	icon := a.Icon
	if icon == "" {
		icon = "📦"
		if a.Project {
			icon = "⚡"
		}
	}
	desc := a.Desc
	if desc == "" {
		desc = "Self-hosted service: " + name
		if a.Project {
			desc = "Developer project: " + name
		}
	}
	if !workspace.SafeDomainRE.MatchString(domain) {
		return Plan{}, fmt.Errorf("Error: invalid domain '%s'", domain)
	}
	space := false
	for _, r := range image {
		space = space || py.IsSpace(r) || unicode.IsSpace(r)
	}
	if space || !YAMLLabelSafe(image) {
		return Plan{}, fmt.Errorf("Error: invalid image '%s'", image)
	}
	if !(YAMLLabelSafe(icon) && YAMLLabelSafe(desc)) {
		return Plan{}, fmt.Errorf("Error: --icon/--desc must not contain quotes, backslashes or newlines")
	}
	for _, kv := range a.Extra {
		if !KnownLabel(kv.Key) {
			return Plan{}, fmt.Errorf("Error: '%s' is not a label om knows (see docs/LABELS.md)", kv.Key)
		}
		if kv.Value == "" || !YAMLLabelSafe(kv.Value) {
			return Plan{}, fmt.Errorf("Error: invalid value for %s: it must not be empty or contain quotes, backslashes or newlines", kv.Key)
		}
	}
	return Plan{WSID: wsID, Name: name, Dest: dest, IsProject: a.Project, Image: image, Port: port, Domain: domain, Icon: icon, Desc: desc,
		CustomImage: a.Image != "", Public: a.Public, NoWeb: a.NoWeb, Extra: a.Extra}, nil
}

// KnownLabel reports whether key is one of the labels `om add` sets or offers (ActiveLabels and LabelMenu).
func KnownLabel(key string) bool {
	for _, l := range ActiveLabels {
		if l.Name == key {
			return true
		}
	}
	for _, g := range LabelMenu {
		for _, l := range g.Items {
			if l.Name == key {
				return true
			}
		}
	}
	return false
}

// ProjectFiles are the files written next to the compose file of a project that uses the default Node image.
func ProjectFiles(p Plan) map[string]string {
	if !(p.IsProject && !p.CustomImage) {
		return nil
	}
	scripts := py.NewObject()
	scripts.Set("dev", "node --watch server.js")
	pkg := py.NewObject()
	pkg.Set("name", p.Name)
	pkg.Set("private", true)
	pkg.Set("scripts", scripts)
	return map[string]string{"server.js": ProjectServerJS, "package.json": py.Dumps(pkg) + "\n"}
}

// Hardening is the least-privilege block. om's own images are known to run with no capabilities and a read-only
// filesystem; an image of your choice usually starts as root and switches user, so it keeps only the five
// capabilities that needs.
func Hardening(customImage bool) string {
	if customImage {
		return "    # Most images start as root and switch to their own user, which needs these five;\n" +
			"    # remove them if your image runs as non-root from the start.\n" +
			"    cap_drop:\n      - ALL\n    cap_add:\n      - CHOWN\n      - DAC_OVERRIDE\n      - FOWNER\n      - SETGID\n      - SETUID\n"
	}
	return "    cap_drop:\n      - ALL\n    read_only: true\n    tmpfs:\n      - /tmp\n"
}

// RenderCompose is the service's compose.yml: 'expose' (never 'ports') keeps it off host interfaces; the edge is the
// only ingress.
func RenderCompose(p Plan) string {
	port := strconv.Itoa(p.Port)
	project := ""
	if p.IsProject && !p.CustomImage {
		project = "    working_dir: /app\n    command: [\"node\", \"--watch\", \"server.js\"]\n    environment:\n      - PORT=" + port + "\n      - PROJECT_NAME=" + p.Name +
			"\n    volumes:\n      - ./:/app:Z\n"
	}
	scope, web := "private", "true"
	if p.Public {
		scope = "public"
	}
	if p.NoWeb {
		web = "false"
	}
	extra := ""
	for _, kv := range p.Extra {
		extra += "      - \"" + kv.Key + "=" + kv.Value + "\"\n"
	}
	return "# priority: 50\nservices:\n  " + p.Name + ":\n    image: " + p.Image + "\n    container_name: ${WORKSPACE_ID:-" + p.WSID + "}_" + p.Name +
		"\n    restart: unless-stopped\n" + project + "    security_opt:\n      - no-new-privileges:true\n" + Hardening(p.CustomImage) +
		"    labels:\n      - \"workspace.id=${WORKSPACE_ID:-" + p.WSID + "}\"\n      - \"dashboard.name=" + py.Title(p.Name) + "\"\n" +
		"      - \"dashboard.icon=" + p.Icon + "\"\n      - \"dashboard.description=" + p.Desc + "\"\n      - \"dashboard.port=" + port + "\"\n" +
		"      - \"dashboard.domain=" + p.Domain + "\"\n      - \"dashboard.scope=" + scope + "\"\n      - \"dashboard.web=" + web + "\"\n" + extra +
		MenuText("      ") + "    expose:\n      - \"" + port + "\"\n    networks:\n      - default\n\nnetworks:\n  default:\n    name: ${WORKSPACE_NET:-" + p.WSID +
		"_net}\n    external: true\n"
}

// EditArgs are the `om edit` options.
type EditArgs struct {
	Scope, Icon, Desc, Name string
	Port                    int
}

// KV is one label and its new value.
type KV struct{ Key, Value string }

// LabelUpdates returns the dashboard labels `om edit` was asked to set, in the order they are applied.
func LabelUpdates(a EditArgs) ([]KV, error) {
	port := ""
	if a.Port != 0 {
		port = strconv.Itoa(a.Port)
	}
	wanted := []KV{{"dashboard.scope", strings.ToLower(a.Scope)}, {"dashboard.port", port}, {"dashboard.icon", a.Icon},
		{"dashboard.description", a.Desc}, {"dashboard.name", a.Name}}
	var updates []KV
	for _, kv := range wanted {
		if kv.Value != "" {
			updates = append(updates, kv)
		}
	}
	if len(updates) == 0 {
		return nil, fmt.Errorf("No edits specified. Use --scope, --port, --icon, --desc, or --name.")
	}
	for _, kv := range updates {
		if !YAMLLabelSafe(kv.Value) {
			return nil, fmt.Errorf("Error: values must not contain quotes, backslashes or newlines")
		}
	}
	return updates, nil
}

func indentOf(line string) string { return line[:len(line)-len(py.LStrip(line))] }

// editExistingLabels sets each label in the service's `labels:` list (replacing the line that has it, adding the
// others after the last list entry); it returns the new lines and whether a labels list was found.
func editExistingLabels(lines []string, updates []KV) ([]string, bool) {
	var out []string
	inLabels, found := false, false
	handled := map[string]bool{}
	labelsIndent := "      "
	for _, line := range lines {
		stripped := py.Strip(line)
		if strings.HasPrefix(stripped, "labels:") {
			inLabels, found = true, true
			labelsIndent = indentOf(line) + "  "
			out = append(out, line)
			continue
		}
		if inLabels {
			if strings.HasPrefix(stripped, "-") {
				matched := false
				for _, kv := range updates {
					matched = matched || strings.Contains(stripped, kv.Key+"=")
				}
				if matched {
					for _, kv := range updates {
						if strings.Contains(stripped, kv.Key+"=") {
							out = append(out, labelsIndent+`- "`+kv.Key+"="+kv.Value+`"`)
							handled[kv.Key] = true
							break
						}
					}
					continue
				}
			}
			if !strings.HasPrefix(stripped, "-") && stripped != "" && !strings.HasPrefix(stripped, "#") {
				for _, kv := range updates {
					if !handled[kv.Key] {
						out = append(out, labelsIndent+`- "`+kv.Key+"="+kv.Value+`"`)
						handled[kv.Key] = true
					}
				}
				inLabels = false
			}
		}
		out = append(out, line)
	}
	if found {
		for _, kv := range updates {
			if !handled[kv.Key] {
				out = append(out, labelsIndent+`- "`+kv.Key+"="+kv.Value+`"`)
			}
		}
	}
	return out, found
}

// insertLabelsBlock adds a new `labels:` block after the first `image:` or `container_name:` line.
func insertLabelsBlock(lines []string, updates []KV) []string {
	var final []string
	inserted := false
	for _, line := range lines {
		final = append(final, line)
		s := py.Strip(line)
		if !inserted && (strings.HasPrefix(s, "image:") || strings.HasPrefix(s, "container_name:")) {
			indent := indentOf(line)
			final = append(final, indent+"labels:")
			for _, kv := range updates {
				final = append(final, indent+`  - "`+kv.Key+"="+kv.Value+`"`)
			}
			inserted = true
		}
	}
	return final
}

// EditLabels returns the compose file with these labels set, everything else untouched.
func EditLabels(text string, updates []KV) string {
	lines, found := editExistingLabels(py.SplitLines(text), updates)
	if !found {
		lines = insertLabelsBlock(lines, updates)
	}
	return strings.Join(lines, "\n") + "\n"
}
