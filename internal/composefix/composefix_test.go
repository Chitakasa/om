package composefix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustParse(t *testing.T, text string) *Doc {
	t.Helper()
	d, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// dump writes each result out when COMPOSEFIX_DUMP names a folder, so a real YAML parser can check them by hand.
func dump(t *testing.T, name, text string) {
	if dir := os.Getenv("COMPOSEFIX_DUMP"); dir != "" {
		os.WriteFile(filepath.Join(dir, strings.ReplaceAll(t.Name()+"_"+name, "/", "_")+".yml"), []byte(text), 0o644)
	}
}

func TestPortsBecomeExposeAndEverythingElseStays(t *testing.T) {
	in := `# my stack
services:
  app:
    image: example/app:1   # the app
    ports:
      - '127.0.0.1:9000:9000'   # admin
      - 8080:80
      - "53:53/udp"
      - "80:80"                  # same container port again
    environment:
      - A=1

  db:
    image: postgres:16
    ports: ["5432:5432"]

volumes:
  data: {}
`
	d := mustParse(t, in)
	changes, ports, advice, err := d.PortsToExpose("app")
	if err != nil || len(advice) != 0 {
		t.Fatalf("%v %v", err, advice)
	}
	if strings.Join(ports, ",") != "9000,80,53/udp" {
		t.Fatalf("ports: %v", ports)
	}
	if len(changes) != 3 || !strings.Contains(changes[0], "app: ports 127.0.0.1:9000:9000 becomes expose 9000") {
		t.Fatalf("changes: %v", changes)
	}
	if _, _, _, err := d.PortsToExpose("db"); err != nil {
		t.Fatal(err)
	}
	want := `# my stack
services:
  app:
    image: example/app:1   # the app
    expose:
      - '9000'   # admin
      - 80
      - "53/udp"
    environment:
      - A=1

  db:
    image: postgres:16
    expose: ["5432"]

volumes:
  data: {}
`
	want = strings.Replace(want, "      - 80\n", "      - \"80\"\n", 1)
	if got := d.String(); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	dump(t, "ports", d.String())
	// a second run has nothing left to do
	if c, p, a, err := mustParse(t, d.String()).PortsToExpose("app"); len(c)+len(p)+len(a) != 0 || err != nil {
		t.Fatalf("not idempotent: %v %v %v %v", c, p, a, err)
	}
}

func TestLabelsAreAddedInPlaceInTheRightService(t *testing.T) {
	in := `services:
  web:
    image: nginx
    labels:
      - "dashboard.name=Old"   # keep this comment
      - 'om.mem=64m'
    restart: always

  # the database
  db:
    image: postgres
`
	d := mustParse(t, in)
	if err := d.AddLabels("web", []KV{{"dashboard.name", "Blog"}, {"om.mem", "256m"}, {"om.egress", "learn"}}, true); err != nil {
		t.Fatal(err)
	}
	if err := d.AddLabels("db", []KV{{"om.log", "off"}}, true); err != nil {
		t.Fatal(err)
	}
	want := `services:
  web:
    image: nginx
    labels:
      - "dashboard.name=Blog"
      - 'om.mem=256m'
      - "om.egress=learn"
    restart: always

  # the database
  db:
    image: postgres
    labels:
      - "om.log=off"
`
	if got := d.String(); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	dump(t, "labels", d.String())
}

func TestMapFormLabelsStayMapForm(t *testing.T) {
	in := "services:\n  web:\n    image: nginx\n    labels:\n      com.example.team: core\n      om.mem: 64m\n"
	d := mustParse(t, in)
	if err := d.AddLabels("web", []KV{{"om.mem", "128m"}, {"dashboard.scope", "public"}}, true); err != nil {
		t.Fatal(err)
	}
	want := "services:\n  web:\n    image: nginx\n    labels:\n      com.example.team: core\n      om.mem: \"128m\"\n      dashboard.scope: \"public\"\n"
	if got := d.String(); got != want {
		t.Fatalf("got:\n%s", got)
	}
	dump(t, "map", d.String())
}

func TestWindowsLineEndingsAndAMissingFinalNewlineSurvive(t *testing.T) {
	in := "services:\r\n  web:\r\n    image: nginx\r\n    ports:\r\n      - \"8080:80\""
	d := mustParse(t, in)
	if _, _, _, err := d.PortsToExpose("web"); err != nil {
		t.Fatal(err)
	}
	if err := d.AddLabels("web", []KV{{"om.log", "off"}}, true); err != nil {
		t.Fatal(err)
	}
	want := "services:\r\n  web:\r\n    image: nginx\r\n    expose:\r\n      - \"80\"\r\n    labels:\r\n      - \"om.log=off\""
	if got := d.String(); got != want {
		t.Fatalf("got %q", got)
	}
}

func TestAnExistingExposeIsMergedInto(t *testing.T) {
	for name, in := range map[string]string{
		"ports first":  "services:\n  web:\n    ports:\n      - \"8080:80\"\n      - \"9090:90\"\n    expose:\n      - \"80\"\n    image: x\n",
		"expose first": "services:\n  web:\n    expose:\n      - \"80\"\n    ports:\n      - \"8080:80\"\n      - \"9090:90\"\n    image: x\n",
	} {
		d := mustParse(t, in)
		_, ports, advice, err := d.PortsToExpose("web")
		if err != nil || len(advice) != 0 || strings.Join(ports, ",") != "80,90" {
			t.Fatalf("%s: %v %v %v", name, ports, advice, err)
		}
		got := d.String()
		if strings.Contains(got, "ports:") || strings.Count(got, "expose:") != 1 || !strings.Contains(got, `"90"`) || strings.Count(got, `"80"`) != 1 {
			t.Fatalf("%s:\n%s", name, got)
		}
		dump(t, name, got)
	}
}

func TestVariablesInPortsAreKept(t *testing.T) {
	in := "services:\n  web:\n    ports:\n      - \"${HTTP_PORT:-8080}:80\"\n      - \"8443:${APP_TLS:-443}\"\n      - \"[::1]:9000:9000\"\n"
	d := mustParse(t, in)
	_, ports, advice, err := d.PortsToExpose("web")
	if err != nil || len(advice) != 0 || strings.Join(ports, ",") != "80,${APP_TLS:-443},9000" {
		t.Fatalf("%v %v %v", ports, advice, err)
	}
	dump(t, "vars", d.String())
}

func TestWhatItWillNotRewriteIsLeftAloneWithAdvice(t *testing.T) {
	long := "services:\n  web:\n    ports:\n      - target: 80\n        published: 8080\n        protocol: tcp\n      - target: 53\n        protocol: udp\n      - \"9000:9000\"\n    image: x\n"
	d := mustParse(t, long)
	c, p, advice, err := d.PortsToExpose("web")
	want := "services:\n  web:\n    expose:\n      - \"80\"\n      - \"53/udp\"\n      - \"9000\"\n    image: x\n"
	if err != nil || len(advice) != 0 || strings.Join(p, ",") != "80,53/udp,9000" || len(c) != 3 || d.String() != want {
		t.Fatalf("%v %v %v %v\n%s", c, p, advice, err, d.String())
	}
	dump(t, "long", d.String())
	odd := "services:\n  web:\n    ports:\n      - \"http\"\n"
	d = mustParse(t, odd)
	if _, _, advice, _ := d.PortsToExpose("web"); len(advice) != 1 || d.String() != odd {
		t.Fatalf("odd port: %v", advice)
	}
	alias := "services:\n  web: *common\n  api:\n    image: x\n    labels: [\"a=b\"]\n"
	d = mustParse(t, alias)
	if err := d.AddLabels("web", []KV{{"om.log", "off"}}, true); err == nil {
		t.Error("labels on an alias service")
	}
	if err := d.AddLabels("api", []KV{{"om.log", "off"}}, true); err == nil || d.String() != alias {
		t.Errorf("one-line labels: %v", err)
	}
	if err := d.AddLabels("nope", []KV{{"om.log", "off"}}, true); err == nil {
		t.Error("an unknown service")
	}
	if _, err := Parse("version: '3'\nvolumes: {}\n"); err != ErrNoServices {
		t.Errorf("no services: %v", err)
	}
}

func TestALabelValueCannotBreakOutOfItsQuotes(t *testing.T) {
	d := mustParse(t, "services:\n  web:\n    image: x\n")
	for _, bad := range []string{"", "a\"b", "a\\b", "a\nb", "x\"\n    privileged: true"} {
		if err := d.AddLabels("web", []KV{{"om.mem", bad}}, true); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if d.String() != "services:\n  web:\n    image: x\n" {
		t.Fatal("a refused label changed the file")
	}
}

func TestServicesAreListedInOrder(t *testing.T) {
	d := mustParse(t, "name: demo\nservices:\n  # first\n  web:\n    image: a\n  \"db\":\n    image: b\n  cache: {image: c}\nnetworks:\n  default: {}\n")
	if got := strings.Join(d.Services(), ","); got != "web,db,cache" {
		t.Fatal(got)
	}
}

func TestDiffShowsOnlyWhatChanged(t *testing.T) {
	a := "services:\n  web:\n    image: x\n    ports:\n      - \"8080:80\"\n    restart: always\n  db:\n    image: y\n"
	b := strings.Replace(strings.Replace(a, "ports:", "expose:", 1), `"8080:80"`, `"80"`, 1)
	got := Diff(a, b)
	for _, want := range []string{"-     ports:", "+     expose:", `-       - "8080:80"`, `+       - "80"`, "      image: x"} {
		if !strings.Contains(got, want) {
			t.Errorf("diff lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "db:") {
		t.Errorf("unrelated lines shown:\n%s", got)
	}
	if Diff(a, a) != "" {
		t.Error("equal texts must give no diff")
	}
}

func TestDefaultsKeepWhatTheAuthorWrote(t *testing.T) {
	in := "services:\n  web:\n    image: x\n    labels:\n      - \"dashboard.name=Mine\"\n"
	d := mustParse(t, in)
	if err := d.AddLabels("web", []KV{{"dashboard.name", "Web"}, {"dashboard.scope", "private"}}, false); err != nil {
		t.Fatal(err)
	}
	want := "services:\n  web:\n    image: x\n    labels:\n      - \"dashboard.name=Mine\"\n      - \"dashboard.scope=private\"\n"
	if d.String() != want {
		t.Fatalf("got:\n%s", d.String())
	}
}

func TestRemovingLabelsKeepsTheRest(t *testing.T) {
	in := "services:\n  web:\n    image: x\n    labels:\n      - \"a=1\"   # keep\n      - \"om.mem=64m\"\n      - 'om.log=off'\n    restart: always\n"
	d := mustParse(t, in)
	if err := d.RemoveLabels("web", []string{"om.mem", "om.log", "nope"}); err != nil {
		t.Fatal(err)
	}
	if want := "services:\n  web:\n    image: x\n    labels:\n      - \"a=1\"   # keep\n    restart: always\n"; d.String() != want {
		t.Fatalf("got:\n%s", d.String())
	}
	if err := d.RemoveLabels("web", []string{"a"}); err != nil {
		t.Fatal(err)
	}
	if want := "services:\n  web:\n    image: x\n    labels: []\n    restart: always\n"; d.String() != want {
		t.Fatalf("got:\n%s", d.String())
	}
	m := mustParse(t, "services:\n  web:\n    labels:\n      a: b\n      om.mem: 64m\n")
	m.RemoveLabels("web", []string{"om.mem"})
	if want := "services:\n  web:\n    labels:\n      a: b\n"; m.String() != want {
		t.Fatalf("map form:\n%s", m.String())
	}
}

func TestAnEmptyLabelsListCanBeAddedTo(t *testing.T) {
	for _, in := range []string{"services:\n  web:\n    labels: []   # none yet\n    image: x\n", "services:\n  web:\n    labels: {}\n    image: x\n"} {
		d := mustParse(t, in)
		if err := d.AddLabels("web", []KV{{"om.log", "off"}}, true); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(d.String(), "labels:") || !strings.Contains(d.String(), `- "om.log=off"`) || strings.Contains(d.String(), "[]") || strings.Contains(d.String(), "{}") {
			t.Fatalf("got:\n%s", d.String())
		}
	}
}

func TestTheWorkspaceNetworkIsAddedOrReplaced(t *testing.T) {
	const expr = "${WORKSPACE_NET:-ws_net}"
	for name, c := range map[string]struct{ in, want string }{
		"none":      {"services:\n  web:\n    image: x\n", "services:\n  web:\n    image: x\n\nnetworks:\n  default:\n    name: " + expr + "\n    external: true\n"},
		"others":    {"services:\n  web:\n    image: x\nnetworks:\n  back: {}\n", "services:\n  web:\n    image: x\nnetworks:\n  default:\n    name: " + expr + "\n    external: true\n  back: {}\n"},
		"a default": {"services:\n  web:\n    image: x\nnetworks:\n  default:\n    driver: bridge\n    name: mine\n  back: {}\n", "services:\n  web:\n    image: x\nnetworks:\n  default:\n    name: " + expr + "\n    external: true\n  back: {}\n"},
		"empty":     {"services:\n  web:\n    image: x\nnetworks: {}\n", "services:\n  web:\n    image: x\nnetworks:\n  default:\n    name: " + expr + "\n    external: true\n"},
		"flow":      {"services:\n  web:\n    image: x\nnetworks: {default: {driver: bridge}, back: {}}\n", "services:\n  web:\n    image: x\nnetworks:\n  default:\n    name: " + expr + "\n    external: true\n  back: {}\n"},
	} {
		d := mustParse(t, c.in)
		if _, err := d.EnsureDefaultNetwork(expr); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if d.String() != c.want {
			t.Errorf("%s:\ngot:\n%s\nwant:\n%s", name, d.String(), c.want)
		}
		dump(t, name, d.String())
	}
}

func TestAServiceThatListsNetworksJoinsTheWorkspaceOne(t *testing.T) {
	for name, c := range map[string]struct{ in, want string }{
		"no list": {"services:\n  web:\n    image: x\n", "services:\n  web:\n    image: x\n"},
		"list":    {"services:\n  web:\n    networks:\n      - back\n    image: x\n", "services:\n  web:\n    networks:\n      - back\n      - default\n    image: x\n"},
		"has it":  {"services:\n  web:\n    networks:\n      - default\n", "services:\n  web:\n    networks:\n      - default\n"},
		"map":     {"services:\n  web:\n    networks:\n      back:\n        aliases: [a]\n", "services:\n  web:\n    networks:\n      back:\n        aliases: [a]\n      default:\n"},
		"flow":    {"services:\n  web:\n    networks: [back]\n", "services:\n  web:\n    networks:\n      - back\n      - default\n"},
	} {
		d := mustParse(t, c.in)
		if _, err := d.Blockify("web"); err != nil {
			t.Fatal(err)
		}
		if err := d.EnsureNetworkRef("web", "default"); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if d.String() != c.want {
			t.Errorf("%s:\ngot:\n%s\nwant:\n%s", name, d.String(), c.want)
		}
	}
	d := mustParse(t, "services:\n  web:\n    image: x\n    container_name: other\n")
	d.SetScalar("web", "container_name", "${WORKSPACE_ID:-ws}_web")
	d.SetScalar("web", "restart", "unless-stopped")
	if want := "services:\n  web:\n    image: x\n    container_name: ${WORKSPACE_ID:-ws}_web\n    restart: unless-stopped\n"; d.String() != want {
		t.Errorf("scalars:\n%s", d.String())
	}
}
