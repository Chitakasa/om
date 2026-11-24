package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Chitakasa/om/internal/composefix"
	"github.com/Chitakasa/om/internal/runcmd"
	"github.com/Chitakasa/om/internal/scaffold"
	"github.com/Chitakasa/om/internal/state"
	"github.com/Chitakasa/om/internal/workspace"
)

// engineFixtures are compose layouts that need more than line editing; each is brought in with the real compose
// engine, which must read the edited files as the originals plus exposed ports and labels, and nothing else.
var engineFixtures = map[string]map[string]string{
	"anchors and merge keys": {"compose.yml": `x-common: &common
  restart: unless-stopped
  ports:
    - "8080:80"
  labels:
    - "team=core"
  environment:
    A: "1"
services:
  web:
    <<: *common
    image: nginx:1
  api:
    <<: *common
    image: httpd:2
    ports: ["9090:80"]
    labels:
      owner: me
`},
	"an alias service": {"compose.yml": `x-base: &base
  image: nginx:1
  ports: ["8080:80"]
  labels: ["team=core"]
services:
  web: *base
`},
	"flow style": {"compose.yml": `services:
  web: {image: "nginx:1", ports: ["8080:80", "8443:443"], labels: ["a=b"], environment: {K: v}}
  db:
    image: postgres:16
    ports: [
      "5432:5432",   # the database
    ]
    labels: {x: "1"}
`},
	"long syntax and variables": {"compose.yml": `services:
  web:
    image: nginx:1
    ports:
      - target: 80
        published: "${HTTP_PORT:-8080}"
        protocol: tcp
      - target: 53
        published: 5353
        protocol: udp
      - "127.0.0.1:9000:9000"
      - "${ADMIN:-7000}:7000"
`},
	"extends in the same file": {"compose.yml": `services:
  base:
    image: nginx:1
    ports: ["8080:80"]
  web:
    extends: base
    labels: ["a=b"]
`},
	"extends from another file": {"compose.yml": "services:\n  web:\n    extends:\n      file: common.yml\n      service: app\n    labels:\n      - \"a=b\"\n", "common.yml": "services:\n  app:\n    image: nginx:1\n    ports:\n      - \"8080:80\"\n"},
	"include":                   {"compose.yml": "include:\n  - db.yml\nservices:\n  web:\n    image: nginx:1\n    ports: [\"8080:80\"]\n", "db.yml": "services:\n  db:\n    image: postgres:16\n    ports:\n      - \"5432:5432\"\n"},
	"aliased labels":            {"compose.yml": "x-l: &l\n  - \"a=b\"\nservices:\n  web:\n    image: nginx:1\n    ports: [\"8080:80\"]\n    labels: *l\n"},
	"both ports and expose":     {"compose.yml": "services:\n  web:\n    image: nginx:1\n    ports: [\"8080:80\", \"9090:90\"]\n    expose: [\"80\"]\n"},
	"quoted keys and comments":  {"compose.yml": "# top\nservices:\n  \"web\":   # main\n    image: nginx:1\n    # the port\n    ports:\n      # http\n      - '8080:80'\n\n      - \"8443:443\"  # tls\n    healthcheck:\n      test: [\"CMD\", \"true\"]\n"},
}

func TestImportsAreProvenAgainstTheRealEngine(t *testing.T) {
	dc, err := exec.LookPath("docker-compose")
	if err != nil {
		t.Skip("docker-compose is not installed")
	}
	for name, files := range engineFixtures {
		t.Run(name, func(t *testing.T) {
			t.Setenv("OM_RUNTIME", "/nonexistent/podman")
			a, out, root := wizardApp(t, "")
			a.Interactive = false
			a.RunIn = func(cmd []string, dir string, env []string) state.Result {
				c := exec.Command(dc, cmd[2:]...)
				c.Dir = dir
				c.Env = append(os.Environ(), env...)
				var so, se strings.Builder
				c.Stdout, c.Stderr = &so, &se
				code := 0
				if err := c.Run(); err != nil {
					code = 1
				}
				return state.Result{Code: code, Stdout: so.String(), Stderr: se.String()}
			}
			src := t.TempDir()
			for f, text := range files {
				os.WriteFile(filepath.Join(src, f), []byte(text), 0o644)
			}
			s, err := a.importCompose(root, "ws", Namespace{"yes": true}, scaffold.AddArgs{Name: "app"}, src)
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			after := a.composeConfig("podman", s.composeFile, nil)
			if after.cfg == nil {
				t.Fatalf("the edited file does not load: %s", after.err)
			}
			for svc, sv := range cfgServices(after.cfg) {
				if len(cfgPorts(sv)) > 0 {
					t.Errorf("%s still publishes ports", svc)
				}
			}
			if strings.Contains(out.String(), "Not changed") {
				t.Errorf("something was left for the user:\n%s", out)
			}
			if os.Getenv("OM_KEEP_IMPORTS") != "" {
				for _, f := range append([]string{filepath.Base(s.composeFile)}, "common.yml", "db.yml") {
					if b, e := os.ReadFile(filepath.Join(filepath.Dir(s.composeFile), f)); e == nil {
						t.Logf("--- %s\n%s", f, b)
					}
				}
			}
		})
	}
}

func TestAScaffoldedServiceWithEverythingIsValidCompose(t *testing.T) {
	dc, err := exec.LookPath("docker-compose")
	if err != nil {
		t.Skip("docker-compose is not installed")
	}
	root := t.TempDir()
	p, text := plan(t, scaffold.AddArgs{Name: "app", Image: "docker.io/library/ghost:5", Port: 2368, Volumes: []string{"app-data:/var/lib/ghost"},
		Env: []scaffold.KV{{Key: "URL", Value: "http://x$y"}, {Key: "TOKEN_FILE", Value: "/run/secrets/token"}}, Secrets: []string{"token"}, Health: "ls /data",
		Extra: []scaffold.KV{{Key: "om.mem", Value: "256m"}}}, root)
	_ = p
	os.WriteFile(filepath.Join(root, "compose.yml"), []byte(text), 0o644)
	c := exec.Command(dc, "config", "--format", "json")
	c.Dir = root
	c.Env = append(os.Environ(), "WORKSPACE_ID=ws", "WORKSPACE_NET=ws_net")
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s\n%s", err, out, text)
	}
	for _, want := range []string{`"URL": "http://x$$y"`, `app-data`, `/run/secrets/token`, `"CMD-SHELL"`} {
		if !strings.Contains(string(out), want) {
			t.Errorf("config lacks %s:\n%s", want, out)
		}
	}
}

// realEngine answers `<runtime> compose ...` with the installed docker-compose.
func realEngine(t *testing.T) func([]string, string, []string) state.Result {
	dc, err := exec.LookPath("docker-compose")
	if err != nil {
		t.Skip("docker-compose is not installed")
	}
	return func(cmd []string, dir string, env []string) state.Result {
		if len(cmd) < 3 || cmd[1] != "compose" {
			return state.Result{Code: 127}
		}
		c := exec.Command(dc, cmd[2:]...)
		c.Dir = dir
		c.Env = append(os.Environ(), env...)
		var so, se strings.Builder
		c.Stdout, c.Stderr = &so, &se
		code := 0
		if c.Run() != nil {
			code = 1
		}
		return state.Result{Code: code, Stdout: so.String(), Stderr: se.String()}
	}
}

func TestLabelEditsWorkOnEveryLayoutAndAreProvenByTheEngine(t *testing.T) {
	run := realEngine(t)
	for name, files := range engineFixtures {
		t.Run(name, func(t *testing.T) {
			t.Setenv("OM_RUNTIME", "/nonexistent/podman")
			a, _, root := wizardApp(t, "")
			a.RunIn = run
			dir := filepath.Join(root, "services", "app")
			os.MkdirAll(dir, 0o755)
			for f, text := range files {
				os.WriteFile(filepath.Join(dir, f), []byte(text), 0o644)
			}
			set := []composefix.KV{{Key: "om.mem", Value: "128m"}, {Key: "dashboard.scope", Value: "public"}}
			if err := a.applyLabelEdit(root, "ws", dir, "", set, []string{"team", "a", "x"}); err != nil {
				t.Fatal(err)
			}
			cf, _ := workspace.FindComposeFile(dir)
			cfg := a.composeConfig("podman", cf, nil).cfg
			if cfg == nil {
				t.Fatal("the edited file does not load")
			}
			found := 0
			for _, sv := range cfgServices(cfg) {
				if l := cfgLabelMap(sv); l["om.mem"] == "128m" && l["dashboard.scope"] == "public" {
					found++
				}
			}
			if found < 1 { // a service that extends the one edited inherits its labels, so more than one is fine
				t.Errorf("the labels reached %d services", found)
			}
		})
	}
}

func TestInteractiveEditChangesOnlyWhatYouChanged(t *testing.T) {
	run := realEngine(t)
	t.Setenv("OM_RUNTIME", "/nonexistent/podman")
	a, out, root := wizardApp(t, "2\n3\napi.example.org\n4\n2\n7\n") // outbound: only a host; updates: hold; done
	a.RunIn = run
	_, compose := plan(t, scaffold.AddArgs{Name: "web", Image: "docker.io/library/nginx:1", Port: 80, Extra: []scaffold.KV{{Key: "om.mem", Value: "64m"}}}, root)
	dir := filepath.Join(root, "services", "web")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "compose.yml"), []byte(compose), 0o644)
	set, unset, svc, err := a.editInteractive(root, "ws", Namespace{}, dir, "web")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	got := map[string]string{}
	for _, kv := range set {
		got[kv.Key] = kv.Value
	}
	if svc != "web" || got["om.egress"] != "api.example.org" || got["om.update"] != "hold" || len(set) != 2 || len(unset) != 0 {
		t.Fatalf("set %v unset %v\n%s", set, unset, out)
	}
	if !strings.Contains(out.String(), "memory 64m") {
		t.Errorf("the current limit was not shown:\n%s", out)
	}
	if err := a.applyLabelEdit(root, "ws", dir, svc, set, unset); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "compose.yml"))
	if !strings.Contains(string(after), `"om.egress=api.example.org"`) || !strings.Contains(string(after), `"om.mem=64m"`) {
		t.Errorf("compose:\n%s", after)
	}
	if want := equivalentEdit("web", set, unset); want != "om edit web --label om.egress=api.example.org --label om.update=hold" {
		t.Errorf("equivalent: %s", want)
	}
}

func TestADockerRunCommandIsBroughtInAndProvenByTheEngine(t *testing.T) {
	run := realEngine(t)
	t.Setenv("OM_RUNTIME", "/nonexistent/podman")
	a, out, root := wizardApp(t, "")
	a.Interactive = false
	a.RunIn = run
	svc, err := runcmd.Parse(`docker run -d --name blog -p 8080:2368 -e url=http://localhost -e DB_PASSWORD=hunter2 -v blog:/var/lib/ghost --memory 512m --restart unless-stopped docker.io/library/ghost:5`)
	if err != nil {
		t.Fatal(err)
	}
	src := t.TempDir()
	os.WriteFile(filepath.Join(src, "compose.yml"), []byte(svc.Compose()), 0o644)
	s, err := a.importCompose(root, "ws", Namespace{"yes": true, "from_label": "your docker run command"}, scaffold.AddArgs{Name: svc.Name}, src)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	got, _ := os.ReadFile(s.composeFile)
	for _, want := range []string{"expose:", `"2368"`, `"om.mem=512m"`, `"dashboard.port=2368"`, "container_name: ${WORKSPACE_ID:-ws}_blog", "external: true", "name: ${WORKSPACE_NET:-ws_net}"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("compose lacks %q:\n%s", want, got)
		}
	}
	for _, want := range []string{"your docker run command", "DB_PASSWORD in plain text", "om secrets set blog/db_password"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
}

func TestCheckWritesNothingAndSaysWhatWouldHappen(t *testing.T) {
	run := realEngine(t)
	t.Setenv("OM_RUNTIME", "/nonexistent/podman")
	a, out, root := wizardApp(t, "")
	a.RunIn = run
	src := t.TempDir()
	os.WriteFile(filepath.Join(src, "compose.yml"), []byte("services:\n  web:\n    image: nginx:1\n    ports: [\"8080:80\"]\n    privileged: true\n"), 0o644)
	err := a.cmdCheck(root, Namespace{"path": src})
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 1 {
		t.Fatalf("a refused service must exit 1: %v\n%s", err, out)
	}
	for _, want := range []string{"ports 8080:80 becomes expose 80", "privileged: true", "nothing was written"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("lacks %q:\n%s", want, out)
		}
	}
	if entries, _ := os.ReadDir(root); len(entries) != 0 {
		t.Fatalf("check wrote into the workspace: %v", entries)
	}
	if !a.Interactive {
		t.Error("check left the terminal mode changed")
	}
}

func TestAnotherServiceCanBeCustomisedOnItsOwn(t *testing.T) {
	run := realEngine(t)
	t.Setenv("OM_RUNTIME", "/nonexistent/podman")
	// name, web service 1, customise another (2 = db is the only other: Which service? 1), outbound(2) learn(2), done(7), add it
	a, out, root := wizardApp(t, "blog\n1\n3\n1\n2\n2\n7\n1\n")
	a.RunIn = run
	src := t.TempDir()
	os.WriteFile(filepath.Join(src, "compose.yml"), []byte("services:\n  web:\n    image: nginx:1\n    ports: [\"8080:80\"]\n  db:\n    image: postgres:16\n"), 0o644)
	s, err := a.importCompose(root, "ws", Namespace{}, scaffold.AddArgs{}, src)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	cfg := a.composeConfig("podman", s.composeFile, nil).cfg
	sv := cfgServices(cfg)
	if cfgLabelMap(sv["db"])["om.egress"] != "learn" || cfgLabelMap(sv["web"])["om.egress"] != "" {
		t.Fatalf("labels: db %v web %v\n%s", cfgLabelMap(sv["db"]), cfgLabelMap(sv["web"]), out)
	}
}
