package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Chitakasa/om/internal/scaffold"
	"github.com/Chitakasa/om/internal/state"
	"github.com/Chitakasa/om/internal/wizard"
)

const wordpress = `# a small blog
services:
  wordpress:
    image: docker.io/library/wordpress:6   # the app
    ports:
      - "8080:80"
    volumes:
      - ./config/app.conf:/etc/app.conf:ro
    environment:
      DB_HOST: db

  db:
    image: docker.io/library/mysql:8
    restart: always
`

// importApp is an App with no engine: `compose config` is answered with the given JSON, so the policy check is fixed.
func importApp(t *testing.T, script, configJSON string) (*App, *bytes.Buffer, string) {
	t.Helper()
	t.Setenv("OM_RUNTIME", "/nonexistent/podman")
	a, out, root := wizardApp(t, script)
	a.RunIn = func(cmd []string, dir string, env []string) state.Result {
		if len(cmd) > 3 && cmd[1] == "compose" && cmd[len(cmd)-3] == "config" {
			text := configJSON
			if b, err := os.ReadFile(cmd[3]); err == nil && strings.Contains(string(b), "WORKSPACE_NET") {
				text = afterEdit(configJSON, filepath.Base(filepath.Dir(cmd[3])))
			}
			return state.Result{Stdout: text}
		}
		return state.Result{Code: 127}
	}
	return a, out, root
}

func sourceFolder(t *testing.T) string {
	t.Helper()
	src := filepath.Join(t.TempDir(), "My Blog")
	for path, text := range map[string]string{"compose.yml": wordpress, "config/app.conf": "x=1\n", "node_modules/pkg/i.js": "//", ".git/HEAD": "ref"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(src, path)), 0o755); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(src, path), []byte(text), 0o644)
	}
	return src
}

const cleanConfig = `{"name":"x","services":{"wordpress":{"image":"w","expose":["80"]},"db":{"image":"m"}}}`

func TestImportingAFolderCopiesItAndEditsOnlyWhatItMust(t *testing.T) {
	a, out, root := importApp(t, "", cleanConfig)
	a.Interactive = false
	src := sourceFolder(t)
	s, err := a.importCompose(root, "ws", Namespace{"yes": true}, scaffold.AddArgs{}, src)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if s.name != "my-blog" || s.main != "wordpress" || !s.web || s.port != "80" || s.files != 2 {
		t.Fatalf("spec: %+v", s)
	}
	got, _ := os.ReadFile(filepath.Join(root, "services", "my-blog", "compose.yml"))
	for _, want := range []string{"# a small blog", "image: docker.io/library/wordpress:6   # the app", "expose:\n      - \"80\"", `"dashboard.port=80"`, `"dashboard.scope=private"`, `"dashboard.name=My-Blog"`, "restart: always"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("compose lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(string(got), "8080:80") || strings.Contains(string(got), "ports:") {
		t.Errorf("ports were kept:\n%s", got)
	}
	if _, err := os.Stat(filepath.Join(root, "services", "my-blog", "config", "app.conf")); err != nil {
		t.Errorf("the config file next to it was not copied: %v", err)
	}
	for _, left := range []string{".git", "node_modules"} {
		if _, err := os.Stat(filepath.Join(root, "services", "my-blog", left)); err == nil {
			t.Errorf("%s was copied", left)
		}
	}
	for _, want := range []string{"Policy check: nothing om would refuse", "wordpress: ports 8080:80 becomes expose 80", "left out 2", "http://ws.my-blog.localhost"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	if orig, _ := os.ReadFile(filepath.Join(src, "compose.yml")); string(orig) != wordpress {
		t.Error("the source file was changed")
	}
}

func TestWithoutATerminalNothingIsKeptUntilYes(t *testing.T) {
	a, out, root := importApp(t, "", cleanConfig)
	a.Interactive = false
	_, err := a.importCompose(root, "ws", Namespace{}, scaffold.AddArgs{}, sourceFolder(t))
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("%v", err)
	}
	if _, e := os.Stat(filepath.Join(root, "services", "my-blog")); e == nil {
		t.Fatalf("the staged copy was left behind\n%s", out)
	}
}

func TestInteractiveImportAsksWhichServiceHasThePageAndCustomises(t *testing.T) {
	script := strings.Join([]string{
		"blog",        // the name
		"1",           // wordpress has the web page
		"2",           // customise more
		"2", "2", "7", // outbound: learn, done
		"1", // add it
	}, "\n") + "\n"
	a, out, root := importApp(t, script, cleanConfig)
	s, err := a.importCompose(root, "ws", Namespace{}, scaffold.AddArgs{}, sourceFolder(t))
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	got, _ := os.ReadFile(s.composeFile)
	if !strings.Contains(string(got), `"om.egress=learn"`) || s.name != "blog" {
		t.Fatalf("%s\n%s", got, out)
	}
	if !strings.Contains(out.String(), "Which service has the web page?") || !strings.Contains(out.String(), "port 80") {
		t.Errorf("never asked which service:\n%s", out)
	}
}

func TestCancellingRemovesTheStagedCopy(t *testing.T) {
	a, _, root := importApp(t, "blog\n1\n3\n", cleanConfig) // name, service, Cancel
	if _, err := a.importCompose(root, "ws", Namespace{}, scaffold.AddArgs{}, sourceFolder(t)); !errors.Is(err, wizard.ErrCancelled) {
		t.Fatalf("%v", err)
	}
	if _, e := os.Stat(filepath.Join(root, "services", "blog")); e == nil {
		t.Fatal("the copy stayed")
	}
}

func TestWhatOmWouldRefuseIsReportedBeforeAnythingIsKept(t *testing.T) {
	bad := `{"services":{"wordpress":{"image":"w","privileged":true}}}`
	a, out, root := importApp(t, "", bad)
	a.Interactive = false
	if _, err := a.importCompose(root, "ws", Namespace{"yes": true}, scaffold.AddArgs{}, sourceFolder(t)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "om start would refuse this until you fix") {
		t.Fatalf("no policy report:\n%s", out)
	}
}

func TestAFileAloneAndBadSourcesAreHandled(t *testing.T) {
	a, out, root := importApp(t, "", cleanConfig)
	a.Interactive = false
	alone := filepath.Join(t.TempDir(), "docker-compose.yml")
	os.WriteFile(alone, []byte(wordpress), 0o644)
	s, err := a.importCompose(root, "ws", Namespace{"yes": true}, scaffold.AddArgs{Name: "solo"}, alone)
	if err != nil || s.files != 1 || !strings.Contains(out.String(), "refers to files next to it") {
		t.Fatalf("%v %+v\n%s", err, s, out)
	}
	for name, from := range map[string]string{"missing": filepath.Join(t.TempDir(), "nope"), "empty folder": t.TempDir()} {
		if _, err := a.importCompose(root, "ws", Namespace{"yes": true}, scaffold.AddArgs{Name: "x" + name[:1]}, from); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	notCompose := filepath.Join(t.TempDir(), "compose.yml")
	os.WriteFile(notCompose, []byte("name: only\n"), 0o644)
	if _, err := a.importCompose(root, "ws", Namespace{"yes": true}, scaffold.AddArgs{Name: "nc"}, notCompose); err == nil || !strings.Contains(err.Error(), "services") {
		t.Errorf("a file without services: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "services", "nc")); err == nil {
		t.Error("a failed import left its copy")
	}
}

func TestAWorkspaceIsNotCopiedIntoItself(t *testing.T) {
	a, _, root := importApp(t, "", cleanConfig)
	a.Interactive = false
	src := t.TempDir()
	os.MkdirAll(filepath.Join(src, ".om"), 0o755)
	os.WriteFile(filepath.Join(src, ".om", "config.json"), []byte("{}"), 0o644)
	os.WriteFile(filepath.Join(src, "compose.yml"), []byte(wordpress), 0o644)
	if _, err := a.importCompose(root, "ws", Namespace{"yes": true}, scaffold.AddArgs{Name: "ws2"}, src); err == nil || !strings.Contains(err.Error(), "itself an om workspace") {
		t.Fatalf("%v", err)
	}
}

// afterEdit is what the engine would print for the edited file: the same config, with the first service named for the
// workspace and the default network external.
func afterEdit(configJSON, folder string) string {
	var cfg map[string]any
	json.Unmarshal([]byte(configJSON), &cfg)
	svcs, _ := cfg["services"].(map[string]any)
	names := make([]string, 0, len(svcs))
	for n := range svcs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if _, has := svcs[n].(map[string]any)["image"]; has && n == "wordpress" || len(names) == 1 {
			sv := svcs[n].(map[string]any)
			sv["container_name"] = "ws_" + folder
			sv["networks"] = map[string]any{"default": nil}
		}
	}
	cfg["networks"] = map[string]any{"default": map[string]any{"name": "ws_net", "external": true}}
	b, _ := json.Marshal(cfg)
	return string(b)
}
