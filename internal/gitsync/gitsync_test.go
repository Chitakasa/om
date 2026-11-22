package gitsync

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

type scenario struct {
	Name   string
	Kind   string
	Setup  [][]string
	Config string
	Op     struct {
		Kind             string
		Force, Rebase    bool
		Health           *bool
		Verify           *bool
		DirtyInReconcile bool `json:"dirty_in_reconcile"`
	}
}

func gitEnv(t *testing.T) {
	for k, v := range map[string]string{
		"GIT_CONFIG_GLOBAL": os.DevNull, "GIT_CONFIG_SYSTEM": os.DevNull,
		"GIT_AUTHOR_NAME": "T", "GIT_AUTHOR_EMAIL": "t@e.x", "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@e.x",
		"GIT_AUTHOR_DATE": "2026-01-01T00:00:00+0000", "GIT_COMMITTER_DATE": "2026-01-01T00:00:00+0000",
	} {
		t.Setenv(k, v)
	}
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	c := exec.Command("git", args...)
	c.Dir = dir
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestScenariosMatchPython(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the goldens were recorded on POSIX and hold / paths")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	gitEnv(t)
	var spec struct{ Scenarios []scenario }
	b, err := os.ReadFile("../../testdata/gitsync_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(b, &spec)
	var golden map[string]struct {
		Stdout string
		Result *bool
		Kinds  []string
		Log    []string
	}
	b, _ = os.ReadFile("../../testdata/golden/gitsync.json")
	json.Unmarshal(b, &golden)
	hex8 := regexp.MustCompile(`\b[0-9a-f]{8}\b`)
	fromURL := regexp.MustCompile(`From \S+|'(/|[A-Za-z]:)[^']*'`) // git names the remote's path (whatever the temp dir is called)

	for _, sc := range spec.Scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			tmp := t.TempDir()
			root := filepath.Join(tmp, "local")
			if sc.Kind == "plain" {
				os.MkdirAll(root, 0o755)
			} else {
				git(t, tmp, "init", "-q", "--bare", "-b", "main", filepath.Join(tmp, "origin.git"))
				git(t, tmp, "clone", "-q", filepath.Join(tmp, "origin.git"), "local")
				os.MkdirAll(filepath.Join(root, ".om"), 0o755)
				cfg := sc.Config
				if cfg == "" {
					cfg = `{"workspace_id":"w"}`
				}
				os.WriteFile(filepath.Join(root, ".om", "config.json"), []byte(cfg), 0o644)
				os.WriteFile(filepath.Join(root, "README"), []byte("init"), 0o644)
				git(t, root, "add", ".")
				git(t, root, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "initial")
				git(t, root, "branch", "-M", "main")
				git(t, root, "push", "-q", "origin", "main")
				git(t, tmp, "clone", "-q", "-b", "main", filepath.Join(tmp, "origin.git"), "other")
				for _, st := range sc.Setup {
					who, what := st[0], st[1]
					switch {
					case who == "origin" && what == "delete":
						os.RemoveAll(filepath.Join(tmp, "origin.git"))
					case what == "no_remote":
						git(t, root, "remote", "remove", "origin")
					case what == "write":
						os.WriteFile(filepath.Join(root, st[2]), []byte(st[3]), 0o644)
					case what == "commit":
						d := filepath.Join(tmp, who)
						os.WriteFile(filepath.Join(d, st[2]), []byte(st[3]), 0o644)
						git(t, d, "add", ".")
						git(t, d, "-c", "commit.gpgsign=false", "commit", "-q", "-m", st[4])
						if who == "other" {
							git(t, d, "push", "-q", "origin", "main")
						}
					}
				}
			}
			var out bytes.Buffer
			s := New(&out, "http://127.0.0.1:1", filepath.Join(tmp, "routes"))
			healthy := sc.Op.Health == nil || *sc.Op.Health
			s.Health = func([]string) bool { return healthy }
			var kinds []string
			reconcile := func(kind string) {
				kinds = append(kinds, kind)
				if sc.Op.DirtyInReconcile && kind == "sync" {
					os.WriteFile(filepath.Join(root, "surprise"), []byte("x"), 0o644)
				}
			}
			var verify func(string) bool
			if sc.Op.Verify != nil {
				v := *sc.Op.Verify
				verify = func(string) bool { return v }
			}
			var res *bool
			if sc.Op.Kind == "report" {
				s.PrintDriftReport(root, "main")
			} else {
				r := s.SyncWorkspace(root, "main", sc.Op.Force, sc.Op.Rebase, reconcile, verify)
				res = &r
			}
			want := golden[sc.Name]
			norm := func(s string) string {
				return fromURL.ReplaceAllString(hex8.ReplaceAllString(s, "H8"), "@REMOTE@")
			}
			if got := norm(out.String()); got != norm(want.Stdout) {
				t.Errorf("output\n go:\n%s\n python:\n%s", got, norm(want.Stdout))
			}
			if (res == nil) != (want.Result == nil) || (res != nil && *res != *want.Result) {
				t.Errorf("result %v want %v", res, want.Result)
			}
			if !reflect.DeepEqual(kinds, want.Kinds) && !(len(kinds) == 0 && len(want.Kinds) == 0) {
				t.Errorf("reconcile calls %v want %v", kinds, want.Kinds)
			}
			if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
				log := strings.Split(git(t, root, "log", "--format=%s")+"\n", "\n")
				if !reflect.DeepEqual(log, want.Log) {
					t.Errorf("log %q want %q", log, want.Log)
				}
			}
		})
	}
}

func TestVhostsAndHealthProbe(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "w-web.caddy"), []byte("# c\nhttp://w.web.localhost {\n  x\n}\nhttp://:20001 {\n}\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "w-api.caddy"), []byte("http://other.api.localhost {\n}\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "w-db.caddy"), []byte("  http://w.db.localhost   {\n"), 0o644)
	s := New(&bytes.Buffer{}, "", dir)
	want := []string{"w.dashboard.localhost", "w.db.localhost", "w.web.localhost"}
	if got := s.WorkspaceVhosts("w"); !reflect.DeepEqual(got, want) {
		t.Fatalf("%v want %v", got, want)
	}

	// 5xx and refused are unhealthy, 4xx (login) is healthy, the Host header picks the vhost
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Host+"|"+r.Header.Get("User-Agent"))
		switch r.Host {
		case "bad.localhost":
			w.WriteHeader(502)
		case "login.localhost":
			w.WriteHeader(401)
		}
	}))
	defer srv.Close()
	var out bytes.Buffer
	clock := time.Unix(1000, 0)
	s = New(&out, srv.URL, dir)
	s.Now = func() time.Time { return clock }
	s.Sleep = func(d time.Duration) { clock = clock.Add(d) }
	if !s.SyntheticHealthCheck([]string{"ok.localhost", "login.localhost"}, 10*time.Second) {
		t.Fatal("200 and 401 are healthy")
	}
	if seen[0] != "ok.localhost|om-healthcheck/1.0" {
		t.Fatal(seen)
	}
	if s.SyntheticHealthCheck([]string{"ok.localhost", "bad.localhost"}, 5*time.Second) {
		t.Fatal("502 is unhealthy")
	}
	if !strings.Contains(out.String(), "✗ bad.localhost unhealthy") || strings.Contains(out.String(), "ok.localhost unhealthy") {
		t.Fatal(out.String())
	}
	if clock.Sub(time.Unix(1000, 0)) < 5*time.Second {
		t.Fatalf("it must keep trying until the deadline: %v", clock)
	}
	srv.Close()
	out.Reset()
	if s.SyntheticHealthCheck([]string{"x.localhost"}, 3*time.Second) || !strings.Contains(out.String(), "x.localhost unhealthy") {
		t.Fatal("refused connections are unhealthy")
	}
	if !s.SyntheticHealthCheck(nil, time.Second) {
		t.Fatal("no hosts is healthy")
	}
	_ = fmt.Sprint
}
