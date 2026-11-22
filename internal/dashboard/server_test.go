package dashboard

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		rel, _ := filepath.Rel(src, p)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, _ := os.ReadFile(p)
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
}

// fakeEngine serves containers.json and stats-<id>.json from dir on a unix socket.
func fakeEngine(t *testing.T, dir, sock string) {
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var file string
		switch {
		case strings.HasPrefix(r.URL.Path, "/containers/json"):
			file = "containers.json"
		case strings.HasSuffix(r.URL.Path, "/stats"):
			file = "stats-" + strings.Split(r.URL.Path, "/")[2] + ".json"
		}
		b, err := os.ReadFile(filepath.Join(dir, file))
		if file == "" || err != nil {
			w.WriteHeader(404)
			return
		}
		w.Write(b)
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
}

var (
	etagRe = regexp.MustCompile(`"\d+-(\d+)"`)
	tsRe   = regexp.MustCompile(`"timestamp": \d+`)
	hostRe = regexp.MustCompile(`"host_[a-z_]+": ("[^"]*"|\d+)`)
)

func norm(s string) string {
	return hostRe.ReplaceAllString(tsRe.ReplaceAllString(etagRe.ReplaceAllString(s, `"M-$1"`), `"timestamp": T`), `"host": H`)
}

// TestMatchesPython replays requests recorded from the Python server (testdata/golden.json) against this one.
func TestMatchesPython(t *testing.T) {
	wd := t.TempDir()
	copyTree(t, "testdata/fx", wd)
	sock := filepath.Join(os.TempDir(), "omdash-"+filepath.Base(wd)+".sock")
	fakeEngine(t, wd, sock)
	t.Cleanup(func() { os.Remove(sock) })
	cfg := Config{SocketPath: sock, WallpapersDir: wd + "/wallpapers", DataDir: wd + "/data", WorkspacesMount: wd + "/workspaces",
		Registry: wd + "/registry/workspaces.json", PrivateBase: 20000, PublicBase: 21000, MeminfoPath: "/nonexistent",
		VPNHosts: []string{"vpn.test", "10.8.0.1"}}
	s := New(cfg)
	if !s.pollStats() {
		t.Fatal("stats poll failed")
	}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	var golden []struct {
		Req struct {
			M, P    string
			H       map[string]string
			Body    *string
			BodyHex *string
		}
		Status  int
		Headers map[string]string
		Body    string
		Bin     bool
	}
	b, _ := os.ReadFile("testdata/golden.json")
	if err := json.Unmarshal(b, &golden); err != nil {
		t.Fatal(err)
	}
	lastETag := ""
	for i, g := range golden {
		var body io.Reader
		var raw []byte
		switch {
		case g.Req.Body != nil:
			raw = []byte(*g.Req.Body)
		case g.Req.BodyHex != nil:
			raw, _ = hex.DecodeString(*g.Req.BodyHex)
		}
		if raw != nil {
			body = strings.NewReader(string(raw))
		}
		req, _ := http.NewRequest(g.Req.M, ts.URL+g.Req.P, body)
		if raw != nil {
			req.ContentLength = int64(len(raw))
		}
		for k, v := range g.Req.H {
			if k == "Host" {
				req.Host = v
			} else if k == "If-None-Match" {
				req.Header.Set(k, lastETag)
			} else {
				req.Header.Set(k, v)
			}
		}
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			t.Fatalf("%d %s %s: %v", i, g.Req.M, g.Req.P, err)
		}
		rb, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if e := resp.Header.Get("ETag"); e != "" {
			lastETag = e
		}
		label := g.Req.M + " " + g.Req.P + " " + g.Req.H["Host"]
		if resp.StatusCode != g.Status {
			t.Errorf("%d %s: status %d, python %d\n%s", i, label, resp.StatusCode, g.Status, rb)
			continue
		}
		for k, want := range g.Headers {
			if k == "Content-Length" || k == "Content-Type" && false {
				continue
			}
			if got := resp.Header.Get(k); norm(got) != norm(want) {
				t.Errorf("%d %s: header %s\n go:     %s\n python: %s", i, label, k, got, want)
			}
		}
		want := g.Body
		if g.Bin {
			d, _ := base64.StdEncoding.DecodeString(want)
			want = string(d)
		}
		if g.Req.M != "HEAD" && norm(string(rb)) != norm(want) {
			t.Errorf("%d %s: body\n go:     %.400s\n python: %.400s", i, label, rb, want)
		}
	}
}

func TestDeclaredRoutesAreServed(t *testing.T) {
	s := New(Config{SocketPath: "/nonexistent", WallpapersDir: t.TempDir(), DataDir: t.TempDir(), Registry: "/nonexistent", MeminfoPath: "/nonexistent"})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	for _, p := range GetRoutes {
		resp, err := http.Get(ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 404 && strings.Contains(string(b), "Endpoint not found") {
			t.Errorf("GET %s is declared but not served", p)
		}
	}
	for _, p := range PostRoutes {
		req, _ := http.NewRequest("POST", ts.URL+p, strings.NewReader("{}"))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 404 && strings.Contains(string(b), "Not Found") {
			t.Errorf("POST %s is declared but not served", p)
		}
	}
	resp, _ := http.Get(ts.URL + "/api/not-declared")
	if resp.StatusCode != 404 {
		t.Errorf("an undeclared API path answers %d", resp.StatusCode)
	}
}
