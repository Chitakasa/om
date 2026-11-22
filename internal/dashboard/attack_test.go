package dashboard

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// attackServer is a dashboard on a throwaway folder tree: wallpapers (one real, one symlink to a secret outside, one
// SVG named .png) and a registry with a workspace.
func attackServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	tmp := t.TempDir()
	for _, d := range []string{"data", "wp", "outside"} {
		os.Mkdir(filepath.Join(tmp, d), 0o755)
	}
	os.WriteFile(filepath.Join(tmp, "reg.json"), []byte(`{"perso": {"id": "perso"}}`), 0o644)
	os.WriteFile(filepath.Join(tmp, "outside", "secret.png"), []byte("\x89PNG\r\n\x1a\nTOP-SECRET"), 0o644)
	os.WriteFile(filepath.Join(tmp, "wp", "ok.png"), []byte("\x89PNG\r\n\x1a\nfine"), 0o644)
	os.Symlink(filepath.Join(tmp, "outside", "secret.png"), filepath.Join(tmp, "wp", "link.png"))
	os.WriteFile(filepath.Join(tmp, "wp", "evil.png"), []byte("<svg onload=alert(1)></svg>"), 0o644)
	s := New(Config{SocketPath: filepath.Join(tmp, "no.sock"), WallpapersDir: filepath.Join(tmp, "wp"), DataDir: filepath.Join(tmp, "data"),
		WorkspacesMount: filepath.Join(tmp, "ws"), Registry: filepath.Join(tmp, "reg.json"), PrivateBase: 20000, PublicBase: 21000, MeminfoPath: "/nonexistent"})
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts, tmp
}

func do(t *testing.T, ts *httptest.Server, method, path string, headers map[string]string, body []byte) (int, http.Header, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.URL+path, r)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "localhost"
	for k, v := range headers {
		if k == "Host" {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, b
}

func TestNoTraversalSymlinkOrAbsolutePathReadsOutsideTheWallpaperFolders(t *testing.T) {
	ts, tmp := attackServer(t)
	for _, p := range []string{"../outside/secret.png", "..%2Foutside%2Fsecret.png", "%2e%2e/outside/secret.png", filepath.Join(tmp, "outside", "secret.png"),
		"link.png", "ok.png%00.png", "....//outside/secret.png", "/etc/passwd", `..\outside\secret.png`, ".hidden"} {
		_, _, body := do(t, ts, "GET", "/api/wallpaper/preview_host?path="+p, nil, nil)
		if bytes.Contains(body, []byte("TOP-SECRET")) || bytes.Contains(body, []byte("root:")) {
			t.Errorf("path %q leaked: %q", p, body)
		}
	}
	if code, _, _ := do(t, ts, "GET", "/api/wallpaper/preview_host?path=ok.png", nil, nil); code != 200 {
		t.Errorf("a real wallpaper answers %d", code)
	}
}

func TestAnSVGNamedPNGIsNeverServedAsAnImageType(t *testing.T) {
	ts, _ := attackServer(t)
	_, h, _ := do(t, ts, "GET", "/api/wallpaper/preview_host?path=evil.png", nil, nil)
	if got := h.Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("Content-Type %q", got)
	}
}

func TestHostsThatAreNotThisMachineAreRefused(t *testing.T) {
	ts, _ := attackServer(t)
	for _, h := range []string{"attacker.example", "localhost.attacker.example", "127.0.0.1.attacker.example", "localhost@evil", "evil.com#localhost", "LOCALHOST.EVIL.COM"} {
		if code, _, _ := do(t, ts, "GET", "/api/services", map[string]string{"Host": h}, nil); code != 403 {
			t.Errorf("Host %q answered %d", h, code)
		}
	}
	// a private address is the LAN tier: not refused, but it never gets private data
	for _, h := range []string{"0.0.0.0", "169.254.169.254", "10.1.2.3", "192.168.1.9", "[fe80::1]"} {
		for _, p := range []string{"/api/system", "/api/wallpapers"} {
			if code, _, _ := do(t, ts, "GET", p, map[string]string{"Host": h}, nil); code != 403 {
				t.Errorf("Host %q on %s answered %d", h, p, code)
			}
		}
	}
	for _, h := range []string{"localhost", "LOCALHOST", "127.0.0.1:8080", "[::1]", "app.localhost", "ws.dashboard.localhost"} {
		if code, _, _ := do(t, ts, "GET", "/api/services", map[string]string{"Host": h}, nil); code != 200 {
			t.Errorf("Host %q answered %d", h, code)
		}
	}
}

func TestAClientCannotRaiseItsPrivilegeWithHeaders(t *testing.T) {
	ts, _ := attackServer(t)
	for _, h := range []map[string]string{{"X-Access-Scope": "private"}, {"X-Access-Scope": ""},
		{"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1", "Forwarded": "for=127.0.0.1"}} {
		if code, _, _ := do(t, ts, "GET", "/api/system", h, nil); code != 200 { // nothing a client sends makes it more private
			t.Errorf("%v answered %d", h, code)
		}
	}
	if code, _, _ := do(t, ts, "GET", "/api/system", map[string]string{"X-Access-Scope": "public"}, nil); code != 403 { // but it can lower itself
		t.Errorf("public scope answered %d", code)
	}
	if code, _, _ := do(t, ts, "GET", "/api/system", map[string]string{"Host": "192.168.1.20"}, nil); code != 403 {
		t.Errorf("a LAN address answered %d", code)
	}
}

func TestStateChangingRequestsNeedTheSameOrigin(t *testing.T) {
	ts, _ := attackServer(t)
	for _, extra := range []map[string]string{{"Origin": "https://evil.example"}, {"Origin": "http://localhost.evil.example"}, {"Sec-Fetch-Site": "cross-site"}, {"Origin": "null"}} {
		if code, _, _ := do(t, ts, "POST", "/api/wallpaper/settings", extra, []byte(`{"dim": 1}`)); code != 403 {
			t.Errorf("%v answered %d", extra, code)
		}
	}
	if code, _, _ := do(t, ts, "POST", "/api/wallpaper/settings", map[string]string{"Origin": "http://localhost"}, []byte(`{"dim": 1}`)); code != 200 {
		t.Errorf("the same origin answered %d", code)
	}
}

func TestOversizedOrMalformedBodiesAreRefusedWithoutBeingRead(t *testing.T) {
	ts, _ := attackServer(t)
	req, _ := http.NewRequest("POST", ts.URL+"/api/wallpaper/upload", io.LimitReader(zeros{}, 0))
	req.Host, req.ContentLength = "localhost", 25*1024*1024
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err == nil {
		if resp.StatusCode != 413 {
			t.Errorf("an oversized upload answered %d", resp.StatusCode)
		}
		resp.Body.Close()
	}
	for _, length := range []string{"-1", "abc", "1e9", ""} {
		req, _ := http.NewRequest("POST", ts.URL+"/api/wallpaper/settings", nil)
		req.Host = "localhost"
		req.Header.Set("Content-Length", length)
		if resp, err := http.DefaultTransport.RoundTrip(req); err == nil {
			if resp.StatusCode != 400 && resp.StatusCode != 413 {
				t.Errorf("Content-Length %q answered %d", length, resp.StatusCode)
			}
			resp.Body.Close()
		}
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { return 0, io.EOF }

func TestWorkspaceParametersNeverBecomePaths(t *testing.T) {
	ts, tmp := attackServer(t)
	for _, ws := range []string{"../../outside", "..%2f..%2foutside", "core/../x", "perso/../../x", strings.Repeat("a", 500), "x%0Ay", "%00"} {
		do(t, ts, "POST", "/api/wallpaper/settings?workspace="+ws, nil, []byte(`{"dim": 2}`))
		do(t, ts, "GET", "/api/wallpaper/current?workspace="+ws, nil, nil)
	}
	ents, _ := os.ReadDir(tmp)
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	for _, n := range names {
		switch n {
		case "data", "wp", "outside", "reg.json":
		default:
			t.Errorf("a request created %q in the tree", n)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(tmp), "outside")); err == nil {
		t.Error("a request created a folder outside the tree")
	}
}

func TestResponsesCarryTheProtectiveHeaders(t *testing.T) {
	ts, _ := attackServer(t)
	_, h, _ := do(t, ts, "GET", "/", nil, nil)
	csp := h.Get("Content-Security-Policy")
	if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("X-Frame-Options") != "SAMEORIGIN" ||
		!strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "unsafe-eval") || !strings.Contains(csp, "frame-ancestors 'self'") {
		t.Errorf("headers %v", h)
	}
}

func TestABadUploadKeepsTheCurrentWallpaper(t *testing.T) {
	ts, tmp := attackServer(t)
	png := append([]byte("\x89PNG\r\n\x1a\n"), []byte("first")...)
	if code, _, _ := do(t, ts, "POST", "/api/wallpaper/upload?name=a.png", nil, png); code != 200 {
		t.Fatalf("upload answered %d", code)
	}
	if code, _, _ := do(t, ts, "POST", "/api/wallpaper/upload?name=b.png", nil, []byte("<svg>not an image</svg>")); code != 400 {
		t.Errorf("a non-image upload answered %d", code)
	}
	got, _ := os.ReadFile(filepath.Join(tmp, "data", "current_wallpaper"))
	if !bytes.Equal(got, png) {
		t.Errorf("the current wallpaper was replaced by %q", got)
	}
	left, _ := filepath.Glob(filepath.Join(tmp, "data", ".upload-*"))
	if len(left) != 0 {
		t.Errorf("temp files left behind: %v", left)
	}
}

// ---- how a container becomes a card ----

func TestServiceEntryShapes(t *testing.T) {
	s := New(Config{SocketPath: "/nonexistent", WallpapersDir: t.TempDir(), DataDir: t.TempDir(), Registry: "/nonexistent",
		PrivateBase: 20000, PublicBase: 21000})
	entry := func(c map[string]any) *Service { return s.serviceEntry(c, map[string]int{"demo/web": 3}) }
	mk := func(name string, labels map[string]any, extra map[string]any) map[string]any {
		c := map[string]any{"Id": "abcdef0123456789", "Names": []any{"/" + name}, "State": "running", "Status": "Up", "Labels": labels, "Ports": []any{}}
		for k, v := range extra {
			c[k] = v
		}
		return c
	}
	ports := func(p ...int) []any {
		var out []any
		for _, n := range p {
			out = append(out, map[string]any{"PrivatePort": float64(n)})
		}
		return out
	}
	if e := entry(mk("demo_web", map[string]any{"dashboard.scope": "public", "dashboard.search": "true"}, map[string]any{"Ports": ports(8080)})); e == nil ||
		!e.public() || !e.IsSearch || e.SearchURL != "/search?q={searchTerms}" || e.PortPublic == nil || *e.PortPublic != 21003 || *e.PortPrivate != 20003 {
		t.Errorf("a public search service: %+v", e)
	}
	if e := entry(mk("demo_job", nil, map[string]any{"State": "exited", "Status": "Exited (3) 1 minute ago"})); e == nil || e.HasWeb || e.Port != nil || e.ExitCode != 3 || e.State != "exited" {
		t.Errorf("an exited container without ports is not a web service: %+v", e)
	}
	if e := entry(mk("demo_x", nil, map[string]any{"Ports": ports(443, 80, 9000)})); e == nil || e.Port == nil || *e.Port != 9000 {
		t.Errorf("the port choice skips 80 and 443: %+v", e)
	}
	if e := entry(mk("demo_x", nil, map[string]any{"Ports": ports(443, 80)})); e == nil || *e.Port != 443 {
		t.Errorf("only 80 and 443: the first one: %+v", e)
	}
	if e := entry(mk("demo_x", map[string]any{"dashboard.port": "nope"}, map[string]any{"Ports": ports(7000)})); e == nil || *e.Port != 7000 {
		t.Errorf("an unreadable port label falls back: %+v", e)
	}
	if e := entry(mk("demo_x", map[string]any{"dashboard.web": "false"}, map[string]any{"Ports": ports(7000)})); e == nil || e.HasWeb {
		t.Errorf("dashboard.web=false: %+v", e)
	}
	if e := entry(mk("lab_db", map[string]any{"workspace.id": "ws1"}, nil)); e == nil || e.WorkspaceID != "ws1" || e.Key != "lab_db" {
		t.Errorf("the workspace comes from the label first: %+v", e)
	}
	if e := entry(mk("lab_db", nil, nil)); e == nil || e.WorkspaceID != "lab" || e.Key != "db" {
		t.Errorf("then from the name: %+v", e)
	}
	if e := entry(mk("single", nil, nil)); e == nil || e.WorkspaceID != "uncategorized" {
		t.Errorf("a name without a workspace: %+v", e)
	}
	for _, name := range []string{"om_caddy", "om_dashboard", "om_router"} {
		if entry(mk(name, nil, nil)) != nil {
			t.Errorf("%s is hidden", name)
		}
	}
	if entry(mk("x_y", map[string]any{"dashboard.hide": "TRUE"}, nil)) != nil || entry(mk("om_egress", map[string]any{"om.core": "true"}, nil)) != nil {
		t.Error("hidden and core containers have no card")
	}
	if e := entry(mk("om_egress", map[string]any{"om.core": "true", "dashboard.name": "Egress"}, nil)); e == nil {
		t.Error("a core container with its own name is shown")
	}
	if st, code := containerState(map[string]any{"State": map[string]any{"Status": "Exited", "ExitCode": float64(2)}}); st != "exited" || code != 2 {
		t.Errorf("the dict state shape: %s %d", st, code)
	}
}
