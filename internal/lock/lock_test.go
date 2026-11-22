package lock

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Chitakasa/om/internal/state"
)

func golden(t *testing.T) map[string]json.RawMessage {
	b, err := os.ReadFile("../../testdata/golden/lock.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	json.Unmarshal(b, &m)
	return m
}

func dec(t *testing.T, raw json.RawMessage, v any) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(v); err != nil {
		t.Fatal(err)
	}
}

func newLock(t *testing.T) *Lock {
	t.Setenv("OM_STATE_DIR", t.TempDir())
	return New(state.NewDirs())
}

func TestPureMatchesPython(t *testing.T) {
	g := golden(t)
	var pr map[string][]string
	dec(t, g["parse_ref"], &pr)
	for in, want := range pr {
		r := ParseRef(in)
		if got := []string{r.Registry, r.Repository, r.Tag, r.Digest}; !reflect.DeepEqual(got, want) {
			t.Errorf("ParseRef(%q) = %v, python %v", in, got, want)
		}
	}
	var dr map[string]bool
	dec(t, g["digest_re"], &dr)
	for in, want := range dr {
		if IsDigest(in) != want {
			t.Errorf("IsDigest(%q)", in)
		}
	}
	cfgs := map[string]map[string]any{
		"mixed": {"services": map[string]any{
			"web":   map[string]any{"image": "nginx:1", "labels": map[string]any{"om.update": "AUTO"}},
			"db":    map[string]any{"image": "pg:16", "labels": []any{"om.update=hold"}},
			"build": map[string]any{"image": "x", "build": ".", "labels": map[string]any{"om.update": "auto"}},
			"noimg": map[string]any{}, "none": nil,
			"bad": map[string]any{"image": "y", "labels": map[string]any{"om.update": " Weekly "}},
			"num": map[string]any{"image": "z", "labels": map[string]any{"om.update": json.Number("1")}},
		}},
		"empty": {}, "none": nil,
	}
	var um map[string][]any
	dec(t, g["update_modes"], &um)
	var im map[string]map[string]string
	dec(t, g["images"], &im)
	for k, cfg := range cfgs {
		modes, bad := UpdateModes(cfg)
		wm := map[string]string{}
		for a, b := range um[k][0].(map[string]any) {
			wm[a] = b.(string)
		}
		var wb []string
		for _, x := range um[k][1].([]any) {
			wb = append(wb, x.(string))
		}
		if !reflect.DeepEqual(modes, wm) || !reflect.DeepEqual(bad, wb) {
			t.Errorf("UpdateModes %s: %v %v, python %v %v", k, modes, bad, wm, wb)
		}
		if got := Images(cfg); !reflect.DeepEqual(got, im[k]) && !(len(got) == 0 && len(im[k]) == 0) {
			t.Errorf("Images %s: %v want %v", k, got, im[k])
		}
	}
}

func TestReadWriteOverrideResolveMatchPython(t *testing.T) {
	g := golden(t)
	l := newLock(t)
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, ".om"), 0o755)
	var reads map[string]any
	dec(t, g["read"], &reads)
	texts := map[string]*string{}
	s := func(x string) *string { return &x }
	d1, d2 := "sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64)
	texts["good"] = s(`{"version":1,"images":{"nginx:1":"` + d1 + `","bad":"nope","pg:16":"` + d2 + `","num":5}}`)
	texts["no_images"], texts["null_images"], texts["list"], texts["garbage"], texts["missing"], texts["images_list"] = s("{}"), s(`{"images":null}`), s("[1]"), s("{"), nil, s(`{"images":[1]}`)
	for name, text := range texts {
		p := filepath.Join(root, ".om", "lock.json")
		if text == nil {
			os.Remove(p)
		} else {
			os.WriteFile(p, []byte(*text), 0o644)
		}
		got := Read(root)
		want := map[string]string{}
		for k, v := range reads[name].(map[string]any) {
			want[k] = v.(string)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Read %s: %v want %v", name, got, want)
		}
	}
	var written string
	dec(t, g["written"], &written)
	if err := Write(root, map[string]string{"zz:1": d2, "aa:1": d1}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, ".om", "lock.json")); string(b) != written {
		t.Errorf("Write:\n%s\npython:\n%s", b, written)
	}

	var ov struct {
		Name      string
		Text      string
		None      any
		PinnedRef []string `json:"pinned_ref"`
	}
	dec(t, g["override"], &ov)
	cfg := map[string]any{"services": map[string]any{
		"web":   map[string]any{"image": "nginx:1", "labels": map[string]any{"om.update": "AUTO"}},
		"db":    map[string]any{"image": "pg:16"},
		"build": map[string]any{"image": "x", "build": "."},
	}}
	p, err := l.WriteOverride("w", "/p/web", cfg, map[string]string{"nginx:1": d1, "pg:16": d2})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); filepath.Base(p) != ov.Name || string(b) != ov.Text {
		t.Errorf("override %s:\n%s\npython %s:\n%s", filepath.Base(p), b, ov.Name, ov.Text)
	}
	if p, _ := l.WriteOverride("w", "/p/web", map[string]any{}, map[string]string{"x": d1}); p != "" {
		t.Error("nothing to pin")
	} else if _, err := os.Stat(filepath.Join(filepath.Dir(filepath.Join(l.D.State, "lock", "overrides", "x")), ov.Name)); err == nil {
		t.Error("the stale override must be removed")
	}
	if got := []string{PinnedRef("nginx:1", d1), PinnedRef("nginx:1@sha256:"+strings.Repeat("9", 64), d2)}; !reflect.DeepEqual(got, ov.PinnedRef) {
		t.Errorf("PinnedRef %v want %v", got, ov.PinnedRef)
	}

	var rs map[string][]any
	dec(t, g["resolve"], &rs)
	reg := map[string]string{"a": d1, "b": d2}
	loc := map[string]string{"b": "sha256:" + strings.Repeat("3", 64), "c": "sha256:" + strings.Repeat("4", 64)}
	cur := map[string]string{"a": "sha256:" + strings.Repeat("5", 64), "d": "sha256:" + strings.Repeat("6", 64)}
	l.Client = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		// stand in for the registry: HEAD manifests/<tag> answers with the digest of reg[repo]
		repo := strings.Split(r.URL.Path, "/")[3] // /v2/library/<name>/manifests/<tag>
		h := http.Header{}
		if d, ok := reg[repo]; ok {
			h.Set("Docker-Content-Digest", d)
			return &http.Response{StatusCode: 200, Header: h, Body: http.NoBody, Request: r}, nil
		}
		return &http.Response{StatusCode: 404, Header: h, Body: http.NoBody, Request: r}, nil
	})}
	l.Run = func(c []string) state.Result {
		ref := c[len(c)-1]
		if d, ok := loc[ref]; ok {
			return state.Result{Stdout: `["` + ref + `@` + d + `"]`}
		}
		return state.Result{Stdout: "[]"}
	}
	for _, c := range []struct {
		name    string
		refs    []string
		cur     map[string]string
		refresh bool
	}{{"False", []string{"a", "b", "c", "d", "e", "a"}, cur, false}, {"True", []string{"a", "b", "c", "d", "e", "a"}, cur, true}, {"empty", nil, nil, false}} {
		pinned, missing := l.Resolve("podman", c.refs, c.cur, c.refresh)
		want := rs[c.name]
		wp := map[string]string{}
		for k, v := range want[0].(map[string]any) {
			wp[k] = v.(string)
		}
		var wm []string
		for _, x := range want[1].([]any) {
			wm = append(wm, x.(string))
		}
		if !reflect.DeepEqual(pinned, wp) || !reflect.DeepEqual(missing, wm) {
			t.Errorf("Resolve %s: %v %v, python %v %v", c.name, pinned, missing, wp, wm)
		}
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// A TLS server stands in for a registry with token auth.
func registry(t *testing.T, handler http.HandlerFunc) (*Lock, *httptest.Server) {
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	l := newLock(t)
	l.Client = &http.Client{Timeout: 5e9, CheckRedirect: stripAuthOnRedirect,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	l.Host = func(string) string { return strings.TrimPrefix(srv.URL, "https://") }
	return l, srv
}

func TestAnonymousTokenFlow(t *testing.T) {
	d := "sha256:" + strings.Repeat("7", 64)
	var gotQuery, gotAuth string
	var srv *httptest.Server
	l, s := registry(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			gotQuery = r.URL.RawQuery
			json.NewEncoder(w).Encode(map[string]string{"token": "tok123"})
		case strings.Contains(r.URL.Path, "/manifests/"):
			if r.Header.Get("Authorization") != "Bearer tok123" {
				w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv.URL+`/token",service="registry.test",scope="repository:library/nginx:pull"`)
				w.WriteHeader(401)
				return
			}
			gotAuth = r.Header.Get("Authorization")
			w.Header().Set("Docker-Content-Digest", d)
			w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
		}
	})
	srv = s
	if got := l.RegistryDigest("nginx:1.31"); got != d {
		t.Fatalf("digest %q", got)
	}
	if gotAuth != "Bearer tok123" || !strings.Contains(gotQuery, "service=registry.test") || !strings.Contains(gotQuery, "scope=repository:library/nginx%3Apull") && !strings.Contains(gotQuery, "scope=repository%3Alibrary") {
		t.Fatalf("token request %q auth %q", gotQuery, gotAuth)
	}
	// a pinned ref never asks the registry
	if got := l.RegistryDigest("nginx@" + d); got != d {
		t.Fatal(got)
	}
}

func TestTokenFlowRefusals(t *testing.T) {
	// a realm that is not https is never contacted
	hits := 0
	l, srv := registry(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("WWW-Authenticate", `Bearer realm="http://127.0.0.1:1/token",service="x"`)
		w.WriteHeader(401)
	})
	_ = srv
	if got := l.RegistryDigest("nginx:1"); got != "" || hits != 1 {
		t.Fatalf("%q %d", got, hits)
	}
	// a second 401 after authenticating gives up (no loop)
	hits = 0
	var srv2 *httptest.Server
	l2, s2 := registry(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Write([]byte(`{"access_token":"t"}`))
			return
		}
		hits++
		w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv2.URL+`/token"`)
		w.WriteHeader(401)
	})
	srv2 = s2
	if got := l2.RegistryDigest("nginx:1"); got != "" || hits != 2 {
		t.Fatalf("%q %d", got, hits)
	}
	// a non-Bearer challenge is not followed
	l3, _ := registry(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="x"`)
		w.WriteHeader(401)
	})
	if l3.RegistryDigest("nginx:1") != "" {
		t.Fatal("basic auth")
	}
}

func TestRedirectDropsAuthorization(t *testing.T) {
	var cdnAuth string
	cdn := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cdnAuth = r.Header.Get("Authorization")
		w.Write([]byte(`{"created":"2024-05-06T07:08:09Z"}`))
	}))
	defer cdn.Close()
	cfgDigest := "sha256:" + strings.Repeat("c", 64)
	var srv *httptest.Server
	l, s := registry(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			w.Write([]byte(`{"token":"secret"}`))
		case r.Header.Get("Authorization") == "":
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv.URL+`/token"`)
			w.WriteHeader(401)
		case strings.Contains(r.URL.Path, "/blobs/"):
			http.Redirect(w, r, cdn.URL+"/blob", 307)
		default: // a single-platform manifest
			json.NewEncoder(w).Encode(map[string]any{"layers": []map[string]any{{"size": 100}, {"size": 23}}, "config": map[string]string{"digest": cfgDigest}})
		}
	})
	srv = s
	got, ok := l.Describe("nginx:1", "sha256:"+strings.Repeat("d", 64))
	if !ok || got.Size != 123 || got.Created != "2024-05-06" || !got.HasSize {
		t.Fatalf("%+v %v", got, ok)
	}
	if cdnAuth != "" {
		t.Fatalf("the registry token was forwarded to the CDN: %q", cdnAuth)
	}
	// nothing readable: no description
	l4, _ := registry(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) })
	if _, ok := l4.Describe("nginx:1", "sha256:"+strings.Repeat("d", 64)); ok {
		t.Fatal("404 must give nothing")
	}
}

func TestDescribePicksThisMachinesImage(t *testing.T) {
	cfg := "sha256:" + strings.Repeat("e", 64)
	idx := "sha256:" + strings.Repeat("a", 64)
	img := "sha256:" + strings.Repeat("b", 64)
	l, _ := registry(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/manifests/"+idx):
			json.NewEncoder(w).Encode(map[string]any{"manifests": []map[string]any{
				{"digest": "sha256:" + strings.Repeat("f", 64), "platform": map[string]string{"os": "windows", "architecture": platformArch()}},
				{"digest": img, "platform": map[string]string{"os": "linux", "architecture": platformArch()}},
			}})
		case strings.HasSuffix(r.URL.Path, "/manifests/"+img):
			json.NewEncoder(w).Encode(map[string]any{"layers": []map[string]any{{"size": 5}}, "config": map[string]string{"digest": cfg}})
		case strings.HasSuffix(r.URL.Path, "/blobs/"+cfg):
			w.Write([]byte(`{"created":"2023-01-02"}`))
		default:
			w.WriteHeader(404)
		}
	})
	if platformArch() == "" {
		t.Skip("unsupported architecture")
	}
	got, ok := l.Describe("nginx:1", idx)
	if !ok || got.Size != 5 || got.Created != "2023-01-02" {
		t.Fatalf("%+v %v", got, ok)
	}
}

func TestLocalDigestPrefersIndex(t *testing.T) {
	idx := "sha256:" + strings.Repeat("a", 64)
	one := "sha256:" + strings.Repeat("b", 64)
	l, _ := registry(t, func(w http.ResponseWriter, r *http.Request) {
		ct := "application/vnd.oci.image.manifest.v1+json"
		if strings.HasSuffix(r.URL.Path, idx) {
			ct = "application/vnd.oci.image.index.v1+json"
		}
		w.Header().Set("Content-Type", ct)
		w.Header().Set("Docker-Content-Digest", strings.TrimPrefix(r.URL.Path[strings.LastIndex(r.URL.Path, "/"):], "/"))
	})
	l.Run = func([]string) state.Result {
		return state.Result{Stdout: `["x@` + one + `","x@` + idx + `","x@bogus"]`}
	}
	if got := l.LocalDigest("podman", "nginx:1"); got != idx {
		t.Fatalf("%q", got)
	}
	l.Run = func([]string) state.Result { return state.Result{Stdout: "null"} }
	if got := l.LocalDigest("podman", "nginx:1"); got != "" {
		t.Fatalf("%q", got)
	}
	l.Run = func([]string) state.Result { return state.Result{Stdout: `["x@` + one + `"]`} }
	l.Client = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 404, Header: http.Header{}, Body: http.NoBody, Request: r}, nil
	})}
	if got := l.LocalDigest("podman", "nginx:1"); got != one {
		t.Fatalf("with no registry the first recorded digest: %q", got)
	}
}
