package generations

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Chitakasa/om/internal/settings"
	"github.com/Chitakasa/om/internal/state"
)

func loadGolden(t *testing.T) map[string]json.RawMessage {
	b, err := os.ReadFile("../../testdata/golden/generations.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func decode(t *testing.T, raw json.RawMessage, v any) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		t.Fatal(err)
	}
}

type fakeGit struct {
	commit, status string
	code           int
	show           string
	showCode       int
	vc             [3]any
}

func newGen(t *testing.T) (*Gen, *fakeGit, string) {
	root := t.TempDir()
	t.Setenv("OM_STATE_DIR", filepath.Join(root, "state"))
	d := state.NewDirs()
	fg := &fakeGit{commit: "c0ffee" + strings.Repeat("0", 34)}
	g := &Gen{D: d,
		Now:       func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("x", 3600)) },
		GitGlobal: func(string) string { return "" },
		LookPath:  func(string) (string, error) { return "", os.ErrNotExist },
		Keygen:    func([]string, string) state.Result { return state.Result{Code: 127} },
	}
	g.Git = func(_ string, args ...string) (int, string, string) {
		switch {
		case len(args) >= 2 && args[0] == "rev-parse" && args[1] == "HEAD":
			return fg.code, fg.commit, ""
		case len(args) >= 2 && args[0] == "status":
			return 0, fg.status, ""
		case len(args) > 0 && args[0] == "show":
			return fg.showCode, fg.show, ""
		}
		for _, a := range args {
			if a == "verify-commit" {
				return fg.vc[0].(int), fg.vc[1].(string), fg.vc[2].(string)
			}
		}
		return 1, "", ""
	}
	ws := filepath.Join(root, "ws")
	os.MkdirAll(filepath.Join(ws, ".om"), 0o755)
	os.WriteFile(filepath.Join(ws, ".om", "lock.json"), []byte("{\"images\":{}}\n"), 0o644)
	return g, fg, ws
}

func snap(dir string) map[string]string {
	out := map[string]string{}
	es, _ := os.ReadDir(dir)
	for _, e := range es {
		if !e.IsDir() && e.Name() != ".lock" {
			b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
			out[e.Name()] = string(b)
		}
	}
	return out
}

func TestRecordAndTamperMatchPython(t *testing.T) {
	gold := loadGolden(t)
	var rec struct {
		Entries []map[string]any
		Files   map[string]string
		Current map[string]any
		Chain   []string
	}
	decode(t, gold["record"], &rec)
	g, fg, ws := newGen(t)
	for i, c := range []struct{ kind, result, signer, status string }{{"start", "running", "me@x", ""}, {"sync", "running", "", " M f"}, {"update", "failed", "me@x", ""}} {
		fg.status = c.status
		if c.kind == "update" {
			fg.code = 1
		}
		e, err := g.Record("w", ws, c.kind, c.result, c.signer)
		if err != nil {
			t.Fatal(err)
		}
		if got := normalize(e); !reflect.DeepEqual(got, rec.Entries[i]) {
			t.Errorf("entry %d:\n go     %v\n python %v", i, got, rec.Entries[i])
		}
	}
	gdir := g.dir("w")
	if got := snap(gdir); !reflect.DeepEqual(got, rec.Files) {
		for k, v := range rec.Files {
			if got[k] != v {
				t.Errorf("file %s:\n go:\n%s\n python:\n%s", k, got[k], v)
			}
		}
	}
	if cur := g.Current("w"); normalize(cur)["n"].(json.Number).String() != rec.Current["n"].(json.Number).String() {
		t.Errorf("current %v want %v", cur, rec.Current)
	}
	if got := g.VerifyChain("w"); len(got) != 0 {
		t.Errorf("fresh chain has problems: %v", got)
	}
	fg.code = 0

	var tam map[string][]string
	decode(t, gold["tamper"], &tam)
	edit := func(d string, n int, kv map[string]any) {
		p := filepath.Join(d, itoa(n)+".json")
		b, _ := os.ReadFile(p)
		var m map[string]any
		json.Unmarshal(b, &m)
		for k, v := range kv {
			m[k] = v
		}
		out, _ := json.MarshalIndent(m, "", "  ")
		os.WriteFile(p, append(out, '\n'), 0o644)
	}
	cases := map[string]func(d string){
		"field_changed": func(d string) { edit(d, 2, map[string]any{"result": "running!"}) },
		"gap":           func(d string) { os.Remove(filepath.Join(d, "2.json")) },
		"last_dropped":  func(d string) { os.Remove(filepath.Join(d, "3.json")) },
		"corrupt":       func(d string) { os.WriteFile(filepath.Join(d, "2.json"), []byte("{not json"), 0o644) },
		"head_garbage":  func(d string) { os.WriteFile(filepath.Join(d, "head"), []byte("garbage\n"), 0o644) },
		"head_wrong_digest": func(d string) {
			os.WriteFile(filepath.Join(d, "head"), []byte("3 "+strings.Repeat("0", 64)+"\n"), 0o644)
		},
		"no_head": func(d string) { os.Remove(filepath.Join(d, "head")) },
		"empty_with_head": func(d string) {
			fs, _ := filepath.Glob(filepath.Join(d, "*.json"))
			for _, f := range fs {
				os.Remove(f)
			}
		},
		"renumbered":         func(d string) { edit(d, 3, map[string]any{"n": 7}) },
		"prev_null_mid":      func(d string) { edit(d, 2, map[string]any{"prev": nil}) },
		"nonnumeric_ignored": func(d string) { os.WriteFile(filepath.Join(d, "notes.json"), []byte("{}"), 0o644) },
		"last_rewritten":     func(d string) { edit(d, 3, map[string]any{"kind": "x"}) },
	}
	for name, mut := range cases {
		copyDir(t, gdir, filepath.Join(filepath.Dir(gdir), "tamper-"+name))
		mut(filepath.Join(filepath.Dir(gdir), "tamper-"+name))
		got := g.VerifyChain("tamper-" + name)
		if !reflect.DeepEqual(orEmpty(got), orEmpty(tam[name])) {
			t.Errorf("tamper %s:\n go     %q\n python %q", name, got, tam[name])
		}
	}
	var empty []string
	decode(t, gold["empty_log"], &empty)
	if got := g.VerifyChain("nobody"); !reflect.DeepEqual(orEmpty(got), orEmpty(empty)) {
		t.Errorf("empty log: %v", got)
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func normalize(v any) map[string]any {
	b, _ := json.Marshal(v)
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	dec.Decode(&m)
	return m
}

func copyDir(t *testing.T, from, to string) {
	os.MkdirAll(to, 0o755)
	es, _ := os.ReadDir(from)
	for _, e := range es {
		if !e.IsDir() {
			b, _ := os.ReadFile(filepath.Join(from, e.Name()))
			os.WriteFile(filepath.Join(to, e.Name()), b, 0o644)
		}
	}
}

func TestSignersVerifyRememberMatchPython(t *testing.T) {
	gold := loadGolden(t)
	var sg struct {
		Text    string
		Fp      [][]string
		Missing [][]string
	}
	decode(t, gold["signers"], &sg)
	g, fg, ws := newGen(t)
	sf := filepath.Join(t.TempDir(), "signers")
	os.WriteFile(sf, []byte(sg.Text), 0o644)
	var got [][]string
	for _, f := range SignerFingerprints(sf) {
		got = append(got, []string{f.Principal, f.Fingerprint})
	}
	if !reflect.DeepEqual(got, sg.Fp) {
		t.Errorf("fingerprints\n go     %v\n python %v", got, sg.Fp)
	}
	if len(SignerFingerprints(filepath.Join(t.TempDir(), "nope"))) != 0 {
		t.Error("missing file")
	}

	var ver map[string][]any
	decode(t, gold["verify"], &ver)
	kept := filepath.Join(g.dir("v"), "allowed_signers")
	own := filepath.Join(ws, ".om", "allowed_signers")
	os.MkdirAll(g.dir("v"), 0o755)
	cases := []struct {
		name  string
		vc    [3]any
		where string
	}{
		{"good_kept", [3]any{0, "", `Good "git" signature for me@x with ED25519 key SHA256:abc`}, "kept"},
		{"good_first", [3]any{0, "", `Good "git" signature for me@x with ED25519 key SHA256:abc`}, "own"},
		{"no_signers", [3]any{0, "", ""}, "none"},
		{"unsigned_empty", [3]any{1, "", ""}, "kept"},
		{"unsigned_msg", [3]any{1, "error: no signature found", ""}, "kept"},
		{"untrusted", [3]any{1, "", "Could not verify signature.\nNo principal matched.\n" + strings.Repeat("x", 300)}, "kept"},
		{"untrusted_out_only", [3]any{1, "only stdout line", ""}, "kept"},
		{"code0_nomatch", [3]any{0, "weird", ""}, "kept"},
	}
	for _, c := range cases {
		os.Remove(kept)
		os.Remove(own)
		switch c.where {
		case "kept":
			os.WriteFile(kept, []byte(sg.Text), 0o644)
		case "own":
			os.WriteFile(own, []byte(sg.Text), 0o644)
		}
		fg.vc = c.vc
		ok, msg := g.Verify("v", ws, "HEAD")
		want := ver[c.name]
		if ok != want[0].(bool) || msg != want[1].(string) {
			t.Errorf("verify %s: %v %q, python %v", c.name, ok, msg, want)
		}
	}

	var fu map[string][][]string
	decode(t, gold["first_use"], &fu)
	os.Remove(kept)
	os.WriteFile(own, []byte(sg.Text), 0o644)
	conv := func(l []Fingerprint) [][]string {
		var o [][]string
		for _, f := range l {
			o = append(o, []string{f.Principal, f.Fingerprint})
		}
		return o
	}
	if got := conv(g.IsFirstUse("v", ws)); !reflect.DeepEqual(got, fu["first_use"]) {
		t.Errorf("first use %v", got)
	}
	os.WriteFile(kept, []byte(sg.Text), 0o644)
	if got := g.IsFirstUse("v", ws); len(got) != 0 {
		t.Errorf("after kept: %v", got)
	}

	k2 := ""
	for _, l := range strings.Split(sg.Text, "\n") {
		if strings.HasPrefix(l, "other@y ") {
			k2 = strings.TrimPrefix(l, "other@y ")
		}
	}
	var rem map[string]struct {
		Stdout string
		Kept   *string
	}
	decode(t, gold["remember"], &rem)
	for _, c := range []struct {
		name, show string
		code       int
	}{{"new", sg.Text, 0}, {"same", sg.Text, 0}, {"changed", sg.Text + "x@y " + k2 + "\n", 0}, {"empty", "", 0}, {"fail", "", 1}} {
		if c.name == "new" {
			os.Remove(kept)
		}
		fg.show, fg.showCode = c.show, c.code
		warn, err := g.RememberSigners("v", ws, "HEAD")
		if err != nil {
			t.Fatal(err)
		}
		want := rem[c.name]
		if c.name == "changed" {
			if (warn != "") != (want.Stdout != "") {
				t.Errorf("remember changed: warning %q vs python %q", warn, want.Stdout)
			}
			continue
		}
		wantWarn := strings.TrimSuffix(want.Stdout, "\n")
		if warn != wantWarn {
			t.Errorf("remember %s: warning %q, python %q", c.name, warn, wantWarn)
		}
		b, err := os.ReadFile(kept)
		gotKept := (*string)(nil)
		if err == nil {
			s := string(b)
			gotKept = &s
		}
		if (gotKept == nil) != (want.Kept == nil) || (gotKept != nil && *gotKept != *want.Kept) {
			t.Errorf("remember %s: kept %v, python %v", c.name, gotKept, want.Kept)
		}
	}

	var mode map[string]string
	decode(t, gold["mode"], &mode)
	for in, want := range mode {
		s := settings.Settings{"OM_SIGNED": in}
		if in == "unset" {
			s = settings.Settings{}
		}
		if got := g.Mode(s); got != want {
			t.Errorf("mode(%q) = %s want %s", in, got, want)
		}
	}
}

// With real git and ssh-keygen: a signed commit verifies against allowed_signers, an unsigned one does not, and the
// signed log head detects a rewrite.
func TestRealGitAndKeygen(t *testing.T) {
	for _, tool := range []string{"git", "ssh-keygen"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool, "not installed")
		}
	}
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	os.MkdirAll(home, 0o755)
	key := filepath.Join(home, "id")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "tester", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	pub, _ := os.ReadFile(key + ".pub")
	gcfg := filepath.Join(home, "gitconfig")
	os.WriteFile(gcfg, []byte("[user]\n\tname = T\n\temail = t@example.com\n\tsigningkey = "+key+".pub\n[gpg]\n\tformat = ssh\n[commit]\n\tgpgsign = true\n"), 0o644)
	t.Setenv("GIT_CONFIG_GLOBAL", gcfg)
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
	t.Setenv("HOME", home)
	t.Setenv("OM_STATE_DIR", filepath.Join(tmp, "state"))
	root := filepath.Join(tmp, "ws")
	os.MkdirAll(filepath.Join(root, ".om"), 0o755)
	os.WriteFile(filepath.Join(root, ".om", "allowed_signers"), []byte("tester@example.com "+strings.TrimSpace(string(pub))+"\n"), 0o644)
	run := func(args ...string) {
		c := exec.Command("git", args...)
		c.Dir = root
		c.Stdin = nil
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	run("init", "-q")
	os.WriteFile(filepath.Join(root, "f"), []byte("1"), 0o644)
	run("add", ".")
	run("commit", "-q", "-m", "signed")
	g := New(state.NewDirs())
	if !g.SigningConfigured() || g.Mode(settings.Settings{"OM_SIGNED": "auto"}) != "enforce" {
		t.Fatal("signing should be configured")
	}
	ok, who := g.Verify("w", root, "HEAD")
	if !ok || !strings.Contains(who, "first use") || !strings.HasPrefix(who, "tester@example.com") {
		t.Fatalf("signed commit: %v %q", ok, who)
	}
	if fp := g.IsFirstUse("w", root); len(fp) != 1 || !strings.HasPrefix(fp[0].Fingerprint, "SHA256:") {
		t.Fatalf("first use fingerprints %v", fp)
	}
	if warn, err := g.RememberSigners("w", root, "HEAD"); err != nil || warn != "" {
		t.Fatal(warn, err)
	}
	if ok, who := g.Verify("w", root, "HEAD"); !ok || strings.Contains(who, "first use") {
		t.Fatalf("after remembering: %v %q", ok, who)
	}
	// an unsigned commit is refused
	run("-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "unsigned")
	if ok, why := g.Verify("w", root, "HEAD"); ok || why != "commit is not signed" {
		t.Fatalf("unsigned: %v %q", ok, why)
	}
	// the log head is signed, and rewriting the log is noticed
	if _, err := g.Record("w", root, "start", "running", "tester@example.com"); err != nil {
		t.Fatal(err)
	}
	if st, _ := g.HeadSignature("w"); st != "valid" {
		t.Fatalf("head signature %s", st)
	}
	if p := g.VerifyChain("w"); len(p) != 0 {
		t.Fatalf("chain: %v", p)
	}
	os.WriteFile(filepath.Join(g.dir("w"), "head"), []byte("1 "+strings.Repeat("a", 64)+"\n"), 0o644)
	if st, _ := g.HeadSignature("w"); st != "invalid" {
		t.Fatalf("a rewritten head must not verify: %s", st)
	}
}
