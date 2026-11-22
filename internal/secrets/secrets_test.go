package secrets

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/Chitakasa/om/internal/state"
)

var gold map[string]json.RawMessage

func g(t *testing.T, key string, v any) {
	if gold == nil {
		b, err := os.ReadFile("../../testdata/golden/secrets.json")
		if err != nil {
			t.Fatal(err)
		}
		json.Unmarshal(b, &gold)
	}
	d := json.NewDecoder(bytes.NewReader(gold[key]))
	d.UseNumber()
	if err := d.Decode(v); err != nil {
		t.Fatal(err)
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestLegacyMatchesPython(t *testing.T) {
	var lg struct {
		Files map[string]any
		Cases []struct {
			File   string
			Pw     string
			Allow  bool
			Result []string
		}
	}
	g(t, "legacy", &lg)
	dir := t.TempDir()
	for name, env := range lg.Files {
		b, _ := json.Marshal(env)
		os.WriteFile(filepath.Join(dir, name+".json"), b, 0o644)
	}
	l := &Legacy{Getenv: func(string) string { return "" }, Sops: func(string) ([]byte, bool) { return nil, false }}
	var warned bytes.Buffer
	l.Warn = &warned
	for _, c := range lg.Cases {
		got, err := l.DecryptFile(filepath.Join(dir, c.File+".json"), c.Pw, c.Allow)
		if c.Result[0] == "ok" {
			if err != nil || b64(got) != c.Result[1] {
				t.Errorf("%s pw=%q allow=%v: %v %s, python %s", c.File, c.Pw, c.Allow, err, b64(got), c.Result[1])
			}
			continue
		}
		if err == nil {
			t.Errorf("%s pw=%q allow=%v: python failed with %q, Go succeeded", c.File, c.Pw, c.Allow, c.Result[2])
			continue
		}
		// Python's KeyError/binascii messages differ from ours; the ValueErrors om raises itself must be identical
		if c.Result[1] == "ValueError" && err.Error() != c.Result[2] {
			t.Errorf("%s pw=%q allow=%v: %q, python %q", c.File, c.Pw, c.Allow, err.Error(), c.Result[2])
		}
	}
	if !strings.Contains(warned.String(), "om-v1 secret has no integrity check") {
		t.Error("the om-v1 warning is shown")
	}
	var envKey string
	g(t, "env_key", &envKey)
	var plain string
	g(t, "legacy", &struct {
		Plain *string `json:"plain"`
	}{&plain})
	l.Getenv = func(k string) string {
		if k == "OM_SECRET_KEY" {
			return "pw"
		}
		return ""
	}
	if got, err := l.DecryptFile(filepath.Join(dir, "v2.json"), "", false); err != nil || b64(got) != envKey {
		t.Errorf("OM_SECRET_KEY: %v", err)
	}
	// sops wins when it can open the file
	l.Sops = func(string) ([]byte, bool) { return []byte("from sops"), true }
	if got, err := l.DecryptFile(filepath.Join(dir, "v3.json"), "", false); err != nil || string(got) != "from sops" {
		t.Errorf("sops: %q %v", got, err)
	}
}

func TestKeystreamAndB64(t *testing.T) {
	data := bytes.Repeat([]byte{7}, 100)
	enc := KeystreamXOR([]byte("k"), data, 8)
	if !bytes.Equal(KeystreamXOR([]byte("k"), enc, 8), data) || bytes.Equal(enc, data) {
		t.Fatal("xor is its own inverse")
	}
	if bytes.Equal(KeystreamXOR([]byte("k"), data, 4), enc) {
		t.Fatal("the counter width matters")
	}
	if got, err := b64Decode("QUJD\n REVG"); err != nil || string(got) != "ABCDEF" {
		t.Fatal(string(got), err)
	}
	if _, err := b64Decode("QUJ"); err == nil {
		t.Fatal("bad padding is an error")
	}
}

func b64Decode(s string) ([]byte, error) { return b64Lenient(s) }

type fakeAge struct {
	calls [][]string
}

func ageFor(t *testing.T) (*Age, string) {
	root := t.TempDir()
	t.Setenv("OM_STATE_DIR", filepath.Join(root, "state"))
	t.Setenv("OM_HOME", filepath.Join(root, "home"))
	d := state.NewDirs()
	a := NewAge(d)
	a.Getenv = func(k string) string {
		if k == "XDG_RUNTIME_DIR" {
			return filepath.Join(root, "xdg")
		}
		return ""
	}
	a.Run = func([]string) state.Result { return state.Result{} } // the image "exists"
	a.Exec = func(cmd []string, stdin []byte) (int, []byte, string) {
		i := 0
		for j, c := range cmd {
			if strings.HasPrefix(c, "localhost/om-tools:") {
				i = j + 1
			}
		}
		a := cmd[i:]
		switch {
		case a[0] == "age-keygen":
			return 0, []byte("# created: x\n# public key: age1abc123xyz\nAGE-SECRET-KEY-1ZZZ\n"), ""
		case a[0] == "age" && a[1] == "--encrypt":
			return 0, append(append([]byte("ENC("), stdin...), ')'), ""
		case a[0] == "age" && a[1] == "--decrypt":
			var key, in string
			for j, c := range cmd {
				if c == "-v" {
					parts := strings.Split(cmd[j+1], ":")
					if parts[1] == "/key" {
						key = parts[0]
					} else {
						in = parts[0]
					}
				}
			}
			kb, _ := os.ReadFile(key)
			data, _ := os.ReadFile(in)
			if (bytes.Contains(kb, []byte("SSHKEY")) || filepath.Base(key) == "age.key") && bytes.HasPrefix(data, []byte("ENC(")) {
				return 0, data[4 : len(data)-1], ""
			}
			return 1, nil, "no identity matched"
		}
		return 1, nil, "?"
	}
	return a, root
}

func TestAgeMatchesPython(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake engine keys on POSIX mount paths and file modes")
	}
	var ag struct {
		HostRecipient string `json:"host_recipient"`
		KeyMode       string `json:"key_mode"`
		KeyText       string `json:"key_text"`
		Steps         []struct {
			Name   string
			Result any
			File   *string
		}
		Encrypt        string
		EncryptArgs    []string `json:"encrypt_args"`
		EncryptNoRcpts string   `json:"encrypt_norecipients"`
		Rekey          []string
		RekeyFiles     map[string]string `json:"rekey_files"`
		DecFail        string            `json:"dec_fail"`
	}
	g(t, "age", &ag)
	a, root := ageFor(t)
	ws := filepath.Join(root, "ws")
	os.MkdirAll(filepath.Join(ws, ".om"), 0o755)
	// the image tag is a hash of core/tools
	var want string
	g(t, "age_image", &want)
	os.MkdirAll(filepath.Join(a.D.Core, "tools"), 0o755)
	os.WriteFile(filepath.Join(a.D.Core, "tools", "Containerfile"), []byte("FROM x\n"), 0o644)
	os.WriteFile(filepath.Join(a.D.Core, "tools", "a.sh"), []byte("echo\n"), 0o644)
	if got := a.Image(); got != want {
		t.Errorf("Image %s want %s", got, want)
	}
	host, err := a.HostRecipient("podman")
	if err != nil || host != ag.HostRecipient {
		t.Fatalf("%q %v", host, err)
	}
	if b, _ := os.ReadFile(a.KeyFile()); string(b) != ag.KeyText {
		t.Error("key text")
	}
	if st, _ := os.Stat(a.KeyFile()); fmt.Sprintf("%#o", st.Mode().Perm()) != strings.Replace(ag.KeyMode, "0o", "0", 1) {
		t.Errorf("key mode %v want %s", st.Mode().Perm(), ag.KeyMode)
	}
	rf := filepath.Join(ws, ".om", "age-recipients")
	read := func() *string {
		b, err := os.ReadFile(rf)
		if err != nil {
			return nil
		}
		s := string(b)
		return &s
	}
	step := func(i int, result any) {
		w := ag.Steps[i]
		got, _ := json.Marshal(result)
		wantJ, _ := json.Marshal(w.Result)
		if string(got) != string(wantJ) && !(string(got) == "null" && string(wantJ) == "[]") {
			t.Errorf("%s: result %s want %s", w.Name, got, wantJ)
		}
		if f := read(); (f == nil) != (w.File == nil) || (f != nil && *f != *w.File) {
			t.Errorf("%s: file %v want %v", w.Name, f, w.File)
		}
	}
	step(0, Recipients(ws))
	r, _ := WriteRecipients(ws, "age1host", "ssh-ed25519 AAAAkey me@box extra")
	step(1, r)
	r, _ = WriteRecipients(ws, "age1host", "ssh-ed25519 AAAAkey me@box")
	step(2, r)
	r, _ = WriteRecipients(ws, "age1other", "")
	step(3, r)
	step(4, Recipients(ws))
	os.WriteFile(rf, []byte("# c\n\n  age1x  \n#age1y\n age1z\n"), 0o644)
	step(5, Recipients(ws))

	os.WriteFile(rf, []byte("# c\nage1host\n"), 0o644)
	enc, err := a.Encrypt("podman", ws, []byte("hello"))
	if err != nil || b64(enc) != ag.Encrypt {
		t.Errorf("encrypt %v", err)
	}
	if _, err := a.Encrypt("podman", filepath.Join(root, "empty"), []byte("x")); err == nil || err.Error() != ag.EncryptNoRcpts {
		t.Errorf("no recipients: %v want %s", err, ag.EncryptNoRcpts)
	}
	put := func(rel, content string) {
		p := filepath.Join(ws, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(content), 0o644)
	}
	put("p1/secrets/a.age", "ENC(one)")
	put("p1/secrets/b.txt", "no")
	put("p-1/secrets/c.age", "ENC(two)")
	put(".om/secrets/skip.age", "ENC(skip)")
	put("x/y/secrets/deep.age", "ENC(deep)")
	done, err := a.Rekey("podman", ws, "")
	if err != nil || !reflect.DeepEqual(done, ag.Rekey) {
		t.Errorf("rekey %v %v want %v", done, err, ag.Rekey)
	}
	for rel, want := range ag.RekeyFiles {
		if b, _ := os.ReadFile(filepath.Join(ws, filepath.FromSlash(rel))); b64(b) != want {
			t.Errorf("rekeyed %s", rel)
		}
	}
	put("p1/secrets/bad.age", "NOTENC")
	if _, err := a.Decrypt("podman", filepath.Join(ws, "p1", "secrets", "bad.age"), ""); err == nil || err.Error() != ag.DecFail {
		t.Errorf("decrypt failure: %v\nwant %s", err, ag.DecFail)
	}

	var ov struct {
		File, Name, Secret, Mode string
		DirMode                  string `json:"dir_mode"`
		BaseMode                 string `json:"base_mode"`
	}
	g(t, "override", &ov)
	put("p1/secrets/a", "plaintext-ignored")
	cfg := map[string]any{"secrets": map[string]any{
		"db_password": map[string]any{"file": filepath.Join(ws, "p1", "secrets", "a")},
		"missing":     map[string]any{"file": filepath.Join(ws, "p1", "secrets", "nofile")},
		"bad name!":   map[string]any{"file": filepath.Join(ws, "p1", "secrets", "a")},
		"nofile_key":  map[string]any{},
	}}
	ovd := filepath.Join(root, "ovr")
	p, err := a.WriteOverride("podman", "w", filepath.Join(ws, "p1"), cfg, ovd)
	if err != nil {
		t.Fatal(err)
	}
	rt, _ := a.RuntimeDir("w", filepath.Join(ws, "p1"))
	b, _ := os.ReadFile(p)
	if got := strings.ReplaceAll(string(b), filepath.ToSlash(rt), "@RT@"); got != ov.File {
		t.Errorf("override:\n%s\npython:\n%s", got, ov.File)
	}
	if s, _ := os.ReadFile(filepath.Join(rt, "db_password")); b64(s) != ov.Secret {
		t.Error("decrypted secret")
	}
	mode := func(path string) string { st, _ := os.Stat(path); return fmt.Sprintf("%#o", st.Mode().Perm()) }
	if mode(filepath.Join(rt, "db_password")) != strings.Replace(ov.Mode, "0o", "0", 1) || mode(rt) != strings.Replace(ov.DirMode, "0o", "0", 1) || mode(filepath.Dir(filepath.Dir(rt))) != strings.Replace(ov.BaseMode, "0o", "0", 1) {
		t.Errorf("modes %s %s", mode(rt), mode(filepath.Dir(filepath.Dir(rt))))
	}
	if p2, _ := a.WriteOverride("podman", "w", filepath.Join(ws, "p1"), map[string]any{"secrets": map[string]any{}}, ovd); p2 != "" {
		t.Error("nothing to decrypt: no override")
	}
	if _, err := os.Stat(p); err == nil {
		t.Error("the stale override must go")
	}
	a.Wipe("w")
	if _, err := os.Stat(filepath.Dir(rt)); err == nil {
		t.Error("wipe")
	}
}

func TestRuntimeDirRefusesSymlinkBase(t *testing.T) {
	a, root := ageFor(t)
	target := filepath.Join(root, "elsewhere")
	os.MkdirAll(target, 0o755)
	os.MkdirAll(filepath.Join(root, "xdg"), 0o755)
	os.Symlink(target, filepath.Join(root, "xdg", "om-secrets"))
	if _, err := a.RuntimeDir("w", "p"); err == nil || !strings.Contains(err.Error(), "is a link or belongs to another user") {
		t.Fatalf("%v", err)
	}
}

func TestAuthAndSignerMatchPython(t *testing.T) {
	var written string
	g(t, "auth_written", &written)
	dir := t.TempDir()
	conf := filepath.Join(dir, "auth", "private.conf")
	if err := WriteAuthUsers(filepath.Join(dir, "auth"), conf, map[string]string{"zed": "$2a$14$abc", "amy": "$2y$10$def.ghi"}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(conf); string(b) != written {
		t.Errorf("auth file:\n%s\npython:\n%s", b, written)
	}
	os.WriteFile(conf, []byte("basic_auth {\n    amy $2a$1$x\n    bad-hash nothash\n  \tbob\t$2b$04$yy  \n    "+strings.Repeat("u", 65)+" $2a$x\n    carl $2a$z\nanomaly $2a$no-indent\n}\n"), 0o644)
	var want map[string]string
	g(t, "auth_read", &want)
	if got := ReadAuthUsers(conf); !reflect.DeepEqual(got, want) {
		t.Errorf("read users %v want %v", got, want)
	}
	WriteAuthUsers(filepath.Join(dir, "auth"), conf, nil)
	if _, err := os.Stat(conf); err == nil || len(ReadAuthUsers(conf)) != 0 {
		t.Error("no users removes the file")
	}

	var sg map[string]string
	g(t, "signer", &sg)
	kf := filepath.Join(dir, "key.pub")
	os.WriteFile(kf, []byte("ssh-ed25519 AAAAxx comment\n"), 0o644)
	line := func(cfg map[string]string) string {
		return MySignerLine(func(c []string) (int, string) {
			if v, ok := cfg[c[len(c)-1]]; ok {
				return 0, v + "\n"
			}
			return 1, "\n"
		}, func(p string) (string, error) { b, err := os.ReadFile(p); return string(b), err }, func(s string) string { return s })
	}
	cases := map[string]map[string]string{
		"inline":       {"user.email": "a@b", "user.signingkey": "ssh-ed25519 AAAAk c", "gpg.format": "ssh"},
		"file":         {"user.email": "a@b", "user.signingkey": kf, "gpg.format": "ssh"},
		"missing_file": {"user.email": "a@b", "user.signingkey": kf + "x", "gpg.format": "ssh"},
		"not_ssh":      {"user.email": "a@b", "user.signingkey": "ssh-ed25519 K", "gpg.format": "openpgp"},
		"no_email":     {"user.signingkey": "ssh-ed25519 K", "gpg.format": "ssh"},
		"sk":           {"user.email": "a@b", "user.signingkey": "sk-ssh-ed25519@openssh.com AAAA x y", "gpg.format": "ssh"},
	}
	for name, cfg := range cases {
		if got := line(cfg); got != sg[name] {
			t.Errorf("signer %s: %q want %q", name, got, sg[name])
		}
	}
}
