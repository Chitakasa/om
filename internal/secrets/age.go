package secrets

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/state"
)

// Service secrets with age: encrypted in the workspace repo, decrypted only at start. A secret is one file
// `<project>/secrets/<name>.age`, encrypted (by the `age` tool, in the om-tools image — om writes no cryptography)
// to the recipients in `.om/age-recipients`: the host key (kept in <state>/data/age.key, never in a repo) and the
// owner's SSH key, so the owner can always decrypt their own secrets. At start om decrypts into $XDG_RUNTIME_DIR
// (memory, 0700) and points the secret there with a compose override. Secrets never become environment variables
// or labels.
const RecipientsName = ".om/age-recipients"

var NameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`) // Go's `$` is Python's `\Z`

// Age runs the age tool through the engine. Run is exec by default; tests replace it.
type Age struct {
	D state.Dirs
	// Exec runs a command with optional stdin and returns (code, stdout, stderr).
	Exec func(cmd []string, stdin []byte) (int, []byte, string)
	Run  func([]string) state.Result
	// Getenv, TempDir and GOOS drive where decrypted secrets live.
	Getenv  func(string) string
	TempDir string
}

// NewAge returns an Age for this machine.
func NewAge(d state.Dirs) *Age {
	a := &Age{D: d, Run: func(c []string) state.Result { return state.Run(c) }, Getenv: os.Getenv, TempDir: os.TempDir()}
	a.Exec = func(cmd []string, stdin []byte) (int, []byte, string) {
		c := exec.Command(cmd[0], cmd[1:]...)
		c.Stdin = bytes.NewReader(stdin)
		var o, e bytes.Buffer
		c.Stdout, c.Stderr = &o, &e
		if err := c.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				return ee.ExitCode(), o.Bytes(), strings.ToValidUTF8(e.String(), "�")
			}
			return 1, nil, err.Error()
		}
		return 0, o.Bytes(), strings.ToValidUTF8(e.String(), "�")
	}
	return a
}

// KeyFile is this host's age key.
func (a *Age) KeyFile() string { return filepath.Join(a.D.Data, "age.key") }

// Image is the local tag of the om-tools image: a hash of core/tools/.
func (a *Age) Image() string {
	h := sha256.New()
	dir := filepath.Join(a.D.Core, "tools")
	entries, _ := os.ReadDir(dir)
	for _, f := range entries {
		p := filepath.Join(dir, f.Name())
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			if b, err := os.ReadFile(p); err == nil {
				h.Write([]byte(f.Name()))
				h.Write([]byte{0})
				h.Write(b)
			}
		}
	}
	return "localhost/om-tools:" + hex.EncodeToString(h.Sum(nil))[:12]
}

// EnsureImage builds the om-tools image if the engine does not have it.
func (a *Age) EnsureImage(runtime string) bool {
	if a.Run([]string{runtime, "image", "inspect", a.Image()}).Code == 0 {
		return true
	}
	dir := filepath.Join(a.D.Core, "tools")
	return a.Run([]string{runtime, "build", "-q", "-t", a.Image(), "-f", filepath.Join(dir, "Containerfile"), dir}).Code == 0
}

type mount struct{ host, inside string }

func (a *Age) age(runtime string, args []string, stdin []byte, mounts ...mount) (int, []byte, string) {
	cmd := []string{runtime, "run", "--rm", "-i", "--network", "none", "--read-only", "--cap-drop", "ALL"}
	for _, m := range mounts {
		cmd = append(cmd, "-v", m.host+":"+m.inside+":ro")
	}
	cmd = append(cmd, a.Image())
	return a.Exec(append(cmd, args...), stdin)
}

var pubKeyRE = regexp.MustCompile(`public key: (age1[0-9a-z]+)`)

func lastRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[len(r)-n:]
	}
	return string(r)
}

// HostRecipient creates the host key once and returns its public age recipient.
func (a *Age) HostRecipient(runtime string) (string, error) {
	if !a.EnsureImage(runtime) {
		return "", fmt.Errorf("could not build the om-tools image (core/tools)")
	}
	if _, err := os.Stat(a.KeyFile()); err != nil {
		code, out, errText := a.age(runtime, []string{"age-keygen"}, nil)
		if code != 0 {
			return "", fmt.Errorf("age-keygen failed: %s", lastRunes(py.Strip(errText), 200))
		}
		if err := state.WritePrivateBytes(a.KeyFile(), out); err != nil {
			return "", err
		}
	}
	b, err := os.ReadFile(a.KeyFile())
	if err != nil {
		return "", err
	}
	m := pubKeyRE.FindSubmatch(b)
	if m == nil {
		return "", fmt.Errorf("%s has no public key line", a.KeyFile())
	}
	return string(m[1]), nil
}

// Recipients lists the recipients of a workspace (comments and blanks dropped).
func Recipients(root string) []string {
	text, err := py.ReadText(filepath.Join(root, filepath.FromSlash(RecipientsName)))
	if err != nil {
		return nil
	}
	var out []string
	for _, ln := range py.SplitLines(text) {
		if s := py.Strip(ln); s != "" && !strings.HasPrefix(ln, "#") {
			out = append(out, s)
		}
	}
	return out
}

// WriteRecipients adds this host (and the owner's SSH key) to the recipients, keeping every machine already listed.
// It returns true when something was added to an existing list (secrets then need `om secrets rekey`).
func WriteRecipients(root, host, ownerSSH string) (bool, error) {
	have := Recipients(root)
	contains := func(s string) bool {
		for _, h := range have {
			if h == s {
				return true
			}
		}
		return false
	}
	var add []string
	owner := ""
	if ownerSSH != "" {
		f := py.Fields(ownerSSH)
		if len(f) > 2 {
			f = f[:2]
		}
		owner = strings.Join(f, " ")
	}
	for _, r := range []string{host, owner} {
		if r != "" && !contains(r) {
			add = append(add, r)
		}
	}
	if len(add) == 0 && len(have) > 0 {
		return false, nil
	}
	lines := append([]string{"# Who can decrypt this workspace's secrets (age): each machine running it, and the owner's SSH key."}, have...)
	lines = append(lines, add...)
	p := filepath.Join(root, filepath.FromSlash(RecipientsName))
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		return false, err
	}
	return len(have) > 0, nil
}

// Encrypt encrypts plaintext to the workspace's recipients (armored).
func (a *Age) Encrypt(runtime, root string, plaintext []byte) ([]byte, error) {
	rc := Recipients(root)
	if len(rc) == 0 {
		return nil, fmt.Errorf("no %s (om secrets init)", RecipientsName)
	}
	args := []string{"age", "--encrypt", "--armor"}
	for _, r := range rc {
		args = append(args, "-r", r)
	}
	code, out, errText := a.age(runtime, args, plaintext)
	if code != 0 {
		return nil, fmt.Errorf("age failed: %s", lastRunes(py.Strip(errText), 200))
	}
	return out, nil
}

// Decrypt decrypts a secret with this host's key; with sshKey ("" for none) also the owner's SSH key.
func (a *Age) Decrypt(runtime, path, sshKey string) ([]byte, error) {
	tries := []string{a.KeyFile()}
	if sshKey != "" {
		if st, err := os.Stat(sshKey); err == nil && st.Mode().IsRegular() {
			tries = append(tries, sshKey)
		}
	}
	errText := ""
	for _, key := range tries {
		if st, err := os.Stat(key); err != nil || !st.Mode().IsRegular() {
			continue
		}
		var code int
		var out []byte
		code, out, errText = a.age(runtime, []string{"age", "--decrypt", "-i", "/key", "/in"}, nil, mount{key, "/key"}, mount{path, "/in"})
		if code == 0 {
			return out, nil
		}
	}
	return nil, fmt.Errorf("cannot decrypt %s: this machine is not a recipient yet — run `om secrets init` here and commit,"+
		" then `om secrets rekey` on a machine that can decrypt (%s)", filepath.Base(path), lastRunes(py.Strip(errText), 120))
}

// Rekey re-encrypts every secret of the workspace to the current recipients and returns the files (relative paths).
func (a *Age) Rekey(runtime, root, sshKey string) ([]string, error) {
	var found []string
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(d.Name(), ".age") && filepath.Base(filepath.Dir(p)) == "secrets" {
			if rel, e := filepath.Rel(root, p); e == nil {
				found = append(found, rel)
			}
		}
		return nil
	})
	// pathlib sorts by path components, not by the joined text
	sort.Slice(found, func(i, j int) bool {
		return lessParts(strings.Split(filepath.ToSlash(found[i]), "/"), strings.Split(filepath.ToSlash(found[j]), "/"))
	})
	done := []string{}
	for _, rel := range found {
		skip := false
		for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
			skip = skip || part == ".om"
		}
		if skip {
			continue
		}
		full := filepath.Join(root, rel)
		plain, err := a.Decrypt(runtime, full, sshKey)
		if err != nil {
			return done, err
		}
		enc, err := a.Encrypt(runtime, root, plain)
		if err != nil {
			return done, err
		}
		if err := os.WriteFile(full, enc, 0o644); err != nil {
			return done, err
		}
		done = append(done, rel)
	}
	return done, nil
}

func lessParts(a, b []string) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// base is where decrypted secrets live: XDG_RUNTIME_DIR (memory), else /dev/shm (memory), else the temp dir.
func (a *Age) base() string {
	root := a.Getenv("XDG_RUNTIME_DIR")
	if root == "" {
		if st, err := os.Stat("/dev/shm"); err == nil && st.IsDir() {
			root = "/dev/shm"
		}
	}
	if root == "" {
		root = a.TempDir
	}
	return filepath.Join(root, "om-secrets")
}

// RuntimeDir is the 0700 folder that holds one project's decrypted secrets.
func (a *Age) RuntimeDir(ws, project string) (string, error) {
	base := a.base()
	sum := sha256.Sum256([]byte(project))
	d := filepath.Join(base, ws, hex.EncodeToString(sum[:])[:12])
	if err := os.MkdirAll(base, 0o755); err != nil {
		return "", err
	}
	if st, err := os.Lstat(base); err != nil || st.Mode()&os.ModeSymlink != 0 || !ownedByMe(st) {
		return "", fmt.Errorf("%s is a link or belongs to another user; refusing to put secrets there", base)
	}
	if err := os.MkdirAll(d, 0o755); err != nil {
		return "", err
	}
	for _, p := range []string{base, filepath.Join(base, ws), d} {
		if err := os.Chmod(p, 0o700); err != nil {
			return "", err
		}
	}
	return d, nil
}

// WriteOverride decrypts this project's secrets and writes a compose override pointing at them; it returns the
// path, or "" (and removes a stale file) when nothing was decrypted. A declared secret whose `<file>.age` is
// missing stays as compose has it. cfg is the normalized `compose config`.
func (a *Age) WriteOverride(runtime, ws, projectDir string, cfg map[string]any, overrideDir string) (string, error) {
	out, err := a.RuntimeDir(ws, projectDir)
	if err != nil {
		return "", err
	}
	var lines []string
	secrets, _ := cfg["secrets"].(map[string]any)
	names := make([]string, 0, len(secrets))
	for n := range secrets {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		spec, _ := secrets[name].(map[string]any)
		src := "."
		if f, ok := spec["file"]; ok && py.Str(f) != "" {
			src = py.Str(f)
		}
		enc := src + ".age"
		if st, err := os.Stat(enc); !NameRE.MatchString(name) || err != nil || !st.Mode().IsRegular() {
			continue
		}
		target := filepath.Join(out, name)
		plain, err := a.Decrypt(runtime, enc, "")
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(target, plain, 0o600); err != nil {
			return "", err
		}
		if err := os.Chmod(target, 0o600); err != nil {
			return "", err
		}
		lines = append(lines, "  "+py.JSONString(name)+":", "    file: "+py.JSONString(filepath.ToSlash(target)))
	}
	sum := sha256.Sum256([]byte(projectDir))
	path := filepath.Join(overrideDir, ws+"-"+hex.EncodeToString(sum[:])[:12]+".yml")
	if len(lines) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return "", err
		}
		return "", nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	text := "# Generated by om — decrypted secrets live in memory only. Do not edit.\nsecrets:\n" + strings.Join(lines, "\n") + "\n"
	return path, os.WriteFile(path, []byte(text), 0o644)
}

// Wipe removes the decrypted secrets of a workspace.
func (a *Age) Wipe(ws string) { os.RemoveAll(filepath.Join(a.base(), ws)) }
