// Package generations implements signed deploys and numbered generations. Every `om start` / `om sync` /
// `om update` / `om rollback` of a workspace is a generation: <state>/generations/<ws>/<n>.json = {n, kind,
// commit, dirty, signer, lock, time, result, prev}, where prev is the SHA-256 of the previous entry, so the log is
// a hash chain that `om fsck` verifies and any rewrite breaks.
//
// A commit is trusted when `git verify-commit` accepts it against the trusted signer list: the copy om took from
// the last deployed generation, not the file in the commit being checked (a hostile commit could otherwise add
// its own key). The first deploy trusts the workspace's .om/allowed_signers once (trust on first use) and says so.
// OM_SIGNED=auto|warn|enforce decides whether an unsigned or untrusted commit is reported or refused.
//
// Port of lib/gitops/generations.py.
package generations

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/settings"
	"github.com/Chitakasa/om/internal/state"
)

const (
	HeadName      = "head"
	HeadSig       = "head.sig"
	HeadNamespace = "om-generations"
	SignersName   = ".om/allowed_signers"
)

var (
	goodRE  = regexp.MustCompile(`Good "git" signature for (\S+) with (\S+) key (\S+)`)
	checkRE = regexp.MustCompile(`key (SHA256:\S+)`)
)

// Gen works on the generation logs of one set of directories. The function fields exist for tests.
type Gen struct {
	D   state.Dirs
	Now func() time.Time
	// Git runs git in root and returns (code, stdout, stderr), both stripped. Real() runs the git binary.
	Git func(root string, args ...string) (int, string, string)
	// GitGlobal reads a global git setting ("" if unset).
	GitGlobal func(key string) string
	// LookPath finds a program (ssh-keygen).
	LookPath func(string) (string, error)
	// Keygen runs ssh-keygen without any chance of prompting. stdinFile may be "".
	Keygen func(args []string, stdinFile string) state.Result
}

// New returns a Gen for this machine.
func New(d state.Dirs) *Gen {
	g := &Gen{D: d, Now: time.Now, LookPath: exec.LookPath}
	g.Git = func(root string, args ...string) (int, string, string) {
		c := exec.Command("git", args...)
		c.Dir = root
		var o, e bytes.Buffer
		c.Stdout, c.Stderr = &o, &e
		err := c.Run()
		code := 0
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				return 1, "", err.Error()
			}
		}
		return code, py.Strip(strings.ToValidUTF8(o.String(), "�")), py.Strip(strings.ToValidUTF8(e.String(), "�"))
	}
	g.GitGlobal = func(key string) string {
		r := state.Run([]string{"git", "config", "--global", "--get", key})
		if r.Code != 0 {
			return ""
		}
		return py.Strip(r.Stdout)
	}
	g.Keygen = func(args []string, stdinFile string) state.Result {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, "ssh-keygen", args...)
		detach(c)
		if stdinFile != "" {
			f, err := os.Open(stdinFile)
			if err != nil {
				return state.Result{Code: 127, Stderr: err.Error()}
			}
			defer f.Close()
			c.Stdin = f
		}
		var o, e bytes.Buffer
		c.Stdout, c.Stderr = &o, &e
		err := c.Run()
		res := state.Result{Stdout: o.String(), Stderr: e.String()}
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				res.Code = ee.ExitCode()
			} else {
				res.Code, res.Stderr = 127, err.Error()
			}
		}
		return res
	}
	return g
}

func (g *Gen) dir(ws string) string { return filepath.Join(g.D.State, "generations", ws) }

// SigningConfigured reports that git is set up to sign commits with an SSH key (the only kind om verifies).
func (g *Gen) SigningConfigured() bool {
	return g.GitGlobal("gpg.format") == "ssh" && g.GitGlobal("user.signingkey") != ""
}

// Mode is `warn` or `enforce`. OM_SIGNED=auto (the default) enforces as soon as git is set up to sign, so a machine
// that can sign is never left deploying unsigned commits by accident; a mistyped value enforces.
func (g *Gen) Mode(s settings.Settings) string {
	m := strings.ToLower(s.Get("OM_SIGNED", "auto"))
	if m == "auto" {
		if g.SigningConfigured() {
			return "enforce"
		}
		return "warn"
	}
	if m == "warn" {
		return "warn"
	}
	return "enforce"
}

// TrustedSignersFile returns the signer file to verify against and whether this is the first use (path "" if
// neither copy exists).
func (g *Gen) TrustedSignersFile(ws, root string) (string, bool) {
	kept := filepath.Join(g.dir(ws), "allowed_signers")
	if _, err := os.Stat(kept); err == nil {
		return kept, false
	}
	own := filepath.Join(root, filepath.FromSlash(SignersName))
	if _, err := os.Stat(own); err == nil {
		return own, true
	}
	return "", false
}

func firstRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

func lastRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[len(r)-n:]
	}
	return string(r)
}

// Verify reports whether commit rev is trusted, and the signer or the reason it is not.
func (g *Gen) Verify(ws, root, rev string) (bool, string) {
	signers, first := g.TrustedSignersFile(ws, root)
	if signers == "" {
		return false, "no " + SignersName + " (list the keys allowed to deploy; `om init` writes yours)"
	}
	code, out, errOut := g.Git(root, "-c", "gpg.ssh.allowedSignersFile="+signers, "verify-commit", rev)
	if m := goodRE.FindStringSubmatch(errOut + "\n" + out); code == 0 && m != nil {
		s := m[1]
		if first {
			s += " (first use: trusting this workspace's allowed_signers)"
		}
		return true, s
	}
	all := errOut + out
	if py.Strip(all) == "" || strings.Contains(strings.ToLower(all), "no signature") {
		return false, "commit is not signed"
	}
	text := errOut
	if text == "" {
		text = out
	}
	lines := py.SplitLines(text)
	last := "?"
	if len(lines) > 0 {
		last = lines[len(lines)-1]
	}
	return false, "signature not from a trusted key: " + firstRunes(last, 160)
}

// Fingerprint is a signer principal and its key's SHA256 fingerprint, as `ssh-keygen -l` prints them.
type Fingerprint struct{ Principal, Fingerprint string }

// SignerFingerprints reads an allowed_signers file.
func SignerFingerprints(file string) []Fingerprint {
	text, err := py.ReadText(file)
	if err != nil {
		return nil
	}
	var out []Fingerprint
	for _, line := range py.SplitLines(text) {
		words := py.Fields(line)
		if len(words) == 0 || strings.HasPrefix(words[0], "#") {
			continue
		}
		key := ""
		for i := 0; i < len(words)-1; i++ {
			w := words[i]
			if strings.HasPrefix(w, "ssh-") || strings.HasPrefix(w, "ecdsa-") || strings.HasPrefix(w, "sk-") {
				key = words[i+1]
				break
			}
		}
		if key == "" {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(blob)
		out = append(out, Fingerprint{words[0], "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])})
	}
	return out
}

// IsFirstUse returns the signers about to be trusted for the first time (nothing kept from an earlier deploy).
func (g *Gen) IsFirstUse(ws, root string) []Fingerprint {
	if f, first := g.TrustedSignersFile(ws, root); f != "" && first {
		return SignerFingerprints(f)
	}
	return nil
}

func (g *Gen) signingKey() string {
	if !g.SigningConfigured() {
		return ""
	}
	k := g.GitGlobal("user.signingkey")
	if strings.HasPrefix(k, "~") {
		if h, err := os.UserHomeDir(); err == nil {
			k = h + k[1:]
		}
	}
	if st, err := os.Stat(k); k != "" && err == nil && st.Mode().IsRegular() {
		return k
	}
	return ""
}

// SignHead signs the log's head with the git signing key, so a log rewritten by someone who can only edit files is
// noticed. Best effort and silent: with no key, no agent or a passphrase it asks for, the head stays unsigned (and
// a signature of an older head is removed, never left to mismatch).
func (g *Gen) SignHead(ws string) bool {
	head, sig := filepath.Join(g.dir(ws), HeadName), filepath.Join(g.dir(ws), HeadSig)
	os.Remove(sig)
	key := g.signingKey()
	if key == "" {
		return false
	}
	if _, err := g.LookPath("ssh-keygen"); err != nil {
		return false
	}
	if st, err := os.Stat(head); err != nil || !st.Mode().IsRegular() {
		return false
	}
	if r := g.Keygen([]string{"-Y", "sign", "-n", HeadNamespace, "-f", key, head}, ""); r.Code == 127 {
		return false
	}
	_, err := os.Stat(sig)
	return err == nil
}

// HeadSignature tells whether the head's signature matches it and was made by a key in the trusted signer list (the
// one kept from the last trusted deploy): "absent", "valid", "invalid" or "untrusted", with a detail.
func (g *Gen) HeadSignature(ws string) (string, string) {
	head, sig := filepath.Join(g.dir(ws), HeadName), filepath.Join(g.dir(ws), HeadSig)
	for _, p := range []string{sig, head} {
		if st, err := os.Stat(p); err != nil || !st.Mode().IsRegular() {
			return "absent", ""
		}
	}
	r := g.Keygen([]string{"-Y", "check-novalidate", "-n", HeadNamespace, "-s", sig}, head)
	m := checkRE.FindStringSubmatch(r.Stdout + r.Stderr)
	if r.Code != 0 || m == nil {
		out := r.Stderr
		if out == "" {
			out = r.Stdout
		}
		return "invalid", lastRunes(py.Strip(out), 160)
	}
	trusted := map[string]bool{}
	for _, f := range SignerFingerprints(filepath.Join(g.dir(ws), "allowed_signers")) {
		trusted[f.Fingerprint] = true
	}
	if len(trusted) > 0 && !trusted[m[1]] {
		return "untrusted", m[1]
	}
	return "valid", m[1]
}

// RememberSigners makes the deployed commit's signer list the trusted one. It returns the warning Python printed
// when that changes the list ("" otherwise).
func (g *Gen) RememberSigners(ws, root, rev string) (string, error) {
	code, out, _ := g.Git(root, "show", rev+":"+SignersName)
	if code != 0 || py.Strip(out) == "" {
		return "", nil
	}
	d := g.dir(ws)
	if err := os.MkdirAll(d, 0o755); err != nil {
		return "", err
	}
	kept := filepath.Join(d, "allowed_signers")
	warn := ""
	if cur, err := py.ReadText(kept); err == nil && py.Strip(cur) != py.Strip(out) {
		warn = "  \033[33m⚠ the trusted signer list changed with this deploy (" + SignersName +
			"); it is now the one used to verify future commits.\033[0m"
	}
	return warn, os.WriteFile(kept, []byte(out+"\n"), 0o644)
}

// Entry is one generation: a JSON object (unknown fields kept). A damaged file is {"n": N, "corrupt": true}.
type Entry = map[string]any

// Entries reads the log in numeric order.
func (g *Gen) Entries(ws string) []Entry {
	files, _ := filepath.Glob(filepath.Join(g.dir(ws), "*.json"))
	type item struct {
		n    int
		path string
	}
	var items []item
	for _, f := range files {
		stem := strings.TrimSuffix(filepath.Base(f), ".json")
		if state.IsNumber(stem) {
			n, _ := strconv.Atoi(stem)
			items = append(items, item{n, f})
		}
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].n < items[j].n })
	var out []Entry
	for _, it := range items {
		var e Entry
		if b, err := os.ReadFile(it.path); err == nil {
			if v, err := py.LoadJSON(b); err == nil {
				e, _ = v.(map[string]any)
			}
		}
		if e == nil {
			e = Entry{"n": it.n, "corrupt": true}
		}
		out = append(out, e)
	}
	return out
}

// Digest is the SHA-256 of an entry's canonical JSON (sorted keys, no spaces).
func Digest(e Entry) string {
	sum := sha256.Sum256([]byte(py.DumpsMinimal(e)))
	return hex.EncodeToString(sum[:])
}

// Snapshot is the commit, dirty flag and lock hash of the workspace as it is now.
func (g *Gen) Snapshot(root string) map[string]any {
	code, commit, _ := g.Git(root, "rev-parse", "HEAD")
	_, status, _ := g.Git(root, "status", "--porcelain")
	out := map[string]any{"commit": nil, "dirty": true, "lock": nil}
	if code == 0 {
		out["commit"] = commit
		out["dirty"] = status != ""
	}
	if b, err := os.ReadFile(filepath.Join(root, ".om", "lock.json")); err == nil {
		sum := sha256.Sum256(b)
		out["lock"] = hex.EncodeToString(sum[:])
	}
	return out
}

func asInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case interface{ Int64() (int64, error) }:
		n, _ := x.Int64()
		return int(n)
	}
	return 0
}

// Record appends one generation to the chain and returns it. It is locked: two `om` processes (a scheduled sync
// and a manual start) must not both take number n+1. signer "" records null.
func (g *Gen) Record(ws, root, kind, result, signer string) (Entry, error) {
	unlock, err := state.FileLock(filepath.Join(g.dir(ws), ".lock"))
	if err != nil {
		return nil, err
	}
	defer unlock()
	prev := g.Entries(ws)
	entry := Entry{"n": 1, "kind": kind, "signer": nil, "time": g.Now().Format("2006-01-02T15:04:05-0700"), "result": result, "prev": nil}
	if len(prev) > 0 {
		entry["n"] = asInt(prev[len(prev)-1]["n"]) + 1
		entry["prev"] = Digest(prev[len(prev)-1])
	}
	for k, v := range g.Snapshot(root) {
		entry[k] = v
	}
	if signer != "" {
		entry["signer"] = signer
	}
	d := g.dir(ws)
	if err := os.MkdirAll(d, 0o755); err != nil {
		return nil, err
	}
	n := strconv.Itoa(entry["n"].(int))
	tmp := filepath.Join(d, "."+n+".tmp")
	if err := os.WriteFile(tmp, []byte(py.Dumps(entry)+"\n"), 0o644); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, filepath.Join(d, n+".json")); err != nil {
		return nil, err
	}
	if err := state.WriteAtomic(filepath.Join(d, HeadName), n+" "+Digest(entry)+"\n"); err != nil {
		return nil, err
	}
	g.SignHead(ws)
	return entry, nil
}

// Current is the last generation that started successfully.
func (g *Gen) Current(ws string) Entry {
	es := g.Entries(ws)
	for i := len(es) - 1; i >= 0; i-- {
		if es[i]["result"] == "running" {
			return es[i]
		}
	}
	return nil
}

// VerifyChain returns the problems in the generation log: gaps, corrupt entries, broken hash links, a head that
// disagrees with the log, a head signature that does not match.
func (g *Gen) VerifyChain(ws string) []string {
	var problems []string
	var prev Entry
	for i, e := range g.Entries(ws) {
		i++
		n := e["n"]
		switch {
		case py.Truthy(e["corrupt"]):
			problems = append(problems, fmt.Sprintf("generation %s: unreadable", py.Str(n)))
		case n == nil || asInt(n) != i:
			problems = append(problems, fmt.Sprintf("generation %s: expected number %d (missing or renumbered)", py.Str(n), i))
		default:
			want := any(nil)
			if prev != nil {
				want = Digest(prev)
			}
			if e["prev"] != want {
				problems = append(problems, fmt.Sprintf("generation %s: does not chain to generation %d (rewritten?)", py.Str(n), i-1))
			}
		}
		prev = e
	}
	problems = append(problems, g.checkHead(ws, prev)...)
	switch st, detail := g.HeadSignature(ws); st {
	case "invalid":
		problems = append(problems, "the generation log's head signature does not match its head (log rewritten?): "+detail)
	case "untrusted":
		problems = append(problems, "the generation log's head is signed by a key that is not a trusted signer: "+detail)
	}
	return problems
}

// checkHead: the `head` file names the newest generation and its digest, so dropping entries from the end (which
// leaves a valid chain) or rewriting the last one is noticed. A log written before `head` existed has none until
// its next generation.
func (g *Gen) checkHead(ws string, last Entry) []string {
	b, err := os.ReadFile(filepath.Join(g.dir(ws), HeadName))
	if err != nil {
		return nil
	}
	f := py.Fields(py.UniversalNewlines(string(b)))
	if len(f) != 2 {
		return nil
	}
	n, digest := f[0], f[1]
	if last == nil {
		return []string{fmt.Sprintf("generation log is empty but its head says generation %s (entries deleted?)", n)}
	}
	if py.Str(last["n"]) != n || Digest(last) != digest {
		return []string{fmt.Sprintf("generation log ends at %s but its head says %s (entries removed or rewritten?)", py.Str(last["n"]), n)}
	}
	return nil
}
