package cli

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Chitakasa/om/internal/generations"
	"github.com/Chitakasa/om/internal/settings"
	"github.com/Chitakasa/om/internal/state"
)

// ---- om doctor: login ----

func TestOtherLoginUsersWithoutALoginIsAFailure(t *testing.T) {
	a := sandboxApp(t)
	a.OtherLoginUsers = func() []string { return []string{"guest"} }
	r := a.docAuth("")
	if r.status != docFail || !strings.Contains(r.msg, "guest") || !strings.Contains(r.fix, "om auth add") {
		t.Errorf("%+v", r)
	}
}

func TestATrustedUserIsNotCounted(t *testing.T) {
	a := sandboxApp(t)
	if err := settings.Set(a.D, "OM_TRUSTED_USERS", "me2"); err != nil {
		t.Fatal(err)
	}
	a.OtherLoginUsers = func() []string { return []string{"me2", "guest"} }
	r := a.docAuth("")
	if r.status != docFail || !strings.Contains(r.msg, "guest") || strings.Contains(r.msg, "me2") {
		t.Errorf("%+v", r)
	}
	a.OtherLoginUsers = func() []string { return []string{"me2"} }
	if r := a.docAuth(""); r.status != docPass {
		t.Errorf("%+v", r)
	}
}

func TestAloneOnTheMachinePasses(t *testing.T) {
	a := sandboxApp(t)
	a.OtherLoginUsers = func() []string { return nil }
	if r := a.docAuth(""); r.status != docPass {
		t.Errorf("%+v", r)
	}
}

func TestALoginFilePassesWhateverTheOtherUsersAre(t *testing.T) {
	a := sandboxApp(t)
	a.OtherLoginUsers = func() []string { return []string{"guest"} }
	os.MkdirAll(a.D.Auth, 0o755)
	os.WriteFile(filepath.Join(a.D.Auth, "private.conf"), []byte("basic_auth {\n}\n"), 0o644)
	if r := a.docAuth(""); r.status != docPass {
		t.Errorf("%+v", r)
	}
}

// ---- generations ----

func TestConcurrentRecordsNeverShareANumber(t *testing.T) {
	a := sandboxApp(t)
	root := t.TempDir()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := a.Gen.Record("gen-ws", root, "start", "running", ""); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	entries := a.Gen.Entries("gen-ws")
	for i, e := range entries {
		if fmt.Sprint(e["n"]) != strconv.Itoa(i+1) {
			t.Errorf("entry %d has number %v", i, e["n"])
		}
	}
	if len(entries) != 8 {
		t.Errorf("%d entries", len(entries))
	}
	if p := a.Gen.VerifyChain("gen-ws"); len(p) != 0 {
		t.Errorf("chain: %v", p)
	}
}

func TestAutoEnforcesExactlyWhenGitCanSignWithAnSSHKey(t *testing.T) {
	a := sandboxApp(t)
	for _, c := range []struct{ format, key, want string }{{"ssh", "~/.ssh/id.pub", "enforce"}, {"ssh", "", "warn"}, {"openpgp", "ABCD", "warn"}, {"", "", "warn"}} {
		a.Gen.GitGlobal = func(k string) string { return map[string]string{"gpg.format": c.format, "user.signingkey": c.key}[k] }
		if got := a.Gen.Mode(settings.Settings{"OM_SIGNED": "auto"}); got != c.want {
			t.Errorf("%+v: %s", c, got)
		}
		if got := a.Gen.Mode(settings.Settings{}); got != c.want {
			t.Errorf("%+v: default %s", c, got)
		}
	}
	for v, want := range map[string]string{"warn": "warn", "enforce": "enforce", "enfroce": "enforce"} {
		if got := a.Gen.Mode(settings.Settings{"OM_SIGNED": v}); got != want {
			t.Errorf("OM_SIGNED=%s: %s", v, got)
		}
	}
}

func TestFirstDeploySignerFingerprintsAreListedLikeSSHKeygen(t *testing.T) {
	a := sandboxApp(t)
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, ".om"), 0o755)
	blob := append([]byte("\x00\x00\x00\x0bssh-ed25519"), func() []byte {
		b := make([]byte, 36)
		for i := range b {
			b[i] = byte(i)
		}
		return b
	}()...)
	key := base64.StdEncoding.EncodeToString(blob)
	os.WriteFile(filepath.Join(root, ".om", "allowed_signers"),
		[]byte("me@x namespaces=\"git\" ssh-ed25519 "+key+"\n# a comment\nbad line\nme@x ssh-ed25519 not*base64\n"), 0o644)
	found := a.Gen.IsFirstUse("fu-ws", root)
	if len(found) != 1 || found[0].Principal != "me@x" || !regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`).MatchString(found[0].Fingerprint) {
		t.Fatalf("%+v", found)
	}
	// it is not the first use once a signer list was kept
	kept := filepath.Join(a.D.State, "generations", "fu-ws")
	os.MkdirAll(kept, 0o755)
	os.WriteFile(filepath.Join(kept, "allowed_signers"), []byte("x\n"), 0o644)
	if got := a.Gen.IsFirstUse("fu-ws", root); len(got) != 0 {
		t.Errorf("still the first use: %+v", got)
	}
}

func TestEnforceNeedsAYesAndWarnOnlyLists(t *testing.T) {
	signers := []signerFP{{"me@x", "SHA256:abc"}}
	run := func(mode string, yes bool, kind string) (bool, string) {
		a := sandboxApp(t)
		var out bytes.Buffer
		a.Out = &out
		a.Interactive = true
		a.In = bufioReader("n\n")
		if yes {
			a.In = bufioReader("y\n")
		}
		a.Gen.GitGlobal = func(string) string { return "" }
		settings.Set(a.D, "OM_SIGNED", mode)
		return a.trustFirstSigners("ws", signers, kind), out.String()
	}
	if ok, out := run("warn", false, "start"); !ok || !strings.Contains(out, "SHA256:abc") {
		t.Errorf("warn lists and goes on: %v %q", ok, out)
	}
	if ok, _ := run("enforce", true, "start"); !ok {
		t.Error("enforce with a yes")
	}
	if ok, out := run("enforce", false, "start"); ok || !strings.Contains(out, "signers were not confirmed") {
		t.Errorf("enforce without a yes: %v %q", ok, out)
	}
	if ok, _ := run("enforce", false, "dev"); !ok { // `om dev` is the unsigned, local loop
		t.Error("om dev is not blocked")
	}
}

func TestAllocateFallsBackInsteadOfCrashing(t *testing.T) {
	a := sandboxApp(t)
	ip, err := a.Egress.AllocateServiceIP("ws-x", "svc", "not-a-subnet")
	if err != nil || !strings.HasPrefix(ip, "10.89.") {
		t.Errorf("%q %v", ip, err)
	}
}

var _ = generations.New
var _ = state.Version

func bufioReader(s string) *bufio.Reader { return bufio.NewReader(strings.NewReader(s)) }
