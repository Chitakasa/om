package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	reActive = regexp.MustCompile(`"last_active": \d+`)
	reStamp  = regexp.MustCompile(`\d{8}-\d{6}`)
	reCfg    = regexp.MustCompile(`/tmp/(tmp[a-z0-9_]+|\d+)\.cfg`)
)

func normalize(s string) string {
	s = reActive.ReplaceAllString(s, `"last_active": N`)
	s = reStamp.ReplaceAllString(s, "TS")
	return reCfg.ReplaceAllString(s, "/tmp/X.cfg")
}

// TestE2EBasicMatchesPython runs the built binary through testdata/e2e/basic.sh (a workspace's life without a real
// engine) and compares everything it prints with what the Python implementation printed.
func TestE2EBasicMatchesPython(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "om")
	if out, err := exec.Command("go", "build", "-o", bin, "../../cmd/om").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	fake := filepath.Join(tmp, "fakebin")
	os.MkdirAll(fake, 0o755)
	src, _ := os.ReadFile("../../testdata/e2e/fake-podman")
	os.WriteFile(filepath.Join(fake, "podman"), src, 0o755)
	scratch := filepath.Join(tmp, "OUTDIR")
	cmd := exec.Command("bash", "../../testdata/e2e/basic.sh")
	cmd.Env = append(os.Environ(), "OM="+bin, "OUT="+scratch, "FAKEBIN="+fake)
	out, _ := cmd.CombinedOutput()
	got := normalize(strings.ReplaceAll(string(out), scratch, "OUT"))
	want, err := os.ReadFile("../../testdata/e2e/basic.golden")
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		os.WriteFile(filepath.Join(os.TempDir(), "om-e2e-got.txt"), []byte(got), 0o644)
		gl, wl := strings.Split(got, "\n"), strings.Split(string(want), "\n")
		for i := 0; i < len(gl) && i < len(wl); i++ {
			if gl[i] != wl[i] {
				t.Fatalf("line %d differs (full output in %s/om-e2e-got.txt)\n go: %s\n py: %s", i+1, os.TempDir(), gl[i], wl[i])
			}
		}
		t.Fatalf("length differs: go %d lines, python %d lines", len(gl), len(wl))
	}
}
