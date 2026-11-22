package cli

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
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
	if runtime.GOOS == "windows" {
		t.Skip("the fake engine is a shell script")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "om")
	if out, err := buildOm(bin).CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	fake := filepath.Join(tmp, "fakebin")
	os.MkdirAll(fake, 0o755)
	src, _ := os.ReadFile("../../testdata/e2e/fake-podman")
	os.WriteFile(filepath.Join(fake, "podman"), src, 0o755)
	scratch := filepath.Join(tmp, "OUTDIR")
	cmd := exec.Command("bash", "../../testdata/e2e/basic.sh")
	cmd.Env = append(append(os.Environ(), covEnv()...), "OM="+bin, "OUT="+scratch, "FAKEBIN="+fake)
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

var (
	reHex      = regexp.MustCompile(`\b[0-9a-f]{8}\b|\b[0-9a-f]{12}\b|\b[0-9a-f]{40}\b|\b[0-9a-f]{64}\b`)
	reISO      = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T[0-9:+]+`)
	reDate     = regexp.MustCompile(`\d{4}-\d{2}-\d{2} \d{2}:\d{2}`)
	reUser     = regexp.MustCompile(`(show-user|enable-linger) \S+`)
	reStale    = regexp.MustCompile(`(?m)^  - Removed stale route .*\n`)
	reInfo     = regexp.MustCompile(`(?m)^podman info --format .*\n`)
	reProbeRun = regexp.MustCompile(`(?m)^podman (run|exec) .*( python3 -c |/om-dashboard probe ).*\n`)
	rePyRow    = regexp.MustCompile(`(?m)^  PASS  Python .*\n`)
)

// sortStale puts each run of "Removed stale route" lines in order: Python printed them in directory order.
func sortStale(s string) string {
	lines := strings.Split(s, "\n")
	for i := 0; i < len(lines); {
		if !strings.HasPrefix(lines[i], "  - Removed stale route ") {
			i++
			continue
		}
		j := i
		for j < len(lines) && strings.HasPrefix(lines[j], "  - Removed stale route ") {
			j++
		}
		sort.Strings(lines[i:j])
		i = j
	}
	return strings.Join(lines, "\n")
}

// normalizeEngine hides what differs between runs and between the two implementations on purpose: hashes, times,
// temp names, the user name, the order of directory listings, the doctor's Python check (gone) and the probes that
// run inside containers (om probe instead of python3 -c), the dashboard binary om now installs, and `podman info`
// (om asks once per run, Python again whenever its cache missed).
func normalizeEngine(s string) string {
	s = reProbeRun.ReplaceAllString(reInfo.ReplaceAllString(s, ""), "")
	s = rePyRow.ReplaceAllString(s, "")
	s = reHex.ReplaceAllString(s, "HEX")
	s = reISO.ReplaceAllString(s, "TS")
	s = reDate.ReplaceAllString(s, "DATE")
	s = reStamp.ReplaceAllString(s, "STAMP")
	s = reUser.ReplaceAllString(s, "$1 USER")
	s = regexp.MustCompile(`/tmp/[A-Za-z0-9_]+\.cfg`).ReplaceAllString(s, "/tmp/X.cfg")
	s = strings.ReplaceAll(s, "~/.local/state/om/bin/om-dashboard\n", "")
	return sortStale(s)
}

// TestE2EEngineMatchesPython runs the commands that need a container engine (start, stop, update, core, sync,
// previews, doctor, firewall, boot, uninstall...) against a fake engine and compares both what om prints and the
// calls it makes with what the Python implementation did (testdata/e2e/record.sh recorded it).
func TestE2EEngineMatchesPython(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the goldens were recorded on Linux (interface detection, the fake engine as an executable)")
	}
	for _, tool := range []string{"bash", "git", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip("no " + tool)
		}
	}
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "om")
	if out, err := buildOm(bin).CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	fake := filepath.Join(tmp, "fakebin")
	if out, err := exec.Command("bash", "../../testdata/e2e/fakebin.sh", fake).CombinedOutput(); err != nil {
		t.Fatalf("fake engine: %v\n%s", err, out)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	scratch := filepath.Join(tmp, "OUT")
	repo, _ := filepath.Abs("../..")
	cmd := exec.Command("bash", "../../testdata/e2e/engine.sh")
	cmd.Env = append(append(os.Environ(), covEnv()...), "OM="+bin, "OUT="+scratch, "FAKEBIN="+fake, "OM_SRC="+repo, "FAKE_EDGE_PORT="+port, "OM_PY=")
	out, _ := cmd.CombinedOutput()
	clean := func(s string) string {
		s = strings.ReplaceAll(s, scratch, "OUT")
		return normalizeEngine(regexp.MustCompile(`\b`+port+`\b`).ReplaceAllString(s, "18080"))
	}
	check := func(what, got, want string) {
		t.Helper()
		if got == want {
			return
		}
		os.WriteFile(filepath.Join(os.TempDir(), "om-e2e-engine-"+what+".txt"), []byte(got), 0o644)
		gl, wl := strings.Split(got, "\n"), strings.Split(want, "\n")
		for i := 0; i < len(gl) && i < len(wl); i++ {
			if gl[i] != wl[i] {
				t.Fatalf("%s: line %d differs (full output in %s)\n go: %s\n py: %s", what, i+1, filepath.Join(os.TempDir(), "om-e2e-engine-"+what+".txt"), gl[i], wl[i])
			}
		}
		t.Fatalf("%s: length differs: go %d lines, python %d lines", what, len(gl), len(wl))
	}
	want, err := os.ReadFile("../../testdata/e2e/engine.golden")
	if err != nil {
		t.Fatal(err)
	}
	check("stdout", clean(string(out)), normalizeEngine(string(want)))
	gotLog, _ := os.ReadFile(filepath.Join(scratch, "engine.log"))
	wantLog, err := os.ReadFile("../../testdata/e2e/engine.log.golden")
	if err != nil {
		t.Fatal(err)
	}
	check("calls", clean(string(gotLog)), normalizeEngine(string(wantLog)))
}

// buildOm is `go build` of the program. With OM_E2E_COVERDIR set the binary is built with coverage, and the runs of the
// scenarios (their environment gets GOCOVERDIR) write their counters there: CI merges them into the coverage figure,
// because the command layer is exercised mostly through the binary.
func buildOm(bin string) *exec.Cmd {
	args := []string{"build", "-o", bin}
	if os.Getenv("OM_E2E_COVERDIR") != "" {
		args = append(args, "-cover", "-coverpkg=github.com/Chitakasa/om/internal/...,github.com/Chitakasa/om/cmd/...")
	}
	return exec.Command("go", append(args, "../../cmd/om")...)
}

// covEnv is the environment addition that makes a coverage build write its counters.
func covEnv() []string {
	if d := os.Getenv("OM_E2E_COVERDIR"); d != "" {
		os.MkdirAll(d, 0o755)
		return []string{"GOCOVERDIR=" + d}
	}
	return nil
}
