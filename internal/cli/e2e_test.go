package cli

import (
	"fmt"
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
	reCfg    = regexp.MustCompile(`[^\s:]*/(tmp[a-z0-9_]+|\d+)\.cfg`)
	// the other login accounts of the machine that recorded (or runs) the scenario
	reOthers = regexp.MustCompile(`(?m); other accounts: .*$`)
	// the state of the machine's own firewall (nft on Linux, pf on macOS)
	reFirewall = regexp.MustCompile(`(?m)^  Host firewall: .*$`)
	// the doctor's totals include the rows of the machine itself (masked above)
	reCounts    = regexp.MustCompile(`(?m)^  \d+ failure\(s\), \d+ warning\(s\)$`)
	reOthersRaw = regexp.MustCompile(`(?s)"other_accounts": \[.*?\]`)
	// rows of om doctor that read the machine itself: its other login accounts, the firewall rules installed in /etc
	reHostRows = regexp.MustCompile(`(?m)^  (PASS|WARN|FAIL)  (Login|Address rules) .*\n(?:[ ]+↳ .*\n)*`)
)

func normalize(s string) string {
	s = reActive.ReplaceAllString(s, `"last_active": N`)
	s = reStamp.ReplaceAllString(s, "TS")
	s = reOthers.ReplaceAllString(s, "")
	s = reFirewall.ReplaceAllString(s, "  Host firewall: STATE")
	s = reOthersRaw.ReplaceAllString(s, `"other_accounts": []`)
	return reCfg.ReplaceAllString(s, "/tmp/X.cfg")
}

// replaceScratch names the scenario's folder OUT, whichever way the binary spelled it (macOS: /private/var/...).
func replaceScratch(s, scratch string) string {
	for _, p := range []string{"/private" + scratch, realPath(scratch), scratch} {
		s = strings.ReplaceAll(s, p, "OUT")
	}
	// the scenario script itself names its folder OUT in the engine log it prints, before this runs
	return strings.ReplaceAll(s, "/privateOUT", "OUT")
}

// firstDiffs lists the first lines that differ (a line added or dropped shifts every line after it).
func firstDiffs(got, want string) string {
	gl, wl := strings.Split(got, "\n"), strings.Split(want, "\n")
	var b strings.Builder
	n := 0
	for i := 0; i < len(gl) || i < len(wl); i++ {
		var g, w string
		if i < len(gl) {
			g = gl[i]
		}
		if i < len(wl) {
			w = wl[i]
		}
		if g == w {
			continue
		}
		fmt.Fprintf(&b, "line %d\n go: %s\n py: %s\n", i+1, g, w)
		if n++; n == 60 {
			b.WriteString("...\n")
			break
		}
	}
	return b.String()
}

// realPath resolves symbolic links of the folder holding path (macOS temp dirs live behind /var -> /private/var, and
// the binary prints the resolved name); the file itself need not exist yet.
func realPath(path string) string {
	if dir, err := filepath.EvalSymlinks(filepath.Dir(path)); err == nil {
		return filepath.Join(dir, filepath.Base(path))
	}
	return path
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
	if out, err := exec.Command("bash", "../../testdata/e2e/fakebasic.sh", fake).CombinedOutput(); err != nil {
		t.Fatalf("fake tools: %v\n%s", err, out)
	}
	scratch := filepath.Join(tmp, "OUTDIR")
	cmd := exec.Command("bash", "../../testdata/e2e/basic.sh")
	cmd.Env = append(append(os.Environ(), covEnv()...), "OM="+bin, "OUT="+scratch, "FAKEBIN="+fake)
	out, _ := cmd.CombinedOutput()
	got := normalize(replaceScratch(string(out), scratch))
	raw, err := os.ReadFile("../../testdata/e2e/basic.golden")
	if err != nil {
		t.Fatal(err)
	}
	want := []byte(normalize(string(raw)))
	if got != string(want) {
		os.WriteFile(filepath.Join(os.TempDir(), "om-e2e-got.txt"), []byte(got), 0o644)
		t.Fatalf("differs (full output in %s/om-e2e-got.txt)\n%s", os.TempDir(), firstDiffs(got, string(want)))
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

// sortRuns puts each run of consecutive lines that start with prefix in order: both programs print some listings in
// the order the file system returns them, which differs between machines.
func sortRuns(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i := 0; i < len(lines); {
		if !strings.HasPrefix(lines[i], prefix) {
			i++
			continue
		}
		j := i
		for j < len(lines) && strings.HasPrefix(lines[j], prefix) {
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
	s = reHostRows.ReplaceAllString(s, "")
	s = reOthers.ReplaceAllString(s, "")
	s = reHex.ReplaceAllString(s, "HEX")
	s = reISO.ReplaceAllString(s, "TS")
	s = reDate.ReplaceAllString(s, "DATE")
	s = reStamp.ReplaceAllString(s, "STAMP")
	s = reUser.ReplaceAllString(s, "$1 USER")
	s = regexp.MustCompile(`[^\s:]*/[A-Za-z0-9_]+\.cfg`).ReplaceAllString(s, "/tmp/X.cfg")
	s = strings.ReplaceAll(s, "~/.local/state/om/bin/om-dashboard\n", "")
	s = reCounts.ReplaceAllString(s, "  N failure(s), M warning(s)")
	return sortRuns(sortRuns(s, "  - Removed stale route "), "~/.local/state/om/")
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
	cmd.Env = append(append(os.Environ(), covEnv()...), "OM="+bin, "OUT="+scratch, "FAKEBIN="+fake, "OM_SRC="+repo, "FAKE_EDGE_PORT="+port)
	out, _ := cmd.CombinedOutput()
	clean := func(s string) string {
		s = replaceScratch(s, scratch)
		return normalizeEngine(regexp.MustCompile(`\b`+port+`\b`).ReplaceAllString(s, "18080"))
	}
	check := func(what, got, want string) {
		t.Helper()
		if got == want {
			return
		}
		os.WriteFile(filepath.Join(os.TempDir(), "om-e2e-engine-"+what+".txt"), []byte(got), 0o644)
		t.Fatalf("%s: differs (full output in %s)\n%s", what, filepath.Join(os.TempDir(), "om-e2e-engine-"+what+".txt"), firstDiffs(got, want))
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
