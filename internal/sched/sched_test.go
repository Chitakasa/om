package sched

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/Chitakasa/om/internal/state"
)

func TestSchedMatchesPython(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the goldens were recorded on POSIX and hold / paths")
	}
	b, err := os.ReadFile("../../testdata/golden/sched.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name      string
		OS        string
		Systemctl bool
		Table     map[string][]any
		Result    any
		Stdout    string
		Files     map[string]string
		Calls     [][]string
		Sudo      [][]string
	}
	if err := json.Unmarshal(b, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		home := t.TempDir()
		var calls, sudo [][]string
		var out bytes.Buffer
		s := &Sched{OS: c.OS, Home: home, OMHome: "/opt/om-home", OMCmd: []string{"/usr/local/bin/om", "with space", `q"uote`, "50%"}, Out: &out,
			LookPath: func(n string) (string, error) {
				if n == "systemctl" && !c.Systemctl {
					return "", errors.New("none")
				}
				return "/usr/bin/" + n, nil
			},
			User: func() string { return "tester" },
		}
		s.Run = func(cmd []string) state.Result {
			calls = append(calls, append([]string(nil), cmd...))
			k := strings.Join(cmd, " ")
			best := ""
			for p := range c.Table {
				if strings.HasPrefix(k, p) && len(p) > len(best) {
					best = p
				}
			}
			if best == "" {
				return state.Result{}
			}
			return state.Result{Code: int(c.Table[best][0].(float64)), Stdout: c.Table[best][1].(string)}
		}
		s.Sudo = func(cmd []string) bool { sudo = append(sudo, append([]string(nil), cmd...)); return true }
		var res any
		n := c.Name
		rt := ""
		if strings.HasPrefix(n, "boot_") {
			parts := strings.Split(n, "_")
			rt = parts[2]
			if parts[1] != "status" {
				rt = parts[2]
			}
			n = strings.Join(parts[:2], "_")
		}
		switch n {
		case "schedule":
			res, _ = s.Schedule("autosync", []string{"sync", "--scheduled"}, 1, "om scheduled GitOps sync", "2min")
		case "schedule_fail_enable":
			res, _ = s.Schedule("heal", []string{"core", "heal"}, 2, "om core self-heal", "30s")
		case "schedule_fail_restart":
			res, _ = s.Schedule("heal", []string{"core", "heal"}, 2, "x", "30s")
		case "unschedule":
			res = s.Unschedule("autosync")
		case "status_active", "status_inactive":
			res = s.ScheduleStatus("autosync")
		case "autosync_enable":
			res, _ = s.AutosyncEnable(1)
		case "watch_enable":
			res, _ = s.WatchEnable()
		case "watch_disable":
			res = s.WatchDisable()
		case "boot_status":
			res = s.BootStatus(rt)
		case "boot_enable":
			res, _ = s.BootEnable(rt)
		case "boot_disable":
			res = s.BootDisable()
		default:
			t.Fatalf("unknown case %s", c.Name)
		}
		label := c.Name + "/" + c.OS
		if !c.Systemctl {
			label += "/nosystemctl"
		}
		if !reflect.DeepEqual(res, c.Result) {
			t.Errorf("%s: result %v, python %v", label, res, c.Result)
		}
		if out.String() != c.Stdout {
			t.Errorf("%s: output %q, python %q", label, out.String(), c.Stdout)
		}
		files := map[string]string{}
		filepath.Walk(home, func(p string, info os.FileInfo, err error) error {
			if err == nil && info.Mode().IsRegular() {
				rel, _ := filepath.Rel(home, p)
				b, _ := os.ReadFile(p)
				files[filepath.ToSlash(rel)] = string(b)
			}
			return nil
		})
		want := map[string]string{}
		for k, v := range c.Files {
			want[strings.TrimPrefix(k, "home/")] = v
		}
		if !reflect.DeepEqual(files, want) {
			t.Errorf("%s: files\n go     %v\n python %v", label, files, want)
		}
		normCalls := func(cs [][]string, home string) [][]string {
			var out [][]string
			for _, c := range cs {
				var n []string
				for _, a := range c {
					a = strings.ReplaceAll(a, home, "@HOME@")
					n = append(n, a)
				}
				out = append(out, n)
			}
			return out
		}
		pyHome := regexp.MustCompile(`/tmp/tmp[^/]+/home`)
		var wantCalls [][]string
		for _, c := range c.Calls {
			var n []string
			for _, a := range c {
				n = append(n, pyHome.ReplaceAllString(a, "@HOME@"))
			}
			wantCalls = append(wantCalls, n)
		}
		calls = normCalls(calls, home)
		c.Calls = wantCalls
		if !reflect.DeepEqual(calls, c.Calls) && !(len(calls) == 0 && len(c.Calls) == 0) {
			t.Errorf("%s: calls\n go     %v\n python %v", label, calls, c.Calls)
		}
		if !reflect.DeepEqual(sudo, c.Sudo) && !(len(sudo) == 0 && len(c.Sudo) == 0) {
			t.Errorf("%s: sudo %v, python %v", label, sudo, c.Sudo)
		}
	}
}

// A job left by the Python version runs `python3 .../bin/om`, a file that is gone: Refresh rewrites only that command.
func TestRefreshPointsOldJobsAtThisOm(t *testing.T) {
	newSched := func(goos string, run func([]string) state.Result) (*Sched, *[][]string) {
		var calls [][]string
		s := &Sched{OS: goos, Home: t.TempDir(), OMHome: "/opt/om", OMCmd: []string{"/new/om"}, Out: &bytes.Buffer{},
			LookPath: func(n string) (string, error) { return "/usr/bin/" + n, nil }}
		s.Run = func(c []string) state.Result {
			calls = append(calls, append([]string(nil), c...))
			return run(c)
		}
		return s, &calls
	}
	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	t.Run("systemd", func(t *testing.T) {
		watchActive := true
		s, calls := newSched("linux", func(c []string) state.Result {
			if len(c) >= 4 && c[2] == "is-active" && watchActive {
				return state.Result{Stdout: "active\n"}
			}
			return state.Result{}
		})
		d := s.systemdUserDir()
		old := func(args string) string {
			return "[Unit]\nDescription=x\n\n[Service]\nEnvironment=\"OM_HOME=/opt/om\"\nExecStart=\"/usr/bin/python3\" \"/opt/om/bin/om\" " + args + "\n"
		}
		write(filepath.Join(d, "om-heal.service"), old(`"core" "heal"`))
		write(filepath.Join(d, "om-watch.service"), old(`"core" "watch"`)+"Restart=always\n")
		write(filepath.Join(d, "om-heal.timer"), "[Timer]\nOnUnitActiveSec=2min\n")
		got := s.Refresh()
		if !reflect.DeepEqual(got, []string{"watch", "heal"}) {
			t.Fatalf("changed %v", got)
		}
		if h := read(filepath.Join(d, "om-heal.service")); !strings.Contains(h, "ExecStart=\"/new/om\" \"core\" \"heal\"\n") || !strings.Contains(h, "Environment=\"OM_HOME=/opt/om\"") || strings.Contains(h, "python") {
			t.Errorf("heal service:\n%s", h)
		}
		if w := read(filepath.Join(d, "om-watch.service")); !strings.Contains(w, "ExecStart=\"/new/om\" \"core\" \"watch\"\n") || !strings.Contains(w, "Restart=always") {
			t.Errorf("watch service:\n%s", w)
		}
		if read(filepath.Join(d, "om-heal.timer")) != "[Timer]\nOnUnitActiveSec=2min\n" {
			t.Error("the timer changed")
		}
		var sawReload, sawRestart bool
		for _, c := range *calls {
			k := strings.Join(c, " ")
			sawReload = sawReload || k == "systemctl --user daemon-reload"
			sawRestart = sawRestart || k == "systemctl --user restart om-watch.service"
		}
		if !sawReload || !sawRestart {
			t.Errorf("calls %v", *calls)
		}
		// nothing left to change: no second pass, no calls
		*calls = nil
		again := s.Refresh()
		for _, c := range *calls {
			if !strings.Contains(strings.Join(c, " "), " show ") { // looking at the watcher is not changing anything
				t.Errorf("second pass called %v", c)
			}
		}
		if len(again) != 0 {
			t.Errorf("second pass changed %v", again)
		}
		// a watcher that is not running is not started
		write(filepath.Join(d, "om-watch.service"), old(`"core" "watch"`))
		watchActive = false
		*calls = nil
		s.Refresh()
		for _, c := range *calls {
			if strings.Join(c, " ") == "systemctl --user restart om-watch.service" {
				t.Error("restarted a watcher that was stopped")
			}
		}
	})

	t.Run("no jobs installed", func(t *testing.T) {
		s, calls := newSched("linux", func([]string) state.Result { return state.Result{} })
		if got := s.Refresh(); len(got) != 0 || len(*calls) != 0 {
			t.Errorf("changed %v with calls %v", got, *calls)
		}
	})

	t.Run("launchd keeps the interval", func(t *testing.T) {
		s, calls := newSched("darwin", func([]string) state.Result { return state.Result{} })
		plist := s.launchdPlist("autosync")
		write(plist, "<plist><dict><key>ProgramArguments</key><array><string>/usr/bin/python3</string><string>/opt/om/bin/om</string><string>sync</string><string>--scheduled</string></array>"+
			"<key>StartInterval</key><integer>600</integer></dict></plist>")
		if got := s.Refresh(); !reflect.DeepEqual(got, []string{"autosync"}) {
			t.Fatalf("changed %v", got)
		}
		p := read(plist)
		if !strings.Contains(p, "<array><string>/new/om</string><string>sync</string><string>--scheduled</string></array>") || !strings.Contains(p, "<integer>600</integer>") {
			t.Errorf("plist:\n%s", p)
		}
		if len(*calls) != 2 || (*calls)[0][1] != "unload" || (*calls)[1][1] != "load" {
			t.Errorf("calls %v", *calls)
		}
		*calls = nil
		if again := s.Refresh(); len(again) != 0 || len(*calls) != 0 {
			t.Errorf("second pass changed %v with calls %v", again, *calls)
		}
	})

	t.Run("schtasks recreates only a stale task", func(t *testing.T) {
		s, calls := newSched("windows", func(c []string) state.Result {
			if len(c) > 1 && c[1] == "/Query" && c[3] == "om-heal" {
				return state.Result{Stdout: "TaskName: om-heal\nTask To Run:   \"python3\" \"C:\\om\\bin\\om\" \"core\" \"heal\"\n"}
			}
			if len(c) > 1 && c[1] == "/Query" {
				return state.Result{Code: 1}
			}
			return state.Result{}
		})
		if got := s.Refresh(); !reflect.DeepEqual(got, []string{"heal"}) {
			t.Fatalf("changed %v", got)
		}
		var created []string
		for _, c := range *calls {
			if len(c) > 1 && c[1] == "/Create" {
				created = c
			}
		}
		if strings.Join(created, " ") != `schtasks /Create /F /SC MINUTE /MO 2 /TN om-heal /TR "/new/om" "core" "heal"` {
			t.Errorf("create %v", created)
		}
		// an up-to-date task is left alone
		s2, calls2 := newSched("windows", func(c []string) state.Result {
			if len(c) > 1 && c[1] == "/Query" && c[3] == "om-heal" {
				return state.Result{Stdout: "Task To Run:   \"/new/om\" \"core\" \"heal\"\n"}
			}
			if len(c) > 1 && c[1] == "/Query" {
				return state.Result{Code: 1}
			}
			return state.Result{}
		})
		if got := s2.Refresh(); len(got) != 0 {
			t.Errorf("changed %v with calls %v", got, *calls2)
		}
	})
}

// The unit may already name this om while the running watcher still holds the one before an upgrade: Refresh restarts it.
func TestRefreshRestartsAWatcherOnTheOldBinary(t *testing.T) {
	proc := t.TempDir()
	setExe := func(target string) {
		os.RemoveAll(filepath.Join(proc, "4242"))
		os.MkdirAll(filepath.Join(proc, "4242"), 0o755)
		if err := os.Symlink(target, filepath.Join(proc, "4242", "exe")); err != nil {
			t.Skip("no symlinks here:", err)
		}
	}
	run := func(restarted *bool) func([]string) state.Result {
		return func(c []string) state.Result {
			k := strings.Join(c, " ")
			switch {
			case strings.Contains(k, "show -p MainPID"):
				return state.Result{Stdout: "4242\n"}
			case k == "systemctl --user restart om-watch.service":
				*restarted = true
			}
			return state.Result{}
		}
	}
	for _, tc := range []struct {
		name, exe string
		want      bool
	}{
		{"replaced by an upgrade", "/new/om (deleted)", true},
		{"another program", "/usr/bin/python3", true},
		{"this om", "/new/om", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setExe(tc.exe)
			var restarted bool
			s := &Sched{OS: "linux", Home: t.TempDir(), OMHome: "/opt/om", OMCmd: []string{"/new/om"}, Out: &bytes.Buffer{}, ProcRoot: proc,
				LookPath: func(n string) (string, error) { return "/usr/bin/" + n, nil }, Run: run(&restarted)}
			// the unit already names this om
			write(filepath.Join(s.systemdUserDir(), "om-watch.service"), "[Service]\nExecStart=\"/new/om\" \"core\" \"watch\"\n")
			got := s.Refresh()
			if restarted != tc.want || (len(got) > 0) != tc.want {
				t.Errorf("restarted=%v changed=%v, want restart=%v", restarted, got, tc.want)
			}
		})
	}
	// no process to inspect: left alone
	var restarted bool
	s := &Sched{OS: "linux", Home: t.TempDir(), OMCmd: []string{"/new/om"}, Out: &bytes.Buffer{}, ProcRoot: t.TempDir(),
		LookPath: func(n string) (string, error) { return "/usr/bin/" + n, nil }, Run: run(&restarted)}
	write(filepath.Join(s.systemdUserDir(), "om-watch.service"), "[Service]\nExecStart=\"/new/om\" \"core\" \"watch\"\n")
	if s.Refresh(); restarted {
		t.Error("restarted a watcher whose process could not be inspected")
	}
}
