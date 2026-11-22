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
