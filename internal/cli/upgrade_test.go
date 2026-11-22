package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Chitakasa/om/internal/state"
)

func upgradeApp(t *testing.T, git func(args []string) state.Result) (*App, *bytes.Buffer, *[][]string) {
	t.Helper()
	a := sandboxApp(t)
	var out bytes.Buffer
	a.Out, a.GOOS = &out, "linux"
	os.MkdirAll(filepath.Join(a.D.Home, ".git"), 0o755)
	a.LookPath = func(string) (string, error) { return "/usr/bin/git", nil }
	a.RunIn = func(cmd []string, dir string, env []string) state.Result {
		return git(cmd[3:]) // git -C <home> <args...>
	}
	var passed [][]string
	a.Passthrough = func(cmd []string, dir string, env []string) int {
		passed = append(passed, append([]string(nil), cmd...))
		return 0
	}
	return a, &out, &passed
}

func upgradeNS(t *testing.T, a *App, args ...string) Namespace {
	t.Helper()
	ns, err := a.Parser.Parse(append([]string{"upgrade"}, args...))
	if err != nil {
		t.Fatal(err)
	}
	return ns
}

func TestUpgradeRefusesWhatItCannotDoSafely(t *testing.T) {
	ok := func([]string) state.Result { return state.Result{} }
	t.Run("not a checkout", func(t *testing.T) {
		a, _, passed := upgradeApp(t, ok)
		os.RemoveAll(filepath.Join(a.D.Home, ".git"))
		err := a.cmdUpgrade(upgradeNS(t, a))
		if err == nil || !strings.Contains(err.Error(), "not a git checkout") || len(*passed) != 0 {
			t.Errorf("err=%v passed=%v", err, *passed)
		}
	})
	t.Run("uncommitted changes", func(t *testing.T) {
		a, _, passed := upgradeApp(t, func(args []string) state.Result {
			if args[0] == "status" {
				return state.Result{Stdout: " M internal/x.go\n"}
			}
			return state.Result{}
		})
		err := a.cmdUpgrade(upgradeNS(t, a))
		if err == nil || !strings.Contains(err.Error(), "uncommitted changes") || len(*passed) != 0 {
			t.Errorf("err=%v passed=%v", err, *passed)
		}
	})
	t.Run("cannot fast-forward", func(t *testing.T) {
		a, _, passed := upgradeApp(t, func(args []string) state.Result {
			switch args[0] {
			case "rev-parse":
				return state.Result{Stdout: "abc1234\n"}
			case "merge":
				return state.Result{Code: 128, Stderr: "fatal: Not possible to fast-forward, aborting."}
			}
			return state.Result{}
		})
		err := a.cmdUpgrade(upgradeNS(t, a))
		if err == nil || !strings.Contains(err.Error(), "Cannot fast-forward") || len(*passed) != 0 {
			t.Errorf("err=%v passed=%v", err, *passed)
		}
	})
}

func TestUpgradeBuildsThroughTheInstallerAndSaysWhatIsLeft(t *testing.T) {
	heads := []string{"aaa1111", "bbb2222"} // before the merge, after it
	newGit := func() func([]string) state.Result {
		n := 0
		return func(args []string) state.Result {
			if args[0] == "rev-parse" && args[1] == "--short" {
				h := heads[min(n, 1)]
				n++
				return state.Result{Stdout: h + "\n"}
			}
			return state.Result{}
		}
	}
	t.Run("up to date", func(t *testing.T) {
		a, out, passed := upgradeApp(t, func(args []string) state.Result {
			if args[0] == "rev-parse" && args[1] == "--short" {
				return state.Result{Stdout: "aaa1111\n"}
			}
			return state.Result{}
		})
		if err := a.cmdUpgrade(upgradeNS(t, a)); err != nil || len(*passed) != 0 || !strings.Contains(out.String(), "up to date") {
			t.Errorf("err=%v passed=%v out=%s", err, *passed, out.String())
		}
	})
	t.Run("upgraded", func(t *testing.T) {
		a, out, passed := upgradeApp(t, newGit())
		if err := a.cmdUpgrade(upgradeNS(t, a)); err != nil {
			t.Fatal(err)
		}
		if len(*passed) != 1 || (*passed)[0][0] != "bash" || !strings.HasSuffix((*passed)[0][len((*passed)[0])-1], "install.sh") {
			t.Fatalf("the installer was not run once: %v", *passed)
		}
		if !strings.Contains(strings.Join((*passed)[0], " "), "/dev/null") {
			t.Errorf("the installer must run without questions: %v", (*passed)[0])
		}
		if s := out.String(); !strings.Contains(s, "aaa1111 → bbb2222") || !strings.Contains(s, "om core restart") {
			t.Errorf("output:\n%s", s)
		}
	})
	t.Run("with --core", func(t *testing.T) {
		a, out, passed := upgradeApp(t, newGit())
		if err := a.cmdUpgrade(upgradeNS(t, a, "--core")); err != nil {
			t.Fatal(err)
		}
		if len(*passed) != 2 || strings.Join((*passed)[1][1:], " ") != "core restart" || filepath.Base((*passed)[1][0]) != "om" {
			t.Fatalf("calls: %v", *passed)
		}
		if strings.Contains(out.String(), "were not restarted") {
			t.Errorf("output:\n%s", out.String())
		}
	})
	t.Run("the installer fails", func(t *testing.T) {
		a, _, _ := upgradeApp(t, newGit())
		a.Passthrough = func([]string, string, []string) int { return 3 }
		err := a.cmdUpgrade(upgradeNS(t, a))
		var e *ExitError
		if err == nil || !errors.As(err, &e) || !strings.Contains(e.Msg, "install.sh failed (exit 3)") {
			t.Errorf("err=%v", err)
		}
	})
}
