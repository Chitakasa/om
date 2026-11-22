// Package sched is om's OS integration for scheduled jobs: auto-sync and the core's self-heal (systemd user timers,
// launchd agents, Windows scheduled tasks) and start at boot. Port of the second half of lib/gitops/hostsetup.py.
//
// The jobs run `om <args>`: OMCmd is the command that starts om (the Go binary itself; in the Python version it was
// the interpreter and bin/om), so unit files name whatever binary is installed.
package sched

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/state"
)

// Sched installs scheduled jobs. The function fields exist for tests.
type Sched struct {
	OS       string
	Home     string // the user's home
	OMHome   string
	OMCmd    []string
	Run      func([]string) state.Result
	LookPath func(string) (string, error)
	Out      io.Writer
	Sudo     func(cmd []string) bool
	User     func() string
	ProcRoot string // "/proc" (replaced in tests)
}

// New returns a Sched for this machine; omCmd is how to start om (usually just the path of this binary).
func New(goos, omHome string, omCmd []string) *Sched {
	home, _ := os.UserHomeDir()
	s := &Sched{OS: goos, Home: home, OMHome: omHome, OMCmd: omCmd, Run: func(c []string) state.Result { return state.Run(c) },
		LookPath: exec.LookPath, Out: os.Stdout, ProcRoot: "/proc"}
	s.Sudo = func(cmd []string) bool {
		fmt.Fprintf(s.Out, "  $ sudo %s\n", strings.Join(cmd, " "))
		c := exec.Command("sudo", cmd...)
		c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
		return c.Run() == nil
	}
	s.User = func() string {
		if u, err := user.Current(); err == nil {
			return u.Username
		}
		return ""
	}
	return s
}

func (s *Sched) linux() bool   { return s.OS == "linux" }
func (s *Sched) macos() bool   { return s.OS == "darwin" }
func (s *Sched) windows() bool { return s.OS == "windows" }

func (s *Sched) hasSystemctl() bool {
	_, err := s.LookPath("systemctl")
	return err == nil
}

func (s *Sched) systemdUserDir() string { return filepath.Join(s.Home, ".config", "systemd", "user") }
func (s *Sched) launchdPlist(name string) string {
	return filepath.Join(s.Home, "Library", "LaunchAgents", "dev.om."+name+".plist")
}

// unitArg is one word of a systemd ExecStart/Environment line: quoted, with `\`, `"` and the `%` specifier escaped.
func unitArg(a string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%").Replace(a) + `"`
}

func unitExec(cmd []string) string {
	o := make([]string, len(cmd))
	for i, a := range cmd {
		o[i] = unitArg(a)
	}
	return strings.Join(o, " ")
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func write(path, text string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(text), 0o644)
}

func (s *Sched) cmd(args []string) []string { return append(append([]string{}, s.OMCmd...), args...) }

// Schedule runs `om <args>` every N minutes and shortly after boot, using the OS scheduler.
func (s *Sched) Schedule(name string, args []string, everyMinutes int, description, bootDelay string) (bool, error) {
	cmd := s.cmd(args)
	switch {
	case s.linux() && s.hasSystemctl():
		d := s.systemdUserDir()
		svc := "[Unit]\nDescription=" + description + "\n\n[Service]\nType=oneshot\nEnvironment=" + unitArg("OM_HOME="+s.OMHome) +
			"\nExecStart=" + unitExec(cmd) + "\n"
		if err := write(filepath.Join(d, "om-"+name+".service"), svc); err != nil {
			return false, err
		}
		timer := "[Unit]\nDescription=" + description + " (timer)\n\n[Timer]\nOnBootSec=" + bootDelay + "\nOnActiveSec=" + bootDelay +
			"\nOnUnitActiveSec=" + strconv.Itoa(everyMinutes) + "min\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"
		if err := write(filepath.Join(d, "om-"+name+".timer"), timer); err != nil {
			return false, err
		}
		s.Run([]string{"systemctl", "--user", "daemon-reload"})
		ok := s.Run([]string{"systemctl", "--user", "enable", "--now", "om-" + name + ".timer"}).Code == 0
		// `enable --now` leaves an already-running timer on its old definition: restart it to load the new one
		return ok && s.Run([]string{"systemctl", "--user", "restart", "om-" + name + ".timer"}).Code == 0, nil
	case s.macos():
		plist := s.launchdPlist(name)
		var argx strings.Builder
		for _, a := range cmd {
			argx.WriteString("<string>" + xmlEscape(a) + "</string>")
		}
		text := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
			"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n" +
			"<plist version=\"1.0\"><dict>\n" +
			"  <key>Label</key><string>dev.om." + name + "</string>\n" +
			"  <key>ProgramArguments</key><array>" + argx.String() + "</array>\n" +
			"  <key>EnvironmentVariables</key><dict><key>OM_HOME</key><string>" + xmlEscape(s.OMHome) + "</string></dict>\n" +
			"  <key>StartInterval</key><integer>" + strconv.Itoa(everyMinutes*60) + "</integer>\n" +
			"  <key>RunAtLoad</key><true/>\n</dict></plist>\n"
		if err := write(plist, text); err != nil {
			return false, err
		}
		s.Run([]string{"launchctl", "unload", plist})
		return s.Run([]string{"launchctl", "load", plist}).Code == 0, nil
	case s.windows():
		q := make([]string, len(cmd))
		for i, a := range cmd {
			q[i] = `"` + a + `"`
		}
		return s.Run([]string{"schtasks", "/Create", "/F", "/SC", "MINUTE", "/MO", strconv.Itoa(everyMinutes),
			"/TN", "om-" + name, "/TR", strings.Join(q, " ")}).Code == 0, nil
	}
	fmt.Fprintf(s.Out, "No supported scheduler found. Add to `crontab -e`:\n  */%d * * * * %s\n", everyMinutes, strings.Join(cmd, " "))
	return false, nil
}

// Unschedule removes a job.
func (s *Sched) Unschedule(name string) bool {
	switch {
	case s.linux() && s.hasSystemctl():
		s.Run([]string{"systemctl", "--user", "disable", "--now", "om-" + name + ".timer"})
		for _, suffix := range []string{"service", "timer"} {
			os.Remove(filepath.Join(s.systemdUserDir(), "om-"+name+"."+suffix))
		}
		s.Run([]string{"systemctl", "--user", "daemon-reload"})
	case s.macos():
		plist := s.launchdPlist(name)
		s.Run([]string{"launchctl", "unload", plist})
		os.Remove(plist)
	case s.windows():
		s.Run([]string{"schtasks", "/Delete", "/F", "/TN", "om-" + name})
	}
	return true
}

// ScheduleStatus is "active", "inactive" or "unknown".
func (s *Sched) ScheduleStatus(name string) string {
	switch {
	case s.linux() && s.hasSystemctl():
		if out := py.Strip(s.Run([]string{"systemctl", "--user", "is-active", "om-" + name + ".timer"}).Stdout); out != "" {
			return out
		}
		return "inactive"
	case s.macos():
		if s.Run([]string{"launchctl", "list", "dev.om." + name}).Code == 0 {
			return "active"
		}
		return "inactive"
	case s.windows():
		if s.Run([]string{"schtasks", "/Query", "/TN", "om-" + name}).Code == 0 {
			return "active"
		}
		return "inactive"
	}
	return "unknown"
}

// AutosyncEnable fires every minute; each workspace's own interval_seconds decides whether it syncs.
func (s *Sched) AutosyncEnable(everyMinutes int) (bool, error) {
	return s.Schedule("autosync", []string{"sync", "--scheduled"}, everyMinutes, "om scheduled GitOps sync", "2min")
}

func (s *Sched) AutosyncDisable() bool  { return s.Unschedule("autosync") }
func (s *Sched) AutosyncStatus() string { return s.ScheduleStatus("autosync") }

// BootStatus summarizes whether containers and the self-heal job come back after a reboot.
func (s *Sched) BootStatus(runtime string) string {
	heal := s.ScheduleStatus("heal")
	engine := s.engineBootStatus(runtime)
	if heal == "active" && strings.HasPrefix(engine, "enabled") && !strings.Contains(engine, "only after") {
		return "enabled"
	}
	parts := "engine: " + engine + "; self-heal: " + heal
	if heal == "active" || strings.HasPrefix(engine, "enabled") {
		return "partial (" + parts + ")"
	}
	return "disabled"
}

// WatchEnable installs `om core watch` as a service (Linux/systemd), so a container whose process dies unseen is
// restarted within a couple of seconds instead of at the next 2-minute self-heal.
func (s *Sched) WatchEnable() (bool, error) {
	if !(s.linux() && s.hasSystemctl()) {
		return false, nil
	}
	text := "[Unit]\nDescription=om container watcher (instant recovery)\n\n[Service]\nType=simple\nEnvironment=" + unitArg("OM_HOME="+s.OMHome) +
		"\nExecStart=" + unitExec(s.cmd([]string{"core", "watch"})) + "\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=default.target\n"
	if err := write(filepath.Join(s.systemdUserDir(), "om-watch.service"), text); err != nil {
		return false, err
	}
	s.Run([]string{"systemctl", "--user", "daemon-reload"})
	return s.Run([]string{"systemctl", "--user", "enable", "--now", "om-watch.service"}).Code == 0, nil
}

func (s *Sched) WatchDisable() bool {
	if s.linux() && s.hasSystemctl() {
		s.Run([]string{"systemctl", "--user", "disable", "--now", "om-watch.service"})
		os.Remove(filepath.Join(s.systemdUserDir(), "om-watch.service"))
		s.Run([]string{"systemctl", "--user", "daemon-reload"})
	}
	return true
}

// BootEnable makes containers restart at boot, and installs a self-heal job that re-applies the network every 2
// minutes (new LAN address, a VPN coming up late, core crashed).
func (s *Sched) BootEnable(runtime string) (bool, error) {
	ok := s.engineBootEnable(runtime)
	s.WatchEnable() // optional extra: instant recovery; the 2-minute self-heal below is the fallback
	healed, err := s.Schedule("heal", []string{"core", "heal"}, 2, "om core self-heal", "30s")
	return healed && ok, err
}

func (s *Sched) BootDisable() bool {
	s.WatchDisable()
	return s.Unschedule("heal")
}

func (s *Sched) engineBootStatus(runtime string) string {
	switch {
	case runtime == "podman" && s.linux():
		en := py.Strip(s.Run([]string{"systemctl", "--user", "is-enabled", "podman-restart.service"}).Stdout)
		linger := py.Strip(s.Run([]string{"loginctl", "show-user", s.User(), "--property=Linger"}).Stdout)
		switch {
		case en == "enabled" && strings.HasSuffix(linger, "yes"):
			return "enabled"
		case en == "enabled":
			return "enabled (containers start only after you log in; run `om boot enable` to start at boot)"
		}
		return "disabled"
	case runtime == "docker" && s.linux():
		if py.Strip(s.Run([]string{"systemctl", "is-enabled", "docker"}).Stdout) == "enabled" {
			return "enabled"
		}
		return "disabled"
	}
	return "managed by your engine's app (Docker Desktop / Podman Desktop: 'start at login')"
}

// engineBootEnable makes containers with restart policies come back after a reboot.
func (s *Sched) engineBootEnable(runtime string) bool {
	switch {
	case runtime == "podman" && s.linux():
		ok := s.Run([]string{"systemctl", "--user", "enable", "--now", "podman-restart.service"}).Code == 0
		if s.Run([]string{"loginctl", "enable-linger", s.User()}).Code != 0 {
			ok = s.Sudo([]string{"loginctl", "enable-linger", s.User()}) && ok
		}
		return ok
	case runtime == "docker" && s.linux():
		return s.Sudo([]string{"systemctl", "enable", "docker"})
	case s.macos() && runtime == "podman":
		plist := filepath.Join(s.Home, "Library", "LaunchAgents", "dev.om.podman-machine.plist")
		podman := "podman"
		if p, err := s.LookPath("podman"); err == nil {
			podman = p
		}
		text := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
			"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n" +
			"<plist version=\"1.0\"><dict>\n" +
			"  <key>Label</key><string>dev.om.podman-machine</string>\n" +
			"  <key>ProgramArguments</key><array><string>" + xmlEscape(podman) + "</string><string>machine</string><string>start</string></array>\n" +
			"  <key>RunAtLoad</key><true/>\n</dict></plist>\n"
		if write(plist, text) != nil {
			return false
		}
		return s.Run([]string{"launchctl", "load", plist}).Code == 0
	}
	fmt.Fprintln(s.Out, "Enable 'Start at login' in Docker Desktop / Podman Desktop settings; om's containers restart with the engine.")
	return true
}

// job is a scheduled om command: what it runs and how often om schedules it by default.
type job struct {
	name    string
	args    []string
	minutes int
}

var jobs = []job{
	{"autosync", []string{"sync", "--scheduled"}, 1},
	{"heal", []string{"core", "heal"}, 2},
}

var (
	reExecStart    = regexp.MustCompile(`(?m)^ExecStart=.*$`)
	reStartSeconds = regexp.MustCompile(`<key>StartInterval</key><integer>(\d+)</integer>`)
	reTaskToRun    = regexp.MustCompile(`(?m)^Task To Run:\s*(.*?)\s*$`)
)

// Refresh points the jobs that already exist at the om that is installed now and returns the names it changed. A job
// left by an older om names a program that is gone (the Python version's jobs ran `python3 .../bin/om`), and a timer
// that calls a missing file fails every time it fires, silently. Only the command is rewritten: the timers, their
// intervals and the jobs that are not installed stay as they are (a job is never created here), and the watcher, a
// long-running service, is restarted onto the new binary.
func (s *Sched) Refresh() []string {
	var changed []string
	switch {
	case s.linux() && s.hasSystemctl():
		units := []struct {
			name string
			args []string
		}{{"watch", []string{"core", "watch"}}}
		for _, j := range jobs {
			units = append(units, struct {
				name string
				args []string
			}{j.name, j.args})
		}
		reload := false
		for _, u := range units {
			path := filepath.Join(s.systemdUserDir(), "om-"+u.name+".service")
			b, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			want := "ExecStart=" + unitExec(s.cmd(u.args))
			if reExecStart.FindString(string(b)) == want {
				continue
			}
			text := reExecStart.ReplaceAllLiteralString(string(b), want)
			if write(path, text) != nil {
				continue
			}
			reload = true
			changed = append(changed, u.name)
		}
		if reload {
			s.Run([]string{"systemctl", "--user", "daemon-reload"})
			for _, n := range changed {
				if n == "watch" && py.Strip(s.Run([]string{"systemctl", "--user", "is-active", "om-watch.service"}).Stdout) == "active" {
					s.Run([]string{"systemctl", "--user", "restart", "om-watch.service"})
				}
			}
		} else if s.watcherOnOldBinary() {
			// the unit already names this om, but the process that runs is the one before an upgrade
			s.Run([]string{"systemctl", "--user", "restart", "om-watch.service"})
			changed = append(changed, "watch")
		}
	case s.macos():
		for _, j := range jobs {
			plist := s.launchdPlist(j.name)
			b, err := os.ReadFile(plist)
			if err != nil {
				continue
			}
			var argx strings.Builder
			for _, a := range s.cmd(j.args) {
				argx.WriteString("<string>" + xmlEscape(a) + "</string>")
			}
			if strings.Contains(string(b), "<key>ProgramArguments</key><array>"+argx.String()+"</array>") {
				continue
			}
			minutes := j.minutes
			if m := reStartSeconds.FindStringSubmatch(string(b)); m != nil {
				if n, err := strconv.Atoi(m[1]); err == nil && n >= 60 {
					minutes = n / 60
				}
			}
			if ok, _ := s.Schedule(j.name, j.args, minutes, "", ""); ok {
				changed = append(changed, j.name)
			}
		}
	case s.windows():
		for _, j := range jobs {
			out := s.Run([]string{"schtasks", "/Query", "/TN", "om-" + j.name, "/V", "/FO", "LIST"})
			if out.Code != 0 {
				continue // not installed
			}
			cmd := s.cmd(j.args)
			q := make([]string, len(cmd))
			for i, a := range cmd {
				q[i] = `"` + a + `"`
			}
			if m := reTaskToRun.FindStringSubmatch(out.Stdout); m != nil && m[1] == strings.Join(q, " ") {
				continue
			}
			if ok, _ := s.Schedule(j.name, j.args, j.minutes, "", ""); ok {
				changed = append(changed, j.name)
			}
		}
	}
	return changed
}

// watcherOnOldBinary: the watcher service is running, and the program it runs is not the om installed now (the file was
// replaced by an upgrade, so the process still holds the old one, which Linux marks "(deleted)", or it is another
// program altogether). A service that is not running, or whose process cannot be inspected, is left alone.
func (s *Sched) watcherOnOldBinary() bool {
	if len(s.OMCmd) == 0 {
		return false
	}
	if _, err := os.Stat(filepath.Join(s.systemdUserDir(), "om-watch.service")); err != nil {
		return false // no watcher installed: nothing to ask systemd
	}
	pid := py.Strip(s.Run([]string{"systemctl", "--user", "show", "-p", "MainPID", "--value", "om-watch.service"}).Stdout)
	if pid == "" || pid == "0" {
		return false
	}
	root := s.ProcRoot
	if root == "" {
		root = "/proc"
	}
	exe, err := os.Readlink(filepath.Join(root, pid, "exe"))
	if err != nil {
		return false
	}
	want, err := filepath.EvalSymlinks(s.OMCmd[0])
	if err != nil {
		want = s.OMCmd[0]
	}
	return exe != want
}
