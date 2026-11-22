// Package notify sends notifications (`om notify test`; image updates found, auto-updates applied or rolled
// back). Every message is appended to <state>/logs/notify.log. OM_NOTIFY picks the channels: auto (default:
// desktop), off, or a list of:
//
//	webhook  POST the text to OM_NOTIFY_URL (e.g. an ntfy topic): the same on every OS, works from a timer. It
//	         leaves the machine, so it is opt-in and carries only workspace and image names.
//	desktop  notify-send (Linux), osascript (macOS), a PowerShell toast (Windows). Best effort: it needs a
//	         graphical session, which a timer may not reach.
//
// A message with a key is sent once per key (<state>/notify/seen.json). Port of lib/gitops/notify.py.
package notify

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/settings"
	"github.com/Chitakasa/om/internal/state"
)

const keepSeconds = 30 * 86400

const toast = "[void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime];" +
	"$x = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02);" +
	"$t = $x.GetElementsByTagName('text');" +
	"[void]$t.Item(0).AppendChild($x.CreateTextNode($env:OM_TITLE)); [void]$t.Item(1).AppendChild($x.CreateTextNode($env:OM_BODY));" +
	"[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe')" +
	".Show([Windows.UI.Notifications.ToastNotification]::new($x))"

// Result is what one channel reported.
type Result struct {
	Channel string
	OK      bool
	Detail  string
}

// Notifier sends messages. Settings loads om.env; the other fields exist for tests.
type Notifier struct {
	D        state.Dirs
	Settings func() (settings.Settings, error)
	Now      func() time.Time
	Channels map[string]func(title, body string) (bool, string)
	Client   *http.Client
	GOOS     string
	LookPath func(string) (string, error)
	Getenv   func(string) string
}

// New returns a Notifier for this machine.
func New(d state.Dirs) *Notifier {
	n := &Notifier{D: d, Now: time.Now, Client: &http.Client{Timeout: 10 * time.Second}, GOOS: runtime.GOOS,
		LookPath: exec.LookPath, Getenv: os.Getenv}
	n.Settings = func() (settings.Settings, error) { return settings.Load(d) }
	n.Channels = map[string]func(string, string) (bool, string){"webhook": n.webhook, "desktop": n.desktop}
	return n
}

func (n *Notifier) log() string  { return filepath.Join(n.D.Logs, "notify.log") }
func (n *Notifier) seen() string { return filepath.Join(n.D.State, "notify", "seen.json") }

// ChannelList is OM_NOTIFY as a list. auto (the default) is desktop: local, nothing leaves the machine; off is none.
func (n *Notifier) ChannelList() []string {
	s, _ := n.Settings()
	raw := strings.ToLower(py.Strip(s.Get("OM_NOTIFY", "auto")))
	switch raw {
	case "auto":
		raw = "desktop"
	case "off":
		raw = ""
	}
	var out []string
	for _, c := range strings.Split(strings.ReplaceAll(raw, " ", ""), ",") {
		if c != "" {
			out = append(out, c)
		}
	}
	return out
}

// Python's ipaddress.is_private tables (3.14), with their exceptions.
var (
	private4 = prefixes("0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.170/31",
		"192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "255.255.255.255/32")
	except4  = prefixes("192.0.0.9/32", "192.0.0.10/32")
	private6 = prefixes("::1/128", "::/128", "::ffff:0.0.0.0/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20", "fc00::/7", "fe80::/10")
	except6  = prefixes("2001:1::1/128", "2001:1::2/128", "2001:3::/32", "2001:4:112::/48", "2001:20::/28", "2001:30::/28")
)

func prefixes(l ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(l))
	for i, s := range l {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

func inAny(a netip.Addr, l []netip.Prefix) bool {
	for _, p := range l {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// isLoopbackOrPrivate is `ip.is_loopback or ip.is_private` of Python's ipaddress (an IPv4-mapped IPv6 address is
// judged as the IPv4 address it carries).
func isLoopbackOrPrivate(a netip.Addr) bool {
	if a.Is4In6() {
		a = a.Unmap()
	}
	if a.Is4() {
		return a.IsLoopback() || (inAny(a, private4) && !inAny(a, except4))
	}
	return a.IsLoopback() || (inAny(a, private6) && !inAny(a, except6))
}

// WebhookURLOK allows https:// anywhere; plain http:// only to this machine or a private address (a home server),
// never across the internet.
func WebhookURLOK(raw string) bool {
	// like urllib: leading control characters and spaces go, and tabs and newlines are dropped anywhere
	raw = strings.TrimLeftFunc(raw, func(r rune) bool { return r <= 0x20 })
	raw = strings.NewReplacer("\t", "", "\r", "", "\n", "").Replace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if u.Scheme == "https" && host != "" {
		return true
	}
	if u.Scheme != "http" || host == "" {
		return false
	}
	if strings.ToLower(host) == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.Zone() == "" && isLoopbackOrPrivate(a)
}

func (n *Notifier) webhook(title, body string) (bool, string) {
	s, _ := n.Settings()
	u := py.Strip(s.Get("OM_NOTIFY_URL", ""))
	if !WebhookURLOK(u) {
		return false, "OM_NOTIFY_URL must be an https:// URL (http:// only to localhost or a private address)"
	}
	req, err := http.NewRequest("POST", u, strings.NewReader(title+"\n"+body))
	if err != nil {
		return false, err.Error()
	}
	resp, err := n.Client.Do(req)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 400 {
		return false, "HTTP Error " + strconv.Itoa(resp.StatusCode) + ": " + http.StatusText(resp.StatusCode)
	}
	return resp.StatusCode >= 200 && resp.StatusCode < 300, "HTTP " + strconv.Itoa(resp.StatusCode)
}

func (n *Notifier) desktop(title, body string) (bool, string) {
	env := append(os.Environ(), "OM_TITLE="+title, "OM_BODY="+body)
	var cmd []string
	switch n.GOOS {
	case "linux":
		if _, err := n.LookPath("notify-send"); err != nil {
			return false, "notify-send is not installed (libnotify)"
		}
		if n.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
			dir := n.Getenv("XDG_RUNTIME_DIR")
			if dir == "" {
				dir = "/run/user/" + strconv.Itoa(os.Getuid())
			}
			env = append(env, "DBUS_SESSION_BUS_ADDRESS=unix:path="+dir+"/bus")
		}
		cmd = []string{"notify-send", "--app-name=om", title, body}
	case "darwin":
		cmd = []string{"osascript", "-e", "display notification " + py.JSONString(body) + " with title " + py.JSONString(title)}
	case "windows":
		cmd = []string{"powershell", "-NoProfile", "-Command", toast}
	default:
		return false, "no desktop notifications on " + n.GOOS
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	c.Env = env
	var errb bytes.Buffer
	c.Stderr = &errb
	err := c.Run()
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			return false, err.Error()
		}
	}
	d := lastRunes(py.Strip(errb.String()), 200)
	if d == "" {
		d = "sent"
	}
	return err == nil, d
}

func lastRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[len(r)-n:]
	}
	return string(r)
}

// wasSent reports whether key was sent already; mark records it now (and forgets keys older than 30 days).
func (n *Notifier) wasSent(key string, mark bool) bool {
	seen := py.NewObject()
	if b, err := os.ReadFile(n.seen()); err == nil {
		if o, err := py.ParseObject(b); err == nil {
			seen = o
		}
	}
	t := n.Now()
	now := float64(t.Unix()) + float64(t.Nanosecond())/1e9
	kept := py.NewObject()
	for _, k := range seen.Keys() {
		v, _ := seen.Get(k)
		if f, ok := toFloat(v); ok && now-f < keepSeconds {
			kept.Set(k, v)
		}
	}
	_, was := kept.Get(key)
	if mark {
		if !was {
			kept.Set(key, now)
		}
		if err := os.MkdirAll(filepath.Dir(n.seen()), 0o755); err == nil {
			os.WriteFile(n.seen(), []byte(py.DumpsCompact(kept)), 0o644)
		}
	}
	return was
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case interface{ Float64() (float64, error) }:
		f, err := x.Float64()
		return f, err == nil
	}
	return 0, false
}

// Notify logs the message and sends it on the configured channels, once per key ("" for always). It returns what
// each channel reported.
func (n *Notifier) Notify(title, body, key string) []Result {
	if key != "" && n.wasSent(key, false) {
		return nil
	}
	if err := os.MkdirAll(n.D.Logs, 0o755); err == nil {
		if f, err := os.OpenFile(n.log(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			fmt.Fprintf(f, "[%s] %s: %s\n", n.Now().Format("2006-01-02 15:04:05"), title, body)
			f.Close()
		}
	}
	var results []Result
	for _, name := range n.ChannelList() {
		fn, ok := n.Channels[name]
		if !ok {
			results = append(results, Result{name, false, "unknown channel (webhook, desktop)"})
			continue
		}
		okv, detail := fn(title, body)
		results = append(results, Result{name, okv, detail})
	}
	if key != "" {
		any := len(results) == 0
		for _, r := range results {
			any = any || r.OK
		}
		if any { // all channels failed: try again next time
			n.wasSent(key, true)
		}
	}
	return results
}
