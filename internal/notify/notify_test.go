package notify

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Chitakasa/om/internal/settings"
	"github.com/Chitakasa/om/internal/state"
)

func golden(t *testing.T, key string, v any) {
	b, err := os.ReadFile("../../testdata/golden/small_modules.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	json.Unmarshal(b, &m)
	d := json.NewDecoder(bytes.NewReader(m[key]))
	d.UseNumber()
	if err := d.Decode(v); err != nil {
		t.Fatal(err)
	}
}

func newN(t *testing.T) *Notifier {
	t.Setenv("OM_STATE_DIR", t.TempDir())
	return New(state.NewDirs())
}

func TestWebhookURLOKMatchesPython(t *testing.T) {
	var cases []struct {
		In  string
		Out any
	}
	golden(t, "urls", &cases)
	for _, c := range cases {
		if s, ok := c.Out.(string); ok && strings.HasPrefix(s, "PYEXC") {
			continue
		}
		if got := WebhookURLOK(c.In); got != c.Out.(bool) {
			t.Errorf("WebhookURLOK(%q) = %v, python %v", c.In, got, c.Out)
		}
	}
}

func TestChannelsMatchPython(t *testing.T) {
	var cases []struct {
		S   map[string]string
		Out []string
	}
	golden(t, "channels", &cases)
	n := newN(t)
	for _, c := range cases {
		n.Settings = func() (settings.Settings, error) { return settings.Settings(c.S), nil }
		if got := n.ChannelList(); !reflect.DeepEqual(got, c.Out) && !(len(got) == 0 && len(c.Out) == 0) {
			t.Errorf("%v: %v want %v", c.S, got, c.Out)
		}
	}
}

func TestNotifyFlowMatchesPython(t *testing.T) {
	var flow []struct {
		Name   string
		Result [][]any
		Sent   int
		Seen   *string
		Log    *string
	}
	golden(t, "flow", &flow)
	n := newN(t)
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	n.Now = func() time.Time { return now }
	// the Python run's clock for seen.json was a Unix time; keep the two clocks apart
	sentCount := 0
	n.Channels = map[string]func(string, string) (bool, string){
		"webhook": func(string, string) (bool, string) { sentCount++; return false, "HTTP 500" },
		"desktop": func(string, string) (bool, string) { sentCount++; return true, "sent" },
	}
	set := func(v string) {
		n.Settings = func() (settings.Settings, error) { return settings.Settings{"OM_NOTIFY": v}, nil }
	}
	steps := []func() []Result{
		func() []Result { set("desktop,webhook"); return n.Notify("T1", "B1", "k1") },
		func() []Result { return n.Notify("T1", "B1", "k1") },
		func() []Result { return n.Notify("T2", "B2", "") },
		func() []Result { set("webhook,bogus"); return n.Notify("T3", "B3", "k3") },
		func() []Result { return n.Notify("T3", "B3", "k3") },
		func() []Result { set("off"); return n.Notify("T4", "B4", "k4") },
		func() []Result { set("desktop"); return n.Notify("T1", "B1", "k1") },
	}
	for i, f := range flow {
		if i == 6 { // 31 days later
			n.Now = func() time.Time { return time.Unix(1_700_000_000, 250_000_000).Add(31 * 86400 * time.Second) }
		} else {
			n.Now = func() time.Time { return time.Unix(1_700_000_000, 250_000_000) }
		}
		res := steps[i]()
		var got [][]any
		for _, r := range res {
			got = append(got, []any{r.Channel, r.OK, r.Detail})
		}
		if !reflect.DeepEqual(got, f.Result) && !(len(got) == 0 && len(f.Result) == 0) {
			t.Errorf("%s: result %v want %v", f.Name, got, f.Result)
		}
		if sentCount != f.Sent {
			t.Errorf("%s: sent %d want %d", f.Name, sentCount, f.Sent)
		}
		seen, _ := os.ReadFile(n.seen())
		if f.Seen == nil && len(seen) != 0 || f.Seen != nil && string(seen) != *f.Seen {
			t.Errorf("%s: seen %q want %v", f.Name, seen, f.Seen)
		}
		log, _ := os.ReadFile(n.log())
		wantLog := ""
		if f.Log != nil {
			wantLog = *f.Log
		}
		// the log line carries local time: compare with the timestamp masked
		mask := func(s string) string {
			var b strings.Builder
			for _, l := range strings.Split(s, "\n") {
				if len(l) > 21 && l[0] == '[' && l[20] == ']' {
					l = "[T]" + l[21:]
				}
				b.WriteString(l + "\n")
			}
			return b.String()
		}
		if mask(string(log)) != mask(wantLog) {
			t.Errorf("%s: log\n%s\nwant\n%s", f.Name, log, wantLog)
		}
	}
	_ = now
}

func TestWebhookPostsAndDesktopFallbacks(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := new(bytes.Buffer)
		b.ReadFrom(r.Body)
		got = r.Method + " " + b.String()
		if r.URL.Path == "/fail" {
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	n := newN(t)
	n.Settings = func() (settings.Settings, error) {
		return settings.Settings{"OM_NOTIFY_URL": " " + srv.URL + "/ok "}, nil
	}
	if ok, detail := n.webhook("Title", "Body"); !ok || detail != "HTTP 200" || got != "POST Title\nBody" {
		t.Fatalf("%v %q %q", ok, detail, got)
	}
	n.Settings = func() (settings.Settings, error) { return settings.Settings{"OM_NOTIFY_URL": srv.URL + "/fail"}, nil }
	if ok, detail := n.webhook("T", "B"); ok || detail != "HTTP Error 404: Not Found" {
		t.Fatalf("%v %q", ok, detail)
	}
	n.Settings = func() (settings.Settings, error) { return settings.Settings{"OM_NOTIFY_URL": "http://8.8.8.8/x"}, nil }
	if ok, detail := n.webhook("T", "B"); ok || !strings.Contains(detail, "must be an https:// URL") {
		t.Fatalf("%v %q", ok, detail)
	}
	n.GOOS = "linux"
	n.LookPath = func(string) (string, error) { return "", os.ErrNotExist }
	if ok, d := n.desktop("t", "b"); ok || d != "notify-send is not installed (libnotify)" {
		t.Fatal(ok, d)
	}
	n.GOOS = "plan9"
	if ok, d := n.desktop("t", "b"); ok || d != "no desktop notifications on plan9" {
		t.Fatal(ok, d)
	}
	_ = filepath.Join
}
