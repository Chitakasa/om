package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Chitakasa/om/internal/scaffold"
	"github.com/Chitakasa/om/internal/wizard"
)

// wizardApp is an App whose terminal is the script: the state folders are throw-away, nothing touches an engine.
func wizardApp(t *testing.T, script string) (*App, *bytes.Buffer, string) {
	t.Helper()
	t.Setenv("OM_STATE_DIR", t.TempDir())
	t.Setenv("OM_CONFIG_DIR", t.TempDir())
	var out bytes.Buffer
	a := NewApp("test", strings.NewReader(script), &out, &bytes.Buffer{})
	a.Interactive = true
	return a, &out, t.TempDir()
}

func plan(t *testing.T, args scaffold.AddArgs, root string) (scaffold.Plan, string) {
	t.Helper()
	p, err := scaffold.MakePlan(args, "ws", root, func(s string) bool { _, e := os.Stat(s); return e == nil })
	if err != nil {
		t.Fatal(err)
	}
	return p, scaffold.RenderCompose(p)
}

func TestTheQuickPathIsThreeAnswersAndAConfirmation(t *testing.T) {
	// name, a web app, an image, its port, create
	a, out, root := wizardApp(t, "blog\n1\ndocker.io/library/ghost:5\n2368\n1\n")
	args, err := a.addWizard(root, "ws", scaffold.AddArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if args.Name != "blog" || args.Image != "docker.io/library/ghost:5" || args.Port != 2368 || args.NoWeb || len(args.Extra) != 0 {
		t.Fatalf("args: %+v", args)
	}
	for _, want := range []string{"About to create", "services/blog", "http://ws.blog.localhost", "this machine and your VPN devices", "dashboard.scope=private", "nothing (it cannot reach the internet)"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}
}

func TestPressingEnterEverywhereMakesTheNginxExample(t *testing.T) {
	a, _, root := wizardApp(t, "demo\n\n\n\n")
	args, err := a.addWizard(root, "ws", scaffold.AddArgs{})
	if err != nil || args.Image != "" || args.Port != 0 {
		t.Fatalf("%+v %v", args, err)
	}
	_, text := plan(t, args, root)
	if !strings.Contains(text, "docker.io/nginxinc/nginx-unprivileged") {
		t.Fatalf("not the default image:\n%s", text)
	}
}

func TestCustomisingWritesTheLabelsAndShowsThem(t *testing.T) {
	script := strings.Join([]string{
		"db", "2", "docker.io/library/redis:7", "6379", // a TCP server
		"2",                  // customise more
		"1", "2", "10.0.0.5", // who can reach it: also the LAN, only from one address
		"2", "3", "*.example.org, API.example.org", // outbound: only these hosts
		"3", "512M", "1.5", // limits
		"4", "3", // updates: automatic
		"5", "2", // logging off
		"6", "🗄", "a cache", // card
		"7", // done
		"1", // create
	}, "\n") + "\n"
	a, out, root := wizardApp(t, script)
	args, err := a.addWizard(root, "ws", scaffold.AddArgs{})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	got := map[string]string{}
	for _, kv := range args.Extra {
		got[kv.Key] = kv.Value
	}
	want := map[string]string{"om.tcp": "6379", "om.net.allow": "10.0.0.5", "om.egress": "*.example.org,api.example.org", "om.mem": "512m", "om.cpus": "1.5", "om.update": "auto", "om.log": "off"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if !args.Public || !args.NoWeb || args.Icon != "🗄" || args.Desc != "a cache" {
		t.Fatalf("args: %+v", args)
	}
	_, text := plan(t, args, root)
	for _, line := range []string{`"om.tcp=6379"`, `"dashboard.scope=public"`, `"dashboard.web=false"`, `"om.update=auto"`} {
		if !strings.Contains(text, line) {
			t.Errorf("compose lacks %s", line)
		}
	}
	if !strings.Contains(out.String(), "om.egress=*.example.org,api.example.org") {
		t.Errorf("the summary should show the label it writes:\n%s", out)
	}
}

func TestBadAnswersAreAskedAgainAndNeverReachTheFile(t *testing.T) {
	script := strings.Join([]string{
		"Bad Name!", "dup", "x", // the name: refused, taken, fine
		"1", "has space", "docker.io/library/nginx:1", "99999", "80", // a web app: a bad image, a bad port
		"2",                                      // customise more
		"2", "3", "not a host", "ok.example.org", // outbound: only these hosts, one bad
		"3", "lots", "256m", "-1", "0.5", // limits: a bad memory and a bad CPU
		"7", "1", // done, create
	}, "\n") + "\n"
	a, out, root := wizardApp(t, script)
	os.MkdirAll(filepath.Join(root, "services", "dup"), 0o755)
	args, err := a.addWizard(root, "ws", scaffold.AddArgs{})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if args.Name != "x" || args.Image != "docker.io/library/nginx:1" || args.Port != 80 {
		t.Fatalf("args: %+v", args)
	}
	for _, msg := range []string{"lowercase letters, digits and - only", "dup already exists here", "no spaces, quotes", "port number from 1 to 65535", "is not a host name", "number with k, m or g", "number above 0"} {
		if !strings.Contains(out.String(), msg) {
			t.Errorf("never said %q", msg)
		}
	}
}

func TestFlagsAnswerTheirQuestionsAndCancelChangesNothing(t *testing.T) {
	a, out, root := wizardApp(t, "1\n")
	args, err := a.addWizard(root, "ws", scaffold.AddArgs{Name: "api", Image: "docker.io/library/nginx:1", Port: 80, Public: true})
	if err != nil || args.Name != "api" || !args.Public {
		t.Fatalf("%+v %v", args, err)
	}
	if strings.Contains(out.String(), "Name (") || strings.Contains(out.String(), "What are you adding?") || strings.Contains(out.String(), "Image") {
		t.Errorf("asked what the flags already said:\n%s", out)
	}
	a, _, root = wizardApp(t, "api\n1\ndocker.io/library/nginx:1\n80\n3\n") // 3 = Cancel
	if _, err := a.addWizard(root, "ws", scaffold.AddArgs{}); !errors.Is(err, wizard.ErrCancelled) {
		t.Fatalf("cancel: %v", err)
	}
	a, _, root = wizardApp(t, "api\n") // the input ends mid-way
	if _, err := a.addWizard(root, "ws", scaffold.AddArgs{}); !errors.Is(err, wizard.ErrCancelled) {
		t.Fatalf("end of input: %v", err)
	}
	if entries, _ := os.ReadDir(root); len(entries) != 0 {
		t.Fatalf("the wizard wrote %v", entries)
	}
}
