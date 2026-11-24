package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Chitakasa/om/internal/scaffold"
	"github.com/Chitakasa/om/internal/state"
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
	a.RunIn = func(cmd []string, dir string, env []string) state.Result {
		if len(cmd) > 2 && cmd[1] == "image" && cmd[2] == "inspect" {
			return state.Result{Stdout: "{}"} // an image that declares nothing
		}
		return state.Result{Code: 127}
	}
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
		"10", // done
		"1",  // create
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
		"10", "1", // done, create
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

func TestTheImageSuggestsItsPortAndDataFolders(t *testing.T) {
	a, out, root := wizardApp(t, "db\n2\ndocker.io/library/postgres:16\n\ny\n1\n") // name, TCP, image, Enter takes the port, yes to volumes, create
	a.RunIn = func(cmd []string, dir string, env []string) state.Result {
		return state.Result{Stdout: `{"ExposedPorts":{"5432/tcp":{}},"Volumes":{"/var/lib/postgresql/data":{}},"User":"postgres"}`}
	}
	args, err := a.addWizard(root, "ws", scaffold.AddArgs{})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if args.Port != 5432 || len(args.Volumes) != 1 || args.Volumes[0] != "db-data:/var/lib/postgresql/data" {
		t.Fatalf("%+v\n%s", args, out)
	}
	if !strings.Contains(out.String(), "db-data:/var/lib/postgresql/data") || !strings.Contains(out.String(), "managed volumes") {
		t.Errorf("summary:\n%s", out)
	}
}

func TestAnImageNotHereIsOnlyDownloadedWhenYouSayYes(t *testing.T) {
	var pulled bool
	run := func(cmd []string, dir string, env []string) state.Result {
		switch {
		case len(cmd) > 2 && cmd[1] == "image":
			if pulled {
				return state.Result{Stdout: `{"ExposedPorts":{"2368/tcp":{}}}`}
			}
			return state.Result{Code: 125}
		case len(cmd) > 1 && cmd[1] == "pull":
			pulled = true
		}
		return state.Result{}
	}
	a, _, root := wizardApp(t, "blog\n1\ndocker.io/library/ghost:5\nn\n2368\n1\n") // no to the download: no suggestions
	a.RunIn = run
	if _, err := a.addWizard(root, "ws", scaffold.AddArgs{}); err != nil || pulled {
		t.Fatalf("pulled without being asked: %v %v", pulled, err)
	}
	a, out, root := wizardApp(t, "blog\n1\ndocker.io/library/ghost:5\ny\n\n1\n")
	a.RunIn = run
	args, err := a.addWizard(root, "ws", scaffold.AddArgs{})
	if err != nil || !pulled || args.Port != 2368 {
		t.Fatalf("%v %v %+v\n%s", pulled, err, args, out)
	}
}

func TestDataSettingsSecretsAndAHealthCheckEndUpInTheCompose(t *testing.T) {
	script := strings.Join([]string{
		"app", "1", "docker.io/library/ghost:5", "2368",
		"2",                             // customise more
		"7", "1", "/var/lib/ghost", "2", // data: add one, done (the list now has a Remove entry, so Done is 3)
	}, "\n")
	_ = script
	a, out, root := wizardApp(t, strings.Join([]string{
		"app", "1", "docker.io/library/ghost:5", "2368",
		"2",
		"7", "1", "/var/lib/ghost", "3", // data
		"8", "1", "url=http://x", // settings: a bad one is refused ...
		"1", "URL=http://x", //   ... a good one
		"1", "DB_PASSWORD=hunter2", "y", //   a password goes to a secret
		"2", "api_token", "API_TOKEN_FILE", //   a secret by name
		"4",                  // done
		"9", "3", "ls /data", // health: a command
		"10", // done
		"1",
	}, "\n")+"\n")
	args, err := a.addWizard(root, "ws", scaffold.AddArgs{})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(args.Volumes) != 1 || args.Health != "ls /data" || len(args.Secrets) != 2 {
		t.Fatalf("%+v\n%s", args, out)
	}
	_, compose := plan(t, args, root)
	for _, want := range []string{"app-data:/var/lib/ghost", `"URL=http://x"`, `"DB_PASSWORD_FILE=/run/secrets/db_password"`, `"API_TOKEN_FILE=/run/secrets/api_token"`,
		"- db_password", "file: ./secrets/api_token", `["CMD-SHELL", "ls /data"]`, "volumes:\n  app-data:"} {
		if !strings.Contains(compose, want) {
			t.Errorf("compose lacks %q:\n%s", want, compose)
		}
	}
	if strings.Contains(compose, "hunter2") {
		t.Error("the password reached the compose file")
	}
	if !strings.Contains(out.String(), "om secrets set app/db_password") {
		t.Errorf("no hint to set the secret:\n%s", out)
	}
}

func TestKeepingDataAndReachingTheInternetNeedsTheWaiverAndSaysSo(t *testing.T) {
	a, out, root := wizardApp(t, strings.Join([]string{"app", "1", "docker.io/library/ghost:5", "2368", "2", "7", "1", "/data", "3", "2", "2", "10", "1"}, "\n")+"\n")
	args, err := a.addWizard(root, "ws", scaffold.AddArgs{})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	found := false
	for _, kv := range args.Extra {
		found = found || kv.Key == "om.policy.allow" && kv.Value == "egress"
	}
	if !found || !strings.Contains(out.String(), "Waiver") {
		t.Fatalf("%+v\n%s", args.Extra, out)
	}
}

func TestEquivalentCommandRebuildsTheSameService(t *testing.T) {
	args := scaffold.AddArgs{Name: "app", Image: "docker.io/library/ghost:5", Port: 2368, Public: true, Volumes: []string{"app-data:/var/lib/ghost"},
		Env: []scaffold.KV{{Key: "URL", Value: "http://x y"}, {Key: "TOKEN_FILE", Value: "/run/secrets/token"}}, Secrets: []string{"token"}, Health: "ls /data",
		Extra: []scaffold.KV{{Key: "om.mem", Value: "256m"}}}
	want := "om add app --image docker.io/library/ghost:5 --port 2368 --public --data /var/lib/ghost --env 'URL=http://x y' --secret token --health 'ls /data' --label om.mem=256m"
	if got := equivalentAdd(args); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}
