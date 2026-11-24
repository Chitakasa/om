package runcmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSplitReadsQuotesAndContinuations(t *testing.T) {
	got, err := Split("docker run -e 'A=b c' -e \"D=e \\\"f\\\"\" \\\n  --name x img sh -c 'echo hi'")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"docker", "run", "-e", "A=b c", "-e", `D=e "f"`, "--name", "x", "img", "sh", "-c", "echo hi"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q", got)
	}
	if _, err := Split("a 'b"); err == nil {
		t.Error("unclosed quote accepted")
	}
}

func TestACommonRunBecomesCompose(t *testing.T) {
	s, err := Parse(`docker run -d --name My_Blog -p 8080:2368 -p 127.0.0.1:9000:9000/udp -e url=http://localhost:8080 -e DB_PASS='p$ss' -v blog:/var/lib/ghost -v ./cfg:/etc/ghost:ro ` +
		`--restart unless-stopped --memory 512M --cpus 1.5 --cap-drop ALL --read-only --tmpfs /tmp --health-cmd "curl -f localhost" --health-interval 30s docker.io/library/ghost:5 node index.js --verbose`)
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "my-blog" || s.Image != "docker.io/library/ghost:5" || strings.Join(s.Command, " ") != "node index.js --verbose" {
		t.Fatalf("%+v", s)
	}
	text := s.Compose()
	for _, want := range []string{"image: \"docker.io/library/ghost:5\"", "- \"8080:2368\"", "- \"127.0.0.1:9000:9000/udp\"", "- \"DB_PASS=p$$ss\"", "- \"blog:/var/lib/ghost\"", "- \"./cfg:/etc/ghost:ro\"",
		"restart: \"unless-stopped\"", "read_only: true", "- \"om.mem=512m\"", "- \"om.cpus=1.5\"", "cap_drop:", "tmpfs:", "test: [\"CMD-SHELL\", \"curl -f localhost\"]", "interval: 30s", "command:", "\nvolumes:\n  blog:\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("compose lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "  ./cfg:") {
		t.Error("a bind mount was declared as a named volume")
	}
}

func TestWhatCannotBeTranslatedIsRefusedNotDropped(t *testing.T) {
	for cmd, want := range map[string]string{
		"docker run --gpus all img":              "--gpus",
		"docker run -P img":                      "publishes every port",
		"docker run --network mynet img":         "om manages the networks",
		"docker run -v /data img":                "anonymous volume",
		"docker run --log-driver none img":       "--log-driver",
		"docker run -p":                          "needs a value",
		"docker run -e":                          "needs a value",
		"docker ps":                              "not a `docker run`",
		"docker run -d":                          "no image",
		"docker run --mount type=tmpfs,dst=/t i": "only type=bind and type=volume",
		"docker run --pull sometimes img":        "not one of",
	} {
		if _, err := Parse(cmd); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want it to contain %q", cmd, err, want)
		}
	}
}

func TestMountAndGroupedFlagsAndHostNetwork(t *testing.T) {
	s, err := Parse("podman run -itd --rm --network=host --mount type=volume,src=data,dst=/d,readonly -p8080:80 -e FOO nginx:1")
	if err != nil {
		t.Fatal(err)
	}
	text := s.Compose()
	for _, want := range []string{"network_mode: \"host\"", "- \"data:/d:ro\"", "- \"8080:80\"", "- \"FOO\"", "volumes:\n  data:"} {
		if !strings.Contains(text, want) {
			t.Errorf("lacks %q:\n%s", want, text)
		}
	}
	if s.Name != "nginx" {
		t.Errorf("name %q", s.Name)
	}
}

func TestOutputIsValidComposeForTheRealEngine(t *testing.T) {
	dc, err := exec.LookPath("docker-compose")
	if err != nil {
		t.Skip("docker-compose is not installed")
	}
	s, err := Parse(`docker run -d --name app -p 8080:80 -e A=b -e 'B=$HOME' -v data:/d -v /srv:/s:ro --restart on-failure:3 --user 1000:1000 -w /w -h box ` +
		`--entrypoint "sh -c" --cap-add NET_ADMIN --security-opt no-new-privileges:true --device /dev/null --add-host a:1.2.3.4 --dns 1.1.1.1 --shm-size 64m --pids-limit 100 ` +
		`--stop-signal SIGINT --stop-timeout 20 --ulimit nofile=1024:2048 --init --health-cmd "true" --health-retries 3 --label k=v --pull missing alpine:3 echo "a b"`)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "compose.yml"), []byte(s.Compose()), 0o644)
	c := exec.Command(dc, "config", "--format", "json")
	c.Dir = dir
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s\n%s", err, out, s.Compose())
	}
	for _, want := range []string{`"B=$$HOME"`, `"a b"`, `"on-failure:3"`, `"nofile"`, `"CMD-SHELL"`, `"SIGINT"`, `"20s"`} {
		if !strings.Contains(string(out), strings.ReplaceAll(want, `"B=$$HOME"`, `"B": "$$HOME"`)) && !strings.Contains(string(out), want) {
			t.Errorf("engine output lacks %s:\n%s", want, out)
		}
	}
}
