package migration

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/Chitakasa/om/internal/state"
)

func TestMigrationMatchesPython(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the goldens were recorded on POSIX and hold / paths")
	}
	b, err := os.ReadFile("../../testdata/golden/scaffold.json")
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		Migration struct {
			PresentBefore bool `json:"present_before"`
			Lines         []string
			Tree          []string
			OMEnv         string `json:"om_env"`
			Parked        string
			Token         string
			Again         []string
			PresentAfter  bool `json:"present_after"`
		}
	}
	json.NewDecoder(bytes.NewReader(b)).Decode(&g)
	T := t.TempDir()
	t.Setenv("OM_HOME", filepath.Join(T, "home"))
	t.Setenv("OM_STATE_DIR", filepath.Join(T, "state"))
	t.Setenv("OM_CONFIG_DIR", filepath.Join(T, "cfg"))
	d := state.NewDirs()
	put := func(rel, text string) {
		p := filepath.Join(T, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(text), 0o644)
	}
	put("home/core/data/caddy/pki", "pki")
	put("home/core/data/edge_token", "tok\n")
	put("home/core/caddy/auth.d/private.conf", "basic_auth {\n}\n")
	put("home/core/caddy/auth.d/readme.txt", "x")
	put("home/core/caddy/conf.d/alpha-web.caddy", "# Service: web (alpha)\nhttp://x {\n}\n")
	put("home/core/caddy/conf.d/00-info.caddy", "# Service: info (core)\nhttp://i {\n}\n")
	put("home/core/caddy/conf.d/mine.caddy", "# hand written\n")
	put("home/core/caddy/conf.d/sub.public_subpath", "# Public Subpath: web (beta)\nx\n")
	put("home/core/.env", "OM_VPN=x\n")
	put("home/core/.runtime.env", "A=1\n")
	put("home/core/ports.generated.yml", "services: {}\n")
	put("home/core/firewall/om.nft", "nft")
	put("home/config/workspaces.json", "{}")
	put("home/config/workspaces.lock", "")
	put("home/logs/notify.log", "log")
	put("cfg/om.env", "NEWER=1\n")
	put("state/data/edge_token", "newer-token\n")
	if LegacyStatePresent(d) != g.Migration.PresentBefore {
		t.Error("present before")
	}
	lines, err := MigrateLegacyState(d)
	if err != nil {
		t.Fatal(err)
	}
	for i := range lines {
		lines[i] = strings.ReplaceAll(lines[i], T, "@T@")
	}
	if !reflect.DeepEqual(lines, g.Migration.Lines) {
		t.Errorf("lines\n go     %q\n python %q", lines, g.Migration.Lines)
	}
	var tree []string
	filepath.Walk(T, func(p string, info os.FileInfo, err error) error {
		if p != T {
			rel, _ := filepath.Rel(T, p)
			s := filepath.ToSlash(rel)
			if info.IsDir() {
				s += "/"
			}
			tree = append(tree, s)
		}
		return nil
	})
	sort.Strings(tree)
	var want []string
	for _, p := range g.Migration.Tree {
		if !strings.HasPrefix(p, "ws/") { // the scaffold part of the same capture created these
			want = append(want, p)
		}
	}
	sort.Strings(want)
	if !reflect.DeepEqual(tree, want) {
		t.Errorf("tree\n go     %v\n python %v", tree, want)
	}
	if b, _ := os.ReadFile(filepath.Join(T, "cfg", "om.env")); string(b) != g.Migration.OMEnv {
		t.Error("om.env must keep the newer file")
	}
	if b, _ := os.ReadFile(filepath.Join(T, "state", "data", "edge_token")); string(b) != g.Migration.Token {
		t.Error("token must keep the newer file")
	}
	again, _ := MigrateLegacyState(d)
	if len(again) != len(g.Migration.Again) || LegacyStatePresent(d) != g.Migration.PresentAfter {
		t.Errorf("idempotence: %v %v", again, LegacyStatePresent(d))
	}
}

func TestRenameRuntimeEnvSocket(t *testing.T) {
	t.Setenv("OM_STATE_DIR", t.TempDir())
	d := state.NewDirs()
	if changed, err := RenameRuntimeEnvSocket(d); changed || err != nil {
		t.Fatalf("no runtime.env: %v %v", changed, err)
	}
	old := "# GENERATED\nOM_ENGINE_SOCKET=/run/user/1000/podman/podman.sock\nOM_ENGINE_SOCKET_PATH=/run/om-engine/engine.sock\nLAN_IP=192.168.1.2\n"
	if err := os.WriteFile(d.RuntimeEnv, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := RenameRuntimeEnvSocket(d)
	if !changed || err != nil {
		t.Fatalf("old key: %v %v", changed, err)
	}
	got, _ := os.ReadFile(d.RuntimeEnv)
	want := "# GENERATED\nOM_ENGINE_SOCK=/run/user/1000/podman/podman.sock\nOM_ENGINE_SOCKET_PATH=/run/om-engine/engine.sock\nLAN_IP=192.168.1.2\n"
	if string(got) != want {
		t.Fatalf("rewritten:\n%s", got)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(d.RuntimeEnv); st.Mode().Perm() != 0o600 {
			t.Fatalf("runtime.env holds the edge token: mode %v", st.Mode().Perm())
		}
	}
	if changed, err := RenameRuntimeEnvSocket(d); changed || err != nil {
		t.Fatalf("second run must change nothing: %v %v", changed, err)
	}
}
