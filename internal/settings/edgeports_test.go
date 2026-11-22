package settings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Chitakasa/om/internal/state"
)

func autoDirs(t *testing.T, env string) state.Dirs {
	t.Helper()
	base := t.TempDir()
	t.Setenv("OM_STATE_DIR", filepath.Join(base, "state"))
	t.Setenv("OM_CONFIG_DIR", filepath.Join(base, "config"))
	d := state.NewDirs()
	os.MkdirAll(filepath.Dir(d.UserEnv), 0o755)
	os.MkdirAll(filepath.Join(d.State, "registry"), 0o755)
	if err := os.WriteFile(d.UserEnv, []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	return d
}

func edgeOf(t *testing.T, d state.Dirs) (int, int) {
	t.Helper()
	s, err := Load(d)
	if err != nil {
		t.Fatal(err)
	}
	return s.EdgePorts()
}

func no() bool  { return false }
func yes() bool { return true }

func busy(ports ...int) func(int) bool {
	return func(p int) bool {
		for _, b := range ports {
			if p == b {
				return false
			}
		}
		return true
	}
}

func TestAutoFrontDoorPorts(t *testing.T) {
	d := autoDirs(t, "OM_HTTP_PORT=auto\nOM_HTTPS_PORT=auto\n")
	// before any start: the defaults
	if h, s := edgeOf(t, d); h != 80 || s != 443 {
		t.Fatalf("before a start: %d %d", h, s)
	}
	// 80 and 443 are free: they are kept, nothing to say
	if notes, err := ResolveEdgePorts(d, busy(), no); err != nil || len(notes) != 0 {
		t.Fatalf("free: %v %v", notes, err)
	}
	if h, s := edgeOf(t, d); h != 80 || s != 443 {
		t.Fatalf("free: %d %d", h, s)
	}
	// they were free once and are remembered: when they are taken later the remembered ones are not kept ...
	if _, err := ResolveEdgePorts(d, busy(80, 443), no); err != nil {
		t.Fatal(err)
	}
	if h, s := edgeOf(t, d); h != 8000 || s != 8444 {
		t.Fatalf("taken: %d %d", h, s)
	}
	// ... but the ones chosen are stable: free again does not move them back
	if notes, _ := ResolveEdgePorts(d, busy(), no); len(notes) != 0 {
		t.Errorf("moved again: %v", notes)
	}
	if h, s := edgeOf(t, d); h != 8000 || s != 8444 {
		t.Fatalf("stable: %d %d", h, s)
	}
	// the core's own edge holds them: kept although they are not free
	if _, err := ResolveEdgePorts(d, busy(8000, 8444), yes); err != nil {
		t.Fatal(err)
	}
	if h, s := edgeOf(t, d); h != 8000 || s != 8444 {
		t.Fatalf("own edge: %d %d", h, s)
	}
	// a remembered port that something else took moves on, and the message says so
	notes, err := ResolveEdgePorts(d, busy(80, 8000), no)
	if err != nil || len(notes) != 1 || !strings.Contains(notes[0], "OM_HTTP_PORT") {
		t.Fatalf("moved on: %v %v", notes, err)
	}
	if h, _ := edgeOf(t, d); h != 8888 {
		t.Fatalf("moved on: %d", h)
	}
	// nothing free at all: an error that names the setting
	if _, err := ResolveEdgePorts(d, busy(80, 8000, 8888, 9080), no); err == nil || !strings.Contains(err.Error(), "OM_HTTP_PORT") {
		t.Errorf("no free port: %v", err)
	}
}

func TestAPinnedFrontDoorPortIsLeftAlone(t *testing.T) {
	d := autoDirs(t, "OM_HTTP_PORT=8123\n")
	notes, err := ResolveEdgePorts(d, busy(8123), no)
	if err != nil || len(notes) != 0 {
		t.Fatalf("%v %v", notes, err)
	}
	if h, s := edgeOf(t, d); h != 8123 || s != 443 {
		t.Fatalf("%d %d", h, s)
	}
	if _, err := os.Stat(filepath.Join(d.State, "registry", "edge_ports.json")); err == nil {
		t.Error("a file was written although nothing is auto")
	}
}
