package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Chitakasa/om/internal/registry"
)

// A service with `network_mode: none` has no route, so the report would never name it: it says so.
func TestExposureNamesTheServicesWithoutANetwork(t *testing.T) {
	a := sandboxApp(t)
	root := t.TempDir()
	d := filepath.Join(root, "services", "backup")
	os.MkdirAll(d, 0o755)
	os.WriteFile(filepath.Join(d, "compose.yml"), []byte("services:\n  backup-host:\n    image: b\n    network_mode: none\n  helper:\n    image: h\n"), 0o644)
	if err := a.Reg.Update(func(w registry.Workspaces) error { w["ws"] = map[string]any{"id": "ws", "path": root}; return nil }); err != nil {
		t.Fatal(err)
	}
	data := a.exposureData()
	nn := anyStrings(data["no_network"])
	if len(nn) != 1 || nn[0] != "ws/backup-host" {
		t.Fatalf("no_network = %v", nn)
	}
	var out bytes.Buffer
	a.Out = &out
	a.printExposure(data)
	if !strings.Contains(out.String(), "No network") || !strings.Contains(out.String(), "    ws/backup-host") {
		t.Errorf("report:\n%s", out.String())
	}
	// with nothing to report the key is absent: the JSON stays what it was
	a2 := sandboxApp(t)
	if _, ok := a2.exposureData()["no_network"]; ok {
		t.Error("no_network present with no workspace")
	}
}
