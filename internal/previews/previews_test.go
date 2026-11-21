package previews

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPreviewsMatchPython(t *testing.T) {
	b, err := os.ReadFile("../../testdata/golden/previews.json")
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		Valid    map[string]bool
		IDs      map[string]*string `json:"ids"`
		Portable []string
	}
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	for br, want := range g.Valid {
		if ValidBranch(br) != want {
			t.Errorf("ValidBranch(%q) != %v", br, want)
		}
	}
	for k, want := range g.IDs {
		ws, br, _ := strings.Cut(k, "|")
		got, err := PreviewID(ws, br)
		switch {
		case want == nil && err == nil:
			t.Errorf("%s: Go made %q, Python refused", k, got)
		case want != nil && (err != nil || got != *want):
			t.Errorf("%s: Go %q (%v), Python %q", k, got, err, *want)
		}
	}
	if _, err := PreviewID("w", "---"); err == nil || err.Error() != "Cannot make a workspace id from branch '---'." {
		t.Error(err)
	}
	root := filepath.Join(t.TempDir(), "ws")
	os.MkdirAll(filepath.Join(root, "sub"), 0o755)
	os.MkdirAll(filepath.Join(root, "ok"), 0o755)
	os.WriteFile(filepath.Join(root, "compose.yml"), []byte("services:\n  a:\n    container_name: fixed\n    image: x\n  b:\n    container_name: \"${WORKSPACE_ID:-w}_b\"\nnetworks:\n  n:\n    name: my_net\n  m:\n    name: ${WORKSPACE_NET}\n  o:\n    name: 'other_net'\n"), 0o644)
	os.WriteFile(filepath.Join(root, "sub", "compose.yaml"), []byte("services:\n  c:\n    container_name: 'x'\n"), 0o644)
	os.WriteFile(filepath.Join(root, "ok", "compose.yml"), []byte("services:\n  c:\n    container_name: ${WORKSPACE_ID}_c\n"), 0o644)
	if got := PreviewPortable(root); !reflect.DeepEqual(got, g.Portable) {
		t.Errorf("portable:\n go     %q\n python %q", got, g.Portable)
	}
}
