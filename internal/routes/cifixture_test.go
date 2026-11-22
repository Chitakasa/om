package routes

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWriteCIFixtures renders a route with everything a route can carry (own ports, aliases, dashboard paths, om.caddy)
// into $OM_CI_OUT, for CI to validate with the real Caddy. Without OM_CI_OUT it does nothing.
func TestWriteCIFixtures(t *testing.T) {
	out := os.Getenv("OM_CI_OUT")
	if out == "" {
		t.Skip("OM_CI_OUT not set")
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	opts := Options{Snippet: "header X-A b\n@old path /old*\nredir @old /new\n", DashboardPaths: []string{"/api/x*"}, KeepPrefix: true, Aliases: []string{"/s"}}
	files := map[string]string{
		"ci-web.caddy":         RenderVhost("ci", "web", 80, opts, 3, true),
		"ci-web.private_alias": RenderAlias("ci", "web", 20003, false, opts),
		"ci-web.public_alias":  RenderAlias("ci", "web", 21003, true, opts),
	}
	for name, text := range files {
		if err := os.WriteFile(filepath.Join(out, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
