package cli

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the generated reference docs")

func repoRoot(t testing.TB) string {
	t.Helper()
	dir, _ := os.Getwd()
	for d := dir; d != filepath.Dir(d); d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
	}
	t.Fatal("no go.mod above " + dir)
	return ""
}

// sandboxApp is an App whose directories are throwaway (so generated text never names this machine).
func sandboxApp(t testing.TB) *App {
	t.Helper()
	base := t.TempDir()
	t.Setenv("OM_HOME", filepath.Join(base, "home"))
	t.Setenv("OM_STATE_DIR", filepath.Join(base, "state"))
	t.Setenv("OM_CONFIG_DIR", filepath.Join(base, "config"))
	t.Setenv("NO_COLOR", "1")
	return NewApp("test", strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
}

func TestReferenceDocs(t *testing.T) {
	a := sandboxApp(t)
	root := repoRoot(t)
	for rel, text := range RenderReference(a) {
		path := filepath.Join(root, rel)
		if *update {
			if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != text {
			t.Errorf("%s is stale: run `go test ./internal/cli -run TestReferenceDocs -update` and commit the result\n%s", rel, firstDiff(string(got), text))
		}
	}
}

func firstDiff(a, b string) string {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	for i := 0; i < len(al) && i < len(bl); i++ {
		if al[i] != bl[i] {
			return "line " + itoaLine(i+1) + "\n  file: " + al[i] + "\n  code: " + bl[i]
		}
	}
	return "lengths differ"
}

func itoaLine(n int) string { return strconv.Itoa(n) }

func TestReferenceCoversEverything(t *testing.T) {
	a := sandboxApp(t)
	docs := RenderReference(a)
	for _, g := range a.Parser.Groups {
		for _, name := range g.Names {
			if !strings.Contains(docs["docs/COMMANDS.md"], "### `om "+name+"`") {
				t.Errorf("command %s is not in COMMANDS.md", name)
			}
		}
	}
	for key := range settingAbout {
		if !strings.Contains(docs["docs/SETTINGS.md"], "## `"+key+"`") {
			t.Errorf("setting %s", key)
		}
	}
	for key := range configSchema {
		if _, ok := settingAbout[key]; !ok {
			t.Errorf("setting %s has no text in settingAbout", key)
		}
	}
	for key := range ownCommand {
		if _, ok := settingAbout[key]; !ok {
			t.Errorf("setting %s has no text in settingAbout", key)
		}
	}
	if len(settingAbout) != len(configSchema)+len(ownCommand) {
		t.Errorf("settingAbout names %d settings, the schema has %d", len(settingAbout), len(configSchema)+len(ownCommand))
	}
	for _, cs := range [][]docCheck{a.docBasic(), a.docPerimeter(), a.docHost()} {
		for _, c := range cs {
			if strings.TrimSpace(doctorDocs[c.title]) == "" {
				t.Errorf("doctor check %q has no text in doctorDocs", c.title)
			}
		}
	}
	titles := map[string]bool{}
	for _, cs := range [][]docCheck{a.docBasic(), a.docPerimeter(), a.docHost()} {
		for _, c := range cs {
			titles[c.title] = true
		}
	}
	for title := range doctorDocs {
		if !titles[title] {
			t.Errorf("doctorDocs has text for %q, which is no check", title)
		}
	}
}
