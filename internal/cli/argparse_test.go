package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/Chitakasa/om/internal/state"
)

func newTestParser() *Parser {
	p := NewParser("1.0.0", state.Dirs{Home: "/home/cyber/.om", State: "/home/cyber/.local/state/om", UserEnv: "/home/cyber/.config/om/om.env"}) // the goldens name the machine they were recorded on
	p.Width = func() int { return 100 }                                                                                                          // the goldens were captured with COLUMNS=100
	return p
}

func TestHelpMatchesPython(t *testing.T) {
	p := newTestParser()
	files, _ := filepath.Glob("../../testdata/golden/help/*.txt")
	if len(files) < 50 {
		t.Fatalf("only %d help goldens", len(files))
	}
	for _, f := range files {
		want, _ := os.ReadFile(f)
		name := strings.TrimSuffix(filepath.Base(f), ".txt")
		cmd := name
		if name == "om" {
			cmd = ""
		}
		if name == "rm" {
			cmd = "remove"
		}
		got := dropGoOnly(p.Help(cmd))
		if got != string(want) {
			t.Errorf("help of %q differs:\n--- go\n%s\n--- python\n%s", name, got, want)
		}
	}
}

func TestParseMatchesPython(t *testing.T) {
	b, err := os.ReadFile("../../testdata/golden/argparse_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Argv   []string
		Result struct {
			Ok     map[string]any
			Exit   *int
			Stderr string
			Stdout string
		}
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(&cases); err != nil {
		t.Fatal(err)
	}
	p := newTestParser()
	for _, c := range cases {
		ns, err := p.Parse(c.Argv)
		label := strings.Join(c.Argv, " ")
		if c.Result.Exit != nil {
			var pe *ParseError
			var hr *HelpRequest
			switch {
			case errors.As(err, &pe):
				if *c.Result.Exit != 2 || dropGoOnly(err.Error()) != c.Result.Stderr {
					t.Errorf("%q:\n go     %q\n python %q", label, err.Error(), c.Result.Stderr)
				}
			case errors.As(err, &hr):
				if *c.Result.Exit != 0 || dropGoOnly(hr.Text) != c.Result.Stdout {
					t.Errorf("%q: help text differs (exit %d)\n go:\n%s\n python:\n%s", label, *c.Result.Exit, hr.Text, c.Result.Stdout)
				}
			default:
				t.Errorf("%q: Go parsed %v, Python exits %d: %s", label, ns, *c.Result.Exit, c.Result.Stderr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: Go fails (%v), Python parses %v", label, err, c.Result.Ok)
			continue
		}
		for k, want := range c.Result.Ok {
			got := ns[k]
			switch w := want.(type) {
			case json.Number:
				n, _ := w.Int64()
				want = int(n)
			case []any:
				var l []string
				for _, x := range w {
					l = append(l, x.(string))
				}
				want = l
			}
			if want == nil && got == nil {
				continue
			}
			if l, ok := want.([]string); ok && len(l) == 0 {
				if g, ok := got.([]string); ok && len(g) == 0 {
					continue
				}
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%q: %s = %#v, python %#v", label, k, got, want)
			}
		}
	}
}

// goOnly are commands the Go program has and the Python original, whose output these tests replay, did not.
var goOnly = []string{"upgrade"}

// dropGoOnly takes the Go-only commands out of a help text, an error message that lists the commands, or a shell
// completion word list, so the rest can be compared with the recording.
func dropGoOnly(s string) string {
	for _, c := range goOnly {
		s = regexp.MustCompile(`(?m)^  `+c+` .*\n`).ReplaceAllString(s, "")
		s = strings.ReplaceAll(s, "'"+c+"', ", "")
		s = strings.ReplaceAll(s, ", '"+c+"'", "")
		s = strings.ReplaceAll(s, " "+c+" version", " version")
		s = strings.ReplaceAll(s, " "+c+",", "")
	}
	return s
}
