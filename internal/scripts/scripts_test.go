package scripts

import (
	"encoding/json"
	"os"
	"testing"
)

func TestDescriptionMatchesPython(t *testing.T) {
	b, _ := os.ReadFile("../../testdata/golden/small_modules.json")
	var m map[string]json.RawMessage
	json.Unmarshal(b, &m)
	var cases []struct{ Head, Fn, Out string }
	json.Unmarshal(m["scripts"], &cases)
	for _, c := range cases {
		head := make([]byte, 0, len(c.Head))
		for _, r := range c.Head { // the golden stores the bytes as latin-1 text
			head = append(head, byte(r))
		}
		if got := Description(head, c.Fn); got != c.Out {
			t.Errorf("%q (%s): %q, python %q", c.Head, c.Fn, got, c.Out)
		}
	}
	for in, want := range map[string]string{"git.sh": "git", ".hidden": ".hidden", "a.tar.gz": "a.tar", "noext": "noext", "dot.": "dot."} {
		if stem(in) != want {
			t.Errorf("stem(%q) = %q want %q", in, stem(in), want)
		}
	}
}
