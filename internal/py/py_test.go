package py

import (
	"encoding/json"
	"os"
	"testing"
)

func TestDumpsMatchesPython(t *testing.T) {
	b, err := os.ReadFile("../../testdata/golden/workspace/dumps.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Doc   json.RawMessage `json:"doc"`
		Dumps string          `json:"dumps"`
	}
	if err := json.Unmarshal(b, &cases); err != nil {
		t.Fatal(err)
	}
	for i, c := range cases {
		o, err := ParseObject(c.Doc)
		if err != nil {
			t.Fatal(err)
		}
		if got := Dumps(o); got != c.Dumps {
			t.Errorf("case %d\n go:\n%s\n python:\n%s", i, got, c.Dumps)
		}
	}
}

func TestObjectKeepsOrderAndDuplicates(t *testing.T) {
	o, err := ParseObject([]byte(`{"b":1,"a":2,"b":3}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := Dumps(o); got != "{\n  \"b\": 3,\n  \"a\": 2\n}" {
		t.Fatal(got)
	}
	o.Delete("b")
	o.Set("c", true)
	o.Set("a", nil)
	if got := Dumps(o); got != "{\n  \"a\": null,\n  \"c\": true\n}" {
		t.Fatal(got)
	}
}

func TestParseObjectRejects(t *testing.T) {
	for _, s := range []string{`[1]`, `"x"`, `{"a":1} x`, `{`, ``} {
		if _, err := ParseObject([]byte(s)); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestStripAndStr(t *testing.T) {
	if Strip("\x1c a 　\n") != "a" || Strip("​a") != "​a" {
		t.Fatal("strip")
	}
	for _, c := range []struct {
		v any
		s string
	}{{nil, "None"}, {true, "True"}, {false, "False"}, {json.Number("1.50"), "1.50"}, {2.0, "2.0"}, {0.5, "0.5"}, {"x", "x"}} {
		if Str(c.v) != c.s {
			t.Errorf("%v -> %q", c.v, Str(c.v))
		}
	}
}

func TestJSONStringAstral(t *testing.T) {
	if got := JSONString("\u00e9\U0001F600<>&\x7f"); got != `"\u00e9\ud83d\ude00<>&\u007f"` {
		t.Fatal(got)
	}
}
