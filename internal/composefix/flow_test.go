package composefix

import "testing"

func TestFlowRoundTrip(t *testing.T) {
	for in, want := range map[string]string{
		`[a, "b:c", 'd']`:                   `[a, "b:c", 'd']`,
		`{image: x, ports: ["80:80", 443]}`: `{image: x, ports: ["80:80", 443]}`,
		`[ {target: 80, published: 8080} ]`: `[{target: 80, published: 8080}]`,
		"[\n  a, # one\n  b\n]":             `[a, b]`,
		`{a: ${X:-1}, b: "${Y:-{z}}"}`:      `{a: ${X:-1}, b: "${Y:-{z}}"}`,
		`[]`:                                `[]`,
	} {
		n, err := parseFlow(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got := n.inline(); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{`[a, b`, `{a: 1`, `"x`, `[a] b`} {
		if _, err := parseFlow(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	n, _ := parseFlow(`{image: x, ports: [{target: 80}]}`)
	got := ""
	for _, l := range n.lines(4) {
		got += l + "\n"
	}
	if got != "    image: x\n    ports:\n      - target: 80\n" {
		t.Errorf("block form:\n%s", got)
	}
}
