package links

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Chitakasa/om/internal/state"
)

type tcase struct {
	Table map[string]struct {
		Rc  int
		Out string
		Err string
	}
	Problems         []string
	Calls            [][]string
	Describe         [][]string
	DescribeProblems []string `json:"describe_problems"`
}

func TestSyncMatchesPython(t *testing.T) {
	b, err := os.ReadFile("../../testdata/golden/links.json")
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		Scen    map[string]tcase
		Alias   string
		Allowed [][]any
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&g); err != nil {
		t.Fatal(err)
	}
	for name, c := range g.Scen {
		var calls [][]string
		run := func(cmd []string) state.Result {
			calls = append(calls, append([]string(nil), cmd...))
			k := strings.Join(cmd, " ")
			best := ""
			for p := range c.Table {
				if strings.HasPrefix(k, p) && len(p) > len(best) {
					best = p
				}
			}
			if best == "" {
				return state.Result{}
			}
			r := c.Table[best]
			return state.Result{Code: r.Rc, Stdout: r.Out, Stderr: r.Err}
		}
		// Python ran sync and then describe on the same fake: the recorded calls hold both
		probs := Sync(run, "podman")
		desc, dprobs := Describe(run, "podman")
		if !reflect.DeepEqual(orEmpty(probs), orEmpty(c.Problems)) {
			t.Errorf("%s: problems\n go     %q\n python %q", name, probs, c.Problems)
		}
		if !reflect.DeepEqual(calls, c.Calls) {
			t.Errorf("%s: calls\n go     %v\n python %v", name, calls, c.Calls)
		}
		var d [][]string
		for _, x := range desc {
			d = append(d, []string{x.Consumer, x.Provider, x.As})
		}
		if !reflect.DeepEqual(d, c.Describe) && !(len(d) == 0 && len(c.Describe) == 0) {
			t.Errorf("%s: describe %v want %v", name, d, c.Describe)
		}
		if !reflect.DeepEqual(orEmpty(dprobs), orEmpty(c.DescribeProblems)) {
			t.Errorf("%s: describe problems %q want %q", name, dprobs, c.DescribeProblems)
		}
	}
	if Alias("a/b") != g.Alias {
		t.Error("alias")
	}
	for _, a := range g.Allowed {
		var allow []string
		for _, x := range a[0].([]any) {
			allow = append(allow, x.(string))
		}
		if Allowed(allow, a[1].(string)) != a[2].(bool) {
			t.Errorf("allowed %v", a)
		}
	}
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
