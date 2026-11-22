package prune

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Chitakasa/om/internal/state"
)

func gold(t *testing.T) map[string]json.RawMessage {
	b, _ := os.ReadFile("../../testdata/golden/small_modules.json")
	var m map[string]json.RawMessage
	json.Unmarshal(b, &m)
	return m
}

func dec(raw json.RawMessage, v any) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	d.Decode(v)
}

func TestPruneMatchesPython(t *testing.T) {
	g := gold(t)
	var sizes []struct {
		In  string
		Out any
	}
	dec(g["sizes"], &sizes)
	for _, c := range sizes {
		if s, ok := c.Out.(string); ok && strings.HasPrefix(s, "PYEXC") {
			if ParseSize(c.In) != 0 {
				t.Errorf("%q", c.In)
			}
			continue
		}
		want, _ := c.Out.(json.Number).Int64()
		if got := ParseSize(c.In); got != want {
			t.Errorf("ParseSize(%q) = %d, python %d", c.In, got, want)
		}
	}
	var cand struct {
		Result []struct {
			ID    string
			Names []string
			Size  json.Number
		}
		Calls [][]string
	}
	dec(g["candidates"], &cand)
	imgs := "aaaaaaaaaaaa111111\tlocalhost/a:1\t52.1 MB\naaaaaaaaaaaa111111\tlocalhost/a:2\t52.1 MB\nbbbbbbbbbbbb222222\t<none>:<none>\t1.5GB\ncccccccccccc333333\tx/c:1\t3 kB\ndddddddddddd444444\tx/d:1\t2 MB\neeeeeeeeeeee555555\t<none>:<none>\t1 MB\n"
	var calls [][]string
	p := Pruner{Run: func(c []string) state.Result {
		calls = append(calls, append([]string(nil), c...))
		k := strings.Join(c, " ")
		switch {
		case strings.HasPrefix(k, "podman images"):
			return state.Result{Stdout: imgs}
		case strings.HasPrefix(k, "podman ps -a -q"):
			return state.Result{Stdout: "id1\nid2\n"}
		case strings.HasPrefix(k, "podman container inspect"):
			return state.Result{Stdout: "sha256:cccccccccccc333333\nsha256:zzz\n"}
		case strings.HasPrefix(k, "podman image inspect"):
			return state.Result{Stdout: map[string]string{"dddddddddddd": `["x/d@sha256:` + strings.Repeat("d", 64) + `"]`, "eeeeeeeeeeee": "bad json"}[c[len(c)-1]]}
		case strings.HasPrefix(k, "podman rmi"):
			if c[len(c)-1] == "localhost/a:2" {
				return state.Result{Code: 1}
			}
		}
		return state.Result{}
	}}
	got := p.Candidates("podman", map[string]bool{"sha256:" + strings.Repeat("d", 64): true})
	if len(got) != len(cand.Result) {
		t.Fatalf("%v", got)
	}
	for i, w := range cand.Result {
		sz, _ := w.Size.Int64()
		if got[i].ID != w.ID || got[i].Size != sz || (len(got[i].Names) != len(w.Names)) {
			t.Errorf("candidate %d: %+v want %+v", i, got[i], w)
		}
	}
	if !reflect.DeepEqual(calls, cand.Calls) {
		t.Errorf("calls\n go     %v\n python %v", calls, cand.Calls)
	}
	var rm []bool
	var rmCalls [][]string
	dec(g["remove"], &rm)
	dec(g["remove_calls"], &rmCalls)
	calls = nil
	out := []bool{p.Remove("podman", got[0]), p.Remove("podman", Image{ID: "x"}), p.Remove("podman", Image{ID: "y", Names: []string{"n1", "n2"}})}
	if !reflect.DeepEqual(out, rm) || !reflect.DeepEqual(calls, rmCalls) {
		t.Errorf("remove %v %v\n python %v %v", out, calls, rm, rmCalls)
	}
	if New().Run == nil {
		t.Fatal("New")
	}
	failing := Pruner{Run: func([]string) state.Result { return state.Result{Code: 1} }}
	if failing.Candidates("podman", nil) != nil {
		t.Error("a failing engine lists nothing")
	}
}
