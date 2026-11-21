package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Chitakasa/om/internal/state"
)

func newReg(t *testing.T) Registry {
	t.Setenv("OM_HOME", t.TempDir())
	t.Setenv("OM_CONFIG_DIR", t.TempDir())
	t.Setenv("OM_STATE_DIR", t.TempDir())
	return New(state.NewDirs())
}

func readJSON(t *testing.T, path string) any {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return v
}

func ip(i int) *int { return &i }

// The same operations the Python implementation ran (testdata/golden/registry/scenario.json), file by file.
func TestScenarioMatchesPython(t *testing.T) {
	r := newReg(t)
	var steps []map[string]any
	b, err := os.ReadFile("../../testdata/golden/registry/scenario.json")
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(b, &steps)
	ops := []func() error{
		func() error { _, e := r.AssignSlots("a", []string{"web", "api"}); return e },
		func() error { _, e := r.AssignSlots("b", []string{"web"}); return e },
		func() error { _, e := r.AssignSlots("a", []string{"api", "db"}); return e },
		func() error {
			_, e := r.AssignStreamSlots("a", map[string]StreamMeta{"mc": {HostPort: ip(25565), ContainerPort: 25565, Scope: "public"}, "x": {ContainerPort: 9}})
			return e
		},
		func() error {
			_, e := r.AssignStreamSlots("b", map[string]StreamMeta{"y": {ContainerPort: 7, Log: "off"}})
			return e
		},
		nil, // the clash: checked below
		func() error {
			return r.SetNetPolicies("a", map[string]any{"mc": map[string]any{"ports": []any{25565}, "allow": nil, "deny": []any{"1.2.3.4/32"}}})
		},
		func() error {
			if e := r.SetNoLog("a", map[string]any{"mc": []any{25565, 20001}}); e != nil {
				return e
			}
			return r.SetNoLog("b", map[string]any{"y": []any{20003}})
		},
		func() error { return r.SetEgressNetworks("a", []string{"z_net", "a_net", "a_net"}) },
		nil, // nolog_ports: checked below
		func() error { return r.ReleaseSlots("a") },
	}
	files := map[string]string{"service_ports": r.D.ServicePorts, "stream_ports": r.D.StreamPorts, "net_policy": r.D.NetPolicy, "no_log": r.D.NoLog, "egress": r.D.EgressNets}
	oi := 0
	for _, st := range steps {
		if msg, ok := st["error"].(string); ok {
			_, err := r.AssignStreamSlots("b", map[string]StreamMeta{"z": {HostPort: ip(25565), ContainerPort: 1}})
			if err == nil || err.Error() != msg {
				t.Fatalf("clash error %v, want %q", err, msg)
			}
			oi++
			continue
		}
		if want, ok := st["nolog_ports"].([]any); ok {
			var got []any
			for _, p := range r.NoLogPorts() {
				got = append(got, float64(p))
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("no_log_ports %v want %v", got, want)
			}
			oi++
			continue
		}
		if err := ops[oi](); err != nil {
			t.Fatalf("%v: %v", st["after"], err)
		}
		oi++
		for name, want := range st["state"].(map[string]any) {
			if got := readJSON(t, files[name]); !reflect.DeepEqual(got, want) {
				t.Errorf("after %v: %s\n go     %v\n python %v", st["after"], name, got, want)
			}
		}
	}
}

func TestSlotsNoFreeSlot(t *testing.T) {
	r := newReg(t)
	var svcs []string
	for i := 0; i < state.PortSlots+1; i++ {
		svcs = append(svcs, "s"+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	if _, err := r.AssignSlots("w", svcs); err == nil {
		t.Fatal("expected exhaustion error")
	}
}

func TestReadsPythonStyleAndGarbage(t *testing.T) {
	r := newReg(t)
	os.MkdirAll(filepath.Dir(r.D.ServicePorts), 0o755)
	os.WriteFile(r.D.ServicePorts, []byte(`{"a/web": 3, "a/bad": 999, "a/f": 1.5, "a/s": "2"}`), 0o644)
	if got := r.ServiceSlots(); !reflect.DeepEqual(got, map[string]int{"a/web": 3}) {
		t.Fatal(got)
	}
	os.WriteFile(r.D.ServicePorts, []byte(`[1,2]`), 0o644)
	if len(r.ServiceSlots()) != 0 {
		t.Fatal("non-object must read as empty")
	}
	os.WriteFile(r.D.Registry, []byte(`not json`), 0o644)
	if len(r.Read()) != 0 {
		t.Fatal("garbage registry must read as empty")
	}
}

func TestUpdateRegistryKeepsUnknownFieldsAndAbortsOnError(t *testing.T) {
	r := newReg(t)
	if err := r.Update(func(w Workspaces) error {
		w["a"] = map[string]any{"id": "a", "path": "/x", "extra": "keep"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.Update(func(w Workspaces) error { delete(w, "a"); return os.ErrInvalid }); err == nil {
		t.Fatal("error not returned")
	}
	if got := r.Read()["a"]["extra"]; got != "keep" {
		t.Fatalf("aborted update changed the registry: %v", got)
	}
}

func TestEgressNetworksUnknownVsEmpty(t *testing.T) {
	r := newReg(t)
	if _, ok := r.EgressNetworks("a"); ok {
		t.Fatal("unknown must be !ok")
	}
	r.SetEgressNetworks("a", []string{})
	if n, ok := r.EgressNetworks("a"); !ok || len(n) != 0 {
		t.Fatal("empty list is known-empty")
	}
	r.SetEgressNetworks("a", nil)
	if _, ok := r.EgressNetworks("a"); ok {
		t.Fatal("nil forgets")
	}
}
