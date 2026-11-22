package cli

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Chitakasa/om/internal/previews"
	"github.com/Chitakasa/om/internal/registry"
	"github.com/Chitakasa/om/internal/routesync"
	"github.com/Chitakasa/om/internal/state"
	"github.com/Chitakasa/om/internal/stream"
	"github.com/Chitakasa/om/internal/workspace"
)

// ---- registry invariants: random operations (seeded) keep slots and host ports unique ----

func checkRegistry(t *testing.T, a *App, ctx string) {
	t.Helper()
	slots := a.Reg.ServiceSlots()
	seen := map[int]bool{}
	for k, s := range slots {
		if seen[s] {
			t.Fatalf("%s: two web services share slot %d (%s)", ctx, s, k)
		}
		seen[s] = true
	}
	ports, used := map[int]bool{}, map[int]bool{}
	for k, v := range a.Reg.StreamPorts() {
		if ports[v.HostPort] {
			t.Fatalf("%s: two stream services share host port %d (%s)", ctx, v.HostPort, k)
		}
		ports[v.HostPort] = true
		if v.Slot != nil {
			if used[*v.Slot] {
				t.Fatalf("%s: two stream services share slot %d", ctx, *v.Slot)
			}
			used[*v.Slot] = true
			if v.HostPort != state.StreamPortBase+*v.Slot {
				t.Fatalf("%s: %s has slot %d but port %d", ctx, k, *v.Slot, v.HostPort)
			}
		} else if v.HostPort == 0 {
			t.Fatalf("%s: %s has neither slot nor port", ctx, k)
		}
	}
}

func TestRandomOperationsKeepTheRegistryConsistent(t *testing.T) {
	for seed := uint64(0); seed < 60; seed++ {
		a := sandboxApp(t)
		r := rand.New(rand.NewPCG(seed, 7))
		lastWeb := map[string]map[string]bool{}
		for i := 0; i < 40; i++ {
			ws := []string{"a", "a-b", "c"}[r.IntN(3)]
			all := []string{"x", "y", "z", "w", "v"}
			r.Shuffle(len(all), func(i, j int) { all[i], all[j] = all[j], all[i] })
			svcs := all[:r.IntN(5)]
			set := map[string]bool{}
			for _, s := range svcs {
				set[s] = true
			}
			var err error
			switch []string{"slots", "stream", "stream", "release"}[r.IntN(4)] {
			case "slots":
				_, err = a.Reg.AssignSlots(ws, svcs)
				if err == nil {
					lastWeb[ws] = set
				}
			case "stream":
				meta := map[string]registry.StreamMeta{}
				for _, s := range svcs {
					m := registry.StreamMeta{ContainerPort: 80}
					if r.Float64() < 0.4 {
						p := []int{25565, 25570, 22003, 30000}[r.IntN(4)]
						m.HostPort = &p
					}
					meta[s] = m
				}
				_, err = a.Reg.AssignStreamSlots(ws, meta)
			default:
				err = a.Reg.ReleaseSlots(ws)
				if err == nil {
					lastWeb[ws] = map[string]bool{}
				}
			}
			if err != nil {
				continue // a clash is refused; what was there stays (checked below)
			}
			checkRegistry(t, a, fmt.Sprintf("seed %d step %d", seed, i))
		}
		web := map[string]map[string]bool{}
		for k := range a.Reg.ServiceSlots() {
			w, s, _ := strings.Cut(k, "/")
			if web[w] == nil {
				web[w] = map[string]bool{}
			}
			web[w][s] = true
		}
		for ws, want := range lastWeb {
			got := web[ws]
			if len(got) != len(want) {
				t.Errorf("seed %d, workspace %s: services %v, last assignment %v", seed, ws, got, want)
				continue
			}
			for s := range want {
				if !got[s] {
					t.Errorf("seed %d, workspace %s: %s is missing", seed, ws, s)
				}
			}
		}
	}
}

func TestAClashRefusesAndChangesNothing(t *testing.T) {
	a := sandboxApp(t)
	p := 25565
	if _, err := a.Reg.AssignStreamSlots("a", map[string]registry.StreamMeta{"mc": {ContainerPort: 25565, HostPort: &p}}); err != nil {
		t.Fatal(err)
	}
	before := fmt.Sprint(a.Reg.StreamPorts())
	if _, err := a.Reg.AssignStreamSlots("b", map[string]registry.StreamMeta{"mc": {ContainerPort: 25565, HostPort: &p}}); err == nil || !strings.Contains(err.Error(), "already reserved") {
		t.Fatalf("a clash was not refused: %v", err)
	}
	if got := fmt.Sprint(a.Reg.StreamPorts()); got != before {
		t.Errorf("a refused clash changed the registry:\n%s\n%s", before, got)
	}
}

func TestADefaultPortClashingWithAnExplicitOneIsRefused(t *testing.T) {
	a := sandboxApp(t)
	p := 22000
	if _, err := a.Reg.AssignStreamSlots("a", map[string]registry.StreamMeta{"x": {ContainerPort: 80, HostPort: &p}}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Reg.AssignStreamSlots("b", map[string]registry.StreamMeta{"y": {ContainerPort: 80}}); err == nil || !strings.Contains(err.Error(), "clashes") {
		t.Fatalf("not refused: %v", err)
	}
}

// ---- ids built from a workspace and a service can collide: `a`+`b-web` and `a-b`+`web` ----

var colliding = [][2]string{{"a", "b-web"}, {"a-b", "web"}}

func collisionWorkspace(t *testing.T, base, ws string) string {
	root := filepath.Join(base, ws)
	os.MkdirAll(filepath.Join(root, ".om"), 0o755)
	os.WriteFile(filepath.Join(root, ".om", "config.json"), []byte(fmt.Sprintf(`{"workspace_id": %q}`, ws)), 0o644)
	return root
}

func makeService(t *testing.T, root, name string, labels ...string) {
	d := filepath.Join(root, "services", name)
	os.MkdirAll(d, 0o755)
	var body strings.Builder
	for _, l := range labels {
		body.WriteString(fmt.Sprintf("      - %q\n", l))
	}
	os.WriteFile(filepath.Join(d, "compose.yml"), []byte(fmt.Sprintf("services:\n  %s:\n    image: x\n    labels:\n%s", name, body.String())), 0o644)
}

func syncRoutes(t *testing.T, a *App, root string) {
	t.Helper()
	if _, err := a.Syncer.SyncCaddyRoutes(root, "none", false, nil); err != nil {
		t.Fatal(err)
	}
}

func TestSecondWorkspaceNeverOverwritesTheFirstOnesRoute(t *testing.T) {
	a := sandboxApp(t)
	base := t.TempDir()
	roots := map[string]string{}
	for _, c := range colliding {
		root := collisionWorkspace(t, base, c[0])
		makeService(t, root, c[1], "dashboard.port=80")
		syncRoutes(t, a, root)
		roots[c[0]] = root
	}
	route := filepath.Join(a.D.Routes, "a-b-web.caddy")
	if got := routesync.RouteOwner(route); got != "a" {
		t.Fatalf("the first one keeps it, but the owner is %q", got)
	}
	for _, ws := range []string{"a-b", "a", "a-b"} { // and syncing again in any order never flips it
		syncRoutes(t, a, roots[ws])
		if got := routesync.RouteOwner(route); got != "a" {
			t.Fatalf("after syncing %s the owner is %q", ws, got)
		}
	}
}

func TestPruningOneWorkspaceLeavesTheOthersRoutes(t *testing.T) {
	a := sandboxApp(t)
	base := t.TempDir()
	roots := map[string]string{}
	for _, ws := range []string{"a", "a-b"} {
		roots[ws] = collisionWorkspace(t, base, ws)
		makeService(t, roots[ws], "web", "dashboard.port=80")
		syncRoutes(t, a, roots[ws])
	}
	os.RemoveAll(filepath.Join(roots["a"], "services"))
	syncRoutes(t, a, roots["a"])
	if got := routesync.RouteOwner(filepath.Join(a.D.Routes, "a-b-web.caddy")); got != "a-b" {
		t.Fatalf("pruning workspace a took a-b's route (owner %q)", got)
	}
}

func TestLogOffAndAddressRulesKeepSeparatePortLists(t *testing.T) {
	a := sandboxApp(t)
	root := collisionWorkspace(t, t.TempDir(), "books")
	makeService(t, root, "mc", "dashboard.port=80", "om.log=off", "om.net.allow=10.0.0.0/8", "om.tcp=25565", "om.tcp.port=25570")
	syncRoutes(t, a, root)
	slot := a.Reg.ServiceSlots()["books/mc"]
	httpPort := state.PrivatePortBase + slot
	pol := a.Reg.NetPolicies()["books/mc"]
	var ports []int
	for _, p := range pol["ports"].([]any) {
		var n int
		fmt.Sscan(fmt.Sprint(p), &n)
		ports = append(ports, n)
	}
	sort.Ints(ports)
	want := []int{httpPort, 25570}
	sort.Ints(want)
	if fmt.Sprint(ports) != fmt.Sprint(want) {
		t.Errorf("address rule ports %v, want %v", ports, want)
	}
	noLog := map[int]bool{}
	for _, p := range a.Reg.NoLogPorts() {
		noLog[p] = true
	}
	if !noLog[httpPort] || !noLog[25570] {
		t.Errorf("no-log ports %v lack %d and 25570", a.Reg.NoLogPorts(), httpPort)
	}
}

func TestEveryPairKeepsItsOwnFragmentThroughAnySyncOrder(t *testing.T) {
	a := sandboxApp(t)
	hosts := map[string]int{"a": 22100, "a-b": 22101}
	orders := [][][2]string{colliding, {colliding[1], colliding[0]}}
	for _, order := range orders {
		for _, c := range order {
			if _, _, err := a.Stream.SyncRoutes(c[0], map[string]stream.Service{c[1]: {HostPort: hosts[c[0]], ContainerPort: 80, Log: "on"}}, "om-test-no-engine"); err != nil {
				t.Fatal(err)
			}
		}
		for _, c := range colliding {
			f := filepath.Join(a.D.State, "stream", "fragments", "edge", stream.FragmentName(c[0], c[1]))
			if _, err := os.Stat(f); err != nil {
				t.Errorf("no fragment for %v after order %v: %v", c, order, err)
			}
		}
	}
	for _, c := range colliding {
		a.Stream.PruneFragments(c[0], "om-test-no-engine")
	}
}

func TestLongBranchesWithACommonPrefixGetDifferentIDs(t *testing.T) {
	base := "feature/" + strings.Repeat("x", 80)
	ids := map[string]bool{}
	for _, suffix := range []string{"-one", "-two", "-three"} {
		id, err := previews.PreviewID("perso", base+suffix)
		if err != nil {
			t.Fatal(err)
		}
		ids[id] = true
		if len(id) > 63 || !workspace.IsValidWorkspaceID(id) {
			t.Errorf("id %q is too long or invalid", id)
		}
	}
	if len(ids) != 3 {
		t.Errorf("ids collide: %v", ids)
	}
}

func TestSameBranchSameID(t *testing.T) {
	a, _ := previews.PreviewID("perso", "Feature/Login")
	b, _ := previews.PreviewID("perso", "feature/login")
	c, _ := previews.PreviewID("perso", "fix/x")
	if a != b || c != "perso--fix-x" {
		t.Errorf("%q %q %q", a, b, c)
	}
}
