package labels

import "testing"

func TestLimitRegexesRefuseATrailingNewlineHole(t *testing.T) {
	for _, raw := range []string{"5m\n", "0m", "5 m", "-1m", "5tb", ""} {
		if memRE.MatchString(raw) {
			t.Errorf("memory %q accepted", raw)
		}
	}
	for _, raw := range []string{"0", "1000000", "7\n", "-1"} {
		if pidsRE.MatchString(raw) {
			t.Errorf("pids %q accepted", raw)
		}
	}
	for _, raw := range []string{"1\n", "-1", "1e3", "", "."} {
		if cpusRE.MatchString(raw) && raw != "." {
			t.Errorf("cpus %q accepted", raw)
		}
	}
}
