package routes

import "testing"

// `$` matching before a final newline once made "/x\n" a valid route path (a hole): the regexes must anchor at the very end.
func TestRoutePathRegexRefusesATrailingNewlineHole(t *testing.T) {
	for _, p := range []string{"/x\n", "/x y", "/x{", "/x}", `/x"`, `/x\`, "/x\x00", "/x%0a", "x", "", "/x`", "/x$y", "/x;y", "/x\r\nrespond evil"} {
		if routePathRE.MatchString(p) {
			t.Errorf("route path %q accepted", p)
		}
	}
	for _, p := range []string{"/x", "/a/b-c_d.e~f", "/api/*", "/"} {
		if !routePathRE.MatchString(p) {
			t.Errorf("route path %q refused", p)
		}
	}
}
