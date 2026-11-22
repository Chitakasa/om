package lock

import (
	"strings"
	"testing"
)

func TestDigestRegexRefusesATrailingNewlineHole(t *testing.T) {
	good := "sha256:" + strings.Repeat("a", 64)
	if !digestRE.MatchString(good) {
		t.Fatal("a digest is refused")
	}
	for _, bad := range []string{good + "\n", good + " ", "sha256:" + strings.Repeat("a", 63), "sha256:" + strings.Repeat("A", 64), "sha1:" + strings.Repeat("a", 40)} {
		if digestRE.MatchString(bad) {
			t.Errorf("digest %q accepted", bad)
		}
	}
}
