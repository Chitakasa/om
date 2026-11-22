// Package previews has the naming and portability checks for `om preview` (the command itself lives in the CLI).
// Port of lib/gitops/previews.py.
package previews

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/workspace"
)

var (
	branchRE = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,100}$`)
	slugRE   = regexp.MustCompile(`[^a-z0-9]+`)
)

// ValidBranch is a branch name that is safe to hand to git as an argument: plain characters, never an option
// (`-…`), and none of the shapes git's ref rules forbid (`..`, `//`, a leading or trailing `/` or `.`, `.lock`).
func ValidBranch(branch string) bool {
	if !branchRE.MatchString(branch) {
		return false
	}
	return !(strings.ContainsRune("-./", rune(branch[0])) || strings.ContainsRune("/.", rune(branch[len(branch)-1])) ||
		strings.Contains(branch, "..") || strings.Contains(branch, "//") || strings.HasSuffix(branch, ".lock"))
}

// PreviewID is the workspace id of a branch's preview: `<ws>--<slug>`, shortened with a hash of the branch when it
// would be too long.
func PreviewID(ws, branch string) (string, error) {
	slug := strings.Trim(slugRE.ReplaceAllString(strings.ToLower(branch), "-"), "-")
	pid := ws + "--" + slug
	if len(pid) > 63 { // truncating alone would give two long branches one id: keep a hash of the branch
		sum := sha256.Sum256([]byte(branch))
		pid = strings.TrimRight(pid[:55], "-") + "-" + hex.EncodeToString(sum[:])[:7]
	}
	if slug == "" || !workspace.IsValidWorkspaceID(pid) {
		return "", fmt.Errorf("Cannot make a workspace id from branch '%s'.", branch)
	}
	return pid, nil
}

const wsc = `\t\n\v\f\r \x{1c}-\x{1f}\x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}`

var (
	containerNameRE = regexp.MustCompile(`(?m)^[` + wsc + `]*container_name:[` + wsc + `]*["']?([^` + wsc + `"']+)`)
	netNameRE       = regexp.MustCompile(`(?m)^[` + wsc + `]*name:[` + wsc + `]*["']?([^` + wsc + `"']+_net)\b`)
)

// PreviewPortable lists compose files that would collide with the original: container or network names that do
// not follow ${WORKSPACE_ID} / ${WORKSPACE_NET}.
func PreviewPortable(root string) []string {
	bad := []string{}
	for _, p := range workspace.DiscoverComposeDirs(root, "") {
		cf, ok := workspace.FindComposeFile(p.Dir)
		if !ok {
			continue
		}
		text, err := py.ReadText(cf)
		if err != nil {
			continue
		}
		rel := "."
		if p.Dir != root {
			rel, _ = filepath.Rel(root, p.Dir)
		}
		for _, m := range containerNameRE.FindAllStringSubmatch(text, -1) {
			if !strings.Contains(m[1], "${WORKSPACE_ID") {
				bad = append(bad, rel+": container_name: "+m[1]+"  → ${WORKSPACE_ID:-…}_<name>")
			}
		}
		for _, m := range netNameRE.FindAllStringSubmatch(text, -1) {
			if !strings.Contains(m[1], "${WORKSPACE") {
				bad = append(bad, rel+": network name: "+m[1]+"  → ${WORKSPACE_NET}")
			}
		}
	}
	return bad
}
