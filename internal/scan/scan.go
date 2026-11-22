// Package scan counts image vulnerabilities (`om scan`) from a scanner already on the machine: trivy or grype. om
// ships no scanner and no vulnerability database; a pinned digest never changes, so it also never gets a security
// fix until `om update` moves it. This shows which pins to move first. Port of lib/gitops/scan.py.
package scan

import (
	"os/exec"
	"strings"

	"github.com/Chitakasa/om/internal/py"
)

var (
	Severities = []string{"CRITICAL", "HIGH"}
	Tools      = []string{"trivy", "grype"}
)

// Scanner returns the first scanner found on the PATH ("" if none).
func Scanner(lookPath func(string) (string, error)) string {
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	for _, t := range Tools {
		if _, err := lookPath(t); err == nil {
			return t
		}
	}
	return ""
}

// Command is the command line that scans ref.
func Command(tool, ref string) []string {
	if tool == "trivy" {
		return []string{"trivy", "image", "--quiet", "--format", "json", "--severity", strings.Join(Severities, ","), ref}
	}
	return []string{"grype", ref, "-o", "json", "--quiet"}
}

// Count returns {CRITICAL: n, HIGH: n} from the scanner's JSON; an error if it is not JSON.
func Count(tool, output string) (map[string]int, error) {
	v, err := py.LoadJSON([]byte(output))
	if err != nil {
		return nil, err
	}
	data, _ := v.(map[string]any)
	asObj := func(v any) map[string]any { o, _ := v.(map[string]any); return o }
	var found []string
	if tool == "trivy" {
		res, _ := data["Results"].([]any)
		for _, r := range res {
			vulns, _ := asObj(r)["Vulnerabilities"].([]any)
			for _, vl := range vulns {
				sev := ""
				if s := asObj(vl)["Severity"]; s != nil {
					sev = py.Str(s)
				}
				found = append(found, sev)
			}
		}
	} else {
		ms, _ := data["matches"].([]any)
		for _, m := range ms {
			sev := ""
			if s := asObj(asObj(m)["vulnerability"])["severity"]; s != nil {
				sev = py.Str(s)
			}
			found = append(found, sev)
		}
	}
	out := map[string]int{}
	for _, s := range Severities {
		out[s] = 0
	}
	for _, f := range found {
		f = strings.ToUpper(f)
		if _, ok := out[f]; ok {
			out[f]++
		}
	}
	return out, nil
}
