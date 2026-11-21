package egress

import (
	"os"
	"regexp"
	"strings"

	"github.com/Chitakasa/om/internal/py"
)

func trimNL(s string) string { return strings.TrimSuffix(s, "\n") }

var (
	servicesRE = regexp.MustCompile(`^services:[` + wsClass + `]*(?:#.*)?$`)
	listLabel  = regexp.MustCompile(`(?m)^([ \t]*-[` + wsClass + `]*["']?)om\.egress=([^"'\r\n]+)(["']?)`)
	dictLabel  = regexp.MustCompile(`(?m)^([ \t]*om\.egress:[` + wsClass + `]*["']?)([^"'\r\n]+)(["']?)`)
	labelsKey  = regexp.MustCompile(`(?m)^([ \t]+)labels:[` + wsClass + `]*(?:#.*)?$`)
)

// FindServiceSpan finds a service's block in compose text: its start and end (in characters) and the indent of
// its name; ok=false when the service is not there. The match is textual, so comments and layout survive an edit.
func FindServiceSpan(text, svc string) (start, end, indent int, ok bool) {
	lines := py.SplitLinesKeepEnds(text)
	type span struct {
		start, end int
		line       string
	}
	spans := make([]span, len(lines))
	pos := 0
	for i, l := range lines {
		n := len([]rune(l))
		spans[i] = span{pos, pos + n, l}
		pos += n
	}
	svcRE := regexp.MustCompile(`^([ \t]+)` + regexp.QuoteMeta(svc) + `:[` + wsClass + `]*(?:#.*)?$`)
	inServices := false
	startIdx := -1
	for i, sp := range spans {
		stripped := py.Strip(sp.line)
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			continue
		}
		if servicesRE.MatchString(trimNL(sp.line)) {
			inServices = true
			continue
		}
		if inServices {
			if m := svcRE.FindStringSubmatch(trimNL(sp.line)); m != nil {
				startIdx, indent = i, len(m[1])
				break
			}
			if !strings.HasPrefix(sp.line, " ") && !strings.HasPrefix(sp.line, "\t") {
				inServices = false
			}
		}
	}
	if startIdx < 0 {
		return 0, 0, 0, false
	}
	endIdx := len(spans)
	for j := startIdx + 1; j < len(spans); j++ {
		stripped := py.Strip(spans[j].line)
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			continue
		}
		if len(spans[j].line)-len(strings.TrimLeft(spans[j].line, " \t")) <= indent {
			endIdx = j
			break
		}
	}
	start = spans[startIdx].start
	if endIdx > 0 {
		end = spans[endIdx-1].end
	} else {
		end = len([]rune(text))
	}
	return start, end, indent, true
}

// ApplyEgressLabel updates (or adds) the om.egress label of svc in a compose file so it also allows newHosts.
// It reports whether the file was changed.
func ApplyEgressLabel(composePath, svc string, newHosts []string) bool {
	text, err := py.ReadText(composePath)
	if err != nil {
		return false
	}
	start, end, indent, ok := FindServiceSpan(text, svc)
	if !ok {
		return false
	}
	rs := []rune(text)
	block := string(rs[start:end])
	var newBlock string
	if m := listLabel.FindStringSubmatchIndex(block); m != nil {
		cur, has := ParseLabel(py.Strip(block[m[4]:m[5]]))
		sugg := Suggestion(cur, has, newHosts)
		pfx := block[m[2]:m[3]]
		var rep string
		if strings.HasSuffix(pfx, `"`) || strings.HasSuffix(pfx, `'`) {
			rep = pfx + "om.egress=" + sugg + pfx[len(pfx)-1:]
		} else {
			rep = pfx + `"om.egress=` + sugg + `"`
		}
		newBlock = block[:m[0]] + rep + block[m[1]:]
	} else if m := dictLabel.FindStringSubmatchIndex(block); m != nil {
		cur, has := ParseLabel(py.Strip(block[m[4]:m[5]]))
		sugg := Suggestion(cur, has, newHosts)
		pfx := block[m[2]:m[3]]
		var rep string
		if strings.HasSuffix(pfx, `"`) || strings.HasSuffix(pfx, `'`) {
			rep = pfx + sugg + pfx[len(pfx)-1:]
		} else {
			rep = pfx + `"` + sugg + `"`
		}
		newBlock = block[:m[0]] + rep + block[m[1]:]
	} else {
		sugg := Suggestion(Rule{}, false, newHosts)
		if m := labelsKey.FindStringSubmatchIndex(block); m != nil {
			lineEnd := strings.Index(block[m[0]:], "\n") + 1
			if lineEnd > 0 {
				lineEnd += m[0]
			} // else Python's find()+1 = 0: the label goes at the very top
			ind := strings.Repeat(" ", (m[3]-m[2])+2)
			newBlock = block[:lineEnd] + ind + `- "om.egress=` + sugg + `"` + "\n" + block[lineEnd:]
		} else {
			firstEnd := strings.Index(block, "\n") + 1
			ind := strings.Repeat(" ", indent+2)
			newBlock = block[:firstEnd] + ind + "labels:\n" + ind + `  - "om.egress=` + sugg + `"` + "\n" + block[firstEnd:]
		}
	}
	out := string(rs[:start]) + newBlock + string(rs[end:])
	return os.WriteFile(composePath, []byte(out), 0o644) == nil
}
