// Package scripts has the script discovery helpers for `om scripts`: which files are runnable and their one-line
// summary. Port of lib/gitops/scripts.py.
package scripts

import (
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/Chitakasa/om/internal/py"
)

var ScriptExts = map[string]bool{".sh": true, ".py": true, ".bash": true, ".ps1": true}

// ExecMagic are the first bytes of runnable files (a shebang or a native executable).
var ExecMagic = [][]byte{[]byte("#!"), []byte("\x7fELF"), []byte("MZ"), []byte("\xca\xfe\xba\xbe"), []byte("\xcf\xfa\xed\xfe"), []byte("\xce\xfa\xed\xfe")}

var docQuotes = []struct{ open, close string }{{`"""`, `"""`}, {"'''", "'''"}, {"<#", "#>"}}

const commentDecor = "=-─━═*~_#│| \t"

const ws = `\t\n\v\f\r \x{1c}-\x{1f}\x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}`

var directiveRE = regexp.MustCompile(`^(shellcheck[` + ws + `]|coding[:=]|vim?:|SPDX-|\.[A-Z]+$)`)

// stem is pathlib's Path(name).stem.
func stem(name string) string {
	ext := filepath.Ext(name)
	if ext == "" || ext == name || ext == "." { // no suffix: a dotfile ".x" or a trailing dot
		return name
	}
	return strings.TrimSuffix(name, ext)
}

func hasAlnum(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			return true
		}
	}
	return false
}

// Description is the one-line summary of a script: the first real line of the leading comment block or docstring.
func Description(head []byte, filename string) string {
	lines := py.SplitLines(strings.ToValidUTF8(string(head), ""))
	if len(lines) > 0 && strings.HasPrefix(lines[0], "#!") {
		lines = lines[1:]
	}
	closeQ := ""
	for _, line := range lines {
		s := py.Strip(line)
		if closeQ == "" {
			for _, q := range docQuotes {
				if strings.HasPrefix(s, q.open) {
					closeQ, s = q.close, s[len(q.open):]
					break
				}
			}
		}
		var text string
		var closed bool
		switch {
		case closeQ != "":
			text, closed = strings.SplitN(s, closeQ, 2)[0], strings.Contains(s, closeQ)
		case strings.HasPrefix(s, "#"):
			text, closed = s, false
		case s != "":
			return "" // first line of code ends the header
		default:
			continue
		}
		text = strings.Trim(text, commentDecor)
		if hasAlnum(text) && !directiveRE.MatchString(text) {
			prefix := regexp.MustCompile(`(?i)^(?:` + regexp.QuoteMeta(filename) + `|` + regexp.QuoteMeta(stem(filename)) + `)[` + ws + `]*[—–:\-][` + ws + `]+`)
			short := prefix.ReplaceAllString(text, "")
			if short == text {
				return text
			}
			r := []rune(short)
			if len(r) == 0 {
				return ""
			}
			return strings.ToUpper(string(r[0])) + string(r[1:])
		}
		if closed {
			break
		}
	}
	return ""
}
