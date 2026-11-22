// Package py holds the few Python behaviors the port must reproduce exactly, because om's files and output are
// read by both implementations while they coexist.
package py

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
)

// IsSpace is Python's str.isspace for one rune: Go's unicode.IsSpace plus the separators U+001C..U+001F.
func IsSpace(r rune) bool { return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f) }

// Strip is str.strip().
func Strip(s string) string { return strings.TrimFunc(s, IsSpace) }

// Str is str(v) for the values a decoded JSON/YAML document holds (use json.Decoder.UseNumber so numbers keep
// their written form).
func Str(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case string:
		return x
	case bool:
		if x {
			return "True"
		}
		return "False"
	case json.Number:
		return x.String()
	case float64:
		return FloatRepr(x)
	case int:
		return strconv.Itoa(x)
	default:
		return fmt.Sprint(x)
	}
}

// FloatRepr is repr(float) for ordinary magnitudes: the shortest round-trip digits, always with a decimal point.
func FloatRepr(f float64) string {
	s := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.ContainsAny(s, ".") {
		s += ".0"
	}
	return s
}

// JSONString is json.dumps(s) with the default ensure_ascii=True: non-ASCII becomes \uXXXX (surrogate pairs
// above the BMP) and nothing is HTML-escaped.
func JSONString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04x`, r)
		case r < 0x7f:
			b.WriteRune(r)
		case r > 0xffff:
			r1, r2 := utf16.EncodeRune(r)
			fmt.Fprintf(&b, `\u%04x\u%04x`, r1, r2)
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// DumpIndent2 is json.dumps(v, indent=2) semantically: two-space indent, no HTML escaping, no trailing newline.
// Map keys come out sorted (Go's rule); Python keeps insertion order, so files are equal as JSON, not as bytes.
func DumpIndent2(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// LoadJSON decodes into any, keeping numbers as json.Number.
func LoadJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing data")
	}
	return v, nil
}

// SplitLines is str.splitlines(): it splits at \n, \r, \r\n, \v, \f, \x1c-\x1e, \x85,   and  , drops the
// terminators, and makes no empty last element for a trailing terminator.
func SplitLines(s string) []string {
	var out []string
	start := 0
	rs := []rune(s)
	// work on runes so the multi-byte separators are found; rebuild substrings from rune offsets
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch r {
		case '\n', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
			out = append(out, string(rs[start:i]))
			start = i + 1
		case '\r':
			out = append(out, string(rs[start:i]))
			if i+1 < len(rs) && rs[i+1] == '\n' {
				i++
			}
			start = i + 1
		}
	}
	if start < len(rs) {
		out = append(out, string(rs[start:]))
	}
	return out
}

// Fields is str.split() with no argument: runs of Python whitespace separate the items.
func Fields(s string) []string { return strings.FieldsFunc(s, IsSpace) }

// Truthy is Python's bool(v) for decoded JSON values.
func Truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case json.Number:
		f, err := strconv.ParseFloat(x.String(), 64)
		return err != nil || f != 0
	case int:
		return x != 0
	case float64:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	case *Object:
		return x.Len() > 0
	}
	return true
}

// Normpath is posixpath.normpath: ".", "..", repeated slashes and a trailing slash are resolved, and exactly two
// leading slashes are kept (three or more become one).
func Normpath(path string) string {
	if path == "" {
		return "."
	}
	initial := 0
	if strings.HasPrefix(path, "/") {
		initial = 1
		if strings.HasPrefix(path, "//") && !strings.HasPrefix(path, "///") {
			initial = 2
		}
	}
	var out []string
	for _, c := range strings.Split(path, "/") {
		if c == "" || c == "." {
			continue
		}
		if c != ".." || (initial == 0 && len(out) == 0) || (len(out) > 0 && out[len(out)-1] == "..") {
			out = append(out, c)
		} else if len(out) > 0 {
			out = out[:len(out)-1]
		}
	}
	p := strings.Join(out, "/")
	if initial > 0 {
		p = strings.Repeat("/", initial) + p
	}
	if p == "" {
		return "."
	}
	return p
}

// PosixJoin is posixpath.join(a, b).
func PosixJoin(a, b string) string {
	switch {
	case strings.HasPrefix(b, "/"):
		return b
	case a == "" || strings.HasSuffix(a, "/"):
		return a + b
	}
	return a + "/" + b
}

// SplitLinesKeepEnds is str.splitlines(keepends=True).
func SplitLinesKeepEnds(s string) []string {
	var out []string
	rs := []rune(s)
	start := 0
	for i := 0; i < len(rs); i++ {
		switch rs[i] {
		case '\n', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
			out = append(out, string(rs[start:i+1]))
			start = i + 1
		case '\r':
			if i+1 < len(rs) && rs[i+1] == '\n' {
				i++
			}
			out = append(out, string(rs[start:i+1]))
			start = i + 1
		}
	}
	if start < len(rs) {
		out = append(out, string(rs[start:]))
	}
	return out
}

// ReadText is Path.read_text(encoding="utf-8"): the file is decoded as UTF-8 (bad bytes become U+FFFD only if
// they would; Python would raise, and om never reads untrusted binary this way) and "\r\n" and a lone "\r"
// become "\n" (universal newlines), so text that goes through Python's regexes looks the same here.
func ReadText(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return UniversalNewlines(string(b)), nil
}

// UniversalNewlines translates "\r\n" and "\r" to "\n".
func UniversalNewlines(s string) string {
	if !strings.Contains(s, "\r") {
		return s
	}
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
}

// Quote is urllib.parse.quote(s, safe=safe): everything but letters, digits, "_.-~" and the safe characters is
// percent-encoded (UTF-8, upper-case hex).
func Quote(s, safe string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '.', c == '-', c == '~', strings.IndexByte(safe, c) >= 0:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// LStrip is str.lstrip().
func LStrip(s string) string { return strings.TrimLeftFunc(s, IsSpace) }

// Title is str.title() for ASCII text: a letter that follows a non-letter is upper-cased, the rest lower-cased.
func Title(s string) string {
	var b strings.Builder
	prevLetter := false
	for _, r := range s {
		isLetter := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		switch {
		case isLetter && !prevLetter:
			b.WriteString(strings.ToUpper(string(r)))
		case isLetter:
			b.WriteString(strings.ToLower(string(r)))
		default:
			b.WriteRune(r)
		}
		prevLetter = isLetter
	}
	return b.String()
}

// Repr is repr() of a str: single quotes unless the text has a ' and no ".
func Repr(s string) string {
	q := byte('\'')
	if strings.Contains(s, "'") && !strings.Contains(s, `"`) {
		q = '"'
	}
	var b strings.Builder
	b.WriteByte(q)
	for _, r := range s {
		switch {
		case r == rune(q) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 32 || r == 127:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte(q)
	return b.String()
}
