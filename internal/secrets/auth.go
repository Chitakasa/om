package secrets

import (
	"os"
	"regexp"
	"sort"
	"strings"
)

const ws = `\t\n\v\f\r \x{1c}-\x{1f}\x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}`

var authLineRE = regexp.MustCompile(`(?m)^[` + ws + `]+([A-Za-z0-9._-]{1,64})[` + ws + `]+(\$2[^` + ws + `]*)[` + ws + `]*$`)

// ReadAuthUsers returns {user: bcrypt hash} from the private-tier basic_auth block.
func ReadAuthUsers(conf string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(conf)
	if err != nil {
		return out
	}
	text := strings.ReplaceAll(strings.ReplaceAll(string(b), "\r\n", "\n"), "\r", "\n")
	for _, m := range authLineRE.FindAllStringSubmatch(text, -1) {
		out[m[1]] = m[2]
	}
	return out
}

// WriteAuthUsers writes the basic_auth block (no users removes the file).
func WriteAuthUsers(authDir, conf string, users map[string]string) error {
	if len(users) == 0 {
		if err := os.Remove(conf); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(authDir, 0o755); err != nil {
		return err
	}
	names := make([]string, 0, len(users))
	for u := range users {
		names = append(names, u)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, u := range names {
		b.WriteString("    " + u + " " + users[u] + "\n")
	}
	return os.WriteFile(conf, []byte("basic_auth {\n"+b.String()+"}\n"), 0o644)
}

// MySignerLine is `<email> namespaces="git" <key>` for the user's git SSH signing key, or "". run runs a command
// (git config in the current folder).
func MySignerLine(run func([]string) (int, string), readFile func(string) (string, error), expand func(string) string) string {
	cfg := func(key string) string {
		code, out := run([]string{"git", "config", "--get", key})
		if code != 0 {
			return ""
		}
		return strings.TrimSpace(out)
	}
	email, key := cfg("user.email"), cfg("user.signingkey")
	if cfg("gpg.format") != "ssh" || email == "" || key == "" {
		return ""
	}
	if !strings.HasPrefix(key, "ssh-") && !strings.HasPrefix(key, "sk-") && !strings.HasPrefix(key, "ecdsa-") {
		text, err := readFile(expand(key))
		if err != nil {
			return ""
		}
		key = strings.TrimSpace(text)
	}
	f := strings.Fields(key)
	if len(f) > 2 {
		f = f[:2]
	}
	return email + ` namespaces="git" ` + strings.Join(f, " ")
}
