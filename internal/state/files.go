package state

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// WritePrivate writes a file readable only by the current user, atomically.
func WritePrivate(path string, content string) error { return WritePrivateBytes(path, []byte(content)) }

// WritePrivateBytes is an atomic write of a file that is 0600 from the moment it exists.
func WritePrivateBytes(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		os.Remove(tmp)
		if werr != nil {
			return werr
		}
		return cerr
	}
	_ = os.Chmod(tmp, 0o600) // a leftover .tmp keeps its old mode through O_CREATE
	return os.Rename(tmp, path)
}

// WriteAtomic replaces a file in one step, so a reader (Caddy reloading routes) never sees half of it.
func WriteAtomic(path string, text string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(text), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ParseEnvFile reads KEY=VALUE lines; blank lines, comments and lines without "=" are skipped, and one level of
// surrounding quotes is stripped. A missing file yields an empty map.
func ParseEnvFile(path string) (map[string]string, error) {
	data := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return data, nil
		}
		return data, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"`)
		v = strings.Trim(v, `'`)
		data[strings.TrimSpace(k)] = v
	}
	return data, sc.Err()
}

// IsNumber reports plain ASCII digits only (not '²' or fullwidth digits, which a Unicode digit test accepts).
func IsNumber(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
