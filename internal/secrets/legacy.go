// Package secrets covers om's secrets: the read-only legacy vault (om-v1 / om-v2 files, and SOPS files when sops is
// installed), the age secrets of a workspace (encrypted in the repo, decrypted only at start) and the private-tier
// login file. om writes no cryptography of its own. Port of lib/gitops/secrets.py, agesecrets.py and the helpers of
// securitycmds.py.
package secrets

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/Chitakasa/om/internal/py"
)

const (
	PBKDF2IterationsV1 = 100000
	PBKDF2IterationsV2 = 600000
)

// Legacy opens old vault files. The fields exist for tests.
type Legacy struct {
	Getenv func(string) string
	// Sops decrypts with sops when it is installed; ok=false falls through to om's own formats.
	Sops func(path string) (plain []byte, ok bool)
	// Warn receives the om-v1 warning (stderr in the CLI).
	Warn io.Writer
}

// NewLegacy returns a Legacy for this machine.
func NewLegacy() *Legacy {
	return &Legacy{Getenv: os.Getenv, Warn: os.Stderr, Sops: func(path string) ([]byte, bool) {
		if exec.Command("sops", "--version").Run() != nil {
			return nil, false
		}
		out, err := exec.Command("sops", "-d", path).Output()
		if err != nil {
			return nil, false
		}
		return out, true
	}}
}

// DeriveKey derives key material from a passphrase with PBKDF2-HMAC-SHA256.
func DeriveKey(passphrase string, salt []byte, iterations, length int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, passphrase, salt, iterations, length)
}

// KeystreamXOR XORs data with a SHA256(key || counter) keystream (CTR-style; the key must be unique per file via
// the salt). counterBytes is 8 for om-v2 and 4 for the legacy om-v1.
func KeystreamXOR(key, data []byte, counterBytes int) []byte {
	out := make([]byte, len(data))
	var stream []byte
	for counter := uint64(0); len(stream) < len(data); counter++ {
		c := make([]byte, 8)
		binary.BigEndian.PutUint64(c, counter)
		h := sha256.Sum256(append(append([]byte{}, key...), c[8-counterBytes:]...))
		stream = append(stream, h[:]...)
	}
	for i := range data {
		out[i] = data[i] ^ stream[i]
	}
	return out
}

func v2MAC(macKey, salt, ciphertext []byte) []byte {
	m := hmac.New(sha256.New, macKey)
	m.Write([]byte("om-v2"))
	m.Write(salt)
	m.Write(ciphertext)
	return m.Sum(nil)
}

// b64 is Python's base64.b64decode(s): characters outside the alphabet are ignored, padding must be right.
func b64Lenient(s string) ([]byte, error) {
	var b strings.Builder
	for _, r := range s {
		if r < 128 && (r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '+' || r == '/' || r == '=') {
			b.WriteRune(r)
		}
	}
	return base64.StdEncoding.DecodeString(b.String())
}

// repr is Python's repr() of a decoded JSON value, for the "Unsupported secret format" message.
func repr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case string:
		if strings.Contains(x, "'") && !strings.Contains(x, `"`) {
			return `"` + x + `"`
		}
		return "'" + strings.ReplaceAll(strings.ReplaceAll(x, `\`, `\\`), "'", `\'`) + "'"
	}
	return py.Str(v)
}

// DecryptFile decrypts a vault file into memory. The error is a ValueError's text on a wrong passphrase or a
// tampered file (om-v2). allowUnauthenticated opens the old om-v1 format, which has no integrity check.
func (l *Legacy) DecryptFile(path, passphrase string, allowUnauthenticated bool) ([]byte, error) {
	if l.Sops != nil {
		if out, ok := l.Sops(path); ok {
			return out, nil
		}
	}
	if passphrase == "" {
		passphrase = l.Getenv("OM_SECRET_KEY")
	}
	if passphrase == "" {
		return nil, errors.New("Passphrase required to decrypt.")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	v, err := py.LoadJSON([]byte(py.UniversalNewlines(string(b))))
	env, ok := v.(map[string]any)
	if err != nil || !ok {
		return nil, fmt.Errorf("%s: not a vault file", path)
	}
	saltText, okS := env["salt"].(string)
	payloadText, okP := env["payload"].(string)
	if !okS || !okP {
		return nil, fmt.Errorf("%s: not a vault file (no salt or payload)", path)
	}
	salt, err := b64Lenient(saltText)
	if err != nil {
		return nil, err
	}
	ciphertext, err := b64Lenient(payloadText)
	if err != nil {
		return nil, err
	}
	version := env["version"]
	switch version {
	case "om-v2":
		material, err := DeriveKey(passphrase, salt, PBKDF2IterationsV2, 64)
		if err != nil {
			return nil, err
		}
		encKey, macKey := material[:32], material[32:]
		macText, _ := env["mac"].(string)
		expected, err := b64Lenient(macText)
		if err != nil {
			return nil, err
		}
		if !hmac.Equal(v2MAC(macKey, salt, ciphertext), expected) {
			return nil, errors.New("Integrity check failed: wrong passphrase or tampered file.")
		}
		return KeystreamXOR(encKey, ciphertext, 8), nil
	case "om-v1":
		// Legacy format: unauthenticated and 4-byte counter, so a wrong passphrase or a tampered file gives garbage
		// silently. Refused unless asked for, to read the data once and move it to age (`om secrets migrate`).
		if !allowUnauthenticated {
			return nil, errors.New("om-v1 secrets have no integrity check (a wrong passphrase or a tampered file gives garbage silently); " +
				"read it once with --allow-unauthenticated and move it to age: om secrets migrate <file> <project>/<name>")
		}
		if l.Warn != nil {
			fmt.Fprintln(l.Warn, "\033[33mWarning: om-v1 secret has no integrity check; re-encrypt it to upgrade to om-v2.\033[0m")
		}
		key, err := DeriveKey(passphrase, salt, PBKDF2IterationsV1, 32)
		if err != nil {
			return nil, err
		}
		return KeystreamXOR(key, ciphertext, 4), nil
	}
	return nil, fmt.Errorf("Unsupported secret format: %s", repr(version))
}
