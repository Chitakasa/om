package state

import (
	"bytes"
	"errors"
	"os/exec"
	"strings"
	"unicode/utf8"
)

// Result is a finished subprocess: like Python's CompletedProcess, a missing binary is code 127, never an error.
type Result struct {
	Code           int
	Stdout, Stderr string
}

// Run executes cmd (name + args) and captures its output as UTF-8 (invalid bytes replaced). It never fails for
// a missing or non-executable binary: that is Code 127 with the reason in Stderr.
func Run(cmd []string, opts ...func(*exec.Cmd)) Result {
	c := exec.Command(cmd[0], cmd[1:]...)
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	for _, o := range opts {
		o(c)
	}
	err := c.Run()
	res := Result{Stdout: toUTF8(out.Bytes()), Stderr: toUTF8(errb.Bytes())}
	if err == nil {
		return res
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		res.Code = ee.ExitCode()
		return res
	}
	res.Code, res.Stderr = 127, err.Error()
	return res
}

// WithStdin feeds input to the command.
func WithStdin(s string) func(*exec.Cmd) { return func(c *exec.Cmd) { c.Stdin = strings.NewReader(s) } }

// WithDir runs the command in dir.
func WithDir(dir string) func(*exec.Cmd) { return func(c *exec.Cmd) { c.Dir = dir } }

func toUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	return strings.ToValidUTF8(string(b), "�")
}

// WithEnv replaces the command's whole environment (KEY=VALUE entries), like subprocess's env=.
func WithEnv(env []string) func(*exec.Cmd) { return func(c *exec.Cmd) { c.Env = env } }
