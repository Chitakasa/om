// Package wizard asks questions on a terminal: free text with a default and a check, a numbered choice, yes or no. It
// reads plain lines (no raw terminal mode), so it behaves the same on every OS and a test can feed it a script.
package wizard

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ErrCancelled is returned when the input ends (Ctrl-D) before an answer: the caller stops and changes nothing.
var ErrCancelled = errors.New("cancelled")

// Prompter asks on Out and reads answers from In.
type Prompter struct {
	In  *bufio.Reader
	Out io.Writer
}

// Option is one line of a numbered choice.
type Option struct{ Label, Hint string }

func (p *Prompter) line() (string, error) {
	s, err := p.In.ReadString('\n')
	if err != nil && s == "" {
		fmt.Fprintln(p.Out)
		return "", ErrCancelled
	}
	return strings.TrimSpace(s), nil
}

// Ask asks for text. An empty answer takes def; check (may be nil) sees the answer and returns a message to ask again,
// or "". Pass a check that rejects "" for a required answer, and none (or one that accepts "") for an optional one.
func (p *Prompter) Ask(question, def string, check func(string) string) (string, error) {
	for {
		if def != "" {
			fmt.Fprintf(p.Out, "%s [%s]: ", question, def)
		} else {
			fmt.Fprintf(p.Out, "%s: ", question)
		}
		s, err := p.line()
		if err != nil {
			return "", err
		}
		if s == "" {
			s = def
		}
		if check != nil {
			if msg := check(s); msg != "" {
				fmt.Fprintf(p.Out, "  %s\n", msg)
				continue
			}
		}
		return s, nil
	}
}

// Choose shows a numbered list and returns the index picked; Enter picks def (marked with *).
func (p *Prompter) Choose(question string, opts []Option, def int) (int, error) {
	fmt.Fprintln(p.Out, question)
	for i, o := range opts {
		mark, hint := " ", ""
		if i == def {
			mark = "*"
		}
		if o.Hint != "" {
			hint = "  — " + o.Hint
		}
		fmt.Fprintf(p.Out, "  %s%d) %s%s\n", mark, i+1, o.Label, hint)
	}
	for {
		fmt.Fprintf(p.Out, "Choose 1-%d [%d]: ", len(opts), def+1)
		s, err := p.line()
		if err != nil {
			return 0, err
		}
		if s == "" {
			return def, nil
		}
		if n, err := strconv.Atoi(s); err == nil && n >= 1 && n <= len(opts) {
			return n - 1, nil
		}
		fmt.Fprintf(p.Out, "  Type a number from 1 to %d.\n", len(opts))
	}
}

// Confirm asks yes or no; Enter takes def.
func (p *Prompter) Confirm(question string, def bool) (bool, error) {
	hint := "y/N"
	if def {
		hint = "Y/n"
	}
	for {
		fmt.Fprintf(p.Out, "%s [%s]: ", question, hint)
		s, err := p.line()
		if err != nil {
			return false, err
		}
		switch strings.ToLower(s) {
		case "":
			return def, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		fmt.Fprintln(p.Out, "  Type y or n.")
	}
}
