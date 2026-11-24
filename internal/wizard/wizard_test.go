package wizard

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"testing"
)

func prompter(script string) (*Prompter, *bytes.Buffer) {
	var out bytes.Buffer
	return &Prompter{In: bufio.NewReader(strings.NewReader(script)), Out: &out}, &out
}

func TestAskTakesTheDefaultAndAsksAgainOnABadAnswer(t *testing.T) {
	p, out := prompter("\nbad name\ngood\n")
	got, err := p.Ask("Name", "web", nil)
	if err != nil || got != "web" {
		t.Fatalf("default: %q %v", got, err)
	}
	check := func(s string) string {
		if strings.Contains(s, " ") {
			return "No spaces."
		}
		return ""
	}
	got, err = p.Ask("Name", "", check)
	if err != nil || got != "good" || !strings.Contains(out.String(), "No spaces.") {
		t.Fatalf("retry: %q %v\n%s", got, err, out)
	}
}

func TestAnOptionalAnswerMayBeEmpty(t *testing.T) {
	p, _ := prompter("\n")
	if got, err := p.Ask("Memory", "", nil); err != nil || got != "" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestChooseTakesANumberTheDefaultAndRejectsOthers(t *testing.T) {
	opts := []Option{{"one", ""}, {"two", "the second"}, {"three", ""}}
	p, out := prompter("\n3\n9\nx\n2\n")
	for i, want := range []int{1, 2, 1} {
		got, err := p.Choose("Pick", opts, 1)
		if err != nil || got != want {
			t.Fatalf("answer %d: got %d %v", i, got, err)
		}
	}
	if !strings.Contains(out.String(), "*2) two  — the second") || !strings.Contains(out.String(), "Type a number from 1 to 3.") {
		t.Fatalf("listing:\n%s", out)
	}
}

func TestConfirm(t *testing.T) {
	p, _ := prompter("\ny\nNO\nmaybe\nyes\n")
	for i, want := range []bool{false, true, false, true} {
		def := i == 99
		got, err := p.Confirm("Sure?", def)
		if err != nil || got != want {
			t.Fatalf("answer %d: %v %v", i, got, err)
		}
	}
}

func TestEndOfInputCancels(t *testing.T) {
	p, _ := prompter("")
	if _, err := p.Ask("x", "", nil); !errors.Is(err, ErrCancelled) {
		t.Fatalf("ask: %v", err)
	}
	if _, err := p.Choose("x", []Option{{"a", ""}}, 0); !errors.Is(err, ErrCancelled) {
		t.Fatalf("choose: %v", err)
	}
	if _, err := p.Confirm("x", true); !errors.Is(err, ErrCancelled) {
		t.Fatalf("confirm: %v", err)
	}
}
