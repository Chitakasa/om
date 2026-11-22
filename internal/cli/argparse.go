// Package cli is om's command line: an argparse-compatible parser (same accepted forms, same errors, same help layout
// as the Python implementation), the command table and the commands themselves.
package cli

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Arg is one argument of a command: an option (it has Flags) or a positional.
type Arg struct {
	Flags   []string // "-f", "--follow"; none for a positional
	Dest    string
	Nargs   string // "" (exactly one), "?", "*" or "..." (everything that is left)
	Action  string // "store" (default), "store_true", "append"
	Type    string // "" (text) or "int"
	Choices []string
	Default any
	Help    string
	Metavar string
}

func (a Arg) isOption() bool { return len(a.Flags) > 0 }

// takesValue reports an option that reads an argument.
func (a Arg) takesValue() bool {
	return a.Action != "store_true" && a.Action != "help" && a.Action != "version"
}

// Command is one `om` subcommand.
type Command struct {
	Name           string
	Aliases        []string
	Help           string
	Description    string
	RawDescription bool
	Args           []Arg
}

// Namespace holds the parsed values: bool, string, int, []string; absent values are nil.
type Namespace map[string]any

// Str returns a text value ("" when absent).
func (n Namespace) Str(k string) string { s, _ := n[k].(string); return s }

// Bool returns a flag.
func (n Namespace) Bool(k string) bool { b, _ := n[k].(bool); return b }

// Int returns a number (0 when absent).
func (n Namespace) Int(k string) int { i, _ := n[k].(int); return i }

// List returns a repeated option or `*` positional.
func (n Namespace) List(k string) []string { l, _ := n[k].([]string); return l }

// Has reports whether the value was given (or has a default).
func (n Namespace) Has(k string) bool { v, ok := n[k]; return ok && v != nil }

// ParseError is a usage error: Python's argparse prints Usage then "<prog>: error: <Message>" and exits 2.
type ParseError struct {
	Usage   string
	Prog    string
	Message string
}

func (e *ParseError) Error() string { return e.Usage + e.Prog + ": error: " + e.Message + "\n" }

// HelpRequest is returned when -h/--help (or --version) asks for text and a clean exit.
type HelpRequest struct{ Text string }

func (h *HelpRequest) Error() string { return h.Text }

// Parser is the whole command line.
type Parser struct {
	Prog        string
	Version     string
	Description string
	Commands    []*Command
	Groups      []HelpGroup // how `om --help` lists the commands
	Width       func() int  // terminal width (COLUMNS)
}

// HelpGroup is a heading of the top-level help.
type HelpGroup struct {
	Title string
	Names []string
}

func (p *Parser) command(name string) *Command {
	for _, c := range p.Commands {
		if c.Name == name {
			return c
		}
		for _, a := range c.Aliases {
			if a == name {
				return c
			}
		}
	}
	return nil
}

// names lists the command names in registration order, each command followed by its aliases.
func (p *Parser) names() []string {
	var out []string
	for _, c := range p.Commands {
		out = append(out, c.Name)
		out = append(out, c.Aliases...)
	}
	return out
}

// scope is the set of arguments of one parser level: the top level or a command.
type scope struct {
	prog        string
	options     []Arg // the -h option first, like argparse's
	positionals []Arg
	byFlag      map[string]int // flag -> index into options
	flagOrder   []string
	isRoot      bool
}

func helpArg() Arg {
	return Arg{Flags: []string{"-h", "--help"}, Dest: "help", Action: "help", Help: "show this help message and exit"}
}

func newScope(prog string, args []Arg, extra ...Arg) *scope {
	s := &scope{prog: prog, byFlag: map[string]int{}}
	s.options = append(s.options, helpArg())
	s.options = append(s.options, extra...)
	for _, a := range args {
		if a.isOption() {
			s.options = append(s.options, a)
		} else {
			s.positionals = append(s.positionals, a)
		}
	}
	for i, o := range s.options {
		for _, f := range o.Flags {
			s.byFlag[f] = i
			s.flagOrder = append(s.flagOrder, f)
		}
	}
	return s
}

func (s *scope) required(a Arg) bool {
	if a.isOption() {
		return false
	}
	switch a.Nargs {
	case "?", "...", "PARSER":
		return false
	}
	return true // "*" without a default is required too, but always matches (it may be empty)
}

func actionName(a Arg) string {
	if a.isOption() {
		return strings.Join(a.Flags, "/")
	}
	if a.Metavar != "" {
		return a.Metavar
	}
	return a.Dest
}

func reprAll(l []string) string {
	q := make([]string, len(l))
	for i, s := range l {
		q[i] = pyRepr(s)
	}
	return strings.Join(q, ", ")
}

// pyRepr is Python's repr() of a string.
func pyRepr(s string) string {
	q := "'"
	if strings.Contains(s, "'") && !strings.Contains(s, `"`) {
		q = `"`
	}
	var b strings.Builder
	b.WriteString(q)
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case string(r) == q:
			b.WriteString(`\` + q)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteString(q)
	return b.String()
}

func nargsPattern(a Arg) string {
	var p string
	switch {
	case a.isOption() && !a.takesValue():
		p = "(-*-*)"
	case a.Nargs == "":
		p = "(-*A-*)"
	case a.Nargs == "?":
		p = "(-*A?-*)"
	case a.Nargs == "*":
		p = "(-*[A-]*)"
	case a.Nargs == "...":
		p = "([-AO]*)"
	case a.Nargs == "PARSER":
		p = "(-*A[-AO]*)"
	}
	if a.isOption() {
		p = strings.ReplaceAll(strings.ReplaceAll(p, "-*", ""), "-", "")
	}
	return p
}

type optionTuple struct {
	arg      *Arg
	flag     string
	sep      string // "=" when the value was attached with =, "" for -n5, "" with no value at all
	explicit *string
}

type parseState struct {
	p         *Parser
	s         *scope
	args      []string
	pattern   string
	ns        Namespace
	seen      map[string]bool
	extras    []string
	opts      map[int]*optionTuple
	pos       []Arg // positionals not consumed yet
	subExtras []string
}

func (st *parseState) usage() string { return st.p.usageOf(st.s) }

func (st *parseState) fail(msg string) error {
	return &ParseError{Usage: st.usage(), Prog: st.s.prog, Message: msg}
}

var negNumberRE = regexp.MustCompile(`^-[0-9]+$|^-[0-9]*\.[0-9]+$`)

// parseOptional classifies one argument string: an option (known, abbreviated or unknown) or a plain argument.
func (st *parseState) parseOptional(arg string) (*optionTuple, error) {
	if arg == "" || !strings.HasPrefix(arg, "-") {
		return nil, nil
	}
	if i, ok := st.s.byFlag[arg]; ok {
		return &optionTuple{&st.s.options[i], arg, "", nil}, nil
	}
	if len(arg) == 1 {
		return nil, nil
	}
	if k := strings.Index(arg, "="); k >= 0 {
		flag, explicit := arg[:k], arg[k+1:]
		if i, ok := st.s.byFlag[flag]; ok {
			return &optionTuple{&st.s.options[i], flag, "=", &explicit}, nil
		}
	}
	var matches []optionTuple
	switch {
	case strings.HasPrefix(arg, "--"):
		prefix := arg
		var explicit *string
		sep := ""
		if k := strings.Index(arg, "="); k >= 0 {
			prefix = arg[:k]
			e := arg[k+1:]
			explicit, sep = &e, "="
		}
		for _, f := range st.s.flagOrder {
			if strings.HasPrefix(f, prefix) {
				matches = append(matches, optionTuple{&st.s.options[st.s.byFlag[f]], f, sep, explicit})
			}
		}
	default:
		short, shortExplicit := arg[:2], arg[2:]
		for _, f := range st.s.flagOrder {
			switch {
			case f == short:
				e := shortExplicit
				matches = append(matches, optionTuple{&st.s.options[st.s.byFlag[f]], f, "", &e})
			case strings.HasPrefix(f, arg):
				matches = append(matches, optionTuple{&st.s.options[st.s.byFlag[f]], f, "", nil})
			}
		}
	}
	if len(matches) > 1 {
		var names []string
		for _, m := range matches {
			names = append(names, m.flag)
		}
		return nil, st.fail(fmt.Sprintf("ambiguous option: %s could match %s", arg, strings.Join(names, ", ")))
	}
	if len(matches) == 1 {
		m := matches[0]
		return &m, nil
	}
	if negNumberRE.MatchString(arg) || strings.Contains(arg, " ") {
		return nil, nil
	}
	return &optionTuple{nil, arg, "", nil}, nil
}

func (st *parseState) match(a Arg, pattern string) (int, error) {
	m := regexp.MustCompile("^" + nargsPattern(a)).FindStringSubmatch(pattern)
	if m == nil {
		if a.Nargs == "?" {
			return 0, st.fail(fmt.Sprintf("argument %s: expected at most one argument", actionName(a)))
		}
		return 0, st.fail(fmt.Sprintf("argument %s: expected one argument", actionName(a)))
	}
	return len(m[1]), nil
}

func (st *parseState) convert(a Arg, v string) (any, error) {
	var val any = v
	if a.Type == "int" {
		n, err := parseInt(v)
		if err != nil {
			return nil, st.fail(fmt.Sprintf("argument %s: invalid int value: %s", actionName(a), pyRepr(v)))
		}
		val = n
	}
	if len(a.Choices) > 0 {
		ok := false
		for _, c := range a.Choices {
			ok = ok || c == v
		}
		if !ok {
			return nil, st.fail(fmt.Sprintf("argument %s: invalid choice: %s (choose from %s)", actionName(a), pyRepr(v), reprAll(a.Choices)))
		}
	}
	return val, nil
}

// parseInt is Python's int(text): surrounding space, a sign and single underscores between digits are allowed.
func parseInt(v string) (int, error) {
	t := strings.TrimSpace(v)
	if t == "" || strings.HasPrefix(t, "_") || strings.HasSuffix(t, "_") || strings.Contains(t, "__") {
		return 0, fmt.Errorf("bad")
	}
	return strconv.Atoi(strings.ReplaceAll(t, "_", ""))
}

func (st *parseState) take(a Arg, args []string) error {
	st.seen[a.Dest] = true
	switch {
	case a.isOption() && !a.takesValue():
		st.ns[a.Dest] = true
	case a.Action == "append":
		v, err := st.convert(a, args[0])
		if err != nil {
			return err
		}
		l, _ := st.ns[a.Dest].([]string)
		st.ns[a.Dest] = append(append([]string(nil), l...), v.(string))
	case a.Nargs == "..." || a.Nargs == "*":
		l := []string{}
		for _, x := range args {
			if _, err := st.convert(a, x); err != nil {
				return err
			}
			l = append(l, x)
		}
		if len(args) == 0 && a.Default != nil {
			st.ns[a.Dest] = a.Default
		} else {
			st.ns[a.Dest] = l
		}
	case a.Nargs == "?" && len(args) == 0:
		if s, ok := a.Default.(string); ok {
			v, err := st.convert(a, s)
			if err != nil {
				return err
			}
			st.ns[a.Dest] = v
		} else {
			st.ns[a.Dest] = a.Default
		}
	default:
		v, err := st.convert(a, args[0])
		if err != nil {
			return err
		}
		st.ns[a.Dest] = v
	}
	return nil
}

type pending struct {
	a    Arg
	args []string
}

func (st *parseState) consumeOptional(start int) (int, error) {
	t := st.opts[start]
	if t.arg == nil {
		st.extras = append(st.extras, st.args[start])
		return start + 1, nil
	}
	action, flag, explicit := *t.arg, t.flag, t.explicit
	var todo []pending
	stop := start + 1
	for {
		if explicit != nil {
			n, err := st.match(action, "A")
			if err != nil {
				return 0, err
			}
			switch {
			case n == 0 && flag[1] != '-' && t.sep == "" && *explicit != "":
				// a cluster such as -fn5: the flags go on in the rest of the word
				todo = append(todo, pending{action, nil})
				next := "-" + string([]rune(*explicit)[0])
				i, ok := st.s.byFlag[next]
				if !ok {
					st.extras = append(st.extras, next+string([]rune(*explicit)[1:]))
					goto done
				}
				action, flag = st.s.options[i], next
				rest := string([]rune(*explicit)[1:])
				if rest == "" {
					explicit = nil
				} else {
					explicit = &rest
				}
				continue
			case n == 1:
				stop = start + 1
				todo = append(todo, pending{action, []string{*explicit}})
				goto done
			}
			return 0, st.fail(fmt.Sprintf("argument %s: ignored explicit argument %s", strings.Join(action.Flags, "/"), pyRepr(*explicit)))
		}
		n, err := st.match(action, st.pattern[start+1:])
		if err != nil {
			return 0, err
		}
		stop = start + 1 + n
		todo = append(todo, pending{action, st.args[start+1 : stop]})
		break
	}
done:
	for _, p := range todo {
		if p.a.Action == "help" {
			return 0, &HelpRequest{Text: st.p.helpOf(st.s)}
		}
		if p.a.Action == "version" {
			return 0, &HelpRequest{Text: st.p.Prog + " " + st.p.Version + "\n"}
		}
		if err := st.take(p.a, p.args); err != nil {
			return 0, err
		}
	}
	return stop, nil
}

func (st *parseState) consumePositionals(start int) (int, error) {
	if len(st.pos) == 0 {
		return start, nil
	}
	rest := st.pattern[start:]
	var counts []int
	for i := len(st.pos); i > 0; i-- {
		var sb strings.Builder
		for _, a := range st.pos[:i] {
			sb.WriteString(nargsPattern(a))
		}
		if m := regexp.MustCompile("^" + sb.String()).FindStringSubmatch(rest); m != nil {
			for _, g := range m[1:] {
				counts = append(counts, len(g))
			}
			break
		}
	}
	taken := st.pos[:len(counts)]
	st.pos = st.pos[len(counts):]
	for i, n := range counts {
		a := taken[i]
		args := append([]string(nil), st.args[start:start+n]...)
		switch {
		case a.Nargs == "PARSER":
			if n > 0 && st.pattern[start] == '-' { // a leading "--" only separates
				args = args[1:]
			}
		case a.Nargs != "...":
			// the first "--" is only a separator, except inside "everything that is left"
			for j := 0; j < n; j++ {
				if st.pattern[start+j] == '-' {
					args = append(args[:j:j], args[j+1:]...)
					break
				}
			}
		}
		start += n
		if a.Nargs == "PARSER" {
			if err := st.takeCommand(a, args); err != nil {
				return 0, err
			}
			continue
		}
		if err := st.take(a, args); err != nil {
			return 0, err
		}
	}
	return start, nil
}

// takeCommand runs the sub-parser of the command named by args[0] on the rest.
func (st *parseState) takeCommand(a Arg, args []string) error {
	st.seen[a.Dest] = true
	cmd := st.p.command(args[0])
	if cmd == nil {
		return st.fail(fmt.Sprintf("argument %s: invalid choice: %s (choose from %s)", actionName(a), pyRepr(args[0]), reprAll(st.p.names())))
	}
	st.ns[a.Dest] = args[0]
	sub := st.p.commandScope(cmd)
	ns, extras, err := st.p.parseScope(sub, args[1:], nil)
	if err != nil {
		return err
	}
	for k, v := range ns {
		st.ns[k] = v
	}
	st.subExtras = append(st.subExtras, extras...)
	return nil
}

func (p *Parser) rootScope() *scope {
	sc := newScope(p.Prog, nil, Arg{Flags: []string{"--version"}, Dest: "version", Action: "version", Help: "show program's version number and exit"})
	sc.isRoot = true
	sc.positionals = []Arg{{Dest: "command", Nargs: "PARSER", Metavar: "<command>"}}
	return sc
}

func (p *Parser) commandScope(c *Command) *scope {
	return newScope(p.Prog+" "+c.Name, c.Args)
}

// parseScope is argparse's parse_known_args for one parser level.
func (p *Parser) parseScope(sc *scope, args []string, defaults Namespace) (Namespace, []string, error) {
	st := &parseState{p: p, s: sc, args: args, ns: Namespace{}, seen: map[string]bool{}, opts: map[int]*optionTuple{}}
	for _, o := range sc.options {
		switch {
		case o.Action == "help" || o.Action == "version":
		case o.Action == "store_true":
			st.ns[o.Dest] = false
		default:
			st.ns[o.Dest] = o.Default
		}
	}
	for _, a := range sc.positionals {
		if a.Nargs == "PARSER" {
			st.ns[a.Dest] = nil
			continue
		}
		st.ns[a.Dest] = a.Default
	}
	st.pos = append([]Arg(nil), sc.positionals...)
	var pat strings.Builder
	rest := false
	for i, a := range args {
		switch {
		case rest:
			pat.WriteByte('A')
		case a == "--":
			pat.WriteByte('-')
			rest = true
		default:
			t, err := st.parseOptional(a)
			if err != nil {
				return nil, nil, err
			}
			if t == nil {
				pat.WriteByte('A')
			} else {
				st.opts[i] = t
				pat.WriteByte('O')
			}
		}
	}
	st.pattern = pat.String()
	var optIdx []int
	for i := range args {
		if _, ok := st.opts[i]; ok {
			optIdx = append(optIdx, i)
		}
	}
	sort.Ints(optIdx)
	start := 0
	maxOpt := -1
	if len(optIdx) > 0 {
		maxOpt = optIdx[len(optIdx)-1]
	}
	for start <= maxOpt {
		next := -1
		for _, i := range optIdx {
			if i >= start {
				next = i
				break
			}
		}
		if start != next {
			end, err := st.consumePositionals(start)
			if err != nil {
				return nil, nil, err
			}
			if end > start { // the option string may already be consumed by what was just parsed
				start = end
				continue
			}
			start = end
		}
		var err error
		if _, isOpt := st.opts[start]; !isOpt {
			st.extras = append(st.extras, args[start:next]...)
			start = next
		}
		if start, err = st.consumeOptional(start); err != nil {
			return nil, nil, err
		}
	}
	stop, err := st.consumePositionals(start)
	if err != nil {
		return nil, nil, err
	}
	st.extras = append(st.extras, args[stop:]...)
	var missing []string
	for _, a := range sc.positionals {
		if sc.required(a) && !st.seen[a.Dest] {
			missing = append(missing, actionName(a))
		}
	}
	if len(missing) > 0 {
		return nil, nil, st.fail("the following arguments are required: " + strings.Join(missing, ", "))
	}
	return st.ns, append(st.extras, st.subExtras...), nil
}

// Parse parses the command line (without the program name). A *HelpRequest means print its text and exit 0; a
// *ParseError means print it to stderr and exit 2.
func (p *Parser) Parse(args []string) (Namespace, error) {
	ns, extras, err := p.parseScope(p.rootScope(), args, nil)
	if err != nil {
		return nil, err
	}
	if len(extras) > 0 {
		return nil, &ParseError{Usage: p.usageOf(p.rootScope()), Prog: p.Prog, Message: "unrecognized arguments: " + strings.Join(extras, " ")}
	}
	return ns, nil
}
