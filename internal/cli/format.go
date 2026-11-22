package cli

import (
	"regexp"
	"strings"
)

const maxHelpPosition = 24

func (p *Parser) width() int {
	w := 80
	if p.Width != nil {
		w = p.Width()
	} else {
		w = termCols()
	}
	return w - 2
}

func metavarOf(a Arg, def string) string {
	if a.Metavar != "" {
		return a.Metavar
	}
	if len(a.Choices) > 0 {
		return "{" + strings.Join(a.Choices, ",") + "}"
	}
	return def
}

func formatArgs(a Arg, def string) string {
	mv := metavarOf(a, def)
	switch a.Nargs {
	case "?":
		return "[" + mv + "]"
	case "*":
		return "[" + mv + " ...]"
	case "...":
		return "..."
	case "PARSER":
		return mv + " ..."
	}
	return mv
}

func usagePart(a Arg) string {
	if !a.isOption() {
		return formatArgs(a, a.Dest)
	}
	part := a.Flags[0]
	if a.takesValue() && a.Action != "help" && a.Action != "version" {
		part += " " + formatArgs(a, strings.ToUpper(a.Dest))
	}
	return "[" + part + "]"
}

func (sc *scope) usageText(optionals, positionals []Arg) (opt, pos string) {
	var o, p []string
	for _, a := range optionals {
		o = append(o, usagePart(a))
	}
	for _, a := range positionals {
		p = append(p, usagePart(a))
	}
	return strings.Join(o, " "), strings.Join(p, " ")
}

// splitParts is findall(r"\(.*?\)+(?=\s|$)|\[.*?\]+(?=\s|$)|\S+", text).
func splitParts(text string) []string {
	t := []rune(text)
	var out []string
	i := 0
	for i < len(t) {
		if t[i] == ' ' {
			i++
			continue
		}
		if t[i] == '[' || t[i] == '(' {
			closer := ']'
			if t[i] == '(' {
				closer = ')'
			}
			end := -1
			for j := i + 1; j < len(t); j++ {
				if t[j] == closer {
					k := j
					for k < len(t) && t[k] == closer {
						k++
					}
					if k == len(t) || t[k] == ' ' {
						end = k
						break
					}
				}
			}
			if end > 0 {
				out = append(out, string(t[i:end]))
				i = end
				continue
			}
		}
		j := i
		for j < len(t) && t[j] != ' ' {
			j++
		}
		out = append(out, string(t[i:j]))
		i = j
	}
	return out
}

func getLines(parts []string, indent string, prefix *string, textWidth int) []string {
	var lines, line []string
	indentLen := runeLen(indent)
	lineLen := indentLen - 1
	if prefix != nil {
		lineLen = runeLen(*prefix) - 1
	}
	for _, part := range parts {
		if lineLen+1+runeLen(part) > textWidth && len(line) > 0 {
			lines = append(lines, indent+strings.Join(line, " "))
			line = nil
			lineLen = indentLen - 1
		}
		line = append(line, part)
		lineLen += runeLen(part) + 1
	}
	if len(line) > 0 {
		lines = append(lines, indent+strings.Join(line, " "))
	}
	if prefix != nil && len(lines) > 0 {
		lines[0] = lines[0][len(indent):]
	}
	return lines
}

// usageOf is "usage: …\n", wrapped like argparse.
func (p *Parser) usageOf(sc *scope) string {
	prefix := "usage: "
	prog := sc.prog
	var optionals, positionals []Arg
	optionals = sc.options
	positionals = sc.positionals
	optUsage, posUsage := sc.usageText(optionals, positionals)
	all := strings.TrimSpace(optUsage + " " + posUsage)
	usage := prog
	if all != "" {
		usage += " " + all
	}
	textWidth := p.width()
	if textWidth < 11 {
		textWidth = 11
	}
	if runeLen(prefix)+runeLen(usage) > textWidth {
		optParts, posParts := splitParts(optUsage), splitParts(posUsage)
		var lines []string
		if float64(runeLen(prefix)+runeLen(prog)) <= 0.75*float64(textWidth) {
			indent := strings.Repeat(" ", runeLen(prefix)+runeLen(prog)+1)
			switch {
			case len(optParts) > 0:
				lines = getLines(append([]string{prog}, optParts...), indent, &prefix, textWidth)
				lines = append(lines, getLines(posParts, indent, nil, textWidth)...)
			case len(posParts) > 0:
				lines = getLines(append([]string{prog}, posParts...), indent, &prefix, textWidth)
			default:
				lines = []string{prog}
			}
		} else {
			indent := strings.Repeat(" ", runeLen(prefix))
			parts := append(append([]string{}, optParts...), posParts...)
			lines = getLines(parts, indent, nil, textWidth)
			if len(lines) > 1 {
				lines = getLines(optParts, indent, nil, textWidth)
				lines = append(lines, getLines(posParts, indent, nil, textWidth)...)
			}
			lines = append([]string{prog}, lines...)
		}
		usage = strings.Join(lines, "\n")
	}
	return prefix + usage + "\n"
}

var wsRun = regexp.MustCompile(`[ \t\n\v\f\r]+`)

func splitLines(text string, width int) []string {
	return Wrap(strings.TrimSpace(wsRun.ReplaceAllString(text, " ")), width)
}

func invocation(a Arg) string {
	if !a.isOption() {
		return metavarOf(a, a.Dest)
	}
	if !a.takesValue() || a.Action == "help" || a.Action == "version" {
		return strings.Join(a.Flags, ", ")
	}
	return strings.Join(a.Flags, ", ") + " " + formatArgs(a, strings.ToUpper(a.Dest))
}

// helpPosition is where the help text starts: shared by every section, from the longest invocation of all of them.
func helpPosition(groups ...[]Arg) int {
	maxLen := 0
	for _, args := range groups {
		for _, a := range args {
			if n := runeLen(invocation(a)) + 2; n > maxLen {
				maxLen = n
			}
		}
	}
	if maxLen+2 > maxHelpPosition {
		return maxHelpPosition
	}
	return maxLen + 2
}

func (p *Parser) section(title string, args []Arg, helpPos int) string {
	if len(args) == 0 {
		return ""
	}
	indent := 2
	helpWidth := p.width() - helpPos
	if helpWidth < 11 {
		helpWidth = 11
	}
	actionWidth := helpPos - indent - 2
	var b strings.Builder
	b.WriteString(title + ":\n")
	for _, a := range args {
		header := invocation(a)
		indentFirst := 0
		switch {
		case strings.TrimSpace(a.Help) == "":
			b.WriteString(strings.Repeat(" ", indent) + header + "\n")
			continue
		case runeLen(header) <= actionWidth:
			b.WriteString(strings.Repeat(" ", indent) + header + strings.Repeat(" ", actionWidth-runeLen(header)) + "  ")
		default:
			b.WriteString(strings.Repeat(" ", indent) + header + "\n")
			indentFirst = helpPos
		}
		lines := splitLines(strings.ReplaceAll(a.Help, "%%", "%"), helpWidth)
		b.WriteString(strings.Repeat(" ", indentFirst) + lines[0] + "\n")
		for _, l := range lines[1:] {
			b.WriteString(strings.Repeat(" ", helpPos) + l + "\n")
		}
	}
	return b.String()
}

// helpOf is the `-h` text of one parser level (a command; the top level has its own, rootHelp).
func (p *Parser) helpOf(sc *scope) string {
	if sc.isRoot {
		return p.rootHelp()
	}
	var cmd *Command
	for _, c := range p.Commands {
		if p.Prog+" "+c.Name == sc.prog {
			cmd = c
		}
	}
	var parts []string
	parts = append(parts, strings.TrimRight(p.usageOf(sc), "\n"))
	if cmd != nil && cmd.Description != "" {
		if cmd.RawDescription {
			parts = append(parts, strings.TrimRight(cmd.Description, "\n"))
		} else {
			parts = append(parts, strings.Join(Wrap(strings.TrimSpace(wsRun.ReplaceAllString(cmd.Description, " ")), maxInt(p.width(), 11)), "\n"))
		}
	}
	pos := helpPosition(sc.positionals, sc.options)
	if s := p.section("positional arguments", sc.positionals, pos); s != "" {
		parts = append(parts, strings.TrimRight(s, "\n"))
	}
	parts = append(parts, strings.TrimRight(p.section("options", sc.options, pos), "\n"))
	return strings.Join(parts, "\n\n") + "\n"
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// rootHelp is `om --help`: the commands in groups, the ones a newcomer needs first.
func (p *Parser) rootHelp() string {
	helps := map[string]string{}
	for _, c := range p.Commands {
		helps[c.Name] = c.Help
	}
	lines := []string{strings.TrimRight(p.usageOf(p.rootScope()), "\n"), "", p.Description}
	for _, g := range p.Groups {
		lines = append(lines, "", g.Title+":")
		for _, n := range g.Names {
			lines = append(lines, "  "+n+strings.Repeat(" ", maxInt(11-len(n), 0))+" "+helps[n])
		}
	}
	lines = append(lines, "", "Options:", "  -h, --help  show this help", "  --version   print the version",
		"", "New here? Run `om docs start`, or `om` inside a folder to see where things stand.",
		"Details of one command: om <command> --help")
	return strings.Join(lines, "\n") + "\n"
}

// Help returns the help text of a command ("" for the top level).
func (p *Parser) Help(command string) string {
	if command == "" {
		return p.rootHelp()
	}
	c := p.command(command)
	if c == nil {
		return ""
	}
	return p.helpOf(p.commandScope(c))
}
