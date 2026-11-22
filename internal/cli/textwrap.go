package cli

import (
	"strings"
	"unicode"
)

// Wrap is Python's textwrap.wrap(text, width) with its defaults (words may be split after a hyphen, and a word longer
// than a line is broken). Lengths count characters, not bytes.
func Wrap(text string, width int) []string {
	chunks := splitChunks(text)
	// reverse, as the Python algorithm pops from the end
	for i, j := 0, len(chunks)-1; i < j; i, j = i+1, j-1 {
		chunks[i], chunks[j] = chunks[j], chunks[i]
	}
	var lines []string
	for len(chunks) > 0 {
		var cur []string
		curLen := 0
		if strings.TrimSpace(chunks[len(chunks)-1]) == "" && len(lines) > 0 {
			chunks = chunks[:len(chunks)-1] // drop whitespace at the start of a continuation line
		}
		for len(chunks) > 0 {
			l := runeLen(chunks[len(chunks)-1])
			if curLen+l <= width {
				cur = append(cur, chunks[len(chunks)-1])
				chunks = chunks[:len(chunks)-1]
				curLen += l
			} else {
				break
			}
		}
		if len(chunks) > 0 && runeLen(chunks[len(chunks)-1]) > width {
			chunks, cur, curLen = handleLongWord(chunks, cur, curLen, width)
		}
		if len(cur) > 0 && strings.TrimSpace(cur[len(cur)-1]) == "" {
			curLen -= runeLen(cur[len(cur)-1])
			cur = cur[:len(cur)-1]
		}
		if len(cur) > 0 {
			lines = append(lines, strings.Join(cur, ""))
		}
	}
	return lines
}

func runeLen(s string) int { return len([]rune(s)) }

func handleLongWord(chunks, cur []string, curLen, width int) ([]string, []string, int) {
	spaceLeft := width - curLen
	if width < 1 {
		spaceLeft = 1
	}
	chunk := []rune(chunks[len(chunks)-1])
	end := spaceLeft
	if len(chunk) > spaceLeft {
		if h := lastIndexRune(chunk[:spaceLeft], '-'); h > 0 {
			for _, c := range chunk[:h] {
				if c != '-' {
					end = h + 1
					break
				}
			}
		}
	}
	if end > len(chunk) {
		end = len(chunk)
	}
	cur = append(cur, string(chunk[:end]))
	chunks[len(chunks)-1] = string(chunk[end:])
	return chunks, cur, curLen + end
}

func lastIndexRune(r []rune, c rune) int {
	for i := len(r) - 1; i >= 0; i-- {
		if r[i] == c {
			return i
		}
	}
	return -1
}

func isWS(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\v' || r == '\f' || r == '\r'
}

func isWordChar(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' }

func isLetter(r rune) bool { return unicode.IsLetter(r) || r == '_' }

func isWordPunct(r rune) bool {
	return isWordChar(r) || strings.ContainsRune(`!"'&.,?`, r)
}

// splitChunks is TextWrapper._split: whitespace runs and words, a word being cut after a hyphen between letters (and
// around an em-dash written as --).
func splitChunks(text string) []string {
	t := []rune(text)
	var out []string
	i := 0
	for i < len(t) {
		if isWS(t[i]) {
			j := i
			for j < len(t) && isWS(t[j]) {
				j++
			}
			out = append(out, string(t[i:j]))
			i = j
			continue
		}
		// an em-dash between words
		if t[i] == '-' && i > 0 && isWordPunct(t[i-1]) {
			j := i
			for j < len(t) && t[j] == '-' {
				j++
			}
			if j-i >= 2 && j < len(t) && isWordChar(t[j]) {
				out = append(out, string(t[i:j]))
				i = j
				continue
			}
		}
		// a word: the shortest run followed by a place where it may end
		e := i + 1
		for ; e <= len(t); e++ {
			if e < len(t) && isWS(t[e]) || e == len(t) {
				break // end of word
			}
			if t[e] == '-' && e+1 < len(t) {
				// hyphenated word: letter letter - or letter - letter -, then letter [-] letter
				before2 := e >= 2 && isLetter(t[e-2]) && isLetter(t[e-1])
				before3 := e >= 3 && isLetter(t[e-3]) && t[e-2] == '-' && isLetter(t[e-1])
				if before2 || before3 {
					k := e + 1
					if k < len(t) && isLetter(t[k]) {
						k++
						if k < len(t) && t[k] == '-' {
							k++
						}
						if k < len(t) && isLetter(t[k]) {
							e++ // the hyphen belongs to this chunk
							break
						}
					}
				}
			}
			// an em-dash right after a word-punctuation character
			if isWordPunct(t[e-1]) && e < len(t) && t[e] == '-' {
				j := e
				for j < len(t) && t[j] == '-' {
					j++
				}
				if j-e >= 2 && j < len(t) && isWordChar(t[j]) {
					break
				}
			}
		}
		out = append(out, string(t[i:e]))
		i = e
	}
	return out
}
