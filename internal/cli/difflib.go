package cli

// closeMatch is difflib.get_close_matches(word, possibilities, n=1) with the default cutoff 0.6 (the strings here
// are short, so SequenceMatcher's autojunk never applies).
func closeMatch(word string, possibilities []string) string {
	best, bestScore := "", 0.0
	for _, p := range possibilities {
		s := ratio([]rune(p), []rune(word))
		if s >= 0.6 && (s > bestScore || (s == bestScore && p > best)) {
			best, bestScore = p, s
		}
	}
	return best
}

func ratio(a, b []rune) float64 {
	if len(a)+len(b) == 0 {
		return 1
	}
	return 2 * float64(matching(a, b, 0, len(a), 0, len(b))) / float64(len(a)+len(b))
}

// matching sums the sizes of the matching blocks: longest block first (earliest in a, then in b), then both sides.
func matching(a, b []rune, alo, ahi, blo, bhi int) int {
	bi, bj, size := 0, 0, 0
	prev := map[int]int{}
	for i := alo; i < ahi; i++ {
		cur := map[int]int{}
		for j := blo; j < bhi; j++ {
			if a[i] != b[j] {
				continue
			}
			k := prev[j-1] + 1
			cur[j] = k
			if k > size {
				bi, bj, size = i-k+1, j-k+1, k
			}
		}
		prev = cur
	}
	if size == 0 {
		return 0
	}
	return size + matching(a, b, alo, bi, blo, bj) + matching(a, b, bi+size, ahi, bj+size, bhi)
}
