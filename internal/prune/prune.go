// Package prune removes unused images (`om prune`): after each `om update` the old digest stays on disk. An image
// is removable when no container (running or stopped) uses it and no registered workspace's .om/lock.json pins it,
// so a stopped workspace keeps its images. Removal is a plain `rmi` (never forced). Port of lib/gitops/prune.py.
package prune

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/state"
)

var sizeRE = regexp.MustCompile(`^([0-9.]+)[\t\n\v\f\r \x{1c}-\x{1f}\x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}]*([kKMGT]?)i?B$`)

var units = map[string]float64{"": 1, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12}

// ParseSize turns '52.1 MB' / '52.1MB' / '980kB' into bytes (0 if unreadable).
func ParseSize(text string) int64 {
	m := sizeRE.FindStringSubmatch(py.Strip(text))
	if m == nil {
		return 0
	}
	f, err := strconv.ParseFloat(m[1], 64)
	if err != nil { // "1.2.3": Python's float() raises; no usable size here
		return 0
	}
	return int64(f * units[strings.ToUpper(m[2])])
}

func short(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	r := []rune(id)
	if len(r) > 12 {
		r = r[:12]
	}
	return string(r)
}

// Image is an image nothing uses.
type Image struct {
	ID    string
	Names []string
	Size  int64
}

// Pruner runs engine commands.
type Pruner struct{ Run func([]string) state.Result }

// New returns a Pruner for this machine.
func New() Pruner { return Pruner{Run: func(c []string) state.Result { return state.Run(c) }} }

// InUse returns the short ids of the images any container, running or not, was created from.
func (p Pruner) InUse(runtime string) map[string]bool {
	out := map[string]bool{}
	ids := strings.Fields(p.Run([]string{runtime, "ps", "-a", "-q"}).Stdout)
	if len(ids) == 0 {
		return out
	}
	r := p.Run(append([]string{runtime, "container", "inspect", "--format", "{{.Image}}"}, ids...))
	for _, i := range strings.Fields(r.Stdout) {
		out[short(i)] = true
	}
	return out
}

// Candidates lists the images nothing uses and no lock pins (locked is the set of pinned digests).
func (p Pruner) Candidates(runtime string, locked map[string]bool) []Image {
	r := p.Run([]string{runtime, "images", "-a", "--format", "{{.ID}}\t{{.Repository}}:{{.Tag}}\t{{.Size}}"})
	if r.Code != 0 {
		return nil
	}
	byID := map[string]*Image{}
	for _, line := range py.SplitLines(r.Stdout) {
		id, rest, _ := strings.Cut(line, "\t")
		name, size, _ := strings.Cut(rest, "\t")
		e, ok := byID[short(id)]
		if !ok {
			e = &Image{ID: short(id), Size: ParseSize(size)}
			byID[short(id)] = e
		}
		if !strings.Contains(name, "<none>") {
			e.Names = append(e.Names, name)
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	used := p.InUse(runtime)
	var out []Image
	for _, id := range ids {
		if used[id] {
			continue
		}
		info := p.Run([]string{runtime, "image", "inspect", "--format", "{{json .RepoDigests}}", id})
		text := info.Stdout
		if text == "" {
			text = "[]"
		}
		var repo []string
		pinned := false
		if json.Unmarshal([]byte(text), &repo) == nil {
			for _, d := range repo {
				if i := strings.LastIndex(d, "@"); i >= 0 {
					d = d[i+1:]
				}
				pinned = pinned || locked[d]
			}
		}
		if pinned {
			continue
		}
		out = append(out, *byID[id])
	}
	return out
}

// Remove runs rmi for every name of the image (or its id when it has none); false if the engine refuses any.
func (p Pruner) Remove(runtime string, e Image) bool {
	targets := e.Names
	if len(targets) == 0 {
		targets = []string{e.ID}
	}
	ok := true
	for _, t := range targets {
		if p.Run([]string{runtime, "rmi", t}).Code != 0 {
			return false // Python's all() stops at the first failure
		}
	}
	return ok
}
