// Package migration moves legacy state: installs from before the program/state split kept their state inside
// OM_HOME. Port of lib/gitops/migration.py.
package migration

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/state"
)

// Generated routes carry their workspace in the header; om's own routes are owned by 'core'.
var generatedRouteRE = regexp.MustCompile(`(?m)^# (?:Service|Public Subpath|Private Subpath): [a-z0-9-]+ \(([a-z0-9-]+)\)`)

type pair struct{ old, new string }

func readDirSorted(dir string) []os.DirEntry {
	es, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	return es
}

func isDir(p string) bool { st, err := os.Stat(p); return err == nil && st.IsDir() }

// legacyMoves returns the (old, new) pairs for state still sitting inside OM_HOME.
func legacyMoves(d state.Dirs) []pair {
	oldCore, oldCfg := d.Core, filepath.Join(d.Home, "config")
	pairs := []pair{
		{filepath.Join(oldCore, ".env"), d.UserEnv},
		{filepath.Join(oldCore, ".runtime.env"), d.RuntimeEnv},
		{filepath.Join(oldCore, "ports.generated.yml"), d.PortsFile},
		{filepath.Join(oldCore, "firewall"), d.Firewall},
		{filepath.Join(oldCfg, "workspaces.json"), d.Registry},
		{filepath.Join(d.Home, "logs"), d.Logs},
	}
	if oldData := filepath.Join(oldCore, "data"); isDir(oldData) {
		for _, e := range readDirSorted(oldData) {
			pairs = append(pairs, pair{filepath.Join(oldData, e.Name()), filepath.Join(d.Data, e.Name())})
		}
	}
	if oldAuth := filepath.Join(oldCore, "caddy", "auth.d"); isDir(oldAuth) {
		files, _ := filepath.Glob(filepath.Join(oldAuth, "*.conf"))
		sort.Strings(files)
		for _, p := range files {
			pairs = append(pairs, pair{p, filepath.Join(d.Auth, filepath.Base(p))})
		}
	}
	if isDir(d.CoreRoutes) {
		for _, e := range readDirSorted(d.CoreRoutes) {
			p := filepath.Join(d.CoreRoutes, e.Name())
			if st, err := os.Stat(p); err != nil || !st.Mode().IsRegular() {
				continue
			}
			b, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			head := []rune(py.UniversalNewlines(strings.ToValidUTF8(string(b), "�")))
			if len(head) > 400 {
				head = head[:400]
			}
			if m := generatedRouteRE.FindStringSubmatch(string(head)); m != nil && m[1] != "core" { // 'core' is reserved for om's own routes
				pairs = append(pairs, pair{p, filepath.Join(d.Routes, e.Name())})
			}
		}
	}
	var out []pair
	for _, pr := range pairs {
		if _, err := os.Lstat(pr.old); err == nil && !strings.HasSuffix(filepath.Base(pr.old), ".pre-migration") {
			out = append(out, pr)
		}
	}
	return out
}

// LegacyStatePresent reports state still inside OM_HOME.
func LegacyStatePresent(d state.Dirs) bool { return len(legacyMoves(d)) > 0 }

// move is shutil.move: a rename, or a copy and delete across file systems.
func move(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	if err := copyTree(src, dst); err != nil {
		return err
	}
	return os.RemoveAll(src)
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		info, err := de.Info()
		if err != nil {
			return err
		}
		switch {
		case de.IsDir():
			return os.MkdirAll(target, info.Mode().Perm())
		case info.Mode()&os.ModeSymlink != 0:
			l, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(l, target)
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	})
}

// MigrateLegacyState moves pre-split state out of OM_HOME. It is idempotent and never overwrites newer state. It
// returns human-readable lines describing what moved. Run with the core stopped: the edge bind-mounts several of
// these paths.
func MigrateLegacyState(d state.Dirs) ([]string, error) {
	var done []string
	for _, pr := range legacyMoves(d) {
		if _, err := os.Lstat(pr.new); err == nil {
			// Already migrated (or recreated since): keep the new one, park the old one.
			parked := pr.old + ".pre-migration"
			if _, err := os.Lstat(parked); err != nil {
				if err := os.Rename(pr.old, parked); err != nil {
					return done, err
				}
				done = append(done, fmt.Sprintf("kept %s (old copy left at %s)", pr.new, parked))
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(pr.new), 0o755); err != nil {
			return done, err
		}
		if err := move(pr.old, pr.new); err != nil {
			return done, err
		}
		done = append(done, pr.old+" → "+pr.new)
	}
	for _, dir := range []string{filepath.Join(d.Home, "config"), filepath.Join(d.Core, "data"), filepath.Join(d.Core, "caddy", "auth.d")} {
		for _, leftover := range []string{"workspaces.lock", ".keep"} {
			os.Remove(filepath.Join(dir, leftover))
		}
		os.Remove(dir) // fails (and is ignored) unless the folder is empty
	}
	return done, nil
}

// GeneratedRouteRE matches the header comment of a route file om generated; group 1 is the workspace.
func GeneratedRouteRE() *regexp.Regexp { return generatedRouteRE }
