package cli

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/Chitakasa/om/internal/runcmd"
	"github.com/Chitakasa/om/internal/scaffold"
	"github.com/Chitakasa/om/internal/workspace"
)

// cmdCheck reads a compose file (or a `docker run` command) the way `om add --from` would, in a scratch folder, and
// says what om would change and what the deploy gate would refuse. It writes nothing to any workspace.
func (a *App) cmdCheck(root string, ns Namespace) error {
	from := ns.Str("path")
	if run := ns.Str("run"); run != "" {
		svc, err := runcmd.Parse(run)
		if err != nil {
			return Die("--run: %s", err)
		}
		dir, err := os.MkdirTemp("", "om-run-")
		if err != nil {
			return Die("%s", err)
		}
		defer os.RemoveAll(dir)
		if err := os.WriteFile(filepath.Join(dir, "compose.yml"), []byte(svc.Compose()), 0o644); err != nil {
			return Die("%s", err)
		}
		from, ns["from_label"] = dir, "your "+strings.Fields(run)[0]+" run command"
	}
	if from == "" {
		return Die("Usage: om check <compose file or folder>   (or --run 'docker run ...')")
	}
	scratch, err := os.MkdirTemp("", "om-check-")
	if err != nil {
		return Die("%s", err)
	}
	defer os.RemoveAll(scratch)
	wsID := "ws"
	if root != "" {
		if id, err := workspace.WorkspaceID(root); err == nil {
			wsID = id
		}
	}
	was := a.Interactive
	a.Interactive = false
	defer func() { a.Interactive = was }()
	s, err := a.importCompose(scratch, wsID, Namespace{"yes": true, "from_label": ns.Str("from_label")}, scaffold.AddArgs{}, from)
	if err != nil {
		return Die("%s", err)
	}
	if len(s.problems) > 0 {
		a.p("Checked only: nothing was written. Fix the lines above, then `om add --from %s`.", from)
		return Exit(1)
	}
	a.p("Checked only: nothing was written. `om add --from %s` brings it in.", pick(ns.Str("from_label") != "", "<the same command>", from))
	return nil
}
