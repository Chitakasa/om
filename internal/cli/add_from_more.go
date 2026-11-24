package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Chitakasa/om/internal/scaffold"
	"github.com/Chitakasa/om/internal/wizard"
)

// customiseOther asks for the per-container choices of a service that is not the web page.
func (a *App) customiseOther(p *wizard.Prompter, s *importSpec) error {
	var others []string
	for _, svc := range s.services {
		if svc != s.main {
			others = append(others, svc)
		}
	}
	opts := make([]wizard.Option, len(others))
	for i, svc := range others {
		opts[i] = wizard.Option{Label: svc}
	}
	i, err := p.Choose("\nWhich service?", opts, 0)
	if err != nil {
		return err
	}
	svc := others[i]
	if s.others == nil {
		s.others = map[string]addAnswers{}
	}
	w := s.others[svc]
	w.kind = "web"
	args := scaffold.AddArgs{Name: svc}
	if err := a.addCustomise(p, &args, &w, false); err != nil {
		return err
	}
	s.others[svc] = w
	return nil
}

// plainSecrets lists settings in the compose file that look like passwords or tokens written in plain text.
func plainSecrets(cfg map[string]any, folder string) []string {
	var out []string
	for name, sv := range cfgServices(cfg) {
		env, _ := sv["environment"].(map[string]any)
		for k, v := range env {
			if val, _ := v.(string); val != "" && secretishRE.MatchString(k) && !strings.HasSuffix(k, "_FILE") {
				out = append(out, fmt.Sprintf("%s sets %s in plain text in the compose file (and in git, if you commit it). To keep it encrypted: om secrets set %s/%s, then read /run/secrets/%s (many images take %s_FILE).",
					name, k, folder, strings.ToLower(k), strings.ToLower(k), k))
			}
		}
	}
	sort.Strings(out)
	return out
}
