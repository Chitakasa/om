package cli

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/Chitakasa/om/internal/wizard"
)

// imageInfo is what an image says about itself: the ports it declares, the folders it keeps data in, its user and
// whether it brings its own health check.
type imageInfo struct {
	Ports   []int
	Volumes []string
	User    string
	Health  bool
}

// inspectImage reads an image's own metadata through the engine ("" and false when the engine has no such image).
func (a *App) inspectImage(rt, image string) (imageInfo, bool) {
	r := a.RunIn([]string{rt, "image", "inspect", "--format", "{{json .Config}}", image}, "", nil)
	if r.Code != 0 {
		return imageInfo{}, false
	}
	return parseImageConfig(r.Stdout)
}

func parseImageConfig(text string) (imageInfo, bool) {
	var cfg struct {
		ExposedPorts map[string]any `json:"ExposedPorts"`
		Volumes      map[string]any `json:"Volumes"`
		User         string         `json:"User"`
		Healthcheck  map[string]any `json:"Healthcheck"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(text)), &cfg) != nil {
		return imageInfo{}, false
	}
	info := imageInfo{User: cfg.User, Health: len(cfg.Healthcheck) > 0}
	for k := range cfg.ExposedPorts {
		num, proto, _ := strings.Cut(k, "/")
		if n, err := strconv.Atoi(num); err == nil && (proto == "" || proto == "tcp") {
			info.Ports = append(info.Ports, n)
		}
	}
	sort.Ints(info.Ports)
	for v := range cfg.Volumes {
		info.Volumes = append(info.Volumes, v)
	}
	sort.Strings(info.Volumes)
	return info, true
}

// imageHints looks inside the image (downloading it first, if the user agrees) so the questions can start from what
// the image declares. It returns false when there is nothing to go on.
func (a *App) imageHints(p *wizard.Prompter, image string) (imageInfo, bool, error) {
	rt := a.Runtime()
	if info, ok := a.inspectImage(rt, image); ok {
		return info, true, nil
	}
	yes, err := p.Confirm("Look inside "+image+" to suggest its port and data folders? (this downloads it, which `om start` would do anyway)", true)
	if err != nil || !yes {
		return imageInfo{}, false, err
	}
	a.p("  downloading %s ...", image)
	if r := a.RunIn([]string{rt, "pull", "-q", image}, "", nil); r.Code != 0 {
		a.p("  \033[33mCould not download it (%s); carrying on without suggestions.\033[0m", firstLine(strings.TrimSpace(r.Stderr)))
		return imageInfo{}, false, nil
	}
	info, ok := a.inspectImage(rt, image)
	return info, ok, nil
}
