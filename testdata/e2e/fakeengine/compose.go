package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type composeArgs struct {
	files      []string
	envFile    string
	project    string
	projectDir string
	cmd        string
	rest       []string
}

func parseCompose(args []string) composeArgs {
	var ca composeArgs
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		switch a {
		case "-f", "--file":
			i++
			ca.files = append(ca.files, args[i])
		case "--env-file":
			i++
			ca.envFile = args[i]
		case "-p", "--project-name":
			i++
			ca.project = args[i]
		case "--project-directory":
			i++
			ca.projectDir = args[i]
		case "--profile", "--ansi", "--progress", "--parallel":
			i++
		default:
			if strings.HasPrefix(a, "-") {
				continue
			}
			ca.cmd, ca.rest = a, args[i+1:]
			return ca
		}
	}
	return ca
}

func readEnvFile(path string) map[string]string {
	env := map[string]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		return env
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if k, v, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(line, "#") {
			env[k] = strings.Trim(v, "\"'")
		}
	}
	return env
}

var varRE = regexp.MustCompile(`\$\$|\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-?+])([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

func interpolate(text string, env map[string]string) (string, string) {
	problem := ""
	out := varRE.ReplaceAllStringFunc(text, func(m string) string {
		if m == "$$" {
			return "$"
		}
		sub := varRE.FindStringSubmatch(m)
		name, op, arg := sub[1], sub[2], sub[3]
		if name == "" {
			name = sub[4]
		}
		val, set := env[name]
		if !set {
			val, set = os.LookupEnv(name)
		}
		switch op {
		case ":-":
			if val == "" {
				return arg
			}
		case "-":
			if !set {
				return arg
			}
		case ":?", "?":
			if val == "" && (op == ":?" || !set) {
				problem = fmt.Sprintf("required variable %s is missing a value: %s", name, arg)
			}
		}
		return val
	})
	return out, problem
}

func deepMerge(a, b any) any {
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if aok && bok {
		out := map[string]any{}
		for k, v := range am {
			out[k] = v
		}
		for k, v := range bm {
			if old, ok := out[k]; ok {
				out[k] = deepMerge(old, v)
			} else {
				out[k] = v
			}
		}
		return out
	}
	al, aok := a.([]any)
	bl, bok := b.([]any)
	if aok && bok {
		return append(append([]any{}, al...), bl...)
	}
	return b
}

func asMap(v any) map[string]any { m, _ := v.(map[string]any); return m }

// loadConfig merges the compose files and normalizes them like `compose config --format json`.
func loadConfig(ca composeArgs) (map[string]any, string, bool) {
	env := map[string]string{}
	if ca.envFile != "" {
		env = readEnvFile(ca.envFile)
	}
	merged := any(map[string]any{})
	first := ""
	for _, f := range ca.files {
		b, err := os.ReadFile(f)
		if err != nil {
			fail("open " + f + ": no such file or directory")
		}
		if first == "" {
			first = f
		}
		text, problem := interpolate(string(b), env)
		if problem != "" {
			fail(problem)
		}
		merged = deepMerge(merged, parseYAML(text))
	}
	cfg := asMap(merged)
	project := ca.project
	if project == "" {
		project = os.Getenv("COMPOSE_PROJECT_NAME")
	}
	if project == "" && first != "" {
		project = strings.ToLower(filepath.Base(filepath.Dir(first)))
	}
	cfg["name"] = project
	nets := asMap(cfg["networks"])
	if nets == nil {
		nets = map[string]any{}
	}
	services := asMap(cfg["services"])
	if services == nil {
		services = map[string]any{}
	}
	usesDefault := false
	for name, raw := range services {
		svc := asMap(raw)
		if svc == nil {
			svc = map[string]any{}
		}
		if l, ok := svc["labels"].([]any); ok {
			m := map[string]any{}
			for _, e := range l {
				k, v, _ := strings.Cut(fmt.Sprint(e), "=")
				m[k] = v
			}
			svc["labels"] = m
		}
		if l, ok := svc["environment"].([]any); ok {
			m := map[string]any{}
			for _, e := range l {
				k, v, _ := strings.Cut(fmt.Sprint(e), "=")
				m[k] = v
			}
			svc["environment"] = m
		}
		if l, ok := svc["expose"].([]any); ok {
			for i, e := range l {
				l[i] = fmt.Sprint(e)
			}
		}
		switch n := svc["networks"].(type) {
		case []any:
			m := map[string]any{}
			for _, e := range n {
				m[fmt.Sprint(e)] = nil
			}
			svc["networks"] = m
		case nil:
			if svc["network_mode"] == nil {
				svc["networks"] = map[string]any{"default": nil}
			}
		}
		for n := range asMap(svc["networks"]) {
			if n == "default" {
				usesDefault = true
			}
		}
		svc["image"] = fmt.Sprint(orStr(svc["image"], project+"-"+name))
		services[name] = svc
	}
	if _, ok := nets["default"]; !ok && usesDefault {
		nets["default"] = map[string]any{}
	}
	for k, v := range nets {
		nm := asMap(v)
		if nm == nil {
			nm = map[string]any{}
		}
		if nm["name"] == nil {
			nm["name"] = project + "_" + k
		}
		nets[k] = nm
	}
	cfg["services"], cfg["networks"] = services, nets
	if len(nets) == 0 {
		delete(cfg, "networks")
	}
	return cfg, project, true
}

func orStr(v any, d string) any {
	if v == nil {
		return d
	}
	return v
}

func compose(args []string) {
	ca := parseCompose(args)
	switch ca.cmd {
	case "version":
		fmt.Println("Docker Compose version v2.29.0")
		return
	case "":
		return
	}
	if len(ca.files) == 0 {
		return
	}
	core := false
	for _, f := range ca.files {
		if b, err := os.ReadFile(f); err == nil && strings.Contains(string(b), "x-hardened:") {
			core = true
		}
	}
	if core {
		composeCore(ca)
		return
	}
	cfg, project, _ := loadConfig(ca)
	switch ca.cmd {
	case "config":
		b, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Println(string(b))
	case "up":
		composeUp(ca, cfg, project)
	case "down":
		for _, c := range sortedContainers() {
			if c.Project == project {
				delete(st.Containers, c.Name)
			}
		}
		for n, nw := range st.Networks {
			if nw.Project == project {
				delete(st.Networks, n)
			}
		}
	case "stop", "start", "restart":
		only := serviceArgs(ca.rest)
		for _, c := range sortedContainers() {
			if c.Project != project || (len(only) > 0 && !only[c.Labels["com.docker.compose.service"]]) {
				continue
			}
			if ca.cmd == "stop" {
				c.State = "exited"
			} else {
				c.State = "running"
			}
		}
	case "logs":
		for _, c := range sortedContainers() {
			if c.Project == project {
				fmt.Printf("%s  | log line\n", c.Name)
			}
		}
	case "ps":
		for _, c := range sortedContainers() {
			if c.Project == project {
				fmt.Println(c.Name)
			}
		}
	case "pull", "build":
		for _, raw := range asMap(cfg["services"]) {
			st.Images[fmt.Sprint(asMap(raw)["image"])] = true
		}
	}
}

func serviceArgs(rest []string) map[string]bool {
	out := map[string]bool{}
	for _, a := range rest {
		if !strings.HasPrefix(a, "-") && !isNumber(a) {
			out[a] = true
		}
	}
	return out
}

func composeUp(ca composeArgs, cfg map[string]any, project string) {
	only := serviceArgs(ca.rest)
	force := false
	for _, a := range ca.rest {
		force = force || a == "--force-recreate"
	}
	netByKey := map[string]string{}
	for k, v := range asMap(cfg["networks"]) {
		nm := asMap(v)
		real := fmt.Sprint(nm["name"])
		netByKey[k] = real
		if _, ok := st.Networks[real]; ok {
			continue
		}
		if nm["external"] == true {
			fail(fmt.Sprintf("network %s declared as external, but could not be found", real))
		}
		addNetwork(&Network{Name: real, Internal: nm["internal"] == true, Project: project,
			Labels: map[string]string{"com.docker.compose.project": project}})
	}
	dir := ""
	if len(ca.files) > 0 {
		dir, _ = filepath.Abs(filepath.Dir(ca.files[0]))
	}
	var names []string
	for n := range asMap(cfg["services"]) {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		if len(only) > 0 && !only[name] {
			continue
		}
		svc := asMap(asMap(cfg["services"])[name])
		cname := fmt.Sprint(orStr(svc["container_name"], project+"-"+name+"-1"))
		old, exists := st.Containers[cname]
		if exists && !force {
			old.State = "running"
			continue
		}
		st.Seq++
		labels := map[string]string{"com.docker.compose.project": project, "com.docker.compose.service": name,
			"com.docker.compose.project.working_dir": dir}
		for k, v := range asMap(svc["labels"]) {
			labels[k] = fmt.Sprint(v)
		}
		c := &Container{ID: fmt.Sprintf("%064x", st.Seq*7919), Name: cname, Image: fmt.Sprint(svc["image"]), State: "running", Labels: labels,
			Networks: map[string]string{}, Health: svc["healthcheck"] != nil, Project: project, Seq: st.Seq}
		if exists {
			c.Seq = old.Seq
		}
		for k, v := range asMap(svc["networks"]) {
			real := netByKey[k]
			if real == "" {
				real = k
			}
			nw, ok := st.Networks[real]
			if !ok {
				fail(fmt.Sprintf("network %s not found", real))
			}
			ip := nextIP(nw)
			if m := asMap(v); m != nil && m["ipv4_address"] != nil {
				ip = fmt.Sprint(m["ipv4_address"])
			}
			c.Networks[real] = ip
		}
		st.Images[c.Image] = true
		st.Containers[cname] = c
	}
}

var (
	svcLineRE  = regexp.MustCompile(`^  ([A-Za-z][A-Za-z0-9_-]*):\s*$`)
	itemRE     = regexp.MustCompile(`^\s+-\s*"?([^"]*)"?\s*$`)
	topNetRE   = regexp.MustCompile(`^  (om_[a-z_]+):`)
	healthRE   = regexp.MustCompile(`^    healthcheck:`)
	containerR = regexp.MustCompile(`^    container_name:\s*(\S+)`)
	imageRE    = regexp.MustCompile(`^    image:\s*(\S+)`)
)

// composeCore handles om's own core compose file, which uses anchors and merge keys: services are read line by line.
func composeCore(ca composeArgs) {
	if ca.cmd != "up" && ca.cmd != "down" && ca.cmd != "stop" && ca.cmd != "start" && ca.cmd != "restart" {
		return
	}
	type svc struct {
		name, container, image string
		labels                 map[string]string
		nets                   []string
		health                 bool
	}
	var svcs []*svc
	for _, f := range ca.files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var cur *svc
		section, sub := "", ""
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "services:") {
				section = "services"
				continue
			}
			if line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "#") {
				section = strings.TrimSuffix(strings.Fields(line)[0], ":")
			}
			if section != "services" {
				continue
			}
			if m := svcLineRE.FindStringSubmatch(line); m != nil {
				cur = &svc{name: m[1], container: "", labels: map[string]string{}}
				svcs = append(svcs, cur)
				sub = ""
				continue
			}
			if cur == nil {
				continue
			}
			if m := containerR.FindStringSubmatch(line); m != nil {
				cur.container = m[1]
			}
			if m := imageRE.FindStringSubmatch(line); m != nil {
				cur.image = m[1]
			}
			if healthRE.MatchString(line) {
				cur.health = true
			}
			if t := strings.TrimSpace(line); strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "     ") && strings.HasSuffix(t, ":") {
				sub = strings.TrimSuffix(t, ":")
			}
			if m := itemRE.FindStringSubmatch(line); m != nil && strings.HasPrefix(line, "      ") {
				switch sub {
				case "labels":
					k, v, _ := strings.Cut(m[1], "=")
					cur.labels[k] = v
				case "networks":
					cur.nets = append(cur.nets, m[1])
				}
			}
		}
	}
	for _, s := range svcs {
		if s.container == "" {
			continue
		}
		switch ca.cmd {
		case "down":
			delete(st.Containers, s.container)
		case "stop":
			if c, ok := st.Containers[s.container]; ok {
				c.State = "exited"
			}
		case "start", "restart":
			if c, ok := st.Containers[s.container]; ok {
				c.State = "running"
			}
		case "up":
			force := false
			for _, a := range ca.rest {
				force = force || a == "--force-recreate"
			}
			if old, ok := st.Containers[s.container]; ok && !force {
				old.State = "running"
				continue
			}
			st.Seq++
			c := &Container{ID: fmt.Sprintf("%064x", st.Seq*7919), Name: s.container, Image: s.image, State: "running", Labels: s.labels,
				Networks: map[string]string{}, Health: s.health, Project: "om_core", Seq: st.Seq}
			c.Labels["com.docker.compose.project"] = "om_core"
			c.Labels["com.docker.compose.service"] = s.name
			for _, n := range append(s.nets, "om_core_net") {
				nw, ok := st.Networks[n]
				if !ok {
					nw = addNetwork(&Network{Name: n, Project: "om_core"})
				}
				c.Networks[n] = nextIP(nw)
				break
			}
			st.Images[c.Image] = true
			st.Containers[s.container] = c
		}
	}
}
