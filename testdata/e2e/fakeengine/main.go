// Command fakeengine is a small stand-in for `podman` used by om's end-to-end tests: it keeps containers, networks and
// images in $FAKE_STATE/state.json, understands the commands om runs (ps, inspect, network, image, compose up/down/
// config/..., logs, exec, start/stop/...), logs every call to $FAKE_LOG and answers anything else with silence.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
)

type Container struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Image    string            `json:"image"`
	State    string            `json:"state"` // running | exited | created
	Labels   map[string]string `json:"labels"`
	Networks map[string]string `json:"networks"` // network -> address
	Health   bool              `json:"health"`
	Ports    string            `json:"ports"`
	Project  string            `json:"project"`
	Seq      int               `json:"seq"`
}

type Network struct {
	Name     string            `json:"name"`
	Internal bool              `json:"internal"`
	Labels   map[string]string `json:"labels"`
	Subnet   string            `json:"subnet"`
	Index    int               `json:"index"`
	Project  string            `json:"project"`
}

type State struct {
	Containers map[string]*Container `json:"containers"`
	Networks   map[string]*Network   `json:"networks"`
	Images     map[string]bool       `json:"images"`
	Seq        int                   `json:"seq"`
	NetSeq     int                   `json:"netseq"`
}

var (
	st        State
	statePath string
)

func load() {
	dir := os.Getenv("FAKE_STATE")
	if dir == "" {
		dir = os.TempDir()
	}
	os.MkdirAll(dir, 0o755)
	statePath = filepath.Join(dir, "state.json")
	st = State{Containers: map[string]*Container{}, Networks: map[string]*Network{}, Images: map[string]bool{}}
	if b, err := os.ReadFile(statePath); err == nil {
		json.Unmarshal(b, &st)
	}
	if st.Containers == nil {
		st.Containers = map[string]*Container{}
	}
	if st.Networks == nil {
		st.Networks = map[string]*Network{}
	}
	if st.Images == nil {
		st.Images = map[string]bool{}
	}
}

func save() {
	b, _ := json.MarshalIndent(st, "", " ")
	os.WriteFile(statePath, b, 0o644)
}

func logCall(args []string) {
	if p := os.Getenv("FAKE_LOG"); p != "" {
		f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			fmt.Fprintln(f, strings.ReplaceAll("podman "+strings.Join(args, " "), "\n", `\n`))
			f.Close()
		}
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	save()
	os.Exit(1)
}

func main() {
	if filepath.Base(os.Args[0]) == "ip" { // no network interfaces: nothing for om to detect on the machine running the test
		fmt.Println("[]")
		return
	}
	args := os.Args[1:]
	if len(args) == 2 && args[0] == "__serve" {
		serve(args[1])
	}
	logCall(args)
	if os.Getenv("FAKE_DOWN") != "" && len(args) > 0 && args[0] != "--version" && args[0] != "version" {
		fmt.Fprintln(os.Stderr, "Cannot connect to Podman: the engine is not running")
		os.Exit(125)
	}
	load()
	defer save()
	if len(args) == 0 {
		return
	}
	switch args[0] {
	case "--version", "version":
		fmt.Println("podman version 5.0.0")
	case "info":
		info(args[1:])
	case "compose":
		compose(args[1:])
	case "ps":
		ps(args[1:])
	case "inspect":
		inspect(args[1:])
	case "container":
		container(args[1:])
	case "network":
		network(args[1:])
	case "image":
		image(args[1:])
	case "images":
		images(args[1:])
	case "logs":
		name := args[len(args)-1]
		if _, ok := st.Containers[name]; !ok {
			fail("Error: no container with name or ID \"" + name + "\" found")
		}
		fmt.Println("log line from " + name)
	case "start", "stop", "restart", "kill", "rm":
		lifecycle(args[0], args[1:])
	case "build":
		for i, a := range args {
			if (a == "-t" || a == "--tag") && i+1 < len(args) {
				st.Images[args[i+1]] = true
			}
		}
	case "pull":
		st.Images[args[len(args)-1]] = true
	}
	// exec, run, volume, system, events, tag, ...: silence
}

func info(args []string) {
	for i, a := range args {
		if a == "--format" && i+1 < len(args) {
			if strings.Contains(args[i+1], "Rootless") {
				fmt.Println("true|/run/user/1000/podman/podman.sock|false")
			}
			return
		}
	}
	fmt.Println(`{"host":{"security":{"rootless":true},"remoteSocket":{"path":"/run/user/1000/podman/podman.sock"}}}`)
}

// ---- rendering ----

func render(format string, data any) string {
	t, err := template.New("f").Funcs(template.FuncMap{"json": func(v any) string { b, _ := json.Marshal(v); return string(b) }}).Parse(format)
	if err != nil {
		fail("template: " + err.Error())
	}
	var b bytes.Buffer
	if err := t.Execute(&b, data); err != nil {
		fail("template: " + err.Error())
	}
	return b.String()
}

func status(c *Container) string {
	switch c.State {
	case "running":
		s := "Up 5 seconds"
		if c.Health {
			s += " (healthy)"
		}
		return s
	case "exited":
		return "Exited (0) 2 seconds ago"
	}
	return "Created"
}

func digest(ref string) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(ref)))
}

func sortedContainers() []*Container {
	var out []*Container
	for _, c := range st.Containers {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out
}

func matchFilter(c *Container, f string) bool {
	k, v, _ := strings.Cut(f, "=")
	switch k {
	case "label":
		lk, lv, hasV := strings.Cut(v, "=")
		got, ok := c.Labels[lk]
		return ok && (!hasV || got == lv)
	case "network":
		_, ok := c.Networks[v]
		return ok
	case "name":
		return strings.Contains(c.Name, v)
	case "status":
		return c.State == v
	}
	return true
}

func ps(args []string) {
	all, format := false, "{{.ID}} {{.Names}}"
	var filters []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-a", "--all":
			all = true
		case "--filter", "-f":
			i++
			filters = append(filters, args[i])
		case "--format":
			i++
			format = args[i]
		}
	}
	for _, c := range sortedContainers() {
		if !all && c.State != "running" {
			continue
		}
		ok := true
		for _, f := range filters {
			ok = ok && matchFilter(c, f)
		}
		if !ok {
			continue
		}
		var nets []string
		for n := range c.Networks {
			nets = append(nets, n)
		}
		sort.Strings(nets)
		row := map[string]any{"ID": c.ID[:12], "Names": c.Name, "Image": c.Image, "Status": status(c), "State": c.State, "Ports": c.Ports,
			"Labels": c.Labels, "Networks": strings.Join(nets, ","), "Command": "\"run\"", "CreatedAt": "2026-01-01 00:00:00 +0000 UTC"}
		fmt.Println(render(format, row))
	}
}

func inspectObject(c *Container) map[string]any {
	nets := map[string]any{}
	for n, ip := range c.Networks {
		nets[n] = map[string]any{"IPAddress": ip, "Aliases": []string{c.Name}}
	}
	pid := 0
	if c.State == "running" {
		pid = 1
	}
	health := map[string]any{}
	if c.Health && c.State == "running" {
		health["Status"] = "healthy"
	}
	return map[string]any{"Id": c.ID, "Name": c.Name, "Created": "2026-01-01T00:00:00Z", "Image": digest(c.Image),
		"State":           map[string]any{"Running": c.State == "running", "Status": c.State, "Pid": pid, "ExitCode": 0, "Health": health},
		"Config":          map[string]any{"Labels": c.Labels, "Image": c.Image},
		"NetworkSettings": map[string]any{"Networks": nets}, "HostConfig": map[string]any{}, "Mounts": []any{}}
}

func inspect(args []string) {
	format := ""
	var names []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-f", "--format":
			i++
			format = args[i]
		default:
			if !strings.HasPrefix(args[i], "-") {
				names = append(names, args[i])
			}
		}
	}
	var objs []any
	for _, n := range names {
		c, ok := st.Containers[n]
		if !ok {
			fail("Error: no such object: \"" + n + "\"")
		}
		objs = append(objs, inspectObject(c))
	}
	if format != "" {
		for _, o := range objs {
			fmt.Println(render(format, o))
		}
		return
	}
	b, _ := json.MarshalIndent(objs, "", "  ")
	fmt.Println(string(b))
}

func container(args []string) {
	if len(args) > 0 && args[0] == "inspect" {
		inspect(args[1:])
		return
	}
	if len(args) > 0 && args[0] == "exists" {
		if _, ok := st.Containers[args[len(args)-1]]; !ok {
			os.Exit(1)
		}
	}
}

func lifecycle(cmd string, names []string) {
	var targets []string
	for _, n := range names {
		if !strings.HasPrefix(n, "-") && !isNumber(n) {
			targets = append(targets, n)
		}
	}
	for _, n := range targets {
		c, ok := st.Containers[n]
		if !ok {
			fail("Error: no container with name or ID \"" + n + "\" found")
		}
		switch cmd {
		case "start", "restart":
			c.State = "running"
		case "stop", "kill":
			c.State = "exited"
		case "rm":
			delete(st.Containers, n)
		}
		fmt.Println(n)
	}
}

func isNumber(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

func network(args []string) {
	if len(args) == 0 {
		return
	}
	switch args[0] {
	case "ls":
		var filters []string
		format := ""
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "--filter", "-f":
				i++
				filters = append(filters, args[i])
			case "--format":
				i++
				format = args[i]
			}
		}
		var names []string
		for n, nw := range st.Networks {
			ok := true
			for _, f := range filters {
				k, v, _ := strings.Cut(f, "=")
				if k == "label" {
					lk, lv, hasV := strings.Cut(v, "=")
					got, has := nw.Labels[lk]
					ok = ok && has && (!hasV || got == lv)
				}
			}
			if ok {
				names = append(names, n)
			}
		}
		sort.Strings(names)
		for _, n := range names {
			if format != "" {
				fmt.Println(render(format, map[string]any{"Name": n, "Internal": st.Networks[n].Internal}))
			} else {
				fmt.Println(n)
			}
		}
	case "create":
		nw := &Network{Labels: map[string]string{}}
		for i := 1; i < len(args); i++ {
			switch {
			case args[i] == "--internal":
				nw.Internal = true
			case args[i] == "--label":
				i++
				k, v, _ := strings.Cut(args[i], "=")
				nw.Labels[k] = v
			case !strings.HasPrefix(args[i], "-"):
				nw.Name = args[i]
			}
		}
		if _, dup := st.Networks[nw.Name]; dup {
			fail("Error: network name " + nw.Name + " already used")
		}
		addNetwork(nw)
		fmt.Println(nw.Name)
	case "inspect":
		format := ""
		var names []string
		for i := 1; i < len(args); i++ {
			if args[i] == "--format" || args[i] == "-f" {
				i++
				format = args[i]
			} else if !strings.HasPrefix(args[i], "-") {
				names = append(names, args[i])
			}
		}
		var objs []any
		for _, n := range names {
			nw, ok := st.Networks[n]
			if !ok {
				fail("Error: network not found: " + n)
			}
			objs = append(objs, map[string]any{"Name": nw.Name, "name": nw.Name, "Internal": nw.Internal, "internal": nw.Internal, "Labels": nw.Labels,
				"subnets": []any{map[string]any{"subnet": nw.Subnet, "gateway": strings.TrimSuffix(nw.Subnet, "0/24") + "1"}},
				"IPAM":    map[string]any{"Config": []any{map[string]any{"Subnet": nw.Subnet}}}})
		}
		if format != "" {
			for _, o := range objs {
				fmt.Println(render(format, o))
			}
			return
		}
		b, _ := json.MarshalIndent(objs, "", "  ")
		fmt.Println(string(b))
	case "connect", "disconnect":
		var pos []string
		for i := 1; i < len(args); i++ {
			if !strings.HasPrefix(args[i], "-") {
				pos = append(pos, args[i])
			}
		}
		if len(pos) < 2 {
			return
		}
		nw, ok := st.Networks[pos[0]]
		if !ok {
			fail("Error: network not found: " + pos[0])
		}
		c, ok := st.Containers[pos[1]]
		if !ok {
			fail("Error: no such container " + pos[1])
		}
		if args[0] == "connect" {
			c.Networks[pos[0]] = nextIP(nw)
		} else {
			delete(c.Networks, pos[0])
		}
	case "rm":
		for _, n := range args[1:] {
			if !strings.HasPrefix(n, "-") {
				delete(st.Networks, n)
			}
		}
	case "exists":
		if _, ok := st.Networks[args[len(args)-1]]; !ok {
			os.Exit(1)
		}
	}
}

func addNetwork(nw *Network) *Network {
	st.NetSeq++
	nw.Index = st.NetSeq
	nw.Subnet = fmt.Sprintf("10.89.%d.0/24", 10+st.NetSeq)
	if nw.Labels == nil {
		nw.Labels = map[string]string{}
	}
	st.Networks[nw.Name] = nw
	return nw
}

func nextIP(nw *Network) string {
	used := map[string]bool{}
	for _, c := range st.Containers {
		if ip, ok := c.Networks[nw.Name]; ok {
			used[ip] = true
		}
	}
	for i := 2; i < 250; i++ {
		ip := fmt.Sprintf("10.89.%d.%d", 10+nw.Index, i)
		if !used[ip] {
			return ip
		}
	}
	return "10.89.0.1"
}

func image(args []string) {
	if len(args) == 0 {
		return
	}
	switch args[0] {
	case "exists":
		if !st.Images[args[len(args)-1]] {
			os.Exit(1)
		}
	case "inspect":
		format := ""
		ref := args[len(args)-1]
		for i := 1; i < len(args); i++ {
			if args[i] == "--format" || args[i] == "-f" {
				i++
				format = args[i]
			}
		}
		if !st.Images[ref] {
			fail("Error: no such image: " + ref)
		}
		name := strings.SplitN(ref, "@", 2)[0]
		obj := map[string]any{"Id": digest(ref), "RepoDigests": []string{name + "@" + digest(name)}, "Os": "linux", "Architecture": "amd64", "Size": 1000000}
		if format != "" {
			fmt.Println(render(format, obj))
			return
		}
		b, _ := json.MarshalIndent([]any{obj}, "", "  ")
		fmt.Println(string(b))
	case "ls":
		images(args[1:])
	case "rm":
		for _, r := range args[1:] {
			delete(st.Images, r)
		}
	case "pull":
		st.Images[args[len(args)-1]] = true
	}
}

func images(args []string) {
	format := "{{.ID}}\t{{.Repository}}:{{.Tag}}\t{{.Size}}"
	for i := 0; i < len(args); i++ {
		if args[i] == "--format" {
			i++
			format = args[i]
		}
	}
	var refs []string
	for r := range st.Images {
		refs = append(refs, r)
	}
	sort.Strings(refs)
	for _, r := range refs {
		name, tag := r, "latest"
		if i := strings.LastIndex(strings.SplitN(r, "@", 2)[0], ":"); i > 0 && !strings.Contains(r[i:], "/") {
			name, tag = r[:i], strings.SplitN(r[i+1:], "@", 2)[0]
		}
		fmt.Println(render(format, map[string]any{"ID": digest(r)[7:19], "Repository": name, "Tag": tag, "Size": "10MB"}))
	}
}
