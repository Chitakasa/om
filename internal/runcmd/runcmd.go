// Package runcmd turns a `docker run` / `podman run` command line into a compose file, so a container you started by
// hand can be brought into a workspace. Every option it knows becomes the compose key that does the same; an option
// it does not know is an error, never silently dropped, so the compose file always does what the command did.
package runcmd

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Service is what the command line describes.
type Service struct {
	Name     string // from --name, else the image's name
	Image    string
	Command  []string
	Keys     map[string][]string // compose key to its values, in order
	Scalars  map[string]string   // compose key to a one-value setting
	Volumes  []string            // named volumes to declare at the top
	Labels   []string            // key=value
	Health   map[string]string
	NoHealth bool
}

// Split breaks a command line into words the way a shell would: quotes, backslashes and line continuations.
func Split(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	in, started := byte(0), false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case in == '\'':
			if c == '\'' {
				in = 0
			} else {
				cur.WriteByte(c)
			}
		case in == '"':
			switch {
			case c == '"':
				in = 0
			case c == '\\' && i+1 < len(s) && strings.IndexByte("\"\\$`\n", s[i+1]) >= 0:
				i++
				if s[i] != '\n' {
					cur.WriteByte(s[i])
				}
			default:
				cur.WriteByte(c)
			}
		case c == '\'' || c == '"':
			in, started = c, true
		case c == '\\' && i+1 < len(s):
			i++
			if s[i] != '\n' {
				cur.WriteByte(s[i])
				started = true
			}
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			if cur.Len() > 0 || started {
				out = append(out, cur.String())
				cur.Reset()
				started = false
			}
		default:
			cur.WriteByte(c)
		}
	}
	if in != 0 {
		return nil, fmt.Errorf("an unclosed %c quote", in)
	}
	if cur.Len() > 0 || started {
		out = append(out, cur.String())
	}
	return out, nil
}

// flag kinds
const (
	boolean = iota // no value
	value          // one value
)

type spec struct {
	kind int
	key  string // the compose key, or a handler name starting with "@"
}

var options = map[string]spec{
	"-d": {boolean, ""}, "--detach": {boolean, ""}, "-i": {boolean, ""}, "--interactive": {boolean, ""}, "-t": {boolean, ""}, "--tty": {boolean, ""},
	"--rm": {boolean, ""}, "--sig-proxy": {boolean, ""}, "-q": {boolean, ""}, "--quiet": {boolean, ""},
	"--init": {boolean, "init"}, "--privileged": {boolean, "privileged"}, "--read-only": {boolean, "read_only"},
	"--no-healthcheck": {boolean, "@nohealth"},
	"-p":               {value, "ports"}, "--publish": {value, "ports"}, "-e": {value, "@env"}, "--env": {value, "@env"}, "--env-file": {value, "env_file"},
	"-v": {value, "@volume"}, "--volume": {value, "@volume"}, "--mount": {value, "@mount"}, "--name": {value, "@name"},
	"--restart": {value, "restart"}, "-u": {value, "user"}, "--user": {value, "user"}, "-w": {value, "working_dir"}, "--workdir": {value, "working_dir"},
	"-h": {value, "hostname"}, "--hostname": {value, "hostname"}, "--entrypoint": {value, "@entrypoint"},
	"--network": {value, "@network"}, "--net": {value, "@network"}, "-m": {value, "@mem"}, "--memory": {value, "@mem"}, "--cpus": {value, "@cpus"},
	"-l": {value, "@label"}, "--label": {value, "@label"}, "--cap-add": {value, "cap_add"}, "--cap-drop": {value, "cap_drop"},
	"--tmpfs": {value, "tmpfs"}, "--security-opt": {value, "security_opt"}, "--device": {value, "devices"}, "--add-host": {value, "extra_hosts"},
	"--dns": {value, "dns"}, "--shm-size": {value, "shm_size"}, "--pids-limit": {value, "pids_limit"}, "--stop-signal": {value, "stop_signal"},
	"--stop-timeout": {value, "@stoptimeout"}, "--platform": {value, "platform"}, "--pull": {value, "@pull"}, "--ulimit": {value, "@ulimit"},
	"--userns": {value, "userns_mode"}, "--pid": {value, "pid"}, "--ipc": {value, "ipc"}, "--group-add": {value, "group_add"},
	"--health-cmd": {value, "@healthcmd"}, "--health-interval": {value, "@health"}, "--health-timeout": {value, "@health"},
	"--health-retries": {value, "@health"}, "--health-start-period": {value, "@health"},
}

var nameRE = regexp.MustCompile(`[^a-z0-9]+`)

// Parse reads the command line; a leading "docker"/"podman" and "run" are optional.
func Parse(cmdline string) (*Service, error) {
	words, err := Split(cmdline)
	if err != nil {
		return nil, err
	}
	if len(words) > 0 && (words[0] == "docker" || words[0] == "podman" || words[0] == "sudo") {
		words = words[1:]
	}
	if len(words) > 0 && words[0] == "container" {
		words = words[1:]
	}
	if len(words) == 0 || words[0] != "run" {
		return nil, fmt.Errorf("this is not a `docker run` or `podman run` command")
	}
	words = words[1:]
	s := &Service{Keys: map[string][]string{}, Scalars: map[string]string{}, Health: map[string]string{}}
	for i := 0; i < len(words); i++ {
		w := words[i]
		if !strings.HasPrefix(w, "-") || w == "-" {
			s.Image = w
			s.Command = words[i+1:]
			break
		}
		name, val, hasVal := w, "", false
		if strings.HasPrefix(w, "--") {
			if k, v, ok := strings.Cut(w, "="); ok {
				name, val, hasVal = k, v, true
			}
		} else if len(w) > 2 && w[1] != '-' { // -itd, -p8080:80
			if sp, ok := options[w[:2]]; ok && sp.kind == value {
				name, val, hasVal = w[:2], w[2:], true
			} else { // a group of booleans
				for _, ch := range w[1:] {
					if sp, ok := options["-"+string(ch)]; !ok || sp.kind != boolean {
						return nil, fmt.Errorf("option %s is not one om can translate", w)
					}
				}
				continue
			}
		}
		if name == "-P" || name == "--publish-all" {
			return nil, fmt.Errorf("%s publishes every port the image declares; use -p with the ports you want", name)
		}
		sp, ok := options[name]
		if !ok {
			return nil, fmt.Errorf("option %s has no compose equivalent om knows, so the command cannot be translated faithfully; add it to the compose file after importing, or remove it", name)
		}
		if sp.kind == value && !hasVal {
			if i+1 >= len(words) {
				return nil, fmt.Errorf("option %s needs a value", name)
			}
			i++
			val = words[i]
		}
		if err := s.apply(name, sp, val); err != nil {
			return nil, err
		}
	}
	if s.Image == "" {
		return nil, fmt.Errorf("no image in the command")
	}
	if s.Name == "" {
		base := s.Image
		if j := strings.LastIndexByte(base, '/'); j >= 0 {
			base = base[j+1:]
		}
		if j := strings.IndexAny(base, ":@"); j >= 0 {
			base = base[:j]
		}
		s.Name = strings.Trim(nameRE.ReplaceAllString(strings.ToLower(base), "-"), "-")
	}
	return s, nil
}

func (s *Service) apply(flag string, sp spec, val string) error {
	switch sp.key {
	case "":
		return nil
	case "@name":
		s.Name = strings.Trim(nameRE.ReplaceAllString(strings.ToLower(val), "-"), "-")
	case "@env":
		if val == "" {
			return fmt.Errorf("%s needs KEY or KEY=value", flag)
		}
		s.Keys["environment"] = append(s.Keys["environment"], val)
	case "@volume":
		parts := strings.Split(val, ":")
		if len(parts) < 2 {
			return fmt.Errorf("%s %s: an anonymous volume has no name to keep it by; give it one (name:%s)", flag, val, val)
		}
		if src := parts[0]; !strings.ContainsAny(src[:1], "/.~") {
			s.Volumes = append(s.Volumes, src)
		}
		s.Keys["volumes"] = append(s.Keys["volumes"], val)
	case "@mount":
		v, err := mountToVolume(val)
		if err != nil {
			return err
		}
		if src, _, _ := strings.Cut(v, ":"); !strings.ContainsAny(src[:1], "/.~") {
			s.Volumes = append(s.Volumes, src)
		}
		s.Keys["volumes"] = append(s.Keys["volumes"], v)
	case "@entrypoint":
		ws, err := Split(val)
		if err != nil {
			return err
		}
		s.Keys["entrypoint"] = ws
	case "@network":
		switch val {
		case "bridge", "default", "":
		case "host", "none":
			s.Scalars["network_mode"] = val
		default:
			return fmt.Errorf("%s %s: om manages the networks (one per folder); remove this option", flag, val)
		}
	case "@mem":
		s.Labels = append(s.Labels, "om.mem="+strings.ToLower(val))
	case "@cpus":
		s.Labels = append(s.Labels, "om.cpus="+val)
	case "@label":
		if !strings.Contains(val, "=") {
			val += "="
		}
		s.Labels = append(s.Labels, val)
	case "@stoptimeout":
		s.Scalars["stop_grace_period"] = val + "s"
	case "@pull":
		m := map[string]string{"always": "always", "missing": "missing", "never": "never", "newer": "always"}
		if m[val] == "" {
			return fmt.Errorf("--pull %s is not one of always, missing, never", val)
		}
		s.Scalars["pull_policy"] = m[val]
	case "@ulimit":
		s.Keys["@ulimit"] = append(s.Keys["@ulimit"], val)
	case "@nohealth":
		s.NoHealth = true
	case "@healthcmd":
		s.Health["test"] = val
	case "@health":
		s.Health[strings.TrimPrefix(flag, "--health-")] = val
	case "ports", "env_file", "cap_add", "cap_drop", "tmpfs", "security_opt", "devices", "extra_hosts", "dns", "group_add":
		s.Keys[sp.key] = append(s.Keys[sp.key], val)
	default:
		if sp.kind == boolean {
			s.Scalars[sp.key] = "true"
		} else {
			s.Scalars[sp.key] = val
		}
	}
	return nil
}

func mountToVolume(spec string) (string, error) {
	kv := map[string]string{}
	ro := false
	for _, p := range strings.Split(spec, ",") {
		k, v, _ := strings.Cut(p, "=")
		switch k {
		case "readonly", "ro":
			ro = v == "" || v == "true" || v == "1"
		default:
			kv[k] = v
		}
	}
	src, dst := firstOf(kv, "src", "source"), firstOf(kv, "dst", "destination", "target")
	if kv["type"] == "tmpfs" || src == "" || dst == "" {
		return "", fmt.Errorf("--mount %s: only type=bind and type=volume with src and dst are translated; write it as -v src:dst", spec)
	}
	for k := range kv {
		switch k {
		case "type", "src", "source", "dst", "destination", "target":
		default:
			return "", fmt.Errorf("--mount %s: the option %s is not translated; write it as -v src:dst", spec, k)
		}
	}
	out := src + ":" + dst
	if ro {
		out += ":ro"
	}
	return out, nil
}

func firstOf(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if m[k] != "" {
			return m[k]
		}
	}
	return ""
}

func q(s string) string {
	b, _ := json.Marshal(strings.ReplaceAll(s, "$", "$$"))
	return strings.ReplaceAll(string(b), `\u0026`, "&")
}

func list(key string, vals []string) string {
	out := "    " + key + ":\n"
	for _, v := range vals {
		out += "      - " + q(v) + "\n"
	}
	return out
}

// Compose writes the service as a compose file. ports: is kept as written; `om add --from` turns it into expose.
func (s *Service) Compose() string {
	var b strings.Builder
	b.WriteString("services:\n  " + s.Name + ":\n    image: " + q(s.Image) + "\n")
	if len(s.Keys["entrypoint"]) > 0 {
		b.WriteString(list("entrypoint", s.Keys["entrypoint"]))
	}
	if len(s.Command) > 0 {
		b.WriteString(list("command", s.Command))
	}
	order := []string{"restart", "user", "working_dir", "hostname", "network_mode", "init", "privileged", "read_only", "stop_signal", "stop_grace_period",
		"pull_policy", "platform", "shm_size", "pids_limit", "userns_mode", "pid", "ipc"}
	for _, k := range order {
		if v, ok := s.Scalars[k]; ok {
			if v == "true" || v == "false" || isNumber(v) {
				b.WriteString("    " + k + ": " + v + "\n")
			} else {
				b.WriteString("    " + k + ": " + q(v) + "\n")
			}
		}
	}
	for _, k := range []string{"environment", "env_file", "ports", "volumes", "tmpfs", "cap_add", "cap_drop", "security_opt", "devices", "extra_hosts", "dns", "group_add"} {
		if len(s.Keys[k]) > 0 {
			b.WriteString(list(k, s.Keys[k]))
		}
	}
	if ul := s.Keys["@ulimit"]; len(ul) > 0 {
		b.WriteString("    ulimits:\n")
		for _, u := range ul {
			name, rest, _ := strings.Cut(u, "=")
			soft, hard, two := strings.Cut(rest, ":")
			if two {
				b.WriteString("      " + name + ":\n        soft: " + soft + "\n        hard: " + hard + "\n")
			} else {
				b.WriteString("      " + name + ": " + rest + "\n")
			}
		}
	}
	if len(s.Labels) > 0 {
		b.WriteString(list("labels", s.Labels))
	}
	switch {
	case s.NoHealth:
		b.WriteString("    healthcheck:\n      disable: true\n")
	case len(s.Health) > 0:
		b.WriteString("    healthcheck:\n")
		if t := s.Health["test"]; t != "" {
			b.WriteString("      test: [\"CMD-SHELL\", " + q(t) + "]\n")
		}
		for _, k := range []string{"interval", "timeout", "retries", "start-period"} {
			if v := s.Health[k]; v != "" {
				key := strings.ReplaceAll(k, "-", "_")
				if isNumber(v) {
					b.WriteString("      " + key + ": " + v + "\n")
				} else {
					b.WriteString("      " + key + ": " + v + "\n")
				}
			}
		}
	}
	if len(s.Volumes) > 0 {
		seen := map[string]bool{}
		b.WriteString("\nvolumes:\n")
		for _, v := range s.Volumes {
			if !seen[v] {
				seen[v] = true
				b.WriteString("  " + v + ":\n")
			}
		}
	}
	return b.String()
}

func isNumber(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
