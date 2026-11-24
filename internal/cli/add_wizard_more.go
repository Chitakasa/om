package cli

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Chitakasa/om/internal/scaffold"
	"github.com/Chitakasa/om/internal/wizard"
)

var (
	absPathRE   = regexp.MustCompile(`^/[A-Za-z0-9_./-]*$`)
	secretishRE = regexp.MustCompile(`(?i)(^|_)(PASS(WORD)?|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|KEY|CREDENTIALS?)($|_)`)
)

func volumeName(service string, taken []string) string {
	base := strings.ReplaceAll(strings.ToLower(service), " ", "-") + "-data"
	name := base
	for n := 2; ; n++ {
		clash := false
		for _, v := range taken {
			clash = clash || strings.HasPrefix(v, name+":")
		}
		if !clash {
			return name
		}
		name = base + strconv.Itoa(n)
	}
}

// addData asks for the folders the service keeps data in; each is a named volume the engine manages, so rootless
// permissions never get in the way and the data survives updates.
func (a *App) addData(p *wizard.Prompter, args *scaffold.AddArgs) error {
	for {
		a.p("\n  Data it keeps: %s", pick(len(args.Volumes) == 0, "nothing yet", strings.Join(args.Volumes, ", ")))
		opts := []wizard.Option{{Label: "Add a folder", Hint: "a path inside the container, kept in a managed volume"}, {Label: "Done"}}
		if len(args.Volumes) > 0 {
			opts = []wizard.Option{opts[0], {Label: "Remove them all"}, opts[1]}
		}
		i, err := p.Choose("Data", opts, len(opts)-1)
		if err != nil {
			return err
		}
		switch {
		case i == len(opts)-1:
			return nil
		case len(opts) == 3 && i == 1:
			args.Volumes = nil
		default:
			path, err := p.Ask("Folder inside the container (for example /var/lib/app)", "", func(s string) string {
				if !absPathRE.MatchString(s) || s == "/" {
					return "Type an absolute path such as /data."
				}
				return ""
			})
			if err != nil {
				return err
			}
			args.Volumes = append(args.Volumes, volumeName(args.Name, args.Volumes)+":"+path)
		}
	}
}

// addSettings asks for environment variables and secrets. A value that looks like a password goes to a secret, not
// into the compose file in plain text.
func (a *App) addSettings(p *wizard.Prompter, args *scaffold.AddArgs) error {
	for {
		var have []string
		for _, kv := range args.Env {
			have = append(have, kv.Key)
		}
		a.p("\n  Settings: %s   Secrets: %s", pick(len(have) == 0, "none", strings.Join(have, ", ")), pick(len(args.Secrets) == 0, "none", strings.Join(args.Secrets, ", ")))
		i, err := p.Choose("Settings and secrets", []wizard.Option{
			{Label: "Add a setting", Hint: "KEY=value, in the compose file"},
			{Label: "Add a secret", Hint: "a password or token, kept encrypted (om secrets)"},
			{Label: "Remove them all"},
			{Label: "Done"},
		}, 3)
		if err != nil {
			return err
		}
		switch i {
		case 3:
			return nil
		case 2:
			args.Env, args.Secrets = nil, nil
		case 0:
			kv, err := p.Ask("Setting (KEY=value)", "", func(s string) string {
				k, v, ok := strings.Cut(s, "=")
				switch {
				case !ok || !scaffold.ValidEnvKey(k):
					return "Type it as KEY=value, with a name in capitals, digits and _."
				case !scaffold.YAMLLabelSafe(v):
					return "The value must not contain quotes, backslashes or line breaks."
				}
				return ""
			})
			if err != nil {
				return err
			}
			k, v, _ := strings.Cut(kv, "=")
			if secretishRE.MatchString(k) && !strings.HasSuffix(k, "_FILE") {
				yes, err := p.Confirm(k+" looks like a secret. Keep it encrypted instead of plain text in the compose file?", true)
				if err != nil {
					return err
				}
				if yes {
					name := strings.ToLower(k)
					args.Secrets = appendUnique(args.Secrets, name)
					args.Env = append(args.Env, scaffold.KV{Key: k + "_FILE", Value: "/run/secrets/" + name})
					a.p("  Added secret %s, read by the image from %s_FILE. Set its value afterwards: om secrets set %s/%s", name, k, args.Name, name)
					_ = v
					continue
				}
			}
			args.Env = append(args.Env, scaffold.KV{Key: k, Value: v})
		case 1:
			name, err := p.Ask("Secret name (lowercase letters, digits and _)", "", func(s string) string {
				if !scaffold.ValidSecretName(s) {
					return "Use lowercase letters, digits and _ only."
				}
				return ""
			})
			if err != nil {
				return err
			}
			args.Secrets = appendUnique(args.Secrets, name)
			via, err := p.Ask("Setting that points the image at the file, such as POSTGRES_PASSWORD_FILE (Enter: none, the service reads /run/secrets/"+name+" itself)", "", func(s string) string {
				if s != "" && !scaffold.ValidEnvKey(s) {
					return "A name in capitals, digits and _."
				}
				return ""
			})
			if err != nil {
				return err
			}
			if via != "" {
				args.Env = append(args.Env, scaffold.KV{Key: via, Value: "/run/secrets/" + name})
			}
			a.p("  Set its value afterwards: om secrets set %s/%s", args.Name, name)
		}
	}
}

// healthHTTP is a check that works with whichever of curl and wget the image has.
func healthHTTP(port int) string {
	url := "http://127.0.0.1:" + strconv.Itoa(port) + "/"
	return "curl -fsS -o /dev/null " + url + " || wget -q -O /dev/null " + url
}

func (a *App) addHealth(p *wizard.Prompter, args *scaffold.AddArgs) error {
	port := args.Port
	if port == 0 {
		port = 8080
	}
	def := 0
	if args.Health != "" {
		def = 1
	}
	i, err := p.Choose("Health check", []wizard.Option{
		{Label: "None", Hint: "the image's own, if it has one"},
		{Label: "A web page answers", Hint: "port " + strconv.Itoa(port) + " (needs curl or wget inside the image)"},
		{Label: "Run a command", Hint: "healthy when it exits 0"},
	}, def)
	if err != nil {
		return err
	}
	switch i {
	case 0:
		args.Health = ""
	case 1:
		args.Health = healthHTTP(port)
	case 2:
		cmd, err := p.Ask("Command (runs inside the container)", "", func(s string) string {
			if s == "" || !scaffold.YAMLLabelSafe(s) {
				return "A command without quotes, backslashes or line breaks."
			}
			return ""
		})
		if err != nil {
			return err
		}
		args.Health = cmd
	}
	return nil
}

// addFlagArgs reads --label, --data, --env, --secret and --health into the request.
func (a *App) addFlagArgs(args *scaffold.AddArgs, ns Namespace) error {
	for _, l := range ns.List("label") {
		k, v, ok := strings.Cut(l, "=")
		if !ok || k == "" || v == "" {
			return fmtErr("--label %q: write it as KEY=VALUE", l)
		}
		args.Extra = mergeKV(args.Extra, scaffold.KV{Key: k, Value: v})
	}
	for _, d := range ns.List("data") {
		if !absPathRE.MatchString(d) || d == "/" {
			return fmtErr("--data %q: give an absolute path inside the container, such as /var/lib/app", d)
		}
		args.Volumes = append(args.Volumes, volumeName(args.Name, args.Volumes)+":"+d)
	}
	for _, e := range ns.List("env") {
		k, v, ok := strings.Cut(e, "=")
		if !ok || !scaffold.ValidEnvKey(k) {
			return fmtErr("--env %q: write it as KEY=VALUE, with a name in capitals, digits and _", e)
		}
		args.Env = append(args.Env, scaffold.KV{Key: k, Value: v})
	}
	for _, s := range ns.List("secret") {
		if !scaffold.ValidSecretName(s) {
			return fmtErr("--secret %q: use lowercase letters, digits and _", s)
		}
		args.Secrets = appendUnique(args.Secrets, s)
	}
	if h := ns.Str("health"); h != "" {
		args.Health = h
	}
	return nil
}

func fmtErr(format string, a ...any) error { return fmt.Errorf(format, a...) }

// mergeKV sets a label, replacing one with the same key.
func mergeKV(list []scaffold.KV, kv scaffold.KV) []scaffold.KV {
	for i := range list {
		if list[i].Key == kv.Key {
			list[i] = kv
			return list
		}
	}
	return append(list, kv)
}

func shellQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"'\\$`!&|;<>()*?[]{}#~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// equivalentAdd is the `om add` command line that makes the same service without questions.
func equivalentAdd(args scaffold.AddArgs) string {
	parts := []string{"om", "add", shellQuote(args.Name)}
	add := func(flag, v string) { parts = append(parts, flag, shellQuote(v)) }
	if args.Project {
		parts = append(parts, "--project")
	}
	if args.Image != "" {
		add("--image", args.Image)
	}
	if args.Port != 0 && !(args.Project && args.Port == 3000) {
		add("--port", strconv.Itoa(args.Port))
	}
	if args.Public {
		parts = append(parts, "--public")
	}
	if args.NoWeb {
		parts = append(parts, "--no-web")
	}
	if args.Icon != "" {
		add("--icon", args.Icon)
	}
	if args.Desc != "" {
		add("--desc", args.Desc)
	}
	for _, v := range args.Volumes {
		add("--data", v[strings.Index(v, ":")+1:])
	}
	for _, kv := range args.Env {
		if strings.HasSuffix(kv.Key, "_FILE") && strings.HasPrefix(kv.Value, "/run/secrets/") {
			continue // rebuilt from --secret below
		}
		add("--env", kv.Key+"="+kv.Value)
	}
	for _, s := range args.Secrets {
		add("--secret", s)
	}
	if args.Health != "" {
		add("--health", args.Health)
	}
	for _, kv := range args.Extra {
		add("--label", kv.Key+"="+kv.Value)
	}
	return strings.Join(parts, " ")
}
