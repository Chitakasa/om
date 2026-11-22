package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Chitakasa/om/internal/links"
	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/secrets"
	"github.com/Chitakasa/om/internal/state"
	"github.com/Chitakasa/om/internal/workspace"
)

// ReadPassword prompts on stderr and reads a line without echo when stdin is a terminal.
func (a *App) ReadPassword(prompt string) string {
	fmt.Fprint(a.Err, prompt)
	if a.Interactive && a.GOOS != "windows" {
		off := exec.Command("stty", "-echo")
		off.Stdin = os.Stdin
		if off.Run() == nil {
			defer func() {
				on := exec.Command("stty", "echo")
				on.Stdin = os.Stdin
				on.Run()
				fmt.Fprintln(a.Err)
			}()
		}
	}
	line, _ := a.In.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

var authUserRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func (a *App) cmdAuth(ns Namespace) error {
	rt := a.Runtime()
	conf := filepath.Join(a.D.Auth, "private.conf")
	users := secrets.ReadAuthUsers(conf)
	action := ns.Str("action")
	switch action {
	case "status", "list":
		if len(users) > 0 {
			a.p("  Private-tier login: \033[32mon\033[0m (%s)", strings.Join(sortedKeys(users), ", "))
		} else {
			a.p("  Private-tier login: \033[33moff\033[0m")
		}
		return nil
	case "off":
		os.Remove(conf)
		a.Core.ReloadCaddy(rt, "", false)
		a.p("\033[32m✓ Private-tier login disabled.\033[0m")
		return nil
	}
	user := ns.Str("user")
	if user == "" || !authUserRE.MatchString(user) {
		return Die("Usage: om auth %s <user>   (letters, digits, . _ -)", action)
	}
	if action == "remove" {
		if _, ok := users[user]; !ok {
			return Die("No login named '%s'. `om auth list` shows them.", user)
		}
		delete(users, user)
		secrets.WriteAuthUsers(a.D.Auth, conf, users)
		a.Core.ReloadCaddy(rt, "", false)
		tail := ""
		if len(users) == 0 {
			tail = " Private-tier login is now off."
		}
		a.p("\033[32m✓ Removed login '%s'.\033[0m%s", user, tail)
		return nil
	}
	pw := a.ReadPassword("New password for " + user + ": ")
	if len([]rune(pw)) < 4 {
		return Die("Use at least 4 characters.")
	}
	if pw != a.ReadPassword("Repeat password: ") {
		return Die("Passwords do not match.")
	}
	if !a.Eng.ContainerRunning(rt, "om_caddy") {
		return Die("The edge proxy must be running (om core start).")
	}
	r := state.Run([]string{rt, "exec", "-i", "om_caddy", "caddy", "hash-password"}, state.WithStdin(pw+"\n"))
	hashed := ""
	if r.Code == 0 && py.Strip(r.Stdout) != "" {
		ls := py.SplitLines(py.Strip(r.Stdout))
		hashed = ls[len(ls)-1]
	}
	if !strings.HasPrefix(hashed, "$2") {
		out := r.Stderr
		if out == "" {
			out = r.Stdout
		}
		return Die("Could not hash the password: %s", lastRunes(py.Strip(out), 300))
	}
	if action == "set" {
		users = map[string]string{user: hashed}
	} else {
		users[user] = hashed
	}
	secrets.WriteAuthUsers(a.D.Auth, conf, users)
	if a.Core.ReloadCaddy(rt, "", false) {
		a.p("\033[32m✓ Private tier now requires a login (%s).\033[0m (LAN public tier unaffected)", strings.Join(sortedKeys(users), ", "))
	}
	return nil
}

func (a *App) cmdLinks(ns Namespace) error {
	rt := a.Runtime()
	found, problems := links.Describe(links.Runner(a.Run), rt)
	if ns.Bool("json") {
		l := []any{}
		for _, f := range found {
			l = append(l, map[string]any{"consumer": f.Consumer, "provider": f.Provider, "reach_as": f.As})
		}
		a.EmitJSON(map[string]any{"links": l, "problems": strList(problems)})
		return nil
	}
	a.p("\n\033[1mLINKS\033[0m")
	if len(found) == 0 && len(problems) == 0 {
		a.p("  None. A service reaches another workspace's service when it declares om.link=<ws>/<svc> and that service declares om.link.allow=<its ws>/<its svc>.\n")
		return nil
	}
	for _, f := range found {
		a.p("  %s → %s reach it as \033[36m%s\033[0m", ljust(f.Consumer, 28), ljust(f.Provider, 28), f.As)
	}
	for _, p := range problems {
		a.p("  \033[33m⚠ %s\033[0m", p)
	}
	a.p("")
	return nil
}

func (a *App) readLegacySecret(ns Namespace) ([]byte, error) {
	file := ns.Str("file")
	if file == "" {
		return nil, Die("usage: om secrets decrypt <file> [-o out]   |   om secrets migrate <file> <project>/<name>")
	}
	if st, err := os.Stat(file); err != nil || st.IsDir() {
		return nil, Die("No such file: %s", file)
	}
	pw := a.Getenv("OM_SECRET_KEY")
	if pw == "" {
		pw = a.ReadPassword("Passphrase: ")
	}
	data, err := a.Legacy.DecryptFile(file, pw, ns.Bool("allow_unauthenticated"))
	if err != nil {
		return nil, Die("%s", err)
	}
	return data, nil
}

func (a *App) cmdSecrets(root string, ns Namespace) error {
	switch ns.Str("action") {
	case "init", "set", "list", "rekey", "migrate":
		return a.cmdAgeSecrets(root, ns)
	}
	data, err := a.readLegacySecret(ns)
	if err != nil {
		return err
	}
	if out := ns.Str("output"); out != "" {
		if err := state.WritePrivateBytes(out, data); err != nil {
			return Die("%s", err)
		}
		a.p("\033[32m✓ Decrypted to %s\033[0m", out)
	} else {
		a.Out.Write(data)
	}
	return nil
}

func validSecretTarget(t string) bool {
	project, name, _ := strings.Cut(t, "/")
	return project != "" && secrets.NameRE.MatchString(name)
}

func (a *App) gitCfg(key string) (int, string) {
	r := a.Run([]string{"git", "config", "--get", key})
	return r.Code, py.Strip(r.Stdout)
}

func (a *App) mySignerLine() string {
	return secrets.MySignerLine(func(c []string) (int, string) { r := a.Run(c); return r.Code, py.Strip(r.Stdout) },
		func(p string) (string, error) { return py.ReadText(p) },
		expandUser)
}

func expandUser(p string) string {
	if strings.HasPrefix(p, "~") {
		if h, err := os.UserHomeDir(); err == nil {
			return h + p[1:]
		}
	}
	return p
}

func (a *App) cmdAgeSecrets(root string, ns Namespace) error {
	if root == "" {
		return Die("Run this inside a workspace (a folder with .om/config.json; `om init` makes one).")
	}
	rt := a.Runtime()
	switch ns.Str("action") {
	case "init":
		host, err := a.Age.HostRecipient(rt)
		if err != nil {
			return Die("%s", err)
		}
		signer := a.mySignerLine()
		owner := ""
		if f := strings.Fields(signer); len(f) > 2 {
			owner = strings.Join(f[2:min(4, len(f))], " ")
		}
		added, err := secrets.WriteRecipients(root, host, owner)
		if err != nil {
			return Die("%s", err)
		}
		tail := ""
		if owner != "" {
			tail = " and your SSH key"
		}
		h := host
		if len(h) > 16 {
			h = h[:16]
		}
		a.p("\033[32m✓ %s\033[0m: this host (%s…)%s can decrypt.", secrets.RecipientsName, h, tail)
		a.p("  Commit it. Back up %s off-host: without it (or your SSH key) secrets cannot be read.", a.Age.KeyFile())
		if added {
			a.p("  This machine was added to an existing list: on a machine that can already decrypt (or here, if your")
			a.p("  SSH key has no passphrase), run `om secrets rekey` and commit, so the existing secrets open here too.")
		}
	case "rekey":
		_, k := a.gitCfg("user.signingkey")
		if k == "" {
			k = "~/.ssh/id_ed25519.pub"
		}
		key := expandUser(k)
		sshKey := strings.TrimSuffix(key, ".pub")
		files, err := a.Age.Rekey(rt, root, sshKey)
		if err != nil {
			return Die("%s", err)
		}
		a.p("\033[32m✓ %d secret(s) re-encrypted for %d recipient(s)\033[0m — commit them.", len(files), len(secrets.Recipients(root)))
	case "list":
		for _, t := range workspace.DiscoverComposeDirs(root, "") {
			ms, _ := filepath.Glob(filepath.Join(t.Dir, "secrets", "*.age"))
			sort.Strings(ms)
			for _, f := range ms {
				b := filepath.Base(f)
				a.p("  %s/%s", filepath.Base(t.Dir), b[:len(b)-4])
			}
		}
	case "migrate":
		target := ns.Str("destination")
		var value []byte
		if validSecretTarget(target) {
			v, err := a.readLegacySecret(ns)
			if err != nil {
				return err
			}
			value = v
		}
		return a.storeSecret(root, rt, target, value)
	default:
		target := ns.Str("file")
		if !validSecretTarget(target) {
			return Die("usage: om secrets set <project>/<name>   (value read from stdin, or asked for)")
		}
		var value []byte
		if !a.Interactive {
			b, _ := io.ReadAll(a.In)
			value = b
		} else {
			value = []byte(a.ReadPassword("Value for " + target + ": "))
		}
		return a.storeSecret(root, rt, target, value)
	}
	return nil
}

func (a *App) storeSecret(root, rt, target string, value []byte) error {
	if !validSecretTarget(target) {
		return Die("usage: om secrets migrate <file> <project>/<name>   (got '%s')", target)
	}
	project, name, _ := strings.Cut(target, "/")
	d, err := workspace.ResolveTarget(root, project)
	if err != nil {
		return Die("%s", err)
	}
	if len(value) == 0 {
		return Die("Empty value.")
	}
	if _, err := a.Age.HostRecipient(rt); err != nil {
		return Die("%s", err)
	}
	os.MkdirAll(filepath.Join(d, "secrets"), 0o755)
	enc, err := a.Age.Encrypt(rt, root, value)
	if err != nil {
		return Die("%s", err)
	}
	out := filepath.Join(d, "secrets", name+".age")
	if err := os.WriteFile(out, enc, 0o644); err != nil {
		return Die("%s", err)
	}
	rel, _ := filepath.Rel(root, out)
	cf, _ := workspace.FindComposeFile(d)
	a.p("\033[32m✓ %s\033[0m (encrypted; commit it). In %s:", rel, filepath.Base(cf))
	a.p("    services:\n      <svc>:\n        secrets: [%s]        # read it from /run/secrets/%s\n    secrets:\n      %s:\n        file: ./secrets/%s", name, name, name, name)
	return nil
}
