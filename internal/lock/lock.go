// Package lock is the image lock: `.om/lock.json` pins every pulled image to its registry digest. A workspace
// commit plus its lock fully describes what runs: a re-pushed tag changes nothing until `om lock` / `om update`
// writes a new digest and you commit it. Digests are the multi-arch *index* digest from the registry (OCI
// distribution API, anonymous token flow), so the same lock works on amd64 and arm64. Services with `build:` are
// built locally and not locked. Port of lib/gitops/lock.py.
package lock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Chitakasa/om/internal/labels"
	"github.com/Chitakasa/om/internal/py"
	"github.com/Chitakasa/om/internal/state"
)

const Name = ".om/lock.json"

var accept = strings.Join([]string{
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.v2+json",
}, ", ")

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// IsDigest reports a well-formed sha256 digest.
func IsDigest(s string) bool { return digestRE.MatchString(s) }

// Ref is a parsed image reference.
type Ref struct{ Registry, Repository, Tag, Digest string }

// ParseRef parses 'nginx:1.31' with Docker Hub defaults.
func ParseRef(ref string) Ref {
	digest := ""
	if i := strings.Index(ref, "@"); i >= 0 {
		ref, digest = ref[:i], ref[i+1:]
	}
	first, rest, _ := strings.Cut(ref, "/")
	var registry, path string
	if rest != "" && (strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost") {
		registry, path = first, rest
	} else {
		registry, path = "docker.io", ref
	}
	name, tag := path, ""
	last := path
	if i := strings.LastIndex(path, "/"); i >= 0 {
		last = path[i+1:]
	}
	if strings.Contains(last, ":") {
		i := strings.LastIndex(path, ":")
		name, tag = path[:i], path[i+1:]
	}
	if tag == "" {
		tag = "latest"
	}
	if registry == "docker.io" && !strings.Contains(name, "/") {
		name = "library/" + name
	}
	return Ref{registry, name, tag, digest}
}

// Lock works on the lock files and registries of one machine. The fields exist for tests.
type Lock struct {
	D      state.Dirs
	Run    func([]string) state.Result
	Client *http.Client
	// Host maps a registry name to the host to contact (docker.io is registry-1.docker.io).
	Host func(registry string) string
}

// New returns a Lock for this machine.
func New(d state.Dirs) *Lock {
	l := &Lock{D: d, Run: func(c []string) state.Result { return state.Run(c) }}
	l.Client = &http.Client{Timeout: 15 * time.Second, CheckRedirect: stripAuthOnRedirect}
	l.Host = func(r string) string {
		if r == "docker.io" {
			return "registry-1.docker.io"
		}
		return r
	}
	return l
}

// stripAuthOnRedirect: blobs redirect to a CDN with its own signed URL; a forwarded registry token makes it refuse.
func stripAuthOnRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("stopped after 10 redirects")
	}
	req.Header.Del("Authorization")
	return nil
}

var paramRE = regexp.MustCompile(`(\w+)="([^"]*)"`)

// bearer fetches an anonymous token for a `WWW-Authenticate: Bearer realm=…,service=…,scope=…` challenge.
func (l *Lock) bearer(challenge string) (string, error) {
	type kv struct{ k, v string }
	var params []kv
	index := map[string]int{}
	for _, m := range paramRE.FindAllStringSubmatch(challenge, -1) {
		if i, ok := index[m[1]]; ok {
			params[i].v = m[2]
		} else {
			index[m[1]] = len(params)
			params = append(params, kv{m[1], m[2]})
		}
	}
	realm := ""
	var rest []string
	for _, p := range params {
		if p.k == "realm" {
			realm = p.v
		} else {
			rest = append(rest, p.k+"="+py.Quote(p.v, "/"))
		}
	}
	if !strings.HasPrefix(realm, "https://") {
		return "", nil
	}
	resp, err := l.Client.Get(realm + "?" + strings.Join(rest, "&"))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("token endpoint: %s", resp.Status)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(b, &body); err != nil {
		return "", err
	}
	if body.Token != "" {
		return body.Token, nil
	}
	return body.AccessToken, nil
}

// open fetches /v2/<repository>/<path>, following one anonymous Bearer challenge. ok is false if the registry
// cannot be read anonymously.
func (l *Lock) open(ref, path, method string) (header http.Header, body []byte, ok bool) {
	r := ParseRef(ref)
	url := "https://" + l.Host(r.Registry) + "/v2/" + r.Repository + "/" + path
	headers := map[string]string{"Accept": accept}
	for i := 0; i < 2; i++ {
		req, err := http.NewRequest(method, url, nil)
		if err != nil {
			return nil, nil, false
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := l.Client.Do(req)
		if err != nil {
			return nil, nil, false
		}
		if resp.StatusCode < 400 {
			var data []byte
			if method == "GET" {
				data, err = io.ReadAll(resp.Body)
			}
			resp.Body.Close()
			if err != nil {
				return nil, nil, false
			}
			return resp.Header, data, true
		}
		challenge := resp.Header.Get("WWW-Authenticate")
		resp.Body.Close()
		_, hasAuth := headers["Authorization"]
		if resp.StatusCode != 401 || hasAuth || !strings.HasPrefix(strings.ToLower(challenge), "bearer") {
			return nil, nil, false
		}
		token, err := l.bearer(challenge)
		if err != nil || token == "" {
			return nil, nil, false
		}
		headers["Authorization"] = "Bearer " + token
	}
	return nil, nil, false
}

// head returns the digest and content type of manifest `reference` (tag or digest) in ref's repository.
func (l *Lock) head(ref, reference string) (digest, contentType string) {
	h, _, ok := l.open(ref, "manifests/"+reference, "HEAD")
	if !ok {
		return "", ""
	}
	d := h.Get("Docker-Content-Digest")
	switch {
	case IsDigest(d):
		digest = d
	case IsDigest(reference):
		digest = reference
	}
	return digest, h.Get("Content-Type")
}

// Description is what the registry tells anonymously about an image.
type Description struct {
	Size    int64
	Created string // YYYY-MM-DD, "" when unknown
	HasSize bool
}

func platformArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	}
	return ""
}

// Describe returns the created date and compressed size of the image behind digest for this machine's platform;
// ok=false for whatever the registry does not tell anonymously.
func (l *Lock) Describe(ref, digest string) (Description, bool) {
	arch := platformArch()
	_, body, _ := l.open(ref, "manifests/"+digest, "GET")
	var manifest struct {
		Manifests []struct {
			Digest   string
			Platform struct{ OS, Architecture string }
		}
		Layers []struct{ Size json.Number }
		Config struct{ Digest string }
	}
	if json.Unmarshal(body, &manifest) != nil {
		return Description{}, false
	}
	if len(manifest.Manifests) > 0 { // an index: take this machine's linux image
		pick := -1
		for i, m := range manifest.Manifests {
			if m.Platform.OS == "linux" && m.Platform.Architecture == arch {
				pick = i
				break
			}
		}
		if pick < 0 {
			return Description{}, false
		}
		_, body, _ = l.open(ref, "manifests/"+manifest.Manifests[pick].Digest, "GET")
		manifest.Manifests, manifest.Layers = nil, nil
		manifest.Config.Digest = ""
		if json.Unmarshal(body, &manifest) != nil {
			return Description{}, false
		}
	}
	var out Description
	for _, ln := range manifest.Layers {
		if ln.Size == "" {
			continue
		}
		n, err := ln.Size.Int64()
		if err != nil {
			return Description{}, false
		}
		out.Size += n
	}
	out.HasSize = true
	if IsDigest(manifest.Config.Digest) {
		_, blob, _ := l.open(ref, "blobs/"+manifest.Config.Digest, "GET")
		var cfg map[string]any
		if json.Unmarshal(blob, &cfg) != nil {
			return Description{}, false
		}
		c := ""
		if v, ok := cfg["created"]; ok {
			c = py.Str(v)
		}
		r := []rune(c)
		if len(r) > 10 {
			r = r[:10]
		}
		out.Created = string(r)
	}
	return out, true
}

// Modes of `om.update`.
var Modes = []string{"manual", "hold", "auto"}

func servicesOf(cfg map[string]any) map[string]any {
	m, _ := cfg["services"].(map[string]any)
	return m
}

func sortedNames(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func pulls(svc map[string]any) bool { return py.Truthy(svc["image"]) && !py.Truthy(svc["build"]) }

// UpdateModes returns {service: mode} and the unrecognised values from the `om.update` label of pulled services.
// `hold` keeps the pin where it is, `auto` lets the scheduled sync move it (and undo it if the health check
// fails); anything else, or no label, is `manual`.
func UpdateModes(cfg map[string]any) (map[string]string, []string) {
	modes := map[string]string{}
	var bad []string
	services := servicesOf(cfg)
	for _, name := range sortedNames(services) {
		svc, _ := services[name].(map[string]any)
		if !pulls(svc) {
			continue
		}
		v := "manual"
		if x, ok := labels.Service(svc)["om.update"]; ok {
			v = py.Str(x)
		}
		v = strings.ToLower(py.Strip(v))
		known := false
		for _, m := range Modes {
			known = known || m == v
		}
		if !known {
			bad = append(bad, name+": om.update="+v)
			v = "manual"
		}
		modes[name] = v
	}
	return modes, bad
}

// RegistryDigest is the current index digest of ref's tag in its registry, or "" if it cannot be read anonymously.
func (l *Lock) RegistryDigest(ref string) string {
	r := ParseRef(ref)
	if r.Digest != "" {
		return r.Digest
	}
	d, _ := l.head(ref, r.Tag)
	return d
}

// LocalDigest is the digest of the image the local tag points to (what runs now), preferring the multi-arch index
// digest; for a private registry, the first digest the engine recorded.
func (l *Lock) LocalDigest(runtimeName, ref string) string {
	r := l.Run([]string{runtimeName, "image", "inspect", "--format", "{{json .RepoDigests}}", ref})
	text := r.Stdout
	if text == "" {
		text = "[]"
	}
	var all []string
	if json.Unmarshal([]byte(text), &all) != nil {
		return ""
	}
	var cands []string
	for _, rd := range all {
		d := rd
		if i := strings.LastIndex(rd, "@"); i >= 0 {
			d = rd[i+1:]
		}
		if IsDigest(d) {
			cands = append(cands, d)
		}
	}
	for _, d := range cands {
		_, ct := l.head(ref, d)
		if strings.Contains(ct, "index") || strings.Contains(ct, "manifest.list") {
			return d
		}
	}
	if len(cands) > 0 {
		return cands[0]
	}
	return ""
}

// Images returns {service: image ref} for services that pull (not build) their image.
func Images(cfg map[string]any) map[string]string {
	out := map[string]string{}
	for name, v := range servicesOf(cfg) {
		if svc, _ := v.(map[string]any); pulls(svc) {
			out[name] = py.Str(svc["image"])
		}
	}
	return out
}

// Read returns the pinned images of a workspace (only well-formed digests; {} when there is no readable lock).
func Read(root string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(Name)))
	if err != nil {
		return out
	}
	v, err := py.LoadJSON(b)
	data, ok := v.(map[string]any)
	if err != nil || !ok {
		return out
	}
	imgs, _ := data["images"].(map[string]any)
	for k, x := range imgs {
		if s := py.Str(x); IsDigest(s) {
			out[k] = s
		}
	}
	return out
}

// Write replaces the lock file.
func Write(root string, pinned map[string]string) error {
	m := map[string]any{} // Dumps writes plain maps with sorted keys, like `dict(sorted(...))`
	for k, v := range pinned {
		m[k] = v
	}
	body := py.NewObject() // the lock is committed: "version" stays before "images"
	body.Set("version", 1)
	body.Set("images", m)
	return state.WriteAtomic(filepath.Join(root, filepath.FromSlash(Name)), py.Dumps(body)+"\n")
}

// Resolve returns a digest for each ref and the refs that could not be resolved. Without refresh: the existing
// pin, else what runs now (local image), else the registry's current one. With refresh (`om update`): the
// registry's current one.
func (l *Lock) Resolve(runtimeName string, refs []string, current map[string]string, refresh bool) (map[string]string, []string) {
	set := map[string]bool{}
	for _, r := range refs {
		set[r] = true
	}
	sorted := make([]string, 0, len(set))
	for r := range set {
		sorted = append(sorted, r)
	}
	sort.Strings(sorted)
	pinned := map[string]string{}
	var missing []string
	for _, ref := range sorted {
		var d string
		if refresh {
			if d = l.RegistryDigest(ref); d == "" {
				d = current[ref]
			}
		} else if d = current[ref]; d == "" {
			if d = l.LocalDigest(runtimeName, ref); d == "" {
				d = l.RegistryDigest(ref)
			}
		}
		if d != "" {
			pinned[ref] = d
		} else {
			missing = append(missing, ref)
		}
	}
	return pinned, missing
}

// PinnedRef is `repo:tag@sha256:…`: the engine pulls by digest; the tag stays for humans.
func PinnedRef(ref, digest string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	return ref + "@" + digest
}

// WriteOverride writes the compose override pinning this project's images to the lock and returns its path, or ""
// if there is nothing to pin (a stale file is removed).
func (l *Lock) WriteOverride(ws, project string, cfg map[string]any, pinned map[string]string) (string, error) {
	mine := map[string]string{}
	for s, ref := range Images(cfg) {
		if d, ok := pinned[ref]; ok {
			mine[s] = PinnedRef(ref, d)
		}
	}
	sum := sha256.Sum256([]byte(project))
	path := filepath.Join(l.D.State, "lock", "overrides", ws+"-"+hex.EncodeToString(sum[:])[:12]+".yml")
	if len(mine) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return "", err
		}
		return "", nil
	}
	lines := []string{"# Generated by om from .om/lock.json — do not edit.", "services:"}
	names := make([]string, 0, len(mine))
	for s := range mine {
		names = append(names, s)
	}
	sort.Strings(names)
	for _, s := range names {
		lines = append(lines, "  "+py.JSONString(s)+":", "    image: "+py.JSONString(mine[s]))
	}
	return path, state.WriteAtomic(path, strings.Join(lines, "\n")+"\n")
}
