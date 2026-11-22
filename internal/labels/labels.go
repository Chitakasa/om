// Package labels reads a compose service's labels. Compose allows both forms (`labels: {a: b}` and
// `labels: [a=b]`); every om feature reads labels through here. Port of lib/gitops/svclabels.py.
package labels

import "strings"

// Service returns the labels of a (normalized or raw) compose service. A bare list entry `a` is the label `a`
// with an empty value. Values keep their decoded type (compose may hold numbers and booleans).
func Service(svc map[string]any) map[string]any {
	out := map[string]any{}
	switch l := svc["labels"].(type) {
	case map[string]any:
		return l
	case []any:
		for _, item := range l {
			s, ok := item.(string)
			if !ok {
				continue
			}
			k, v, _ := strings.Cut(s, "=")
			out[k] = v
		}
	}
	return out
}
