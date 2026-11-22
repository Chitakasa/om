// Package attacks holds om's attack and fuzz tests, and no code. Untrusted text reaches om as folder names, compose
// labels, `om.caddy` snippets, the egress label, branch names and HTTP requests; each ends up in a generated config
// (Caddy, Squid, HAProxy, nftables, compose) or on the filesystem. The tests feed every one of them hostile input and
// check what comes out: refused, or harmless. Fuzzing is seeded, so a failure reproduces.
//
// A test named *Hole* is a hole these suites found in om (in the Python original) and that is closed: it stays as the
// regression that names it.
package attacks
