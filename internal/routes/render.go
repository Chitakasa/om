package routes

import (
	"strconv"
	"strings"

	"github.com/Chitakasa/om/internal/state"
)

func serviceBody(upstream, sname string, o Options, dashboard string) string {
	body := "    import to_workspace " + upstream + "\n"
	if len(o.DashboardPaths) > 0 {
		var handles strings.Builder
		for _, p := range o.DashboardPaths {
			handles.WriteString("    handle " + p + " {\n        import " + dashboard + "\n    }\n")
		}
		body = handles.String() + "    handle {\n        import to_workspace " + upstream + "\n    }\n"
	}
	if o.KeepPrefix {
		body = "    redir / /" + sname + "/\n" + body
	}
	if o.Snippet != "" { // the service's om.caddy runs first, in order, then om's own handling
		body = "    route {\n" + indent(o.Snippet) + indent(body) + "    }\n"
	}
	return body
}

func indent(text string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		if line != "" {
			b.WriteString("    " + line + "\n")
		} else {
			b.WriteString("\n")
		}
	}
	return b.String()
}

// RenderVhost renders the service's *.localhost vhost, plus — with a slot (>= 0) — its own ports: 20000+slot on
// loopback and the VPN, and if public 21000+slot on the LAN and the VPN. One origin per service, so one
// service's scripts can never read another's pages; a foreign Host is aborted (DNS rebinding). Pass slot < 0 for
// no own ports.
func RenderVhost(ws, sname string, port int, o Options, slot int, public bool) string {
	upstream := ws + "_" + sname + ":" + strconv.Itoa(port)
	body := serviceBody(upstream, sname, o, "to_dashboard")
	if o.Log == "off" { // om.log=off: the edge keeps no trace of this service's requests
		body = "    log_skip\n" + body
	}
	custom := ""
	if o.Snippet != "" {
		custom = "\n# custom: " + SnippetFile + " of this service is included below"
	}
	out := "# ==============================================================================\n" +
		"# Service: " + sname + " (" + ws + ")" + custom + "\n" +
		"# ==============================================================================\n" +
		"http://" + ws + "." + sname + ".localhost {\n" +
		"    import security_headers\n" +
		"    import private_auth\n" +
		body + "}\n"
	if slot < 0 {
		return out
	}
	out += "\nhttp://:" + strconv.Itoa(state.PrivatePortBase+slot) + " {\n" +
		"    import security_headers\n" +
		"    import private_auth\n" +
		"    @foreign not host {$PRIVATE_NAMES}\n" +
		"    handle @foreign {\n        abort\n    }\n" +
		"    handle {\n" + indent(body) + "    }\n}\n"
	if public {
		pbody := serviceBody(upstream, sname, o, "to_dashboard_public")
		if o.Log == "off" {
			pbody = "    log_skip\n" + pbody
		}
		out += "\nhttp://:" + strconv.Itoa(state.PublicPortBase+slot) + " {\n" +
			"    import security_headers\n" +
			"    @foreign not host {$PUBLIC_NAMES}\n" +
			"    handle @foreign {\n        abort\n    }\n" +
			"    handle {\n" + indent(pbody) + "    }\n}\n"
	}
	return out
}

// RenderAlias renders the redirects on the dashboard's address: /<svc> and each om.route.aliases path go to the
// service's own port, on the same host the visitor used.
func RenderAlias(ws, sname string, port int, public bool, o Options) string {
	title := "# Private Alias: " + sname + " (" + ws + ")"
	if public {
		title = "# Public Alias: " + sname + " (" + ws + ")"
	}
	root := "/"
	if o.KeepPrefix {
		root = "/" + sname + "/"
	}
	p := strconv.Itoa(port)
	lines := []string{title, "redir /" + sname + " http://{host}:" + p + root, "redir /" + sname + "/* http://{host}:" + p + root}
	for _, a := range o.Aliases {
		lines = append(lines, "redir "+a+" http://{host}:"+p+"{uri}", "redir "+a+"/* http://{host}:"+p+"{uri}")
	}
	return strings.Join(lines, "\n") + "\n"
}
