// Package probe holds the checks `om doctor` runs from inside throwaway containers (`om probe <kind> ...`, the om
// binary mounted at /om): each one prints a single line of words that doctor compares with what it expects.
package probe

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Run executes one probe (args[0] is its kind) and returns the process exit code.
func Run(args []string, out, errOut io.Writer, getenv func(string) string) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "usage: om probe router|sock|egress|isolation|stream ...")
		return 2
	}
	var line string
	var err error
	switch args[0] {
	case "router":
		line, err = Router("/run/om-router/router.sock")
	case "sock":
		line, err = Sock(getenv("OM_ENGINE_SOCKET_PATH"))
	case "egress":
		line = Egress(args[1:], "om_egress:3128")
	case "isolation":
		if len(args) != 3 {
			fmt.Fprintln(errOut, "usage: om probe isolation <name> <ip>")
			return 2
		}
		line = Isolation(args[1], args[2])
	case "stream":
		line = Stream(args[1:])
	default:
		fmt.Fprintf(errOut, "unknown probe %q\n", args[0])
		return 2
	}
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	fmt.Fprintln(out, line)
	return 0
}

// Router connects to the router's unix socket and sends a request without the edge token: "refused" is the answer
// that passes, "forwarded" means the router relayed it.
func Router(sock string) (string, error) {
	c, err := net.DialTimeout("unix", sock, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nX-Om-Upstream: om_dashboard:80\r\n\r\n")); err != nil {
		return "", err
	}
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err == nil && n > 0 {
		return "forwarded", nil
	}
	return "refused", nil
}

func unixStatus(sock, method, path string) (int, error) {
	cl := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}, DisableKeepAlives: true}}
	req, err := http.NewRequest(method, "http://localhost"+path, nil)
	if err != nil {
		return 0, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

// Sock reports "<raw docker socket present> <GET /containers/json status> <POST kill status>" through the filtered
// engine socket: "0 200 403" is read-only access without the raw socket.
func Sock(sock string) (string, error) {
	_, rawErr := os.Stat("/var/run/docker.sock")
	raw := 0
	if rawErr == nil {
		raw = 1
	}
	get, err := unixStatus(sock, "GET", "/containers/json")
	if err != nil {
		return "", err
	}
	post, err := unixStatus(sock, "POST", "/containers/om_dashboard/kill")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d %d %d", raw, get, post), nil
}

func state(ok bool) string {
	if ok {
		return "open"
	}
	return "blocked"
}

func resolves(name string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a, err := net.DefaultResolver.LookupIP(ctx, "ip4", name)
	return err == nil && len(a) > 0
}

func dials(addr string, timeout time.Duration) bool {
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// Egress probes a workspace network's perimeter from inside it: "<dns> <direct> <host> <proxy> <raw_forge>".
// target is the host to ask the proxy for (example.com when the first argument is an address).
func Egress(args []string, proxy string) string {
	target := "example.com"
	addrs := args
	if len(args) > 0 && !isDigitsDots(args[0]) {
		target, addrs = args[0], args[1:]
	}
	host := "blocked"
outer:
	for _, a := range addrs {
		for _, p := range []int{22, 80, 443, 2019, 9091} {
			if dials(net.JoinHostPort(a, strconv.Itoa(p)), 2*time.Second) {
				host = fmt.Sprintf("open:%s:%d", a, p)
				break outer
			}
		}
	}
	return strings.Join([]string{state(resolves("example.com")), state(dials("1.1.1.1:443", 4*time.Second)), host,
		viaProxy(proxy, target), rawForge()}, " ")
}

func isDigitsDots(s string) bool {
	return strings.Trim(s, "0123456789.") == "" && strings.Trim(strings.ReplaceAll(s, ".", ""), "0123456789") == "" && s != ""
}

// viaProxy asks the egress proxy for a tunnel to target:443: "refused" for 403/407 (the proxy knows no such source),
// "open" when it grants it, "error" otherwise.
func viaProxy(proxy, target string) string {
	c, err := net.DialTimeout("tcp", proxy, 8*time.Second)
	if err != nil {
		return "error"
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(8 * time.Second))
	fmt.Fprintf(c, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", target, target)
	status, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return "error"
	}
	f := strings.Fields(status)
	if len(f) < 2 {
		return "error"
	}
	switch f[1] {
	case "403", "407":
		return "refused"
	case "200":
		return "open"
	}
	return "error"
}

// Isolation checks that a container cannot reach another folder's service by name or address: "<dns> <direct>".
func Isolation(name, ip string) string {
	direct := false
	c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "80"), 3*time.Second)
	if err == nil {
		c.Close()
		direct = true
	} else if errors.Is(err, syscall.ECONNREFUSED) {
		direct = true // an answer, even a refusal, means a path exists
	}
	return state(resolves(name)) + " " + state(direct)
}

// Stream probes host:port pairs: "open", "refused" or "unreachable" for each.
func Stream(pairs []string) string {
	var out []string
	for _, p := range pairs {
		i := strings.Index(p, ":")
		if i < 0 {
			out = append(out, "unreachable")
			continue
		}
		port, _ := strconv.Atoi(p[i+1:])
		out = append(out, streamOne(p[:i], port))
	}
	return strings.Join(out, " ")
}

func streamOne(host string, port int) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return "unreachable"
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(ips[0].String(), strconv.Itoa(port)), 2*time.Second)
	if err == nil {
		c.Close()
		return "open"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "refused"
	}
	return "unreachable"
}
