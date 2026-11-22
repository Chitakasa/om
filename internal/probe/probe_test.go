package probe

import (
	"bytes"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func unixListener(t *testing.T, h func(net.Conn)) string {
	t.Helper()
	sock := filepath.Join(os.TempDir(), "omprobe-"+filepath.Base(t.TempDir())+".sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close(); os.Remove(sock) })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go h(c)
		}
	}()
	return sock
}

func TestRouterRefusedAndForwarded(t *testing.T) {
	closing := unixListener(t, func(c net.Conn) { c.Read(make([]byte, 512)); c.Close() })
	if got, err := Router(closing); err != nil || got != "refused" {
		t.Fatalf("closing router: %q %v", got, err)
	}
	relaying := unixListener(t, func(c net.Conn) { c.Read(make([]byte, 512)); c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); c.Close() })
	if got, _ := Router(relaying); got != "forwarded" {
		t.Fatalf("relaying router: %q", got)
	}
	if _, err := Router("/nonexistent/sock"); err == nil {
		t.Fatal("a missing socket is an error (doctor shows the message)")
	}
}

func TestSockReportsFilteredEngine(t *testing.T) {
	sock := filepath.Join(os.TempDir(), "omprobe-sock-"+filepath.Base(t.TempDir())+".sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close(); os.Remove(sock) })
	go http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.WriteHeader(403)
		}
	}))
	got, err := Sock(sock)
	if err != nil {
		t.Fatal(err)
	}
	want := "0 200 403"
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		want = "1 200 403"
	}
	if got != want {
		t.Fatalf("%q, want %q", got, want)
	}
}

func TestViaProxyStatuses(t *testing.T) {
	for status, want := range map[string]string{"403 Forbidden": "refused", "407 Proxy Authentication Required": "refused", "200 Connection established": "open", "503 Service Unavailable": "error"} {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		go func(status string) {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Read(make([]byte, 512))
			c.Write([]byte("HTTP/1.1 " + status + "\r\n\r\n"))
			c.Close()
		}(status)
		if got := viaProxy(l.Addr().String(), "example.com"); got != want {
			t.Errorf("%s: %q, want %q", status, got, want)
		}
		l.Close()
	}
	if got := viaProxy("127.0.0.1:1", "example.com"); got != "error" {
		t.Errorf("no proxy: %q", got)
	}
}

func TestIsolationAndStream(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	if got := Stream([]string{net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}); got != "open" {
		t.Errorf("open: %q", got)
	}
	l2, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := l2.Addr().(*net.TCPAddr).Port
	l2.Close()
	if got := Stream([]string{"127.0.0.1:" + strconv.Itoa(closedPort), "no-such-host.invalid:80", "garbage"}); got != "refused unreachable unreachable" {
		t.Errorf("mixed: %q", got)
	}
	// nothing listens on port 80 of loopback in a test sandbox (a refusal still counts as a path)
	if got := Isolation("no-such-host.invalid", "127.0.0.1"); got != "blocked open" && got != "blocked blocked" {
		t.Errorf("isolation: %q", got)
	}
}

func TestRunUsageAndUnknown(t *testing.T) {
	var out, errb bytes.Buffer
	if Run(nil, &out, &errb, os.Getenv) != 2 || Run([]string{"nope"}, &out, &errb, os.Getenv) != 2 || Run([]string{"isolation", "x"}, &out, &errb, os.Getenv) != 2 {
		t.Fatal("bad usage must exit 2")
	}
	if Run([]string{"router"}, &out, &errb, os.Getenv) != 1 {
		t.Fatal("an unreachable router socket exits 1")
	}
}

func TestEgressTargetSelection(t *testing.T) {
	if !isDigitsDots("10.0.0.1") || isDigitsDots("example.com") || isDigitsDots("") {
		t.Fatal("isDigitsDots")
	}
}
