// Command tools holds the two small helpers testdata/e2e/record.sh needs, so the repository has no script language
// to run besides bash and Go:
//
//	go run ./testdata/e2e/tools freeport   prints a free TCP port on 127.0.0.1
//	go run ./testdata/e2e/tools hostfree   reads a recording on stdin and drops what the recording machine itself
//	                                       held (its other login accounts, firewall rules installed in /etc, its user name)
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
)

var (
	reOthers  = regexp.MustCompile(`; other accounts: .*`)
	reJSON    = regexp.MustCompile(`(?s)"other_accounts": \[.*?\]`)
	reRows    = regexp.MustCompile(`(?m)^  (PASS|WARN|FAIL)  (Login|Address rules) .*\n(?:[ ]+↳ .*\n)*`)
	reAccount = regexp.MustCompile(`(show-user|enable-linger) \S+`)
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: tools freeport|hostfree")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "freeport":
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(l.Addr().(*net.TCPAddr).Port)
		l.Close()
	case "hostfree":
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		s := string(b)
		s = reOthers.ReplaceAllString(s, "")
		s = reJSON.ReplaceAllString(s, `"other_accounts": []`)
		s = reRows.ReplaceAllString(s, "")
		s = reAccount.ReplaceAllString(s, "$1 USER")
		os.Stdout.WriteString(s)
	default:
		fmt.Fprintln(os.Stderr, "usage: tools freeport|hostfree")
		os.Exit(2)
	}
}
