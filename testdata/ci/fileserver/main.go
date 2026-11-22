// Command fileserver serves a folder over HTTP on loopback: the installers test's stand-in for a release page.
//
//	go run ./testdata/ci/fileserver -dir rel -addr 127.0.0.1:8099
package main

import (
	"flag"
	"log"
	"net/http"
)

func main() {
	dir := flag.String("dir", ".", "folder to serve")
	addr := flag.String("addr", "127.0.0.1:8099", "address to listen on")
	flag.Parse()
	log.Fatal(http.ListenAndServe(*addr, http.FileServer(http.Dir(*dir))))
}
