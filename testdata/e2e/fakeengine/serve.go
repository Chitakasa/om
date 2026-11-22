package main

import (
	"fmt"
	"net/http"
	"os"
)

// serve answers every request with 200: the stand-in for the edge that om's post-deploy health check asks.
func serve(port string) {
	err := http.ListenAndServe("127.0.0.1:"+port, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") }))
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
