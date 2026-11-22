package main

import (
	"os"

	"github.com/Chitakasa/om/internal/cli"
	"github.com/Chitakasa/om/internal/state"
)

func main() {
	app := cli.NewApp(state.Version, os.Stdin, os.Stdout, os.Stderr)
	os.Exit(app.Main(os.Args[1:]))
}
