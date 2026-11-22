//go:build !unix

package cli

func ttyCols() int { return 0 }
