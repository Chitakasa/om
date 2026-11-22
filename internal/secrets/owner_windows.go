//go:build windows

package secrets

import "os"

func ownedByMe(os.FileInfo) bool { return true }
