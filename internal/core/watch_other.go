//go:build !linux

package core

import "github.com/Chitakasa/om/internal/engine"

// NewLinuxWatcher is nil off Linux: `om core watch` is Linux-only and says so.
func NewLinuxWatcher(*engine.Engine) func(string) (Watcher, error) { return nil }
