package core

import (
	"fmt"
	"strings"
	"time"
)

// Watcher is what `om core watch` listens to: a pidfd per om container (the kernel says at once when a process exits)
// and the engine's own event stream (it says when the set of containers may have changed).
type Watcher interface {
	// Refresh forgets every pidfd and opens one per running om container.
	Refresh()
	// Wait blocks up to 60 s and returns the containers whose process exited and whether the set may have changed.
	Wait() (exited []string, changed bool)
	// Count is the number of containers being watched.
	Count() int
	Close()
}

// Watch is the event loop of `om core watch`: recover a container the moment its process dies unseen. A pidfd per
// container tells the kernel-level truth instantly (no polling); the engine's own event stream and a 60 s backstop
// refresh the set. When a process exits, wait 2 s for the engine to record a normal exit, then restart whatever it
// still lists as running. Linux, local engine only; `om core heal` (every 2 min) remains the fallback elsewhere.
// maxEvents < 0 runs until stopped.
func (c *Core) Watch(runtime string, maxEvents int) int {
	if !(c.GOOS == "linux" && c.NewWatcher != nil && c.Eng.LocalEngine(runtime)) {
		c.p("om core watch needs Linux with local Podman; `om core heal` covers other setups.")
		return 1
	}
	w, err := c.NewWatcher(runtime)
	if err != nil {
		c.p("om core watch: %s", err)
		return 1
	}
	defer w.Close()
	log := func(msg string) { fmt.Fprintf(c.Out, "[%s] %s\n", c.Now().Format("2006-01-02 15:04:05"), msg) }
	w.Refresh()
	c.Eng.ReviveZombies(runtime)
	log(fmt.Sprintf("watching %d container(s)", w.Count()))
	handled := 0
	for maxEvents < 0 || handled < maxEvents {
		exited, changed := w.Wait()
		if len(exited) > 0 {
			c.Sleep(2 * time.Second)
			revived, failed := c.Eng.ReviveZombies(runtime)
			if len(revived) > 0 || len(failed) > 0 {
				msg := "process of " + strings.Join(exited, ", ") + " died unseen; restarted " + pyList(revived)
				if len(failed) > 0 {
					msg += ", failed " + pyList(failed)
				}
				log(msg)
				handled++
			}
			changed = true
		}
		if changed {
			w.Refresh()
		}
	}
	return 0
}

// pyList is Python's str of a list of strings (or "nothing" for an empty one: `revived or 'nothing'`).
func pyList(l []string) string {
	if len(l) == 0 {
		return "nothing"
	}
	q := make([]string, len(l))
	for i, s := range l {
		q[i] = "'" + s + "'"
	}
	return "[" + strings.Join(q, ", ") + "]"
}
