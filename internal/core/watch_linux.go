//go:build linux

package core

import (
	"fmt"
	"os/exec"
	"syscall"

	"github.com/Chitakasa/om/internal/engine"
)

const sysPidfdOpen = 434 // the same number on every architecture since Linux 5.3

type linuxWatcher struct {
	eng     *engine.Engine
	runtime string
	epfd    int
	fds     map[int]string // pidfd -> container name
	events  *exec.Cmd
	evFd    int
}

// NewLinuxWatcher builds the pidfd/epoll watcher.
func NewLinuxWatcher(eng *engine.Engine) func(runtime string) (Watcher, error) {
	return func(runtime string) (Watcher, error) {
		if _, _, errno := syscall.Syscall(sysPidfdOpen, 0, 0, 0); errno == syscall.ENOSYS {
			return nil, fmt.Errorf("this kernel has no pidfd_open")
		}
		epfd, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
		if err != nil {
			return nil, err
		}
		w := &linuxWatcher{eng: eng, runtime: runtime, epfd: epfd, fds: map[int]string{}}
		if err := w.openEvents(); err != nil {
			syscall.Close(epfd)
			return nil, err
		}
		return w, nil
	}
}

func (w *linuxWatcher) openEvents() error {
	cmd := exec.Command(w.runtime, "events", "--filter", "type=container", "--format", "{{.Status}}")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	f := out.(interface{ Fd() uintptr })
	w.events, w.evFd = cmd, int(f.Fd())
	ev := syscall.EpollEvent{Events: syscall.EPOLLIN | syscall.EPOLLHUP, Fd: int32(w.evFd)}
	return syscall.EpollCtl(w.epfd, syscall.EPOLL_CTL_ADD, w.evFd, &ev)
}

func (w *linuxWatcher) Refresh() {
	for fd := range w.fds {
		syscall.EpollCtl(w.epfd, syscall.EPOLL_CTL_DEL, fd, nil)
		syscall.Close(fd)
	}
	w.fds = map[int]string{}
	for pid, name := range w.eng.OMPids(w.runtime) {
		fd, _, errno := syscall.Syscall(sysPidfdOpen, uintptr(pid), 0, 0)
		if errno != 0 {
			continue // already gone: ReviveZombies handles it
		}
		ev := syscall.EpollEvent{Events: syscall.EPOLLIN, Fd: int32(fd)}
		if syscall.EpollCtl(w.epfd, syscall.EPOLL_CTL_ADD, int(fd), &ev) != nil {
			syscall.Close(int(fd))
			continue
		}
		w.fds[int(fd)] = name
	}
}

func (w *linuxWatcher) Wait() ([]string, bool) {
	events := make([]syscall.EpollEvent, 16)
	var n int
	for {
		var err error
		n, err = syscall.EpollWait(w.epfd, events, 60000)
		if err == syscall.EINTR {
			continue
		}
		break
	}
	if n <= 0 {
		return nil, true // the 60 s backstop
	}
	var exited []string
	changed := false
	for _, e := range events[:n] {
		fd := int(e.Fd)
		switch {
		case fd == w.evFd:
			buf := make([]byte, 4096)
			if r, _ := syscall.Read(fd, buf); r <= 0 { // the event stream ended
				syscall.EpollCtl(w.epfd, syscall.EPOLL_CTL_DEL, fd, nil)
				w.events.Process.Kill()
				w.events.Wait()
				w.openEvents()
			}
			changed = true
		default:
			if name, ok := w.fds[fd]; ok {
				exited = append(exited, name)
			}
		}
	}
	return exited, changed
}

func (w *linuxWatcher) Count() int { return len(w.fds) }

func (w *linuxWatcher) Close() {
	for fd := range w.fds {
		syscall.Close(fd)
	}
	if w.events != nil && w.events.Process != nil {
		w.events.Process.Kill()
		w.events.Wait()
	}
	syscall.Close(w.epfd)
}
