package probe

import "syscall"

// rawForge reports whether the container may open a raw IP socket (to forge source addresses).
func rawForge() string {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return "blocked"
	}
	syscall.Close(fd)
	return "open"
}
