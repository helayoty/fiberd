//go:build linux

package artifact

import (
	"os/exec"
	"strings"
	"syscall"
)

func unameRelease() string {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return "unknown"
	}
	b := make([]byte, 0, len(u.Release))
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

// libcVersion asks the dynamic loader; glibc prints "ldd (GNU libc) 2.36".
func libcVersion() string {
	out, err := exec.Command("ldd", "--version").Output()
	if err != nil {
		return "unknown"
	}
	first := strings.SplitN(string(out), "\n", 2)[0]
	fields := strings.Fields(first)
	if len(fields) == 0 {
		return "unknown"
	}
	return strings.ToLower(strings.Join(fields[1:], " "))
}
