//go:build linux

package artifact

import (
	"os/exec"
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

// libcVersion asks the dynamic loader.
func libcVersion() string {
	return parseLdd(exec.Command("ldd", "--version").Output())
}
