//go:build linux

package artifact

import (
	"context"
	"syscall"

	"github.com/Azure/fiberd/pkg/sys/helper"
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
func libcVersion() string { return LibcVersion("ldd") }

// LibcVersion is the libc the ldd called bin names.
func LibcVersion(bin string) string {
	return parseLdd(helper.Command(context.Background(), bin, "--version").Output())
}
