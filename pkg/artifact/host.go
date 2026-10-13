package artifact

import (
	"runtime"
	"strings"
)

// HostInfo fills the parity fields for the running host.
func HostInfo() (arch, kernel, libc string) {
	return runtime.GOARCH, unameRelease(), libcVersion()
}

// Complete returns p with the Arch, Kernel and Libc it leaves empty
// detected on this host. A platform that names all three is returned as
// is, so no detection runs for it. That is the seam a unit test uses,
// because the libc comes from ldd on Linux.
func (p Platform) Complete() Platform {
	if p.Arch != "" && p.Kernel != "" && p.Libc != "" {
		return p
	}
	return detect(p)
}

// detect fills the empty facts of p from this host, one at a time, so a
// platform that names its libc never runs ldd. It is a variable so the
// package's own tests can stand in for the host.
var detect = func(p Platform) Platform {
	if p.Arch == "" {
		p.Arch = runtime.GOARCH
	}
	if p.Kernel == "" {
		p.Kernel = unameRelease()
	}
	if p.Libc == "" {
		p.Libc = libcVersion()
	}
	return p
}

// parseLdd reads the libc out of what `ldd --version` printed, whose
// first line glibc writes as "ldd (GNU libc) 2.36". An ldd that failed,
// as musl's does, or printed nothing leaves the libc unknown.
func parseLdd(out []byte, err error) string {
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
