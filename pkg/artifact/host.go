package artifact

import (
	"runtime"
	"strings"
)

// HostInfo fills the parity fields for the running host.
func HostInfo() (arch, kernel, libc string) {
	return runtime.GOARCH, unameRelease(), libcVersion()
}

// hostInfo is what Build and Host record about this host. It is a
// variable because HostInfo runs ldd on Linux, which a unit test stands
// in for.
var hostInfo = HostInfo

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
