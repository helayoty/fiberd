//go:build linux && integration

package testenv

import (
	"runtime"
	"testing"
)

// filterProbes are refzygote's "probe <name>" commands with the answer
// a fiber under the fiber filter gives. The refused classes come first,
// then the neighbours the filter lets through.
var filterProbes = []struct {
	probe, want string
	amd64       bool // the x32 table exists on x86_64 alone
}{
	{probe: "unshare-user", want: "EPERM"},
	{probe: "unshare-net", want: "EPERM"},
	{probe: "clone-newuser", want: "EPERM"},
	{probe: "setns", want: "EPERM"},
	{probe: "clone3", want: "ENOSYS"},
	{probe: "af-alg", want: "EAFNOSUPPORT"},
	{probe: "af-packet", want: "EAFNOSUPPORT"},
	{probe: "af-vsock", want: "EAFNOSUPPORT"},
	{probe: "netlink-sock-diag", want: "EPROTONOSUPPORT"},
	{probe: "netlink-audit", want: "EPROTONOSUPPORT"},
	{probe: "personality-uname26", want: "EPERM"},
	{probe: "io-uring", want: "EPERM"},
	{probe: "userfaultfd", want: "EPERM"},
	{probe: "bpf", want: "EPERM"},
	{probe: "perf", want: "EPERM"},
	{probe: "keyctl", want: "EPERM"},
	{probe: "memfd-secret", want: "EPERM"},
	{probe: "ptrace", want: "EPERM"},
	{probe: "process-vm-readv", want: "EPERM"},
	{probe: "kcmp", want: "EPERM"},
	{probe: "pidfd-getfd", want: "EPERM"},
	{probe: "syslog", want: "EPERM"},
	{probe: "sethostname", want: "EPERM"},
	{probe: "x32", want: "SIGSYS", amd64: true},
	{probe: "unshare-fs", want: "ok"},
	{probe: "af-unix", want: "ok"},
	{probe: "af-inet", want: "ok"},
	{probe: "af-inet6", want: "ok"},
	{probe: "netlink-route", want: "ok"},
	{probe: "netlink-generic", want: "ok"},
	{probe: "personality-query", want: "ok"},
	{probe: "thread", want: "ok"},
}

// CheckFilter asks a fiber, through ask, to try every probe and checks
// each answer, one subtest per probe under when. ask sends one line to
// the fiber and returns its reply.
func CheckFilter(t *testing.T, when string, ask func(t *testing.T, line string) string) {
	t.Helper()
	for _, p := range filterProbes {
		t.Run(when+"/"+p.probe, func(t *testing.T) {
			if p.amd64 && runtime.GOARCH != "amd64" {
				t.Skipf("%s needs amd64", p.probe)
			}
			if got := ask(t, "probe "+p.probe); got != p.want {
				t.Errorf("probe %s = %q, want %q", p.probe, got, p.want)
			}
		})
	}
}
