//go:build linux

package agent

import (
	"os"
	"syscall"
	"testing"
)

// readOnlyDir makes dir a directory on a read-only bind mount of itself,
// so even root cannot change its mode. It skips unless root.
func readOnlyDir(t *testing.T, dir string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to mount (run it with hack/dev/run.sh)")
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount(dir, dir, "", syscall.MS_BIND, ""); err != nil {
		t.Skipf("bind mount: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Unmount(dir, syscall.MNT_DETACH) })
	if err := syscall.Mount("", dir, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY, ""); err != nil {
		t.Skipf("read-only remount: %v", err)
	}
}
