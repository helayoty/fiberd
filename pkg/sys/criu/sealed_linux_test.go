//go:build linux

package criu_test

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// sealedFile puts a file with the given contents at path that reads
// fine and refuses every write, even root's. It is a write-sealed memfd
// reached through a symlink into /proc/self/fd.
func sealedFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	// x/sys/unix, because the standard syscall package has no
	// SYS_MEMFD_CREATE on amd64.
	fd, err := unix.MemfdCreate(filepath.Base(path), unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatalf("memfd_create: %v", err)
	}
	f := os.NewFile(uintptr(fd), path)
	t.Cleanup(func() { _ = f.Close() })
	if _, err := f.Write(contents); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_SEAL); err != nil {
		t.Fatalf("seal the memfd: %v", err)
	}
	if err := os.Symlink("/proc/self/fd/"+strconv.Itoa(fd), path); err != nil {
		t.Fatal(err)
	}
}
