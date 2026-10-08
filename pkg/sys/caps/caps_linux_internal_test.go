//go:build linux

package caps

import (
	"errors"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// threadInheritable is the calling thread's inheritable set, read from
// /proc/thread-self/status.
func threadInheritable(t *testing.T) uint64 {
	t.Helper()
	b, err := os.ReadFile("/proc/thread-self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if val, ok := strings.CutPrefix(line, "CapInh:"); ok {
			v, err := strconv.ParseUint(strings.TrimSpace(val), 16, 64)
			if err != nil {
				t.Fatal(err)
			}
			return v
		}
	}
	t.Fatal("no CapInh line")
	return 0
}

// raiseInheritable sets the calling thread's inheritable set to mask
// with capset(2), which needs the capabilities in the permitted set and
// CAP_SETPCAP.
func raiseInheritable(mask uint64) error {
	hdr := capHeader{version: capabilityVersion3}
	var data [2]capData
	if _, _, errno := syscall.RawSyscall(syscall.SYS_CAPGET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); errno != 0 {
		return errno
	}
	data[0].inheritable = uint32(mask)
	data[1].inheritable = uint32(mask >> 32)
	if _, _, errno := syscall.RawSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); errno != 0 {
		return errno
	}
	return nil
}

// TestMaskInheritable checks that on one locked thread the inheritable set is
// cut to keep and nothing else about it changes. Narrow does this just before
// it execs, so it cannot be watched from the API.
func TestMaskInheritable(t *testing.T) {
	cases := []struct {
		name  string
		raise uint64 // the inheritable set before
		keep  []int
		want  uint64
	}{
		{name: "nothing kept clears it", raise: 1<<Chown | 1<<Kill, keep: nil, want: 0},
		{name: "kept capabilities stay", raise: 1<<Chown | 1<<Kill | 1<<SysAdmin, keep: []int{Kill, SysAdmin}, want: 1<<Kill | 1<<SysAdmin},
		{name: "keep beyond the set adds nothing", raise: 1 << Chown, keep: []int{Chown, SysTime}, want: 1 << Chown},
		{name: "an empty set stays empty", raise: 0, keep: Proc, want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			if err := raiseInheritable(tc.raise); err != nil {
				if errors.Is(err, syscall.EPERM) {
					t.Skipf("cannot raise the inheritable set: %v", err)
				}
				t.Fatal(err)
			}
			defer func() {
				if err := raiseInheritable(0); err != nil {
					t.Errorf("restore the inheritable set: %v", err)
				}
			}()
			if got := threadInheritable(t); got != tc.raise {
				t.Fatalf("inheritable set before = %#x, want %#x", got, tc.raise)
			}
			if err := maskInheritable(tc.keep); err != nil {
				t.Fatal(err)
			}
			if got := threadInheritable(t); got != tc.want {
				t.Fatalf("inheritable set after = %#x, want %#x", got, tc.want)
			}
		})
	}
}
