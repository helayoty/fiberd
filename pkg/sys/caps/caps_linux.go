//go:build linux

package caps

import (
	"fmt"
	"os"
	"runtime"
	"slices"
	"syscall"
	"unsafe"
)

// Extra lists, ascending, the capabilities outside keep that this process
// holds in its bounding set, or in its inheritable or ambient set (read
// from /proc/self/status). The last two matter because a binary with
// inheritable file capabilities, or an ambient set, carries them through
// exec whatever the bounding set says about everything else.
func Extra(keep []int) []int {
	extra := boundingExtra(keep)
	if b, err := os.ReadFile("/proc/self/status"); err == nil {
		if inh, amb, err := statusCaps(string(b)); err == nil {
			for _, c := range outside(inh|amb, keep) {
				if !slices.Contains(extra, c) {
					extra = append(extra, c)
				}
			}
		}
	}
	slices.Sort(extra)
	return extra
}

// boundingExtra lists the capabilities in the bounding set outside keep.
func boundingExtra(keep []int) []int {
	var extra []int
	for c := 0; ; c++ {
		r, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_CAPBSET_READ, uintptr(c), 0)
		if errno != 0 {
			return extra
		}
		if r == 1 && !slices.Contains(keep, c) {
			extra = append(extra, c)
		}
	}
}

// Narrow re-executes the process with only keep in its bounding set, its
// inheritable set masked to keep and its ambient set emptied.
// Capabilities are per thread and the Go runtime runs several, so one
// locked thread narrows its sets and then execs, and the new process
// starts with them on every thread. Call it first in main, before anything
// that must not run twice. It returns nil without exec when nothing
// outside keep is held. It never adds a capability, and leaves the
// effective and permitted sets as they are.
func Narrow(keep []int) error {
	if len(Extra(keep)) == 0 {
		return nil
	}
	// The thread stays locked on every path but the first-drop refusal,
	// because the others exec or exit.
	runtime.LockOSThread()
	for i, c := range boundingExtra(keep) {
		if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_CAPBSET_DROP, uintptr(c), 0); errno != 0 {
			if i == 0 && errno == syscall.EPERM {
				runtime.UnlockOSThread()
				return ErrCannotNarrow
			}
			// Part of this thread's set is gone, and carrying on would
			// leave threads that disagree.
			fmt.Fprintf(os.Stderr, "caps: drop capability %d: %v\n", c, errno)
			os.Exit(1)
		}
	}
	// Lowering the inheritable set needs no capability, and the ambient
	// set is a subset of it. A kernel without ambient capabilities
	// answers EINVAL, which leaves nothing to clear.
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prCapAmbient, prCapAmbientClearAll, 0); errno != 0 && errno != syscall.EINVAL {
		fmt.Fprintf(os.Stderr, "caps: clear the ambient set: %v\n", errno)
		os.Exit(1)
	}
	if err := maskInheritable(keep); err != nil {
		fmt.Fprintf(os.Stderr, "caps: narrow the inheritable set: %v\n", err)
		os.Exit(1)
	}
	if err := syscall.Exec("/proc/self/exe", os.Args, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "caps: re-exec with narrowed capabilities: %v\n", err)
		os.Exit(1)
	}
	return nil
}

// prctl(2) and capget(2) constants not in package syscall.
const (
	prCapAmbient         = 47
	prCapAmbientClearAll = 4
	capabilityVersion3   = 0x20080522 // _LINUX_CAPABILITY_VERSION_3, two 32-bit words per set
)

type capHeader struct {
	version uint32
	pid     int32
}

type capData struct {
	effective, permitted, inheritable uint32
}

// maskInheritable clears from the calling thread's inheritable set every
// capability keep does not name. The effective and permitted sets are
// written back as read.
func maskInheritable(keep []int) error {
	hdr := capHeader{version: capabilityVersion3}
	var data [2]capData
	if _, _, errno := syscall.RawSyscall(syscall.SYS_CAPGET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); errno != 0 {
		return fmt.Errorf("capget: %w", errno)
	}
	inh := (uint64(data[0].inheritable) | uint64(data[1].inheritable)<<32) & keepMask(keep)
	data[0].inheritable = uint32(inh)
	data[1].inheritable = uint32(inh >> 32)
	if _, _, errno := syscall.RawSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); errno != 0 {
		return fmt.Errorf("capset: %w", errno)
	}
	return nil
}
