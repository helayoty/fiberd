// Package mounts prepares what a container mounts read-only before fiberd
// builds its runtime. A Pod without privileges gets /sys/fs/cgroup and
// /proc/sys read-only from its container runtime. Every host runtime makes
// cgroup leaves under the first, and CRIU writes four kernel sysctls under
// the second to give a restored fiber the pids and IPC ids it had.
//
// cmd/fiberd calls Prepare at startup before narrowing capabilities, for
// every runtime but the stub, so no home has to prepare anything. Prepare touches only a mount
// it finds read-only. On a standalone host it does nothing, and after a
// success a second call does nothing either.
package mounts

import (
	"errors"
	"fmt"
	"strings"
)

// CRIUSysctls are the kernel sysctls CRIU writes during a restore. The
// first pins the next pid, the others the next System V IPC ids, so a
// restored fiber gets back the identifiers it was dumped with.
var CRIUSysctls = []string{
	"/proc/sys/kernel/ns_last_pid",
	"/proc/sys/kernel/msg_next_id",
	"/proc/sys/kernel/sem_next_id",
	"/proc/sys/kernel/shm_next_id",
}

// ErrSysctlsReadOnly is in the error Prepare returns when a CRIU sysctl
// could not be made writable. The cgroup mount is ready by then, so
// fiberd can start, and the proc backend offers the warm tier alone.
var ErrSysctlsReadOnly = errors.New("mounts: the CRIU sysctls stayed read-only")

// Mount flag bits, as the kernel's uapi defines them. They are stated
// here rather than taken from a platform package so that this file builds
// everywhere. mounts_linux.go checks each against the kernel's value at
// compile time.
const (
	flagRdonly  = 0x1
	flagNosuid  = 0x2
	flagNodev   = 0x4
	flagNoexec  = 0x8
	flagRemount = 0x20
	flagBind    = 0x1000
)

// cgroupRemountFlags turns a read-only cgroup mount read-write. The
// read-only bit of a bind mount belongs to that mount point, not to the
// filesystem behind it. A remount that also passes the bind flag changes
// the mount point's own bits and leaves the filesystem's alone, so the
// bit goes away exactly where the container set it. Such a remount
// replaces every per-mount bit with what it is given, and the container
// set nosuid, nodev and noexec for a reason, so those are restated.
const cgroupRemountFlags = flagRemount | flagBind | flagNosuid | flagNodev | flagNoexec

// A mounter is what prepare needs of the kernel. On Linux it is mount(2)
// and statfs(2). Tests use a fake.
type mounter interface {
	// Mount is mount(2), with its arguments in the kernel's order.
	Mount(source, target, fstype string, flags uintptr, data string) error
	// ReadOnly reports whether the mount holding path is read-only.
	ReadOnly(path string) (bool, error)
}

// prepare is Prepare over m. The cgroup mount comes first, and a failure
// there is returned at once. Every sysctl is then tried, and their
// failures come back together, wrapped in ErrSysctlsReadOnly.
func prepare(m mounter, cgroup string, sysctls []string) error {
	ro, err := m.ReadOnly(cgroup)
	if err != nil {
		return fmt.Errorf("mounts: check %s: %w", cgroup, err)
	}
	if ro {
		if err := m.Mount("", cgroup, "", cgroupRemountFlags, ""); err != nil {
			return fmt.Errorf("mounts: remount %s read-write: %w", cgroup, err)
		}
	}
	var failed sysctlErrors
	for _, path := range sysctls {
		if err := prepareSysctl(m, path); err != nil {
			failed = append(failed, err)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("%w: %w", ErrSysctlsReadOnly, failed)
	}
	return nil
}

// prepareSysctl makes one sysctl file writable. /proc/sys is one
// read-only bind mount over a part of proc, and a sysctl file is no mount
// of its own, so a remount of /proc/sys would open every sysctl in it.
// Binding the file onto itself gives that one file a mount point of its
// own, and the remount that follows drops the read-only bit on that
// mount point alone. The bind is not enough by itself, because a new
// bind mount starts with the bits of the mount it was made from.
func prepareSysctl(m mounter, path string) error {
	ro, err := m.ReadOnly(path)
	if err != nil {
		return fmt.Errorf("check %s: %w", path, err)
	}
	if !ro {
		return nil
	}
	if err := m.Mount(path, path, "", flagBind, ""); err != nil {
		return fmt.Errorf("bind %s onto itself: %w", path, err)
	}
	if err := m.Mount("", path, "", flagRemount|flagBind, ""); err != nil {
		return fmt.Errorf("remount %s read-write: %w", path, err)
	}
	return nil
}

// sysctlErrors are the sysctl failures of one prepare. They print on one
// line, and each stays reachable through errors.Is.
type sysctlErrors []error

func (e sysctlErrors) Error() string {
	msgs := make([]string, len(e))
	for i, err := range e {
		msgs[i] = err.Error()
	}
	return strings.Join(msgs, ", ")
}

func (e sysctlErrors) Unwrap() []error { return e }
