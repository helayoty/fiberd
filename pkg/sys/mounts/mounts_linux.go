//go:build linux

package mounts

import "golang.org/x/sys/unix"

// The flag bits in mounts.go must be the kernel's. A line here fails to
// compile when its bit differs.
var (
	_ = [1]struct{}{}[flagRdonly-unix.MS_RDONLY]
	_ = [1]struct{}{}[flagNosuid-unix.MS_NOSUID]
	_ = [1]struct{}{}[flagNodev-unix.MS_NODEV]
	_ = [1]struct{}{}[flagNoexec-unix.MS_NOEXEC]
	_ = [1]struct{}{}[flagRemount-unix.MS_REMOUNT]
	_ = [1]struct{}{}[flagBind-unix.MS_BIND]
)

// cgroupMount is the cgroup v2 mount a container gives fiberd.
const cgroupMount = "/sys/fs/cgroup"

// Prepare makes the cgroup v2 mount at /sys/fs/cgroup and each file in
// CRIUSysctls writable where the container left them read-only, and
// leaves what is already writable alone. It needs CAP_SYS_ADMIN in its
// mount namespace. A cgroup failure is returned at once. Every sysctl is
// tried, and their failures are returned together, wrapped in
// ErrSysctlsReadOnly.
func Prepare() error { return prepare(kernel{}, cgroupMount, CRIUSysctls) }

// kernel is the mounter over the real system calls.
type kernel struct{}

func (kernel) Mount(source, target, fstype string, flags uintptr, data string) error {
	return unix.Mount(source, target, fstype, flags, data)
}

// ReadOnly asks statfs(2). The read-only bit it reports is the mount
// point's own, so a read-only bind mount of a writable filesystem counts
// as read-only, which is the case a container makes.
func (kernel) ReadOnly(path string) (bool, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return false, err
	}
	return st.Flags&unix.ST_RDONLY != 0, nil
}
