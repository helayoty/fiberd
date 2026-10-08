//go:build linux

package host

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// dialFiberSocket connects to the unix socket at path without following
// a link planted in its place. The fiber writes its grant's run directory,
// so the name could be a symlink to another grant's socket, the agent's
// own, or a container runtime's, and a dial by name would splice the
// caller there. The name is opened relative to its directory with no
// symlink resolution at all (openat2 where the kernel has it, else a
// one-component openat with O_NOFOLLOW), the descriptor is checked to be
// a socket, and the connect goes through /proc/self/fd, which names that
// inode and nothing the fiber can rename.
func dialFiberSocket(path string, timeout time.Duration) (net.Conn, error) {
	dir, err := unix.Open(filepath.Dir(path), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", filepath.Dir(path), err)
	}
	defer func() { _ = unix.Close(dir) }()
	name := filepath.Base(path)
	fd, err := unix.Openat2(dir, name, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_BENEATH,
	})
	if errors.Is(err, unix.ENOSYS) {
		fd, err = unix.Openat(dir, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return nil, fmt.Errorf("%s is not a socket (mode %#o)", path, st.Mode&unix.S_IFMT)
	}
	d := net.Dialer{Timeout: timeout}
	return d.Dial("unix", fmt.Sprintf("/proc/self/fd/%d", fd))
}
