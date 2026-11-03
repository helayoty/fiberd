//go:build linux && integration

package systest

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/helayoty/fiberd/pkg/sys/mounts"
)

// cgroupMount is the cgroup v2 mount a container gives fiberd.
const cgroupMount = "/sys/fs/cgroup"

// controlSysctl is a sysctl Prepare must leave as it found it.
const controlSysctl = "/proc/sys/kernel/pid_max"

// mountState is what the probes of one path saw. flags are the mount's
// statfs flags, and open is the error of opening the path for writing,
// nil when that worked.
type mountState struct {
	flags int64
	open  error
}

// probe reads a path's mount flags and opens it for writing without
// writing. The cgroup mount is a directory, so its probe opens
// cgroup.procs of the delegated root instead, which is what the proc
// backend writes.
func probe(path string) mountState {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return mountState{open: err}
	}
	target := path
	if path == cgroupMount {
		target = filepath.Join(cgRoot, "cgroup.procs")
	}
	s := mountState{flags: st.Flags}
	fd, err := unix.Open(target, unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err == nil {
		_ = unix.Close(fd)
	}
	s.open = err
	return s
}

func probeAll(paths []string) map[string]mountState {
	seen := make(map[string]mountState, len(paths))
	for _, p := range paths {
		seen[p] = probe(p)
	}
	return seen
}

// readOnlyBind mounts path over itself read-only with extra flags, the
// way a container runtime masks a path for a Pod without privileges.
func readOnlyBind(t *testing.T, path string, extra uintptr) {
	t.Helper()
	if err := unix.Mount(path, path, "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("bind %s onto itself: %v", path, err)
	}
	if err := unix.Mount("", path, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY|extra, ""); err != nil {
		t.Fatalf("remount %s read-only: %v", path, err)
	}
}

// readOnly reports whether a probe found the mount read-only both ways,
// by its flags and by the open.
func readOnly(s mountState) bool {
	return s.flags&unix.ST_RDONLY != 0 && errors.Is(s.open, unix.EROFS)
}

// writable reports whether a probe found the mount writable both ways.
func writable(s mountState) bool {
	return s.flags&unix.ST_RDONLY == 0 && s.open == nil
}

// TestPrepareMounts runs Prepare under the mounts an unprivileged Pod
// gets, a read-only bind of /sys/fs/cgroup and of /proc/sys, and checks
// that it opens the cgroup mount and the CRIU sysctls, nothing else, and
// that a second run changes nothing.
//
// A mount namespace belongs to the thread that unshared it, and the Go
// scheduler moves goroutines between threads, so the test locks its
// goroutine to one thread, enters a private namespace there and never
// unlocks. The runtime lets a locked thread die with its goroutine when
// the test returns rather than hand it to another goroutine, and the
// namespace goes with it. Every mount and every probe runs on that
// thread. The subtests only compare what the probes saw, because a
// subtest's goroutine runs on some other thread, outside the namespace.
func TestPrepareMounts(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to shape a mount namespace")
	}
	if cgRoot != cgroupMount && !strings.HasPrefix(cgRoot, cgroupMount+"/") {
		t.Skipf("the delegated cgroup root %s is not under %s", cgRoot, cgroupMount)
	}
	runtime.LockOSThread()
	if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
		t.Skipf("cannot make a mount namespace: %v", err)
	}
	// Nothing mounted here may reach the namespace the suite runs in.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatalf("make / private: %v", err)
	}
	readOnlyBind(t, cgroupMount, unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC)
	readOnlyBind(t, "/proc/sys", 0)

	paths := append([]string{cgroupMount, controlSysctl}, mounts.CRIUSysctls...)
	before := probeAll(paths)
	firstErr := mounts.Prepare()
	after := probeAll(paths)
	secondErr := mounts.Prepare()
	again := probeAll(paths)

	t.Run("a Pod's mounts start read-only", func(t *testing.T) {
		for _, p := range paths {
			if !readOnly(before[p]) {
				t.Errorf("%s before Prepare = %+v, want read-only", p, before[p])
			}
		}
	})
	t.Run("the first Prepare succeeds", func(t *testing.T) {
		if firstErr != nil {
			t.Fatalf("Prepare = %v, want nil", firstErr)
		}
	})
	t.Run("the cgroup mount is writable and keeps nosuid, nodev and noexec", func(t *testing.T) {
		s := after[cgroupMount]
		if !writable(s) {
			t.Fatalf("%s after Prepare = %+v, want writable", cgroupMount, s)
		}
		const keep = unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC
		if s.flags&keep != keep {
			t.Fatalf("%s flags = %#x, want nosuid, nodev and noexec kept", cgroupMount, s.flags)
		}
	})
	t.Run("each CRIU sysctl is writable", func(t *testing.T) {
		for _, p := range mounts.CRIUSysctls {
			if !writable(after[p]) {
				t.Errorf("%s after Prepare = %+v, want writable", p, after[p])
			}
		}
	})
	t.Run("the rest of /proc/sys stays read-only", func(t *testing.T) {
		if !readOnly(after[controlSysctl]) {
			t.Fatalf("%s after Prepare = %+v, want read-only", controlSysctl, after[controlSysctl])
		}
	})
	t.Run("a second Prepare changes nothing", func(t *testing.T) {
		if secondErr != nil {
			t.Fatalf("second Prepare = %v, want nil", secondErr)
		}
		for _, p := range paths {
			if again[p] != after[p] {
				t.Errorf("%s after the second Prepare = %+v, want %+v", p, again[p], after[p])
			}
		}
	})
}
