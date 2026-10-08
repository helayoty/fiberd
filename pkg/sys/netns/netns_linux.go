//go:build linux

// Package netns runs small pieces of work inside another process's
// network namespace. A unix socket belongs to the namespace it was
// created in, and criu only finds the sockets of the namespaces it
// dumps, so a channel the agent shares with a tree inside a container
// has to be made in the container's namespace. The agent is root in the
// initial user namespace, which may enter every namespace below it.
package netns

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Do runs fn on an OS thread switched into the network namespace of
// pid, then switches the thread back. The thread is locked to the
// goroutine throughout. Should switching back fail, the thread is left
// locked to a goroutine that ends, which makes the runtime discard it
// rather than hand a thread in the wrong namespace to other goroutines.
func Do(pid int, fn func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		self, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			runtime.UnlockOSThread()
			errc <- err
			return
		}
		defer func() { _ = self.Close() }()
		target, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", pid))
		if err != nil {
			runtime.UnlockOSThread()
			errc <- err
			return
		}
		err = setns(target)
		_ = target.Close()
		if err != nil {
			runtime.UnlockOSThread()
			errc <- fmt.Errorf("netns: enter the network namespace of %d: %w", pid, err)
			return
		}
		ferr := fn()
		if err := setns(self); err != nil {
			errc <- fmt.Errorf("netns: return from the network namespace of %d: %w (thread discarded)", pid, err)
			return
		}
		runtime.UnlockOSThread()
		errc <- ferr
	}()
	return <-errc
}

// setns uses x/sys/unix, because the standard syscall package has no
// SYS_SETNS on every architecture (amd64 lacks it).
func setns(f *os.File) error {
	return unix.Setns(int(f.Fd()), unix.CLONE_NEWNET)
}

// Socketpair makes a unix socket pair of the given type (SOCK_STREAM,
// SOCK_SEQPACKET) in the network namespace of pid, close-on-exec.
func Socketpair(pid, typ int) ([2]int, error) {
	var fds [2]int
	err := Do(pid, func() error {
		var err error
		fds, err = syscall.Socketpair(syscall.AF_UNIX, typ|syscall.SOCK_CLOEXEC, 0)
		return err
	})
	if err != nil {
		return [2]int{-1, -1}, err
	}
	return fds, nil
}

// ifreq is struct ifreq for SIOCGIFFLAGS and SIOCSIFFLAGS, the name and
// the flags of the union that follows it.
type ifreq struct {
	name  [16]byte
	flags uint16
	_     [22]byte
}

// LoopbackUp brings the loopback interface up in the network namespace
// of pid. A namespace criu creates empty has it down.
func LoopbackUp(pid int) error {
	return Do(pid, func() error {
		s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer func() { _ = syscall.Close(s) }()
		var r ifreq
		copy(r.name[:], "lo")
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(s), syscall.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&r))); errno != 0 {
			return fmt.Errorf("netns: flags of lo: %w", errno)
		}
		if r.flags&syscall.IFF_UP != 0 {
			return nil
		}
		r.flags |= syscall.IFF_UP | syscall.IFF_RUNNING
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(s), syscall.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&r))); errno != 0 {
			return fmt.Errorf("netns: bring lo up: %w", errno)
		}
		return nil
	})
}
