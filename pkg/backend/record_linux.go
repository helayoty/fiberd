//go:build linux

package backend

import (
	"crypto/rand"
	"fmt"
	"os"
	"syscall"
)

// Channel makes a fiber's channel, a SOCK_SEQPACKET pair, with inc
// queued on the host's end as the fiber's incarnation record, a fresh
// seed drawn here. make makes the pair where the fiber's checkpoint can
// carry it, and nil is plain socketpair(2) in the host's namespace. An
// inc with no fence queues nothing. The record and the seed are cleared
// once sent.
func Channel(make func(typ int) ([2]int, error), inc Incarnation) (host, fiber *os.File, err error) {
	fds, err := ChannelFDs(make, inc)
	if err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(fds[0]), "channel"), os.NewFile(uintptr(fds[1]), "channel-fiber"), nil
}

// ChannelFDs is Channel as bare descriptors, the host's end first, for
// a clone that passes the fiber's end on and closes both: wrapping
// them costs a system call each.
func ChannelFDs(make func(typ int) ([2]int, error), inc Incarnation) ([2]int, error) {
	if make == nil {
		make = func(typ int) ([2]int, error) { return syscall.Socketpair(syscall.AF_UNIX, typ|syscall.SOCK_CLOEXEC, 0) }
	}
	fds, err := make(syscall.SOCK_SEQPACKET)
	if err != nil {
		return [2]int{-1, -1}, fmt.Errorf("backend: channel: %w", err)
	}
	if inc.Fence == "" {
		return fds, nil
	}
	if err := Queue(fds[0], inc); err != nil {
		_ = syscall.Close(fds[0])
		_ = syscall.Close(fds[1])
		return [2]int{-1, -1}, err
	}
	return fds, nil
}

// Queue frames inc with a fresh seed drawn here and sends it on fd
// without blocking: the first message a fiber reads at birth, and the
// one a resumed fiber polls off its channel. The record and the seed
// are cleared once sent.
func Queue(fd int, inc Incarnation) error {
	seed := make([]byte, SeedBytes)
	if _, err := rand.Read(seed); err != nil {
		return fmt.Errorf("backend: seed of %s: %w", inc.Fence, err)
	}
	inc.Seed = seed
	rec, err := inc.Record()
	clear(seed)
	if err != nil {
		return err
	}
	defer clear(rec)
	if err := syscall.Sendmsg(fd, rec, nil, nil, syscall.MSG_DONTWAIT|syscall.MSG_NOSIGNAL); err != nil {
		return fmt.Errorf("backend: record of %s: %w", inc.Fence, err)
	}
	return nil
}
