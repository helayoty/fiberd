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
// inc with no fence queues nothing, which is a resume's channel. The
// record and the seed are cleared once sent.
func Channel(make func(typ int) ([2]int, error), inc Incarnation) (host, fiber *os.File, err error) {
	if make == nil {
		make = func(typ int) ([2]int, error) { return syscall.Socketpair(syscall.AF_UNIX, typ|syscall.SOCK_CLOEXEC, 0) }
	}
	fds, err := make(syscall.SOCK_SEQPACKET)
	if err != nil {
		return nil, nil, fmt.Errorf("backend: channel: %w", err)
	}
	host, fiber = os.NewFile(uintptr(fds[0]), "channel"), os.NewFile(uintptr(fds[1]), "channel-fiber")
	if inc.Fence == "" {
		return host, fiber, nil
	}
	if err := queue(fds[0], inc); err != nil {
		_ = host.Close()
		_ = fiber.Close()
		return nil, nil, err
	}
	return host, fiber, nil
}

// queue frames inc with a fresh seed and sends it on fd without
// blocking, the one message a fiber reads before anything else.
func queue(fd int, inc Incarnation) error {
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
