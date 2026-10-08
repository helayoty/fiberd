//go:build linux

package host

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/handoff"
)

// handoffEndpoint is what a handoff fiber is told to serve on. It binds
// nothing, because connections come through fz_accept.
const handoffEndpoint = "handoff"

// identityTag opens the one message a fresh handoff fiber reads from its
// channel before any connection, the grant's TLS identity. A connection
// message is a zero byte with the socket in SCM_RIGHTS, so the two never
// look alike.
const identityTag = 'k'

// handoffIdentity is the identity derived for a grant and the caller its
// fibers accept. It is kept so HandoffRoute has the pin at hand and the
// derivation runs once.
type handoffIdentity struct {
	id     handoff.Identity
	caller string
}

// canHandoff reports whether the backend can pass connections to fibers
// and a router exists to take them from.
func (r *Runtime) canHandoff() bool {
	h, ok := r.be.(backend.Handoffer)
	return ok && h.Handoff() && r.cfg.Handoff != nil
}

// handoffPair makes a handoff fiber's channel. The host keeps the first
// end and the backend hands the second to the fiber. A backend whose fibers
// live in a network namespace of their own makes the pair itself, where
// the fiber's checkpoint can carry it.
func (r *Runtime) handoffPair(grantUID string) (host, fiber *os.File, err error) {
	if !r.canHandoff() {
		return nil, nil, fmt.Errorf("%w: grant %s on backend %s", ErrNoHandoff, grantUID, r.be.Name())
	}
	var fds [2]int
	if cm, ok := r.be.(backend.ChannelMaker); ok {
		fds, err = cm.Socketpair(grantUID, syscall.SOCK_SEQPACKET)
	} else {
		fds, err = syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("host: handoff channel: %w", err)
	}
	return os.NewFile(uintptr(fds[0]), "handoff"), os.NewFile(uintptr(fds[1]), "handoff-fiber"), nil
}

// prepareIdentity derives the grant's TLS identity (once) and records
// the caller its fibers accept, so HandoffRoute can name the pin. It
// writes nothing, because sendIdentity carries the identity to each fiber.
func (r *Runtime) prepareIdentity(grantUID, caller string) error {
	r.mu.Lock()
	had, ok := r.identities[grantUID]
	r.mu.Unlock()
	if !ok {
		id, err := handoff.Derive(r.cfg.HandoffKey, grantUID)
		if err != nil {
			return err
		}
		had = handoffIdentity{id: id}
	}
	had.caller = caller
	r.mu.Lock()
	if r.identities == nil {
		r.identities = map[string]handoffIdentity{}
	}
	r.identities[grantUID] = had
	r.mu.Unlock()
	return nil
}

// forgetIdentity drops a grant's identity when its warm instance ends,
// which takes every fiber of the grant with it. Nothing then needs the
// key, and keeping it would hold the key material of every grant ever
// admitted for the life of the home. The next PrepareTemplate or resume
// derives it again.
func (r *Runtime) forgetIdentity(grantUID string) {
	r.mu.Lock()
	delete(r.identities, grantUID)
	r.mu.Unlock()
}

// identityMessage frames an identity the way fz_handoff_identity parses
// it. That is the tag, then the key PEM, the certificate PEM and the
// caller thumbprint, each ended by a NUL.
func identityMessage(id handoff.Identity, caller string) ([]byte, error) {
	for _, f := range []struct{ name, v string }{{"key", string(id.KeyPEM)}, {"certificate", string(id.CertPEM)}, {"caller", caller}} {
		if f.v == "" || strings.ContainsRune(f.v, 0) {
			return nil, fmt.Errorf("host: handoff identity %s is empty or holds a NUL", f.name)
		}
	}
	var b bytes.Buffer
	b.WriteByte(identityTag)
	for _, v := range [][]byte{id.KeyPEM, id.CertPEM, []byte(caller)} {
		b.Write(v)
		b.WriteByte(0)
	}
	return b.Bytes(), nil
}

// sendIdentity queues a fresh handoff fiber's grant identity on the
// host's end of its channel before the fiber is born, so it is the first
// thing fz_accept reads. A resumed fiber holds it in memory and gets none.
// The key is never a file, because fibers of every grant run as the
// agent's user and no file mode would keep grants apart.
func (r *Runtime) sendIdentity(ch *os.File, grantUID string) error {
	r.mu.Lock()
	had, ok := r.identities[grantUID]
	r.mu.Unlock()
	if !ok {
		return fmt.Errorf("host: no handoff identity prepared for grant %s", grantUID)
	}
	msg, err := identityMessage(had.id, had.caller)
	if err != nil {
		return err
	}
	rc, err := ch.SyscallConn()
	if err != nil {
		return fmt.Errorf("host: handoff identity of %s: %w", grantUID, err)
	}
	var sendErr error
	ctlErr := rc.Control(func(fd uintptr) {
		sendErr = syscall.Sendmsg(int(fd), msg, nil, nil, syscall.MSG_DONTWAIT|syscall.MSG_NOSIGNAL)
	})
	if ctlErr != nil {
		return fmt.Errorf("host: handoff identity of %s: %w", grantUID, ctlErr)
	}
	if sendErr != nil {
		return fmt.Errorf("host: handoff identity of %s: %w", grantUID, sendErr)
	}
	return nil
}

// route gives a ready handoff fiber its routing key and returns the
// endpoint its handle names, which is the router's address.
func (r *Runtime) route(f *fiber) (string, error) {
	if f.handoff == nil || r.cfg.Handoff == nil {
		return f.endpoint, nil
	}
	if _, err := r.cfg.Handoff.Add(f.id); err != nil {
		return "", fmt.Errorf("host: routing key for %s: %w", f.id, err)
	}
	return r.cfg.Handoff.Advertise, nil
}

func (r *Runtime) unroute(f *fiber) {
	if f.handoff != nil && r.cfg.Handoff != nil {
		r.cfg.Handoff.Remove(f.id)
	}
}

// HandsOff implements core.HandoffRouter.
func (r *Runtime) HandsOff() bool { return r.canHandoff() }

// HandoffRoute implements core.HandoffRouter. It returns a handoff
// fiber's routing key and the pin of the key it serves TLS with.
func (r *Runtime) HandoffRoute(fiberID string) (key, pin string, ok bool) {
	if r.cfg.Handoff == nil {
		return "", "", false
	}
	r.mu.Lock()
	f, known := r.fibers[fiberID]
	var id handoffIdentity
	if known {
		id = r.identities[f.grantUID]
	}
	r.mu.Unlock()
	if !known || f.handoff == nil {
		return "", "", false
	}
	key, ok = r.cfg.Handoff.Key(fiberID)
	return key, id.id.KeySHA256, ok
}

// Deliver passes a connected socket to a handoff fiber, which serves it
// from fz_accept. It never blocks, so a full queue is ErrHandoffBusy.
// The caller still owns conn and closes its copy.
func (r *Runtime) Deliver(fiberID string, conn *os.File) error {
	r.mu.Lock()
	var ch *os.File
	if f, ok := r.fibers[fiberID]; ok && f.ready {
		ch = f.handoff
	}
	r.mu.Unlock()
	if ch == nil {
		return fmt.Errorf("%w: %s", ErrNotHandoff, fiberID)
	}
	rc, err := ch.SyscallConn()
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrNotHandoff, fiberID, err)
	}
	var sendErr error
	// Control holds the channel open against a concurrent finish.
	ctlErr := rc.Control(func(fd uintptr) {
		sendErr = syscall.Sendmsg(int(fd), []byte{0}, syscall.UnixRights(int(conn.Fd())), nil, syscall.MSG_DONTWAIT|syscall.MSG_NOSIGNAL)
	})
	switch {
	case ctlErr != nil:
		return fmt.Errorf("%w: %s: %w", ErrNotHandoff, fiberID, ctlErr)
	case errors.Is(sendErr, syscall.EAGAIN):
		return fmt.Errorf("%w: %s", ErrHandoffBusy, fiberID)
	case sendErr != nil:
		return fmt.Errorf("%w: %s: %w", ErrNotHandoff, fiberID, sendErr)
	}
	return nil
}
