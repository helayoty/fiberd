//go:build linux

package host

import (
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/handoff"
)

// handoffEndpoint is what a handoff fiber is told to serve on. It binds
// nothing, because connections come through fz_accept.
const handoffEndpoint = "handoff"

// handoffIdentity is the identity derived for a grant and the caller its
// fibers accept. It is kept so HandoffRoute has the pin at hand and the
// derivation runs once.
type handoffIdentity struct {
	id     handoff.Identity
	caller string
}

// channels reports whether the backend hands every fiber its
// incarnation record on a channel at birth, which a handoff fiber keeps
// for its connections (backend.Fiber.Channel).
func (r *Runtime) channels() bool {
	h, ok := r.be.(backend.Handoffer)
	return ok && h.Handoff()
}

// canHandoff reports whether the backend can pass connections to fibers
// and a router exists to take them from.
func (r *Runtime) canHandoff() bool {
	return r.channels() && r.cfg.Handoff != nil
}

// prepareIdentity derives the grant's TLS identity (once) and records
// the caller its fibers accept, so HandoffRoute can name the pin. It
// writes nothing, because identityFor puts the identity on each fiber's record.
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

// identityFor is the grant's TLS identity for a handoff fiber's record,
// the key PEM, the certificate PEM, the caller thumbprint and the
// caller's certificate as PEM. callerCert is the DER the clone arrived
// under, which the thumbprint is of. A fiber pins that one certificate
// in its handshake. The identity is never a file, because fibers of
// every grant run as fiberd's user and no file mode would keep grants
// apart.
func (r *Runtime) identityFor(grantUID string, callerCert []byte) (*backend.Identity, error) {
	r.mu.Lock()
	had, ok := r.identities[grantUID]
	r.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("host: no handoff identity prepared for grant %s", grantUID)
	}
	if len(callerCert) == 0 {
		return nil, errors.New("host: handoff identity has no caller certificate, which only a clone over mutual TLS carries")
	}
	if had.caller == "" {
		return nil, errors.New("host: handoff identity names no caller")
	}
	return &backend.Identity{KeyPEM: string(had.id.KeyPEM), CertPEM: string(had.id.CertPEM), Caller: had.caller,
		CallerPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: callerCert}))}, nil
}

// route gives a ready handoff fiber its routing key and returns the
// endpoint its handle names, which is the router's address.
func (r *Runtime) route(f *fiber) (string, error) {
	if !f.handoff || r.cfg.Handoff == nil {
		return f.endpoint, nil
	}
	if _, err := r.cfg.Handoff.Add(f.id); err != nil {
		return "", fmt.Errorf("host: routing key for %s: %w", f.id, err)
	}
	return r.cfg.Handoff.Advertise, nil
}

func (r *Runtime) unroute(f *fiber) {
	if f.handoff && r.cfg.Handoff != nil {
		r.cfg.Handoff.Remove(f.id)
	}
}

// HandsOff implements core.HandoffRouter.
func (r *Runtime) HandsOff() bool { return r.canHandoff() }

// HandoffRoute implements core.HandoffRouter. It returns a handoff
// fiber's routing key, the pin of the key it serves TLS with and the
// certificate it presents.
func (r *Runtime) HandoffRoute(fiberID string) (key, pin string, cert []byte, ok bool) {
	if r.cfg.Handoff == nil {
		return "", "", nil, false
	}
	r.mu.Lock()
	f, known := r.fibers[fiberID]
	var id handoffIdentity
	if known {
		id = r.identities[f.grantUID]
	}
	r.mu.Unlock()
	if !known || !f.handoff {
		return "", "", nil, false
	}
	key, ok = r.cfg.Handoff.Key(fiberID)
	return key, id.id.KeySHA256, id.id.Cert, ok
}

// Deliver passes a connected socket to a handoff fiber, which serves it
// from fz_accept. It never blocks, so a full queue is ErrHandoffBusy.
// The caller still owns conn and closes its copy.
func (r *Runtime) Deliver(fiberID string, conn *os.File) error {
	r.mu.Lock()
	var ch *os.File
	if f, ok := r.fibers[fiberID]; ok && f.ready && f.handoff {
		ch = f.channel
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
