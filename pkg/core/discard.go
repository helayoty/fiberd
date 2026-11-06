package core

import (
	"context"
	"errors"
	"fmt"
	"log"
)

// DiscardRequest names a parked session to delete. It carries the grant
// as CloneRequest does, since a parked session has no fiber to name.
type DiscardRequest struct {
	GrantJWT []byte // the signed grant; verified offline
	Session  string
	// CallerThumbprint is the thumbprint of the key in the client
	// certificate the request arrived over.
	CallerThumbprint string
}

// errNoSession refuses a Discard that names no session.
var errNoSession = errors.New("fiberd: discard names no session")

// Discard deletes a parked session's delta, here and in the shared store,
// and forgets the session. The next Clone of it creates.
//
//   - Parked here. The published copy is withdrawn first, then the local
//     delta goes with the port it kept, and the session is forgotten.
//   - Parked here but claimed elsewhere since. The stale copy goes as
//     Clone drops it, and the store is asked as for an unknown session.
//   - Running here. Refused, since its state is in the fiber. The caller
//     releases the fiber with discard.
//   - Unknown here. The store's copy is deleted while it is the one found,
//     as a claim deletes it. Not in the store, or no store, is NotFound.
//
// It runs under the session's gate, so a park or resume in flight
// finishes first.
func (a *Core) Discard(ctx context.Context, req DiscardRequest) (StatusCode, error) {
	if req.Session == "" {
		return Invalid, errNoSession
	}
	g, code, err := a.authenticate(ctx, req.GrantJWT, req.CallerThumbprint)
	if err != nil {
		return code, err
	}
	// An expired grant is refused as Admit refuses it. Verify does not
	// check the lease, and the admitted grant's lease is the one that
	// counts once the home holds it.
	if g.Expired(a.Ledger.Now()) {
		return a.missCode(ErrGrantExpired), ErrGrantExpired
	}
	// A named session is filed under the grant's tenant, so a grant
	// without one has nothing to discard. Refused as Clone refuses it.
	if g.Tenant == "" {
		return NeedsTier, fmt.Errorf("%w: grant %s, session %q", ErrNoTenant, g.UID, req.Session)
	}
	hold := a.Ledger.holdSession(g.UID, req.Session)
	defer hold.release()
	fence := Fence{GrantUID: g.UID, Epoch: a.Ledger.Epoch()}
	st, ref, known := a.Ledger.SessionState(g.UID, req.Session)
	switch {
	case known && st == StateRunning:
		return Invalid, fmt.Errorf("%w: %s/%s", ErrSessionRunning, g.UID, req.Session)
	case known:
		finder, mobile := a.Runtime.(DeltaFinder)
		if !mobile || finder.Owned(ctx, ref) {
			return a.discardParked(ctx, g, fence, req.Session, ref)
		}
		// Another home claimed the session since this one published it.
		// The copy here is older state no one may resume, and the store
		// holds whatever the session is now.
		log.Printf("discard: session %s/%s was claimed by another home; dropping the local copy", g.UID, req.Session)
		a.Ledger.ForgetSession(g.UID, req.Session)
		a.persist()
		a.discardDelta(ctx, fence, req.Session, ref)
		_ = a.audit(ctx, BestEffort, AuditRecord{Event: "migrate-out", Fence: fence, Session: req.Session})
		a.notify()
	}
	return a.discardRemote(ctx, g, fence, req.Session)
}

// authenticate verifies a token as Clone's frontend does: the signature, the
// audience and the caller binding. A grant this home admitted answers
// for the token, and it must name the same caller. On the home's own UID
// with no grant admitted, the grant the home holds for itself answers
// instead, and nothing is admitted.
func (a *Core) authenticate(ctx context.Context, token []byte, thumbprint string) (Grant, StatusCode, error) {
	g, err := a.Verify.Verify(ctx, token)
	if err != nil {
		if errors.Is(err, ErrVerifyUnavailable) {
			return Grant{}, Shed, fmt.Errorf("capability: %w", err)
		}
		return Grant{}, Unauthenticated, fmt.Errorf("capability: %w", err)
	}
	if a.NodeID != "" && g.Audience != a.NodeID {
		return Grant{}, Unauthenticated, fmt.Errorf("%w: aud=%q node=%q", ErrWrongAudience, g.Audience, a.NodeID)
	}
	switch {
	case g.CallerThumbprint != "" && g.CallerThumbprint != thumbprint:
		return Grant{}, Unauthenticated, ErrCallerMismatch
	case g.CallerThumbprint == "" && a.RequireBoundGrants:
		return Grant{}, Unauthenticated, ErrUnboundGrant
	}
	held, ok := a.Ledger.Grant(g.UID)
	if !ok && a.OwnGrant != nil && g.UID == a.SelfAdmitUID {
		own, err := a.ownGrant(ctx, g)
		if err != nil {
			return Grant{}, a.missCode(err), err
		}
		held, ok = own, true
	}
	if ok {
		if held.CallerThumbprint != g.CallerThumbprint {
			return Grant{}, Unauthenticated, fmt.Errorf("%w: the token names another caller than the admitted grant", ErrCallerMismatch)
		}
		g = held
	}
	return g, OK, nil
}

// discardParked drops a session parked here. The published copy goes
// first. While it stands another home could claim the session, and so
// could this one once the session is forgotten, so a store that cannot
// withdraw it refuses the discard and changes nothing. After that the
// session is forgotten even if its files cannot all go. The boot sweep
// removes what is left.
func (a *Core) discardParked(ctx context.Context, g Grant, fence Fence, session, ref string) (StatusCode, error) {
	if rt, ok := a.Runtime.(DeltaRetirer); ok {
		if err := rt.RetireDelta(ctx, ref); err != nil {
			return Internal, fmt.Errorf("discard %s/%s: withdraw the published copy: %w", g.UID, session, err)
		}
	}
	var derr error
	if dd, ok := a.Runtime.(DeltaDiscarder); ok {
		if derr = dd.DiscardDelta(ctx, ref); derr != nil {
			log.Printf("discard %s/%s: remove %s: %v", g.UID, session, ref, derr)
		}
	}
	a.Ledger.ForgetSession(g.UID, session)
	a.persist()
	aerr := a.audit(ctx, g.Policy.Durability, AuditRecord{Event: "discard", Fence: fence, Session: session, Detail: ref})
	a.notify()
	switch {
	case derr != nil:
		return Internal, fmt.Errorf("discard %s/%s: forgotten, but its delta was not all removed: %w", g.UID, session, derr)
	case aerr != nil:
		return Internal, aerr
	}
	return OK, nil
}

// discardRemote deletes the store's copy of a session this home does not
// hold. A copy found but not to be taken here (another platform, another
// engine) is still deleted, since a discard takes nothing.
func (a *Core) discardRemote(ctx context.Context, g Grant, fence Fence, session string) (StatusCode, error) {
	finder, canFind := a.Runtime.(DeltaFinder)
	deleter, canDelete := a.Runtime.(DeltaDeleter)
	if !canFind || !canDelete {
		return NotFound, fmt.Errorf("%w: %s/%s", ErrSessionUnknown, g.UID, session)
	}
	rd, found, err := finder.FindDelta(ctx, g, session)
	if !found {
		if err != nil {
			return Internal, fmt.Errorf("discard %s/%s: find: %w", g.UID, session, err)
		}
		return NotFound, fmt.Errorf("%w: %s/%s", ErrSessionUnknown, g.UID, session)
	}
	if rd.Handle == "" {
		// The store's copy did not verify, so nothing it says is
		// believed, its digest included.
		if err == nil {
			err = errors.New("the store named no digest")
		}
		return Internal, fmt.Errorf("discard %s/%s: %w", g.UID, session, err)
	}
	remote, removed, err := deleter.DeleteDelta(ctx, g, session, rd.Handle)
	if err != nil {
		return Internal, fmt.Errorf("discard %s/%s: %w", g.UID, session, err)
	}
	if !removed {
		return NotFound, fmt.Errorf("%w: %s/%s was claimed or parked again meanwhile", ErrSessionUnknown, g.UID, session)
	}
	if err := a.audit(ctx, g.Policy.Durability, AuditRecord{Event: "discard", Fence: fence, Session: session, Detail: remote}); err != nil {
		return Internal, err
	}
	return OK, nil
}
