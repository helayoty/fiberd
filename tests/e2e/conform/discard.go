//go:build integration

package main

import (
	"testing"

	"google.golang.org/grpc/codes"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/core"
)

// C13: Discard deletes a parked session by name. Clone(S), Park, Discard,
// then Clone(S) is CREATE, never RESUME. On a home with a delta registry
// that clone asks the registry too, so the published copy must be gone
// as well. A running session is refused, and a session nowhere is
// NotFound.
func (c *client) c13(t *testing.T) {
	if c.d.TargetTier < core.TierCheckpoint {
		t.Skipf("target tier %s is below FIBER_CHECKPOINT; nothing parks to discard", c.d.TargetTier)
	}
	ctx, cancel := c.ctx(t, 2)
	defer cancel()
	_, tok := c.grant(t, "c13", nil)
	session := uid("S")
	discard := func(session string) error {
		_, err := c.api.Discard(ctx, &grantv1.DiscardRequest{GrantJwt: tok, Session: session})
		return err
	}
	r1, err := c.clone(ctx, tok, session, nil)
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	if _, err := c.api.Park(ctx, &grantv1.ParkRequest{FiberId: r1.GetFiberId(), Sync: true}); err != nil {
		t.Fatalf("park: %v", err)
	}
	if err := discard(session); err != nil {
		t.Fatalf("discard of the parked session: %v", err)
	}
	r2, err := c.clone(ctx, tok, session, nil)
	if err != nil {
		t.Fatalf("clone after the discard: %v", err)
	}
	defer c.release(ctx, r2.GetFiberId())
	if r2.GetKind() != grantv1.CloneKind_CREATE {
		t.Fatalf("clone after the discard kind = %v, want CREATE", r2.GetKind())
	}
	expectCode(t, "discard of a running session", discard(session), codes.InvalidArgument)
	expectCode(t, "discard of a session nowhere", discard(uid("none")), codes.NotFound)
}
