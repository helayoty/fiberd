//go:build integration

package main

import (
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/core"
)

// Peer is a second home that shares the target's delta registry and keys
// and serves the same template.
type Peer struct {
	// Target is host:port of the peer's Fibers service.
	Target string
	// NodeID is the audience of the grants minted for the peer.
	NodeID string
}

// C11: a named session moves between homes through the registry they
// share. Parked on the target, Clone(S) on the peer resumes it, and parked
// there, Clone(S) on the target resumes it again. Each move is a claim of a
// sealed, signed delta and, where the claiming home lacks it, of the
// sealed parent it is relative to. Then nothing of the template's memory
// may sit in the registry in the clear.
func (c *client) c11(t *testing.T) {
	if c.d.Peer == nil {
		t.Skip("no -peer-target; session mobility not driven")
	}
	if c.d.TargetTier < core.TierCheckpoint {
		t.Skipf("target tier %s is below FIBER_CHECKPOINT; no park to move", c.d.TargetTier)
	}
	ctx, cancel := c.ctx(t, 4)
	defer cancel()
	creds := insecure.NewCredentials()
	if c.d.TLS != nil {
		creds = credentials.NewTLS(c.d.TLS)
	}
	conn, err := grpc.NewClient(c.d.Peer.Target, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatalf("dial the peer %s: %v", c.d.Peer.Target, err)
	}
	defer func() { _ = conn.Close() }()
	peer := grantv1.NewFibersClient(conn)
	// One grant per home, the same tenant and template: the session's
	// domain, which it moves within.
	_, tokA := c.grant(t, "c11a", nil)
	_, tokB := c.grant(t, "c11b", func(g *core.Grant) { g.Audience = c.d.Peer.NodeID })
	session := uid("S")

	r1, err := c.clone(ctx, tokA, session, nil)
	if err != nil {
		t.Fatalf("clone on the target: %v", err)
	}
	if r1.GetKind() != grantv1.CloneKind_CREATE {
		t.Fatalf("first clone kind = %v, want CREATE", r1.GetKind())
	}
	if _, err := c.api.Park(ctx, &grantv1.ParkRequest{FiberId: r1.GetFiberId(), Sync: true}); err != nil {
		t.Fatalf("park on the target: %v", err)
	}
	r2, err := peer.Clone(ctx, &grantv1.CloneRequest{GrantJwt: tokB, Session: session})
	if err != nil {
		t.Fatalf("clone on the peer: %v", err)
	}
	if r2.GetKind() != grantv1.CloneKind_RESUME {
		_, _ = peer.Release(ctx, &grantv1.ReleaseRequest{FiberId: r2.GetFiberId(), Discard: true})
		t.Fatalf("clone on the peer kind = %v, want RESUME of the session parked on the target", r2.GetKind())
	}
	if _, err := peer.Park(ctx, &grantv1.ParkRequest{FiberId: r2.GetFiberId(), Sync: true}); err != nil {
		t.Fatalf("park on the peer: %v", err)
	}
	r3, err := c.clone(ctx, tokA, session, nil)
	if err != nil {
		t.Fatalf("clone back on the target: %v", err)
	}
	defer c.release(ctx, r3.GetFiberId())
	if r3.GetKind() != grantv1.CloneKind_RESUME {
		t.Fatalf("clone back on the target kind = %v, want RESUME of the session parked on the peer", r3.GetKind())
	}
	if c.d.SealCheck == nil {
		return
	}
	if err := c.d.SealCheck(ctx); err != nil {
		t.Fatalf("the registry holds template memory in the clear: %v", err)
	}
}
