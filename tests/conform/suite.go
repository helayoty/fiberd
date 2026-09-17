// The suite: the executable contract of the grant protocol, cases C1-C10
// any home must pass, driven only through the public gRPC surface plus a
// few out-of-band hooks (mint a grant, restart the target, flip
// control-plane health, look up an audit record, end the engine, lose the
// scope). conform_test.go wraps it as the `go test`-style grant-conform
// binary; homes provide the hooks as shell commands.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/endpoint"
	"github.com/helayoty/fiberd/pkg/rpc"
)

// Driver is everything the suite needs that is not on the wire.
type Driver struct {
	// Target is host:port of the Fibers service under test.
	Target string
	// TargetTier is the tier the target advertises; C7 mints a grant one
	// tier above it, C2 needs at least FIBER_CHECKPOINT.
	TargetTier core.Tier
	// NodeID is the audience every minted grant names.
	NodeID string
	// Template is the template digest to put in minted grants.
	Template string
	// Mint turns a grant into whatever the target's verifier accepts (a
	// signed JWT, or protobuf JSON for the insecure development verifier).
	Mint func(g core.Grant) (string, error)
	// Restart restarts the target in place (same address, same state
	// directory) and returns when it is serving again. Nil skips C3.
	Restart func(ctx context.Context) error
	// SetCPHealth makes the target's grant lane healthy or stale. Nil
	// skips C4.
	SetCPHealth func(ctx context.Context, healthy bool) error
	// AuditHas reports whether the target's audit spool holds a record for
	// the event and fence. Nil skips the audit half of C6 and C8.
	AuditHas func(ctx context.Context, event string, fence core.Fence) (bool, error)
	// EngineKill ends the grant's warm template instance (its engine) the
	// way a crash would. Nil skips C9.
	EngineKill func(ctx context.Context, grantUID string) error
	// ScopeLost tells the home the scope everything was minted under is
	// gone while it keeps running (a namespace, a fabric claim): the home
	// must turn that into fence revocation. Nil skips C10.
	ScopeLost func(ctx context.Context) error
	// Timeout bounds each case (default 15s); Restart gets twice that.
	Timeout time.Duration
}

func (d Driver) timeout() time.Duration {
	if d.Timeout > 0 {
		return d.Timeout
	}
	return 15 * time.Second
}

// Run executes the seven cases as subtests.
func Run(t *testing.T, d Driver) {
	t.Helper()
	if d.Target == "" || d.NodeID == "" || d.Mint == nil {
		t.Fatal("conform: Target, NodeID and Mint are required")
	}
	if d.Template == "" {
		d.Template = "sha256:conform"
	}
	c := newClient(t, d)
	t.Run("C1_Idempotency", func(t *testing.T) { c.c1(t) })
	t.Run("C2_FenceMonotonic", func(t *testing.T) { c.c2(t) })
	t.Run("C3_EpochBump", func(t *testing.T) { c.c3(t) })
	t.Run("C4_RevocationByTTL", func(t *testing.T) { c.c4(t) })
	t.Run("C5_AdmissionCompleteness", func(t *testing.T) { c.c5(t) })
	t.Run("C6_WBudget", func(t *testing.T) { c.c6(t) })
	t.Run("C7_TierFloor", func(t *testing.T) { c.c7(t) })
	t.Run("C8_DeviceBudget", func(t *testing.T) { c.c8(t) })
	t.Run("C9_EngineLoss", func(t *testing.T) { c.c9(t) })
	t.Run("C10_ScopeRevocation", func(t *testing.T) { c.c10(t) })
}

type client struct {
	d    Driver
	conn *grpc.ClientConn
	api  grantv1.FibersClient
}

func newClient(t *testing.T, d Driver) *client {
	t.Helper()
	conn, err := grpc.NewClient(d.Target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("conform: dial %s: %v", d.Target, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &client{d: d, conn: conn, api: grantv1.NewFibersClient(conn)}
}

func (c *client) ctx(t *testing.T, mul time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), c.d.timeout()*mul)
}

func uid(prefix string) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return prefix + "-" + hex.EncodeToString(b)
}

// grant mints a grant for the target with sensible defaults and applies
// the caller's overrides.
func (c *client) grant(t *testing.T, prefix string, mut func(g *core.Grant)) (core.Grant, string) {
	t.Helper()
	g := core.Grant{
		UID:            uid(prefix),
		Audience:       c.d.NodeID,
		TemplateDigest: c.d.Template,
		FiberMax:       2,
		MinTier:        core.TierBasic,
		LeaseExpiry:    time.Now().Add(10 * time.Minute),
	}
	if mut != nil {
		mut(&g)
	}
	tok, err := c.d.Mint(g)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return g, tok
}

func (c *client) clone(ctx context.Context, tok, session string, payload []byte) (*grantv1.CloneResponse, error) {
	return c.api.Clone(ctx, &grantv1.CloneRequest{GrantJwt: tok, Session: session, Payload: payload})
}

func (c *client) release(ctx context.Context, ids ...string) {
	for _, id := range ids {
		_, _ = c.api.Release(ctx, &grantv1.ReleaseRequest{FiberId: id, Discard: true})
	}
}

// waitStatus blocks until the grant's status satisfies pred, or ctx ends.
func (c *client) waitStatus(ctx context.Context, grantUID string, pred func(*grantv1.Status) bool) (*grantv1.Status, error) {
	stream, err := c.api.Watch(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	for {
		st, err := stream.Recv()
		if err != nil {
			return nil, fmt.Errorf("watch: %w", err)
		}
		if st.GetGrantUid() == grantUID && pred(st) {
			return st, nil
		}
	}
}

func expectCode(t *testing.T, what string, err error, want codes.Code) {
	t.Helper()
	if status.Code(err) != want {
		t.Fatalf("%s: code %v, want %v (err: %v)", what, status.Code(err), want, err)
	}
}

func expectMiss(t *testing.T, what string, err error, want grantv1.MissCode) *grantv1.Miss {
	t.Helper()
	miss, ok := rpc.MissFromError(err)
	if !ok {
		t.Fatalf("%s: miss without a Miss detail (bare code %v): %v", what, status.Code(err), err)
	}
	if miss.GetCode() != want {
		t.Fatalf("%s: Miss.code = %v, want %v", what, miss.GetCode(), want)
	}
	return miss
}

// C1: Clone(S) twice -> second is ATTACH with the same endpoint and fence.
func (c *client) c1(t *testing.T) {
	ctx, cancel := c.ctx(t, 1)
	defer cancel()
	_, tok := c.grant(t, "c1", nil)
	r1, err := c.clone(ctx, tok, "S", nil)
	if err != nil {
		t.Fatalf("first clone: %v", err)
	}
	defer c.release(ctx, r1.GetFiberId())
	if r1.GetKind() != grantv1.CloneKind_CREATE {
		t.Fatalf("first clone kind = %v, want CREATE", r1.GetKind())
	}
	// The endpoint is a URL a caller dials as given: unix://<path>, or
	// tcp://host:port with an IPv6 literal bracketed. Which family a home
	// hands out is its declaration, not the caller's business.
	if err := endpoint.Validate(r1.GetEndpoint()); err != nil {
		t.Fatalf("endpoint %q is not well-formed: %v", r1.GetEndpoint(), err)
	}
	r2, err := c.clone(ctx, tok, "S", nil)
	if err != nil {
		t.Fatalf("second clone: %v", err)
	}
	if r2.GetKind() != grantv1.CloneKind_ATTACH {
		t.Fatalf("second clone kind = %v, want ATTACH", r2.GetKind())
	}
	if r2.GetEndpoint() != r1.GetEndpoint() || !proto.Equal(r1.GetFence(), r2.GetFence()) || r2.GetFiberId() != r1.GetFiberId() {
		t.Fatalf("attach differs: first %+v, second %+v", r1, r2)
	}
}

// C2: Park(S), Clone(S) -> RESUME, seq+1, same epoch.
func (c *client) c2(t *testing.T) {
	if c.d.TargetTier < core.TierCheckpoint {
		t.Skipf("target tier %s is below FIBER_CHECKPOINT; park/resume not offered (C7 covers the refusal)", c.d.TargetTier)
	}
	ctx, cancel := c.ctx(t, 1)
	defer cancel()
	_, tok := c.grant(t, "c2", nil)
	r1, err := c.clone(ctx, tok, "S", nil)
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	if _, err := c.api.Park(ctx, &grantv1.ParkRequest{FiberId: r1.GetFiberId(), Sync: true}); err != nil {
		t.Fatalf("park: %v", err)
	}
	r2, err := c.clone(ctx, tok, "S", nil)
	if err != nil {
		t.Fatalf("clone after park: %v", err)
	}
	defer c.release(ctx, r2.GetFiberId())
	if r2.GetKind() != grantv1.CloneKind_RESUME {
		t.Fatalf("kind = %v, want RESUME", r2.GetKind())
	}
	f1, f2 := r1.GetFence(), r2.GetFence()
	if f2.GetEpoch() != f1.GetEpoch() || f2.GetSeq() != f1.GetSeq()+1 || f2.GetGrantUid() != f1.GetGrantUid() {
		t.Fatalf("resume fence = %v, want same epoch and seq+1 of %v", f2, f1)
	}
	// The old fiber id is gone: parking ended that incarnation.
	_, err = c.api.Park(ctx, &grantv1.ParkRequest{FiberId: r1.GetFiberId()})
	expectCode(t, "park of the pre-resume fiber id", err, codes.NotFound)
}

// C3: restart the target -> every prior fence rejected; new epoch > old.
func (c *client) c3(t *testing.T) {
	if c.d.Restart == nil {
		t.Skip("no restart hook (-restart-cmd); C3 needs one")
	}
	ctx, cancel := c.ctx(t, 3)
	defer cancel()
	_, tok := c.grant(t, "c3", nil)
	r1, err := c.clone(ctx, tok, "S", nil)
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	// A session parked before the restart must survive it when the
	// target keeps deltas durably: Clone(P) afterwards is RESUME under
	// the new epoch. Targets without durable deltas answer CREATE.
	var parked *grantv1.CloneResponse
	if c.d.TargetTier >= core.TierCheckpoint {
		parked, err = c.clone(ctx, tok, "P", nil)
		if err != nil {
			t.Fatalf("clone P: %v", err)
		}
		if _, err := c.api.Park(ctx, &grantv1.ParkRequest{FiberId: parked.GetFiberId(), Sync: true}); err != nil {
			t.Fatalf("park P: %v", err)
		}
	}
	if err := c.d.Restart(ctx); err != nil {
		t.Fatalf("restart hook: %v", err)
	}
	// Prior fence: Park and Release on its fiber id must be refused.
	var perr error
	for i := 0; i < 50; i++ { // the hook says it is serving; tolerate a brief reconnect
		_, perr = c.api.Park(ctx, &grantv1.ParkRequest{FiberId: r1.GetFiberId()})
		if status.Code(perr) != codes.Unavailable {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	expectCode(t, "park with a pre-restart fiber id", perr, codes.NotFound)
	_, rerr := c.api.Release(ctx, &grantv1.ReleaseRequest{FiberId: r1.GetFiberId()})
	expectCode(t, "release with a pre-restart fiber id", rerr, codes.NotFound)
	// New fence: strictly greater epoch. The session name is fresh again
	// (no snapshot yet), so this is CREATE; with a ledger snapshot it may
	// be RESUME. Either way the epoch moved.
	r2, err := c.clone(ctx, tok, "S", nil)
	if err != nil {
		t.Fatalf("clone after restart: %v", err)
	}
	defer c.release(ctx, r2.GetFiberId())
	if r2.GetFence().GetEpoch() <= r1.GetFence().GetEpoch() {
		t.Fatalf("epoch after restart = %d, want > %d", r2.GetFence().GetEpoch(), r1.GetFence().GetEpoch())
	}
	if parked != nil {
		r3, err := c.clone(ctx, tok, "P", nil)
		if err != nil {
			t.Fatalf("clone P after restart: %v", err)
		}
		defer c.release(ctx, r3.GetFiberId())
		if r3.GetKind() == grantv1.CloneKind_CREATE {
			t.Log("parked session did not survive the restart (target keeps no durable deltas)")
		} else if r3.GetKind() != grantv1.CloneKind_RESUME || r3.GetFence().GetEpoch() <= parked.GetFence().GetEpoch() {
			t.Fatalf("clone P after restart = %v epoch %d, want RESUME under a newer epoch than %d",
				r3.GetKind(), r3.GetFence().GetEpoch(), parked.GetFence().GetEpoch())
		}
	}
}

// C4: expired grant -> SHED with the control plane unreachable,
// DEFERRED_FALLBACK with it healthy. Both carry a Miss detail.
func (c *client) c4(t *testing.T) {
	if c.d.SetCPHealth == nil {
		t.Skip("no control-plane health hook (-cp-health-cmd); C4 needs one")
	}
	ctx, cancel := c.ctx(t, 2)
	defer cancel()
	_, tok := c.grant(t, "c4", func(g *core.Grant) { g.LeaseExpiry = time.Now().Add(-time.Minute) })
	defer func() { _ = c.d.SetCPHealth(context.Background(), true) }()

	if err := c.d.SetCPHealth(ctx, true); err != nil {
		t.Fatalf("health up: %v", err)
	}
	_, err := c.clone(ctx, tok, "", nil)
	expectCode(t, "expired grant, control plane healthy", err, codes.Unavailable)
	expectMiss(t, "expired grant, control plane healthy", err, grantv1.MissCode_DEFERRED_FALLBACK)

	if err := c.d.SetCPHealth(ctx, false); err != nil {
		t.Fatalf("health down: %v", err)
	}
	_, err = c.clone(ctx, tok, "", nil)
	expectCode(t, "expired grant, control plane unreachable", err, codes.ResourceExhausted)
	miss := expectMiss(t, "expired grant, control plane unreachable", err, grantv1.MissCode_SHED)
	if miss.GetRetryAfterS() == 0 {
		t.Fatalf("SHED without retry_after_s")
	}
}

// C5: any field beyond the four allowed -> InvalidArgument. Also the
// payload cap.
func (c *client) c5(t *testing.T) {
	ctx, cancel := c.ctx(t, 1)
	defer cancel()
	_, tok := c.grant(t, "c5", nil)

	// Encode a legal request, then append field 99 (a string "image"):
	// what a caller trying to shape a workload at clone time would send.
	legal, err := proto.Marshal(&grantv1.CloneRequest{GrantJwt: tok, Session: "S"})
	if err != nil {
		t.Fatal(err)
	}
	wire := append([]byte{}, legal...)
	wire = append(wire, 0x9a, 0x06, byte(len("evil")))
	wire = append(wire, "evil"...)
	var smuggled grantv1.CloneRequest
	if err := proto.Unmarshal(wire, &smuggled); err != nil {
		t.Fatal(err)
	}
	if len(smuggled.ProtoReflect().GetUnknown()) == 0 {
		t.Fatal("test setup: unknown field not preserved by the client library")
	}
	r, err := c.api.Clone(ctx, &smuggled)
	if err == nil {
		c.release(ctx, r.GetFiberId())
		t.Fatalf("clone with an unknown field succeeded: %+v", r)
	}
	expectCode(t, "clone with an unknown field", err, codes.InvalidArgument)

	_, err = c.clone(ctx, tok, "", make([]byte, core.MaxPayload+1))
	expectCode(t, "clone with an oversized payload", err, codes.InvalidArgument)

	// A clean request on the same grant still works.
	r, err = c.clone(ctx, tok, "S", nil)
	if err != nil {
		t.Fatalf("clean clone after rejections: %v", err)
	}
	c.release(ctx, r.GetFiberId())
}

// C6: dirtied working set over w_budget_bytes -> the fiber is killed, the
// ledger frees the slot, and an audit record is written with its fence.
func (c *client) c6(t *testing.T) {
	ctx, cancel := c.ctx(t, 2)
	defer cancel()
	const budget = 1 << 20
	g, tok := c.grant(t, "c6", func(g *core.Grant) { g.WBudgetBytes = budget; g.FiberMax = 2 })

	r, err := c.clone(ctx, tok, "", []byte(fmt.Sprintf(`{"dirty_bytes": %d}`, 4*budget)))
	if err != nil && status.Code(err) != codes.Unavailable {
		t.Fatalf("over-budget clone: %v", err)
	}
	// Either the clone was accepted and the fiber died, or the runtime
	// reported the death inside the deadline. In both cases the slot must
	// come back: running returns to 0 for this grant.
	if _, err := c.waitStatus(ctx, g.UID, func(st *grantv1.Status) bool { return st.GetRunning() == 0 }); err != nil {
		t.Fatalf("slot never freed after over-budget clone: %v", err)
	}
	if r != nil {
		_, perr := c.api.Park(ctx, &grantv1.ParkRequest{FiberId: r.GetFiberId()})
		expectCode(t, "park of the killed fiber", perr, codes.NotFound)
	}
	// Both slots are usable: two more clones within budget succeed.
	a, err := c.clone(ctx, tok, "", []byte(`{"dirty_bytes": 1024}`))
	if err != nil {
		t.Fatalf("clone 1 after kill: %v", err)
	}
	b, err := c.clone(ctx, tok, "", []byte(`{"dirty_bytes": 1024}`))
	if err != nil {
		t.Fatalf("clone 2 after kill: %v", err)
	}
	defer c.release(ctx, a.GetFiberId(), b.GetFiberId())

	if c.d.AuditHas == nil {
		t.Log("no audit hook (-audit-file/-audit-cmd); audit record not checked")
		return
	}
	if r == nil {
		t.Log("runtime reported the kill inside Clone; no fence to look up in the audit spool")
		return
	}
	fence := rpc.FenceFromProto(r.GetFence())
	var found bool
	for i := 0; i < 50 && !found; i++ {
		found, err = c.d.AuditHas(ctx, "oom", fence)
		if err != nil {
			t.Fatalf("audit hook: %v", err)
		}
		if !found {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if !found {
		t.Fatalf("no audit record event=oom fence=%s", fence)
	}
}

// C8: a grant with a device budget is either refused loudly (the home's
// template offers no such device: FailedPrecondition, never a silent
// CPU-only fiber) or enforced: a fiber whose engine slice exceeds
// device_budget is killed, the slot comes back, and an audit record is
// written with its fence, exactly as C6 does for W.
func (c *client) c8(t *testing.T) {
	ctx, cancel := c.ctx(t, 2)
	defer cancel()
	const budget = 1 << 20
	g, tok := c.grant(t, "c8", func(g *core.Grant) {
		g.DeviceBudget = core.DeviceBudget{Bytes: budget, Class: "sim"}
		g.FiberMax = 2
	})
	r, err := c.clone(ctx, tok, "", []byte(fmt.Sprintf(`{"device_bytes": %d}`, 4*budget)))
	if status.Code(err) == codes.FailedPrecondition {
		t.Logf("target offers no device for the grant's class: refused loudly (%v)", err)
		if _, ok := status.FromError(err); !ok {
			t.Fatalf("refusal is not a gRPC status: %v", err)
		}
		return
	}
	if err != nil && status.Code(err) != codes.Unavailable {
		t.Fatalf("over-device-budget clone: %v", err)
	}
	if _, err := c.waitStatus(ctx, g.UID, func(st *grantv1.Status) bool { return st.GetRunning() == 0 }); err != nil {
		t.Fatalf("slot never freed after over-budget device slice: %v", err)
	}
	a, err := c.clone(ctx, tok, "", []byte(`{"device_bytes": 1024}`))
	if err != nil {
		t.Fatalf("clone within the device budget after the kill: %v", err)
	}
	defer c.release(ctx, a.GetFiberId())
	if c.d.AuditHas == nil || r == nil {
		t.Log("audit record not checked (no hook, or the kill was reported inside Clone)")
		return
	}
	fence := rpc.FenceFromProto(r.GetFence())
	var found bool
	for i := 0; i < 50 && !found; i++ {
		found, err = c.d.AuditHas(ctx, "oom", fence)
		if err != nil {
			t.Fatalf("audit hook: %v", err)
		}
		if !found {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if !found {
		t.Fatalf("no audit record event=oom fence=%s", fence)
	}
}

// C9: the engine (the grant's warm template instance) dies. Every running
// fiber of the grant ends and its slot comes back; parked sessions
// survive; the next Clone of a parked session resumes it once the home
// has warmed the template again, never a fresh amnesiac instance.
func (c *client) c9(t *testing.T) {
	if c.d.EngineKill == nil {
		t.Skip("no -engine-kill-cmd hook; engine loss not driven")
	}
	if c.d.TargetTier < core.TierCheckpoint {
		t.Skipf("target tier %s is below FIBER_CHECKPOINT; nothing parked can survive", c.d.TargetTier)
	}
	ctx, cancel := c.ctx(t, 3)
	defer cancel()
	g, tok := c.grant(t, "c9", func(g *core.Grant) { g.FiberMax = 4 })
	anon, err := c.clone(ctx, tok, "", nil)
	if err != nil {
		t.Fatalf("anonymous clone: %v", err)
	}
	s, err := c.clone(ctx, tok, "S", nil)
	if err != nil {
		t.Fatalf("clone S: %v", err)
	}
	if _, err := c.api.Park(ctx, &grantv1.ParkRequest{FiberId: s.GetFiberId(), Sync: true}); err != nil {
		t.Fatalf("park S: %v", err)
	}
	if err := c.d.EngineKill(ctx, g.UID); err != nil {
		t.Fatalf("engine-kill hook: %v", err)
	}
	if _, err := c.waitStatus(ctx, g.UID, func(st *grantv1.Status) bool { return st.GetRunning() == 0 && st.GetParked() == 1 }); err != nil {
		t.Fatalf("after engine loss: want running=0 parked=1: %v", err)
	}
	_, perr := c.api.Park(ctx, &grantv1.ParkRequest{FiberId: anon.GetFiberId()})
	expectCode(t, "park of a fiber the engine took with it", perr, codes.NotFound)
	r, err := c.clone(ctx, tok, "S", nil)
	if err != nil {
		t.Fatalf("clone S after engine loss: %v", err)
	}
	defer c.release(ctx, r.GetFiberId())
	if r.GetKind() != grantv1.CloneKind_RESUME {
		t.Fatalf("clone S after engine loss = %v, want RESUME of the parked session", r.GetKind())
	}
	if !rpc.FenceFromProto(r.GetFence()).Newer(rpc.FenceFromProto(s.GetFence())) {
		t.Fatalf("resumed fence %v is not newer than %v", r.GetFence(), s.GetFence())
	}
}

// C10: scope revocation is fence revocation. When the home's scope is
// lost while it runs, every fence minted under it is invalid at once
// (Park and Release answer NotFound, running drops to 0), parked sessions
// survive and resume under a newer epoch, and the grant keeps serving:
// nothing minted before the loss validates after it.
func (c *client) c10(t *testing.T) {
	if c.d.ScopeLost == nil {
		t.Skip("no -scope-cmd hook; scope loss not driven")
	}
	ctx, cancel := c.ctx(t, 3)
	defer cancel()
	g, tok := c.grant(t, "c10", func(g *core.Grant) { g.FiberMax = 4 })
	a, err := c.clone(ctx, tok, "", nil)
	if err != nil {
		t.Fatalf("anonymous clone: %v", err)
	}
	var parked *grantv1.CloneResponse
	if c.d.TargetTier >= core.TierCheckpoint {
		parked, err = c.clone(ctx, tok, "P", nil)
		if err != nil {
			t.Fatalf("clone P: %v", err)
		}
		if _, err := c.api.Park(ctx, &grantv1.ParkRequest{FiberId: parked.GetFiberId(), Sync: true}); err != nil {
			t.Fatalf("park P: %v", err)
		}
	}
	if err := c.d.ScopeLost(ctx); err != nil {
		t.Fatalf("scope-lost hook: %v", err)
	}
	if _, err := c.waitStatus(ctx, g.UID, func(st *grantv1.Status) bool { return st.GetRunning() == 0 }); err != nil {
		t.Fatalf("after scope loss: want running=0: %v", err)
	}
	_, perr := c.api.Park(ctx, &grantv1.ParkRequest{FiberId: a.GetFiberId()})
	expectCode(t, "park of a fiber from the lost scope", perr, codes.NotFound)
	_, rerr := c.api.Release(ctx, &grantv1.ReleaseRequest{FiberId: a.GetFiberId()})
	expectCode(t, "release of a fiber from the lost scope", rerr, codes.NotFound)
	fresh, err := c.clone(ctx, tok, "", nil)
	if err != nil {
		t.Fatalf("clone after scope loss: %v", err)
	}
	defer c.release(ctx, fresh.GetFiberId())
	if !rpc.FenceFromProto(fresh.GetFence()).Newer(rpc.FenceFromProto(a.GetFence())) || fresh.GetFence().GetEpoch() <= a.GetFence().GetEpoch() {
		t.Fatalf("fence after scope loss %v is not in a newer epoch than %v", fresh.GetFence(), a.GetFence())
	}
	if parked != nil {
		r, err := c.clone(ctx, tok, "P", nil)
		if err != nil {
			t.Fatalf("clone P after scope loss: %v", err)
		}
		defer c.release(ctx, r.GetFiberId())
		if r.GetKind() != grantv1.CloneKind_RESUME || r.GetFence().GetEpoch() <= parked.GetFence().GetEpoch() {
			t.Fatalf("P after scope loss = %v %v, want RESUME in a newer epoch", r.GetKind(), r.GetFence())
		}
	}
}

// C7: min_tier above the target -> FailedPrecondition, never a fresh fork.
func (c *client) c7(t *testing.T) {
	ctx, cancel := c.ctx(t, 1)
	defer cancel()
	if c.d.TargetTier >= core.TierFabric {
		t.Skip("target advertises the top tier; nothing is above it")
	}
	_, tok := c.grant(t, "c7", func(g *core.Grant) { g.MinTier = c.d.TargetTier + 1 })
	r, err := c.clone(ctx, tok, "S", nil)
	if err == nil {
		c.release(ctx, r.GetFiberId())
		t.Fatalf("grant with min_tier %s served by a %s target: %+v", c.d.TargetTier+1, c.d.TargetTier, r)
	}
	expectCode(t, "min_tier above the target", err, codes.FailedPrecondition)
	if rpc.IsMiss(err) {
		t.Fatalf("tier gap must not be reported as a capacity miss: %v", err)
	}

	// At the floor exactly: served.
	_, tok = c.grant(t, "c7b", func(g *core.Grant) { g.MinTier = c.d.TargetTier })
	r, err = c.clone(ctx, tok, "", nil)
	if err != nil {
		t.Fatalf("grant with min_tier == target tier refused: %v", err)
	}
	c.release(ctx, r.GetFiberId())
}
