package core_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// acceptVerifier returns whatever grant the token names: tests hand the
// grant UID as the token and pre-register the grants they need.
type acceptVerifier struct {
	grants map[string]core.Grant
}

func (v acceptVerifier) Verify(_ context.Context, token []byte) (core.Grant, error) {
	if g, ok := v.grants[string(token)]; ok {
		return g, nil
	}
	return core.Grant{}, errors.New("unknown token")
}

type fakeRuntime struct {
	tier  core.Tier
	exits chan core.FiberExit
	fail  error
}

func (f fakeRuntime) Tier() core.Tier                                   { return f.tier }
func (f fakeRuntime) PrepareTemplate(context.Context, core.Grant) error { return nil }
func (fakeRuntime) Park(context.Context, string, bool) (string, error)  { return "delta", nil }
func (fakeRuntime) Release(context.Context, string, bool) error         { return nil }
func (fakeRuntime) List(context.Context) ([]core.FiberHandle, error)    { return nil, nil }
func (f fakeRuntime) Exits() <-chan core.FiberExit                      { return f.exits }
func (fakeRuntime) Stats(context.Context, string) (core.FiberStats, error) {
	return core.FiberStats{WUsedBytes: 7}, nil
}
func (f fakeRuntime) Clone(_ context.Context, spec core.CloneSpec) (core.FiberHandle, error) {
	if f.fail != nil {
		return core.FiberHandle{}, f.fail
	}
	return core.FiberHandle{ID: spec.Fence.String(), Endpoint: "127.0.0.1:1"}, nil
}

func testHealth(kind string) *core.SourceHealth {
	switch kind {
	case "nil":
		return nil
	case "down":
		h := core.NewSourceHealth(10*time.Second, time.Now())
		h.MarkSync(time.Now().Add(-10 * time.Second))
		return h
	default:
		return core.NewSourceHealth(10*time.Second, time.Now())
	}
}

func newAgent(t *testing.T, health string, tier core.Tier, grants ...core.Grant) *core.Agent {
	t.Helper()
	v := acceptVerifier{grants: map[string]core.Grant{}}
	for _, g := range grants {
		v.grants[g.UID] = g
	}
	return &core.Agent{
		NodeID:  "node-a",
		Ledger:  core.NewLedger(1),
		Budget:  core.NewBudget(1000, 256<<20),
		Runtime: fakeRuntime{tier: tier, exits: make(chan core.FiberExit, 8)},
		Audit:   core.NopAuditor{},
		Verify:  v,
		Health:  testHealth(health),
	}
}

func TestCloneOutcomes(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	g1 := core.Grant{UID: "g1", Audience: "node-a", FiberMax: 1}
	full := func(t *testing.T, a *core.Agent) { a.Ledger.AdmitGrant(g1); createFiber(t, a.Ledger, "g1", "", "f1") }
	cases := []struct {
		name    string
		health  string
		tier    core.Tier
		grants  []core.Grant
		setup   func(t *testing.T, a *core.Agent)
		token   string
		session string
		payload int
		want    core.StatusCode
		wantErr error
	}{
		{name: "bad token is unauthenticated", health: "up", tier: core.TierCheckpoint, token: "nope", want: core.Unauthenticated},
		{name: "wrong audience is unauthenticated", health: "up", tier: core.TierCheckpoint,
			grants: []core.Grant{{UID: "gx", Audience: "node-b"}}, token: "gx", want: core.Unauthenticated, wantErr: core.ErrWrongAudience},
		{name: "first sight self-admits and creates", health: "down", tier: core.TierCheckpoint,
			grants: []core.Grant{g1}, token: "g1", want: core.OK},
		{name: "full healthy is fallback", health: "up", tier: core.TierCheckpoint, grants: []core.Grant{g1},
			setup: full, token: "g1", want: core.DeferredFallback, wantErr: core.ErrGrantFull},
		{name: "full unhealthy is shed", health: "down", tier: core.TierCheckpoint, grants: []core.Grant{g1},
			setup: full, token: "g1", want: core.Shed, wantErr: core.ErrGrantFull},
		{name: "full nil health fails toward fallback", health: "nil", tier: core.TierCheckpoint, grants: []core.Grant{g1},
			setup: full, token: "g1", want: core.DeferredFallback, wantErr: core.ErrGrantFull},
		{name: "expired healthy is fallback", health: "up", tier: core.TierCheckpoint,
			grants: []core.Grant{{UID: "ge", Audience: "node-a", LeaseExpiry: past}},
			token:  "ge", want: core.DeferredFallback, wantErr: core.ErrGrantExpired},
		{name: "expired unhealthy is shed", health: "down", tier: core.TierCheckpoint,
			grants: []core.Grant{{UID: "ge", Audience: "node-a", LeaseExpiry: past}},
			token:  "ge", want: core.Shed, wantErr: core.ErrGrantExpired},
		{name: "min_tier above runtime is needs-tier at admission", health: "down", tier: core.TierWarm,
			grants: []core.Grant{{UID: "gt", Audience: "node-a", MinTier: core.TierCheckpoint}},
			token:  "gt", want: core.NeedsTier, wantErr: core.ErrNeedsTier},
		{name: "parked session on warm runtime is needs-tier", health: "down", tier: core.TierWarm, grants: []core.Grant{g1},
			setup: func(t *testing.T, a *core.Agent) {
				a.Ledger.AdmitGrant(g1)
				createFiber(t, a.Ledger, "g1", "S1", "f1")
				a.Ledger.OnPark("f1", "delta-f1")
			},
			token: "g1", session: "S1", want: core.NeedsTier, wantErr: core.ErrNeedsTier},
		{name: "payload too large is invalid", health: "up", tier: core.TierCheckpoint, grants: []core.Grant{g1},
			token: "g1", payload: core.MaxPayload + 1, want: core.Invalid, wantErr: core.ErrPayloadTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newAgent(t, tc.health, tc.tier, tc.grants...)
			if tc.setup != nil {
				tc.setup(t, a)
			}
			req := core.CloneRequest{GrantJWT: []byte(tc.token), Session: tc.session, Deadline: time.Second,
				Payload: make([]byte, tc.payload)}
			_, code, err := a.Clone(context.Background(), req)
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("Clone err = %v, want %v", err, tc.wantErr)
			}
			if code != tc.want {
				t.Fatalf("Clone code = %d, want %d (err %v)", code, tc.want, err)
			}
		})
	}
}

func TestCloneIdempotentAndResume(t *testing.T) {
	g := core.Grant{UID: "g1", Audience: "node-a", FiberMax: 2}
	a := newAgent(t, "up", core.TierCheckpoint, g)
	ctx := context.Background()
	req := core.CloneRequest{GrantJWT: []byte("g1"), Session: "S", Deadline: time.Second}

	r1, code, err := a.Clone(ctx, req)
	if err != nil || code != core.OK || r1.Kind != core.ActCreate {
		t.Fatalf("first clone: %v %d %v", err, code, r1.Kind)
	}
	r2, _, _ := a.Clone(ctx, req)
	if r2.Kind != core.ActAttach || r2.Endpoint != r1.Endpoint || r2.Fence != r1.Fence {
		t.Fatalf("second clone = %+v, want attach with same endpoint/fence as %+v", r2, r1)
	}
	if _, code, err := a.Park(ctx, r1.FiberID, false); err != nil || code != core.OK {
		t.Fatalf("park: %v %d", err, code)
	}
	r3, _, _ := a.Clone(ctx, req)
	if r3.Kind != core.ActResume || r3.Fence.Seq != r1.Fence.Seq+1 || r3.Fence.Epoch != r1.Fence.Epoch {
		t.Fatalf("resume = %+v, want RESUME with seq+1 same epoch (from %+v)", r3.Fence, r1.Fence)
	}
	if _, code, err := a.Park(ctx, "g1/1/99", false); code != core.NotFound || !errors.Is(err, core.ErrFiberUnknown) {
		t.Fatalf("park unknown: %v %d, want NotFound", err, code)
	}
	if code, err := a.Release(ctx, r3.FiberID, true); err != nil || code != core.OK {
		t.Fatalf("release: %v %d", err, code)
	}
	r4, _, _ := a.Clone(ctx, req)
	if r4.Kind != core.ActCreate {
		t.Fatalf("after release, clone = %v, want create (name freed)", r4.Kind)
	}
}

func TestExitBeforeCommitIsNotLeaked(t *testing.T) {
	g := core.Grant{UID: "g1", Audience: "node-a", FiberMax: 1}
	a := newAgent(t, "up", core.TierCheckpoint, g)
	ctx := context.Background()
	// Deliver the exit for the fiber the next Clone will mint (fence
	// g1/1/1) before that Clone commits.
	a.OnExit(ctx, core.FiberExit{FiberID: "g1/1/1", Reason: "oom"})
	if _, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Deadline: time.Second}); err != nil || code != core.OK {
		t.Fatalf("clone: %v %d", err, code)
	}
	st, _ := a.Ledger.Status("g1")
	if st.Running != 0 {
		t.Fatalf("running = %d after early exit, want 0 (slot leaked)", st.Running)
	}
}

func TestWatchAndSampler(t *testing.T) {
	g := core.Grant{UID: "g1", Audience: "node-a"}
	a := newAgent(t, "up", core.TierCheckpoint, g)
	a.StatusInterval = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Run(ctx)
	w := a.Watch(ctx)
	<-w // initial (empty)
	if _, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Deadline: time.Second}); err != nil || code != core.OK {
		t.Fatalf("clone: %v %d", err, code)
	}
	deadline := time.After(2 * time.Second)
	for {
		select {
		case batch := <-w:
			for _, st := range batch {
				if st.GrantUID == "g1" && st.Running == 1 && st.WUsedBytes == 7 {
					return
				}
			}
		case <-deadline:
			t.Fatal("never observed running=1 with sampled W=7")
		}
	}
}

func TestSyncAuditFailureFailsClone(t *testing.T) {
	g := core.Grant{UID: "g1", Audience: "node-a", Policy: core.Policy{Durability: core.Sync}}
	a := newAgent(t, "up", core.TierCheckpoint, g)
	a.Audit = failingAuditor{}
	_, code, err := a.Clone(context.Background(), core.CloneRequest{GrantJWT: []byte("g1"), Deadline: time.Second})
	if code != core.Internal || !errors.Is(err, core.ErrAudit) {
		t.Fatalf("clone under SYNC with failing audit = %d %v, want Internal ErrAudit", code, err)
	}
}

type failingAuditor struct{}

func (failingAuditor) Append(_ context.Context, d core.Durability, _ core.AuditRecord) error {
	if d == core.Sync {
		return core.ErrAudit
	}
	return nil
}
