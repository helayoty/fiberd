package core_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/core/coretest"
)

// acceptVerifier returns whatever grant the token names: tests hand the
// grant UID as the token and pre-register the grants they need. A down
// verifier cannot decide at all, like one whose key set never loaded.
type acceptVerifier struct {
	grants map[string]core.Grant
	down   bool
	// unavailable are tokens the verifier cannot decide on, as when their
	// key is not loaded yet.
	unavailable map[string]bool
}

func (v acceptVerifier) Verify(_ context.Context, token []byte) (core.Grant, error) {
	if v.down || v.unavailable[string(token)] {
		return core.Grant{}, fmt.Errorf("%w: key set never loaded", core.ErrVerifyUnavailable)
	}
	if g, ok := v.grants[string(token)]; ok {
		return g, nil
	}
	return core.Grant{}, errors.New("unknown token")
}

type fakeRuntime struct {
	tier     core.Tier
	exits    chan core.FiberExit
	fail     error
	parkFail error
	// parkRef makes Park return the delta ref alongside parkFail. The
	// delta exists and the fiber is gone, but a later step failed (the
	// manifest, the wait for the exit).
	parkRef bool
	shared  bool // fibers share the host kernel, so not an isolating runtime
	routes  bool // routes connections to fibers (core.HandoffRouter)
	// noRef makes Park return neither a ref nor an error.
	noRef bool
	// releaseFail is what Release answers.
	releaseFail error
	// statsFail names the fiber whose Stats fails.
	statsFail string
}

func (f fakeRuntime) HandsOff() bool { return f.routes }

func (f fakeRuntime) HandoffRoute(fiberID string) (string, string, bool) {
	return "rk-" + fiberID, "pin", f.routes
}

func (f fakeRuntime) Tier() core.Tier                                   { return f.tier }
func (f fakeRuntime) IsolatesTenants() bool                             { return !f.shared }
func (f fakeRuntime) PrepareTemplate(context.Context, core.Grant) error { return nil }
func (f fakeRuntime) Park(context.Context, string, bool) (string, error) {
	if f.noRef {
		return "", nil
	}
	if f.parkFail != nil && !f.parkRef {
		return "", f.parkFail
	}
	return "delta", f.parkFail
}
func (f fakeRuntime) Release(context.Context, string, bool) error    { return f.releaseFail }
func (fakeRuntime) List(context.Context) ([]core.FiberHandle, error) { return nil, nil }
func (f fakeRuntime) Exits() <-chan core.FiberExit                   { return f.exits }
func (f fakeRuntime) Stats(_ context.Context, id string) (core.FiberStats, error) {
	if f.statsFail != "" && id == f.statsFail {
		return core.FiberStats{}, errors.New("stats: cgroup gone")
	}
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
		Verify:  v,
		Health:  testHealth(health),
	}
}

// TestCloneOutcomes checks the status code and error Clone answers, and how
// many fibers the grant runs afterwards. A refused clone must return its
// reservation, and an exit that beats the commit must not leak a slot.
func TestCloneOutcomes(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	g1 := core.Grant{UID: "g1", Tenant: "acme", Audience: "node-a", FiberMax: 1}
	full := func(t *testing.T, a *core.Agent) { a.Ledger.AdmitGrant(g1); createFiber(t, a.Ledger, "g1", "", "f1") }
	bound := core.Grant{UID: "gb", Tenant: "acme", Audience: "node-a", CallerThumbprint: "router-x5t"}
	trusted := core.Grant{UID: "gtr", Tenant: "acme", Audience: "node-a", Policy: core.Policy{Isolation: core.Trusted}}
	shared := func(t *testing.T, a *core.Agent) {
		a.Runtime = fakeRuntime{tier: core.TierCheckpoint, exits: make(chan core.FiberExit, 8), shared: true}
	}
	handoff := core.Grant{UID: "gh", Tenant: "acme", Audience: "node-a", CallerThumbprint: "router-x5t", Policy: core.Policy{EndpointMode: core.EndpointHandoff}}
	unboundHandoff := core.Grant{UID: "gu", Tenant: "acme", Audience: "node-a", Policy: core.Policy{EndpointMode: core.EndpointHandoff}}
	syncG := core.Grant{UID: "gs", Tenant: "acme", Audience: "node-a", Policy: core.Policy{Durability: core.Sync}}
	routes := func(t *testing.T, a *core.Agent) {
		a.Runtime = fakeRuntime{tier: core.TierCheckpoint, exits: make(chan core.FiberExit, 8), routes: true}
	}
	removed := func(t *testing.T, a *core.Agent) {
		r, err := core.OpenRevoked(filepath.Join(t.TempDir(), "revoked.json"), time.Hour, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		a.Revoked = r
		full(t, a)
		a.Remove(context.Background(), "g1")
	}
	cases := []struct {
		name         string
		health       string
		tier         core.Tier
		grants       []core.Grant
		setup        func(t *testing.T, a *core.Agent)
		token        string
		session      string
		payload      int
		caller       string
		requireBound bool
		want         core.StatusCode
		wantErr      error
		running      int    // the token's grant's running fibers after the clone
		wantRoute    string // the routing key the response carries
	}{
		{name: "handoff grant answers the fiber's route", health: "up", tier: core.TierCheckpoint, grants: []core.Grant{handoff},
			setup: routes, token: "gh", caller: "router-x5t", want: core.OK, running: 1, wantRoute: "rk-gh/1/1"},
		{name: "handoff grant without a caller binding is unauthenticated", health: "up", tier: core.TierCheckpoint, grants: []core.Grant{unboundHandoff},
			setup: routes, token: "gu", want: core.Unauthenticated, wantErr: core.ErrHandoffUnbound},
		{name: "handoff grant on a home that does not hand off is needs-tier", health: "up", tier: core.TierCheckpoint, grants: []core.Grant{handoff},
			token: "gh", caller: "router-x5t", want: core.NeedsTier, wantErr: core.ErrNeedsHandoff},
		{name: "direct fiber has no route", health: "up", tier: core.TierCheckpoint, grants: []core.Grant{bound},
			token: "gb", caller: "router-x5t", want: core.OK, running: 1},
		{name: "bound grant from its caller creates", health: "up", tier: core.TierCheckpoint, grants: []core.Grant{bound},
			token: "gb", caller: "router-x5t", requireBound: true, want: core.OK, running: 1},
		{name: "bound grant from another caller is unauthenticated", health: "up", tier: core.TierCheckpoint, grants: []core.Grant{bound},
			token: "gb", caller: "intruder-x5t", want: core.Unauthenticated, wantErr: core.ErrCallerMismatch},
		{name: "bound grant over plaintext is unauthenticated", health: "up", tier: core.TierCheckpoint, grants: []core.Grant{bound},
			token: "gb", want: core.Unauthenticated, wantErr: core.ErrCallerMismatch},
		{name: "unbound grant where binding is required is unauthenticated", health: "up", tier: core.TierCheckpoint, grants: []core.Grant{g1},
			token: "g1", caller: "router-x5t", requireBound: true, want: core.Unauthenticated, wantErr: core.ErrUnboundGrant},
		// The admitted grant and the token must bind the UID to the same
		// caller, because Park, Release and Watch check the admitted one.
		{name: "bound grant delivered ahead creates for its caller", health: "up", tier: core.TierCheckpoint, grants: []core.Grant{bound},
			setup: func(t *testing.T, a *core.Agent) { a.Ledger.AdmitGrant(bound) },
			token: "gb", caller: "router-x5t", want: core.OK, running: 1},
		{name: "token re-minted for another caller than the admitted grant is unauthenticated", health: "up", tier: core.TierCheckpoint, grants: []core.Grant{bound},
			setup: func(t *testing.T, a *core.Agent) {
				a.Ledger.AdmitGrant(core.Grant{UID: "gb", Tenant: "acme", Audience: "node-a", CallerThumbprint: "old-x5t"})
			},
			token: "gb", caller: "router-x5t", want: core.Unauthenticated, wantErr: core.ErrCallerMismatch},
		{name: "token that drops the admitted grant's caller binding is unauthenticated", health: "up", tier: core.TierCheckpoint, grants: []core.Grant{g1},
			setup: func(t *testing.T, a *core.Agent) {
				a.Ledger.AdmitGrant(core.Grant{UID: "g1", Tenant: "acme", Audience: "node-a", CallerThumbprint: "router-x5t"})
			},
			token: "g1", caller: "router-x5t", want: core.Unauthenticated, wantErr: core.ErrCallerMismatch},
		{name: "bad token is unauthenticated", health: "up", tier: core.TierCheckpoint, token: "nope", want: core.Unauthenticated},
		{name: "wrong audience is unauthenticated", health: "up", tier: core.TierCheckpoint,
			grants: []core.Grant{{UID: "gx", Tenant: "acme", Audience: "node-b"}}, token: "gx", want: core.Unauthenticated, wantErr: core.ErrWrongAudience},
		{name: "first sight self-admits and creates", health: "down", tier: core.TierCheckpoint,
			grants: []core.Grant{g1}, token: "g1", want: core.OK, running: 1},
		{name: "full healthy is fallback", health: "up", tier: core.TierCheckpoint, grants: []core.Grant{g1},
			setup: full, token: "g1", want: core.DeferredFallback, wantErr: core.ErrGrantFull, running: 1},
		{name: "full unhealthy is shed", health: "down", tier: core.TierCheckpoint, grants: []core.Grant{g1},
			setup: full, token: "g1", want: core.Shed, wantErr: core.ErrGrantFull, running: 1},
		{name: "full nil health fails toward fallback", health: "nil", tier: core.TierCheckpoint, grants: []core.Grant{g1},
			setup: full, token: "g1", want: core.DeferredFallback, wantErr: core.ErrGrantFull, running: 1},
		{name: "expired healthy is fallback", health: "up", tier: core.TierCheckpoint,
			grants: []core.Grant{{UID: "ge", Tenant: "acme", Audience: "node-a", LeaseExpiry: past}},
			token:  "ge", want: core.DeferredFallback, wantErr: core.ErrGrantExpired},
		{name: "expired unhealthy is shed", health: "down", tier: core.TierCheckpoint,
			grants: []core.Grant{{UID: "ge", Tenant: "acme", Audience: "node-a", LeaseExpiry: past}},
			token:  "ge", want: core.Shed, wantErr: core.ErrGrantExpired},
		{name: "a grant the home removed is fallback while healthy, its fiber released", health: "up", tier: core.TierCheckpoint,
			grants: []core.Grant{g1}, setup: removed, token: "g1", want: core.DeferredFallback, wantErr: core.ErrGrantRevoked},
		{name: "a grant the home removed is shed while unhealthy", health: "down", tier: core.TierCheckpoint,
			grants: []core.Grant{g1}, setup: removed, token: "g1", want: core.Shed, wantErr: core.ErrGrantRevoked},
		{name: "min_tier above runtime is needs-tier at admission", health: "down", tier: core.TierWarm,
			grants: []core.Grant{{UID: "gt", Tenant: "acme", Audience: "node-a", MinTier: core.TierCheckpoint}},
			token:  "gt", want: core.NeedsTier, wantErr: core.ErrNeedsTier},
		{name: "parked session on warm runtime is needs-tier", health: "down", tier: core.TierWarm, grants: []core.Grant{g1},
			setup: func(t *testing.T, a *core.Agent) {
				a.Ledger.AdmitGrant(g1)
				createFiber(t, a.Ledger, "g1", "S1", "f1")
				a.Ledger.OnPark("f1", "delta-f1")
			},
			token: "g1", session: "S1", want: core.NeedsTier, wantErr: core.ErrNeedsTier},
		{name: "unset isolation on a shared-kernel runtime is needs-tier", health: "up", tier: core.TierCheckpoint, grants: []core.Grant{g1},
			setup: shared, token: "g1", want: core.NeedsTier, wantErr: core.ErrNeedsIsolation},
		{name: "untrusted on a shared-kernel runtime is needs-tier", health: "up", tier: core.TierCheckpoint,
			grants: []core.Grant{{UID: "gu", Tenant: "acme", Audience: "node-a", Policy: core.Policy{Isolation: core.Untrusted}}},
			setup:  shared, token: "gu", want: core.NeedsTier, wantErr: core.ErrNeedsIsolation},
		{name: "trusted on a shared-kernel runtime creates", health: "up", tier: core.TierCheckpoint, grants: []core.Grant{trusted},
			setup: shared, token: "gtr", want: core.OK, running: 1},
		{name: "untrusted on an isolating runtime creates", health: "up", tier: core.TierCheckpoint,
			grants: []core.Grant{{UID: "gu", Tenant: "acme", Audience: "node-a", Policy: core.Policy{Isolation: core.Untrusted}}},
			token:  "gu", want: core.OK, running: 1},
		{name: "grant at its task limit is shed", health: "up", tier: core.TierCheckpoint, grants: []core.Grant{g1},
			setup: func(t *testing.T, a *core.Agent) {
				a.Runtime = fakeRuntime{tier: core.TierCheckpoint, exits: make(chan core.FiberExit, 8),
					fail: fmt.Errorf("%w: pids.max", core.ErrPressure)}
			},
			token: "g1", want: core.Shed, wantErr: core.ErrPressure},
		{name: "other runtime failure is fallback", health: "up", tier: core.TierCheckpoint, grants: []core.Grant{g1},
			setup: func(t *testing.T, a *core.Agent) {
				a.Runtime = fakeRuntime{tier: core.TierCheckpoint, exits: make(chan core.FiberExit, 8), fail: errors.New("zygote gone")}
			},
			token: "g1", want: core.DeferredFallback},
		{name: "payload too large is invalid", health: "up", tier: core.TierCheckpoint, grants: []core.Grant{g1},
			token: "g1", payload: core.MaxPayload + 1, want: core.Invalid, wantErr: core.ErrPayloadTooLarge},
		{name: "sync audit failure fails the clone as internal", health: "up", tier: core.TierCheckpoint,
			grants: []core.Grant{{UID: "gs", Tenant: "acme", Audience: "node-a", Policy: core.Policy{Durability: core.Sync}}},
			setup:  func(t *testing.T, a *core.Agent) { a.Audit = failingAuditor{} },
			token:  "gs", want: core.Internal, wantErr: core.ErrAudit, running: 0},
		// The exit for the fiber the clone will mint (fence g1/1/1) is
		// delivered before that clone commits.
		{name: "exit before commit is not leaked", health: "up", tier: core.TierCheckpoint, grants: []core.Grant{g1},
			setup: func(t *testing.T, a *core.Agent) {
				a.OnExit(context.Background(), core.FiberExit{FiberID: "g1/1/1", Reason: "oom"})
			},
			token: "g1", want: core.OK},
		{name: "a verifier that cannot decide is shed, not unauthenticated", health: "up", tier: core.TierCheckpoint, grants: []core.Grant{g1},
			setup: func(t *testing.T, a *core.Agent) { a.Verify = acceptVerifier{down: true} },
			token: "g1", want: core.Shed, wantErr: core.ErrVerifyUnavailable},
		{name: "an exhausted thrash budget is shed before any work", health: "up", tier: core.TierCheckpoint, grants: []core.Grant{g1},
			setup: func(t *testing.T, a *core.Agent) { a.Budget = core.NewBudget(0, 256<<20) },
			token: "g1", want: core.Shed, wantErr: core.ErrBudget},
		{name: "a sync audit failure on attach is internal, and the fiber runs on", health: "up", tier: core.TierCheckpoint, grants: []core.Grant{syncG},
			setup: func(t *testing.T, a *core.Agent) {
				a.Ledger.AdmitGrant(syncG)
				createFiber(t, a.Ledger, "gs", "S", "f1")
				a.Audit = failingAuditor{}
			},
			token: "gs", session: "S", want: core.Internal, wantErr: core.ErrAudit, running: 1},
		{name: "a runtime past its deadline is fallback", health: "up", tier: core.TierCheckpoint, grants: []core.Grant{g1},
			setup: func(t *testing.T, a *core.Agent) {
				a.Runtime = fakeRuntime{tier: core.TierCheckpoint, exits: make(chan core.FiberExit, 8), fail: context.DeadlineExceeded}
			},
			token: "g1", want: core.DeferredFallback, wantErr: core.ErrDeadline},
		{name: "a best-effort audit failure does not fail the clone", health: "up", tier: core.TierCheckpoint, grants: []core.Grant{g1},
			setup: func(t *testing.T, a *core.Agent) { a.Audit = brokenAuditor{} },
			token: "g1", want: core.OK, running: 1},
		// The rollback after a failed sync record cannot release the fiber,
		// so it may still run. It stays counted against the grant.
		{name: "a rollback the runtime refuses keeps the fiber counted", health: "up", tier: core.TierCheckpoint, grants: []core.Grant{syncG},
			setup: func(t *testing.T, a *core.Agent) {
				a.Runtime = fakeRuntime{tier: core.TierCheckpoint, exits: make(chan core.FiberExit, 8), releaseFail: errors.New("kill: EPERM")}
				a.Audit = failingAuditor{}
			},
			token: "gs", want: core.Internal, wantErr: core.ErrAudit, running: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newAgent(t, tc.health, tc.tier, tc.grants...)
			a.RequireBoundGrants = tc.requireBound
			if tc.setup != nil {
				tc.setup(t, a)
			}
			req := core.CloneRequest{GrantJWT: []byte(tc.token), Session: tc.session, Deadline: time.Second,
				Payload: make([]byte, tc.payload), CallerThumbprint: tc.caller}
			resp, code, err := a.Clone(context.Background(), req)
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("Clone err = %v, want %v", err, tc.wantErr)
			}
			if code != tc.want {
				t.Fatalf("Clone code = %d, want %d (err %v)", code, tc.want, err)
			}
			if resp.RoutingKey != tc.wantRoute || (tc.wantRoute != "") != (resp.ServerKeySHA256 != "") {
				t.Fatalf("route = %q pin %q, want %q", resp.RoutingKey, resp.ServerKeySHA256, tc.wantRoute)
			}
			if st, _ := coretest.GrantStatus(a.Ledger, tc.token); st.Running != tc.running {
				t.Fatalf("running = %d after clone, want %d", st.Running, tc.running)
			}
		})
	}
}

// blockingRuntime is a fakeRuntime whose Clone announces the fiber it is
// about to make and then waits until the test lets it finish, so the
// test can act on the agent mid-clone. It records the fibers it is asked
// to release.
type blockingRuntime struct {
	fakeRuntime
	started    chan string   // the fiber about to be born
	proceed    chan struct{} // closed to let clones finish
	released   chan string
	releaseErr error // what Release answers after recording the fiber
}

func newBlockingRuntime() blockingRuntime {
	return blockingRuntime{
		fakeRuntime: fakeRuntime{tier: core.TierCheckpoint, exits: make(chan core.FiberExit, 8)},
		started:     make(chan string, 4), proceed: make(chan struct{}), released: make(chan string, 4),
	}
}

func (r blockingRuntime) Clone(ctx context.Context, spec core.CloneSpec) (core.FiberHandle, error) {
	id := spec.Fence.String()
	r.started <- id
	select {
	case <-r.proceed:
	case <-ctx.Done():
		return core.FiberHandle{}, ctx.Err()
	}
	return core.FiberHandle{ID: id, Endpoint: "127.0.0.1:1"}, nil
}

func (r blockingRuntime) Release(_ context.Context, id string, _ bool) error {
	r.released <- id
	return r.releaseErr
}

// TestCloneRacesSweep yields, removes or bumps the epoch of a grant while
// the runtime is mid-clone, after Resolve and before commit. The new fiber
// must not outlive the sweep. The runtime releases it, the ledger never
// counts it, and the caller gets the miss the sweep implies. A fresh clone
// afterwards creates under the current epoch.
func TestCloneRacesSweep(t *testing.T) {
	g := core.Grant{UID: "g1", Tenant: "acme", Audience: "node-a", TemplateDigest: "sha256:t", LeaseExpiry: time.Now().Add(time.Hour)}
	ctx := context.Background()
	cases := []struct {
		name     string
		setup    func(t *testing.T, a *core.Agent)
		midClone func(t *testing.T, a *core.Agent)
		readmit  func(t *testing.T, a *core.Agent) // optional, lifts what the sweep left behind
		// syncAudit makes the grant sync and fails its records during the
		// swept clone, so the clone rolls back before it commits.
		syncAudit  bool
		releaseErr error // the runtime cannot release the swept fiber
		want       core.StatusCode
		wantErr    error
		wantEpoch  uint64 // the epoch the clone after the sweep is minted under
	}{
		{name: "yield mid-clone", midClone: func(_ *testing.T, a *core.Agent) { a.Yield(ctx, "g1", "ladder") },
			want: core.DeferredFallback, wantErr: core.ErrGrantUnknown, wantEpoch: 1},
		{name: "remove mid-clone", setup: func(t *testing.T, a *core.Agent) {
			r, err := core.OpenRevoked(filepath.Join(t.TempDir(), "revoked.json"), time.Hour, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			a.Revoked = r
		}, midClone: func(_ *testing.T, a *core.Agent) { a.Remove(ctx, "g1") },
			readmit: func(_ *testing.T, a *core.Agent) { a.Redeliver(ctx, "g1") },
			want:    core.DeferredFallback, wantErr: core.ErrGrantRevoked, wantEpoch: 1},
		{name: "bumpEpoch mid-clone", setup: func(t *testing.T, a *core.Agent) {
			store, err := core.OpenEpochStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			a.Epoch = store
		}, midClone: func(t *testing.T, a *core.Agent) {
			if _, err := a.BumpEpoch(ctx, "namespace deleted"); err != nil {
				t.Fatal(err)
			}
		}, want: core.DeferredFallback, wantErr: core.ErrFiberUnknown, wantEpoch: 2},
		// The fiber cannot be released, so nothing counts it. The runtime's
		// List at the next start finds it.
		{name: "yield mid-clone with a release that fails", midClone: func(_ *testing.T, a *core.Agent) { a.Yield(ctx, "g1", "ladder") },
			releaseErr: errors.New("kill: EPERM"), want: core.DeferredFallback, wantErr: core.ErrGrantUnknown, wantEpoch: 1},
		// The rollback after the failed record cannot release the fiber,
		// and the commit that would keep it counted is refused too.
		{name: "yield mid-clone after a failed sync record, with a release that fails", syncAudit: true,
			midClone:   func(_ *testing.T, a *core.Agent) { a.Yield(ctx, "g1", "ladder") },
			releaseErr: errors.New("kill: EPERM"), want: core.Internal, wantErr: core.ErrAudit, wantEpoch: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := g
			if tc.syncAudit {
				g.Policy.Durability = core.Sync
			}
			a := newAgent(t, "up", core.TierCheckpoint, g)
			rt := newBlockingRuntime()
			rt.releaseErr = tc.releaseErr
			a.Runtime = rt
			if tc.syncAudit {
				a.Audit = failingAuditor{}
			}
			if tc.setup != nil {
				tc.setup(t, a)
			}
			req := core.CloneRequest{GrantJWT: []byte("g1"), Session: "S", Deadline: 5 * time.Second}
			type result struct {
				resp core.CloneResponse
				code core.StatusCode
				err  error
			}
			done := make(chan result, 1)
			go func() {
				r, code, err := a.Clone(ctx, req)
				done <- result{r, code, err}
			}()
			var id string
			select {
			case id = <-rt.started:
			case <-time.After(2 * time.Second):
				t.Fatal("the clone never reached the runtime")
			}
			tc.midClone(t, a)
			close(rt.proceed)
			r := <-done
			if r.code != tc.want || !errors.Is(r.err, tc.wantErr) {
				t.Fatalf("clone under the sweep = %d %v, want %d %v", r.code, r.err, tc.want, tc.wantErr)
			}
			select {
			case got := <-rt.released:
				if got != id {
					t.Fatalf("released %s, want the fiber born under the sweep, %s", got, id)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("fiber %s born under the sweep was never released", id)
			}
			if ids := a.Ledger.RunningFibers(); len(ids) != 0 {
				t.Fatalf("running fibers after the sweep = %v, want none", ids)
			}
			if st, _ := coretest.GrantStatus(a.Ledger, "g1"); st.Running != 0 {
				t.Fatalf("running = %d after the sweep, want 0", st.Running)
			}
			if tc.readmit != nil {
				tc.readmit(t, a)
			}
			a.Audit = nil
			again, code, err := a.Clone(ctx, req)
			if err != nil || code != core.OK || again.Kind != core.ActCreate {
				t.Fatalf("clone after the sweep = %v %d %v, want a fresh create", again.Kind, code, err)
			}
			// After a yield the re-admitted grant mints from seq 1 again, so
			// the new fence may equal the swept fiber's. The ledger must
			// know only the new one under it.
			if again.Fence.Epoch != tc.wantEpoch {
				t.Fatalf("clone after the sweep = %s epoch %d, want epoch %d", again.FiberID, again.Fence.Epoch, tc.wantEpoch)
			}
			if f, ok := a.Ledger.Fiber(again.FiberID); !ok || f != again.Fence {
				t.Fatalf("ledger fiber %s = %+v %v, want the fresh clone's fence %+v", again.FiberID, f, ok, again.Fence)
			}
			if st, _ := coretest.GrantStatus(a.Ledger, "g1"); st.Running != 1 {
				t.Fatalf("running = %d after the fresh clone, want 1", st.Running)
			}
		})
	}
}

// TestExitRacesCommit delivers a fiber's exit while its Clone is between
// the runtime call and the commit. The exit looks the fiber up and finds
// it unknown, the Clone commits, and only then does the exit go on. The
// exit must still end the fiber. Before the fix the lookup and the hold
// were under different locks, so the commit found nothing held, the hold
// landed after it, and the dead fiber stayed counted with no record.
func TestExitRacesCommit(t *testing.T) {
	g := core.Grant{UID: "g1", Tenant: "acme", Audience: "node-a", FiberMax: 1, LeaseExpiry: time.Now().Add(time.Hour)}
	ctx := context.Background()
	cases := []struct {
		name    string
		session string
		reason  string
	}{
		{name: "anonymous fiber", reason: "oom"},
		{name: "named session", session: "S", reason: "exit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newAgent(t, "up", core.TierCheckpoint, g)
			rt := newBlockingRuntime()
			a.Runtime = rt
			audit := &auditLog{}
			a.Audit = audit
			lookedUp := make(chan struct{})
			goOn := make(chan struct{})
			core.SetExitLookedUp(a, func(_ string, known bool) {
				if known {
					return // the replay from the commit, which may run it
				}
				lookedUp <- struct{}{}
				<-goOn
			})
			type result struct {
				code core.StatusCode
				err  error
			}
			done := make(chan result, 1)
			go func() {
				_, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Session: tc.session, Deadline: 5 * time.Second})
				done <- result{code, err}
			}()
			var id string
			select {
			case id = <-rt.started:
			case <-time.After(2 * time.Second):
				t.Fatal("the clone never reached the runtime")
			}
			// The exit arrives on its own goroutine, as Run delivers it, and
			// is held once it has found the fiber unknown.
			exited := make(chan struct{})
			go func() {
				a.OnExit(ctx, core.FiberExit{FiberID: id, Reason: tc.reason})
				close(exited)
			}()
			select {
			case <-lookedUp:
			case <-time.After(2 * time.Second):
				t.Fatal("the exit never looked the fiber up")
			}
			close(rt.proceed)
			select {
			case r := <-done:
				if r.code != core.OK || r.err != nil {
					t.Fatalf("clone = %d %v, want OK", r.code, r.err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("the clone never returned")
			}
			close(goOn)
			select {
			case <-exited:
			case <-time.After(2 * time.Second):
				t.Fatal("the exit never returned")
			}
			if _, ok := a.Ledger.Fiber(id); ok {
				t.Fatalf("fiber %s is still known after its exit", id)
			}
			if st, _ := coretest.GrantStatus(a.Ledger, "g1"); st.Running != 0 {
				t.Fatalf("running = %d after the exit, want 0", st.Running)
			}
			if tc.session != "" {
				if _, _, known := a.Ledger.SessionState("g1", tc.session); known {
					t.Fatalf("session %s is still known after its fiber exited", tc.session)
				}
			}
			if recs := audit.events(tc.reason); len(recs) != 1 || recs[0].FiberID != id {
				t.Fatalf("%s records = %+v, want one for %s", tc.reason, recs, id)
			}
		})
	}
}

// TestCloneIdempotentAndResume runs one session name through its life. A
// repeated clone attaches to the same fiber, a parked session resumes
// under the next fence, and a released name is free for a fresh create.
// The steps run in order against one agent.
func TestCloneIdempotentAndResume(t *testing.T) {
	g := core.Grant{UID: "g1", Tenant: "acme", Audience: "node-a", FiberMax: 2}
	a := newAgent(t, "up", core.TierCheckpoint, g)
	ctx := context.Background()
	req := core.CloneRequest{GrantJWT: []byte("g1"), Session: "S", Deadline: time.Second}
	clone := func() (core.CloneResponse, core.StatusCode, error) { return a.Clone(ctx, req) }
	park := func(id func() string) func() (core.CloneResponse, core.StatusCode, error) {
		return func() (core.CloneResponse, core.StatusCode, error) {
			_, code, err := a.Park(ctx, id(), false)
			return core.CloneResponse{}, code, err
		}
	}
	var first, resumed core.CloneResponse
	steps := []struct {
		name     string
		do       func() (core.CloneResponse, core.StatusCode, error)
		wantCode core.StatusCode
		wantErr  error
		check    func(t *testing.T, r core.CloneResponse) // optional
	}{
		{name: "first clone creates", do: clone, check: func(t *testing.T, r core.CloneResponse) {
			if r.Kind != core.ActCreate {
				t.Fatalf("first clone = %v, want create", r.Kind)
			}
			first = r
		}},
		{name: "second clone attaches to the same endpoint and fence", do: clone, check: func(t *testing.T, r core.CloneResponse) {
			if r.Kind != core.ActAttach || r.Endpoint != first.Endpoint || r.Fence != first.Fence {
				t.Fatalf("second clone = %+v, want attach with same endpoint/fence as %+v", r, first)
			}
		}},
		{name: "park", do: park(func() string { return first.FiberID })},
		{name: "clone after park resumes with seq+1 in the same epoch", do: clone, check: func(t *testing.T, r core.CloneResponse) {
			if r.Kind != core.ActResume || r.Fence.Seq != first.Fence.Seq+1 || r.Fence.Epoch != first.Fence.Epoch {
				t.Fatalf("resume = %+v, want RESUME with seq+1 same epoch (from %+v)", r.Fence, first.Fence)
			}
			resumed = r
		}},
		{name: "park of an unknown fiber is not found", do: park(func() string { return "g1/1/99" }),
			wantCode: core.NotFound, wantErr: core.ErrFiberUnknown},
		{name: "release", do: func() (core.CloneResponse, core.StatusCode, error) {
			code, err := a.Release(ctx, resumed.FiberID, true)
			return core.CloneResponse{}, code, err
		}},
		{name: "clone after release creates (name freed)", do: clone, check: func(t *testing.T, r core.CloneResponse) {
			if r.Kind != core.ActCreate {
				t.Fatalf("after release, clone = %v, want create (name freed)", r.Kind)
			}
		}},
	}
	for _, tc := range steps {
		if !t.Run(tc.name, func(t *testing.T) {
			r, code, err := tc.do()
			if code != tc.wantCode || !errors.Is(err, tc.wantErr) {
				t.Fatalf("%s = %d %v, want %d %v", tc.name, code, err, tc.wantCode, tc.wantErr)
			}
			if tc.check != nil {
				tc.check(t, r)
			}
		}) {
			return // later steps build on this one
		}
	}
}

// TestParkOutcomes checks what Park and Release answer, the session's
// ledger state afterwards, and whether the snapshot holds it parked. The
// ledger must follow the runtime. A fiber the runtime ended is parked or
// gone even if a later step failed, or its slot stays taken forever.
func TestParkOutcomes(t *testing.T) {
	g := core.Grant{UID: "g1", Tenant: "acme", Audience: "node-a", FiberMax: 1}
	gs := core.Grant{UID: "g1", Tenant: "acme", Audience: "node-a", FiberMax: 1, Policy: core.Policy{Durability: core.Sync}}
	cases := []struct {
		name      string
		grant     core.Grant // zero = g
		fiber     string     // "" = the fiber just created
		release   bool       // Release(discard) instead of Park
		parkFail  error
		parkRef   bool // the runtime ended the fiber and has the delta despite parkFail
		auditFail bool // sync records fail
		noRef     bool // the runtime parks nothing and reports no error
		// releaseFail is what the runtime's Release answers.
		releaseFail error
		revoke      bool // the grant is revoked, its fibers left running, before the call
		storeFail   bool // the snapshot cannot be written
		want        core.StatusCode
		wantErr     error
		wantState   string // the session in the ledger and the snapshot (running, parked, gone)
	}{
		{name: "parks", want: core.OK, wantState: "parked"},
		{name: "unknown fiber is not found", fiber: "g1/1/99", want: core.NotFound, wantErr: core.ErrFiberUnknown, wantState: "running"},
		{name: "over the delta quota is shed", parkFail: fmt.Errorf("%w: 2GiB", core.ErrDeltaQuota), want: core.Shed, wantErr: core.ErrDeltaQuota, wantState: "running"},
		{name: "checkpoint failure is internal", parkFail: errors.New("criu dump"), want: core.Internal, wantState: "running"},
		{name: "a failure after the dump is internal, and the session is parked", parkFail: errors.New("did not exit after park"), parkRef: true,
			want: core.Internal, wantState: "parked"},
		{name: "a sync audit failure after the park is internal, and the session is parked", grant: gs, auditFail: true,
			want: core.Internal, wantErr: core.ErrAudit, wantState: "parked"},
		{name: "releases", release: true, want: core.OK, wantState: "gone"},
		{name: "a sync audit failure after the release is internal, and the session is gone", grant: gs, release: true, auditFail: true,
			want: core.Internal, wantErr: core.ErrAudit, wantState: "gone"},
		{name: "a runtime that parks nothing without an error is internal", noRef: true, want: core.Internal, wantState: "running"},
		{name: "release of an unknown fiber is not found", release: true, fiber: "g1/1/99", want: core.NotFound, wantErr: core.ErrFiberUnknown, wantState: "running"},
		{name: "a release the runtime refuses is internal, and the fiber runs on", release: true, releaseFail: errors.New("kill: EPERM"),
			want: core.Internal, wantState: "running"},
		// Durability is the admitted grant's. A revoked grant has none, so
		// the record is best-effort and its failure does not fail the park.
		{name: "a fiber whose grant was revoked parks with a best-effort record", grant: gs, auditFail: true, revoke: true,
			want: core.OK, wantState: "parked"},
		{name: "a snapshot that cannot be written does not fail the park", storeFail: true, want: core.OK, wantState: "parked"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			grant := tc.grant
			if grant.UID == "" {
				grant = g
			}
			a := newAgent(t, "up", core.TierCheckpoint, grant)
			a.Runtime = fakeRuntime{tier: core.TierCheckpoint, exits: make(chan core.FiberExit, 8), parkFail: tc.parkFail, parkRef: tc.parkRef,
				noRef: tc.noRef, releaseFail: tc.releaseFail}
			dir := t.TempDir()
			if tc.storeFail {
				dir = filepath.Join(dir, "missing")
			}
			a.Store = &core.SnapshotStore{Path: filepath.Join(dir, "ledger.json")}
			ctx := context.Background()
			r, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Session: "S", Deadline: time.Second})
			if err != nil || code != core.OK {
				t.Fatalf("clone: %v %d", err, code)
			}
			if tc.auditFail {
				a.Audit = failingAuditor{}
			}
			if tc.revoke {
				a.Revoke("g1")
			}
			id := tc.fiber
			if id == "" {
				id = r.FiberID
			}
			if tc.release {
				code, err = a.Release(ctx, id, true)
			} else {
				_, code, err = a.Park(ctx, id, false)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if code != tc.want {
				t.Fatalf("code = %d, want %d (err %v)", code, tc.want, err)
			}
			if got := ledgerState(a.Ledger, "g1", "S"); got != tc.wantState {
				t.Fatalf("ledger session = %s, want %s", got, tc.wantState)
			}
			if _, ok := a.Ledger.Fiber(r.FiberID); ok != (tc.wantState == "running") {
				t.Fatalf("ledger knows fiber %s = %v, want %v", r.FiberID, ok, tc.wantState == "running")
			}
			snap, err := a.Store.Load()
			if err != nil {
				t.Fatal(err)
			}
			// Only parked sessions are persisted. The warm path (create,
			// release) writes no snapshot.
			wantPersisted := tc.wantState == "parked" && !tc.storeFail
			if got := snapshotState(snap, "g1", "S"); (got == "parked") != wantPersisted {
				t.Fatalf("persisted session = %s, want parked %v", got, wantPersisted)
			}
		})
	}
}

// ledgerState names a session's state in the ledger as running, parked,
// or gone when the ledger does not know it.
func ledgerState(l *core.Ledger, grant, session string) string {
	st, _, ok := l.SessionState(grant, session)
	switch {
	case !ok:
		return "gone"
	case st == core.StateParked:
		return "parked"
	default:
		return "running"
	}
}

// snapshotState is ledgerState for a persisted snapshot.
func snapshotState(snap core.Snapshot, grant, session string) string {
	for _, s := range snap.Sessions {
		if s.GrantUID == grant && s.Name == session {
			if s.State == core.StateParked {
				return "parked"
			}
			return "running"
		}
	}
	return "gone"
}

// TestWatchAndSampler checks that the agent samples each fiber's W from the
// runtime (the fake reports 7 bytes per fiber) and Watch streams the
// grant's status once it reflects the clones. A fiber whose stats fail
// adds nothing, and the sum stays at what the others report. With no
// StatusInterval both loops run every second.
func TestWatchAndSampler(t *testing.T) {
	cases := []struct {
		name        string
		sessions    []string
		statsFail   string        // the fiber whose stats fail
		interval    time.Duration // StatusInterval, 0 means the one-second default
		stable      int           // further emissions the observed state must hold for
		wantRunning int
		wantW       uint64
	}{
		{name: "one fiber is reported running with its sampled W", sessions: []string{""}, interval: 10 * time.Millisecond, wantRunning: 1, wantW: 7},
		{name: "W of several fibers is summed", sessions: []string{"", "S"}, interval: 10 * time.Millisecond, wantRunning: 2, wantW: 14},
		{name: "a fiber whose stats fail adds nothing", sessions: []string{"", "S"}, statsFail: "g1/1/2", interval: 10 * time.Millisecond,
			stable: 5, wantRunning: 2, wantW: 7},
		{name: "the default interval samples every second", sessions: []string{""}, wantRunning: 1, wantW: 7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := core.Grant{UID: "g1", Tenant: "acme", Audience: "node-a"}
			a := newAgent(t, "up", core.TierCheckpoint, g)
			a.Runtime = fakeRuntime{tier: core.TierCheckpoint, exits: make(chan core.FiberExit, 8), statsFail: tc.statsFail}
			a.StatusInterval = tc.interval
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go a.Run(ctx)
			w := a.Watch(ctx)
			<-w // initial (empty)
			for _, session := range tc.sessions {
				if _, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Session: session, Deadline: time.Second}); err != nil || code != core.OK {
					t.Fatalf("clone %q: %v %d", session, err, code)
				}
			}
			deadline := time.After(5 * time.Second)
			seen := -1 // emissions since the state was first observed
			for seen < tc.stable {
				select {
				case batch := <-w:
					for _, st := range batch {
						if st.GrantUID != "g1" {
							continue
						}
						match := st.Running == tc.wantRunning && st.WUsedBytes == tc.wantW
						switch {
						case match:
							seen++
						case seen >= 0:
							t.Fatalf("status after the sampled state = %+v, want running=%d W=%d to hold", st, tc.wantRunning, tc.wantW)
						}
					}
				case <-deadline:
					t.Fatalf("never observed running=%d with sampled W=%d for %d emissions", tc.wantRunning, tc.wantW, tc.stable+1)
				}
			}
		})
	}
}

type failingAuditor struct{}

func (failingAuditor) Append(_ context.Context, d core.Durability, _ core.AuditRecord) error {
	if d == core.Sync {
		return core.ErrAudit
	}
	return nil
}

// brokenAuditor fails every record, sync or not.
type brokenAuditor struct{}

func (brokenAuditor) Append(context.Context, core.Durability, core.AuditRecord) error {
	return core.ErrAudit
}
