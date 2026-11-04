package core_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/Azure/fiberd/pkg/core"
)

// drainRuntime is fakeRuntime with what a drain test needs on top. It
// keeps the deltas its parks write, so a resume needs a real one and
// HasDelta answers. A park can fail or wait on a gate, a clone can wait
// on a gate, a publish can fail, and it records every release and how
// many parks and releases run at once.
type drainRuntime struct {
	fakeRuntime
	parkErr error         // what Park answers, the fiber left running
	pubErr  error         // what PublishDelta answers
	gate    chan struct{} // when set, Park waits on it or on its ctx
	entered chan string   // told the fiber each Park starts on

	mu    sync.Mutex
	syncs []bool // the sync flag of every Park
	busy  int    // parks and releases under way
	peak  int    // the most that were under way at once
	// cloneGate, when set, holds every Clone until it closes, and cloning
	// is told each held Clone's session as it starts.
	cloneGate chan struct{}
	cloning   chan string
	held      []string // the fibers held Clones made
	released  []string // every fiber Release was asked for
	// deltas are the refs parks wrote that nothing discarded.
	deltas map[string]bool
}

func (r *drainRuntime) Clone(ctx context.Context, spec core.CloneSpec) (core.FiberHandle, error) {
	r.mu.Lock()
	gate := r.cloneGate
	r.mu.Unlock()
	if gate != nil {
		r.cloning <- spec.Session
		select {
		case <-gate:
		case <-ctx.Done():
			return core.FiberHandle{}, ctx.Err()
		}
	}
	if spec.Source == core.SourceDelta && !r.HasDelta(spec.Ref) {
		return core.FiberHandle{}, fmt.Errorf("drain runtime: unknown delta %q", spec.Ref)
	}
	h, err := r.fakeRuntime.Clone(ctx, spec)
	if gate != nil {
		r.mu.Lock()
		r.held = append(r.held, h.ID)
		r.mu.Unlock()
	}
	return h, err
}

// HasDelta implements core.DeltaChecker.
func (r *drainRuntime) HasDelta(ref string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.deltas[ref]
}

// DiscardDelta implements core.DeltaDiscarder.
func (r *drainRuntime) DiscardDelta(_ context.Context, ref string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.deltas, ref)
	return nil
}

// holdClones makes every later Clone wait until the returned release.
func (r *drainRuntime) holdClones() (release func()) {
	gate := make(chan struct{})
	r.mu.Lock()
	r.cloneGate, r.cloning = gate, make(chan string, 8)
	r.mu.Unlock()
	return func() { close(gate) }
}

// heldReleased reports the fibers held Clones made, and whether Release
// was asked for each.
func (r *drainRuntime) heldReleased() ([]string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range r.held {
		if !slices.Contains(r.released, id) {
			return r.held, false
		}
	}
	return r.held, len(r.held) > 0
}

func newDrainRuntime() *drainRuntime {
	return &drainRuntime{
		fakeRuntime: fakeRuntime{tier: core.TierCheckpoint, exits: make(chan core.FiberExit, 8)},
		entered:     make(chan string, 32),
		deltas:      map[string]bool{},
	}
}

func (r *drainRuntime) enter() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.busy++
	r.peak = max(r.peak, r.busy)
}

func (r *drainRuntime) leave() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.busy--
}

func (r *drainRuntime) Park(ctx context.Context, id string, sync bool) (string, error) {
	r.enter()
	defer r.leave()
	r.mu.Lock()
	r.syncs = append(r.syncs, sync)
	r.mu.Unlock()
	r.entered <- id
	if r.gate != nil {
		select {
		case <-r.gate:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if r.parkErr != nil {
		return "", r.parkErr
	}
	ref := "delta-" + id
	r.mu.Lock()
	r.deltas[ref] = true
	r.mu.Unlock()
	return ref, nil
}

func (r *drainRuntime) Release(ctx context.Context, id string, discard bool) error {
	r.enter()
	defer r.leave()
	r.mu.Lock()
	r.released = append(r.released, id)
	if discard {
		delete(r.deltas, "delta-"+id)
	}
	r.mu.Unlock()
	return r.fakeRuntime.Release(ctx, id, discard)
}

// PublishDelta implements core.DeltaPublisher.
func (r *drainRuntime) PublishDelta(_ context.Context, _ string, _ core.Grant, session string) (string, error) {
	if r.pubErr != nil {
		return "", r.pubErr
	}
	return "registry.test/" + session, nil
}

func (r *drainRuntime) parkSyncs() []bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]bool(nil), r.syncs...)
}

func (r *drainRuntime) peakBusy() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.peak
}

var drainGrant = core.Grant{UID: "g1", Tenant: "acme", Audience: "node-a", FiberMax: 16, LeaseExpiry: time.Now().Add(time.Hour)}

// newDrainCore is a core over rt that admits drainGrant on its first
// clone and snapshots its ledger to a file.
func newDrainCore(t *testing.T, rt core.Runtime) (*core.Core, *core.SnapshotStore) {
	t.Helper()
	store := &core.SnapshotStore{Path: filepath.Join(t.TempDir(), "ledger.json")}
	return &core.Core{
		NodeID:    "node-a",
		Ledger:    core.NewLedger(1),
		RateLimit: core.NewRateLimit(1000, 256<<20),
		Runtime:   rt,
		Verify:    acceptVerifier{grants: map[string]core.Grant{drainGrant.UID: drainGrant}},
		Health:    testHealth("up"),
		Store:     store,
	}, store
}

// cloneN starts n fibers of drainGrant and returns their IDs. A prefix
// names them as sessions prefix0, prefix1 and so on, and none makes
// them anonymous.
func cloneN(t *testing.T, a *core.Core, n int, prefix string) []string {
	t.Helper()
	var ids []string
	for i := range n {
		session := ""
		if prefix != "" {
			session = fmt.Sprintf("%s%d", prefix, i)
		}
		resp, code, err := a.Clone(context.Background(), core.CloneRequest{GrantJWT: []byte(drainGrant.UID), Session: session, Deadline: time.Second})
		if code != core.OK {
			t.Fatalf("Clone(%q) = %d %v", session, code, err)
		}
		ids = append(ids, resp.FiberID)
	}
	return ids
}

// TestDrain checks what Drain does with the fibers it finds. Named
// sessions are parked with sync and published, anonymous fibers are
// released, and ledger.json holds the parked sessions afterwards. A park
// that fails leaves its fiber running. An ended ctx leaves every fiber
// as it was. At most four calls run at once, and a fiber gone before
// the drain reaches it is skipped.
func TestDrain(t *testing.T) {
	cases := []struct {
		name      string
		named     int
		anon      int
		parkErr   error
		pubErr    error
		cancelled bool // ctx ends before the drain
		gate      bool // parks wait until during has run
		// during runs while the drain is under way, before the gate opens.
		during  func(t *testing.T, a *core.Core, rt *drainRuntime, anon []string)
		want    core.DrainReport
		running int // fibers still running after the drain
	}{
		{name: "named sessions are parked and published, anonymous fibers released", named: 2, anon: 2,
			want: core.DrainReport{Parked: 2, Published: 2, Shed: 2}},
		{name: "a failed publish leaves the session parked on this home", named: 2, anon: 1, pubErr: errors.New("registry down"),
			want: core.DrainReport{Parked: 2, Shed: 1}},
		{name: "a failed park is counted and its fiber keeps running", named: 1, anon: 1, parkErr: errors.New("criu: dump failed"),
			want: core.DrainReport{Failed: 1, Shed: 1}, running: 1},
		{name: "an ended ctx leaves every fiber", named: 2, anon: 1, cancelled: true,
			want: core.DrainReport{Left: 3}, running: 3},
		{name: "four at a time, and a fiber gone meanwhile is skipped", named: 4, anon: 1, gate: true,
			during: func(t *testing.T, a *core.Core, rt *drainRuntime, anon []string) {
				for range 4 {
					select {
					case <-rt.entered:
					case <-time.After(5 * time.Second):
						t.Fatal("four parks did not start")
					}
				}
				// The anonymous fiber waits for a free worker.
				time.Sleep(100 * time.Millisecond)
				if _, ok := a.Ledger.Fiber(anon[0]); !ok || rt.peakBusy() != 4 {
					t.Fatalf("with four parks held: anonymous fiber running %v, peak %d, want running and 4", ok, rt.peakBusy())
				}
				// It dies on its own before a worker frees up.
				a.OnExit(context.Background(), core.FiberExit{FiberID: anon[0], Reason: "exit"})
			},
			want: core.DrainReport{Parked: 4, Published: 4}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newDrainRuntime()
			rt.parkErr, rt.pubErr = tc.parkErr, tc.pubErr
			if tc.gate {
				rt.gate = make(chan struct{})
			}
			a, store := newDrainCore(t, rt)
			cloneN(t, a, tc.named, "s")
			anon := cloneN(t, a, tc.anon, "")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancelled {
				cancel()
			}
			done := make(chan core.DrainReport, 1)
			go func() { done <- a.Drain(ctx) }()
			if tc.during != nil {
				tc.during(t, a, rt, anon)
			}
			if rt.gate != nil {
				close(rt.gate)
			}
			var got core.DrainReport
			select {
			case got = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("Drain did not return")
			}
			if got != tc.want {
				t.Fatalf("Drain = %v, want %v", got, tc.want)
			}
			if n := len(a.Ledger.RunningFibers()); n != tc.running {
				t.Fatalf("running fibers = %d, want %d", n, tc.running)
			}
			for _, s := range rt.parkSyncs() {
				if !s {
					t.Fatal("a drain park was not sync")
				}
			}
			if peak := rt.peakBusy(); peak > 4 {
				t.Fatalf("%d parks and releases ran at once, want at most 4", peak)
			}
			snap, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			parked := 0
			for _, s := range snap.Sessions {
				if s.State == core.StateParked {
					parked++
				}
			}
			if parked != tc.want.Parked {
				t.Fatalf("ledger.json holds %d parked sessions, want %d", parked, tc.want.Parked)
			}
			if !a.Draining() {
				t.Fatal("Draining() = false after Drain")
			}
		})
	}
}

// TestDrainingRefusesClones checks that once Drain has run every Clone is
// a DeferredFallback miss with ErrDraining, an attach to a session still
// running included. A drain is final, so the refusal stays.
func TestDrainingRefusesClones(t *testing.T) {
	cases := []struct {
		name     string
		drain    bool
		running  string // a session started before the drain, kept running by a failing park
		session  string // what the clone asks for
		wantCode core.StatusCode
		wantErr  error
	}{
		{name: "before a drain a new fiber is created", wantCode: core.OK},
		{name: "before a drain an attach answers", running: "s0", session: "s0", wantCode: core.OK},
		{name: "a draining home refuses a new fiber", drain: true, wantCode: core.DeferredFallback, wantErr: core.ErrDraining},
		{name: "a draining home refuses a new session", drain: true, session: "s1", wantCode: core.DeferredFallback, wantErr: core.ErrDraining},
		{name: "a draining home refuses an attach", drain: true, running: "s0", session: "s0",
			wantCode: core.DeferredFallback, wantErr: core.ErrDraining},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newDrainRuntime()
			rt.parkErr = errors.New("criu: dump failed")
			a, _ := newDrainCore(t, rt)
			if tc.running != "" {
				cloneN(t, a, 1, "s")
			}
			if tc.drain {
				a.Drain(context.Background())
			}
			for range 2 {
				_, code, err := a.Clone(context.Background(), core.CloneRequest{GrantJWT: []byte(drainGrant.UID), Session: tc.session, Deadline: time.Second})
				if code != tc.wantCode || (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) || (tc.wantErr == nil && err != nil) {
					t.Fatalf("Clone = %d %v, want %d %v", code, err, tc.wantCode, tc.wantErr)
				}
			}
		})
	}
}

// TestDrainRefusesCloneInFlight checks a Clone that passed its draining
// check before Drain began and whose runtime work ends after Drain
// listed the fibers. The ledger refuses its commit, so no fiber escapes
// the drain. The Clone is a DeferredFallback miss with ErrDraining, its
// fiber is released, and a session it was resuming stays parked with its
// delta.
func TestDrainRefusesCloneInFlight(t *testing.T) {
	cases := []struct {
		name    string
		session string
		parked  bool // the session is parked first, so the clone resumes it
	}{
		{name: "a new anonymous fiber"},
		{name: "a new named session", session: "s0"},
		{name: "a resumed session stays parked", session: "s0", parked: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			rt := newDrainRuntime()
			a, _ := newDrainCore(t, rt)
			var parkedRef string
			if tc.parked {
				id := cloneN(t, a, 1, "s")[0]
				ref, code, err := a.Park(ctx, id, true)
				if code != core.OK {
					t.Fatalf("Park = %d %v", code, err)
				}
				parkedRef = ref
			}
			release := rt.holdClones()
			type result struct {
				code core.StatusCode
				err  error
			}
			done := make(chan result, 1)
			go func() {
				_, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte(drainGrant.UID), Session: tc.session, Deadline: 10 * time.Second})
				done <- result{code, err}
			}()
			select {
			case <-rt.cloning:
			case <-time.After(5 * time.Second):
				t.Fatal("the clone never reached the runtime")
			}
			if rep := a.Drain(ctx); rep != (core.DrainReport{}) {
				t.Fatalf("Drain = %v, want nothing listed while the clone is in flight", rep)
			}
			release()
			var got result
			select {
			case got = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("Clone did not return")
			}
			if got.code != core.DeferredFallback || !errors.Is(got.err, core.ErrDraining) {
				t.Fatalf("Clone = %d %v, want DeferredFallback with ErrDraining", got.code, got.err)
			}
			if held, ok := rt.heldReleased(); !ok {
				t.Fatalf("the clone made %v and the runtime was not asked to release it", held)
			}
			if n := len(a.Ledger.RunningFibers()); n != 0 {
				t.Fatalf("running fibers = %d, want 0", n)
			}
			st, ref, known := a.Ledger.SessionState(drainGrant.UID, tc.session)
			switch {
			case tc.parked && (!known || st != core.StateParked || ref != parkedRef || !rt.HasDelta(parkedRef)):
				t.Fatalf("session = %v %q known %v, want parked at %q with its delta", st, ref, known, parkedRef)
			case !tc.parked && tc.session != "" && known:
				t.Fatalf("session %q is in the ledger as %v, want none", tc.session, st)
			}
		})
	}
}

// TestDrainStopsRefill checks that the refill loop starts no fill once
// Drain has run, and fills as usual otherwise.
func TestDrainStopsRefill(t *testing.T) {
	cases := []struct {
		name  string
		drain bool
		fills bool
	}{
		{name: "a home that is not draining fills its pool", fills: true},
		{name: "a draining home fills nothing", drain: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := core.Grant{UID: "g1", Tenant: "acme", Audience: "node-a", FiberMax: 2, FiberWarm: 2, LeaseExpiry: time.Now().Add(time.Hour)}
			a := newCore(t, "up", core.TierSnapshot, g)
			p := newFakePool(core.TierSnapshot)
			a.Runtime = p
			ctx := context.Background()
			if code, err := a.Admit(ctx, g); err != nil || code != core.OK {
				t.Fatalf("admit = %d %v", code, err)
			}
			if tc.drain {
				a.Drain(ctx)
			}
			stop := runCore(t, a)
			defer stop()
			if tc.fills {
				waitUntil(t, 5*time.Second, "a fill", func() bool { return p.fillCount() > 0 })
				return
			}
			if n := settled(p, 200*time.Millisecond); n != 0 {
				t.Fatalf("fills = %d, want 0", n)
			}
		})
	}
}
