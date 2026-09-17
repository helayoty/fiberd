package core_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// listingRuntime is a fakeRuntime that reports running fibers and knows
// which deltas exist, like a real runtime after a restart.
type listingRuntime struct {
	fakeRuntime
	running  []core.FiberHandle
	deltas   map[string]bool
	released []string
}

func (l *listingRuntime) List(context.Context) ([]core.FiberHandle, error) { return l.running, nil }
func (l *listingRuntime) HasDelta(ref string) bool                         { return l.deltas[ref] }
func (l *listingRuntime) Release(_ context.Context, id string, _ bool) error {
	l.released = append(l.released, id)
	return nil
}

func TestSnapshotRoundTripAndReconcile(t *testing.T) {
	now := time.Now()
	live := core.Grant{UID: "live", Audience: "node-a", FiberMax: 3, LeaseExpiry: now.Add(time.Hour)}
	dead := core.Grant{UID: "dead", Audience: "node-a", LeaseExpiry: now.Add(-time.Minute)}

	// Epoch 1: run, park one session, leave one running, persist.
	a1 := newAgent(t, "up", core.TierCheckpoint, live, dead)
	store := &core.SnapshotStore{Path: filepath.Join(t.TempDir(), "ledger.json")}
	a1.Store = store
	ctx := context.Background()
	a1.Ledger.AdmitGrant(dead)
	p, code, err := a1.Clone(ctx, core.CloneRequest{GrantJWT: []byte("live"), Session: "parked", Deadline: time.Second})
	if err != nil || code != core.OK {
		t.Fatal(err)
	}
	if _, code, err := a1.Park(ctx, p.FiberID, true); err != nil || code != core.OK {
		t.Fatal(err)
	}
	r, _, _ := a1.Clone(ctx, core.CloneRequest{GrantJWT: []byte("live"), Session: "running", Deadline: time.Second})
	lost, _, _ := a1.Clone(ctx, core.CloneRequest{GrantJWT: []byte("live"), Session: "lost", Deadline: time.Second})
	if _, code, err := a1.Park(ctx, lost.FiberID, true); err != nil || code != core.OK {
		t.Fatal(err)
	}
	snap, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if snap.Epoch != 1 || len(snap.Grants) != 2 || len(snap.Sessions) != 3 || len(snap.Fibers) != 1 {
		t.Fatalf("snapshot = epoch %d grants %d sessions %d fibers %d", snap.Epoch, len(snap.Grants), len(snap.Sessions), len(snap.Fibers))
	}

	// Epoch 2: the runtime still shows the epoch-1 fiber (an orphan) and
	// has the delta for "parked" but not for "lost".
	a2 := newAgent(t, "up", core.TierCheckpoint, live, dead)
	a2.Ledger = core.NewLedger(2)
	rt := &listingRuntime{
		fakeRuntime: fakeRuntime{tier: core.TierCheckpoint, exits: make(chan core.FiberExit, 8)},
		running:     []core.FiberHandle{{ID: r.FiberID, Endpoint: "127.0.0.1:1"}},
		deltas:      map[string]bool{"delta": true},
	}
	// The fake park returns "delta" for every park; make "lost" distinct.
	for i := range snap.Sessions {
		if snap.Sessions[i].Name == "lost" {
			snap.Sessions[i].DeltaRef = "gone"
		}
	}
	a2.Runtime = rt
	rep, err := a2.Reconcile(ctx, snap)
	if err != nil {
		t.Fatal(err)
	}
	if rep.GrantsReadmitted != 1 || rep.GrantsExpired != 1 || rep.ParkedRestored != 1 || rep.ParkedDropped != 1 || rep.OrphansKilled != 1 {
		t.Fatalf("report = %+v", rep)
	}
	if len(rt.released) != 1 || rt.released[0] != r.FiberID {
		t.Fatalf("orphans released = %v, want [%s]", rt.released, r.FiberID)
	}
	if _, ok := a2.Ledger.Grant("dead"); ok {
		t.Fatal("expired grant re-admitted")
	}
	// The parked session resumes under the new epoch.
	res, code, err := a2.Clone(ctx, core.CloneRequest{GrantJWT: []byte("live"), Session: "parked", Deadline: time.Second})
	if err != nil || code != core.OK || res.Kind != core.ActResume || res.Fence.Epoch != 2 {
		t.Fatalf("resume after restart = %+v %d %v", res, code, err)
	}
	// The dropped one is a fresh create; the orphaned running one too.
	for _, name := range []string{"lost", "running"} {
		res, _, _ := a2.Clone(ctx, core.CloneRequest{GrantJWT: []byte("live"), Session: name, Deadline: time.Second})
		if res.Kind != core.ActCreate {
			t.Fatalf("%s after restart = %v, want create", name, res.Kind)
		}
	}
}

func TestSweepYieldsExpiredGrants(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	g := core.Grant{UID: "g1", Audience: "node-a", FiberMax: 3, LeaseExpiry: now.Add(time.Minute)}
	a := newAgent(t, "up", core.TierCheckpoint, g)
	a.Ledger.Now = func() time.Time { return now }
	ctx := context.Background()
	if _, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Session: "S", Deadline: time.Second}); err != nil || code != core.OK {
		t.Fatal(err)
	}
	if _, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Deadline: time.Second}); err != nil || code != core.OK {
		t.Fatal(err)
	}
	if n := a.Sweep(ctx); n != 0 {
		t.Fatalf("sweep before expiry yielded %d", n)
	}
	now = now.Add(2 * time.Minute)
	if n := a.Sweep(ctx); n != 1 {
		t.Fatalf("sweep after expiry yielded %d, want 1", n)
	}
	if _, ok := a.Ledger.Grant("g1"); ok {
		t.Fatal("expired grant still held")
	}
	if fibers := a.Ledger.RunningFibers(); len(fibers) != 0 {
		t.Fatalf("fibers still running after yield: %v", fibers)
	}
	// An expired grant presented again is a capacity miss, not re-admitted.
	if _, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Deadline: time.Second}); code != core.DeferredFallback || err == nil {
		t.Fatalf("expired grant after sweep = %d %v, want DeferredFallback", code, err)
	}
	if _, ok := a.Ledger.Grant("g1"); ok {
		t.Fatal("expired grant re-admitted by Clone")
	}
}
