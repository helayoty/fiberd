package core_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// listingRuntime is a fakeRuntime that reports running fibers and knows
// which deltas exist, like a real runtime after a restart.
type listingRuntime struct {
	fakeRuntime
	running    []core.FiberHandle
	deltas     map[string]bool
	released   []string // every fiber Release was asked for, failed or not
	releaseErr error    // what Release answers
	listErr    error    // what List answers
	// onRelease, when set, runs inside Release, as what happens on the
	// home while the runtime works.
	onRelease func(id string)
}

func (l *listingRuntime) List(context.Context) ([]core.FiberHandle, error) {
	return l.running, l.listErr
}
func (l *listingRuntime) HasDelta(ref string) bool { return l.deltas[ref] }
func (l *listingRuntime) Release(_ context.Context, id string, _ bool) error {
	l.released = append(l.released, id)
	if l.onRelease != nil {
		l.onRelease(id)
	}
	return l.releaseErr
}

// TestSnapshotRoundTripAndReconcile runs across restarts in order.
//   - epoch 1 runs, parks and persists
//   - epoch 2 reconciles that snapshot against the runtime, then the home
//     removes the grant
//   - epoch 3 refuses it from the persisted deny-list until the lane
//     delivers it again, and a denial lapses with its entry
func TestSnapshotRoundTripAndReconcile(t *testing.T) {
	now := time.Now()
	live := core.Grant{UID: "live", Audience: "node-a", FiberMax: 3, LeaseExpiry: now.Add(time.Hour)}
	dead := core.Grant{UID: "dead", Audience: "node-a", LeaseExpiry: now.Add(-time.Minute)}
	// A renewal of live minted before the removal, and a grant with no lease.
	renewed := core.Grant{UID: "live", Audience: "node-a", FiberMax: 3, LeaseExpiry: now.Add(3 * time.Hour)}
	forever := core.Grant{UID: "forever", Audience: "node-a", FiberMax: 1}
	tokens := acceptVerifier{grants: map[string]core.Grant{"live": live, "dead": dead, "live-renewed": renewed, "forever": forever}}
	ctx := context.Background()
	clone := func(a *core.Agent, session string) (core.CloneResponse, core.StatusCode, error) {
		return a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("live"), Session: session, Deadline: time.Second})
	}
	present := func(a *core.Agent, token string) (core.StatusCode, error) {
		_, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte(token), Deadline: time.Second})
		return code, err
	}
	store := &core.SnapshotStore{Path: filepath.Join(t.TempDir(), "ledger.json")}
	revokedPath := filepath.Join(t.TempDir(), "revoked.json")
	clock := now
	var (
		snap    core.Snapshot
		running core.CloneResponse // left running in epoch 1, an orphan in epoch 2
		a2, a3  *core.Agent
		rt      *listingRuntime
	)
	steps := []struct {
		name string
		step func(t *testing.T)
	}{
		// Epoch 1 parks one session, leaves one running, parks one whose
		// delta will be gone after the restart, and persists.
		{name: "epoch 1 persists its grants and sessions", step: func(t *testing.T) {
			a1 := newAgent(t, "up", core.TierCheckpoint, live, dead)
			a1.Store = store
			a1.Ledger.AdmitGrant(dead)
			p, code, err := clone(a1, "parked")
			if err != nil || code != core.OK {
				t.Fatal(err)
			}
			if _, code, err := a1.Park(ctx, p.FiberID, true); err != nil || code != core.OK {
				t.Fatal(err)
			}
			running, _, _ = clone(a1, "running")
			lost, _, _ := clone(a1, "lost")
			if _, code, err := a1.Park(ctx, lost.FiberID, true); err != nil || code != core.OK {
				t.Fatal(err)
			}
			if snap, err = store.Load(); err != nil {
				t.Fatal(err)
			}
			if snap.Epoch != 1 || len(snap.Grants) != 2 || len(snap.Sessions) != 3 {
				t.Fatalf("snapshot = epoch %d grants %d sessions %d", snap.Epoch, len(snap.Grants), len(snap.Sessions))
			}
		}},
		// In epoch 2 the runtime still shows the epoch-1 fiber (an orphan)
		// and has the delta for "parked" but not for "lost".
		{name: "epoch 2 reconciles: live grant re-admitted, expired dropped, missing delta dropped, orphan killed", step: func(t *testing.T) {
			a2 = newAgent(t, "up", core.TierCheckpoint, live, dead)
			a2.Ledger = core.NewLedger(2)
			rt = &listingRuntime{
				fakeRuntime: fakeRuntime{tier: core.TierCheckpoint, exits: make(chan core.FiberExit, 8)},
				running:     []core.FiberHandle{{ID: running.FiberID, Endpoint: "127.0.0.1:1"}},
				deltas:      map[string]bool{"delta": true},
			}
			// The fake park returns "delta" for every park, so make "lost" distinct.
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
			if len(rt.released) != 1 || rt.released[0] != running.FiberID {
				t.Fatalf("orphans released = %v, want [%s]", rt.released, running.FiberID)
			}
			if _, ok := a2.Ledger.Grant("dead"); ok {
				t.Fatal("expired grant re-admitted")
			}
		}},
		{name: "the parked session resumes under the new epoch", step: func(t *testing.T) {
			res, code, err := clone(a2, "parked")
			if err != nil || code != core.OK || res.Kind != core.ActResume || res.Fence.Epoch != 2 {
				t.Fatalf("resume after restart = %+v %d %v", res, code, err)
			}
		}},
		{name: "the dropped session is a fresh create", step: func(t *testing.T) {
			if res, _, _ := clone(a2, "lost"); res.Kind != core.ActCreate {
				t.Fatalf("lost after restart = %v, want create", res.Kind)
			}
		}},
		{name: "the orphaned running session is a fresh create", step: func(t *testing.T) {
			if res, _, _ := clone(a2, "running"); res.Kind != core.ActCreate {
				t.Fatalf("running after restart = %v, want create", res.Kind)
			}
		}},
		{name: "the home removes the grant: its fibers are released and its token is refused", step: func(t *testing.T) {
			r, err := core.OpenRevoked(revokedPath, time.Hour, now)
			if err != nil {
				t.Fatal(err)
			}
			a2.Revoked, a2.Verify = r, tokens
			before := len(rt.released)
			a2.Remove(ctx, "live")
			if n := len(a2.Ledger.RunningFibers()); n != 0 || len(rt.released) != before+3 {
				t.Fatalf("after removal: running %d, released %d more; want 0 running, 3 released", n, len(rt.released)-before)
			}
			if code, err := present(a2, "live"); code != core.DeferredFallback || !errors.Is(err, core.ErrGrantRevoked) {
				t.Fatalf("removed grant's token = %d %v, want fallback with ErrGrantRevoked", code, err)
			}
		}},
		{name: "a renewal minted before the removal is refused and extends the denial", step: func(t *testing.T) {
			if _, err := present(a2, "live-renewed"); !errors.Is(err, core.ErrGrantRevoked) {
				t.Fatalf("renewed token = %v, want ErrGrantRevoked", err)
			}
		}},
		{name: "epoch 3 keeps the denial: reconcile does not re-admit the grant", step: func(t *testing.T) {
			r, err := core.OpenRevoked(revokedPath, time.Hour, now)
			if err != nil {
				t.Fatal(err)
			}
			a3 = newAgent(t, "up", core.TierCheckpoint)
			a3.Ledger, a3.Verify, a3.Revoked = core.NewLedger(3), tokens, r
			a3.Ledger.Now = func() time.Time { return clock }
			rep, err := a3.Reconcile(ctx, snap)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := a3.Ledger.Grant("live"); ok || rep.GrantsReadmitted != 0 {
				t.Fatalf("after restart: live admitted %v, report %+v; want it refused", ok, rep)
			}
		}},
		{name: "past the first lease and ttl, the renewal is still refused", step: func(t *testing.T) {
			clock = now.Add(2 * time.Hour)
			if _, err := present(a3, "live-renewed"); !errors.Is(err, core.ErrGrantRevoked) {
				t.Fatalf("renewed token at +2h = %v, want ErrGrantRevoked", err)
			}
		}},
		{name: "the lane delivering it again lifts the denial", step: func(t *testing.T) {
			a3.Redeliver(ctx, "live")
			if code, err := present(a3, "live-renewed"); err != nil || code != core.OK {
				t.Fatalf("after redelivery = %d %v, want OK", code, err)
			}
		}},
		{name: "a grant with no lease stays refused past the ttl: its token never expires", step: func(t *testing.T) {
			a3.Remove(ctx, "forever")
			if _, err := present(a3, "forever"); !errors.Is(err, core.ErrGrantRevoked) {
				t.Fatalf("removed lease-less grant = %v, want ErrGrantRevoked", err)
			}
			clock = clock.Add(time.Hour + time.Second)
			if _, err := present(a3, "forever"); !errors.Is(err, core.ErrGrantRevoked) {
				t.Fatalf("lease-less grant past the ttl = %v, want ErrGrantRevoked", err)
			}
		}},
		{name: "a deny-list that does not read refuses to open", step: func(t *testing.T) {
			if err := os.WriteFile(revokedPath, []byte("{torn"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := core.OpenRevoked(revokedPath, time.Hour, now); err == nil {
				t.Fatal("OpenRevoked on a torn file succeeded")
			}
		}},
	}
	for _, tc := range steps {
		if !t.Run(tc.name, tc.step) {
			return // later steps build on this one
		}
	}
}

// TestSnapshotPersistsWhatBootReads checks that the snapshot is written
// only on transitions Reconcile reads back (grants, parked sessions, the
// epoch), so the warm path writes no file. A resume must write, or a
// restart would resume the session again. Watch subscribers wake on every
// ledger change, written or not. The steps run in order against one agent,
// and each starts with no file.
func TestSnapshotPersistsWhatBootReads(t *testing.T) {
	g := core.Grant{UID: "g1", Audience: "node-a", FiberMax: 4}
	a := newAgent(t, "up", core.TierCheckpoint, g)
	path := filepath.Join(t.TempDir(), "ledger.json")
	a.Store = &core.SnapshotStore{Path: path}
	wake := core.Subscribe(a)
	ctx := context.Background()
	clone := func(session string) core.CloneResponse {
		t.Helper()
		r, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Session: session, Deadline: time.Second})
		if err != nil || code != core.OK {
			t.Fatalf("clone %q: %d %v", session, code, err)
		}
		return r
	}
	var named, anon core.CloneResponse
	steps := []struct {
		name      string
		do        func(t *testing.T)
		wantWrite bool
		wantWake  bool
	}{
		{name: "admitting a grant writes", wantWrite: true, wantWake: true, do: func(t *testing.T) {
			if code, err := a.Admit(ctx, g); err != nil || code != core.OK {
				t.Fatalf("admit: %d %v", code, err)
			}
		}},
		{name: "creating a named session does not write", wantWake: true, do: func(t *testing.T) { named = clone("S") }},
		{name: "attaching to it does not write", do: func(t *testing.T) { clone("S") }},
		// A slow watcher holds one pending wake, and notify never blocks.
		{name: "changes before a read coalesce into one wake", wantWake: true, do: func(t *testing.T) {
			clone("")
			clone("")
		}},
		{name: "creating an anonymous fiber does not write", wantWake: true, do: func(t *testing.T) { anon = clone("") }},
		{name: "releasing it does not write", wantWake: true, do: func(t *testing.T) {
			if code, err := a.Release(ctx, anon.FiberID, false); err != nil || code != core.OK {
				t.Fatalf("release: %d %v", code, err)
			}
		}},
		{name: "parking the session writes", wantWrite: true, wantWake: true, do: func(t *testing.T) {
			if _, code, err := a.Park(ctx, named.FiberID, true); err != nil || code != core.OK {
				t.Fatalf("park: %d %v", code, err)
			}
		}},
		{name: "resuming it writes", wantWrite: true, wantWake: true, do: func(t *testing.T) {
			if r := clone("S"); r.Kind != core.ActResume {
				t.Fatalf("clone S = %v, want resume", r.Kind)
			}
		}},
		{name: "yielding the grant writes", wantWrite: true, wantWake: true, do: func(t *testing.T) { a.Yield(ctx, "g1", "test") }},
	}
	for _, tc := range steps {
		if !t.Run(tc.name, func(t *testing.T) {
			_ = os.Remove(path)
			select {
			case <-wake:
			default:
			}
			tc.do(t)
			if _, err := os.Stat(path); (err == nil) != tc.wantWrite {
				t.Fatalf("ledger.json written = %v, want %v", err == nil, tc.wantWrite)
			}
			select {
			case <-wake:
				if !tc.wantWake {
					t.Fatal("watchers woken, want none")
				}
			default:
				if tc.wantWake {
					t.Fatal("watchers not woken")
				}
			}
		}) {
			return // later steps build on this one
		}
	}
}

// TestReconcileReverifiesSnapshotGrants checks that boot re-admits a
// snapshot grant only when its token verifies again, for the same grant
// and this home. The snapshot is a file on the home's disk, so an entry
// edited into it with an unsigned token or none at all is dropped and
// counted. A verifier that cannot decide yet is different from a token
// that fails. Its entries are held, not admitted, and the snapshot written
// at the end of boot still carries them and their parked sessions, so the
// token presented once the verifier is back resumes the session.
func TestReconcileReverifiesSnapshotGrants(t *testing.T) {
	now := time.Now()
	lease := now.Add(time.Hour)
	good := core.Grant{UID: "good", Audience: "node-a", FiberMax: 1, LeaseExpiry: lease, Token: "good-token"}
	parkedS := core.SessionSnapshot{Name: "S", GrantUID: "good", State: core.StateParked, DeltaRef: "delta"}
	cases := []struct {
		name         string
		snapshot     core.Grant            // the entry in the file
		parked       bool                  // the file also holds S parked under the grant
		accepts      map[string]core.Grant // token -> grant the verifier returns
		down         bool                  // the verifier cannot decide at boot
		wantAdmitted bool
		wantHeld     bool // kept in the snapshot without being admitted
		wantReport   core.ReconcileReport
	}{
		{name: "a grant whose token verifies again is re-admitted", snapshot: good,
			accepts: map[string]core.Grant{"good-token": good}, wantAdmitted: true, wantReport: core.ReconcileReport{GrantsReadmitted: 1}},
		{name: "a grant whose token no longer verifies is dropped", snapshot: good,
			accepts: map[string]core.Grant{}, wantReport: core.ReconcileReport{GrantsUnverified: 1}},
		{name: "a token the verifier cannot check yet is held with its parked session, not dropped", snapshot: good, parked: true, down: true,
			accepts: map[string]core.Grant{"good-token": good}, wantHeld: true, wantReport: core.ReconcileReport{GrantsUnavailable: 1, ParkedHeld: 1}},
		{name: "a token that fails for real is dropped with its parked session", snapshot: good, parked: true,
			accepts: map[string]core.Grant{}, wantReport: core.ReconcileReport{GrantsUnverified: 1, ParkedDropped: 1}},
		{name: "an entry without a token is dropped, never trusted",
			snapshot: core.Grant{UID: "good", Audience: "node-a", FiberMax: 1, LeaseExpiry: lease},
			accepts:  map[string]core.Grant{"good-token": good}, wantReport: core.ReconcileReport{GrantsUnverified: 1}},
		{name: "a token signed for another grant does not re-admit this one",
			snapshot:   core.Grant{UID: "good", Audience: "node-a", FiberMax: 1, LeaseExpiry: lease, Token: "other-token"},
			accepts:    map[string]core.Grant{"other-token": {UID: "other", Audience: "node-a", LeaseExpiry: lease}},
			wantReport: core.ReconcileReport{GrantsUnverified: 1}},
		{name: "a token for another home is dropped", snapshot: good,
			accepts:    map[string]core.Grant{"good-token": {UID: "good", Audience: "node-b", LeaseExpiry: lease}},
			wantReport: core.ReconcileReport{GrantsUnverified: 1}},
		{name: "the claims come from the token, not the file: a forged fibers.max is ignored",
			snapshot: core.Grant{UID: "good", Audience: "node-a", FiberMax: 1000, LeaseExpiry: lease, Token: "good-token"},
			accepts:  map[string]core.Grant{"good-token": good}, wantAdmitted: true, wantReport: core.ReconcileReport{GrantsReadmitted: 1}},
		{name: "an expired entry is counted expired before any verification",
			snapshot: core.Grant{UID: "good", Audience: "node-a", LeaseExpiry: now.Add(-time.Minute)},
			accepts:  map[string]core.Grant{}, wantReport: core.ReconcileReport{GrantsExpired: 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			a := newAgent(t, "up", core.TierCheckpoint)
			a.Ledger = core.NewLedger(2)
			a.Verify = acceptVerifier{grants: tc.accepts, down: tc.down}
			a.Store = &core.SnapshotStore{Path: filepath.Join(t.TempDir(), "ledger.json")}
			snap := core.Snapshot{Epoch: 1, Grants: []core.Grant{tc.snapshot}}
			if tc.parked {
				snap.Sessions = []core.SessionSnapshot{parkedS}
			}
			rep, err := a.Reconcile(ctx, snap)
			if err != nil {
				t.Fatal(err)
			}
			if rep != tc.wantReport {
				t.Fatalf("report = %+v, want %+v", rep, tc.wantReport)
			}
			g, ok := a.Ledger.Grant(tc.snapshot.UID)
			if ok != tc.wantAdmitted {
				t.Fatalf("grant admitted after reconcile = %v, want %v", ok, tc.wantAdmitted)
			}
			if ok && (g.FiberMax != good.FiberMax || g.Token != good.Token) {
				t.Fatalf("re-admitted grant = %+v, want the verified claims %+v with its token", g, good)
			}
			// What boot persisted is what the next boot reads.
			written, err := a.Store.Load()
			if err != nil {
				t.Fatal(err)
			}
			wantKept := tc.wantAdmitted || tc.wantHeld
			if kept := snapshotHolds(written, tc.snapshot.UID, ""); kept != wantKept {
				t.Fatalf("grant in the persisted snapshot = %v, want %v", kept, wantKept)
			}
			if kept := snapshotHolds(written, tc.snapshot.UID, "S"); kept != (tc.parked && wantKept) {
				t.Fatalf("parked session in the persisted snapshot = %v, want %v", kept, tc.parked && wantKept)
			}
			if !tc.parked {
				return
			}
			// The verifier is back. A held grant's token resumes the
			// session it kept, and a dropped one's creates afresh.
			a.Verify = acceptVerifier{grants: map[string]core.Grant{"good-token": good}}
			res, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("good-token"), Session: "S", Deadline: time.Second})
			if err != nil || code != core.OK {
				t.Fatalf("clone once the verifier is back = %d %v, want OK", code, err)
			}
			wantKind := core.ActCreate
			if tc.wantHeld {
				wantKind = core.ActResume
			}
			if res.Kind != wantKind {
				t.Fatalf("clone once the verifier is back = %v, want %v", res.Kind, wantKind)
			}
			if written, err = a.Store.Load(); err != nil {
				t.Fatal(err)
			}
			if len(written.Grants) != 1 || !snapshotHolds(written, tc.snapshot.UID, "") {
				t.Fatalf("persisted grants after the clone = %+v, want the admitted grant once", written.Grants)
			}
		})
	}
}

// snapshotHolds reports whether a snapshot carries the grant, or with a
// session name, that session under it.
func snapshotHolds(s core.Snapshot, uid, session string) bool {
	if session == "" {
		for _, g := range s.Grants {
			if g.UID == uid {
				return true
			}
		}
		return false
	}
	for _, sess := range s.Sessions {
		if sess.GrantUID == uid && sess.Name == session {
			return true
		}
	}
	return false
}

// TestSweepYieldsExpiredGrants checks that a sweep yields grants whose
// lease has expired and stops their fibers. An expired grant presented
// again is a capacity miss, not a re-admission. The steps run in order
// against one agent and a clock they advance.
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
	steps := []struct {
		name        string
		advance     time.Duration // the clock moves before the step
		present     bool          // present the grant again via Clone instead of sweeping
		wantYield   int
		wantCode    core.StatusCode
		wantHeld    bool
		wantRunning int
	}{
		{name: "sweep before expiry yields nothing", wantHeld: true, wantRunning: 2},
		{name: "sweep after expiry yields the grant and stops its fibers", advance: 2 * time.Minute, wantYield: 1},
		{name: "an expired grant presented again is a capacity miss, not re-admitted", present: true, wantCode: core.DeferredFallback},
	}
	for _, tc := range steps {
		if !t.Run(tc.name, func(t *testing.T) {
			now = now.Add(tc.advance)
			if tc.present {
				if _, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Deadline: time.Second}); code != tc.wantCode || err == nil {
					t.Fatalf("expired grant after sweep = %d %v, want %d with an error", code, err, tc.wantCode)
				}
			} else if n := a.Sweep(ctx); n != tc.wantYield {
				t.Fatalf("sweep yielded %d, want %d", n, tc.wantYield)
			}
			if _, ok := a.Ledger.Grant("g1"); ok != tc.wantHeld {
				t.Fatalf("grant held = %v, want %v", ok, tc.wantHeld)
			}
			if fibers := a.Ledger.RunningFibers(); len(fibers) != tc.wantRunning {
				t.Fatalf("running fibers = %v, want %d", fibers, tc.wantRunning)
			}
		}) {
			return // later steps build on this one
		}
	}
}

// TestRestoreParkedRefusesExisting checks that a parked entry from a
// snapshot or a claim never overwrites a session the ledger holds. A
// running session restored as parked would resume a second time, and a
// parked one would lose its delta.
func TestRestoreParkedRefusesExisting(t *testing.T) {
	cases := []struct {
		name      string
		admitted  bool
		existing  string // the session before ("", running, parked)
		want      bool
		wantState string // the session after (running, parked, gone)
		wantRef   string // the parked session's delta after
	}{
		{name: "a grant that is not admitted is refused", wantState: "gone"},
		{name: "a session the ledger does not know is restored", admitted: true, want: true, wantState: "parked", wantRef: "claimed"},
		{name: "a running session is kept running", admitted: true, existing: "running", wantState: "running"},
		{name: "a parked session keeps its own delta", admitted: true, existing: "parked", wantState: "parked", wantRef: "delta-f1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := core.NewLedger(1)
			if tc.admitted {
				l.AdmitGrant(core.Grant{UID: "g1"})
			}
			if tc.existing != "" {
				createFiber(t, l, "g1", "S", "f1")
			}
			if tc.existing == "parked" {
				l.OnPark("f1", "delta-f1")
			}
			got := l.RestoreParked(core.SessionSnapshot{Name: "S", GrantUID: "g1", State: core.StateParked, DeltaRef: "claimed"})
			if got != tc.want {
				t.Fatalf("RestoreParked = %v, want %v", got, tc.want)
			}
			if st := ledgerState(l, "g1", "S"); st != tc.wantState {
				t.Fatalf("session = %s, want %s", st, tc.wantState)
			}
			if _, ref, _ := l.SessionState("g1", "S"); ref != tc.wantRef {
				t.Fatalf("delta = %q, want %q", ref, tc.wantRef)
			}
		})
	}
}

// Concurrent writers each admit a grant and then persist the ledger, as
// concurrent admissions do. No write may fail or leave a temporary file
// behind. The file must end up holding every grant, because a write that
// captured an older ledger never lands after a newer one.
func TestSnapshotStoreConcurrentWrites(t *testing.T) {
	cases := []struct {
		name    string
		writers int
	}{
		{name: "one writer persists its change", writers: 1},
		{name: "16 concurrent writers all land in the file", writers: 16},
		{name: "128 concurrent writers all land in the file", writers: 128},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			store := &core.SnapshotStore{Path: filepath.Join(dir, "ledger.json")}
			led := core.NewLedger(1)
			var wg sync.WaitGroup
			errs := make(chan error, tc.writers)
			for i := 0; i < tc.writers; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					led.AdmitGrant(core.Grant{UID: fmt.Sprintf("g%d", i)})
					errs <- store.Persist(led.Snapshot)
				}(i)
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatalf("write: %v", err)
				}
			}
			snap, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			if len(snap.Grants) != tc.writers {
				t.Fatalf("snapshot holds %d grants, want %d", len(snap.Grants), tc.writers)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 {
				var names []string
				for _, e := range entries {
					names = append(names, e.Name())
				}
				t.Fatalf("state dir holds %v, want only ledger.json", names)
			}
		})
	}
}

// TestSnapshotStoreLoadAndPersist checks what Load reads back and when
// Persist fails. No file is an empty snapshot, and so is a torn one, since
// the snapshot is a cache. A path that does not read is an error. A
// snapshot that cannot be written or encoded is an error that leaves the
// file as it was.
func TestSnapshotStoreLoadAndPersist(t *testing.T) {
	g := core.Grant{UID: "g1", FiberMax: 2}
	cases := []struct {
		name       string
		before     string // the file's content before, "" means none
		dirAtPath  bool   // the path is a directory
		missingDir bool   // the path's directory does not exist
		persist    *core.Grant
		wantPerErr bool
		wantLoad   bool // Load fails
		wantGrants int
	}{
		{name: "no file is an empty snapshot"},
		{name: "a torn file is an empty snapshot", before: "{torn"},
		{name: "a written snapshot reads back", persist: &g, wantGrants: 1},
		{name: "a path that is a directory does not load", dirAtPath: true, wantLoad: true},
		{name: "a missing directory fails the write", missingDir: true, persist: &g, wantPerErr: true},
		// A time past year 9999 has no JSON form.
		{name: "a snapshot that does not encode fails the write and keeps the file", before: `{"epoch":7}`,
			persist: &core.Grant{UID: "g2", LeaseExpiry: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}, wantPerErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.missingDir {
				dir = filepath.Join(dir, "missing")
			}
			path := filepath.Join(dir, "ledger.json")
			if tc.dirAtPath {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if tc.before != "" {
				if err := os.WriteFile(path, []byte(tc.before), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			st := &core.SnapshotStore{Path: path}
			if tc.persist != nil {
				l := core.NewLedger(3)
				l.AdmitGrant(*tc.persist)
				if err := st.Persist(l.Snapshot); (err != nil) != tc.wantPerErr {
					t.Fatalf("Persist = %v, want error %v", err, tc.wantPerErr)
				}
			}
			snap, err := st.Load()
			if tc.wantLoad {
				if err == nil {
					t.Fatal("Load succeeded, want an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Load = %v", err)
			}
			if len(snap.Grants) != tc.wantGrants {
				t.Fatalf("loaded grants = %+v, want %d", snap.Grants, tc.wantGrants)
			}
			if tc.before != "" && tc.wantPerErr {
				if b, _ := os.ReadFile(path); string(b) != tc.before {
					t.Fatalf("file after a failed write = %q, want %q", b, tc.before)
				}
			}
		})
	}
}

// TestReconcileOrphans checks what boot does with the fibers the runtime
// still reports. A fiber from a prior epoch is killed and recorded, and so
// is one whose ID is not a fence. A fiber of the current epoch is kept. An
// orphan the runtime cannot kill is not counted. A runtime that cannot
// list fails boot.
func TestReconcileOrphans(t *testing.T) {
	cases := []struct {
		name         string
		running      []string
		listErr      error
		releaseErr   error
		wantErr      bool
		wantKilled   int
		wantReleased int
	}{
		{name: "a fiber from a prior epoch is killed", running: []string{"g1/1/1"}, wantKilled: 1, wantReleased: 1},
		{name: "a fiber ID that is not a fence is killed", running: []string{"stray"}, wantKilled: 1, wantReleased: 1},
		{name: "a fiber of the current epoch is kept", running: []string{"g1/2/1"}},
		{name: "an orphan the runtime cannot kill is not counted", running: []string{"g1/1/1", "g1/1/2"}, releaseErr: errors.New("kill: EPERM"),
			wantReleased: 2},
		{name: "a runtime that cannot list fails boot", listErr: errors.New("runc list: EIO"), wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newAgent(t, "up", core.TierCheckpoint)
			a.Ledger = core.NewLedger(2)
			rt := &listingRuntime{fakeRuntime: fakeRuntime{tier: core.TierCheckpoint}, listErr: tc.listErr, releaseErr: tc.releaseErr}
			for _, id := range tc.running {
				rt.running = append(rt.running, core.FiberHandle{ID: id})
			}
			a.Runtime = rt
			rec := &auditLog{}
			a.Audit = rec
			rep, err := a.Reconcile(context.Background(), core.Snapshot{Epoch: 1})
			if (err != nil) != tc.wantErr {
				t.Fatalf("Reconcile = %v, want error %v", err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, tc.listErr) {
				t.Fatalf("Reconcile = %v, want it to wrap %v", err, tc.listErr)
			}
			if rep.OrphansKilled != tc.wantKilled || len(rt.released) != tc.wantReleased {
				t.Fatalf("killed %d (released %v), want %d killed of %d released", rep.OrphansKilled, rt.released, tc.wantKilled, tc.wantReleased)
			}
			if n := len(rec.events("orphan")); n != tc.wantKilled {
				t.Fatalf("orphan records = %d, want %d", n, tc.wantKilled)
			}
		})
	}
}

// TestReconcileHoldsBesideAdmitted boots from a snapshot with one grant
// whose token verifies and one the verifier cannot check yet, each with a
// parked session. The first is admitted and its session restored. The
// second is held. Every snapshot written from then on carries both grants
// and both sessions, each once, until the held grant is admitted again.
func TestReconcileHoldsBesideAdmitted(t *testing.T) {
	lease := time.Now().Add(time.Hour)
	good := core.Grant{UID: "good", Audience: "node-a", FiberMax: 1, LeaseExpiry: lease, Token: "good-token"}
	held := core.Grant{UID: "held", Audience: "node-a", FiberMax: 1, LeaseExpiry: lease, Token: "held-token"}
	cases := []struct {
		name       string
		readmit    bool // the held grant's token is presented once it can be checked
		wantGrants []string
		wantHeld   bool // the held grant is still only held
	}{
		{name: "the held grant persists beside the admitted one", wantGrants: []string{"good", "held"}, wantHeld: true},
		{name: "the held grant admitted again persists once, with its session", readmit: true, wantGrants: []string{"good", "held"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newAgent(t, "up", core.TierCheckpoint)
			a.Ledger = core.NewLedger(2)
			a.Verify = acceptVerifier{grants: map[string]core.Grant{"good-token": good, "held-token": held}, unavailable: map[string]bool{"held-token": true}}
			a.Store = &core.SnapshotStore{Path: filepath.Join(t.TempDir(), "ledger.json")}
			snap := core.Snapshot{Epoch: 1, Grants: []core.Grant{good, held}, Sessions: []core.SessionSnapshot{
				{Name: "S1", GrantUID: "good", State: core.StateParked, DeltaRef: "d1"},
				{Name: "S2", GrantUID: "held", State: core.StateParked, DeltaRef: "d2"},
			}}
			rep, err := a.Reconcile(context.Background(), snap)
			if err != nil {
				t.Fatal(err)
			}
			want := core.ReconcileReport{GrantsReadmitted: 1, GrantsUnavailable: 1, ParkedRestored: 1, ParkedHeld: 1}
			if rep != want {
				t.Fatalf("report = %+v, want %+v", rep, want)
			}
			if tc.readmit {
				a.Verify = acceptVerifier{grants: map[string]core.Grant{"good-token": good, "held-token": held}}
				r, code, err := a.Clone(context.Background(), core.CloneRequest{GrantJWT: []byte("held-token"), Session: "S2", Deadline: time.Second})
				if err != nil || code != core.OK || r.Kind != core.ActResume {
					t.Fatalf("clone of the held session = %v %d %v, want a resume", r.Kind, code, err)
				}
			}
			if _, ok := a.Ledger.Grant("held"); ok == tc.wantHeld {
				t.Fatalf("held grant admitted = %v, want %v", ok, !tc.wantHeld)
			}
			written, err := a.Store.Load()
			if err != nil {
				t.Fatal(err)
			}
			var uids []string
			for _, g := range written.Grants {
				uids = append(uids, g.UID)
			}
			slices.Sort(uids)
			if !slices.Equal(uids, tc.wantGrants) {
				t.Fatalf("persisted grants = %v, want %v", uids, tc.wantGrants)
			}
			if len(written.Sessions) != 2 || !snapshotHolds(written, "good", "S1") || !snapshotHolds(written, "held", "S2") {
				t.Fatalf("persisted sessions = %+v, want S1 and S2 once each", written.Sessions)
			}
		})
	}
}
