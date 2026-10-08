package core_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/core/coretest"
)

// createFiber drives one full Resolve→commit→unlock cycle and returns the
// fiber ID it registered, failing the test on any unexpected outcome.
func createFiber(t *testing.T, l *core.Ledger, grant, session, id string) string {
	t.Helper()
	act, fence, _, commit, unlock, err := l.Resolve(grant, session, core.TierCheckpoint)
	if err != nil {
		t.Fatalf("createFiber(%s/%s): %v", grant, session, err)
	}
	if act != core.ActCreate && act != core.ActResume {
		t.Fatalf("createFiber(%s/%s): action %d, want create or resume", grant, session, act)
	}
	if !commit(core.Session{
		Name: session, GrantUID: grant, State: core.StateRunning,
		Fence: fence, Handle: core.FiberHandle{ID: id, Endpoint: "127.0.0.1:1"},
	}) {
		t.Fatalf("createFiber(%s/%s): commit refused", grant, session)
	}
	unlock()
	return id
}

// TestCommitAfterSweep checks what a Resolve's commit answers when the
// ledger changed between the resolve and the commit. A refused commit
// records nothing, and its reservation goes back with unlock.
func TestCommitAfterSweep(t *testing.T) {
	const grant = "g1"
	cases := []struct {
		name    string
		between func(l *core.Ledger)
		want    bool
	}{
		{name: "nothing changed commits", between: func(*core.Ledger) {}, want: true},
		{name: "commit after revoke returns false", between: func(l *core.Ledger) { l.RevokeGrant(grant) }},
		{name: "commit after revoke and re-admit returns false", between: func(l *core.Ledger) {
			l.RevokeGrant(grant)
			l.AdmitGrant(grantMax(1))
		}},
		{name: "commit after an epoch bump returns false", between: func(l *core.Ledger) { l.BumpEpoch(2) }},
		{name: "a re-delivery of the same grant still commits", between: func(l *core.Ledger) { l.AdmitGrant(grantMax(2)) }, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := core.NewLedger(1)
			l.AdmitGrant(grantMax(1))
			_, fence, _, commit, unlock, err := l.Resolve(grant, "S1", core.TierCheckpoint)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			tc.between(l)
			got := commit(core.Session{Name: "S1", GrantUID: grant, State: core.StateRunning, Fence: fence, Handle: core.FiberHandle{ID: "f1"}})
			unlock()
			if got != tc.want {
				t.Fatalf("commit = %v, want %v", got, tc.want)
			}
			_, running := l.Fiber("f1")
			_, _, known := l.SessionState(grant, "S1")
			if running != tc.want || known != tc.want {
				t.Fatalf("fiber recorded = %v, session known = %v, want both %v", running, known, tc.want)
			}
			wantRunning := 0
			if tc.want {
				wantRunning = 1
			}
			if st, ok := coretest.GrantStatus(l, grant); ok && st.Running != wantRunning {
				t.Fatalf("running = %d after commit=%v, want %d (a refusal returns the reservation)", st.Running, tc.want, wantRunning)
			}
		})
	}
}

func grantMax(max int) core.Grant { return core.Grant{UID: "g1", FiberMax: max} }

// TestResolve checks what Resolve answers for a session name, given the
// grant's capacity (fiberMax counts running fibers and in-flight
// reservations), its lease and min_tier, and the runtime's tier.
func TestResolve(t *testing.T) {
	const grant = "g1"
	now := time.Unix(1000, 0)
	cases := []struct {
		name     string
		max      int
		admit    *core.Grant // admitted instead of grantMax(max)
		tier     core.Tier   // runtime tier, unset means checkpoint
		setup    func(t *testing.T, l *core.Ledger)
		grant    string
		session  string
		wantAct  core.Action
		wantErr  error
		seqAfter uint64 // a successful Resolve's fence must be past this seq
	}{
		{name: "create under max", max: 2, setup: func(t *testing.T, l *core.Ledger) { createFiber(t, l, grant, "", "f1") }, grant: grant, wantAct: core.ActCreate},
		{name: "create at max is full", max: 2, setup: func(t *testing.T, l *core.Ledger) {
			createFiber(t, l, grant, "", "f1")
			createFiber(t, l, grant, "", "f2")
		}, grant: grant, wantErr: core.ErrGrantFull},
		{name: "fiberMax zero is unlimited", max: 0, setup: func(t *testing.T, l *core.Ledger) {
			for i := 0; i < 50; i++ {
				createFiber(t, l, grant, "", fmt.Sprintf("f%d", i))
			}
		}, grant: grant, wantAct: core.ActCreate},
		{name: "attach at max still succeeds", max: 1, setup: func(t *testing.T, l *core.Ledger) { createFiber(t, l, grant, "S1", "f1") }, grant: grant, session: "S1", wantAct: core.ActAttach},
		{name: "resume at max is full", max: 1, setup: func(t *testing.T, l *core.Ledger) {
			createFiber(t, l, grant, "S1", "f1")
			l.OnPark("f1", "delta-f1")
			createFiber(t, l, grant, "", "f2") // takes the freed slot
		}, grant: grant, session: "S1", wantErr: core.ErrGrantFull},
		{name: "resume under max reserves the slot", max: 1, setup: func(t *testing.T, l *core.Ledger) {
			createFiber(t, l, grant, "S1", "f1")
			l.OnPark("f1", "delta-f1")
		}, grant: grant, session: "S1", wantAct: core.ActResume},
		{name: "parked session below checkpoint tier needs tier", max: 1, tier: core.TierWarm, setup: func(t *testing.T, l *core.Ledger) {
			createFiber(t, l, grant, "S1", "f1")
			l.OnPark("f1", "delta-f1")
		}, grant: grant, session: "S1", wantErr: core.ErrNeedsTier},
		{name: "unknown grant", max: 1, setup: func(t *testing.T, l *core.Ledger) {}, grant: "nope", wantErr: core.ErrGrantUnknown},
		{name: "release frees a slot", max: 1, setup: func(t *testing.T, l *core.Ledger) {
			createFiber(t, l, grant, "", "f1")
			l.OnRelease("f1")
		}, grant: grant, wantAct: core.ActCreate},
		{name: "exit frees a slot", max: 1, setup: func(t *testing.T, l *core.Ledger) {
			createFiber(t, l, grant, "S1", "f1")
			l.OnFiberExit("f1")
		}, grant: grant, session: "S1", wantAct: core.ActCreate},
		{name: "park frees a slot for anonymous create", max: 1, setup: func(t *testing.T, l *core.Ledger) {
			createFiber(t, l, grant, "S1", "f1")
			l.OnPark("f1", "delta-f1")
		}, grant: grant, wantAct: core.ActCreate},
		{name: "abandoned reservation rolls back", max: 1, setup: func(t *testing.T, l *core.Ledger) {
			_, _, _, _, unlock, err := l.Resolve(grant, "", core.TierCheckpoint)
			if err != nil {
				t.Fatalf("setup resolve: %v", err)
			}
			unlock()
		}, grant: grant, wantAct: core.ActCreate},
		{name: "reservation counts before commit", max: 1, setup: func(t *testing.T, l *core.Ledger) {
			if _, _, _, _, _, err := l.Resolve(grant, "", core.TierCheckpoint); err != nil {
				t.Fatalf("setup resolve: %v", err)
			}
		}, grant: grant, wantErr: core.ErrGrantFull},
		{name: "released session name is forgotten", max: 2, setup: func(t *testing.T, l *core.Ledger) {
			createFiber(t, l, grant, "S1", "f1")
			l.OnRelease("f1")
		}, grant: grant, session: "S1", wantAct: core.ActCreate},
		{name: "revoked grant is unknown", max: 1, setup: func(t *testing.T, l *core.Ledger) { l.RevokeGrant(grant) }, grant: grant, wantErr: core.ErrGrantUnknown},
		{name: "re-admit preserves live count (still full)", max: 1, setup: func(t *testing.T, l *core.Ledger) {
			createFiber(t, l, grant, "", "f1")
			l.AdmitGrant(grantMax(1))
		}, grant: grant, wantErr: core.ErrGrantFull},
		{name: "re-admit refreshes fiberMax in place", max: 1, setup: func(t *testing.T, l *core.Ledger) {
			createFiber(t, l, grant, "", "f1")
			l.AdmitGrant(grantMax(2))
		}, grant: grant, wantAct: core.ActCreate},
		{name: "re-admit preserves fence sequence", max: 4, setup: func(t *testing.T, l *core.Ledger) {
			createFiber(t, l, grant, "", "f1") // mints seq 1
			l.AdmitGrant(grantMax(4))
		}, grant: grant, wantAct: core.ActCreate, seqAfter: 1},
		{name: "unexpired lease", admit: &core.Grant{UID: grant, LeaseExpiry: now.Add(time.Minute)}, tier: core.TierWarm, grant: grant, wantAct: core.ActCreate},
		{name: "expired lease", admit: &core.Grant{UID: grant, LeaseExpiry: now.Add(-time.Second)}, tier: core.TierWarm, grant: grant, wantErr: core.ErrGrantExpired},
		{name: "lease expiring exactly now is expired", admit: &core.Grant{UID: grant, LeaseExpiry: now}, tier: core.TierWarm, grant: grant, wantErr: core.ErrGrantExpired},
		{name: "min_tier met", admit: &core.Grant{UID: grant, MinTier: core.TierWarm}, tier: core.TierWarm, grant: grant, wantAct: core.ActCreate},
		{name: "min_tier above runtime", admit: &core.Grant{UID: grant, MinTier: core.TierSnapshot}, tier: core.TierCheckpoint, grant: grant, wantErr: core.ErrNeedsTier},
		{name: "snapshot runtime serves warm grant", admit: &core.Grant{UID: grant, MinTier: core.TierWarm}, tier: core.TierSnapshot, grant: grant, wantAct: core.ActCreate},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := core.NewLedger(1)
			l.Now = func() time.Time { return now }
			admit := grantMax(tc.max)
			if tc.admit != nil {
				admit = *tc.admit
			}
			l.AdmitGrant(admit)
			if tc.setup != nil {
				tc.setup(t, l)
			}
			tier := tc.tier
			if tier == core.TierUnspecified {
				tier = core.TierCheckpoint
			}
			act, fence, _, _, unlock, err := l.Resolve(tc.grant, tc.session, tier)
			if unlock != nil {
				defer unlock()
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Resolve err = %v, want %v", err, tc.wantErr)
			}
			if err == nil && act != tc.wantAct {
				t.Fatalf("Resolve action = %d, want %d", act, tc.wantAct)
			}
			if err == nil && fence.Seq <= tc.seqAfter {
				t.Fatalf("fence.Seq = %d, want > %d (sequence reused)", fence.Seq, tc.seqAfter)
			}
		})
	}
}

// TestResolveWaitsOnSessionLock checks that an in-flight Resolve holds the
// per-session lock until its unlock. A second Resolve on the same name
// waits behind it and then sees whatever happened meanwhile.
func TestResolveWaitsOnSessionLock(t *testing.T) {
	const grant = "g1"
	cases := []struct {
		name         string
		whileBlocked func(l *core.Ledger)
		wantAct      core.Action
		wantErr      error
	}{
		{name: "revoke while blocked is unknown", whileBlocked: func(l *core.Ledger) { l.RevokeGrant(grant) }, wantErr: core.ErrGrantUnknown},
		{name: "nothing changed while blocked still attaches", whileBlocked: func(*core.Ledger) {}, wantAct: core.ActAttach},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := core.NewLedger(1)
			l.AdmitGrant(grantMax(2))
			createFiber(t, l, grant, "S1", "f1")
			_, _, _, _, holdUnlock, err := l.Resolve(grant, "S1", core.TierCheckpoint)
			if err != nil {
				t.Fatalf("holding resolve: %v", err)
			}
			type result struct {
				act core.Action
				err error
			}
			done := make(chan result, 1)
			go func() {
				act, _, _, _, unlock, err := l.Resolve(grant, "S1", core.TierCheckpoint)
				if unlock != nil {
					unlock()
				}
				done <- result{act, err}
			}()
			select {
			case r := <-done:
				holdUnlock()
				t.Fatalf("Resolve returned before the holder unlocked (did not block): %v", r.err)
			case <-time.After(50 * time.Millisecond):
			}
			tc.whileBlocked(l)
			holdUnlock()
			r := <-done
			if !errors.Is(r.err, tc.wantErr) {
				t.Fatalf("Resolve err = %v, want %v", r.err, tc.wantErr)
			}
			if r.err == nil && r.act != tc.wantAct {
				t.Fatalf("Resolve action = %d, want %d", r.act, tc.wantAct)
			}
		})
	}
}

// TestStatus checks that Statuses and Fiber report a grant's
// running and parked fibers, the W of the running ones, and the latest
// fence minted.
func TestStatus(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T, l *core.Ledger)
		grant   string
		wantOK  bool
		want    core.Status
		running map[string]uint64 // fiber ID -> fence seq, 0 means not running
	}{
		{name: "running and parked fibers with the latest fence", setup: func(t *testing.T, l *core.Ledger) {
			createFiber(t, l, "g1", "S1", "f1")
			createFiber(t, l, "g1", "", "f2")
			l.SetFiberW("f1", 100)
			l.SetFiberW("f2", 50)
			l.OnPark("f1", "d1")
		}, grant: "g1", wantOK: true,
			want:    core.Status{GrantUID: "g1", Running: 1, Parked: 1, WUsedBytes: 50, Latest: core.Fence{GrantUID: "g1", Epoch: 5, Seq: 2}},
			running: map[string]uint64{"f1": 0, "f2": 2}},
		{name: "unknown grant has no status", setup: func(*testing.T, *core.Ledger) {}, grant: "nope"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := core.NewLedger(5)
			l.AdmitGrant(grantMax(3))
			tc.setup(t, l)
			st, ok := coretest.GrantStatus(l, tc.grant)
			if ok != tc.wantOK {
				t.Fatalf("status ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if st != tc.want {
				t.Fatalf("status = %+v, want %+v", st, tc.want)
			}
			if got := l.Statuses(); len(got) != 1 || got[0] != st {
				t.Fatalf("statuses = %+v, want [%+v]", got, st)
			}
			for id, seq := range tc.running {
				f, ok := l.Fiber(id)
				if seq == 0 && ok {
					t.Fatalf("fiber %s = %+v, want not running", id, f)
				}
				if seq != 0 && (!ok || f.Seq != seq) {
					t.Fatalf("fiber %s = %+v %v, want running at seq %d", id, f, ok, seq)
				}
			}
		})
	}
}

// TestGrantBoundTo checks that an admitted grant is bound to exactly the
// caller its token names, and an unknown grant to nobody.
func TestGrantBoundTo(t *testing.T) {
	cases := []struct {
		name       string
		admitted   *core.Grant
		thumbprint string
		want       bool
	}{
		{name: "the named caller", admitted: &core.Grant{UID: "g1", CallerThumbprint: "x5t"}, thumbprint: "x5t", want: true},
		{name: "another caller", admitted: &core.Grant{UID: "g1", CallerThumbprint: "x5t"}, thumbprint: "other"},
		{name: "an unbound grant and no caller", admitted: &core.Grant{UID: "g1"}, want: true},
		{name: "an unbound grant and a caller", admitted: &core.Grant{UID: "g1"}, thumbprint: "x5t"},
		{name: "an unknown grant is bound to nobody", thumbprint: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := core.NewLedger(1)
			if tc.admitted != nil {
				l.AdmitGrant(*tc.admitted)
			}
			if got := l.GrantBoundTo("g1", tc.thumbprint); got != tc.want {
				t.Fatalf("GrantBoundTo(g1, %q) = %v, want %v", tc.thumbprint, got, tc.want)
			}
		})
	}
}

// TestOnPark checks what the ledger records for a park. A named session is
// parked with its delta. An anonymous fiber frees its slot and leaves no
// session, since nobody can ask for its delta. An unknown fiber changes
// nothing.
func TestOnPark(t *testing.T) {
	cases := []struct {
		name        string
		session     string // the fiber's session, "" is anonymous
		park        string // the fiber parked, "" means the one created
		wantName    string
		wantRunning int
		wantParked  int
	}{
		{name: "a named session is parked", session: "S", wantName: "S", wantParked: 1},
		{name: "an anonymous fiber frees its slot", wantRunning: 0},
		{name: "an unknown fiber changes nothing", session: "S", park: "nope", wantRunning: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := core.NewLedger(1)
			l.AdmitGrant(grantMax(2))
			id := createFiber(t, l, "g1", tc.session, "f1")
			if tc.park != "" {
				id = tc.park
			}
			if got, _ := l.OnPark(id, "delta"); got != tc.wantName {
				t.Fatalf("OnPark = %q, want %q", got, tc.wantName)
			}
			st, _ := coretest.GrantStatus(l, "g1")
			if st.Running != tc.wantRunning || st.Parked != tc.wantParked {
				t.Fatalf("status = %+v, want running %d parked %d", st, tc.wantRunning, tc.wantParked)
			}
		})
	}
}

// TestStatusesSorted checks that Statuses lists every admitted grant once,
// by UID, whatever the order of admission.
func TestStatusesSorted(t *testing.T) {
	cases := []struct {
		name  string
		admit []string
		want  []string
	}{
		{name: "none", want: []string{}},
		{name: "admitted in reverse", admit: []string{"c", "b", "a"}, want: []string{"a", "b", "c"}},
		{name: "admitted twice", admit: []string{"b", "a", "b"}, want: []string{"a", "b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := core.NewLedger(1)
			for _, uid := range tc.admit {
				l.AdmitGrant(core.Grant{UID: uid})
			}
			got := []string{}
			for _, st := range l.Statuses() {
				got = append(got, st.GrantUID)
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("statuses = %v, want %v", got, tc.want)
			}
		})
	}
}
