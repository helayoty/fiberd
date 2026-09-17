package core_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
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
	commit(core.Session{
		Name: session, GrantUID: grant, State: core.StateRunning,
		Fence: fence, Handle: core.FiberHandle{ID: id, Endpoint: "127.0.0.1:1"},
	})
	unlock()
	return id
}

func grantMax(max int) core.Grant { return core.Grant{UID: "g1", FiberMax: max} }

func TestResolveCapacity(t *testing.T) {
	const grant = "g1"
	cases := []struct {
		name    string
		max     int
		tier    core.Tier
		setup   func(t *testing.T, l *core.Ledger)
		grant   string
		session string
		wantAct core.Action
		wantErr error
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
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := core.NewLedger(1)
			l.AdmitGrant(grantMax(tc.max))
			tc.setup(t, l)
			tier := tc.tier
			if tier == core.TierUnspecified {
				tier = core.TierCheckpoint
			}
			act, _, _, _, unlock, err := l.Resolve(tc.grant, tc.session, tier)
			if unlock != nil {
				defer unlock()
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Resolve err = %v, want %v", err, tc.wantErr)
			}
			if err == nil && act != tc.wantAct {
				t.Fatalf("Resolve action = %d, want %d", act, tc.wantAct)
			}
		})
	}

	t.Run("re-admit preserves fence sequence", func(t *testing.T) {
		l := core.NewLedger(1)
		l.AdmitGrant(grantMax(4))
		createFiber(t, l, grant, "", "f1") // mints seq 1
		l.AdmitGrant(grantMax(4))
		_, fence, _, commit, unlock, err := l.Resolve(grant, "", core.TierCheckpoint)
		if err != nil {
			t.Fatalf("Resolve after re-admit: %v", err)
		}
		commit(core.Session{GrantUID: grant, State: core.StateRunning, Fence: fence, Handle: core.FiberHandle{ID: "f2"}})
		unlock()
		if fence.Seq <= 1 {
			t.Fatalf("fence.Seq = %d after re-admit, want > 1 (sequence reused)", fence.Seq)
		}
	})

	t.Run("revoke while blocked on session lock", func(t *testing.T) {
		l := core.NewLedger(1)
		l.AdmitGrant(grantMax(2))
		createFiber(t, l, grant, "S1", "f1")
		// An in-flight Resolve on S1 holds the per-session lock until its
		// unlock; a second Resolve on the same name must wait behind it.
		_, _, _, _, holdUnlock, err := l.Resolve(grant, "S1", core.TierCheckpoint)
		if err != nil {
			t.Fatalf("holding resolve: %v", err)
		}
		done := make(chan error, 1)
		go func() {
			_, _, _, _, unlock, err := l.Resolve(grant, "S1", core.TierCheckpoint)
			if unlock != nil {
				unlock()
			}
			done <- err
		}()
		select {
		case err := <-done:
			holdUnlock()
			t.Fatalf("Resolve returned before revoke (did not block): %v", err)
		case <-time.After(50 * time.Millisecond):
		}
		l.RevokeGrant(grant)
		holdUnlock()
		if err := <-done; !errors.Is(err, core.ErrGrantUnknown) {
			t.Fatalf("Resolve err = %v, want %v", err, core.ErrGrantUnknown)
		}
	})
}

func TestResolveLeaseAndTier(t *testing.T) {
	now := time.Unix(1000, 0)
	cases := []struct {
		name    string
		grant   core.Grant
		tier    core.Tier
		wantErr error
	}{
		{name: "unexpired", grant: core.Grant{UID: "g", LeaseExpiry: now.Add(time.Minute)}, tier: core.TierWarm},
		{name: "expired", grant: core.Grant{UID: "g", LeaseExpiry: now.Add(-time.Second)}, tier: core.TierWarm, wantErr: core.ErrGrantExpired},
		{name: "expiring exactly now is expired", grant: core.Grant{UID: "g", LeaseExpiry: now}, tier: core.TierWarm, wantErr: core.ErrGrantExpired},
		{name: "min_tier met", grant: core.Grant{UID: "g", MinTier: core.TierWarm}, tier: core.TierWarm},
		{name: "min_tier above runtime", grant: core.Grant{UID: "g", MinTier: core.TierSnapshot}, tier: core.TierCheckpoint, wantErr: core.ErrNeedsTier},
		{name: "snapshot runtime serves warm grant", grant: core.Grant{UID: "g", MinTier: core.TierWarm}, tier: core.TierSnapshot},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := core.NewLedger(3)
			l.Now = func() time.Time { return now }
			l.AdmitGrant(tc.grant)
			_, _, _, _, unlock, err := l.Resolve("g", "", tc.tier)
			if unlock != nil {
				unlock()
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Resolve err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestStatus(t *testing.T) {
	l := core.NewLedger(5)
	l.AdmitGrant(grantMax(3))
	createFiber(t, l, "g1", "S1", "f1")
	createFiber(t, l, "g1", "", "f2")
	l.SetFiberW("f1", 100)
	l.SetFiberW("f2", 50)
	l.OnPark("f1", "d1")
	st, ok := l.Status("g1")
	if !ok {
		t.Fatal("status missing")
	}
	want := core.Status{GrantUID: "g1", Running: 1, Parked: 1, WUsedBytes: 50, Latest: core.Fence{GrantUID: "g1", Epoch: 5, Seq: 2}}
	if st != want {
		t.Fatalf("status = %+v, want %+v", st, want)
	}
	if got := l.Statuses(); len(got) != 1 || got[0] != st {
		t.Fatalf("statuses = %+v", got)
	}
	if _, ok := l.Fiber("f1"); ok {
		t.Fatal("parked fiber still known as running")
	}
	if f, ok := l.Fiber("f2"); !ok || f.Seq != 2 {
		t.Fatalf("fiber f2 = %+v %v", f, ok)
	}
}
