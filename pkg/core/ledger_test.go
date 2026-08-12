package core

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// createFiber drives one full Resolve→commit→unlock cycle and returns the
// fiber ID it registered, failing the test on any unexpected outcome.
func createFiber(t *testing.T, l *Ledger, grant, session, id string) string {
	t.Helper()
	act, fence, _, commit, unlock, err := l.Resolve(grant, session, TierCheckpoint)
	if err != nil {
		t.Fatalf("createFiber(%s/%s): %v", grant, session, err)
	}
	if act != ActCreate && act != ActResume {
		t.Fatalf("createFiber(%s/%s): action %d, want create or resume", grant, session, act)
	}
	commit(Session{
		Name: session, GrantUID: grant, State: StateRunning,
		Fence: fence, Handle: FiberHandle{ID: id, Endpoint: "127.0.0.1:1"},
	})
	unlock()
	return id
}

func TestResolveCapacity(t *testing.T) {
	const grant = "g1"
	cases := []struct {
		name    string
		max     int
		setup   func(t *testing.T, l *Ledger)
		grant   string
		session string
		wantAct Action
		wantErr error
	}{
		{
			name:    "create under max",
			max:     2,
			setup:   func(t *testing.T, l *Ledger) { createFiber(t, l, grant, "", "f1") },
			grant:   grant,
			wantAct: ActCreate,
		},
		{
			name: "create at max is full",
			max:  2,
			setup: func(t *testing.T, l *Ledger) {
				createFiber(t, l, grant, "", "f1")
				createFiber(t, l, grant, "", "f2")
			},
			grant:   grant,
			wantErr: ErrGrantFull,
		},
		{
			name: "fiberMax zero is unlimited",
			max:  0,
			setup: func(t *testing.T, l *Ledger) {
				for i := 0; i < 50; i++ {
					createFiber(t, l, grant, "", fmt.Sprintf("f%d", i))
				}
			},
			grant:   grant,
			wantAct: ActCreate,
		},
		{
			name: "attach at max still succeeds",
			max:  1,
			setup: func(t *testing.T, l *Ledger) {
				createFiber(t, l, grant, "S1", "f1")
			},
			grant:   grant,
			session: "S1",
			wantAct: ActAttach,
		},
		{
			name: "resume at max is full",
			max:  1,
			setup: func(t *testing.T, l *Ledger) {
				createFiber(t, l, grant, "S1", "f1")
				l.OnPark("f1", "delta-f1")
				createFiber(t, l, grant, "", "f2") // takes the freed slot
			},
			grant:   grant,
			session: "S1",
			wantErr: ErrGrantFull,
		},
		{
			name: "resume under max reserves the slot",
			max:  1,
			setup: func(t *testing.T, l *Ledger) {
				createFiber(t, l, grant, "S1", "f1")
				l.OnPark("f1", "delta-f1")
			},
			grant:   grant,
			session: "S1",
			wantAct: ActResume,
		},
		{
			name:    "unknown grant",
			max:     1,
			setup:   func(t *testing.T, l *Ledger) {},
			grant:   "nope",
			wantErr: ErrGrantUnknown,
		},
		{
			name: "release frees a slot",
			max:  1,
			setup: func(t *testing.T, l *Ledger) {
				createFiber(t, l, grant, "", "f1")
				l.OnRelease("f1")
			},
			grant:   grant,
			wantAct: ActCreate,
		},
		{
			name: "park frees a slot for anonymous create",
			max:  1,
			setup: func(t *testing.T, l *Ledger) {
				createFiber(t, l, grant, "S1", "f1")
				l.OnPark("f1", "delta-f1")
			},
			grant:   grant,
			wantAct: ActCreate,
		},
		{
			name: "abandoned reservation rolls back",
			max:  1,
			setup: func(t *testing.T, l *Ledger) {
				// Resolve reserves, but the runtime "fails": unlock without
				// commit must return the slot.
				_, _, _, _, unlock, err := l.Resolve(grant, "", TierCheckpoint)
				if err != nil {
					t.Fatalf("setup resolve: %v", err)
				}
				unlock()
			},
			grant:   grant,
			wantAct: ActCreate,
		},
		{
			name: "reservation counts before commit",
			max:  1,
			setup: func(t *testing.T, l *Ledger) {
				// A clone in flight (resolved, not yet committed) must
				// already hold the slot, or a burst overshoots fibers.max.
				_, _, _, _, _, err := l.Resolve(grant, "", TierCheckpoint)
				if err != nil {
					t.Fatalf("setup resolve: %v", err)
				}
			},
			grant:   grant,
			wantErr: ErrGrantFull,
		},
		{
			name: "released session name is forgotten",
			max:  2,
			setup: func(t *testing.T, l *Ledger) {
				createFiber(t, l, grant, "S1", "f1")
				l.OnRelease("f1")
			},
			grant:   grant,
			session: "S1",
			wantAct: ActCreate, // not attach or resume: the name was freed
		},
		{
			name: "revoked grant is unknown",
			max:  1,
			setup: func(t *testing.T, l *Ledger) {
				l.RevokeGrant(grant)
			},
			grant:   grant,
			wantErr: ErrGrantUnknown,
		},
		{
			name: "re-admit preserves live count (still full)",
			max:  1,
			setup: func(t *testing.T, l *Ledger) {
				createFiber(t, l, grant, "", "f1") // live = 1 at max = 1
				// A duplicate delivery (relist/reconnect) must not reset live.
				l.AdmitGrant(grant, "sbx-"+grant, 1)
			},
			grant:   grant,
			wantErr: ErrGrantFull, // regression: overwrite would zero live → ActCreate
		},
		{
			name: "re-admit refreshes fiberMax in place",
			max:  1,
			setup: func(t *testing.T, l *Ledger) {
				createFiber(t, l, grant, "", "f1")   // live = 1
				l.AdmitGrant(grant, "sbx-"+grant, 2) // raise the ceiling to 2
			},
			grant:   grant,
			wantAct: ActCreate, // live 1 < new max 2, so a second create fits
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := NewLedger(1)
			l.AdmitGrant(grant, "sbx-"+grant, tc.max)
			tc.setup(t, l)

			act, _, _, _, unlock, err := l.Resolve(tc.grant, tc.session, TierCheckpoint)
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
		l := NewLedger(1)
		l.AdmitGrant(grant, "sbx-"+grant, 4)
		createFiber(t, l, grant, "", "f1") // mints seq 1

		// Duplicate delivery: must not reset nextSeq, or the next fence would
		// reuse a sequence already handed out for this grant+epoch.
		l.AdmitGrant(grant, "sbx-"+grant, 4)

		_, fence, _, commit, unlock, err := l.Resolve(grant, "", TierCheckpoint)
		if err != nil {
			t.Fatalf("Resolve after re-admit: %v", err)
		}
		commit(Session{
			GrantUID: grant, State: StateRunning, Fence: fence,
			Handle: FiberHandle{ID: "f2", Endpoint: "127.0.0.1:2"},
		})
		unlock()
		if fence.Seq <= 1 {
			t.Fatalf("fence.Seq = %d after re-admit, want > 1 (sequence reused)", fence.Seq)
		}
	})

	t.Run("revoke while blocked on session lock", func(t *testing.T) {
		l := NewLedger(1)
		l.AdmitGrant(grant, "sbx-"+grant, 2)
		createFiber(t, l, grant, "S1", "f1")

		key := grant + "/S1"
		gate := l.acquireSession(key) // hold the per-name lock so Resolve blocks

		done := make(chan error, 1)
		go func() {
			_, _, _, _, unlock, err := l.Resolve(grant, "S1", TierCheckpoint)
			if unlock != nil {
				unlock()
			}
			done <- err
		}()

		select {
		case err := <-done:
			l.releaseSession(key, gate)
			t.Fatalf("Resolve returned before revoke (did not block): %v", err)
		case <-time.After(50 * time.Millisecond):
		}
		l.RevokeGrant(grant)
		l.releaseSession(key, gate)
		if err := <-done; !errors.Is(err, ErrGrantUnknown) {
			t.Fatalf("Resolve err = %v, want %v", err, ErrGrantUnknown)
		}
	})
}
