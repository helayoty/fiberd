package core

import (
	"errors"
	"fmt"
	"testing"
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
}
