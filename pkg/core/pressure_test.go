package core_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

type fakePressure struct {
	mu  sync.Mutex
	psi map[string]float64
}

func (f *fakePressure) set(uid string, v float64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.psi == nil {
		f.psi = map[string]float64{}
	}
	f.psi[uid] = v
}

func (f *fakePressure) Pressure(uid string) (float64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.psi[uid], nil
}

// recorder wraps the agent's verbs so the test sees the ladder's choices.
type recorder struct {
	mu      sync.Mutex
	parked  []string
	freed   []string
	yielded []string
}

func TestPressureLadder(t *testing.T) {
	g := core.Grant{UID: "g1", Audience: "node-a", FiberMax: 10,
		Policy: core.Policy{PSISomeAvg10Shed: 10, PSISomeAvg10Park: 25}}
	a := newAgent(t, "up", core.TierCheckpoint, g)
	src := &fakePressure{}
	rec := &recorder{}
	ctl := &core.PressureController{
		Ledger: a.Ledger, Source: src,
		Park: func(ctx context.Context, id string) error {
			rec.mu.Lock()
			rec.parked = append(rec.parked, id)
			rec.mu.Unlock()
			_, _, err := a.Park(ctx, id, false)
			return err
		},
		Release: func(ctx context.Context, id string) error {
			rec.mu.Lock()
			rec.freed = append(rec.freed, id)
			rec.mu.Unlock()
			_, err := a.Release(ctx, id, false)
			return err
		},
		Yield: func(_ context.Context, uid string) {
			rec.mu.Lock()
			rec.yielded = append(rec.yielded, uid)
			rec.mu.Unlock()
			a.Ledger.RevokeGrant(uid)
		},
	}
	a.Pressure = ctl
	ctx := context.Background()
	clone := func(session string) core.CloneResponse {
		t.Helper()
		r, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Session: session, Deadline: time.Second})
		if err != nil || code != core.OK {
			t.Fatalf("clone %q: %d %v", session, code, err)
		}
		return r
	}
	big := clone("big")     // named, largest W
	small := clone("small") // named, smaller W
	anon := clone("")       // anonymous
	a.Ledger.SetFiberW(big.FiberID, 300)
	a.Ledger.SetFiberW(small.FiberID, 100)
	a.Ledger.SetFiberW(anon.FiberID, 200)

	// Below shed: nothing happens, clones allowed.
	src.set("g1", 5)
	ctl.Tick(ctx)
	if ctl.Shedding("g1") {
		t.Fatal("shedding below the shed watermark")
	}

	// Shed band: new fibers refused with SHED; attach still served.
	src.set("g1", 15)
	ctl.Tick(ctx)
	if !ctl.Shedding("g1") {
		t.Fatal("not shedding in the shed band")
	}
	if _, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Deadline: time.Second}); code != core.Shed || !errors.Is(err, core.ErrPressure) {
		t.Fatalf("new fiber under shed = %d %v, want Shed ErrPressure", code, err)
	}
	if r, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Session: "big", Deadline: time.Second}); code != core.OK || r.Kind != core.ActAttach {
		t.Fatalf("attach under shed = %d %v %v, want OK attach", code, err, r.Kind)
	}
	if st, _ := a.Ledger.Status("g1"); st.Running != 3 {
		t.Fatalf("running = %d after a refused clone, want 3 (reservation returned)", st.Running)
	}

	// Park band: one victim per tick, largest W first. big (300, named)
	// is parked; then anon (200, anonymous) is released; then small (100,
	// named) is parked.
	src.set("g1", 40)
	ctl.Tick(ctx)
	ctl.Tick(ctx)
	ctl.Tick(ctx)
	rec.mu.Lock()
	parked, freed := append([]string{}, rec.parked...), append([]string{}, rec.freed...)
	rec.mu.Unlock()
	if len(parked) != 2 || parked[0] != big.FiberID || parked[1] != small.FiberID {
		t.Fatalf("parked = %v, want [%s %s]", parked, big.FiberID, small.FiberID)
	}
	if len(freed) != 1 || freed[0] != anon.FiberID {
		t.Fatalf("released = %v, want [%s]", freed, anon.FiberID)
	}
	st, _ := a.Ledger.Status("g1")
	if st.Running != 0 || st.Parked != 2 {
		t.Fatalf("status after reclaim = %+v, want running 0 parked 2", st)
	}

	// Pressure persists with nothing left: yield after three ticks.
	ctl.Tick(ctx)
	ctl.Tick(ctx)
	if len(rec.yielded) != 0 {
		t.Fatal("yielded too early")
	}
	ctl.Tick(ctx)
	if len(rec.yielded) != 1 || rec.yielded[0] != "g1" {
		t.Fatalf("yielded = %v, want [g1]", rec.yielded)
	}
	if _, ok := a.Ledger.Grant("g1"); ok {
		t.Fatal("grant still held after yield")
	}

	// Recovery: pressure gone clears shedding (on a re-admitted grant).
	a.Ledger.AdmitGrant(g)
	src.set("g1", 0)
	ctl.Tick(ctx)
	if ctl.Shedding("g1") {
		t.Fatal("still shedding after pressure cleared")
	}
}

func TestPressureParkFailsOverToRelease(t *testing.T) {
	// A FIBER_WARM runtime cannot park: named sessions are released.
	g := core.Grant{UID: "g1", Audience: "node-a", FiberMax: 10}
	a := newAgent(t, "up", core.TierWarm, g)
	src := &fakePressure{}
	var released []string
	ctl := &core.PressureController{
		Ledger: a.Ledger, Source: src,
		Park: func(context.Context, string) error { return errors.New("no checkpoint tier") },
		Release: func(ctx context.Context, id string) error {
			released = append(released, id)
			_, err := a.Release(ctx, id, false)
			return err
		},
	}
	ctx := context.Background()
	r, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Session: "S", Deadline: time.Second})
	if err != nil || code != core.OK {
		t.Fatal(err)
	}
	src.set("g1", 50)
	ctl.Tick(ctx)
	if len(released) != 1 || released[0] != r.FiberID {
		t.Fatalf("released = %v, want [%s]", released, r.FiberID)
	}
	// Default watermarks apply when the policy leaves them zero.
	a.Ledger.AdmitGrant(g)
	src.set("g1", core.DefaultPSIShed)
	ctl.Tick(ctx)
	if !ctl.Shedding("g1") {
		t.Fatal("default shed watermark not applied")
	}
}
