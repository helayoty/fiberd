package core_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/core/coretest"
)

// fakePool is a runtime whose Clone takes from a per-grant pool the
// refill loop fills through it.
type fakePool struct {
	fakeRuntime
	mu      sync.Mutex
	pooled  map[string]int
	fills   []time.Time
	fillErr error
	gate    chan struct{} // when set, Fill waits on it
	drained int
	exits   chan string
}

func newFakePool(tier core.Tier) *fakePool {
	return &fakePool{
		fakeRuntime: fakeRuntime{tier: tier, exits: make(chan core.FiberExit, 8)},
		pooled:      map[string]int{},
		exits:       make(chan string, 8),
	}
}

func (p *fakePool) Fill(ctx context.Context, g core.Grant, _ time.Duration) error {
	p.mu.Lock()
	p.fills = append(p.fills, time.Now())
	gate, err := p.gate, p.fillErr
	p.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.pooled[g.UID]++
	p.mu.Unlock()
	return nil
}

func (p *fakePool) Drain(uid string, n int) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n < 0 || n > p.pooled[uid] {
		n = p.pooled[uid]
	}
	p.pooled[uid] -= n
	p.drained += n
	return n
}

func (p *fakePool) Pooled(uid string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pooled[uid]
}

func (p *fakePool) PooledExits() <-chan string { return p.exits }

// DefaultDeadlines gives a fill the second a restore takes, as a
// snapshot runtime advises.
func (p *fakePool) DefaultDeadlines() (time.Duration, time.Duration) {
	return time.Second, 2 * time.Second
}

func (p *fakePool) Clone(ctx context.Context, spec core.CloneSpec) (core.FiberHandle, error) {
	h, err := p.fakeRuntime.Clone(ctx, spec)
	if err != nil || spec.Source == core.SourceDelta {
		return h, err
	}
	p.mu.Lock()
	if p.pooled[spec.Grant.UID] > 0 {
		p.pooled[spec.Grant.UID]--
		h.Pooled = true
	}
	p.mu.Unlock()
	return h, nil
}

// die is a pooled sandbox of the grant dying before its hand-out.
func (p *fakePool) die(uid string) {
	p.mu.Lock()
	p.pooled[uid]--
	p.mu.Unlock()
	p.exits <- uid
}

func (p *fakePool) fillTimes() []time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]time.Time(nil), p.fills...)
}

func (p *fakePool) fillCount() int { return len(p.fillTimes()) }

// runAgent drives Run on a fast tick until the returned stop is called.
func runAgent(t *testing.T, a *core.Agent) (stop func()) {
	t.Helper()
	a.StatusInterval = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		a.Run(ctx)
		close(done)
	}()
	return func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Run did not return after its context ended")
		}
	}
}

// settled waits settle and then reports the fill count, for rows that
// expect the loop to do nothing more.
func settled(p *fakePool, settle time.Duration) int {
	time.Sleep(settle)
	return p.fillCount()
}

// TestRefillPolicy checks what the refill loop does for one grant: how
// far it fills, what holds it, and how it backs off.
func TestRefillPolicy(t *testing.T) {
	cases := []struct {
		name    string
		warm    int
		max     int
		budget  float64 // the thrash budget's base rate, 1000 when zero
		shed    bool    // the grant is shedding
		fillErr error
		gate    bool // fills wait until the test lets them through
		check   func(t *testing.T, a *core.Agent, p *fakePool)
	}{
		{name: "warm 0 fills nothing", warm: 0, max: 2, check: func(t *testing.T, _ *core.Agent, p *fakePool) {
			if n := settled(p, 200*time.Millisecond); n != 0 {
				t.Fatalf("fills = %d, want 0", n)
			}
		}},
		{name: "warm past max fills to max", warm: 5, max: 2, check: func(t *testing.T, a *core.Agent, p *fakePool) {
			waitUntil(t, 5*time.Second, "two pooled", func() bool { return p.Pooled("g1") == 2 })
			if n := settled(p, 200*time.Millisecond); n != 2 {
				t.Fatalf("fills = %d, want 2", n)
			}
			if st, _ := coretest.GrantStatus(a.Ledger, "g1"); st.Pooled != 2 || st.Running != 0 {
				t.Fatalf("status = %+v, want pooled 2 running 0", st)
			}
		}},
		{name: "an empty budget holds the fill", warm: 2, max: 2, budget: -1, check: func(t *testing.T, _ *core.Agent, p *fakePool) {
			if n := settled(p, 200*time.Millisecond); n != 0 {
				t.Fatalf("fills = %d, want 0", n)
			}
		}},
		{name: "a shedding grant is not filled", warm: 2, max: 2, shed: true, check: func(t *testing.T, _ *core.Agent, p *fakePool) {
			if n := settled(p, 200*time.Millisecond); n != 0 {
				t.Fatalf("fills = %d, want 0", n)
			}
		}},
		{name: "a failed fill backs off, doubling", warm: 1, max: 1, fillErr: errors.New("fake: restore refused"), check: backsOff},
		{name: "pressure from the fill backs off", warm: 1, max: 1, fillErr: core.ErrPressure, check: backsOff},
		{name: "no pool is remembered", warm: 1, max: 1, fillErr: core.ErrNoPool, check: func(t *testing.T, _ *core.Agent, p *fakePool) {
			waitUntil(t, 5*time.Second, "one fill", func() bool { return p.fillCount() == 1 })
			if n := settled(p, 300*time.Millisecond); n != 1 {
				t.Fatalf("fills = %d, want 1 and no retry", n)
			}
		}},
		{name: "a pooled death backs off", warm: 1, max: 1, check: func(t *testing.T, _ *core.Agent, p *fakePool) {
			waitUntil(t, 5*time.Second, "one pooled", func() bool { return p.Pooled("g1") == 1 })
			died := time.Now()
			p.die("g1")
			waitUntil(t, 5*time.Second, "the refill", func() bool { return p.fillCount() == 2 })
			if gap := p.fillTimes()[1].Sub(died); gap < 100*time.Millisecond {
				t.Fatalf("refilled %s after the death, want 100ms or more", gap)
			}
		}},
		{name: "one fill in flight per grant", warm: 3, max: 3, gate: true, check: func(t *testing.T, _ *core.Agent, p *fakePool) {
			waitUntil(t, 5*time.Second, "one fill", func() bool { return p.fillCount() == 1 })
			if n := settled(p, 200*time.Millisecond); n != 1 {
				t.Fatalf("fills = %d while one waits, want 1", n)
			}
			close(p.gate)
			waitUntil(t, 5*time.Second, "three pooled", func() bool { return p.Pooled("g1") == 3 })
			if n := settled(p, 200*time.Millisecond); n != 3 {
				t.Fatalf("fills = %d, want 3", n)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := core.Grant{UID: "g1", Tenant: "acme", Audience: "node-a", FiberMax: tc.max, FiberWarm: tc.warm, LeaseExpiry: time.Now().Add(time.Hour)}
			a := newAgent(t, "up", core.TierSnapshot, g)
			p := newFakePool(core.TierSnapshot)
			p.fillErr = tc.fillErr
			if tc.gate {
				p.gate = make(chan struct{})
			}
			a.Runtime = p
			if tc.budget < 0 {
				a.Budget = core.NewBudget(0, 256<<20)
			}
			ctx := context.Background()
			if code, err := a.Admit(ctx, g); err != nil || code != core.OK {
				t.Fatalf("admit = %d %v", code, err)
			}
			if tc.shed {
				src := &fakePressure{}
				src.set("g1", 30)
				a.Pressure = &core.PressureController{Ledger: a.Ledger, Source: src}
				a.Pressure.Tick(ctx)
			}
			stop := runAgent(t, a)
			defer stop()
			tc.check(t, a, p)
		})
	}
}

// backsOff checks that failed fills are retried 100 ms apart, then 200.
func backsOff(t *testing.T, _ *core.Agent, p *fakePool) {
	t.Helper()
	waitUntil(t, 5*time.Second, "three fills", func() bool { return p.fillCount() >= 3 })
	ts := p.fillTimes()
	if g1, g2 := ts[1].Sub(ts[0]), ts[2].Sub(ts[1]); g1 < 100*time.Millisecond || g2 < 200*time.Millisecond {
		t.Fatalf("retries %s and %s apart, want 100ms then 200ms or more", g1, g2)
	}
}

// TestPooledCountsInMax checks that pooled sandboxes sit inside
// fibers.max: a Clone takes one, the refill waits while live + pooled is
// at max, and a freed slot refills.
func TestPooledCountsInMax(t *testing.T) {
	cases := []struct {
		name        string
		clones      int
		release     bool // release the first fiber after the clones
		wantRunning int
		wantPooled  int
		wantFills   int
	}{
		{name: "a clone takes a pooled sandbox and the refill waits", clones: 1, wantRunning: 1, wantPooled: 1, wantFills: 2},
		{name: "two clones empty the pool", clones: 2, wantRunning: 2, wantPooled: 0, wantFills: 2},
		{name: "a freed slot refills", clones: 2, release: true, wantRunning: 1, wantPooled: 1, wantFills: 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := core.Grant{UID: "g1", Tenant: "acme", Audience: "node-a", FiberMax: 2, FiberWarm: 2, LeaseExpiry: time.Now().Add(time.Hour)}
			a := newAgent(t, "up", core.TierSnapshot, g)
			p := newFakePool(core.TierSnapshot)
			a.Runtime = p
			rec := &auditLog{}
			a.Audit = rec
			ctx := context.Background()
			if code, err := a.Admit(ctx, g); err != nil || code != core.OK {
				t.Fatalf("admit = %d %v", code, err)
			}
			stop := runAgent(t, a)
			defer stop()
			waitUntil(t, 5*time.Second, "the pool to fill", func() bool { return p.Pooled("g1") == 2 })
			var first string
			for i := range tc.clones {
				r, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Deadline: time.Second})
				if err != nil || code != core.OK {
					t.Fatalf("clone %d = %d %v", i, code, err)
				}
				if i == 0 {
					first = r.FiberID
				}
			}
			if tc.release {
				if code, err := a.Release(ctx, first, false); err != nil || code != core.OK {
					t.Fatalf("release = %d %v", code, err)
				}
			}
			waitUntil(t, 5*time.Second, "the ledger to settle", func() bool {
				st, _ := coretest.GrantStatus(a.Ledger, "g1")
				return st.Running == tc.wantRunning && st.Pooled == tc.wantPooled && p.fillCount() == tc.wantFills
			})
			if n := settled(p, 200*time.Millisecond); n != tc.wantFills {
				t.Fatalf("fills = %d, want %d", n, tc.wantFills)
			}
			creates := rec.events("create")
			if len(creates) != tc.clones {
				t.Fatalf("create records = %d, want %d", len(creates), tc.clones)
			}
			for _, c := range creates {
				if c.Detail != "pooled" {
					t.Fatalf("create record detail = %q, want pooled", c.Detail)
				}
			}
		})
	}
}

// TestLadderDrainsPoolFirst checks that the pressure ladder discards a
// pooled sandbox before it parks any fiber, and parks once none waits.
func TestLadderDrainsPoolFirst(t *testing.T) {
	cases := []struct {
		name       string
		pooled     int
		ticks      int
		wantDrain  int
		wantParked int
	}{
		{name: "pooled present, one tick drains", pooled: 1, ticks: 1, wantDrain: 1, wantParked: 0},
		{name: "pooled present, the second tick parks", pooled: 1, ticks: 2, wantDrain: 1, wantParked: 1},
		{name: "pooled absent, the first tick parks", pooled: 0, ticks: 1, wantDrain: 0, wantParked: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := core.Grant{UID: "g1", Tenant: "acme", Audience: "node-a", FiberMax: 4, FiberWarm: 1,
				Policy: core.Policy{PSISomeAvg10Shed: 10, PSISomeAvg10Park: 25}}
			a := newAgent(t, "up", core.TierSnapshot, g)
			p := newFakePool(core.TierSnapshot)
			a.Runtime = p
			ctx := context.Background()
			r, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Session: "s", Deadline: time.Second})
			if err != nil || code != core.OK {
				t.Fatalf("clone = %d %v", code, err)
			}
			p.pooled["g1"] = tc.pooled
			a.Ledger.SetPooled("g1", tc.pooled)
			src := &fakePressure{}
			src.set("g1", 30)
			rec := &recorder{}
			ctl := &core.PressureController{
				Ledger: a.Ledger, Source: src, Drain: a.DrainPool,
				Park: func(ctx context.Context, id string) error {
					rec.mu.Lock()
					rec.parked = append(rec.parked, id)
					rec.mu.Unlock()
					_, _, err := a.Park(ctx, id, false)
					return err
				},
			}
			for range tc.ticks {
				ctl.Tick(ctx)
			}
			st, _ := coretest.GrantStatus(a.Ledger, "g1")
			if p.drained != tc.wantDrain || st.Pooled != tc.pooled-tc.wantDrain {
				t.Fatalf("drained %d, status pooled %d, want %d drained", p.drained, st.Pooled, tc.wantDrain)
			}
			if len(rec.parked) != tc.wantParked || (tc.wantParked == 1 && rec.parked[0] != r.FiberID) {
				t.Fatalf("parked %v, want %d park of %s", rec.parked, tc.wantParked, r.FiberID)
			}
		})
	}
}

// TestEpochBumpKeepsPool checks that an epoch bump releases the running
// fibers and leaves the pool alone, and that the next hand-out carries
// the new epoch's fence.
func TestEpochBumpKeepsPool(t *testing.T) {
	cases := []struct {
		name   string
		pooled int
		fibers int
	}{
		{name: "pooled present", pooled: 2},
		{name: "pooled present with running fibers", pooled: 1, fibers: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := core.Grant{UID: "g1", Tenant: "acme", Audience: "node-a", FiberMax: 8, FiberWarm: tc.pooled}
			a := newAgent(t, "up", core.TierSnapshot, g)
			p := newFakePool(core.TierSnapshot)
			a.Runtime = p
			store, err := core.OpenEpochStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			a.Epoch = store
			rec := &auditLog{}
			a.Audit = rec
			ctx := context.Background()
			if code, err := a.Admit(ctx, g); err != nil || code != core.OK {
				t.Fatalf("admit = %d %v", code, err)
			}
			for range tc.fibers {
				if _, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Deadline: time.Second}); err != nil || code != core.OK {
					t.Fatalf("clone = %d %v", code, err)
				}
			}
			p.pooled["g1"] = tc.pooled
			a.Ledger.SetPooled("g1", tc.pooled)
			next, err := a.BumpEpoch(ctx, "namespace deleted")
			if err != nil {
				t.Fatal(err)
			}
			st, _ := coretest.GrantStatus(a.Ledger, "g1")
			if p.Pooled("g1") != tc.pooled || p.drained != 0 || st.Pooled != tc.pooled || st.Running != 0 {
				t.Fatalf("after the bump: pooled %d drained %d status %+v, want the pool kept and no fiber", p.Pooled("g1"), p.drained, st)
			}
			r, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Deadline: time.Second})
			if err != nil || code != core.OK {
				t.Fatalf("clone after the bump = %d %v", code, err)
			}
			creates := rec.events("create")
			last := creates[len(creates)-1]
			if r.Fence.Epoch != next || last.Detail != "pooled" || p.Pooled("g1") != tc.pooled-1 {
				t.Fatalf("hand-out: fence %s detail %q pooled %d, want epoch %d, pooled, %d left", r.Fence, last.Detail, p.Pooled("g1"), next, tc.pooled-1)
			}
			if st, _ := coretest.GrantStatus(a.Ledger, "g1"); st.Pooled != tc.pooled-1 || st.Running != 1 {
				t.Fatalf("status = %+v, want pooled %d running 1", st, tc.pooled-1)
			}
		})
	}
}
