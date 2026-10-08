package core_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/core/coretest"
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

// TestPressureLadder walks one grant up and down the ladder as its
// pressure rises and falls. It sheds new clones, then reclaims one victim
// per tick, largest W first. Named sessions are parked and anonymous
// fibers released. It yields when pressure persists with nothing left and
// clears once pressure drops. The steps run in order.
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
	shedding := func(want bool) func(t *testing.T) {
		return func(t *testing.T) {
			if got := ctl.Shedding("g1"); got != want {
				t.Fatalf("shedding = %v, want %v", got, want)
			}
		}
	}

	steps := []struct {
		name    string
		readmit bool // re-admit the grant before setting the pressure
		psi     float64
		ticks   int
		check   func(t *testing.T)
	}{
		{name: "below shed nothing happens", psi: 5, ticks: 1, check: shedding(false)},
		{name: "shed band refuses new fibers with SHED but still serves attach", psi: 15, ticks: 1, check: func(t *testing.T) {
			shedding(true)(t)
			if _, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Deadline: time.Second}); code != core.Shed || !errors.Is(err, core.ErrPressure) {
				t.Fatalf("new fiber under shed = %d %v, want Shed ErrPressure", code, err)
			}
			if r, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Session: "big", Deadline: time.Second}); code != core.OK || r.Kind != core.ActAttach {
				t.Fatalf("attach under shed = %d %v %v, want OK attach", code, err, r.Kind)
			}
			if st, _ := coretest.GrantStatus(a.Ledger, "g1"); st.Running != 3 {
				t.Fatalf("running = %d after a refused clone, want 3 (reservation returned)", st.Running)
			}
		}},
		// big (300, named) is parked, then anon (200, anonymous) is
		// released, then small (100, named) is parked.
		{name: "park band reclaims one victim per tick, largest W first", psi: 40, ticks: 3, check: func(t *testing.T) {
			rec.mu.Lock()
			parked, freed := append([]string{}, rec.parked...), append([]string{}, rec.freed...)
			rec.mu.Unlock()
			if len(parked) != 2 || parked[0] != big.FiberID || parked[1] != small.FiberID {
				t.Fatalf("parked = %v, want [%s %s]", parked, big.FiberID, small.FiberID)
			}
			if len(freed) != 1 || freed[0] != anon.FiberID {
				t.Fatalf("released = %v, want [%s]", freed, anon.FiberID)
			}
			st, _ := coretest.GrantStatus(a.Ledger, "g1")
			if st.Running != 0 || st.Parked != 2 {
				t.Fatalf("status after reclaim = %+v, want running 0 parked 2", st)
			}
		}},
		{name: "persisting pressure with nothing left does not yield after two ticks", psi: 40, ticks: 2, check: func(t *testing.T) {
			if len(rec.yielded) != 0 {
				t.Fatal("yielded too early")
			}
		}},
		{name: "persisting pressure with nothing left yields on the third tick", psi: 40, ticks: 1, check: func(t *testing.T) {
			if len(rec.yielded) != 1 || rec.yielded[0] != "g1" {
				t.Fatalf("yielded = %v, want [g1]", rec.yielded)
			}
			if _, ok := a.Ledger.Grant("g1"); ok {
				t.Fatal("grant still held after yield")
			}
		}},
		{name: "pressure gone clears shedding on a re-admitted grant", readmit: true, psi: 0, ticks: 1, check: shedding(false)},
	}
	for _, tc := range steps {
		if !t.Run(tc.name, func(t *testing.T) {
			if tc.readmit {
				a.Ledger.AdmitGrant(g)
			}
			src.set("g1", tc.psi)
			for range tc.ticks {
				ctl.Tick(ctx)
			}
			tc.check(t)
		}) {
			return // later steps build on this one
		}
	}
}

// TestPressureReclaimVictim checks that park-band pressure parks a named
// session. A runtime that cannot park (FIBER_WARM) releases it instead. An
// anonymous fiber is released without a park. A victim that cannot be
// released either is no reclaim, so pressure that persists yields the
// grant on the third tick.
func TestPressureReclaimVictim(t *testing.T) {
	cases := []struct {
		name         string
		tier         core.Tier
		session      string
		parkErr      error
		releaseErr   error
		ticks        int // 0 means one
		wantParked   bool
		wantReleased bool
		wantYielded  bool
	}{
		{name: "a named session is parked", tier: core.TierCheckpoint, session: "S", wantParked: true},
		{name: "a named session the runtime cannot park is released", tier: core.TierWarm, session: "S",
			parkErr: errors.New("no checkpoint tier"), wantParked: true, wantReleased: true},
		{name: "an anonymous fiber is released without a park", tier: core.TierCheckpoint, wantReleased: true},
		{name: "a victim that cannot be released is retried, then the grant is yielded", tier: core.TierCheckpoint,
			releaseErr: errors.New("kill: EPERM"), ticks: 3, wantReleased: true, wantYielded: true},
		{name: "a victim that cannot be released does not yield before the third tick", tier: core.TierCheckpoint,
			releaseErr: errors.New("kill: EPERM"), ticks: 2, wantReleased: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := core.Grant{UID: "g1", Audience: "node-a", FiberMax: 10}
			a := newAgent(t, "up", tc.tier, g)
			src := &fakePressure{}
			var parked, released, yielded []string
			ctl := &core.PressureController{
				Ledger: a.Ledger, Source: src,
				Park: func(_ context.Context, id string) error {
					parked = append(parked, id)
					return tc.parkErr
				},
				Release: func(ctx context.Context, id string) error {
					released = append(released, id)
					if tc.releaseErr != nil {
						return tc.releaseErr
					}
					_, err := a.Release(ctx, id, false)
					return err
				},
				Yield: func(_ context.Context, uid string) { yielded = append(yielded, uid) },
			}
			ctx := context.Background()
			r, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Session: tc.session, Deadline: time.Second})
			if err != nil || code != core.OK {
				t.Fatal(err)
			}
			src.set("g1", 50)
			ticks := max(tc.ticks, 1)
			for range ticks {
				ctl.Tick(ctx)
			}
			if got := len(parked) == 1 && parked[0] == r.FiberID; got != tc.wantParked || len(parked) > 1 {
				t.Fatalf("park attempts = %v, want parked %v (%s)", parked, tc.wantParked, r.FiberID)
			}
			wantAttempts := 0
			if tc.wantReleased {
				wantAttempts = 1
				if tc.releaseErr != nil {
					wantAttempts = ticks
				}
			}
			if len(released) != wantAttempts {
				t.Fatalf("release attempts = %v, want %d of %s", released, wantAttempts, r.FiberID)
			}
			for _, id := range released {
				if id != r.FiberID {
					t.Fatalf("released %s, want %s", id, r.FiberID)
				}
			}
			if got := len(yielded) == 1 && yielded[0] == "g1"; got != tc.wantYielded || len(yielded) > 1 {
				t.Fatalf("yielded = %v, want yielded %v", yielded, tc.wantYielded)
			}
		})
	}
}

// TestPressureTickSkips checks the grants a tick leaves alone. A grant
// whose pressure cannot be read keeps its rung. A grant revoked while the
// tick runs is not evaluated.
func TestPressureTickSkips(t *testing.T) {
	cases := []struct {
		name         string
		readFails    string // the grant whose second reading fails
		revokeDuring string // the grant revoked when another is read
		wantShedding map[string]bool
		wantRead     map[string]int // readings per grant over both ticks
	}{
		{name: "a reading that fails keeps the grant shedding", readFails: "b",
			wantShedding: map[string]bool{"a": false, "b": true}, wantRead: map[string]int{"a": 2, "b": 2}},
		// Had b been read at zero, its rung would have cleared.
		{name: "a grant revoked during the tick is not read", revokeDuring: "b",
			wantShedding: map[string]bool{"a": false, "b": true}, wantRead: map[string]int{"a": 2, "b": 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := core.NewLedger(1)
			l.AdmitGrant(core.Grant{UID: "a"})
			l.AdmitGrant(core.Grant{UID: "b"})
			tick := 0
			read := map[string]int{}
			src := pressureFunc(func(uid string) (float64, error) {
				read[uid]++
				if tick == 0 {
					return 15, nil // both shed
				}
				if uid == tc.readFails {
					return 0, errors.New("psi: cgroup gone")
				}
				if uid == "a" && tc.revokeDuring != "" {
					l.RevokeGrant(tc.revokeDuring)
				}
				return 0, nil // clear
			})
			ctl := &core.PressureController{Ledger: l, Source: src}
			ctx := context.Background()
			ctl.Tick(ctx)
			tick++
			ctl.Tick(ctx)
			for uid, want := range tc.wantShedding {
				if got := ctl.Shedding(uid); got != want {
					t.Fatalf("Shedding(%s) = %v, want %v", uid, got, want)
				}
			}
			if fmt.Sprint(read) != fmt.Sprint(tc.wantRead) {
				t.Fatalf("readings = %v, want %v", read, tc.wantRead)
			}
		})
	}
}

// pressureFunc adapts a function to a PressureSource.
type pressureFunc func(uid string) (float64, error)

func (f pressureFunc) Pressure(uid string) (float64, error) { return f(uid) }

// TestMaxPressure checks that the highest reading of several sources wins,
// a source that errors is skipped, and no reading at all is an error.
func TestMaxPressure(t *testing.T) {
	gone := errors.New("psi: cgroup gone")
	full := errors.New("engine: not reporting")
	reading := func(v float64, err error) core.PressureSource {
		return pressureFunc(func(string) (float64, error) { return v, err })
	}
	cases := []struct {
		name    string
		sources core.MaxPressure
		want    float64
		wantErr error // nil, or the error, unless noSource
		// noSource means an error of its own, with nothing to read.
		noSource bool
	}{
		{name: "no source is an error", noSource: true},
		{name: "one source is its reading", sources: core.MaxPressure{reading(12, nil)}, want: 12},
		{name: "the highest reading wins", sources: core.MaxPressure{reading(5, nil), reading(30, nil), reading(10, nil)}, want: 30},
		{name: "a source that errors is skipped", sources: core.MaxPressure{reading(5, nil), reading(99, gone)}, want: 5},
		{name: "zero readings are zero, not an error", sources: core.MaxPressure{reading(0, nil), reading(0, nil)}},
		{name: "every source erroring is the last error", sources: core.MaxPressure{reading(0, gone), reading(0, full)}, wantErr: full},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.sources.Pressure("g1")
			switch {
			case tc.noSource:
				if err == nil {
					t.Fatalf("Pressure = %v, want an error", got)
				}
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Pressure = %v %v, want %v", got, err, tc.wantErr)
				}
			case err != nil || got != tc.want:
				t.Fatalf("Pressure = %v %v, want %v", got, err, tc.want)
			}
		})
	}
}

// TestPressureRun checks that Run ticks on its interval, a second when it
// has none, until its context ends.
func TestPressureRun(t *testing.T) {
	cases := []struct {
		name     string
		interval time.Duration
	}{
		{name: "on its interval", interval: 10 * time.Millisecond},
		{name: "every second without one"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := core.NewLedger(1)
			l.AdmitGrant(core.Grant{UID: "g1"})
			src := &fakePressure{}
			src.set("g1", 15)
			ctl := &core.PressureController{Ledger: l, Source: src, Interval: tc.interval}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() {
				ctl.Run(ctx)
				close(done)
			}()
			waitUntil(t, 5*time.Second, "the controller to shed", func() bool { return ctl.Shedding("g1") })
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Run did not return after its context ended")
			}
		})
	}
}

// TestPressureWatermarks checks that shedding starts at the shed
// watermark, from the policy or from the defaults when it leaves them zero.
// A park watermark below shed is raised to it.
func TestPressureWatermarks(t *testing.T) {
	cases := []struct {
		name   string
		policy core.Policy
		psi    float64
		want   bool
	}{
		{name: "below the policy shed watermark is clear", policy: core.Policy{PSISomeAvg10Shed: 10, PSISomeAvg10Park: 25}, psi: 5},
		{name: "in the policy shed band sheds", policy: core.Policy{PSISomeAvg10Shed: 10, PSISomeAvg10Park: 25}, psi: 15, want: true},
		{name: "in the policy park band sheds", policy: core.Policy{PSISomeAvg10Shed: 10, PSISomeAvg10Park: 25}, psi: 40, want: true},
		{name: "the default shed watermark applies when the policy leaves it zero", psi: core.DefaultPSIShed, want: true},
		{name: "just below the default shed watermark is clear", psi: core.DefaultPSIShed - 0.1},
		{name: "a park watermark below shed is raised to it", policy: core.Policy{PSISomeAvg10Shed: 30, PSISomeAvg10Park: 20}, psi: 25},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := core.NewLedger(1)
			l.AdmitGrant(core.Grant{UID: "g1", Policy: tc.policy})
			src := &fakePressure{}
			src.set("g1", tc.psi)
			ctl := &core.PressureController{Ledger: l, Source: src}
			ctl.Tick(context.Background())
			if got := ctl.Shedding("g1"); got != tc.want {
				t.Fatalf("Shedding at psi %.1f = %v, want %v", tc.psi, got, tc.want)
			}
		})
	}
}
