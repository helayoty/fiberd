package compare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// clock is a fake monotonic clock. Every reading advances it by a
// millisecond, and the fake adapter's untimed steps advance it further,
// so where a step falls relative to the activation's clock shows in
// the records.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(time.Millisecond)
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fake is an adapter that counts calls and fails where told. Prepare,
// Park and Refill take prepCost, parkCost and refillCost of clock time. Release and
// Cleanup refuse a cancelled context, as a real API client would.
type fake struct {
	mu                 sync.Mutex
	clock              *clock
	activate, released int
	prepared, parked   int
	refilled, cleaned  int
	failActivate       bool
	failPrepare        bool
	park               bool
	density            int64
	prepCost, parkCost time.Duration
	refillCost         time.Duration
	setupHangs         bool // Setup waits until its context ends
	// cancel, when set, is called on the first Activate, like a SIGINT
	// in the middle of a burst.
	cancel context.CancelFunc
}

func (f *fake) Setup(ctx context.Context) error {
	if f.setupHangs {
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

func TestSetupTimeout(t *testing.T) {
	cases := []struct {
		name    string
		hangs   bool
		wantErr error
	}{
		{name: "a system that never comes up fails the run", hangs: true, wantErr: context.DeadlineExceeded},
		{name: "a system that comes up runs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fake{clock: &clock{t: time.Unix(0, 0)}, setupHangs: tc.hangs}
			r := &Runner{Adapter: f, System: "s", Class: "c", Runs: 1, Bursts: []int{1}, Poll: time.Millisecond,
				SetupTimeout: 50 * time.Millisecond, Out: &bytes.Buffer{}, Load: func() string { return "1 2 3" }, Now: f.clock.Now}
			done := make(chan error, 1)
			go func() { done <- r.Run(context.Background()) }()
			select {
			case err := <-done:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Run = %v, want %v", err, tc.wantErr)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Run hung in Setup")
			}
		})
	}
}

func (f *fake) Prepare(_ context.Context, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prepared++
	if f.failPrepare {
		return errors.New("rmi: no crictl")
	}
	f.clock.advance(f.prepCost)
	return nil
}

func (f *fake) Refill(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refilled++
	f.clock.advance(f.refillCost)
	return nil
}

func (f *fake) Activate(_ context.Context, id string) (Handle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.activate++
	if f.cancel != nil {
		f.cancel()
	}
	if f.failActivate {
		return Handle{}, errors.New("no capacity")
	}
	return Handle{ID: id, Meta: map[string]string{}}, nil
}

func (f *fake) Ready(_ context.Context, h Handle) (Handle, time.Time, error) {
	h.Addr = "fake"
	h.Meta["attempts"] = "2"
	return h, f.clock.Now(), nil
}

func (f *fake) Release(ctx context.Context, _ Handle) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.released++
	return nil
}

func (f *fake) Park(_ context.Context, _ Handle) error {
	if !f.park {
		return ErrUnsupported
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.parked++
	f.clock.advance(f.parkCost)
	return nil
}

func (f *fake) Resume(_ context.Context, h Handle) (Handle, error) {
	return Handle{ID: h.ID + "-resumed", Meta: map[string]string{}}, nil
}

func (f *fake) Density(_ context.Context, hs []Handle) (int64, error) {
	if f.density == 0 {
		return 0, ErrUnsupported
	}
	return f.density * int64(len(hs)), nil
}

func (f *fake) Cleanup(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cleaned++
	return nil
}

func decode(t *testing.T, out []byte) []Record {
	t.Helper()
	var recs []Record
	for _, line := range bytes.Split(bytes.TrimSpace(out), []byte("\n")) {
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatalf("%s: %v", line, err)
		}
		recs = append(recs, r)
	}
	return recs
}

func count(recs []Record, kind string, keep func(Record) bool) int {
	n := 0
	for _, r := range recs {
		if r.Kind == kind && (keep == nil || keep(r)) {
			n++
		}
	}
	return n
}

func TestRunner(t *testing.T) {
	cases := []struct {
		name           string
		fake           *fake
		runs           int
		bursts         []int
		resume         bool
		density        int
		cancel         bool // the first Activate cancels the run
		wantErr        error
		wantActivation int // activation lines, the latency samples
		wantHold       int // hold lines, for resume and density
		wantErrors     int
		wantReleased   int
		wantResumeErr  string
		wantDensity    int64
		check          func(t *testing.T, recs []Record, f *fake)
	}{
		{name: "two runs, bursts 1 and 2, plus the cold run", fake: &fake{}, runs: 2, bursts: []int{1, 2},
			wantActivation: 9, wantReleased: 9},
		{name: "activation errors are recorded, nothing released", fake: &fake{failActivate: true}, runs: 1, bursts: []int{3},
			wantActivation: 6, wantErrors: 6},
		{name: "the pre-step runs before the activation's clock", fake: &fake{prepCost: 100 * time.Millisecond}, runs: 1, bursts: []int{2},
			wantActivation: 4, wantReleased: 4,
			check: func(t *testing.T, recs []Record, f *fake) {
				if f.prepared != 4 {
					t.Errorf("prepared %d, want 4", f.prepared)
				}
				for _, r := range recs {
					if r.Kind == "activation" && r.TFirstByteMs >= 100 {
						t.Errorf("activation %s took %.0fms: the pre-step was timed", r.ID, r.TFirstByteMs)
					}
				}
			}},
		{name: "a failed pre-step fails the activation before its clock", fake: &fake{failPrepare: true}, runs: 1, bursts: []int{1},
			wantActivation: 2, wantErrors: 2,
			check: func(t *testing.T, recs []Record, f *fake) {
				if f.activate != 0 {
					t.Errorf("activated %d times after a failed pre-step", f.activate)
				}
				for _, r := range recs {
					if r.Kind == "activation" && (!strings.HasPrefix(r.Error, "prepare: ") || r.T0 != "") {
						t.Errorf("record %+v", r)
					}
				}
			}},
		{name: "resume unsupported is a line, not a failure, and no latency sample", fake: &fake{}, runs: 1, bursts: []int{1}, resume: true,
			wantActivation: 2, wantHold: 2, wantReleased: 4, wantResumeErr: ErrUnsupported.Error()},
		{name: "resume supported: the park is untimed, the resumed handle is released", fake: &fake{park: true, parkCost: 100 * time.Millisecond},
			runs: 1, bursts: []int{1}, resume: true,
			wantActivation: 2, wantHold: 2, wantReleased: 4,
			check: func(t *testing.T, recs []Record, f *fake) {
				if f.parked != 2 {
					t.Errorf("parked %d, want 2", f.parked)
				}
				for _, r := range recs {
					if r.Kind == "resume" && (r.TFirstByteMs <= 0 || r.TFirstByteMs >= 100) {
						t.Errorf("resume took %.0fms: the park was timed", r.TFirstByteMs)
					}
				}
			}},
		{name: "density holds n instances and reads them, as hold lines", fake: &fake{density: 1 << 20}, runs: 1, bursts: []int{1}, density: 2,
			wantActivation: 2, wantHold: 4, wantReleased: 6, wantDensity: 2 << 20},
		{name: "the pool refills before every burst, resume and density step, untimed",
			fake: &fake{park: true, density: 1 << 20, refillCost: 100 * time.Millisecond}, runs: 1, bursts: []int{1, 2}, resume: true, density: 1,
			wantActivation: 6, wantHold: 4, wantReleased: 10, wantDensity: 1 << 20,
			check: func(t *testing.T, recs []Record, f *fake) {
				// Two runs of two bursts, a resume and a density step each.
				if f.refilled != 8 {
					t.Errorf("refilled %d times, want 8", f.refilled)
				}
				for _, r := range recs {
					if (r.Kind == "activation" || r.Kind == "resume") && r.TFirstByteMs >= 100 {
						t.Errorf("%s %s took %.0fms: the refill was timed", r.Kind, r.ID, r.TFirstByteMs)
					}
					if r.Kind == "burst" && r.WallMs >= 100 {
						t.Errorf("burst of %d took %.0fms: the refill was timed", r.Burst, r.WallMs)
					}
				}
			}},
		{name: "a cancelled run stops, releases what it holds and cleans up", fake: &fake{}, runs: 2, bursts: []int{2}, cancel: true,
			wantErr: context.Canceled, wantActivation: 2, wantReleased: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			tc.fake.clock = &clock{t: time.Unix(0, 0)}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				tc.fake.cancel = cancel
			}
			r := &Runner{Adapter: tc.fake, System: "s", Class: "c", Runs: tc.runs, Bursts: tc.bursts, Poll: time.Millisecond,
				Resume: tc.resume, Density: tc.density, Idle: time.Millisecond, Out: &out,
				Load: func() string { return "1 2 3" }, Now: tc.fake.clock.Now}
			if err := r.Run(ctx); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Run = %v, want %v", err, tc.wantErr)
			}
			recs := decode(t, out.Bytes())
			if got := count(recs, "setup", nil); got != 1 {
				t.Errorf("setup lines %d, want 1", got)
			}
			if tc.wantErr == nil {
				if got := count(recs, "run", nil); got != tc.runs+1 {
					t.Errorf("run lines %d, want %d", got, tc.runs+1)
				}
				if got := count(recs, "run", func(r Record) bool { return r.Cold }); got != 1 {
					t.Errorf("cold run lines %d, want 1", got)
				}
			}
			if got := count(recs, "activation", nil); got != tc.wantActivation {
				t.Errorf("activation lines %d, want %d", got, tc.wantActivation)
			}
			if got := count(recs, "activation", func(r Record) bool { return r.Burst == 0 }); got != 0 {
				t.Errorf("%d activation lines have no burst: hold lines leaked into the latency samples", got)
			}
			if got := count(recs, "hold", nil); got != tc.wantHold {
				t.Errorf("hold lines %d, want %d", got, tc.wantHold)
			}
			if got := count(recs, "activation", func(r Record) bool { return r.Error != "" }); got != tc.wantErrors {
				t.Errorf("errors %d, want %d", got, tc.wantErrors)
			}
			if got := count(recs, "activation", func(r Record) bool { return r.Cold && r.Run != 0 || !r.Cold && r.Run == 0 }); got != 0 {
				t.Errorf("%d activation lines flag cold wrongly", got)
			}
			if tc.fake.released != tc.wantReleased {
				t.Errorf("released %d, want %d", tc.fake.released, tc.wantReleased)
			}
			if tc.fake.cleaned != 1 {
				t.Errorf("cleaned up %d times, want once", tc.fake.cleaned)
			}
			for _, rec := range recs {
				if rec.Kind == "activation" && rec.Error == "" && rec.Attempts != 2 {
					t.Errorf("attempts %d not copied from the handle", rec.Attempts)
				}
				if rec.Kind == "run" && rec.LoadBefore != "1 2 3" {
					t.Errorf("load %q not recorded", rec.LoadBefore)
				}
				if rec.Kind == "resume" && rec.Error != tc.wantResumeErr {
					t.Errorf("resume error %q, want %q", rec.Error, tc.wantResumeErr)
				}
				if rec.Kind == "density" && rec.Bytes != tc.wantDensity {
					t.Errorf("density %d, want %d", rec.Bytes, tc.wantDensity)
				}
			}
			if tc.resume && count(recs, "resume", nil) != tc.runs+1 {
				t.Errorf("resume lines %d, want %d", count(recs, "resume", nil), tc.runs+1)
			}
			if tc.check != nil {
				tc.check(t, recs, tc.fake)
			}
		})
	}
}

func TestHostLoad(t *testing.T) {
	cases := []struct{ name string }{{"three fields or unknown"}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := HostLoad()
			if l != "unknown" && len(strings.Fields(l)) != 3 {
				t.Errorf("load %q should be three averages", l)
			}
		})
	}
}
