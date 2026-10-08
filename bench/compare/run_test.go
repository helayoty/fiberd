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

// fake is an adapter that counts calls and fails where told.
type fake struct {
	mu                 sync.Mutex
	activate, released int
	failActivate       bool
	resume             bool
	density            int64
}

func (f *fake) Setup(context.Context) error { return nil }

func (f *fake) Activate(_ context.Context, id string) (Handle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.activate++
	if f.failActivate {
		return Handle{}, errors.New("no capacity")
	}
	return Handle{ID: id, Meta: map[string]string{}}, nil
}

func (f *fake) Ready(_ context.Context, h Handle) (Handle, time.Time, error) {
	h.Addr = "fake"
	h.Meta["attempts"] = "2"
	return h, time.Now(), nil
}

func (f *fake) Release(context.Context, Handle) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.released++
	return nil
}

func (f *fake) Resume(_ context.Context, h Handle) (Handle, error) {
	if !f.resume {
		return Handle{}, ErrUnsupported
	}
	return Handle{ID: h.ID + "-resumed", Meta: map[string]string{}}, nil
}

func (f *fake) Density(_ context.Context, hs []Handle) (int64, error) {
	if f.density == 0 {
		return 0, ErrUnsupported
	}
	return f.density * int64(len(hs)), nil
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
		wantActivation int // activation lines
		wantErrors     int
		wantReleased   int
		wantResumeErr  string
		wantDensity    int64
	}{
		{name: "two runs, bursts 1 and 2, plus the cold run", fake: &fake{}, runs: 2, bursts: []int{1, 2},
			wantActivation: 9, wantReleased: 9},
		{name: "activation errors are recorded, nothing released", fake: &fake{failActivate: true}, runs: 1, bursts: []int{3},
			wantActivation: 6, wantErrors: 6},
		{name: "resume unsupported is a line, not a failure", fake: &fake{}, runs: 1, bursts: []int{1}, resume: true,
			wantActivation: 4, wantReleased: 4, wantResumeErr: ErrUnsupported.Error()},
		{name: "resume supported releases the resumed handle", fake: &fake{resume: true}, runs: 1, bursts: []int{1}, resume: true,
			wantActivation: 4, wantReleased: 4},
		{name: "density holds n instances and reads them", fake: &fake{density: 1 << 20}, runs: 1, bursts: []int{1}, density: 2,
			wantActivation: 6, wantReleased: 6, wantDensity: 2 << 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			r := &Runner{Adapter: tc.fake, System: "s", Class: "c", Runs: tc.runs, Bursts: tc.bursts, Poll: time.Millisecond,
				Resume: tc.resume, Density: tc.density, Idle: time.Millisecond, Out: &out, Load: func() string { return "1 2 3" }}
			if err := r.Run(context.Background()); err != nil {
				t.Fatal(err)
			}
			recs := decode(t, out.Bytes())
			if got := count(recs, "setup", nil); got != 1 {
				t.Errorf("setup lines %d, want 1", got)
			}
			if got := count(recs, "run", nil); got != tc.runs+1 {
				t.Errorf("run lines %d, want %d", got, tc.runs+1)
			}
			if got := count(recs, "run", func(r Record) bool { return r.Cold }); got != 1 {
				t.Errorf("cold run lines %d, want 1", got)
			}
			if got := count(recs, "activation", nil); got != tc.wantActivation {
				t.Errorf("activation lines %d, want %d", got, tc.wantActivation)
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
