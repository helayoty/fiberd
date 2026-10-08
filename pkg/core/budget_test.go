package core_test

import (
	"errors"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// TestBudgetTake checks the thrash budget's token bucket. A full bucket
// allows its burst and then refuses with ErrBudget until it refills. A
// zero rate refuses from the start. A non-positive refW has no curve, so
// the bucket refills at the flat base rate and still runs out.
func TestBudgetTake(t *testing.T) {
	cases := []struct {
		name   string
		base   float64
		refW   float64
		w      float64 // observed working set
		takes  int
		wantOK int
		refill bool // after the refusals, the bucket refills
	}{
		{name: "a full bucket allows its burst, then refuses", base: 3, refW: 256 << 20, takes: 4, wantOK: 3},
		{name: "a zero rate refuses from the start", base: 0, refW: 256 << 20, takes: 1},
		{name: "a zero refW still enforces the burst", base: 3, takes: 4, wantOK: 3},
		{name: "a zero refW with a working set still enforces the burst", base: 3, w: 1 << 20, takes: 4, wantOK: 3},
		{name: "a negative refW still enforces the burst", base: 3, refW: -1, takes: 4, wantOK: 3},
		{name: "a refused take succeeds again once the bucket refills", base: 100, refW: 256 << 20, w: 1 << 20, takes: 101, wantOK: 100, refill: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := core.NewBudget(tc.base, tc.refW)
			b.ObserveWorkingSet(tc.w)
			ok := 0
			for range tc.takes {
				err := b.Take()
				switch {
				case err == nil:
					ok++
				case !errors.Is(err, core.ErrBudget):
					t.Fatalf("Take = %v, want nil or ErrBudget", err)
				}
			}
			if ok != tc.wantOK {
				t.Fatalf("takes allowed = %d, want %d", ok, tc.wantOK)
			}
			if !tc.refill {
				return
			}
			deadline := time.Now().Add(5 * time.Second)
			for b.Take() != nil {
				if time.Now().After(deadline) {
					t.Fatal("the bucket never refilled")
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}
