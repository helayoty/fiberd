package main

import "testing"

// TestRoundsOver checks when the storm stops sampling. It once stopped as
// soon as the demand was reached and gave the ladder two seconds, which a
// park in flight on a loaded CI runner missed (storm: FAIL no fiber was
// parked, with the agent's "shedding, reclaiming" line and no park after
// it).
func TestRoundsOver(t *testing.T) {
	cases := []struct {
		name    string
		allDone bool
		running uint32
		parked  bool
		want    bool
	}{
		{name: "fibers still dirtying, nothing parked", running: 8},
		{name: "fibers still dirtying, one parked", running: 7, parked: true},
		{name: "demand reached, nothing parked yet: keep sampling", allDone: true, running: 8},
		{name: "demand reached and a park showed", allDone: true, running: 7, parked: true, want: true},
		{name: "every fiber gone", allDone: true, parked: true, want: true},
		{name: "every fiber gone before the demand was reached", running: 0, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := roundsOver(tc.allDone, tc.running, tc.parked); got != tc.want {
				t.Fatalf("roundsOver(%v, %d, %v) = %v, want %v", tc.allDone, tc.running, tc.parked, got, tc.want)
			}
		})
	}
}
