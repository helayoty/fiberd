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
		seen    bool // a status from the agent has arrived
		parked  bool
		want    bool
	}{
		{name: "fibers still dirtying, nothing parked", running: 8, seen: true},
		{name: "fibers still dirtying, one parked", running: 7, seen: true, parked: true},
		{name: "demand reached, nothing parked yet: keep sampling", allDone: true, running: 8, seen: true},
		{name: "demand reached and a park showed", allDone: true, running: 7, seen: true, parked: true, want: true},
		{name: "every fiber gone", allDone: true, seen: true, parked: true, want: true},
		{name: "every fiber gone before the demand was reached", running: 0, seen: true, want: true},
		// The Watch stream's first status can come after the first round.
		{name: "no status yet: running 0 is not every fiber gone", running: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := roundsOver(tc.allDone, tc.running, tc.seen, tc.parked); got != tc.want {
				t.Fatalf("roundsOver(%v, %d, %v, %v) = %v, want %v", tc.allDone, tc.running, tc.seen, tc.parked, got, tc.want)
			}
		})
	}
}
