package main

import (
	"testing"
	"time"
)

func TestParseLayout(t *testing.T) {
	cases := []struct {
		name, layout string
		n            int
		want         layout
		wantErr      bool
	}{
		{name: "shared: one process forks every worker", layout: "shared", n: 8, want: layout{name: "shared", procs: 1, forks: 8}},
		{name: "separate: a process per worker, none forks", layout: "separate", n: 8, want: layout{name: "separate", procs: 8}},
		{name: "shared at storm-grower's fork limit", layout: "shared", n: maxForks, want: layout{name: "shared", procs: 1, forks: maxForks}},
		{name: "shared past it", layout: "shared", n: maxForks + 1, wantErr: true},
		{name: "separate past it is fine", layout: "separate", n: maxForks + 1, want: layout{name: "separate", procs: maxForks + 1}},
		{name: "no workers", layout: "shared", n: 0, wantErr: true},
		{name: "an unknown layout", layout: "fibers", n: 8, wantErr: true},
		{name: "case matters", layout: "Shared", n: 8, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseLayout(tc.layout, tc.n)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseLayout(%q, %d) error = %v, want error %v", tc.layout, tc.n, err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("parseLayout(%q, %d) = %+v, want %+v", tc.layout, tc.n, got, tc.want)
			}
		})
	}
}

func TestWorkersOf(t *testing.T) {
	cases := []struct {
		name string
		l    layout
		want int
	}{
		{name: "the shared parent serves all of its forks", l: layout{name: "shared", procs: 1, forks: 8}, want: 8},
		{name: "a separate process is its one worker", l: layout{name: "separate", procs: 8}, want: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.l.workersOf(); got != tc.want {
				t.Fatalf("workersOf = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestTally pins the kill accounting of the baseline's summary line.
func TestTally(t *testing.T) {
	growth := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	at := growth.Add
	var alive time.Time
	cases := []struct {
		name         string
		t            tally
		survivors    int
		killedBefore int
		firstKill    string
	}{
		{name: "nothing killed",
			t:         tally{growth: growth, deaths: []time.Time{alive, alive, alive}},
			survivors: 3, firstKill: "none"},
		{name: "kills during growth, the earliest first",
			t:         tally{growth: growth, deaths: []time.Time{at(3 * time.Second), alive, at(2100 * time.Millisecond)}, firstOOM: at(2200 * time.Millisecond)},
			survivors: 1, firstKill: "2.1s"},
		{name: "the counter rose before any worker went: the shared parent killed",
			t:         tally{growth: growth, deaths: []time.Time{alive, at(4 * time.Second)}, firstOOM: at(1500 * time.Millisecond)},
			survivors: 1, firstKill: "1.5s"},
		{name: "separate heaps that do not fit: kills before growth",
			t:         tally{growth: growth, deaths: []time.Time{at(-time.Second), alive, at(-500 * time.Millisecond), at(time.Second)}, firstOOM: at(-2 * time.Second)},
			survivors: 1, killedBefore: 2, firstKill: "before-growth"},
		{name: "every worker killed before growth began",
			t:            tally{deaths: []time.Time{growth, growth}},
			killedBefore: 2, firstKill: "before-growth"},
		{name: "a kill exactly at growth counts as during growth",
			t:         tally{growth: growth, deaths: []time.Time{growth}},
			firstKill: "0s"},
		// The CI run of PR 46: one OOM kill, every worker alive. The parent
		// died first, and storm sees that before the next round's counter.
		{name: "the shared parent killed, no worker",
			t:         tally{growth: growth, deaths: []time.Time{alive, alive}, parentDied: at(13400 * time.Millisecond), firstOOM: at(13600 * time.Millisecond)},
			survivors: 2, firstKill: "13.4s"},
		{name: "a worker before the parent",
			t:         tally{growth: growth, deaths: []time.Time{at(5 * time.Second), alive}, parentDied: at(6 * time.Second)},
			survivors: 1, firstKill: "5s"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.t.survivors(); got != tc.survivors {
				t.Errorf("survivors = %d, want %d", got, tc.survivors)
			}
			if got := tc.t.killedBeforeGrowth(); got != tc.killedBefore {
				t.Errorf("killedBeforeGrowth = %d, want %d", got, tc.killedBefore)
			}
			if got := since(tc.t.firstKill(), tc.t.growth).String(); got != tc.firstKill {
				t.Errorf("first kill = %q, want %q", got, tc.firstKill)
			}
		})
	}
}

// TestParentOutcome pins parent_killed, which says whether the shared
// layout's one OOM kill took the parent rather than a worker.
func TestParentOutcome(t *testing.T) {
	cases := []struct {
		name           string
		layout         string
		ended, sigkill bool
		want           string
	}{
		{name: "shared, the parent alive", layout: "shared", want: "no"},
		{name: "shared, the parent killed", layout: "shared", ended: true, sigkill: true, want: "yes"},
		{name: "shared, the parent ended some other way", layout: "shared", ended: true, want: "exited"},
		{name: "separate has no parent", layout: "separate", want: "n/a"},
		{name: "separate has no parent, even when its first process died", layout: "separate", ended: true, sigkill: true, want: "n/a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parentOutcome(tc.layout, tc.ended, tc.sigkill); got != tc.want {
				t.Fatalf("parentOutcome(%q, %v, %v) = %q, want %q", tc.layout, tc.ended, tc.sigkill, got, tc.want)
			}
		})
	}
}
