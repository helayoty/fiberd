package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPerInstance(t *testing.T) {
	cases := []struct {
		name       string
		ceiling    uint64
		overcommit float64
		n          int
		want       uint64
	}{
		{name: "the storm's numbers: 2x of 160 MiB over 8", ceiling: 160 << 20, overcommit: 2, n: 8, want: 40 << 20},
		{name: "1x", ceiling: 160 << 20, overcommit: 1, n: 8, want: 20 << 20},
		{name: "one instance takes it all", ceiling: 160 << 20, overcommit: 2, n: 1, want: 320 << 20},
		{name: "no instances", ceiling: 160 << 20, overcommit: 2, n: 0, want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := perInstance(tc.ceiling, tc.overcommit, tc.n); got != tc.want {
				t.Fatalf("perInstance(%d, %v, %d) = %d, want %d", tc.ceiling, tc.overcommit, tc.n, got, tc.want)
			}
		})
	}
}

// TestNextStep pins the growth both sides share: the plain baseline
// must step exactly as the fiberd storm always has.
func TestNextStep(t *testing.T) {
	cases := []struct {
		name                 string
		dirtied, share, step uint64
		want                 uint64
		wantOK               bool
	}{
		{name: "the first step", dirtied: 0, share: 40 << 20, step: 2 << 20, want: 2 << 20, wantOK: true},
		{name: "the last step lands on the share", dirtied: 38 << 20, share: 40 << 20, step: 2 << 20, want: 40 << 20, wantOK: true},
		{name: "the share reached: no more", dirtied: 40 << 20, share: 40 << 20, step: 2 << 20, want: 40 << 20},
		{name: "a share not a multiple of step overshoots once", dirtied: 4 << 20, share: 5 << 20, step: 2 << 20, want: 6 << 20, wantOK: true},
		{name: "past the share: no more", dirtied: 6 << 20, share: 5 << 20, step: 2 << 20, want: 6 << 20},
		{name: "a zero share never grows", share: 0, step: 2 << 20, want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := nextStep(tc.dirtied, tc.share, tc.step)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("nextStep(%d, %d, %d) = %d, %v, want %d, %v", tc.dirtied, tc.share, tc.step, got, ok, tc.want, tc.wantOK)
			}
		})
	}
	// 20 steps of 2 MiB reach the storm's 40 MiB share, on either side.
	var d uint64
	steps := 0
	for {
		next, ok := nextStep(d, 40<<20, 2<<20)
		if !ok {
			break
		}
		d, steps = next, steps+1
	}
	if steps != 20 || d != 40<<20 {
		t.Fatalf("the storm's share took %d steps to %d bytes, want 20 to %d", steps, d, 40<<20)
	}
}

func TestRise(t *testing.T) {
	cases := []struct {
		name          string
		after, before uint64
		want          uint64
	}{
		{name: "no kills", after: 3, before: 3, want: 0},
		{name: "two kills", after: 5, before: 3, want: 2},
		{name: "a failed read after is no rise", after: 0, before: 3, want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rise(tc.after, tc.before); got != tc.want {
				t.Fatalf("rise(%d, %d) = %d, want %d", tc.after, tc.before, got, tc.want)
			}
		})
	}
}

func TestSince(t *testing.T) {
	growth := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name      string
		at, start time.Time
		want      string
	}{
		{name: "never seen", start: growth, want: "none"},
		{name: "at growth", at: growth, start: growth, want: "0s"},
		{name: "rounded to 100 ms", at: growth.Add(2340 * time.Millisecond), start: growth, want: "2.3s"},
		{name: "over a minute", at: growth.Add(65 * time.Second), start: growth, want: "1m5s"},
		{name: "before growth", at: growth.Add(-time.Second), start: growth, want: "before-growth"},
		{name: "growth never began", at: growth, want: "before-growth"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := since(tc.at, tc.start).String(); got != tc.want {
				t.Fatalf("since = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSummaryLine pins the record's format, which docs/benchmarks.md and
// the demo's generator read. Change it only with them.
func TestSummaryLine(t *testing.T) {
	cases := []struct {
		name string
		s    summary
		want string
	}{
		{name: "the fiberd side",
			s: summary{side: "fiberd", layout: "fibers", n: 8, demand: 320 << 20, survivors: 8, parked: 3,
				firstPark: moment{at: 4200 * time.Millisecond, seen: true}, parentKilled: "n/a", kernel: "6.17.0-1010-azure"},
			want: "storm summary: side=fiberd layout=fibers n=8 demand=320MiB oom_kills=0 survivors=8 parked=3 first_park=4.2s first_kill=none killed_before_growth=0 parent_killed=n/a kernel=6.17.0-1010-azure"},
		{name: "the shared baseline, its one kill the parent",
			s: summary{side: "plain", layout: "shared", n: 8, demand: 320 << 20, oomKills: 1, survivors: 8,
				firstKill: moment{at: 13400 * time.Millisecond, seen: true}, parentKilled: "yes", kernel: "6.17.0-1010-azure"},
			want: "storm summary: side=plain layout=shared n=8 demand=320MiB oom_kills=1 survivors=8 parked=0 first_park=none first_kill=13.4s killed_before_growth=0 parent_killed=yes kernel=6.17.0-1010-azure"},
		{name: "the separate baseline, killed before growth",
			s: summary{side: "plain", layout: "separate", n: 8, demand: 320 << 20, oomKills: 4, survivors: 4,
				firstKill: moment{seen: true, early: true}, killedBeforeGrowth: 3, parentKilled: "n/a", kernel: "6.17.0-1010-azure"},
			want: "storm summary: side=plain layout=separate n=8 demand=320MiB oom_kills=4 survivors=4 parked=0 first_park=none first_kill=before-growth killed_before_growth=3 parent_killed=n/a kernel=6.17.0-1010-azure"},
		{name: "unset parent and kernel still print a value",
			s:    summary{side: "plain", layout: "shared", n: 8, demand: 320 << 20, survivors: 8},
			want: "storm summary: side=plain layout=shared n=8 demand=320MiB oom_kills=0 survivors=8 parked=0 first_park=none first_kill=none killed_before_growth=0 parent_killed=n/a kernel=unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.String(); got != tc.want {
				t.Fatalf("summary =\n%s\nwant\n%s", got, tc.want)
			}
		})
	}
}

func TestKernelRelease(t *testing.T) {
	cases := []struct {
		name    string
		content *string // nil: no file
		want    string
	}{
		{name: "a release with its newline", content: ptr("6.17.0-1010-azure\n"), want: "6.17.0-1010-azure"},
		{name: "linuxkit", content: ptr("6.12.54-linuxkit\n"), want: "6.12.54-linuxkit"},
		{name: "spaces become underscores, so the line stays key=value", content: ptr("6.1 custom build\n"), want: "6.1_custom_build"},
		{name: "an empty file", content: ptr(""), want: "unknown"},
		{name: "only whitespace", content: ptr(" \n"), want: "unknown"},
		{name: "no file, as on macOS", want: "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "osrelease")
			if tc.content != nil {
				if err := os.WriteFile(path, []byte(*tc.content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if got := kernelRelease(path); got != tc.want {
				t.Fatalf("kernelRelease = %q, want %q", got, tc.want)
			}
		})
	}
}

func ptr(s string) *string { return &s }
