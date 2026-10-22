package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// perInstance is each instance's share of the aggregate demand,
// overcommit times the ceiling. Fibers and plain processes get the same.
func perInstance(ceiling uint64, overcommit float64, n int) uint64 {
	if n <= 0 {
		return 0
	}
	return uint64(float64(ceiling) * overcommit / float64(n))
}

// nextStep is one round's growth for one instance: dirtied plus step,
// while dirtied is still under its share. The last step may overshoot a
// share that is not a multiple of step, the same on both sides.
func nextStep(dirtied, share, step uint64) (uint64, bool) {
	if dirtied >= share {
		return dirtied, false
	}
	return dirtied + step, true
}

// rise is how far a counter went up from before. A read that failed
// (0) is no rise.
func rise(after, before uint64) uint64 {
	if after < before {
		return 0
	}
	return after - before
}

// moment is a time on the storm's clock, from the start of growth.
type moment struct {
	at    time.Duration
	seen  bool
	early bool // before growth began
}

func (m moment) String() string {
	switch {
	case !m.seen:
		return "none"
	case m.early:
		return "before-growth"
	}
	return m.at.Round(100 * time.Millisecond).String()
}

// since places t on the clock that started at growth. A zero t was
// never seen. A zero growth means growth never began, so every t is
// before it.
func since(t, growth time.Time) moment {
	switch {
	case t.IsZero():
		return moment{}
	case growth.IsZero() || t.Before(growth):
		return moment{seen: true, early: true}
	}
	return moment{at: t.Sub(growth), seen: true}
}

// summary is one side of the storm in one line, the record
// docs/benchmarks.md copies. Every side prints every field, so the lines
// line up.
type summary struct {
	side, layout       string // fiberd and fibers, or plain and shared or separate
	n                  int    // fibers or processes
	demand             uint64 // the aggregate demand, overcommit times the ceiling
	oomKills           uint64 // the OOM counter's rise over the run
	survivors          int    // still running or parked at the end
	parked             int
	firstPark          moment
	firstKill          moment
	killedBeforeGrowth int
	parentKilled       string // the shared layout's parent: yes, no or exited. n/a elsewhere
	kernel             string
}

func (s summary) String() string {
	return fmt.Sprintf("storm summary: side=%s layout=%s n=%d demand=%dMiB oom_kills=%d survivors=%d parked=%d first_park=%s first_kill=%s killed_before_growth=%d parent_killed=%s kernel=%s",
		s.side, s.layout, s.n, s.demand>>20, s.oomKills, s.survivors, s.parked, s.firstPark, s.firstKill, s.killedBeforeGrowth,
		orElse(s.parentKilled, "n/a"), orElse(s.kernel, "unknown"))
}

func orElse(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

// osReleasePath is where Linux names its kernel release.
const osReleasePath = "/proc/sys/kernel/osrelease"

// kernelRelease is the kernel the storm ran on, for the record. One
// word, so the summary line stays key=value. "unknown" when unreadable.
func kernelRelease(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	return orElse(strings.Join(strings.Fields(string(b)), "_"), "unknown")
}
