package core

import (
	"context"
	"errors"
	"log"
	"sort"
	"sync"
	"time"
)

// PressureSource reports memory pressure for a grant as PSI "some avg10"
// in percent: the share of the last ten seconds in which at least one
// task in the grant's cgroup was stalled on memory. The runtime supplies
// it; the core never reads a kernel file.
type PressureSource interface {
	Pressure(grantUID string) (someAvg10 float64, err error)
}

// MaxPressure combines several sources into the ladder's one input: the
// highest reading wins, so kernel PSI on the grant's cgroup and the
// engine's device occupancy (used over capacity, in percent) drive the
// same rungs. A source that errors is skipped; all erroring is an error.
type MaxPressure []PressureSource

func (m MaxPressure) Pressure(grantUID string) (float64, error) {
	var best float64
	var lastErr error
	got := false
	for _, s := range m {
		v, err := s.Pressure(grantUID)
		if err != nil {
			lastErr = err
			continue
		}
		got = true
		if v > best {
			best = v
		}
	}
	if !got {
		if lastErr == nil {
			lastErr = errors.New("pressure: no source")
		}
		return 0, lastErr
	}
	return best, nil
}

// FiberInfo is what the ladder needs to pick a victim.
type FiberInfo struct {
	ID      string
	Session string // "" for anonymous
	WUsed   uint64
}

// Default watermarks, in PSI percent, used when a grant's policy leaves
// them zero. They are deliberately low: the point is to react before the
// home's own eviction (kubelet's memory.available, a hard memory.max)
// does, because the ladder can park state and eviction cannot.
const (
	DefaultPSIShed = 10.0
	DefaultPSIPark = 25.0
	// yieldAfter is how many consecutive ticks at or above the park
	// watermark with nothing left to park or release before the grant is
	// yielded.
	yieldAfter = 3
)

var ErrPressure = errors.New("pressure: grant is shedding new clones")

// PressureController is the two-input, one-ladder controller from the
// design, reduced to its first input (kernel PSI; the device ledger input
// arrives with the GPU work). Cheapest reaction first:
//
//	shed    refuse new clones for the grant (Clone consults Shedding)
//	park    checkpoint the running named session with the largest W
//	release kill the anonymous fiber with the largest W
//	yield   nothing left to reclaim and pressure persists: take the grant
//
// Park and Release are the agent's own verbs so every rung writes its
// audit record; Yield revokes the grant.
type PressureController struct {
	Ledger   *Ledger
	Source   PressureSource
	Interval time.Duration
	Park     func(ctx context.Context, fiberID string) error
	Release  func(ctx context.Context, fiberID string) error
	Yield    func(ctx context.Context, grantUID string)

	mu       sync.Mutex
	shedding map[string]bool
	stuck    map[string]int // consecutive ticks over park with no victim
}

// Shedding is the predicate Clone consults.
func (c *PressureController) Shedding(grantUID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.shedding[grantUID]
}

func (c *PressureController) setShedding(grantUID string, v bool) (changed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.shedding == nil {
		c.shedding = map[string]bool{}
	}
	if c.shedding[grantUID] == v {
		return false
	}
	c.shedding[grantUID] = v
	return true
}

// Run evaluates every admitted grant each Interval until ctx ends.
func (c *PressureController) Run(ctx context.Context) {
	interval := c.Interval
	if interval <= 0 {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.Tick(ctx)
		}
	}
}

// Tick runs one evaluation. Exported so tests drive it deterministically.
func (c *PressureController) Tick(ctx context.Context) {
	for _, st := range c.Ledger.Statuses() {
		g, ok := c.Ledger.Grant(st.GrantUID)
		if !ok {
			continue
		}
		psi, err := c.Source.Pressure(g.UID)
		if err != nil {
			continue
		}
		c.evaluate(ctx, g, psi)
	}
}

func (c *PressureController) watermarks(g Grant) (shed, park float64) {
	shed, park = g.Policy.PSISomeAvg10Shed, g.Policy.PSISomeAvg10Park
	if shed <= 0 {
		shed = DefaultPSIShed
	}
	if park <= 0 {
		park = DefaultPSIPark
	}
	if park < shed {
		park = shed
	}
	return shed, park
}

func (c *PressureController) evaluate(ctx context.Context, g Grant, psi float64) {
	shed, park := c.watermarks(g)
	switch {
	case psi >= park:
		if c.setShedding(g.UID, true) {
			log.Printf("pressure: grant %s psi=%.1f >= park %.1f: shedding, reclaiming", g.UID, psi, park)
		}
		if c.reclaim(ctx, g.UID) {
			c.resetStuck(g.UID)
			return
		}
		if c.bumpStuck(g.UID) >= yieldAfter && c.Yield != nil {
			log.Printf("pressure: grant %s psi=%.1f persists with nothing to reclaim: yield", g.UID, psi)
			c.resetStuck(g.UID)
			c.Yield(ctx, g.UID)
		}
	case psi >= shed:
		c.resetStuck(g.UID)
		if c.setShedding(g.UID, true) {
			log.Printf("pressure: grant %s psi=%.1f >= shed %.1f: shedding new clones", g.UID, psi, shed)
		}
	default:
		c.resetStuck(g.UID)
		if c.setShedding(g.UID, false) {
			log.Printf("pressure: grant %s psi=%.1f: clear", g.UID, psi)
		}
	}
}

// reclaim performs one park-or-release step, largest W first. Named
// sessions are parked (their state is worth keeping); if the runtime
// cannot park, they are released like anonymous fibers. Returns whether a
// victim was found.
func (c *PressureController) reclaim(ctx context.Context, grantUID string) bool {
	fibers := c.Ledger.FibersOf(grantUID)
	if len(fibers) == 0 {
		return false
	}
	sort.Slice(fibers, func(i, j int) bool {
		// Named before anonymous at equal W? No: largest W first, the
		// cheapest reclaim per byte; the verb differs by kind.
		return fibers[i].WUsed > fibers[j].WUsed
	})
	v := fibers[0]
	if v.Session != "" && c.Park != nil {
		if err := c.Park(ctx, v.ID); err == nil {
			log.Printf("pressure: parked %s (session %s, W=%d)", v.ID, v.Session, v.WUsed)
			return true
		}
	}
	if c.Release != nil {
		if err := c.Release(ctx, v.ID); err == nil {
			log.Printf("pressure: released %s (W=%d)", v.ID, v.WUsed)
			return true
		}
	}
	return false
}

func (c *PressureController) bumpStuck(uid string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stuck == nil {
		c.stuck = map[string]int{}
	}
	c.stuck[uid]++
	return c.stuck[uid]
}

func (c *PressureController) resetStuck(uid string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.stuck, uid)
}
