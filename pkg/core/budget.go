package core

import (
	"errors"
	"sync"
	"time"
)

// ErrBudget is backpressure, not failure: a misbehaving router degrades one
// node, never the fleet. Routers translate it to 429 + Retry-After.
var ErrBudget = errors.New("budget: clone rate over f(W), retry later")

// Budget enforces and advertises the thrash budget: the maximum sustainable
// activation rate as a function of working-set size W. Density is stock;
// this is flow — the same measured quantity (dirtied working set) prices
// both churn and parking.
//
// Model (placeholder until the fork-storm rig produces the real curve):
//
//	rate(W) = base / (1 + W/refW)
//
// implemented as a token bucket refilled at rate(W).
type Budget struct {
	mu     sync.Mutex
	base   float64 // clones/sec at W → 0
	refW   float64 // working-set bytes at which rate halves
	w      float64 // current estimate of dirtied working set
	tokens float64
	burst  float64
	last   time.Time
}

func NewBudget(baseClonesPerSec, refWBytes float64) *Budget {
	return &Budget{
		base: baseClonesPerSec, refW: refWBytes,
		burst: baseClonesPerSec, tokens: baseClonesPerSec,
		last: time.Now(),
	}
}

// ObserveWorkingSet feeds the current W estimate (from park-delta sizes and
// PSI-adjacent stats). The advertised maxClonesPerSec in grant status is
// Rate() at the same instant.
func (b *Budget) ObserveWorkingSet(bytes float64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.w = bytes
}

func (b *Budget) rateLocked() float64 { return b.base / (1 + b.w/b.refW) }

// Rate is what grant.status advertises so routers and autoscalers can plan.
func (b *Budget) Rate() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.rateLocked()
}

// Take is called by the frontend before any work happens.
func (b *Budget) Take() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * b.rateLocked()
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.last = now
	if b.tokens < 1 {
		return ErrBudget
	}
	b.tokens--
	return nil
}
