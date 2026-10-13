package core

import (
	"errors"
	"sync"
	"time"
)

// ErrRateLimit is backpressure, not failure. A misbehaving router degrades one
// node, never the fleet. Routers translate it to 429 + Retry-After.
var ErrRateLimit = errors.New("rate limit: clone rate over f(W), retry later")

// fiberd's clone rate limit is DefaultBaseRate clones/sec at W -> 0. It
// halves at DefaultRefW bytes of working set.
const (
	DefaultBaseRate = 200
	DefaultRefW     = 256 << 20
)

// RateLimit enforces the clone rate limit, the maximum sustainable activation
// rate as a function of working-set size W. Density is stock and this is
// flow. The same measured quantity, the dirtied working set, prices both
// churn and parking.
//
// Model (placeholder until the fork-storm rig produces the real curve):
//
//	rate(W) = base / (1 + W/refW)
//
// implemented as a token bucket refilled at rate(W).
type RateLimit struct {
	mu     sync.Mutex
	base   float64 // clones/sec at W → 0
	refW   float64 // working-set bytes at which rate halves
	w      float64 // current estimate of dirtied working set
	tokens float64
	burst  float64
	last   time.Time
}

func NewRateLimit(baseClonesPerSec, refWBytes float64) *RateLimit {
	return &RateLimit{
		base: baseClonesPerSec, refW: refWBytes,
		burst: baseClonesPerSec, tokens: baseClonesPerSec,
		last: time.Now(),
	}
}

// ObserveWorkingSet feeds the current W estimate (from park-delta sizes and
// PSI-adjacent stats).
func (b *RateLimit) ObserveWorkingSet(bytes float64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.w = bytes
}

func (b *RateLimit) rateLocked() float64 {
	// refW is the working-set scale at which rate halves; a non-positive refW
	// has no meaningful curve (and w/refW would divide by zero → +Inf, or 0/0
	// → NaN). Degrade to the flat base rate rather than poison the token math.
	if b.refW <= 0 {
		return b.base
	}
	return b.base / (1 + b.w/b.refW)
}

// Take is called by the frontend before any work happens.
func (b *RateLimit) Take() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * b.rateLocked()
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.last = now
	if b.tokens < 1 {
		return ErrRateLimit
	}
	b.tokens--
	return nil
}
