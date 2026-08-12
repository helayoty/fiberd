package core

import (
	"sync/atomic"
	"time"
)

// SourceHealth tracks liveness of the async grant lane. Core-owned so the
// staleness rule is identical under every adapter; adapters only MarkSync.
type SourceHealth struct {
	stale    time.Duration // unhealthy past this; default: lease TTL
	recover  time.Duration // healthy again only under this; e.g. stale/2 (hysteresis)
	lastSync atomic.Int64  // unix nanos of last successful sync
	degraded atomic.Bool
}

// NewSourceHealth: stale should default to the grant lease TTL — the same
// horizon that already bounds revocation. recover < stale gives hysteresis.
func NewSourceHealth(stale time.Duration, now time.Time) *SourceHealth {
	h := &SourceHealth{
		stale:   stale,
		recover: stale / 2,
	}
	h.lastSync.Store(now.UnixNano()) // boot counts as a sync: fail toward healthy at start
	return h
}

func (h *SourceHealth) MarkSync(now time.Time) { h.lastSync.Store(now.UnixNano()) }

func (h *SourceHealth) Healthy(now time.Time) bool {
	age := now.Sub(time.Unix(0, h.lastSync.Load()))
	switch {
	case age >= h.stale:
		h.degraded.Store(true)
	case age < h.recover:
		h.degraded.Store(false)
	}
	return !h.degraded.Load()
}
