package kubernetes

import (
	"context"
	"time"
)

// What the external tests reach into.

var (
	PickResourceClaimVersion = pickResourceClaimVersion
	KubeDefaults             = kubeDefaults
	IsClaimNotFound          = isClaimNotFound
	WarmMessage              = warmMessage
	ZygoteCondition          = zygoteCondition
	ClaimNames               = claimNames
	PodIP                    = podIP
)

const (
	PodIPWait  = podIPWait
	PodIPRetry = podIPRetry
)

// Once runs one poll round now, as a tick would.
func (h *Home) Once(ctx context.Context) error { return h.poll.Once(ctx) }

// PendingLosses is how many scope-loss reasons wait for delivery.
func (h *Home) PendingLosses() int { return h.losses.Pending() }

// RunFetch runs the grant renewal alone until ctx ends, as Run does
// beside the polls.
func (h *Home) RunFetch(ctx context.Context) { h.fetch.run(ctx) }

// NewWithHook is New, handing built the home before the first grant
// fetch, so a test can Close it or end ctx while New retries.
func NewWithHook(ctx context.Context, cfg Config, built func(*Home)) (*Home, error) {
	return newHome(ctx, cfg, built)
}

// SetJitter fixes the home's jitter draw. Call it from the NewWithHook
// hook, before the first fetch.
func (h *Home) SetJitter(draw float64) { h.fetch.jitter = func() float64 { return draw } }

// SetSyncDir replaces how the home flushes the grants directory after a
// rename. Call it from the NewWithHook hook, before the first fetch.
func (h *Home) SetSyncDir(fn func(dir string) error) { h.fetch.syncDir = fn }

// DelayInput is nextDelay's input with its fields exported.
type DelayInput struct {
	Wrote         bool
	Status        int
	RetryAfter    time.Duration
	HasRetryAfter bool
	Failures      int
	Remaining     time.Duration
	Jitter        float64
}

// NextDelay is nextDelay over in.
func NextDelay(in DelayInput) time.Duration {
	return nextDelay(delayInput{
		wrote: in.Wrote, status: in.Status, retryAfter: in.RetryAfter, hasRetryAfter: in.HasRetryAfter,
		failures: in.Failures, remaining: in.Remaining, jitter: in.Jitter,
	})
}
