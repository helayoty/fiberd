package home

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"k8s.io/utils/clock"

	"github.com/Azure/fiberd/pkg/core"
)

// ErrRoundTimeout is the error a poll round reports when it did not
// answer within one interval.
var ErrRoundTimeout = errors.New("poll round timed out")

// HealthPoll runs a round against a home's control plane every interval
// and turns the answers into the issuer health the miss codes key on. A
// round that answers marks the health sync at the clock's now, unless the
// poll is paused. A round that fails leaves the health alone, so the
// health goes stale on its own once the control plane has been silent
// for the stale TTL.
//
// Run is serial. One round runs at a time, and the next waits for it. A
// round gets one interval to answer, then its context ends with
// ErrRoundTimeout as the cause. A Round that honours its context returns
// the context's error, and the poll reports it as ErrRoundTimeout. A
// Round that ignores its context delays the next round for as long as it
// runs. An error of the Round's own is reported as it is, even when the
// interval ran out while it was being returned.
//
// The poll does not log. OnError is called once per distinct error
// message, OnRecovered once when a round answers after errors, so a home
// logs each transition once.
type HealthPoll struct {
	// Health is marked on every answered round. Required.
	Health *core.SourceHealth
	// Every is the interval between rounds and the timeout of one round.
	Every time.Duration
	// Clock drives the rounds and stamps the health. Required.
	Clock clock.WithTicker
	// Round asks the control plane once. Required.
	Round func(ctx context.Context) error
	// OnError and OnRecovered report transitions. Either may be nil.
	OnError     func(err error)
	OnRecovered func()

	// mu guards paused and lastErr. An answered round reads paused and
	// marks the health under it, so a pause and the mark never interleave.
	mu      sync.Mutex
	paused  bool
	lastErr string
}

// SetPaused stops answered rounds from marking the health while paused.
// The rounds keep running, so error transitions are still reported. A
// pause waits for a mark in progress, so a health set right after the
// pause is not marked over by the round that answered just before it.
func (p *HealthPoll) SetPaused(paused bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.paused = paused
}

// Run runs a round at once, then one every interval, until ctx ends. It
// blocks. Run is called once.
func (p *HealthPoll) Run(ctx context.Context) {
	t := p.Clock.NewTicker(p.Every)
	defer t.Stop()
	for {
		// Once reports its error through OnError, so the loop has
		// nothing to add.
		_ = p.Once(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C():
		}
	}
}

// Once runs one round now and reports its error. Run calls it on every
// tick, and a test can call it directly.
func (p *HealthPoll) Once(ctx context.Context) error {
	err := p.round(ctx)

	p.mu.Lock()
	was := p.lastErr
	if err != nil {
		p.lastErr = err.Error()
	} else {
		p.lastErr = ""
		if !p.paused {
			p.Health.MarkSync(p.Clock.Now())
		}
	}
	p.mu.Unlock()

	switch {
	case err != nil:
		if err.Error() != was && p.OnError != nil {
			p.OnError(err)
		}
	case was != "":
		if p.OnRecovered != nil {
			p.OnRecovered()
		}
	}
	return err
}

// round runs Round under a context that ends after one interval. The
// timer comes from the clock, so a fake clock can time a round out. Only
// a Round that returned the context's own error is reported as a
// timeout. The timer may fire while a Round returns an error of its own,
// and that error is kept.
func (p *HealthPoll) round(ctx context.Context) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	timer := p.Clock.NewTimer(p.Every)
	defer timer.Stop()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-timer.C():
			cancel(ErrRoundTimeout)
		case <-done:
		}
	}()
	err := p.Round(ctx)
	if errors.Is(err, context.Canceled) && errors.Is(context.Cause(ctx), ErrRoundTimeout) {
		return fmt.Errorf("%w after %s", ErrRoundTimeout, p.Every)
	}
	return err
}
