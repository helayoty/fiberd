package home_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	testingclock "k8s.io/utils/clock/testing"

	"github.com/Azure/fiberd/pkg/core"
	"github.com/Azure/fiberd/pkg/home"
)

const pollEvery = time.Second

// transitions records what a HealthPoll reported.
type transitions struct {
	mu        sync.Mutex
	errs      []string
	recovered int
}

func (tr *transitions) onError(err error) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.errs = append(tr.errs, err.Error())
}

func (tr *transitions) onRecovered() {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.recovered++
}

// staleHealth is a health that is unhealthy until something marks it.
func staleHealth(now time.Time) *core.SourceHealth {
	stale := 10 * time.Second
	return core.NewSourceHealth(stale, now.Add(-2*stale))
}

// TestHealthPollMarks checks when an answered round reaches the health,
// and what a round's own error is reported as.
func TestHealthPollMarks(t *testing.T) {
	noRoute := errors.New("no route")
	cases := []struct {
		name   string
		paused bool
		// round is what the poll's Round does, given the poll and its clock.
		round       func(p *home.HealthPoll, fc *testingclock.FakeClock) error
		wantErr     error
		wantHealthy bool
	}{
		{name: "an answered round marks the health", wantHealthy: true},
		{name: "a paused poll leaves the health alone", paused: true},
		{name: "a failed round leaves the health alone",
			round: func(*home.HealthPoll, *testingclock.FakeClock) error { return noRoute }, wantErr: noRoute},
		{name: "a pause between the answer and the mark leaves the health alone",
			round: func(p *home.HealthPoll, _ *testingclock.FakeClock) error { p.SetPaused(true); return nil }},
		{name: "a round's own error as the interval runs out is kept",
			round: func(_ *home.HealthPoll, fc *testingclock.FakeClock) error { fc.Step(pollEvery); return noRoute }, wantErr: noRoute},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
			fc := testingclock.NewFakeClock(now)
			health := staleHealth(now)
			if health.Healthy(now) {
				t.Fatal("the health starts healthy")
			}
			p := &home.HealthPoll{Health: health, Every: pollEvery, Clock: fc}
			p.Round = func(context.Context) error {
				if c.round == nil {
					return nil
				}
				return c.round(p, fc)
			}
			p.SetPaused(c.paused)
			err := p.Once(context.Background())
			if !errors.Is(err, c.wantErr) || (err != nil && errors.Is(err, home.ErrRoundTimeout)) {
				t.Fatalf("Once = %v, want %v", err, c.wantErr)
			}
			if got := health.Healthy(fc.Now()); got != c.wantHealthy {
				t.Fatalf("healthy = %v, want %v", got, c.wantHealthy)
			}
		})
	}
}

// TestHealthPollTransitions checks that an error is reported once per
// distinct message and a recovery once per run of errors.
func TestHealthPollTransitions(t *testing.T) {
	e1, e2 := errors.New("forbidden"), errors.New("timeout")
	cases := []struct {
		name          string
		rounds        []error
		wantErrs      []string
		wantRecovered int
	}{
		{name: "answers only report nothing", rounds: []error{nil, nil}},
		{name: "the same error is reported once", rounds: []error{e1, e1, e1}, wantErrs: []string{"forbidden"}},
		{name: "a different message is reported again", rounds: []error{e1, e2, e1}, wantErrs: []string{"forbidden", "timeout", "forbidden"}},
		{name: "answering again after errors is reported once", rounds: []error{e1, nil, nil}, wantErrs: []string{"forbidden"}, wantRecovered: 1},
		{name: "each run of errors gets its own recovery", rounds: []error{e1, nil, e1, nil}, wantErrs: []string{"forbidden", "forbidden"}, wantRecovered: 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
			fc := testingclock.NewFakeClock(now)
			var tr transitions
			i := 0
			p := &home.HealthPoll{Health: staleHealth(now), Every: pollEvery, Clock: fc,
				Round: func(context.Context) error {
					err := c.rounds[i]
					i++
					return err
				},
				OnError: tr.onError, OnRecovered: tr.onRecovered}
			for range c.rounds {
				_ = p.Once(context.Background())
			}
			if !slices.Equal(tr.errs, c.wantErrs) {
				t.Fatalf("errors reported %v, want %v", tr.errs, c.wantErrs)
			}
			if tr.recovered != c.wantRecovered {
				t.Fatalf("recovered %d times, want %d", tr.recovered, c.wantRecovered)
			}
		})
	}
}

// TestHealthPollRun drives Run with the fake clock: a round at once, one
// more per tick, and a round that does not answer is cut off after one
// interval.
func TestHealthPollRun(t *testing.T) {
	cases := []struct {
		name string
		hang bool
		// wantRounds after one tick, wantErr what the tick reports.
		wantRounds int
		wantErr    error
	}{
		{name: "a round runs at once and one per tick", wantRounds: 2},
		{name: "a round that does not answer is cut off after one interval", hang: true, wantRounds: 1, wantErr: home.ErrRoundTimeout},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
			fc := testingclock.NewFakeClock(now)
			rounds := make(chan struct{}, 8)
			errs := make(chan error, 8)
			var ran atomic.Int32
			p := &home.HealthPoll{Health: staleHealth(now), Every: pollEvery, Clock: fc,
				Round: func(ctx context.Context) error {
					ran.Add(1)
					rounds <- struct{}{}
					if c.hang {
						<-ctx.Done()
						return ctx.Err()
					}
					return nil
				},
				OnError: func(err error) { errs <- err }}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() { defer close(done); p.Run(ctx) }()

			waitRound := func() {
				t.Helper()
				select {
				case <-rounds:
				case <-time.After(10 * time.Second):
					t.Fatal("no round ran")
				}
			}
			waitRound()
			// The ticker waits from before the first round. A hanging round
			// adds its timeout timer, so the tick cuts it off too.
			want := 1
			if c.hang {
				want = 2
			}
			for fc.Waiters() < want {
				time.Sleep(time.Millisecond)
			}
			fc.Step(pollEvery)
			waitRound()
			if c.wantErr != nil {
				select {
				case err := <-errs:
					if !errors.Is(err, c.wantErr) {
						t.Fatalf("reported %v, want %v", err, c.wantErr)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("the cut-off round was not reported")
				}
			}
			cancel()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("Run did not return after its context ended")
			}
			if n := int(ran.Load()); n < c.wantRounds {
				t.Fatalf("rounds %d, want at least %d", n, c.wantRounds)
			}
			if len(errs) > 0 && c.wantErr == nil {
				t.Fatalf("an answered round reported %v", <-errs)
			}
		})
	}
}
