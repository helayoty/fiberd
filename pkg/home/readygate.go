package home

import (
	"context"
	"slices"
	"sync"
)

// ReadyGate tracks which grants have a warm template and publishes the
// one readiness fact a control plane wants, "any template is warm", through
// Publish. Publish is called on the first PublishReady and whenever that
// fact flips. A failed publish leaves the published state as it was, so
// the next PublishReady or the next Republish sends it again.
//
// One publish is in flight at a time and no lock is held across it. A
// PublishReady that arrives while another is in flight records its change
// and returns, and the publisher in flight sends the newest state once its
// call returns. The control plane therefore sees states in the order they
// were decided, never an older state after a newer one.
//
// The gate does not log. Republish reports whether the outcome changed so
// the home logs each distinct failure, and the recovery, once.
type ReadyGate struct {
	// Publish sends the gate. warm holds the UIDs of the grants with a
	// warm template, sorted, and is empty when none has. Required.
	Publish func(ctx context.Context, warm []string) error

	mu        sync.Mutex
	warm      map[string]bool
	decided   bool // PublishReady was called at least once
	known     bool // published is what the control plane holds
	published bool
	inFlight  bool
	lastErr   string
}

// PublishReady records that grantUID's template is warm, or no longer
// is, and publishes the gate when that flips it. It returns the publish
// error, or nil when nothing had to be sent or another publish in flight
// will send it.
func (g *ReadyGate) PublishReady(ctx context.Context, grantUID string, ready bool) error {
	g.mu.Lock()
	if g.warm == nil {
		g.warm = map[string]bool{}
	}
	if ready {
		g.warm[grantUID] = true
	} else {
		delete(g.warm, grantUID)
	}
	g.decided = true
	g.mu.Unlock()
	_, err := g.flush(ctx)
	return err
}

// Republish sends the gate again when the last publish failed, or when
// the control plane has not been told yet. Before the first PublishReady
// there is nothing to republish. changed is true when the outcome differs
// from the last one, that is a new error message, or a success after a
// failure.
func (g *ReadyGate) Republish(ctx context.Context) (changed bool, err error) {
	g.mu.Lock()
	decided := g.decided
	g.mu.Unlock()
	if !decided {
		return false, nil
	}
	return g.flush(ctx)
}

// Ready reports whether any grant has a warm template.
func (g *ReadyGate) Ready() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.warm) > 0
}

// flush publishes until the published state matches the warm set, or a
// publish fails. It returns at once when a publish is already in flight,
// since that publisher re-checks the state before it returns.
func (g *ReadyGate) flush(ctx context.Context) (changed bool, err error) {
	for {
		g.mu.Lock()
		if g.inFlight {
			g.mu.Unlock()
			return changed, nil
		}
		warm := g.warmLocked()
		want := len(warm) > 0
		if g.known && g.published == want {
			g.mu.Unlock()
			return changed, nil
		}
		g.inFlight = true
		g.mu.Unlock()

		err := g.Publish(ctx, warm)

		g.mu.Lock()
		g.inFlight = false
		if err != nil {
			changed = err.Error() != g.lastErr
			g.lastErr = err.Error()
			g.mu.Unlock()
			return changed, err
		}
		g.known, g.published = true, want
		if g.lastErr != "" {
			changed = true
			g.lastErr = ""
		}
		g.mu.Unlock()
	}
}

func (g *ReadyGate) warmLocked() []string {
	warm := make([]string, 0, len(g.warm))
	for uid := range g.warm {
		warm = append(warm, uid)
	}
	slices.Sort(warm)
	return warm
}
