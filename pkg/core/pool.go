package core

import (
	"context"
	"errors"
	"log"
	"time"
)

// Pooler is implemented by runtimes that restore sandboxes ahead of their
// fibers. Drain discards up to n, every one when n < 0. PooledExits names
// the grant of each pooled sandbox that dies before its hand-out.
type Pooler interface {
	Fill(ctx context.Context, g Grant, deadline time.Duration) error
	Drain(grantUID string, n int) int
	Pooled(grantUID string) int
	PooledExits() <-chan string
}

// A failed fill or a pooled death backs off, so a template that dies at
// restore cannot churn.
const (
	refillBackoffMin = 100 * time.Millisecond
	refillBackoffMax = 30 * time.Second
	// fillDeadlineFactor is how many create deadlines a fill gets. No
	// caller waits on a fill, and a short deadline on a busy home only
	// makes it fail and try again.
	fillDeadlineFactor = 4
)

// poolState is the refill loop's view of one grant.
type poolState struct {
	backoff time.Duration // the next wait after a failure, 0 after a success
	until   time.Time     // no fill before this
	noPool  bool          // the template cannot pool, so no fill is tried again
}

// delay holds the next fill for the next step of the backoff.
func (s *poolState) delay() {
	switch {
	case s.backoff == 0:
		s.backoff = refillBackoffMin
	case s.backoff < refillBackoffMax:
		s.backoff = min(s.backoff*2, refillBackoffMax)
	}
	s.until = time.Now().Add(s.backoff)
}

func (a *Agent) pooler() Pooler {
	p, _ := a.Runtime.(Pooler)
	return p
}

// poolState returns the grant's refill state, under poolMu.
func (a *Agent) poolState(grantUID string) *poolState {
	if a.pools == nil {
		a.pools = map[string]*poolState{}
	}
	st := a.pools[grantUID]
	if st == nil {
		st = &poolState{}
		a.pools[grantUID] = st
	}
	return st
}

// forgetPool drops a revoked grant's refill state, so a re-admission
// starts fresh.
func (a *Agent) forgetPool(grantUID string) {
	a.poolMu.Lock()
	delete(a.pools, grantUID)
	a.poolMu.Unlock()
}

// refillKicks is the channel that wakes the refill loop.
func (a *Agent) refillKicks() chan struct{} {
	a.poolMu.Lock()
	defer a.poolMu.Unlock()
	if a.refill == nil {
		a.refill = make(chan struct{}, 1)
	}
	return a.refill
}

// kickRefill wakes the refill loop. One kick waiting is enough.
func (a *Agent) kickRefill() {
	select {
	case a.refillKicks() <- struct{}{}:
	default:
	}
}

// syncPooled copies the runtime's pool count into the ledger, where
// Watch reads it.
func (a *Agent) syncPooled(grantUID string) {
	p := a.pooler()
	if p == nil {
		return
	}
	if a.Ledger.SetPooled(grantUID, p.Pooled(grantUID)) {
		a.notify()
	}
}

// handedOut records that a Clone took a pooled sandbox.
func (a *Agent) handedOut(grantUID string) {
	a.syncPooled(grantUID)
	a.kickRefill()
}

// pooledDied holds the grant's next fill, since its template may be
// dying at restore.
func (a *Agent) pooledDied(grantUID string) {
	a.poolMu.Lock()
	st := a.poolState(grantUID)
	st.delay()
	wait := st.backoff
	a.poolMu.Unlock()
	log.Printf("pool: a pooled sandbox of grant %s died before hand-out, next fill in %s", grantUID, wait)
	a.syncPooled(grantUID)
}

// DrainPool discards up to n of the grant's pooled sandboxes and returns
// how many went. The pressure ladder calls it before it parks a fiber.
func (a *Agent) DrainPool(grantUID string, n int) int {
	p := a.pooler()
	if p == nil {
		return 0
	}
	went := p.Drain(grantUID, n)
	if went > 0 {
		a.syncPooled(grantUID)
	}
	return went
}

// refillPass starts one fill when none runs, for the first grant with
// room after the last one filled, so the grants take turns and the home
// restores one sandbox ahead at a time. It returns when the earliest
// held grant may be tried again, zero when none is held.
func (a *Agent) refillPass(ctx context.Context) time.Time {
	p := a.pooler()
	if p == nil {
		return time.Time{}
	}
	var next time.Time
	sts := a.Ledger.Statuses()
	// Statuses are sorted by uid, so the turn after the last filled grant
	// starts at the first uid above it.
	a.poolMu.Lock()
	last := a.lastFill
	a.poolMu.Unlock()
	start := 0
	for i, st := range sts {
		if st.GrantUID > last {
			start = i
			break
		}
	}
	for i := range sts {
		st := sts[(start+i)%len(sts)]
		g, ok := a.Ledger.Grant(st.GrantUID)
		if !ok || g.FiberWarm <= 0 {
			continue
		}
		a.syncPooled(g.UID)
		if a.Pressure != nil && a.Pressure.Shedding(g.UID) {
			continue
		}
		a.poolMu.Lock()
		ps := a.poolState(g.UID)
		if ps.noPool || a.filling {
			a.poolMu.Unlock()
			continue
		}
		if until := ps.until; time.Now().Before(until) {
			a.poolMu.Unlock()
			if next.IsZero() || until.Before(next) {
				next = until
			}
			continue
		}
		if a.Ledger.PoolRoom(g.UID) <= 0 {
			a.poolMu.Unlock()
			continue
		}
		if a.Budget != nil {
			if err := a.Budget.Take(); err != nil {
				ps.delay()
				until := ps.until
				a.poolMu.Unlock()
				if next.IsZero() || until.Before(next) {
					next = until
				}
				continue
			}
		}
		a.filling, a.lastFill = true, g.UID
		a.poolMu.Unlock()
		go a.fill(ctx, p, g)
	}
	return next
}

// fill restores one sandbox for the grant and settles the loop's state.
func (a *Agent) fill(ctx context.Context, p Pooler, g Grant) {
	create, _ := a.deadlines()
	deadline := fillDeadlineFactor * create
	fctx, cancel := context.WithTimeout(ctx, deadline)
	err := p.Fill(fctx, g, deadline)
	cancel()
	a.poolMu.Lock()
	a.filling = false
	// A revoked grant's state is gone, and a fill that outlived it settles nothing.
	if ps := a.pools[g.UID]; ps != nil {
		switch {
		case err == nil:
			ps.backoff = 0
		case errors.Is(err, ErrNoPool):
			ps.noPool = true
			log.Printf("pool: grant %s is not refilled: %v", g.UID, err)
		case errors.Is(err, ErrYielded):
			ps.delay()
			log.Printf("pool: fill for grant %s yielded to a clone, next in %s", g.UID, ps.backoff)
		default:
			ps.delay()
			log.Printf("pool: fill for grant %s failed, next in %s: %v", g.UID, ps.backoff, err)
		}
	}
	a.poolMu.Unlock()
	a.syncPooled(g.UID)
	a.kickRefill()
}
