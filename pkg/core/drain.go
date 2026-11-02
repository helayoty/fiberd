package core

import (
	"context"
	"fmt"
	"log"
	"sync"
)

// drainWorkers is how many parks and releases a drain runs at once. A park
// is a checkpoint to disk and, on a publishing runtime, a registry push,
// so a few at a time keep the disk and the network busy without one
// session's push starving the rest of the timeout.
const drainWorkers = 4

// DrainReport is what a drain did with the fibers it found running.
type DrainReport struct {
	Parked    int // named sessions parked
	Published int // of those, the ones whose delta was published
	Shed      int // anonymous fibers released
	Failed    int // a park or release that returned an error, the fiber still running
	Left      int // fibers the drain did not reach before its context ended
}

func (r DrainReport) String() string {
	return fmt.Sprintf("parked=%d published=%d shed=%d failed=%d left=%d", r.Parked, r.Published, r.Shed, r.Failed, r.Left)
}

func (r *DrainReport) add(o DrainReport) {
	r.Parked += o.Parked
	r.Published += o.Published
	r.Shed += o.Shed
	r.Failed += o.Failed
	r.Left += o.Left
}

// Draining reports whether Drain has been called.
func (a *Core) Draining() bool { return a.draining.Load() }

// Drain readies the home to stop. From its first line every Clone, attach
// included, is a DeferredFallback miss with ErrDraining, and the refill
// loop starts nothing. A drain is final. Nothing clears it, since the
// home is about to stop.
//
// Then every running fiber is parked or ended, named sessions first, a
// few at a time. A named session is parked with sync, so its delta is
// durable and published before fiberd exits. An anonymous fiber has
// nothing to resume and is released. A fiber that is gone by the time
// the drain reaches it, parked by the pressure ladder or dead on its
// own, is skipped. Once ctx ends no more are started, and the rest count
// as Left. The calls under way carry ctx, so they end with it.
//
// The park and release records are the audit trail. The drain writes no
// record of its own.
func (a *Core) Drain(ctx context.Context) DrainReport {
	a.draining.Store(true)
	var rep DrainReport
	// A Clone that passed its draining check before the flag was set can
	// still commit a fiber after the first list, so the drain lists again
	// until a list holds only fibers it already tried.
	tried := map[string]bool{}
	for {
		batch := a.drainList(tried)
		if len(batch) == 0 {
			break
		}
		if ctx.Err() != nil {
			rep.Left += len(batch)
			break
		}
		rep.add(a.drainBatch(ctx, batch))
	}
	a.persist()
	a.notify()
	return rep
}

// drainList is every running fiber not in tried, named sessions first,
// and marks them tried.
func (a *Core) drainList(tried map[string]bool) []FiberInfo {
	var named, anon []FiberInfo
	for _, st := range a.Ledger.Statuses() {
		for _, f := range a.Ledger.FibersOf(st.GrantUID) {
			if tried[f.ID] {
				continue
			}
			tried[f.ID] = true
			if f.Session != "" {
				named = append(named, f)
			} else {
				anon = append(anon, f)
			}
		}
	}
	return append(named, anon...)
}

// drainBatch parks or releases the fibers in order, drainWorkers at a
// time, and waits for every call it started.
func (a *Core) drainBatch(ctx context.Context, batch []FiberInfo) DrainReport {
	var (
		mu  sync.Mutex
		rep DrainReport
		wg  sync.WaitGroup
	)
	sem := make(chan struct{}, drainWorkers)
	started := 0
	for _, f := range batch {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
		}
		// Checked after the select too, since a free slot and an ended ctx
		// can both be ready and the select picks either.
		if ctx.Err() != nil {
			break
		}
		started++
		wg.Go(func() {
			defer func() { <-sem }()
			o := a.drainOne(ctx, f)
			mu.Lock()
			rep.add(o)
			mu.Unlock()
		})
	}
	wg.Wait()
	rep.Left += len(batch) - started
	return rep
}

// drainOne parks a named session or releases an anonymous fiber, and
// reports which.
func (a *Core) drainOne(ctx context.Context, f FiberInfo) DrainReport {
	if f.Session == "" {
		code, err := a.Release(ctx, f.ID, false)
		switch code {
		case NotFound:
			// Gone before the drain reached it.
			return DrainReport{}
		case OK:
			return DrainReport{Shed: 1}
		}
		if _, running := a.Ledger.Fiber(f.ID); running {
			log.Printf("drain: release %s: %v", f.ID, err)
			return DrainReport{Failed: 1}
		}
		// Released, and only a later step failed (a sync audit record).
		log.Printf("drain: released %s, then: %v", f.ID, err)
		return DrainReport{Shed: 1}
	}
	// sync, as host.Runtime.Park reads it: the fiber runs until its delta
	// and manifest are fsynced, then it is killed, and a failure before
	// then gives the fiber back running. Without it the checkpoint ends
	// the fiber and the delta is not fsynced. fiberd exits right after the
	// drain, so the delta must be durable before the fiber goes.
	ref, published, code, err := a.park(ctx, f.ID, true)
	switch {
	case code == NotFound:
		return DrainReport{}
	case ref == "":
		// Nothing was parked, so the fiber runs on.
		log.Printf("drain: park %s (session %q): %v", f.ID, f.Session, err)
		return DrainReport{Failed: 1}
	case err != nil:
		// The delta exists and the ledger has it, so the session is parked.
		log.Printf("drain: parked %s (session %q) as %s, then: %v", f.ID, f.Session, ref, err)
	}
	if !published {
		log.Printf("drain: session %q parked as %s, not published, so it resumes on this home only", f.Session, ref)
		return DrainReport{Parked: 1}
	}
	return DrainReport{Parked: 1, Published: 1}
}
