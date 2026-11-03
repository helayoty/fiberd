package home

import (
	"context"
	"sync"
)

// ScopeLossQueue hands scope-loss reasons to one callback, in the order
// they were detected, each reason once per lifetime. A home detects a
// loss inside a poll round and calls Lose. Delivery happens on the one
// goroutine Run owns, with the context Run was given, so a slow callback
// (an epoch bump that waits for fibers) never stalls a poll round and
// outlives the round that found the loss. Reasons detected before
// OnScopeLost is called wait in the queue and are delivered in order once
// a callback exists. The queue does not log. Lose reports whether a
// reason is new so the home can.
//
// The zero value is ready to use.
type ScopeLossQueue struct {
	mu   sync.Mutex
	seen map[string]bool
	todo []string
	fn   func(ctx context.Context, reason string)
	wake chan struct{}
}

// Lose queues reason for delivery and reports whether it is new. A reason
// already seen is dropped.
func (q *ScopeLossQueue) Lose(reason string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.seen[reason] {
		return false
	}
	if q.seen == nil {
		q.seen = map[string]bool{}
	}
	q.seen[reason] = true
	q.todo = append(q.todo, reason)
	q.wakeLocked()
	return true
}

// OnScopeLost sets the callback. A nil fn is ignored, and the queued
// reasons keep waiting. Setting a callback wakes delivery.
func (q *ScopeLossQueue) OnScopeLost(fn func(ctx context.Context, reason string)) {
	if fn == nil {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.fn = fn
	q.wakeLocked()
}

// Pending is how many reasons wait for delivery.
func (q *ScopeLossQueue) Pending() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.todo)
}

// Run delivers queued reasons until ctx ends. It blocks, so the caller
// gives it a goroutine and waits for it to return. It is the only
// goroutine that ever calls the callback. Run is called once.
func (q *ScopeLossQueue) Run(ctx context.Context) {
	q.mu.Lock()
	wake := q.wakeChanLocked()
	q.mu.Unlock()
	for {
		q.deliver(ctx)
		select {
		case <-ctx.Done():
			return
		case <-wake:
		}
	}
}

// deliver calls the callback for every queued reason, oldest first, and
// stops when the queue is empty, there is no callback yet, or ctx ends.
func (q *ScopeLossQueue) deliver(ctx context.Context) {
	for ctx.Err() == nil {
		q.mu.Lock()
		if q.fn == nil || len(q.todo) == 0 {
			q.mu.Unlock()
			return
		}
		reason, fn := q.todo[0], q.fn
		q.todo = q.todo[1:]
		q.mu.Unlock()
		fn(ctx, reason)
	}
}

// wakeLocked nudges Run. The channel holds one wake, so a nudge nobody
// waits for yet is kept, and repeated nudges collapse into one.
func (q *ScopeLossQueue) wakeLocked() {
	select {
	case q.wakeChanLocked() <- struct{}{}:
	default:
	}
}

func (q *ScopeLossQueue) wakeChanLocked() chan struct{} {
	if q.wake == nil {
		q.wake = make(chan struct{}, 1)
	}
	return q.wake
}
