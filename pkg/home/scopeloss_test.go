package home_test

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/home"
)

// losses records what a ScopeLossQueue delivered, in order.
type losses struct {
	mu   sync.Mutex
	got  []string
	seen chan string
}

func newLosses() *losses { return &losses{seen: make(chan string, 16)} }

func (l *losses) fn(_ context.Context, reason string) {
	l.mu.Lock()
	l.got = append(l.got, reason)
	l.mu.Unlock()
	l.seen <- reason
}

func (l *losses) wait(t *testing.T, n int) []string {
	t.Helper()
	for range n {
		select {
		case <-l.seen:
		case <-time.After(10 * time.Second):
			t.Fatalf("delivered %v, waited for %d", l.snapshot(), n)
		}
	}
	return l.snapshot()
}

func (l *losses) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.got)
}

// TestScopeLossQueueDelivers walks the queue through the orders a home can
// call it in and checks what reaches the callback, and in which order.
func TestScopeLossQueueDelivers(t *testing.T) {
	cases := []struct {
		name string
		// before runs before Run starts, after once it has.
		before, after func(t *testing.T, q *home.ScopeLossQueue, l *losses)
		want          []string
		wantPending   int
	}{
		{name: "two reasons arrive in detection order",
			before: func(_ *testing.T, q *home.ScopeLossQueue, l *losses) {
				q.OnScopeLost(l.fn)
				q.Lose("namespace gone")
				q.Lose("claim gone")
			},
			want: []string{"namespace gone", "claim gone"}},
		{name: "a reason fires once per lifetime",
			before: func(t *testing.T, q *home.ScopeLossQueue, l *losses) {
				q.OnScopeLost(l.fn)
				if !q.Lose("pod gone") {
					t.Fatal("the first Lose is not new")
				}
				if q.Lose("pod gone") {
					t.Fatal("the second Lose is new")
				}
			},
			want: []string{"pod gone"}},
		{name: "reasons detected before the callback wait and arrive in order",
			before: func(_ *testing.T, q *home.ScopeLossQueue, _ *losses) {
				q.Lose("first")
				q.Lose("second")
			},
			after: func(t *testing.T, q *home.ScopeLossQueue, l *losses) {
				if n := q.Pending(); n != 2 {
					t.Fatalf("pending %d before a callback, want 2", n)
				}
				q.OnScopeLost(l.fn)
			},
			want: []string{"first", "second"}},
		{name: "a nil callback is ignored and queued losses keep waiting",
			before: func(_ *testing.T, q *home.ScopeLossQueue, _ *losses) {
				q.Lose("first")
				q.OnScopeLost(nil)
			},
			after: func(t *testing.T, q *home.ScopeLossQueue, l *losses) {
				if n := q.Pending(); n != 1 {
					t.Fatalf("pending %d after a nil callback, want 1", n)
				}
				q.OnScopeLost(l.fn)
			},
			want: []string{"first"}},
		{name: "a reason detected while running is delivered",
			before: func(_ *testing.T, q *home.ScopeLossQueue, l *losses) { q.OnScopeLost(l.fn) },
			after:  func(_ *testing.T, q *home.ScopeLossQueue, _ *losses) { q.Lose("late") },
			want:   []string{"late"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			q := &home.ScopeLossQueue{}
			l := newLosses()
			if c.before != nil {
				c.before(t, q, l)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { defer close(done); q.Run(ctx) }()
			if c.after != nil {
				c.after(t, q, l)
			}
			got := l.wait(t, len(c.want))
			if !slices.Equal(got, c.want) {
				t.Fatalf("delivered %v, want %v", got, c.want)
			}
			if n := q.Pending(); n != c.wantPending {
				t.Fatalf("pending %d, want %d", n, c.wantPending)
			}
			cancel()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("Run did not return after its context ended")
			}
		})
	}
}

// TestScopeLossQueueDeliversOffTheDetector checks that Lose never waits
// for the callback and that the callback gets Run's context, so a slow
// epoch bump neither stalls a poll round nor dies with it.
func TestScopeLossQueueDeliversOffTheDetector(t *testing.T) {
	type key struct{}
	cases := []struct {
		name    string
		reasons []string
	}{
		{name: "one reason", reasons: []string{"a"}},
		{name: "a second reason queues behind a blocked callback", reasons: []string{"a", "b"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			release := make(chan struct{})
			entered := make(chan string, len(c.reasons))
			var mu sync.Mutex
			var got []string
			var ctxOK bool
			q := &home.ScopeLossQueue{}
			q.OnScopeLost(func(ctx context.Context, reason string) {
				mu.Lock()
				got = append(got, reason)
				ctxOK = ctx.Value(key{}) == "run"
				mu.Unlock()
				entered <- reason
				<-release
			})
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), key{}, "run"))
			done := make(chan struct{})
			go func() { defer close(done); q.Run(ctx) }()

			// Every Lose returns at once, blocked callback or not.
			for _, r := range c.reasons {
				returned := make(chan struct{})
				go func() { defer close(returned); q.Lose(r) }()
				select {
				case <-returned:
				case <-time.After(10 * time.Second):
					t.Fatalf("Lose(%q) waited for the callback", r)
				}
			}
			for i := range c.reasons {
				select {
				case r := <-entered:
					if r != c.reasons[i] {
						t.Fatalf("callback %d got %q, want %q", i, r, c.reasons[i])
					}
				case <-time.After(10 * time.Second):
					t.Fatalf("callback %d never ran", i)
				}
				release <- struct{}{}
			}
			cancel()
			<-done
			mu.Lock()
			defer mu.Unlock()
			if !slices.Equal(got, c.reasons) {
				t.Fatalf("delivered %v, want %v", got, c.reasons)
			}
			if !ctxOK {
				t.Fatal("the callback did not get Run's context")
			}
		})
	}
}
