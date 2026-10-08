package core_test

import (
	"context"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/core/coretest"
)

// waitUntil polls cond until it holds or the deadline passes.
func waitUntil(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestRunLoop checks what Run drives until its context ends. An exit from
// the runtime frees the fiber's slot and is recorded, even when a sync
// record fails. A closed exit channel stops nothing else. The lease reaper
// yields a grant once its lease has lapsed, every five seconds.
func TestRunLoop(t *testing.T) {
	cases := []struct {
		name     string
		sync     bool          // the grant's records are sync and fail
		interval time.Duration // StatusInterval, 0 means the one-second default
		exit     bool          // the runtime reports the fiber dead
		close    bool          // the runtime closes its exit channel
		expire   bool          // the grant's lease lapses after the clone
		wait     time.Duration
		check    func(a *core.Agent, rec *auditLog, fiber string) bool
	}{
		{name: "an exit frees the slot and is recorded", interval: 10 * time.Millisecond, exit: true, wait: 5 * time.Second,
			check: func(a *core.Agent, rec *auditLog, fiber string) bool {
				oom := rec.events("oom")
				return len(a.Ledger.RunningFibers()) == 0 && len(oom) == 1 && oom[0].FiberID == fiber && oom[0].Detail == "W over budget"
			}},
		{name: "an exit whose sync record fails still frees the slot", sync: true, interval: 10 * time.Millisecond, exit: true, wait: 5 * time.Second,
			check: func(a *core.Agent, _ *auditLog, _ string) bool {
				st, _ := coretest.GrantStatus(a.Ledger, "g1")
				return len(a.Ledger.RunningFibers()) == 0 && st.Running == 0
			}},
		{name: "a closed exit channel leaves the sampler running", interval: 10 * time.Millisecond, close: true, wait: 5 * time.Second,
			check: func(a *core.Agent, _ *auditLog, _ string) bool {
				st, _ := coretest.GrantStatus(a.Ledger, "g1")
				return st.Running == 1 && st.WUsedBytes == 7
			}},
		{name: "the reaper yields a grant whose lease lapsed", expire: true, wait: 15 * time.Second,
			check: func(a *core.Agent, rec *auditLog, _ string) bool {
				_, held := a.Ledger.Grant("g1")
				return !held && len(a.Ledger.RunningFibers()) == 0 && len(rec.events("revoke")) == 1
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			g := core.Grant{UID: "g1", Audience: "node-a", FiberMax: 2, LeaseExpiry: start.Add(time.Hour)}
			if tc.sync {
				g.Policy.Durability = core.Sync
			}
			a := newAgent(t, "up", core.TierCheckpoint, g)
			exits := make(chan core.FiberExit, 1)
			a.Runtime = fakeRuntime{tier: core.TierCheckpoint, exits: exits}
			a.StatusInterval = tc.interval
			var clock atomic.Int64 // the ledger's clock, as an offset from start
			a.Ledger.Now = func() time.Time { return start.Add(time.Duration(clock.Load())) }
			rec := &auditLog{}
			a.Audit = rec
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g1"), Deadline: time.Second})
			if err != nil || code != core.OK {
				t.Fatalf("clone = %d %v", code, err)
			}
			if tc.sync {
				a.Audit = failingAuditor{}
			}
			if tc.close {
				close(exits)
			}
			done := make(chan struct{})
			go func() {
				a.Run(ctx)
				close(done)
			}()
			if tc.exit {
				exits <- core.FiberExit{FiberID: r.FiberID, Reason: "oom", Detail: "W over budget"}
			}
			if tc.expire {
				clock.Store(int64(2 * time.Hour))
			}
			waitUntil(t, tc.wait, "the agent to settle", func() bool { return tc.check(a, rec, r.FiberID) })
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Run did not return after its context ended")
			}
		})
	}
}

// TestWatchCloses checks that a Watch stream closes once its context ends,
// whether or not its reader keeps up. That includes a stream blocked
// delivering a change or a tick to a reader that stopped reading, which
// would otherwise leak its goroutine.
func TestWatchCloses(t *testing.T) {
	cases := []struct {
		name     string
		interval time.Duration // StatusInterval, 0 means the one-second default
		read     bool          // read the first emission before the changes
		changes  int           // transitions that notify before the cancel
		// blocked waits, before the cancel, until the stream is blocked
		// delivering an update the reader has not taken.
		blocked bool
	}{
		{name: "cancelled before the first read", interval: 10 * time.Millisecond},
		{name: "cancelled with changes unread", interval: 10 * time.Millisecond, changes: 3},
		{name: "cancelled after a read with changes pending", interval: time.Hour, read: true, changes: 2},
		{name: "cancelled on the default interval", changes: 1},
		{name: "cancelled while a change waits on a stopped reader", interval: time.Hour, changes: 1, blocked: true},
		{name: "cancelled while a tick waits on a stopped reader", interval: time.Millisecond, blocked: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newAgent(t, "up", core.TierCheckpoint)
			a.StatusInterval = tc.interval
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			out := a.Watch(ctx)
			if tc.read {
				if batch := <-out; len(batch) != 0 {
					t.Fatalf("first emission = %+v, want no grants", batch)
				}
			}
			if tc.blocked {
				// The first emission fills the buffer, so the next one blocks.
				waitUntil(t, 5*time.Second, "the first emission", func() bool { return len(out) == 1 })
			}
			for i := range tc.changes {
				uid := string(rune('a' + i))
				if code, err := a.Admit(ctx, core.Grant{UID: uid, Audience: "node-a"}); err != nil || code != core.OK {
					t.Fatalf("admit %s = %d %v", uid, code, err)
				}
			}
			if tc.blocked {
				waitUntil(t, 5*time.Second, "the stream to block on its reader", watchBlocked)
			}
			cancel()
			deadline := time.After(5 * time.Second)
			for {
				select {
				case _, ok := <-out:
					if !ok {
						return
					}
				case <-deadline:
					t.Fatal("the stream did not close after its context ended")
				}
			}
		})
	}
}

// watchBlocked reports whether a Watch goroutine is parked in its emit
// closure, waiting for a reader to take an update. A goroutine's state in
// a stack dump is the only place that shows it.
func watchBlocked() bool {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	for _, g := range strings.Split(string(buf[:n]), "\n\n") {
		if strings.Contains(g, "[select") && strings.Contains(g, "core.(*Agent).Watch.func1.1(") {
			return true
		}
	}
	return false
}
