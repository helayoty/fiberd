//go:build linux && integration

package proctest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// hold opens a connection to the fiber's unix endpoint and keeps it,
// after one exchange, so the fiber is busy serving it. The connection
// is returned for the test to close or watch.
func hold(t *testing.T, endpoint, line, want string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("unix", strings.TrimPrefix(endpoint, "unix://"), 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", endpoint, err)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintln(c, line); err != nil {
		t.Fatal(err)
	}
	if reply, err := bufio.NewReader(c).ReadString('\n'); err != nil || strings.TrimSpace(reply) != want {
		t.Fatalf("%s = %q (%v), want %q", line, reply, err, want)
	}
	return c
}

// leafProcs is the cgroup.procs of the fiber's leaf, or "" for a leaf
// that is gone.
func leafProcs(t *testing.T, rt core.Runtime, g core.Grant, epoch, seq int) string {
	t.Helper()
	leaf := filepath.Join(rt.(interface{ CgroupRoot() string }).CgroupRoot(), g.UID, fmt.Sprintf("f-%d-%d", epoch, seq), "cgroup.procs")
	b, err := os.ReadFile(leaf)
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// TestParkRefused pins that a park is cooperative: fiberd dumps a fiber
// only once it has said it serves nothing. A fiber that serves on
// through the park's signal is not dumped, the park fails by name
// within the grant's resume deadline, and the fiber still serves. A
// fiber busy with a connection closes it at the signal and is parked.
func TestParkRefused(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		payload []byte
		busy    bool   // a client holds a connection open through the park
		late    bool   // the fiber answers after the deadline, and must serve again
		wantErr string // "" for a park that succeeds
	}{
		// The round fiberd named gave up before the fiber answered, so
		// the fiber meets that round's carry-on and serves on, rather
		// than wait for a resume that never comes.
		{name: "a fiber that answers after the deadline serves again", payload: []byte(`{"park_delay_ms":3500}`), late: true, wantErr: "did not stop serving for the park"},
		{name: "a fiber that ignores the signal is not parked and still serves", payload: []byte(`{"park_ignore":1}`), wantErr: "did not stop serving for the park"},
		{name: "a fiber that ignores the signal while serving a client", payload: []byte(`{"park_ignore":1}`), busy: true, wantErr: "did not stop serving for the park"},
		{name: "a fiber serving a client closes it at the signal and is parked", busy: true},
		// The signal lands while the fiber is between a reply and its
		// next read, with the client quiet. Nothing but the signal can
		// end that read, so it must not be entered unaware of the park.
		{name: "a signal between a reply and the next read still cuts the client", payload: []byte(`{"reply_delay_ms":500}`), busy: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRuntime(t)
			if rt.Tier() < core.TierCheckpoint {
				t.Skip("criu not usable here")
			}
			g := core.Grant{UID: "gpr", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second, Payload: tc.payload})
			if err != nil {
				t.Fatalf("clone: %v", err)
			}
			if got := talk(t, h.Endpoint, "incr"); got != "1" {
				t.Fatalf("incr = %q, want 1", got)
			}
			var held net.Conn
			if tc.busy {
				held = hold(t, h.Endpoint, "ping", "pong")
				defer func() { _ = held.Close() }()
			}
			_, resume := core.GrantDeadlines(rt, g.UID)
			t0 := time.Now()
			ref, err := rt.Park(ctx, h.ID, false)
			took := time.Since(t0)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !strings.Contains(err.Error(), h.ID) {
					t.Fatalf("park = %q, %v, want an error naming %s and %q", ref, err, h.ID, tc.wantErr)
				}
				if took < resume || took > resume+2*time.Second {
					t.Fatalf("the park gave up after %s, want the grant's resume deadline %s", took, resume)
				}
				if ref != "" {
					t.Fatalf("a refused park returned a delta %q", ref)
				}
				if held != nil {
					_ = held.Close()
				}
				if tc.late {
					waitServes(t, h.Endpoint, 6*time.Second)
				}
				if got := talk(t, h.Endpoint, "get"); got != "1" {
					t.Fatalf("get after the refused park = %q, want 1 from the fiber still serving", got)
				}
				if err := rt.Release(ctx, h.ID, false); err != nil {
					t.Fatalf("release after the refused park: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("park: %v", err)
			}
			// The fiber closed the held connection before it said it
			// serves nothing, so the client sees the end of it.
			_ = held.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := held.Read(make([]byte, 1)); err == nil {
				t.Fatal("the held connection is still open after the park")
			}
			h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 2}, Deadline: 5 * time.Second})
			if err != nil {
				t.Fatalf("resume: %v", err)
			}
			if got := talk(t, h2.Endpoint, "get"); got != "1" {
				t.Fatalf("get after the resume = %q, want the parked counter 1", got)
			}
			_ = rt.Release(ctx, h2.ID, true)
		})
	}
}

// waitServes asks the endpoint for a pong until it answers one, within
// bound, for a fiber that listens again after a late answer to a park.
// A dial alone would not do, since the fiber's listener stays open
// while it finishes its request, and that queue is dropped at the
// close.
func waitServes(t *testing.T, endpoint string, bound time.Duration) {
	t.Helper()
	deadline := time.Now().Add(bound)
	for {
		c, err := net.DialTimeout("unix", strings.TrimPrefix(endpoint, "unix://"), time.Second)
		if err == nil {
			_ = c.SetDeadline(time.Now().Add(time.Second))
			_, _ = fmt.Fprintln(c, "ping")
			reply, rerr := bufio.NewReader(c).ReadString('\n')
			_ = c.Close()
			if rerr == nil && strings.TrimSpace(reply) == "pong" {
				return
			}
			err = fmt.Errorf("ping = %q: %w", reply, rerr)
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s does not serve again %s after the park gave up: %v", endpoint, bound, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestNoAckNoServe pins the resume's gate: fiberd routes a resumed fiber
// only once it has said it serves again. A fiber that takes its record
// and never acks is ended within the deadline, its endpoint is never
// routed and its leaf is empty afterwards.
func TestNoAckNoServe(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name     string
		payload  []byte
		deadline time.Duration
	}{
		{name: "a resumed fiber that never acks is ended and nothing is routed", payload: []byte(`{"ack_skip":1}`), deadline: 2 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRuntime(t)
			if rt.Tier() < core.TierCheckpoint {
				t.Skip("criu not usable here")
			}
			g := core.Grant{UID: "gna", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second, Payload: tc.payload})
			if err != nil {
				t.Fatalf("clone: %v", err)
			}
			ref, err := rt.Park(ctx, h.ID, false)
			if err != nil {
				t.Fatalf("park: %v", err)
			}
			t0 := time.Now()
			h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 2}, Deadline: tc.deadline})
			took := time.Since(t0)
			if err == nil || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "did not say it serves again") {
				t.Fatalf("resume = %+v, %v, want the ack's deadline", h2, err)
			}
			if took < tc.deadline || took > tc.deadline+3*time.Second {
				t.Fatalf("the resume gave up after %s, want its deadline %s", took, tc.deadline)
			}
			// Nothing serves on the endpoint the restore bound, and the
			// restored tree is gone with its leaf.
			ep := filepath.Join(filepath.Dir(strings.TrimPrefix(h.Endpoint, "unix://")), "1-2.sock")
			if _, err := os.Stat(ep); err == nil {
				t.Fatalf("%s exists after the failed resume", ep)
			}
			deadline := time.Now().Add(5 * time.Second)
			for leafProcs(t, rt, g, 1, 2) != "" && time.Now().Before(deadline) {
				time.Sleep(50 * time.Millisecond)
			}
			if procs := leafProcs(t, rt, g, 1, 2); procs != "" {
				t.Fatalf("the leaf still holds %q after the failed resume", procs)
			}
		})
	}
}

// TestParkMeetsClosedQueuedConnection is the regression for the storm's
// failed parks. A client that connects while the fiber is busy with
// another waits in the listener's queue. One that then gives up leaves
// a closed in-flight socket there, which criu refuses to dump ("Found a
// closed in-flight socket"), and under pressure fiberd released the
// fiber instead of parking it. The cooperative park has the fiber close
// its listener, queue and all, and its connection in hand before it
// says it serves nothing, so the dump meets neither.
func TestParkMeetsClosedQueuedConnection(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		gaveUp int // clients that connected behind the busy fiber and gave up
	}{
		{name: "one client gave up while the fiber served another", gaveUp: 1},
		{name: "three clients gave up while the fiber served another", gaveUp: 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRuntime(t)
			if rt.Tier() < core.TierCheckpoint {
				t.Skip("criu not usable here")
			}
			g := core.Grant{UID: "gqc", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
			if err != nil {
				t.Fatalf("clone: %v", err)
			}
			// The fiber serves one connection at a time. This one keeps
			// it busy, so the next ones wait in the listener's queue.
			busy := hold(t, h.Endpoint, "incr", "1")
			defer func() { _ = busy.Close() }()
			for i := 0; i < tc.gaveUp; i++ {
				c, err := net.DialTimeout("unix", strings.TrimPrefix(h.Endpoint, "unix://"), 2*time.Second)
				if err != nil {
					t.Fatalf("dial %d: %v", i, err)
				}
				_ = c.Close()
			}
			ref, err := rt.Park(ctx, h.ID, false)
			if err != nil {
				t.Fatalf("park with %d closed connections queued: %v", tc.gaveUp, err)
			}
			h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 2}, Deadline: 5 * time.Second})
			if err != nil {
				t.Fatalf("resume: %v", err)
			}
			if got := talk(t, h2.Endpoint, "get"); got != "1" {
				t.Fatalf("get after the resume = %q, want the parked counter 1", got)
			}
			_ = rt.Release(ctx, h2.ID, true)
		})
	}
}
