//go:build linux && integration

package runctest

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

// hold opens a connection to the fiber's unix endpoint from the host
// and keeps it, after one exchange, so the fiber is busy serving it.
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

// TestParkRefused pins that a park inside the container is cooperative
// too. A fiber that serves on through the signal is not dumped and the
// park fails by name, with a host client held open or not. The refusal
// is the fiber's, not criu's word about the host's socket, since the
// dump never ran.
func TestParkRefused(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		payload []byte
		busy    bool // a host client holds a connection open through the park
		late    bool // the fiber answers after the deadline, and must serve again
		parks   bool // the park goes through, the client is cut and the resume serves
	}{
		// The round fiberd named gave up before the fiber answered, so
		// the fiber meets that round's carry-on and serves on, rather
		// than wait for a resume that never comes.
		{name: "a fiber that answers after the deadline serves again", payload: []byte(`{"park_delay_ms":3500}`), late: true},
		// The signal lands while the fiber is between a reply and its
		// next read, with the host client quiet, and must still cut it.
		{name: "a signal between a reply and the next read still cuts the client", payload: []byte(`{"reply_delay_ms":500}`), busy: true, parks: true},
		{name: "a fiber that ignores the signal is not parked and still serves", payload: []byte(`{"park_ignore":1}`)},
		{name: "a fiber that ignores the signal with a host client held open", payload: []byte(`{"park_ignore":1}`), busy: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRuntime(t)
			g := core.Grant{UID: "pr", TemplateDigest: "sha256:ref", FiberMax: 2, WBudgetBytes: 64 << 20}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatalf("prepare: %v", err)
			}
			h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 5 * time.Second, Payload: tc.payload})
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
			if tc.parks {
				if err != nil {
					t.Fatalf("park: %v", err)
				}
				_ = held.SetReadDeadline(time.Now().Add(2 * time.Second))
				if _, err := held.Read(make([]byte, 1)); err == nil {
					t.Fatal("the held connection is still open after the park")
				}
				h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 2}, Deadline: 10 * time.Second})
				if err != nil {
					t.Fatalf("resume: %v", err)
				}
				if got := talk(t, h2.Endpoint, "get"); got != "1" {
					t.Fatalf("get after the resume = %q, want the parked counter 1", got)
				}
				_ = rt.Release(ctx, h2.ID, true)
				return
			}
			if err == nil || !strings.Contains(err.Error(), "did not stop serving for the park") || !strings.Contains(err.Error(), h.ID) ||
				strings.Contains(err.Error(), "outside the container") {
				t.Fatalf("park = %q, %v, want the fiber named for not stopping, nothing about the host's socket", ref, err)
			}
			if took < resume || took > resume+2*time.Second {
				t.Fatalf("the park gave up after %s, want the grant's resume deadline %s", took, resume)
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

// TestNoAckNoServe pins the resume's gate inside the container: a
// restored fiber that never acks its record is ended within the
// deadline, nothing is routed to it and its leaf is empty afterwards.
func TestNoAckNoServe(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name     string
		payload  []byte
		deadline time.Duration
	}{
		{name: "a resumed fiber that never acks is ended and nothing is routed", payload: []byte(`{"ack_skip":1}`), deadline: 3 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRuntime(t)
			g := core.Grant{UID: "na", TemplateDigest: "sha256:ref", FiberMax: 2, WBudgetBytes: 64 << 20}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatalf("prepare: %v", err)
			}
			h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 5 * time.Second, Payload: tc.payload})
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
			if took < tc.deadline || took > tc.deadline+5*time.Second {
				t.Fatalf("the resume gave up after %s, want its deadline %s", took, tc.deadline)
			}
			ep := filepath.Join(filepath.Dir(strings.TrimPrefix(h.Endpoint, "unix://")), "1-2.sock")
			if _, err := os.Stat(ep); err == nil {
				t.Fatalf("%s exists after the failed resume", ep)
			}
			leaf := filepath.Join(rt.(interface{ CgroupRoot() string }).CgroupRoot(), g.UID, "fibers", "f-1-2", "cgroup.procs")
			deadline := time.Now().Add(5 * time.Second)
			procs := ""
			for time.Now().Before(deadline) {
				b, err := os.ReadFile(leaf)
				procs = strings.TrimSpace(string(b))
				if errors.Is(err, os.ErrNotExist) || procs == "" {
					procs = ""
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if procs != "" {
				t.Fatalf("the leaf still holds %q after the failed resume", procs)
			}
		})
	}
}
