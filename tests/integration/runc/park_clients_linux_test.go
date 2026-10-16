//go:build linux && integration

package runctest

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// TestParkWaitsForClients parks a fiber while a host client is still
// connected. The fiber closes the connection at the park's signal, so
// the client is cut off, criu meets no socket from the host's network
// namespace, and the park goes through whether the client closes first
// or stays.
func TestParkWaitsForClients(t *testing.T) {
	cases := []struct {
		name       string
		closeAfter time.Duration // 0 keeps the connection open through the park
	}{
		{name: "a client that closes moments after the park was asked for", closeAfter: 150 * time.Millisecond},
		{name: "a client that stays connected is cut off and the fiber is parked"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRuntime(t)
			ctx := context.Background()
			g := core.Grant{UID: "pc", TemplateDigest: "sha256:ref", FiberMax: 2, WBudgetBytes: 64 << 20}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatalf("prepare: %v", err)
			}
			h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "pc", Epoch: 1, Seq: 1}, Deadline: 5 * time.Second})
			if err != nil {
				t.Fatalf("clone: %v", err)
			}
			c, err := net.DialTimeout("unix", strings.TrimPrefix(h.Endpoint, "unix://"), 2*time.Second)
			if err != nil {
				t.Fatalf("dial %s: %v", h.Endpoint, err)
			}
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := fmt.Fprintln(c, "incr"); err != nil {
				t.Fatal(err)
			}
			if reply, err := bufio.NewReader(c).ReadString('\n'); err != nil || strings.TrimSpace(reply) != "1" {
				t.Fatalf("incr = %q (%v), want 1", reply, err)
			}
			if tc.closeAfter > 0 {
				go func() {
					time.Sleep(tc.closeAfter)
					_ = c.Close()
				}()
			}
			ref, err := rt.Park(ctx, h.ID, false)
			if err != nil {
				t.Fatalf("park with a client connected: %v", err)
			}
			if tc.closeAfter == 0 {
				// The fiber closed the connection before it said it serves
				// nothing, so the client sees the end of it.
				if _, err := c.Read(make([]byte, 1)); err == nil {
					t.Fatal("the client's connection is still open after the park")
				}
			}
			h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: "pc", Epoch: 1, Seq: 2}, Deadline: 10 * time.Second})
			if err != nil {
				t.Fatalf("resume: %v", err)
			}
			if got := talk(t, h2.Endpoint, "get"); got != "1" {
				t.Fatalf("get after resume = %q, want the parked counter 1", got)
			}
			_ = rt.Release(ctx, h2.ID, false)
		})
	}
}
