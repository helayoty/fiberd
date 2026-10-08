//go:build linux

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
// connected. A client that closes soon is waited for. One that stays is
// named, and the fiber keeps serving.
func TestParkWaitsForClients(t *testing.T) {
	cases := []struct {
		name       string
		closeAfter time.Duration // 0 keeps the connection open through the park
		wantErr    string
	}{
		{name: "a client that closes moments after the park was asked for", closeAfter: 150 * time.Millisecond},
		{name: "a client that stays connected is named and the fiber keeps serving", wantErr: "from outside the container"},
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
			t0 := time.Now()
			ref, err := rt.Park(ctx, h.ID, false)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("park with a client connected = %v, want %q", err, tc.wantErr)
				}
				// The fiber serves one connection at a time, so ours goes
				// before the next one is answered.
				_ = c.Close()
				if got := talk(t, h.Endpoint, "get"); got != "1" {
					t.Fatalf("get after the refused park = %q, want 1 from the fiber still running", got)
				}
				_ = rt.Release(ctx, h.ID, false)
				return
			}
			if err != nil {
				t.Fatalf("park %s after the client closed: %v", time.Since(t0).Round(time.Millisecond), err)
			}
			if since := time.Since(t0); since < tc.closeAfter {
				t.Fatalf("park returned after %s, before the client closed at %s", since, tc.closeAfter)
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
