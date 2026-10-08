//go:build linux

package runctest

import (
	"context"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// TestRandomPerIncarnation is the proc test of the same name across the
// container boundary: forked siblings draw their own randomness, and so
// do two fibers resumed from one park. On runc the fence file the host
// publishes at resume is read by the fiber as a mapped root inside the
// container, which is the signal that makes the second part hold.
func TestRandomPerIncarnation(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		// draw makes two incarnations of g and returns the first
		// random() each one answers.
		draw func(t *testing.T, rt core.Runtime, g core.Grant) (a, b string)
	}{
		{name: "forked siblings", draw: func(t *testing.T, rt core.Runtime, g core.Grant) (string, string) {
			var out []string
			for seq := uint64(1); seq <= 2; seq++ {
				h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: seq}, Deadline: 2 * time.Second})
				if err != nil {
					t.Fatalf("clone %d: %v", seq, err)
				}
				t.Cleanup(func() { _ = rt.Release(ctx, h.ID, true) })
				out = append(out, talk(t, h.Endpoint, "random"))
			}
			return out[0], out[1]
		}},
		{name: "two resumes of one park", draw: func(t *testing.T, rt core.Runtime, g core.Grant) (string, string) {
			h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
			if err != nil {
				t.Fatalf("clone: %v", err)
			}
			talk(t, h.Endpoint, "random")
			ref, err := rt.Park(ctx, h.ID, true)
			if err != nil {
				t.Fatalf("park: %v", err)
			}
			var out []string
			for seq := uint64(2); seq <= 3; seq++ {
				h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: seq}, Deadline: 5 * time.Second})
				if err != nil {
					t.Fatalf("resume %d: %v", seq, err)
				}
				out = append(out, talk(t, h2.Endpoint, "random"))
				if got := talk(t, h2.Endpoint, "fence"); got != h2.ID {
					t.Fatalf("resume %d: fence = %q, want %q", seq, got, h2.ID)
				}
				if err := rt.Release(ctx, h2.ID, false); err != nil {
					t.Fatalf("release %s: %v", h2.ID, err)
				}
			}
			return out[0], out[1]
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRuntime(t)
			g := core.Grant{UID: "grnd", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			a, b := tc.draw(t, rt, g)
			if a == b {
				t.Fatalf("both incarnations answered random = %q, want different values", a)
			}
			t.Logf("random: %s and %s", a, b)
		})
	}
}
