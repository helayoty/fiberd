//go:build linux

package proctest

import (
	"context"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// TestRandomPerIncarnation pins that every new incarnation of a fiber
// draws its own randomness. Two forked siblings differ at birth, which
// on_fiber's reseed gives. Two fibers resumed from one park must differ
// too: CRIU restores the parked RNG state under the same pid, so the
// fence the host publishes beside the endpoint at resume is the one
// signal the template has to reseed before it serves.
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
			talk(t, h.Endpoint, "random") // the parked image holds a sequence in progress
			ref, err := rt.Park(ctx, h.ID, true)
			if err != nil {
				t.Fatalf("park: %v", err)
			}
			// The same delta twice, as a second home or a retry after a
			// failed resume would. The first resume is released, not
			// discarded, so the delta stays. Each incarnation answers
			// random as its very first request.
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
			if rt.Tier() < core.TierCheckpoint {
				t.Skip("criu not usable here")
			}
			g := core.Grant{UID: "grnd", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20}
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
