//go:build linux && integration

package runctest

import (
	"context"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// TestRandomPerIncarnation is the proc test of the same name across the
// container boundary: forked siblings draw their own randomness, each
// from the seed on its own incarnation record, and so do two fibers
// resumed from one park. On runc the fence file the host
// publishes at resume is read by the fiber as a mapped root inside the
// container, which is the signal that makes the second part hold. The
// getrandom rows ask the kernel directly, which a glibc of 2.41 or later
// answers from a vDSO state page in user memory. The park drops that
// page (pkg/sys/criu), or every resume would replay one keystream.
func TestRandomPerIncarnation(t *testing.T) {
	ctx := context.Background()
	siblings := func(payload []byte) func(t *testing.T, rt core.Runtime, g core.Grant, cmd string) (string, string) {
		return func(t *testing.T, rt core.Runtime, g core.Grant, cmd string) (string, string) {
			var out []string
			for seq := uint64(1); seq <= 2; seq++ {
				h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: seq}, Deadline: 2 * time.Second, Payload: payload})
				if err != nil {
					t.Fatalf("clone %d: %v", seq, err)
				}
				t.Cleanup(func() { _ = rt.Release(ctx, h.ID, true) })
				out = append(out, talk(t, h.Endpoint, cmd))
			}
			return out[0], out[1]
		}
	}
	resumes := func(t *testing.T, rt core.Runtime, g core.Grant, cmd string) (string, string) {
		h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
		if err != nil {
			t.Fatalf("clone: %v", err)
		}
		talk(t, h.Endpoint, cmd)
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
			out = append(out, talk(t, h2.Endpoint, cmd))
			if got := talk(t, h2.Endpoint, "fence"); got != h2.ID {
				t.Fatalf("resume %d: fence = %q, want %q", seq, got, h2.ID)
			}
			if err := rt.Release(ctx, h2.ID, false); err != nil {
				t.Fatalf("release %s: %v", h2.ID, err)
			}
		}
		return out[0], out[1]
	}
	cases := []struct {
		name string
		cmd  string // what each incarnation is asked first
		// draw makes two incarnations of g and returns the first
		// answer to cmd from each one.
		draw func(t *testing.T, rt core.Runtime, g core.Grant, cmd string) (a, b string)
		// hex is how many hex characters each answer must be, 0 for
		// any answer.
		hex int
	}{
		{name: "forked siblings, libc random", cmd: "random", draw: siblings(nil)},
		{name: "forked siblings, getrandom", cmd: "getrandom", draw: siblings(nil)},
		// The record's seed, which the channel made in the container's
		// network namespace carries. Before the record, no forked fiber
		// had one.
		{name: "forked siblings, the record's seed", cmd: "seed", draw: siblings([]byte(`{"keep_seed":1}`)), hex: 64},
		{name: "two resumes of one park, libc random", cmd: "random", draw: resumes},
		{name: "two resumes of one park, getrandom", cmd: "getrandom", draw: resumes},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRuntime(t)
			g := core.Grant{UID: "grnd", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			a, b := tc.draw(t, rt, g, tc.cmd)
			if a == b {
				t.Fatalf("both incarnations answered %s = %q, want different values", tc.cmd, a)
			}
			if tc.hex > 0 && (len(a) != tc.hex || len(b) != tc.hex) {
				t.Fatalf("%s: answers %q and %q, want %d hex characters each", tc.cmd, a, b, tc.hex)
			}
			t.Logf("%s: %s and %s", tc.cmd, a, b)
		})
	}
}
