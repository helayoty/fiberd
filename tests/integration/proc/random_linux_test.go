//go:build linux && integration

package proctest

import (
	"context"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	fiberendpoint "github.com/helayoty/fiberd/pkg/endpoint"
)

// TestRandomPerIncarnation pins that every new incarnation of a fiber
// draws its own randomness. Two forked siblings differ at birth, which
// on_fiber's reseed gives. Two fibers resumed from one park must differ
// too: CRIU restores the parked RNG state under the same pid, so the
// fence the host publishes beside the endpoint at resume is the one
// signal the template has to reseed before it serves. The getrandom
// rows ask the kernel directly. A glibc of 2.41 or later answers
// getrandom from a per-thread state page the vDSO keeps in user memory,
// which a park dumps like any other page, so the park must drop it or
// every resume replays one keystream, the template's reseed included.
func TestRandomPerIncarnation(t *testing.T) {
	ctx := context.Background()
	// resumeTwice parks one fiber and resumes the delta twice, as a
	// second home or a retry after a failed resume would. The first
	// resume is released, not discarded, so the delta stays. Each
	// incarnation answers cmd as its very first request, and names
	// the fence it serves under.
	resumeTwice := func(t *testing.T, rt core.Runtime, g core.Grant, cmd string) (string, string) {
		h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
		if err != nil {
			t.Fatalf("clone: %v", err)
		}
		talk(t, h.Endpoint, cmd) // the parked image holds a sequence in progress
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
	siblings := func(t *testing.T, rt core.Runtime, g core.Grant, cmd string) (string, string) {
		var out []string
		for seq := uint64(1); seq <= 2; seq++ {
			h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: seq}, Deadline: 2 * time.Second})
			if err != nil {
				t.Fatalf("clone %d: %v", seq, err)
			}
			t.Cleanup(func() { _ = rt.Release(ctx, h.ID, true) })
			out = append(out, talk(t, h.Endpoint, cmd))
		}
		return out[0], out[1]
	}
	cases := []struct {
		name string
		cmd  string // what each incarnation is asked first
		// runtime opens the home; nil for the unix-endpoint default.
		runtime func(t *testing.T) core.Runtime
		// draw makes two incarnations of g and returns the first
		// answer to cmd from each one.
		draw func(t *testing.T, rt core.Runtime, g core.Grant, cmd string) (a, b string)
	}{
		{name: "forked siblings, libc random", cmd: "random", draw: siblings},
		{name: "forked siblings, getrandom", cmd: "getrandom", draw: siblings},
		{name: "two resumes of one park, libc random", cmd: "random", draw: resumeTwice},
		{name: "two resumes of one park, getrandom", cmd: "getrandom", draw: resumeTwice},
		// A fiber that binds tcp itself has no socket to find its fence
		// file beside. It reads the file named by its birth fence. The
		// ports sit below the kernel's ephemeral range (32768 and up), which
		// any suite's listener or dial may be holding.
		{name: "two resumes of one park on a tcp endpoint, libc random", cmd: "random", draw: resumeTwice,
			runtime: func(t *testing.T) core.Runtime { return tcpRuntime(t, fiberendpoint.Inet4, "127.0.0.1", 21010, 21013) }},
		{name: "two resumes of one park on a tcp endpoint, getrandom", cmd: "getrandom", draw: resumeTwice,
			runtime: func(t *testing.T) core.Runtime { return tcpRuntime(t, fiberendpoint.Inet4, "127.0.0.1", 21010, 21013) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRuntime(t)
			if tc.runtime != nil {
				rt = tc.runtime(t)
			}
			if rt.Tier() < core.TierCheckpoint {
				t.Skip("criu not usable here")
			}
			g := core.Grant{UID: "grnd", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			a, b := tc.draw(t, rt, g, tc.cmd)
			if a == b {
				t.Fatalf("both incarnations answered %s = %q, want different values", tc.cmd, a)
			}
			t.Logf("%s: %s and %s", tc.cmd, a, b)
		})
	}
}
