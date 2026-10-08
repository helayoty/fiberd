//go:build linux

package gvisortest

import (
	"context"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// TestRandomPerIncarnation pins that sandboxes restored from one image
// draw their own randomness. There is no fork on gVisor: every fiber is
// a restore of the template's self-checkpoint, and so is every resume
// of a park, so the template's libc state is the same in each copy until
// the template reseeds when its checkpoint read returns "restore". The
// getrandom rows show the entropy under that reseed is the Sentry's own
// and fresh per sandbox, not part of the restored state.
func TestRandomPerIncarnation(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		cmd     string // what each incarnation is asked first
		resumed bool   // two resumes of one park instead of two clones
	}{
		{name: "two clones of the template, libc random", cmd: "random"},
		{name: "two clones of the template, getrandom", cmd: "getrandom"},
		{name: "two resumes of one park, libc random", cmd: "random", resumed: true},
		{name: "two resumes of one park, getrandom", cmd: "getrandom", resumed: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRuntime(t)
			g := core.Grant{UID: "grnd", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			source, ref := core.SourceZygote, ""
			if tc.resumed {
				h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 5 * time.Second})
				if err != nil {
					t.Fatalf("clone: %v", err)
				}
				talk(t, h.Endpoint, tc.cmd)
				if ref, err = rt.Park(ctx, h.ID, false); err != nil {
					t.Fatalf("park: %v", err)
				}
				source = core.SourceDelta
			}
			var out []string
			for seq := uint64(2); seq <= 3; seq++ {
				h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: source, Ref: ref, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: seq}, Deadline: 10 * time.Second})
				if err != nil {
					t.Fatalf("incarnation %d: %v", seq, err)
				}
				out = append(out, talk(t, h.Endpoint, tc.cmd))
				if got := talk(t, h.Endpoint, "fence"); got != h.ID {
					t.Fatalf("incarnation %d: fence = %q, want %q", seq, got, h.ID)
				}
				// A resumed sandbox binds the parked socket path, so the
				// first is released (the delta kept) before the second.
				if err := rt.Release(ctx, h.ID, false); err != nil {
					t.Fatalf("release %s: %v", h.ID, err)
				}
			}
			if out[0] == out[1] {
				t.Fatalf("both incarnations answered %s = %q, want different values", tc.cmd, out[0])
			}
			t.Logf("%s: %s and %s", tc.cmd, out[0], out[1])
		})
	}
}
