//go:build linux && integration

package gvisortest

import (
	"context"
	"strconv"
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
// and fresh per sandbox, not part of the restored state. Each
// incarnation also names its generation, which is the host's count of
// the lineage on the identity record: a restore of the template is 1,
// a resume is the parked generation plus one. The old record carried a
// constant, "2" for a clone and "0" for a resume, which the parser
// dropped, so no incarnation could name its generation at all.
func TestRandomPerIncarnation(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		cmd     string // what each incarnation is asked first
		resumed bool   // two resumes of one park instead of two clones
		// chained parks the first resume and resumes that park for the
		// second incarnation, instead of resuming the first park again.
		chained bool
		gens    [2]int // the generation each incarnation reports
	}{
		{name: "two clones of the template, libc random", cmd: "random", gens: [2]int{1, 1}},
		{name: "two clones of the template, getrandom", cmd: "getrandom", gens: [2]int{1, 1}},
		{name: "two resumes of one park, libc random", cmd: "random", resumed: true, gens: [2]int{2, 2}},
		{name: "two resumes of one park, getrandom", cmd: "getrandom", resumed: true, gens: [2]int{2, 2}},
		{name: "a resume of a resumed park, libc random", cmd: "random", resumed: true, chained: true, gens: [2]int{2, 3}},
		{name: "a resume of a resumed park, getrandom", cmd: "getrandom", resumed: true, chained: true, gens: [2]int{2, 3}},
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
				if got, want := talk(t, h.Endpoint, "generation"), strconv.Itoa(tc.gens[seq-2]); got != want {
					t.Fatalf("incarnation %d: generation = %q, want %s", seq, got, want)
				}
				if tc.chained && seq == 2 {
					// The second incarnation resumes this one's park.
					if ref, err = rt.Park(ctx, h.ID, false); err != nil {
						t.Fatalf("park %s: %v", h.ID, err)
					}
					continue
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
