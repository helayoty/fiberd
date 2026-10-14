//go:build linux && integration

package pythontest

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// TestReferenceTemplate pins what a fiber of the Python reference
// template knows at birth, on every backend. Its fence, its environment,
// the payload and the session the caller named all arrive as the C
// reference's do, whether the fiber is a fork or a restored sandbox.
func TestReferenceTemplate(t *testing.T) {
	cases := []struct {
		name    string
		session string
		payload []byte
		asks    map[string]string // request line to the reply wanted, with FENCE for the fiber's id and PATH for the backend's
	}{
		{name: "an anonymous fiber", asks: map[string]string{
			"ping": "pong", "fence": "FENCE", "getenv FIBERD_FENCE": "FENCE", "getenv PATH": "PATH", "getenv PYTHONPATH": "-",
			"session": "-", "getenv FIBERD_SESSION": "-", "payload": "-",
		}},
		{name: "a session with a space and a payload", session: "conv 42", payload: []byte(`{"task":1}`), asks: map[string]string{
			"session": "conv 42", "getenv FIBERD_SESSION": "conv 42", "payload": hex.EncodeToString([]byte(`{"task":1}`)),
		}},
		{name: "state is per fiber", asks: map[string]string{"get": "1"}},
	}
	for _, be := range backends {
		t.Run(be.name, func(t *testing.T) {
			rt := be.open(t, be.template)
			g := prepare(t, rt, "gpy")
			for i, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					h := clone(t, rt, g, uint64(i+1), tc.session, tc.payload)
					if got := talk(t, h.Endpoint, "incr"); got != "1" {
						t.Fatalf("incr = %q, want 1", got)
					}
					for ask, want := range tc.asks {
						want = strings.NewReplacer("FENCE", h.ID, "PATH", be.pathEnv).Replace(want)
						if got := talk(t, h.Endpoint, ask); got != want {
							t.Errorf("%s = %q, want %q", ask, got, want)
						}
					}
				})
			}
		})
	}
}

// TestRandomPerIncarnation pins that every copy of the Python template
// draws its own randomness, on every backend. Two forked siblings differ,
// which the fork incarnation's reseed gives, and so do two sandboxes
// restored from one image, two pooled sandboxes handed out, and two
// fibers resumed from one park. On proc the fence file beside the
// endpoint is what a resumed fiber notices, and the on_incarnation hook
// records the fork and then the resume under the new fence.
func TestRandomPerIncarnation(t *testing.T) {
	ctx := context.Background()
	type draw func(t *testing.T, rt core.Runtime, g core.Grant) (a, b string)
	siblings := func(t *testing.T, rt core.Runtime, g core.Grant) (string, string) {
		a := clone(t, rt, g, 1, "", nil)
		b := clone(t, rt, g, 2, "", nil)
		return talk(t, a.Endpoint, "random"), talk(t, b.Endpoint, "random")
	}
	pooled := func(t *testing.T, rt core.Runtime, g core.Grant) (string, string) {
		for i := 0; i < 2; i++ {
			if err := rt.(interface {
				Fill(context.Context, core.Grant, time.Duration) error
			}).Fill(ctx, g, 30*time.Second); err != nil {
				t.Fatalf("fill %d: %v", i, err)
			}
		}
		a := clone(t, rt, g, 1, "", nil)
		b := clone(t, rt, g, 2, "", nil)
		if !a.Pooled || !b.Pooled {
			t.Fatalf("pooled = %v and %v, want both hand-outs from the pool", a.Pooled, b.Pooled)
		}
		return talk(t, a.Endpoint, "random"), talk(t, b.Endpoint, "random")
	}
	resumes := func(t *testing.T, rt core.Runtime, g core.Grant) (string, string) {
		if rt.Tier() < core.TierCheckpoint {
			t.Skip("no park and resume here")
		}
		h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 20 * time.Second})
		if err != nil {
			t.Fatalf("clone: %v", err)
		}
		talk(t, h.Endpoint, "random") // the parked image holds a sequence in progress
		ref, err := rt.Park(ctx, h.ID, true)
		if err != nil {
			t.Fatalf("park: %v", err)
		}
		var out []string
		for seq := uint64(2); seq <= 3; seq++ {
			h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: seq}, Deadline: 30 * time.Second})
			if err != nil {
				t.Fatalf("resume %d: %v", seq, err)
			}
			out = append(out, talk(t, h2.Endpoint, "random"))
			if got := talk(t, h2.Endpoint, "fence"); got != h2.ID {
				t.Fatalf("resume %d: fence = %q, want %q", seq, got, h2.ID)
			}
			// A resumed sandbox binds the parked socket path, so the
			// first is released (the delta kept) before the second.
			if err := rt.Release(ctx, h2.ID, false); err != nil {
				t.Fatalf("release %s: %v", h2.ID, err)
			}
		}
		return out[0], out[1]
	}
	cases := []struct {
		name   string
		pooled bool // needs a backend that pools
		draw   draw
	}{
		{name: "two clones", draw: siblings},
		{name: "two pooled hand-outs", pooled: true, draw: pooled},
		{name: "two resumes of one park", draw: resumes},
	}
	for _, be := range backends {
		t.Run(be.name, func(t *testing.T) {
			for _, tc := range cases {
				if tc.pooled && !be.pooled {
					continue
				}
				t.Run(tc.name, func(t *testing.T) {
					rt := be.open(t, be.template)
					g := prepare(t, rt, "grnd")
					a, b := tc.draw(t, rt, g)
					if a == b {
						t.Fatalf("both incarnations answered random = %q, want different values", a)
					}
					t.Logf("random: %s and %s", a, b)
				})
			}
		})
	}
	t.Run("proc hook sees the fork and then the resume", func(t *testing.T) {
		rt := newRuntime(t, python+" "+testdata+"/hooked.py")
		if rt.Tier() < core.TierCheckpoint {
			t.Skip("criu not usable here")
		}
		g := prepare(t, rt, "grnd")
		h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 5 * time.Second})
		if err != nil {
			t.Fatalf("clone: %v", err)
		}
		ref, err := rt.Park(ctx, h.ID, true)
		if err != nil {
			t.Fatalf("park: %v", err)
		}
		h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 3}, Deadline: 10 * time.Second})
		if err != nil {
			t.Fatalf("resume: %v", err)
		}
		t.Cleanup(func() { _ = rt.Release(ctx, h2.ID, true) })
		if got := talk(t, h2.Endpoint, "incarnations"); got != "fork:1:grnd/1/1 resume:2:grnd/1/3" {
			t.Fatalf("the hook saw %q, want the fork and then the resume under the new fence", got)
		}
	})
}

// TestParkResumeKeepsState pins a Python fiber's park and resume on every
// backend that has one. The counter survives, the resumed fiber serves
// under the new fence with the session it was born with, and the park
// and the resume are timed, which is the arm64 evidence docs/design/sdk.md
// records.
func TestParkResumeKeepsState(t *testing.T) {
	ctx := context.Background()
	for _, be := range backends {
		t.Run(be.name, func(t *testing.T) {
			rt := be.open(t, be.template)
			if rt.Tier() < core.TierCheckpoint {
				t.Skip("no park and resume here")
			}
			g := prepare(t, rt, "gpark")
			h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 20 * time.Second, Session: "S"})
			if err != nil {
				t.Fatalf("clone: %v", err)
			}
			if got := talk(t, h.Endpoint, "incr"); got != "1" {
				t.Fatalf("incr = %q", got)
			}
			start := time.Now()
			ref, err := rt.Park(ctx, h.ID, false)
			if err != nil {
				t.Fatalf("park: %v", err)
			}
			parked := time.Since(start)
			start = time.Now()
			h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 2}, Deadline: 30 * time.Second, Session: "S"})
			if err != nil {
				t.Fatalf("resume: %v", err)
			}
			resumed := time.Since(start)
			t.Cleanup(func() { _ = rt.Release(ctx, h2.ID, true) })
			for ask, want := range map[string]string{"incr": "2", "fence": h2.ID, "session": "S", "getenv FIBERD_SESSION": "S", "ping": "pong"} {
				if got := talk(t, h2.Endpoint, ask); got != want {
					t.Errorf("%s after resume = %q, want %q", ask, got, want)
				}
			}
			t.Logf("%s: park %s, resume %s", be.name, parked.Round(time.Millisecond), resumed.Round(time.Millisecond))
		})
	}
}
