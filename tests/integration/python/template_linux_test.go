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
// template knows at birth. Its fence, its scrubbed environment, the
// payload and the session the caller named all arrive as the C
// reference's do.
func TestReferenceTemplate(t *testing.T) {
	cases := []struct {
		name    string
		session string
		payload []byte
		asks    map[string]string // request line to the reply wanted, with FENCE for the fiber's id
	}{
		{name: "an anonymous fiber", asks: map[string]string{
			"ping": "pong", "fence": "FENCE", "getenv FIBERD_FENCE": "FENCE", "getenv PATH": "-", "getenv PYTHONPATH": "-",
			"session": "-", "getenv FIBERD_SESSION": "-", "payload": "-",
		}},
		{name: "a session with a space and a payload", session: "conv 42", payload: []byte(`{"task":1}`), asks: map[string]string{
			"session": "conv 42", "getenv FIBERD_SESSION": "conv 42", "payload": hex.EncodeToString([]byte(`{"task":1}`)),
		}},
		{name: "state is per fiber", asks: map[string]string{"get": "1"}},
	}
	rt := newRuntime(t, refTemplate())
	g := prepare(t, rt, "gpy")
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := clone(t, rt, g, uint64(i+1), tc.session, tc.payload)
			if got := talk(t, h.Endpoint, "incr"); got != "1" {
				t.Fatalf("incr = %q, want 1", got)
			}
			for ask, want := range tc.asks {
				want = strings.ReplaceAll(want, "FENCE", h.ID)
				if got := talk(t, h.Endpoint, ask); got != want {
					t.Errorf("%s = %q, want %q", ask, got, want)
				}
			}
		})
	}
}

// TestRandomPerIncarnation pins that every copy of the Python template
// draws its own randomness. Two forked siblings differ, which the fork
// incarnation's reseed gives. Two fibers resumed from one park differ
// too, since the fence file beside the endpoint is checked before a
// resumed fiber serves its first connection, and the generation and the
// kind the on_incarnation hook saw say which copy this is.
func TestRandomPerIncarnation(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name     string
		template string
		// draw makes two incarnations and returns the first random each
		// answers, and what the hook saw in the second.
		draw func(t *testing.T, rt core.Runtime, g core.Grant) (a, b, hooks string)
	}{
		{name: "forked siblings", template: refTemplate(), draw: func(t *testing.T, rt core.Runtime, g core.Grant) (string, string, string) {
			a := clone(t, rt, g, 1, "", nil)
			b := clone(t, rt, g, 2, "", nil)
			return talk(t, a.Endpoint, "random"), talk(t, b.Endpoint, "random"), ""
		}},
		{name: "two resumes of one park", template: python + " " + testdata + "/hooked.py", draw: func(t *testing.T, rt core.Runtime, g core.Grant) (string, string, string) {
			if rt.Tier() < core.TierCheckpoint {
				t.Skip("criu not usable here")
			}
			h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 5 * time.Second})
			if err != nil {
				t.Fatalf("clone: %v", err)
			}
			talk(t, h.Endpoint, "random") // the parked image holds a sequence in progress
			ref, err := rt.Park(ctx, h.ID, true)
			if err != nil {
				t.Fatalf("park: %v", err)
			}
			var out, hooks []string
			for seq := uint64(2); seq <= 3; seq++ {
				h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: seq}, Deadline: 10 * time.Second})
				if err != nil {
					t.Fatalf("resume %d: %v", seq, err)
				}
				out = append(out, talk(t, h2.Endpoint, "random"))
				if got := talk(t, h2.Endpoint, "fence"); got != h2.ID {
					t.Fatalf("resume %d: fence = %q, want %q", seq, got, h2.ID)
				}
				hooks = append(hooks, talk(t, h2.Endpoint, "incarnations"))
				if err := rt.Release(ctx, h2.ID, false); err != nil {
					t.Fatalf("release %s: %v", h2.ID, err)
				}
			}
			return out[0], out[1], hooks[1]
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRuntime(t, tc.template)
			g := prepare(t, rt, "grnd")
			a, b, hooks := tc.draw(t, rt, g)
			if a == b {
				t.Fatalf("both incarnations answered random = %q, want different values", a)
			}
			if hooks != "" && hooks != "fork:1:grnd/1/1 resume:2:grnd/1/3" {
				t.Fatalf("the hook saw %q, want the fork and then the resume under the new fence", hooks)
			}
			t.Logf("random: %s and %s", a, b)
		})
	}
}

// TestParkResumeKeepsState pins a Python fiber's park and resume on the
// proc backend. The counter survives, and the resumed fiber serves under
// the new fence.
func TestParkResumeKeepsState(t *testing.T) {
	ctx := context.Background()
	rt := newRuntime(t, refTemplate())
	if rt.Tier() < core.TierCheckpoint {
		t.Skip("criu not usable here")
	}
	g := prepare(t, rt, "gpark")
	h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 5 * time.Second, Session: "S"})
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	if got := talk(t, h.Endpoint, "incr"); got != "1" {
		t.Fatalf("incr = %q", got)
	}
	ref, err := rt.Park(ctx, h.ID, false)
	if err != nil {
		t.Fatalf("park: %v", err)
	}
	h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 2}, Deadline: 10 * time.Second, Session: "S"})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	t.Cleanup(func() { _ = rt.Release(ctx, h2.ID, true) })
	if got := talk(t, h2.Endpoint, "incr"); got != "2" {
		t.Fatalf("incr after resume = %q, want 2", got)
	}
	if got := talk(t, h2.Endpoint, "fence"); got != h2.ID {
		t.Fatalf("fence after resume = %q, want %q", got, h2.ID)
	}
}
