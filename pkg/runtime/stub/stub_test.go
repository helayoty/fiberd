package stub_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/runtime/stub"
)

func TestCapabilities(t *testing.T) {
	cases := []struct {
		name string
		rt   *stub.Runtime
		tier core.Tier
	}{
		{name: "New advertises checkpoint", rt: stub.New(), tier: core.TierCheckpoint},
		{name: "NewWithTier advertises the tier asked for", rt: stub.NewWithTier(core.TierWarm), tier: core.TierWarm},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.rt.Tier(); got != c.tier {
				t.Fatalf("Tier = %s, want %s", got, c.tier)
			}
			// The stub runs no code, so it isolates, offers a device for
			// every template and is never under pressure.
			if !c.rt.IsolatesTenants() || !c.rt.OffersDevice("g", "gpu") {
				t.Fatal("the stub must isolate and offer devices")
			}
			if p, err := c.rt.Pressure("g"); p != 0 || err != nil {
				t.Fatalf("Pressure = %v, %v; want 0, nil", p, err)
			}
			if err := c.rt.PrepareTemplate(context.Background(), core.Grant{TemplateDigest: "sha256:t"}); err != nil {
				t.Fatalf("PrepareTemplate: %v", err)
			}
		})
	}
}

// TestClone covers birth from the template. W comes from the payload, and
// a fiber over its W or device budget is OOM-killed at once.
func TestClone(t *testing.T) {
	fence := core.Fence{GrantUID: "g", Epoch: 1, Seq: 1}
	cases := []struct {
		name    string
		grant   core.Grant
		payload string
		wantW   uint64
		oom     string // the exit detail's prefix when the fiber is killed
	}{
		{name: "no payload dirties nothing"},
		{name: "the payload's dirty bytes are W", payload: `{"dirty_bytes": 4096}`, wantW: 4096},
		{name: "a malformed payload is ignored", payload: `{not json`},
		{name: "W at the budget lives", grant: core.Grant{WBudgetBytes: 10}, payload: `{"dirty_bytes": 10}`, wantW: 10},
		{name: "W over the budget is OOM-killed", grant: core.Grant{WBudgetBytes: 10}, payload: `{"dirty_bytes": 11}`,
			oom: "dirtied 11 > w_budget 10"},
		{name: "a device slice without a budget lives", payload: `{"device_bytes": 99}`},
		{name: "a device slice over the budget is OOM-killed", grant: core.Grant{DeviceBudget: core.DeviceBudget{Bytes: 5}},
			payload: `{"device_bytes": 6}`, oom: "device 6 > device_budget 5"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			rt := stub.New()
			h, err := rt.Clone(ctx, core.CloneSpec{Grant: c.grant, Fence: fence, Payload: []byte(c.payload)})
			if err != nil {
				t.Fatalf("Clone: %v", err)
			}
			if h.ID != fence.String() || !strings.HasPrefix(h.Endpoint, "tcp://127.0.0.1:") {
				t.Fatalf("handle = %+v", h)
			}
			listed, _ := rt.List(ctx)
			st, statErr := rt.Stats(ctx, h.ID)
			if c.oom != "" {
				select {
				case ex := <-rt.Exits():
					if ex.FiberID != h.ID || ex.Reason != "oom" || ex.Detail != c.oom {
						t.Fatalf("exit = %+v, want oom %q", ex, c.oom)
					}
				default:
					t.Fatal("no exit for a fiber over budget")
				}
				if len(listed) != 0 || statErr == nil {
					t.Fatalf("a killed fiber is still known: list %v, stats err %v", listed, statErr)
				}
				return
			}
			if len(rt.Exits()) != 0 {
				t.Fatal("a fiber within budget exited")
			}
			if !slices.Equal(listed, []core.FiberHandle{h}) {
				t.Fatalf("List = %v, want [%v]", listed, h)
			}
			if statErr != nil || st.WUsedBytes != c.wantW {
				t.Fatalf("Stats = %+v, %v; want W %d", st, statErr, c.wantW)
			}
		})
	}
}

// TestLifecycle walks one runtime through park, resume and release, in
// order: each step builds on the state the last one left.
func TestLifecycle(t *testing.T) {
	ctx := context.Background()
	rt := stub.New()
	f1 := core.Fence{GrantUID: "g", Epoch: 1, Seq: 1}
	f2 := core.Fence{GrantUID: "g", Epoch: 1, Seq: 2}
	f3 := core.Fence{GrantUID: "g", Epoch: 1, Seq: 3}
	var ref string

	steps := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"each clone gets its own endpoint", func(t *testing.T) {
			a, err := rt.Clone(ctx, core.CloneSpec{Fence: f1, Payload: []byte(`{"dirty_bytes": 100}`)})
			if err != nil {
				t.Fatal(err)
			}
			b, err := rt.Clone(ctx, core.CloneSpec{Fence: f3})
			if err != nil {
				t.Fatal(err)
			}
			if a.Endpoint == b.Endpoint {
				t.Fatalf("two fibers share %s", a.Endpoint)
			}
		}},
		{"parking an unknown fiber fails", func(t *testing.T) {
			if _, err := rt.Park(ctx, "nope", false); err == nil {
				t.Fatal("park of an unknown fiber succeeded")
			}
		}},
		{"park keeps the fiber's W in a delta and ends the fiber", func(t *testing.T) {
			var err error
			if ref, err = rt.Park(ctx, f1.String(), false); err != nil {
				t.Fatal(err)
			}
			if !rt.HasDelta(ref) {
				t.Fatalf("delta %s missing after park", ref)
			}
			if _, err := rt.Stats(ctx, f1.String()); err == nil {
				t.Fatal("a parked fiber still has stats")
			}
		}},
		{"an unknown delta does not resume", func(t *testing.T) {
			if _, err := rt.Clone(ctx, core.CloneSpec{Source: core.SourceDelta, Ref: "delta-x", Fence: f2}); err == nil {
				t.Fatal("clone from an unknown delta succeeded")
			}
		}},
		{"resume adds the payload's W to the delta's and consumes it", func(t *testing.T) {
			h, err := rt.Clone(ctx, core.CloneSpec{Source: core.SourceDelta, Ref: ref, Fence: f2, Payload: []byte(`{"dirty_bytes": 5}`)})
			if err != nil {
				t.Fatal(err)
			}
			if st, err := rt.Stats(ctx, h.ID); err != nil || st.WUsedBytes != 105 {
				t.Fatalf("Stats = %+v, %v; want W 105", st, err)
			}
			if rt.HasDelta(ref) {
				t.Fatal("the delta survived its resume")
			}
		}},
		{"release without discard keeps the fiber's delta", func(t *testing.T) {
			ref2, err := rt.Park(ctx, f2.String(), false)
			if err != nil {
				t.Fatal(err)
			}
			if err := rt.Release(ctx, f2.String(), false); err != nil || !rt.HasDelta(ref2) {
				t.Fatalf("release: %v, delta kept %v", err, rt.HasDelta(ref2))
			}
		}},
		{"release with discard drops the delta and the fiber", func(t *testing.T) {
			if err := rt.Release(ctx, f2.String(), true); err != nil || rt.HasDelta("delta-"+f2.String()) {
				t.Fatalf("release: %v, delta kept %v", err, rt.HasDelta("delta-"+f2.String()))
			}
			if err := rt.Release(ctx, f3.String(), true); err != nil {
				t.Fatal(err)
			}
			if l, _ := rt.List(ctx); len(l) != 0 {
				t.Fatalf("List = %v after every release", l)
			}
		}},
	}
	for _, st := range steps {
		if !t.Run(st.name, st.run) {
			return // later steps build on this one
		}
	}
}
