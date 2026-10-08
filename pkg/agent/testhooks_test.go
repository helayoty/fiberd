//go:build fiberd_testhooks

package agent_test

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/helayoty/fiberd/pkg/agent"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/home"
)

// bareHome is a home without a lane override. Embedding home.Home
// promotes only the interface's methods, so SetLane is not one of them.
type bareHome struct{ home.Home }

// TestAdminControls: the test-only admin controls refuse unless the agent
// runs with -admin-unsafe. With it, POST /lane drives the home's lane and
// POST /scope-lost bumps the epoch.
func TestAdminControls(t *testing.T) {
	cases := []struct {
		name       string
		unsafe     bool
		bare       bool // the home has no lane override
		breakEpoch bool // the epoch cannot be persisted
		path, body string
		wantCode   int
		want       map[string]any // fields of the reply
		wantBump   uint64         // how far the epoch moves
	}{
		{name: "lane refused without -admin-unsafe", path: "/lane", body: `{"healthy":false}`, wantCode: http.StatusForbidden},
		{name: "scope-lost refused without -admin-unsafe", path: "/scope-lost", wantCode: http.StatusForbidden},
		{name: "lane with a bad body", unsafe: true, path: "/lane", body: `{"healthy":`, wantCode: http.StatusBadRequest},
		{name: "lane on a home without an override", unsafe: true, bare: true, path: "/lane", body: `{"healthy":false}`,
			wantCode: http.StatusNotImplemented},
		{name: "lane down", unsafe: true, path: "/lane", body: `{"healthy":false}`, wantCode: http.StatusOK,
			want: map[string]any{"grantLaneHealthy": false}},
		{name: "lane up", unsafe: true, path: "/lane", body: `{"healthy":true}`, wantCode: http.StatusOK,
			want: map[string]any{"grantLaneHealthy": true}},
		{name: "scope-lost bumps the epoch", unsafe: true, path: "/scope-lost", wantCode: http.StatusOK, wantBump: 1},
		{name: "scope-lost with an unwritable epoch", unsafe: true, breakEpoch: true, path: "/scope-lost",
			wantCode: http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := stateDir(t)
			nh := agent.Standalone
			if tc.bare {
				nh = func(c *agent.Config, jwks *grant.Cache) (home.Home, error) {
					h, err := agent.Standalone(c, jwks)
					return bareHome{h}, err
				}
			}
			var args []string
			if tc.unsafe {
				args = append(args, "-admin-unsafe")
			}
			r := start(t, newConfig(t, state, args...), nh)
			before := epochOf(t, r.c)
			if tc.breakEpoch {
				epoch := filepath.Join(state, "private", "epoch")
				if err := os.Remove(epoch); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Join(epoch, "x"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			code, out := adminDo(t, r.c, http.MethodPost, tc.path, tc.body)
			if code != tc.wantCode {
				t.Fatalf("POST %s = %d, want %d", tc.path, code, tc.wantCode)
			}
			for k, v := range tc.want {
				if out[k] != v {
					t.Fatalf("reply %s = %v, want %v (%v)", k, out[k], v, out)
				}
			}
			after := epochOf(t, r.c)
			if after != before+tc.wantBump {
				t.Fatalf("epoch %d -> %d, want +%d", before, after, tc.wantBump)
			}
			if tc.wantBump > 0 && out["epoch"] != float64(after) {
				t.Fatalf("reply epoch %v, want %d", out["epoch"], after)
			}
			if err := r.stop(t); err != nil {
				t.Fatal(err)
			}
			noRunGoroutines(t)
		})
	}
}
