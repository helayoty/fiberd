//go:build linux

package gvisortest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
	gvisorbackend "github.com/helayoty/fiberd/pkg/backend/gvisor"
	"github.com/helayoty/fiberd/pkg/core"
)

// TestPooledHandOut drives the backend's pool with real runsc. Sandboxes
// restored ahead of their fibers wait on the pool socket, which is the
// agent's alone (0600 in a 0700 directory), serving nothing. Bind hands
// each a fence, an endpoint and a seed on that channel, and the first
// request answers the fence. The seed is fresh per hand-out, so a
// pooled fiber's random differs from an on-demand sibling's and from
// another pooled fiber's.
func TestPooledHandOut(t *testing.T) {
	cases := []struct {
		name string
		warm int
	}{
		{name: "warm 1", warm: 1},
		{name: "warm 3", warm: 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := filepath.Join(work, fmt.Sprintf("pool%d", time.Now().UnixNano()%1_000_000))
			b := gvisorbackend.New(gvisorbackend.Options{Rootfs: rootfs, StateDir: state}).(*gvisorbackend.Backend)
			if b.Tier() != core.TierSnapshot {
				t.Fatalf("gvisor backend not usable here: %v", b.ProbeErr())
			}
			t.Cleanup(b.Close)
			workDir := filepath.Join(t.TempDir(), "g")
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			w, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "pool", Template: backend.Template{Argv: []string{"/bin/refzygote", "--heap-mb", "32", "--gvisor"}},
				CgroupFD: -1, ProbeCgroupFD: cgroupLeaf(t), WorkDir: workDir})
			if err != nil {
				t.Fatalf("Warm: %v", err)
			}
			socks, err := filepath.Glob(filepath.Join(state, "agent", "*", "pool.sock"))
			if err != nil || len(socks) != 1 {
				t.Fatalf("pool sockets = %v (%v), want one", socks, err)
			}
			if st, err := os.Stat(socks[0]); err != nil || st.Mode().Perm() != 0o600 {
				t.Fatalf("pool socket mode = %v (%v), want 0600", st.Mode(), err)
			}
			if st, err := os.Stat(filepath.Dir(socks[0])); err != nil || st.Mode().Perm() != 0o700 {
				t.Fatalf("agent directory mode = %v (%v), want 0700", st.Mode(), err)
			}
			var pooled []backend.Pooled
			t0 := time.Now()
			for i := 0; i < tc.warm; i++ {
				p, err := b.Pool(ctx, w.ID, backend.PoolSpec{CgroupFD: -1, Deadline: 10 * time.Second})
				if err != nil {
					t.Fatalf("Pool %d: %v", i, err)
				}
				pooled = append(pooled, p)
			}
			t.Logf("%d pooled in %s", tc.warm, time.Since(t0).Round(time.Millisecond))
			// Nothing serves before the hand-out: the run directory holds
			// no endpoint of theirs.
			if socks, _ := filepath.Glob(filepath.Join(workDir, "*.sock")); len(socks) != 0 {
				t.Fatalf("the run directory holds %v before any hand-out", socks)
			}
			seen := map[string]bool{}
			for i, p := range pooled {
				fence := fmt.Sprintf("pool/1-%d", i+1)
				ep := filepath.Join(workDir, fmt.Sprintf("p%d.sock", i))
				t0 := time.Now()
				fb, err := b.Bind(ctx, p.ID, backend.FiberSpec{Fence: fence, Endpoint: ep, CgroupFD: -1, Deadline: 5 * time.Second})
				if err != nil {
					t.Fatalf("Bind %s: %v", p.ID, err)
				}
				t.Logf("%s handed out as %s in %s", p.ID, fence, time.Since(t0).Round(time.Millisecond))
				if fb.ID != fence || fb.PID != p.PID {
					t.Fatalf("Bind = %+v, want %s with pid %d", fb, fence, p.PID)
				}
				if got := talk(t, "unix://"+ep, "fence"); got != fence {
					t.Fatalf("fence = %q, want %q", got, fence)
				}
				r := talk(t, "unix://"+ep, "random")
				if seen[r] {
					t.Fatalf("random = %q twice", r)
				}
				seen[r] = true
			}
			// An on-demand sibling draws differently too.
			ep := filepath.Join(workDir, "od.sock")
			if _, err := b.Clone(ctx, w.ID, backend.FiberSpec{Fence: "pool/1-9", Endpoint: ep, CgroupFD: -1, Deadline: 10 * time.Second}); err != nil {
				t.Fatalf("Clone: %v", err)
			}
			if r := talk(t, "unix://"+ep, "random"); seen[r] {
				t.Fatalf("the on-demand fiber's random %q repeats a pooled one's", r)
			}
			if got := talk(t, "unix://"+ep, "fence"); got != "pool/1-9" {
				t.Fatalf("fence = %q", got)
			}
		})
	}
}
