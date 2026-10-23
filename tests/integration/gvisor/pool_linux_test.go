//go:build linux && integration

package gvisortest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
	gvisorbackend "github.com/helayoty/fiberd/pkg/backend/gvisor"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/runtime/host"
)

// TestPooledHandOut drives the backend's pool with real runsc. Sandboxes
// restored ahead of their fibers wait on the pool socket, which is the
// fiberd's alone (0600 in a 0700 directory), serving nothing. Bind hands
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
			socks, err := filepath.Glob(filepath.Join(state, "channel", "*", "pool.sock"))
			if err != nil || len(socks) != 1 {
				t.Fatalf("pool sockets = %v (%v), want one", socks, err)
			}
			if st, err := os.Stat(socks[0]); err != nil || st.Mode().Perm() != 0o600 {
				t.Fatalf("pool socket mode = %v (%v), want 0600", st.Mode(), err)
			}
			if st, err := os.Stat(filepath.Dir(socks[0])); err != nil || st.Mode().Perm() != 0o700 {
				t.Fatalf("channel directory mode = %v (%v), want 0700", st.Mode(), err)
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
				fb, err := b.Bind(ctx, p.ID, backend.FiberSpec{Fence: fence, Endpoint: ep, CgroupFD: -1, Deadline: 5 * time.Second, Generation: 1})
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
			if _, err := b.Clone(ctx, w.ID, backend.FiberSpec{Fence: "pool/1-9", Endpoint: ep, CgroupFD: -1, Deadline: 10 * time.Second, Generation: 1}); err != nil {
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

// runscList lists the sandboxes alive in the backend's runsc root.
func runscList(t *testing.T, state string) []string {
	t.Helper()
	out, err := exec.Command("runsc", "--root="+filepath.Join(state, "root"), "list", "-quiet").CombinedOutput()
	if err != nil {
		t.Fatalf("runsc list: %v: %s", err, out)
	}
	return strings.Fields(string(out))
}

// TestPooledRevocation checks that nothing of a grant's pool survives
// the grant going through the host: no pool leaf and no sandbox, whether
// the template is dropped or a new life sweeps the old one's.
func TestPooledRevocation(t *testing.T) {
	cases := []struct {
		name string
		// revoke ends the grant on rt, whose cgroups and state are named name.
		revoke func(t *testing.T, rt *host.Runtime, name string)
	}{
		{name: "yield or remove drops the template", revoke: func(t *testing.T, rt *host.Runtime, _ string) {
			rt.DropTemplate("g1")
		}},
		{name: "a restart sweeps the previous life", revoke: func(t *testing.T, _ *host.Runtime, name string) {
			state := filepath.Join(work, name)
			r2, err := host.New(host.Config{
				Backend:       gvisorbackend.New(gvisorbackend.Options{Rootfs: rootfs, StateDir: state}),
				Templates:     map[string]string{"default": "/bin/refzygote --heap-mb 32 --gvisor"},
				CgroupRoot:    filepath.Join(cgRoot, name),
				RunDir:        filepath.Join("/tmp", "fz-"+name),
				DeltaDir:      filepath.Join(state, "deltas"),
				TemplateCache: filepath.Join(work, "templates"),
			})
			if err != nil {
				t.Fatalf("New over the old root: %v", err)
			}
			t.Cleanup(r2.Close)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRuntimeWith(t, "/bin/refzygote --heap-mb 32 --gvisor").(*host.Runtime)
			life := name
			state := filepath.Join(work, life)
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			g := core.Grant{UID: "g1", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatalf("prepare: %v", err)
			}
			for i := 0; i < 2; i++ {
				if err := rt.Fill(ctx, g, 20*time.Second); err != nil {
					t.Fatalf("Fill %d: %v", i, err)
				}
			}
			h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g1", Epoch: 1, Seq: 1}, Deadline: 10 * time.Second})
			if err != nil || !h.Pooled {
				t.Fatalf("Clone = %+v %v, want a pooled fiber", h, err)
			}
			if got := talk(t, h.Endpoint, "fence"); got != h.ID {
				t.Fatalf("fence = %q, want %q", got, h.ID)
			}
			pool := filepath.Join(cgRoot, life, "g1", "fibers", "pool")
			if leaves, _ := filepath.Glob(filepath.Join(pool, "p-*")); len(leaves) != 2 || rt.Pooled("g1") != 1 {
				t.Fatalf("pool leaves %v, pooled %d, want two leaves and one waiting", leaves, rt.Pooled("g1"))
			}
			if err := rt.Release(ctx, h.ID, false); err != nil {
				t.Fatalf("Release: %v", err)
			}
			tc.revoke(t, rt, life)
			if leaves, _ := filepath.Glob(filepath.Join(pool, "p-*")); len(leaves) != 0 {
				t.Fatalf("pool leaves %v after the revocation, want none", leaves)
			}
			// The reaper deletes each sandbox once it has exited, and the
			// old life hears of its pooled sandbox's end the same way.
			deadline := time.Now().Add(10 * time.Second)
			for {
				alive := runscList(t, state)
				if len(alive) == 0 && rt.Pooled("g1") == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("after the revocation: sandboxes alive %v, pooled %d", alive, rt.Pooled("g1"))
				}
				time.Sleep(50 * time.Millisecond)
			}
		})
	}
}
