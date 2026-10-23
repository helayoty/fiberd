//go:build linux && integration

package hosttest

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/endpoint"
	"github.com/helayoty/fiberd/pkg/runtime/host"
	"github.com/helayoty/fiberd/pkg/sys/cgroup"
)

var sized = core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 2, WBudgetBytes: 64 * mib}

// TestLeafCeilings checks the limits the kernel accepts on a fiber's
// leaf, and that the kernel's own kill at memory.max reaches the host
// as an oom exit.
func TestLeafCeilings(t *testing.T) {
	cases := []struct {
		name  string
		be    func() backend.Backend
		check func(t *testing.T, r *host.Runtime, be backend.Backend, h core.FiberHandle)
	}{
		{name: "a fork backend's leaf: the budget, group OOM, no swap, a task limit under the grant's",
			be: func() backend.Backend { return newFake(core.TierWarm) },
			check: func(t *testing.T, r *host.Runtime, _ backend.Backend, _ core.FiberHandle) {
				leaf, gcg := leafOf(r, "g1", "f-1-1"), cgroup.Root(r.CgroupRoot()).Child("g1")
				if cgFile(t, leaf, "memory.max") != strconv.Itoa(64*mib) || cgFile(t, leaf, "memory.oom.group") != "1" || cgFile(t, leaf, "memory.swap.max") != "0" {
					t.Fatalf("leaf memory.max %s oom.group %s swap.max %s", cgFile(t, leaf, "memory.max"), cgFile(t, leaf, "memory.oom.group"), cgFile(t, leaf, "memory.swap.max"))
				}
				leafPids, err := strconv.Atoi(cgFile(t, leaf, "pids.max"))
				if err != nil || leafPids <= 0 {
					t.Fatalf("leaf pids.max = %s, want a number", cgFile(t, leaf, "pids.max"))
				}
				// The grant's cap leaves room for FiberMax fibers and the warm instance.
				if got := cgFile(t, gcg, "pids.max"); got != strconv.Itoa((sized.FiberMax+1)*leafPids) {
					t.Fatalf("grant pids.max = %s, want %d", got, (sized.FiberMax+1)*leafPids)
				}
				if cgFile(t, gcg, "memory.high") == "max" || cgFile(t, gcg, "memory.swap.max") != "0" {
					t.Fatalf("grant memory.high %s swap.max %s, want a ceiling without swap", cgFile(t, gcg, "memory.high"), cgFile(t, gcg, "memory.swap.max"))
				}
			}},
		{name: "a sandbox backend's tenants get no task limit",
			be: func() backend.Backend { return sandbox{newFake(core.TierWarm)} },
			check: func(t *testing.T, r *host.Runtime, _ backend.Backend, _ core.FiberHandle) {
				leaf, gcg := leafOf(r, "g1", "f-1-1"), cgroup.Root(r.CgroupRoot()).Child("g1")
				if cgFile(t, leaf, "pids.max") != "max" || cgFile(t, gcg, "pids.max") != "max" {
					t.Fatalf("leaf pids.max %s grant pids.max %s, want both unlimited", cgFile(t, leaf, "pids.max"), cgFile(t, gcg, "pids.max"))
				}
			}},
		{name: "killed by the kernel for exceeding its budget: reported as oom",
			be: func() backend.Backend { return newFake(core.TierWarm) },
			check: func(t *testing.T, r *host.Runtime, be backend.Backend, h core.FiberHandle) {
				// A task of the test's own in the leaf allocates past the leaf's
				// memory.max, and the kernel's group OOM takes the leaf.
				leaf := leafOf(r, "g1", "f-1-1")
				startInLeaf(t, leaf, "exec dd if=/dev/zero of=/dev/null bs=256M count=1")
				waitFor(t, "the kernel to kill the leaf", func() bool { n, _ := leaf.OOMKills(); return n > 0 })
				be.(*fake).die(h.ID, "signal:SIGKILL")
				if e := waitExit(t, r); e.Reason != "oom" || !strings.HasPrefix(e.Detail, "signal:SIGKILL oom_kill=") {
					t.Fatalf("exit = %+v, want oom with the kill count", e)
				}
				waitFor(t, "the leaf to go", func() bool { return !leaf.Exists() })
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := tc.be()
			r, h := prepared(t, be, sized, nil)
			tc.check(t, r, be, h)
		})
	}
}

// refuseLeaves caps d at the descendants it has now, so the kernel refuses
// the next leaf with EAGAIN. Every cgroup v2 kernel enforces this, unlike a
// tiny memory.max, which only some kernels refuse a child under.
func refuseLeaves(t *testing.T, d cgroup.Dir) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(d.Path, "cgroup.stat"))
	if err != nil {
		t.Fatal(err)
	}
	n := ""
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "nr_descendants "); ok {
			n = v
		}
	}
	if n == "" {
		t.Fatal("no nr_descendants in cgroup.stat")
	}
	if err := os.WriteFile(filepath.Join(d.Path, "cgroup.max.descendants"), []byte(n), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestLeafRefused checks a clone under a grant cgroup the kernel lets no
// leaf more be made in: the error names the leaf, nothing is left behind
// and the backend is never asked. Lifting the cap lets the next clone in.
func TestLeafRefused(t *testing.T) {
	cases := []struct {
		name string
		lift bool // the cap is lifted before the second clone
	}{
		{name: "the cap holds"},
		{name: "the cap is lifted", lift: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := newFake(core.TierWarm)
			r := newRuntime(t, be, nil)
			ctx := context.Background()
			if err := r.PrepareTemplate(ctx, sized); err != nil {
				t.Fatal(err)
			}
			gcg := cgroup.Root(r.CgroupRoot()).Child("g1")
			refuseLeaves(t, gcg)
			clone := func(seq uint64) error {
				_, err := r.Clone(ctx, core.CloneSpec{Grant: sized, Fence: core.Fence{GrantUID: "g1", Epoch: 1, Seq: seq}})
				return err
			}
			if err := clone(1); err == nil || !strings.Contains(err.Error(), "f-1-1") {
				t.Fatalf("Clone = %v, want the leaf refused", err)
			}
			if leafOf(r, "g1", "f-1-1").Exists() || be.cloned() != 0 {
				t.Fatalf("leaf exists %v, %d clones asked, want nothing left and the backend never asked", leafOf(r, "g1", "f-1-1").Exists(), be.cloned())
			}
			if tc.lift {
				if err := os.WriteFile(filepath.Join(gcg.Path, "cgroup.max.descendants"), []byte("max"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			err := clone(2)
			if tc.lift && (err != nil || !leafOf(r, "g1", "f-1-2").Exists() || be.cloned() != 1) {
				t.Fatalf("Clone after the lift = %v, leaf exists %v, %d clones", err, leafOf(r, "g1", "f-1-2").Exists(), be.cloned())
			}
			if !tc.lift && err == nil {
				t.Fatal("a second clone under the cap succeeded")
			}
		})
	}
}

// TestOrphanKilledInLeaf restarts fiberd over a leaf a previous life
// left with a live task. The release of that orphan kills the task
// through its leaf, waits for it to go, and removes the leaf and the
// files it served on.
func TestOrphanKilledInLeaf(t *testing.T) {
	cases := []struct {
		name    string
		command string // what runs in the orphan's leaf
	}{
		{name: "one task", command: "exec sleep 300"},
		{name: "a task and its child", command: "sleep 300 & wait"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, h := prepared(t, newFake(core.TierWarm), sized, nil)
			orphan := core.Fence{GrantUID: "g1", Epoch: 5, Seq: 5}
			leaf := leafOf(r, "g1", "f-5-5")
			if err := leaf.Create(0, false); err != nil {
				t.Fatal(err)
			}
			pid := startInLeaf(t, leaf, tc.command)
			// The orphan served beside the live fiber, in the grant's run directory.
			sock := filepath.Join(filepath.Dir(endpoint.UnixPath(h.Endpoint)), "5-5.sock")
			if err := os.WriteFile(sock, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			list, err := r.List(ctx)
			if err != nil || len(list) != 1 || list[0].ID != orphan.String() {
				t.Fatalf("List = %+v %v, want the orphan alone", list, err)
			}
			if err := r.Release(ctx, orphan.String(), false); err != nil {
				t.Fatal(err)
			}
			if leaf.Exists() || exists(sock) {
				t.Fatal("the orphan's leaf or socket remain")
			}
			// The task is dead, reaped or not, so it only answers as a zombie.
			if st, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat"); err == nil && !strings.Contains(string(st), ") Z ") {
				t.Fatalf("the orphan's task %d is still alive: %s", pid, st)
			}
			if list, err := r.List(ctx); err != nil || len(list) != 0 {
				t.Fatalf("List after the release = %+v %v", list, err)
			}
		})
	}
}

// TestWBytesOfLiveTask checks what a fiber's working set reads as when a
// task of the test's own runs in its leaf: the leaf's count for a fork
// backend, less the fixed footprint for a sandbox.
func TestWBytesOfLiveTask(t *testing.T) {
	cases := []struct {
		name string
		be   func() backend.Backend
		// positive is whether W must be above zero. Otherwise it must be 0.
		positive bool
	}{
		{name: "a fork backend reads the leaf's memory.current", be: func() backend.Backend { return newFake(core.TierWarm) }, positive: true},
		{name: "a sandbox's fixed footprint is subtracted from the leaf's count", be: func() backend.Backend {
			b := newFake(core.TierWarm)
			b.warm = backend.Warm{Bytes: 1 << 40}
			return sandbox{b}
		}},
		{name: "a sandbox's own count before the hand-out beats the template's probe", be: func() backend.Backend {
			b := newFake(core.TierWarm)
			b.warm = backend.Warm{Bytes: 1 << 40}
			b.footprint = 1
			return sandbox{b}
		}, positive: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, h := prepared(t, tc.be(), core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl"}, nil)
			leaf := leafOf(r, "g1", "f-1-1")
			startSleeper(t, leaf)
			// The sleeper joins the leaf after Start returns, so wait for its
			// pages there, or every case reads 0.
			waitFor(t, "the sleeper's pages in the leaf", func() bool {
				n, err := leaf.MemoryCurrent()
				return err == nil && n > 0
			})
			st, err := r.Stats(context.Background(), h.ID)
			if err != nil || (st.WUsedBytes > 0) != tc.positive {
				t.Fatalf("Stats = %+v %v, want W above zero %v", st, err, tc.positive)
			}
		})
	}
}

// TestBootSweepsPool checks that a new life kills and removes the pool
// leaves of the previous one before it serves, the sandboxes still in
// them included, and that List never reports them.
func TestBootSweepsPool(t *testing.T) {
	cases := []struct {
		name  string
		procs bool // the leaf still holds the sandbox
	}{
		{name: "a leaf holding a sandbox", procs: true},
		{name: "an empty leaf", procs: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t, newFake(core.TierWarm))
			root := cgroup.Root(cfg.CgroupRoot)
			g1 := root.Child("g1").Child("fibers")
			pool := g1.Child("pool")
			for _, d := range []cgroup.Dir{root, root.Child("g1"), g1, pool} {
				if err := d.Ensure("memory", "pids"); err != nil {
					t.Fatal(err)
				}
			}
			stale, live := pool.Child("p-7"), g1.Child("f-1-1")
			for _, d := range []cgroup.Dir{stale, live} {
				if err := d.Create(0, false); err != nil {
					t.Fatal(err)
				}
			}
			startSleeper(t, live)
			if tc.procs {
				startSleeper(t, stale)
			}
			r, err := host.New(cfg)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(r.Close)
			if stale.Exists() || pool.Exists() {
				t.Fatalf("after New: %s exists %v, %s exists %v", stale.Path, stale.Exists(), pool.Path, pool.Exists())
			}
			list, err := r.List(context.Background())
			if err != nil || len(list) != 1 || list[0].ID != "g1/1/1" {
				t.Fatalf("List = %+v %v, want the one fiber leaf", list, err)
			}
		})
	}
}

// fileOwner is the uid owning path.
func fileOwner(t *testing.T, path string) uint32 {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Sys().(*syscall.Stat_t).Uid
}

// TestDelegateProcs checks that an id-mapping backend's grant gets the
// cgroup.procs of its cgroup and of every leaf handed to its mapped
// root, a foreign uid, and nothing else. A mapper that refuses the
// grant stops everything before a cgroup is made.
func TestDelegateProcs(t *testing.T) {
	cases := []struct {
		name    string
		be      func() backend.Backend
		wantErr string
	}{
		{name: "cgroup.procs is handed to the mapped root", be: func() backend.Backend {
			return &mapped{fake: newFake(core.TierWarm), uid: 100000}
		}},
		{name: "the mapper refuses", be: func() backend.Backend {
			return &mapped{fake: newFake(core.TierWarm), err: os.ErrPermission}
		}, wantErr: "permission"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := tc.be()
			r := newRuntime(t, be, nil)
			ctx := context.Background()
			gcg := cgroup.Root(r.CgroupRoot()).Child("g1")
			err := r.PrepareTemplate(ctx, sized)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("PrepareTemplate = %v, want an error mentioning %q", err, tc.wantErr)
				}
				if gcg.Exists() {
					t.Fatal("a refused grant got a cgroup")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.Clone(ctx, core.CloneSpec{Grant: sized, Fence: core.Fence{GrantUID: "g1", Epoch: 1, Seq: 1}}); err != nil {
				t.Fatal(err)
			}
			for _, d := range []cgroup.Dir{gcg.Child("fibers"), leafOf(r, "g1", "f-1-1")} {
				if got := fileOwner(t, filepath.Join(d.Path, "cgroup.procs")); got != 100000 {
					t.Fatalf("%s cgroup.procs owner = %d, want 100000", d.Path, got)
				}
				if got := fileOwner(t, filepath.Join(d.Path, "memory.max")); got != 0 {
					t.Fatalf("%s memory.max owner = %d, want root", d.Path, got)
				}
			}
		})
	}
}
