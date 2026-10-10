//go:build linux

package host

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/sys/cgroup"
)

var poolGrant = core.Grant{UID: "g1", TemplateDigest: "sha256:tmpl", FiberMax: 4, WBudgetBytes: 64 * mib}

// poolLeaf is the n-th pool leaf of the grant.
func poolLeaf(r *Runtime, n string) cgroup.Dir {
	return r.root.Child("g1").Child(poolDir).Child("p-" + n)
}

// fillOne fills the grant's pool with one sandbox and returns its id.
func fillOne(t *testing.T, r *Runtime, be *poolBackend) string {
	t.Helper()
	if err := r.Fill(context.Background(), poolGrant, time.Second); err != nil {
		t.Fatalf("Fill: %v", err)
	}
	ids := be.pooledIDs()
	if len(ids) != 1 {
		t.Fatalf("pooled in the backend = %v, want one", ids)
	}
	return ids[0]
}

// TestPoolLeaves checks that a pooled sandbox lives in a leaf with a
// fiber's limits, that the fiber it becomes keeps that leaf, and that
// every other end removes it.
func TestPoolLeaves(t *testing.T) {
	ctx := context.Background()
	fence := core.Fence{GrantUID: "g1", Epoch: 1, Seq: 1}
	cases := []struct {
		name string
		// act runs after one Fill, with the pooled sandbox's id.
		act       func(t *testing.T, r *Runtime, be *poolBackend, id string)
		leafStays bool // pool/p-1 exists afterwards
		pooled    int  // what Pooled reports afterwards
	}{
		{name: "a fill makes pool/p-1 with a fiber leaf's limits", leafStays: true, pooled: 1},
		{name: "a hand-out: the fiber keeps the leaf until its end", act: func(t *testing.T, r *Runtime, be *poolBackend, id string) {
			h, err := r.Clone(ctx, core.CloneSpec{Grant: poolGrant, Fence: fence, Deadline: time.Second})
			if err != nil || !h.Pooled {
				t.Fatalf("Clone = %+v %v, want a pooled fiber", h, err)
			}
			r.mu.Lock()
			f := r.fibers[h.ID]
			r.mu.Unlock()
			if f == nil || !f.pooled || f.cg.Path != poolLeaf(r, "1").Path || f.pid == 0 {
				t.Fatalf("fiber = %+v, want one in %s", f, poolLeaf(r, "1").Path)
			}
			if r.root.Child("g1").Child("f-1-1").Exists() {
				t.Fatal("a fresh leaf was made for a pooled fiber")
			}
			if ff := be.fiber(h.ID); ff == nil || ff.spec.CgroupFD < 0 || ff.spec.Deadline != time.Second || !ff.spec.OwnPIDNS {
				t.Fatalf("bound fiber = %+v", ff)
			}
			if r.Pooled("g1") != 0 || poolLeaf(r, "1").Exists() != true {
				t.Fatalf("after the hand-out: pooled %d, leaf exists %v", r.Pooled("g1"), poolLeaf(r, "1").Exists())
			}
			if err := r.Release(ctx, h.ID, false); err != nil {
				t.Fatalf("Release: %v", err)
			}
		}},
		{name: "a drain discards it", act: func(t *testing.T, r *Runtime, be *poolBackend, id string) {
			if n := r.Drain("g1", 1); n != 1 {
				t.Fatalf("Drain = %d, want 1", n)
			}
			if ids := be.discardedIDs(); len(ids) != 1 || ids[0] != id {
				t.Fatalf("discarded %v, want %s", ids, id)
			}
			noExit(t, r)
		}},
		{name: "a death before the hand-out", act: func(t *testing.T, r *Runtime, be *poolBackend, id string) {
			be.pooledDie(id, "exit:7")
			waitFor(t, "the leaf to go", func() bool { return !poolLeaf(r, "1").Exists() })
			noExit(t, r)
			if r.warmOf("g1") == nil {
				t.Fatal("the warm instance was forgotten")
			}
		}},
		{name: "an exit of a pooled sandbox the host does not hold is ignored", act: func(t *testing.T, r *Runtime, be *poolBackend, id string) {
			be.exits <- backend.Exit{PooledID: "p-nobody-9", Status: "exit:1"}
			noExit(t, r)
			if r.warmOf("g1") == nil {
				t.Fatal("the warm instance was forgotten")
			}
		}, leafStays: true, pooled: 1},
		{name: "the warm instance goes", act: func(t *testing.T, r *Runtime, be *poolBackend, id string) {
			be.warmGone("g1")
			waitFor(t, "the leaf to go", func() bool { return !poolLeaf(r, "1").Exists() })
			if ids := be.discardedIDs(); len(ids) != 1 || ids[0] != id {
				t.Fatalf("discarded %v, want %s", ids, id)
			}
			noExit(t, r)
		}},
		{name: "DropTemplate drains before Unwarm", act: func(t *testing.T, r *Runtime, be *poolBackend, id string) {
			r.DropTemplate("g1")
			if got := be.eventLog(); len(got) != 2 || got[0] != "discard "+id || got[1] != "unwarm g1" {
				t.Fatalf("events = %v, want the discard before the unwarm", got)
			}
		}},
		{name: "Close drains", act: func(t *testing.T, r *Runtime, be *poolBackend, id string) {
			r.Close()
			if ids := be.discardedIDs(); len(ids) != 1 || ids[0] != id {
				t.Fatalf("discarded %v, want %s", ids, id)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := newPoolBackend(core.TierWarm)
			r := newTestRuntime(t, be, nil)
			if err := r.PrepareTemplate(ctx, poolGrant); err != nil {
				t.Fatalf("PrepareTemplate: %v", err)
			}
			id := fillOne(t, r, be)
			leaf := poolLeaf(r, "1")
			if want := r.leafMax(poolGrant); !leaf.Exists() || cgUint(t, leaf, "memory.max") != want || want <= 64*mib ||
				cgFile(t, leaf, "memory.oom.group") != "1" || cgFile(t, leaf, "memory.swap.max") != "0" {
				t.Fatalf("leaf %s: exists %v memory.max %s, want a fiber leaf capped at %d", leaf.Path, leaf.Exists(), cgFile(t, leaf, "memory.max"), want)
			}
			be.pmu.Lock()
			spec := be.pooled[id].spec
			be.pmu.Unlock()
			if spec.CgroupFD < 0 || spec.Deadline != time.Second {
				t.Fatalf("pool spec = %+v", spec)
			}
			if tc.act != nil {
				tc.act(t, r, be, id)
			}
			if tc.leafStays {
				if !leaf.Exists() {
					t.Fatal("the leaf is gone")
				}
			} else {
				waitFor(t, "the leaf to go", func() bool { return !leaf.Exists() })
			}
			if got := r.Pooled("g1"); got != tc.pooled {
				t.Fatalf("Pooled = %d, want %d", got, tc.pooled)
			}
		})
	}
}

// TestFillRefused checks the fills that make no pooled sandbox, and
// that each leaves no leaf behind.
func TestFillRefused(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		be      func() backend.Backend
		prepare bool
		before  func(t *testing.T, r *Runtime, be backend.Backend)
		fill    func(t *testing.T, r *Runtime) error
		wantErr error
		errText string
		check   func(t *testing.T, r *Runtime, be backend.Backend)
	}{
		{name: "a backend without a pool", be: func() backend.Backend { return newFakeBackend(core.TierWarm) }, prepare: true, wantErr: backend.ErrNoPool},
		{name: "a template that does not bind late", be: func() backend.Backend {
			b := newPoolBackend(core.TierWarm)
			b.noPool = true
			return b
		}, prepare: true, wantErr: backend.ErrNoPool,
			check: func(t *testing.T, r *Runtime, _ backend.Backend) {
				if !r.warmOf("g1").noPool {
					t.Fatal("the warm instance was not marked as having no pool")
				}
			}},
		{name: "a grant that is not prepared", be: func() backend.Backend { return newPoolBackend(core.TierWarm) }, wantErr: ErrNotPrepared},
		{name: "no room under the grant's ceiling", be: func() backend.Backend { return newPoolBackend(core.TierWarm) }, prepare: true,
			before: func(t *testing.T, r *Runtime, _ backend.Backend) {
				if limitOf(r.root.Child("g1"), "memory.high") == 0 {
					t.Fatal("the grant has no memory.high")
				}
				r.mu.Lock()
				r.warms["g1"].total = 1 << 40
				r.mu.Unlock()
			}, wantErr: core.ErrPressure},
		{name: "the restore fails", be: func() backend.Backend {
			b := newPoolBackend(core.TierWarm)
			b.poolErr = errors.New("fake: restore refused")
			return b
		}, prepare: true, errText: "restore refused"},
		{name: "the template goes during the restore", be: func() backend.Backend {
			b := newPoolBackend(core.TierWarm)
			b.poolGate = make(chan struct{})
			return b
		}, prepare: true,
			fill: func(t *testing.T, r *Runtime) error {
				done := make(chan error, 1)
				go func() { done <- r.Fill(ctx, poolGrant, time.Second) }()
				waitFor(t, "the restore to begin", func() bool { return poolLeaf(r, "1").Exists() })
				r.DropTemplate("g1")
				close(r.be.(*poolBackend).poolGate)
				return <-done
			}, wantErr: ErrNotPrepared,
			check: func(t *testing.T, r *Runtime, be backend.Backend) {
				if ids := be.(*poolBackend).discardedIDs(); len(ids) != 1 {
					t.Fatalf("discarded %v, want the sandbox the fill made", ids)
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := tc.be()
			r := newTestRuntime(t, be, nil)
			if tc.prepare {
				if err := r.PrepareTemplate(ctx, poolGrant); err != nil {
					t.Fatalf("PrepareTemplate: %v", err)
				}
			}
			if tc.before != nil {
				tc.before(t, r, be)
			}
			var err error
			if tc.fill != nil {
				err = tc.fill(t, r)
			} else {
				err = r.Fill(ctx, poolGrant, time.Second)
			}
			switch {
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				t.Fatalf("Fill = %v, want %v", err, tc.wantErr)
			case tc.errText != "" && (err == nil || !strings.Contains(err.Error(), tc.errText)):
				t.Fatalf("Fill = %v, want an error mentioning %q", err, tc.errText)
			}
			waitFor(t, "no pool leaf to remain", func() bool {
				leaves, _ := r.root.Child("g1").Child(poolDir).Children("")
				return len(leaves) == 0
			})
			if r.Pooled("g1") != 0 {
				t.Fatalf("Pooled = %d after a refused fill", r.Pooled("g1"))
			}
			if tc.check != nil {
				tc.check(t, r, be)
			}
		})
	}
}

// TestBootSweepsPool checks that a new life kills and removes the pool
// leaves of the previous one before it serves, and that List never
// reports them.
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
			be := newPoolBackend(core.TierWarm)
			cfg := testConfig(t, be)
			root := cgroup.Root(cfg.CgroupRoot)
			g1 := root.Child("g1")
			pool := g1.Child(poolDir)
			for _, d := range []cgroup.Dir{root, g1, pool} {
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
			r, err := New(cfg)
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

// TestCloneTakesPool checks that a Clone is served from the pool when a
// sandbox waits there, restores on demand otherwise, and shares its
// deadline between a failed hand-out and the restore that follows.
func TestCloneTakesPool(t *testing.T) {
	ctx := context.Background()
	fence := core.Fence{GrantUID: "g1", Epoch: 1, Seq: 1}
	clone := core.CloneSpec{Grant: poolGrant, Fence: fence, Deadline: 2 * time.Second}
	cases := []struct {
		name    string
		tier    core.Tier
		fill    int
		mod     func(*Config)
		before  func(t *testing.T, r *Runtime, be *poolBackend)
		spec    func(t *testing.T, r *Runtime) core.CloneSpec
		wantErr error
		errText string
		pooled  bool // the handle says the fiber came from the pool
		check   func(t *testing.T, r *Runtime, be *poolBackend, h core.FiberHandle)
	}{
		{name: "the pool has one: handed out in its leaf", fill: 1, pooled: true,
			check: func(t *testing.T, r *Runtime, be *poolBackend, h core.FiberHandle) {
				r.mu.Lock()
				f := r.fibers[h.ID]
				r.mu.Unlock()
				if f == nil || f.cg.Path != poolLeaf(r, "1").Path || r.root.Child("g1").Child("f-1-1").Exists() || r.Pooled("g1") != 0 {
					t.Fatalf("fiber = %+v, pooled %d", f, r.Pooled("g1"))
				}
				if ff := be.fiber(h.ID); ff == nil || ff.spec.Deadline != 2*time.Second {
					t.Fatalf("bound fiber = %+v", ff)
				}
			}},
		{name: "the pool is empty: restored on demand",
			check: func(t *testing.T, r *Runtime, be *poolBackend, h core.FiberHandle) {
				if !r.root.Child("g1").Child("f-1-1").Exists() {
					t.Fatal("no fresh leaf")
				}
			}},
		{name: "the oldest goes first", fill: 2, pooled: true,
			check: func(t *testing.T, r *Runtime, be *poolBackend, h core.FiberHandle) {
				h2, err := r.Clone(ctx, core.CloneSpec{Grant: poolGrant, Fence: core.Fence{GrantUID: "g1", Epoch: 1, Seq: 2}})
				if err != nil || !h2.Pooled {
					t.Fatalf("second Clone = %+v %v", h2, err)
				}
				r.mu.Lock()
				first, second := r.fibers[h.ID].cg.Name(), r.fibers[h2.ID].cg.Name()
				r.mu.Unlock()
				if first != "p-1" || second != "p-2" || r.Pooled("g1") != 0 {
					t.Fatalf("leaves %s then %s, pooled %d", first, second, r.Pooled("g1"))
				}
			}},
		{name: "a failed hand-out restores on demand with the time left", fill: 1,
			before: func(t *testing.T, r *Runtime, be *poolBackend) {
				be.bindErr, be.bindDelay = errors.New("fake: no ack"), 50*time.Millisecond
			},
			check: func(t *testing.T, r *Runtime, be *poolBackend, h core.FiberHandle) {
				ff := be.fiber(h.ID)
				if ff == nil || ff.spec.Deadline >= 2*time.Second-50*time.Millisecond || ff.spec.Deadline < time.Second {
					t.Fatalf("on-demand fiber = %+v, want a deadline under 2s less the failed hand-out", ff)
				}
				waitFor(t, "the pool leaf to go", func() bool { return !poolLeaf(r, "1").Exists() })
				if !r.root.Child("g1").Child("f-1-1").Exists() || r.Pooled("g1") != 0 {
					t.Fatalf("fresh leaf exists %v, pooled %d", r.root.Child("g1").Child("f-1-1").Exists(), r.Pooled("g1"))
				}
				noExit(t, r)
			}},
		{name: "a failed hand-out's late exit does not end the on-demand fiber", fill: 1,
			before: func(t *testing.T, r *Runtime, be *poolBackend) {
				be.bindErr, be.bindExitDelay = errors.New("fake: no ack"), 200*time.Millisecond
			},
			check: func(t *testing.T, r *Runtime, be *poolBackend, h core.FiberHandle) {
				waitFor(t, "the killed sandbox's end to be reported", func() bool { return be.bindExits.Load() == 1 })
				noExit(t, r)
				r.mu.Lock()
				f := r.fibers[h.ID]
				r.mu.Unlock()
				if f == nil || !be.alive(h.ID) {
					t.Fatalf("the on-demand fiber was ended by the pooled sandbox's exit: host %+v, backend alive %v", f, be.alive(h.ID))
				}
			}},
		{name: "a failed hand-out with no time left", fill: 1,
			before: func(t *testing.T, r *Runtime, be *poolBackend) {
				be.bindErr, be.bindDelay = context.DeadlineExceeded, 50*time.Millisecond
			},
			spec: func(*testing.T, *Runtime) core.CloneSpec {
				s := clone
				s.Deadline = 30 * time.Millisecond
				return s
			}, wantErr: context.DeadlineExceeded,
			check: func(t *testing.T, r *Runtime, be *poolBackend, _ core.FiberHandle) {
				if be.fiber("g1/1/1") != nil || r.root.Child("g1").Child("f-1-1").Exists() {
					t.Fatal("a restore was tried with no time left")
				}
				waitFor(t, "the pool leaf to go", func() bool { return !poolLeaf(r, "1").Exists() })
				noExit(t, r)
			}},
		{name: "a failure before the hand-out keeps the sandbox pooled", fill: 1,
			mod: func(c *Config) { c.Endpoints = tcpPolicy },
			before: func(t *testing.T, r *Runtime, be *poolBackend) {
				r.mu.Lock()
				r.ports[20000], r.ports[20001] = "g1/9/1", "g1/9/2"
				r.mu.Unlock()
			}, errText: "no free endpoint port",
			check: func(t *testing.T, r *Runtime, be *poolBackend, _ core.FiberHandle) {
				if r.Pooled("g1") != 1 || !poolLeaf(r, "1").Exists() || len(be.discardedIDs()) != 0 {
					t.Fatalf("pooled %d, leaf exists %v, discarded %v", r.Pooled("g1"), poolLeaf(r, "1").Exists(), be.discardedIDs())
				}
			}},
		{name: "a resume never takes from the pool", tier: core.TierSnapshot, fill: 1,
			spec: func(t *testing.T, r *Runtime) core.CloneSpec {
				dir := filepath.Join(r.cfg.DeltaDir, "g1", "by-hand")
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				m := manifest{Fence: "g1/1/1", GrantUID: "g1", Endpoint: "unix://" + filepath.Join(r.cfg.RunDir, "g1", "1-1.sock"), Backend: "fake"}
				if err := writeJSON(filepath.Join(dir, "manifest.json"), m); err != nil {
					t.Fatal(err)
				}
				return core.CloneSpec{Grant: poolGrant, Source: core.SourceDelta, Ref: dir, Fence: core.Fence{GrantUID: "g1", Epoch: 2, Seq: 1}}
			},
			check: func(t *testing.T, r *Runtime, be *poolBackend, h core.FiberHandle) {
				if r.Pooled("g1") != 1 || !r.root.Child("g1").Child("f-2-1").Exists() {
					t.Fatalf("pooled %d, resumed leaf exists %v", r.Pooled("g1"), r.root.Child("g1").Child("f-2-1").Exists())
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tier := tc.tier
			if tier == core.TierUnspecified {
				tier = core.TierWarm
			}
			be := newPoolBackend(tier)
			r := newTestRuntime(t, be, tc.mod)
			if err := r.PrepareTemplate(ctx, poolGrant); err != nil {
				t.Fatalf("PrepareTemplate: %v", err)
			}
			for i := 0; i < tc.fill; i++ {
				if err := r.Fill(ctx, poolGrant, time.Second); err != nil {
					t.Fatalf("Fill %d: %v", i, err)
				}
			}
			if tc.before != nil {
				tc.before(t, r, be)
			}
			spec := clone
			if tc.spec != nil {
				spec = tc.spec(t, r)
			}
			h, err := r.Clone(ctx, spec)
			switch {
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				t.Fatalf("Clone = %v, want %v", err, tc.wantErr)
			case tc.errText != "" && (err == nil || !strings.Contains(err.Error(), tc.errText)):
				t.Fatalf("Clone = %v, want an error mentioning %q", err, tc.errText)
			case tc.wantErr == nil && tc.errText == "" && err != nil:
				t.Fatalf("Clone: %v", err)
			}
			if err == nil && h.Pooled != tc.pooled {
				t.Fatalf("handle = %+v, want Pooled %v", h, tc.pooled)
			}
			if tc.check != nil {
				tc.check(t, r, be, h)
			}
		})
	}
}
