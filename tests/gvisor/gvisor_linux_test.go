//go:build linux

package gvisortest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gvisorbackend "github.com/helayoty/fiberd/pkg/backend/gvisor"
	"github.com/helayoty/fiberd/pkg/core"
	fiberendpoint "github.com/helayoty/fiberd/pkg/endpoint"
	"github.com/helayoty/fiberd/pkg/runtime/host"
)

var (
	rootfs string
	cgRoot = os.Getenv("FIBERD_CGROUP_ROOT")
	work   = "/var/lib/fiberd-test/gvisor" // not tmpfs: images are memory there
)

func TestMain(m *testing.M) {
	if cgRoot == "" {
		cgRoot = "/sys/fs/cgroup/fiberd"
	}
	if f, err := os.OpenFile(filepath.Join(cgRoot, "cgroup.subtree_control"), os.O_WRONLY, 0); err != nil {
		fmt.Fprintf(os.Stderr, "skipping gvisor tests: %s not writable (run under make linux-test)\n", cgRoot)
		os.Exit(0)
	} else {
		_ = f.Close()
	}
	if _, err := exec.LookPath("runsc"); err != nil {
		fmt.Fprintln(os.Stderr, "skipping gvisor tests: runsc not installed")
		os.Exit(0)
	}
	_ = os.RemoveAll(work)
	rootfs = filepath.Join(work, "rootfs")
	build := exec.Command("../../hack/gvisor/rootfs.sh", rootfs)
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "skipping gvisor tests: cannot build the rootfs: %v\n", err)
		os.Exit(0)
	}
	code := m.Run()
	_ = os.RemoveAll(work)
	os.Exit(code)
}

var name string // the current runtime's name: its cgroup and directories

func newRuntime(t *testing.T) core.Runtime {
	t.Helper()
	name = fmt.Sprintf("gv%d", time.Now().UnixNano()%1_000_000)
	state := filepath.Join(work, name)
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		// The workloads' stderr, for a post-mortem.
		outs, _ := filepath.Glob(filepath.Join(state, "runsc-*.out"))
		for _, o := range outs {
			if data, err := os.ReadFile(o); err == nil && len(data) > 0 {
				t.Logf("%s:\n%s", filepath.Base(o), data)
			}
		}
	})
	rt, err := host.New(host.Config{
		Backend:    gvisorbackend.New(gvisorbackend.Options{Rootfs: rootfs, StateDir: state, Debug: true}),
		Templates:  map[string]string{"default": "/bin/refzygote --heap-mb 64 --gvisor"},
		CgroupRoot: filepath.Join(cgRoot, name),
		RunDir:     filepath.Join("/tmp", "fz-"+name),
		DeltaDir:   filepath.Join(work, name, "deltas"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rt.(interface{ Close() }).Close() })
	if rt.Tier() < core.TierSnapshot {
		t.Skip("gvisor backend not usable here")
	}
	return rt
}

func talk(t *testing.T, endpoint, line string) string {
	t.Helper()
	dctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := fiberendpoint.Dial(dctx, endpoint)
	if err != nil {
		t.Fatalf("dial %s: %v", endpoint, err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintln(c, line); err != nil {
		t.Fatalf("%s: %v", line, err)
	}
	reply, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("%s: %v", line, err)
	}
	return strings.TrimSpace(reply)
}

func TestSandboxPerFiber(t *testing.T) {
	rt := newRuntime(t)
	ctx := context.Background()
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20}
	t0 := time.Now()
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	t.Logf("template warm (sandbox + self-checkpoint) in %s", time.Since(t0).Round(time.Millisecond))

	var hs []core.FiberHandle
	for i := 1; i <= 3; i++ {
		t0 = time.Now()
		h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g1", Epoch: 1, Seq: uint64(i)}, Deadline: 2 * time.Second})
		if err != nil {
			t.Fatalf("clone %d: %v", i, err)
		}
		t.Logf("fiber %d restored and serving in %s", i, time.Since(t0).Round(time.Millisecond))
		if got := talk(t, h.Endpoint, "ping"); got != "pong" {
			t.Fatalf("ping = %q", got)
		}
		if got := talk(t, h.Endpoint, "fence"); got != h.ID {
			t.Fatalf("fence = %q, want %q", got, h.ID)
		}
		hs = append(hs, h)
	}
	// Each sandbox is its own: counters do not bleed.
	talk(t, hs[0].Endpoint, "incr")
	talk(t, hs[0].Endpoint, "incr")
	if got := talk(t, hs[1].Endpoint, "get"); got != "0" {
		t.Fatalf("fiber 2 counter = %q, want 0", got)
	}
	// W is the leaf's memory.current above the template's measured
	// footprint: a fresh fiber sits near zero (within the sandbox's own
	// variance) and growing the working set moves it by that much.
	leafCurrent := func() string {
		data, _ := os.ReadFile(filepath.Join(cgRoot, name, "g1", "f-1-1", "memory.current"))
		return strings.TrimSpace(string(data))
	}
	// What the leaves are made of: anon and shmem (the sandbox's guest
	// memory lives in a memfd) against file cache, which is reclaimable
	// and varies from sandbox to sandbox.
	statOf := func(leaf string) string {
		data, _ := os.ReadFile(filepath.Join(cgRoot, name, "g1", leaf, "memory.stat"))
		var keep []string
		for _, l := range strings.Split(string(data), "\n") {
			for _, k := range []string{"anon ", "file ", "shmem ", "kernel "} {
				if strings.HasPrefix(l, k) {
					f := strings.Fields(l)
					var n uint64
					_, _ = fmt.Sscan(f[1], &n)
					keep = append(keep, fmt.Sprintf("%s%dM", f[0], n>>20))
				}
			}
		}
		return strings.Join(keep, " ")
	}
	t.Logf("leaf f-1-1: %s | f-1-2: %s | f-1-3: %s", statOf("f-1-1"), statOf("f-1-2"), statOf("f-1-3"))
	st0, err := rt.Stats(ctx, hs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	rss0, cur0 := talk(t, hs[0].Endpoint, "rss"), leafCurrent()
	if got := talk(t, hs[0].Endpoint, "dirty 33554432"); got != "ok 33554432" {
		t.Fatalf("dirty = %q", got)
	}
	rss1, cur1 := talk(t, hs[0].Endpoint, "rss"), leafCurrent()
	st1, err := rt.Stats(ctx, hs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("fiber 1 W: %d MiB fresh, %d MiB after growing by 32 MiB (guest rss %s -> %s, leaf memory.current %s -> %s)",
		st0.WUsedBytes>>20, st1.WUsedBytes>>20, rss0, rss1, cur0, cur1)
	t.Logf("leaf f-1-1 after growth: %s", statOf("f-1-1"))
	if grew := int64(st1.WUsedBytes) - int64(st0.WUsedBytes); grew < 20<<20 || grew > 44<<20 {
		t.Fatalf("W grew by %d bytes, want about 32 MiB", grew)
	}
	if st0.WUsedBytes > 32<<20 {
		t.Fatalf("fresh fiber W = %d MiB, want within the sandbox's own variance of the template footprint", st0.WUsedBytes>>20)
	}
	// Everything runs in the fiber leaves: List sees them.
	list, err := rt.List(ctx)
	if err != nil || len(list) != 3 {
		t.Fatalf("List = %v (%v), want 3 fibers", list, err)
	}
	for _, h := range hs {
		if err := rt.Release(ctx, h.ID, false); err != nil {
			t.Fatalf("release %s: %v", h.ID, err)
		}
	}
	if list, _ := rt.List(ctx); len(list) != 0 {
		t.Fatalf("after release List = %v", list)
	}
}

func TestParkResumeKeepsState(t *testing.T) {
	rt := newRuntime(t)
	ctx := context.Background()
	g := core.Grant{UID: "g2", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g2", Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		talk(t, h.Endpoint, "incr")
	}
	t0 := time.Now()
	ref, err := rt.Park(ctx, h.ID, true)
	if err != nil {
		t.Fatalf("park: %v", err)
	}
	t.Logf("parked in %s -> %s", time.Since(t0).Round(time.Millisecond), ref)
	if _, err := os.Stat(fiberendpoint.UnixPath(h.Endpoint)); err == nil {
		t.Fatal("endpoint still present after park")
	}
	if list, _ := rt.List(ctx); len(list) != 0 {
		t.Fatalf("after park List = %v, want empty", list)
	}
	t0 = time.Now()
	h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref,
		Fence: core.Fence{GrantUID: "g2", Epoch: 1, Seq: 2}, Deadline: 5 * time.Second})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	t.Logf("resumed in %s at %s", time.Since(t0).Round(time.Millisecond), h2.Endpoint)
	if got := talk(t, h2.Endpoint, "get"); got != "3" {
		t.Fatalf("counter after resume = %q, want 3", got)
	}
	if got := talk(t, h2.Endpoint, "fence"); got != h2.ID {
		t.Fatalf("fence after resume = %q, want the new fence %q", got, h2.ID)
	}
	// Park again without sync (the checkpoint ends the sandbox) and resume
	// once more: state accumulates across incarnations.
	talk(t, h2.Endpoint, "incr")
	ref2, err := rt.Park(ctx, h2.ID, false)
	if err != nil {
		t.Fatalf("second park: %v", err)
	}
	h3, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref2,
		Fence: core.Fence{GrantUID: "g2", Epoch: 1, Seq: 3}, Deadline: 5 * time.Second})
	if err != nil {
		t.Fatalf("second resume: %v", err)
	}
	if got := talk(t, h3.Endpoint, "get"); got != "4" {
		t.Fatalf("counter after second resume = %q, want 4", got)
	}
	_ = rt.Release(ctx, h3.ID, true)
}

func TestDeadlineAndOOM(t *testing.T) {
	rt := newRuntime(t)
	ctx := context.Background()
	g := core.Grant{UID: "g3", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 8 << 20}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	// A fiber that takes longer than the deadline to serve is a miss.
	dctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	_, err := rt.Clone(dctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g3", Epoch: 1, Seq: 1}, Deadline: 300 * time.Millisecond,
		Payload: []byte(`{"ready_delay_ms": 1500}`)})
	cancel()
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("late fiber: err = %v, want deadline exceeded", err)
	}
	// Over the W budget (8 MiB above the template's measured footprint):
	// the kernel kills the sandbox and the exit is reported as oom.
	h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g3", Epoch: 1, Seq: 2}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	if st, err := rt.Stats(ctx, h.ID); err == nil {
		t.Logf("fresh fiber W = %d MiB above the template footprint", st.WUsedBytes>>20)
	}
	c, err := fiberendpoint.Dial(ctx, h.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fmt.Fprintln(c, "dirty 67108864") // grow by 64 MiB against an 8 MiB budget
	_ = c.Close()
	select {
	case e := <-rt.Exits():
		if e.FiberID != h.ID {
			t.Fatalf("exit for %s, want %s", e.FiberID, h.ID)
		}
		t.Logf("exit: %s %s", e.Reason, e.Detail)
		if e.Reason != "oom" {
			t.Fatalf("reason = %s, want oom", e.Reason)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("no exit after dirtying past the budget")
	}
}
