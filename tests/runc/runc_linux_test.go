//go:build linux

package runctest

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	runcbackend "github.com/helayoty/fiberd/pkg/backend/runc"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/runtime/host"
)

var (
	rootfs string
	cgRoot = os.Getenv("FIBERD_CGROUP_ROOT")
	work   = "/var/lib/fiberd-test/runc"
)

func TestMain(m *testing.M) {
	if cgRoot == "" {
		cgRoot = "/sys/fs/cgroup/fiberd"
	}
	if f, err := os.OpenFile(filepath.Join(cgRoot, "cgroup.subtree_control"), os.O_WRONLY, 0); err != nil {
		fmt.Fprintf(os.Stderr, "skipping runc tests: %s not writable (run under make linux-test)\n", cgRoot)
		os.Exit(0)
	} else {
		_ = f.Close()
	}
	if _, err := exec.LookPath("runc"); err != nil {
		fmt.Fprintln(os.Stderr, "skipping runc tests: runc not installed")
		os.Exit(0)
	}
	_ = os.RemoveAll(work)
	rootfs = filepath.Join(work, "rootfs")
	build := exec.Command("../../hack/gvisor/rootfs.sh", rootfs)
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "skipping runc tests: cannot build the rootfs: %v\n", err)
		os.Exit(0)
	}
	code := m.Run()
	_ = os.RemoveAll(work)
	os.Exit(code)
}

func newRuntime(t *testing.T) core.Runtime {
	t.Helper()
	name := fmt.Sprintf("rc%d", time.Now().UnixNano()%1_000_000)
	rt, err := host.New(host.Config{
		Backend:    runcbackend.New(runcbackend.Options{Rootfs: rootfs, StateDir: filepath.Join(work, name)}),
		Templates:  map[string]string{"default": "/bin/refzygote --heap-mb 32"},
		CgroupRoot: filepath.Join(cgRoot, name),
		RunDir:     filepath.Join("/tmp", "fz-"+name),
		DeltaDir:   filepath.Join(work, name, "deltas"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rt.(interface{ Close() }).Close() })
	if rt.Tier() < core.TierCheckpoint {
		t.Skip("criu not usable here")
	}
	return rt
}

func talk(t *testing.T, endpoint, line string) string {
	t.Helper()
	c, err := net.DialTimeout("unix", strings.TrimPrefix(endpoint, "unix://"), 2*time.Second)
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

func TestForkInsideContainer(t *testing.T) {
	rt := newRuntime(t)
	ctx := context.Background()
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20}
	t0 := time.Now()
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	t.Logf("container warm (runc run + zygote init + self-checkpoint) in %s", time.Since(t0).Round(time.Millisecond))
	var hs []core.FiberHandle
	for i := 1; i <= 3; i++ {
		t0 = time.Now()
		h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g1", Epoch: 1, Seq: uint64(i)}, Deadline: time.Second})
		if err != nil {
			t.Fatalf("clone %d: %v", i, err)
		}
		t.Logf("fiber %d forked and serving in %s", i, time.Since(t0).Round(time.Millisecond))
		if got := talk(t, h.Endpoint, "ping"); got != "pong" {
			t.Fatalf("ping = %q", got)
		}
		hs = append(hs, h)
	}
	// Scrubbed and namespaced: the fiber is init of its own pid namespace
	// inside the container, and sees no host environment.
	if got := talk(t, hs[0].Endpoint, "pid"); got != "1" {
		t.Fatalf("fiber pid = %q, want 1 (own pid namespace)", got)
	}
	if got := talk(t, hs[0].Endpoint, "getenv PATH"); got != "-" {
		t.Fatalf("PATH in fiber = %q, want scrubbed", got)
	}
	// W is the leaf's memory.current, as for proc: forked, copy-on-write.
	talk(t, hs[0].Endpoint, "dirty 8388608")
	st, err := rt.Stats(ctx, hs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("fiber 1 W after dirtying 8 MiB = %d MiB", st.WUsedBytes>>20)
	if st.WUsedBytes < 8<<20 || st.WUsedBytes > 12<<20 {
		t.Fatalf("W = %d, want about 8 MiB", st.WUsedBytes)
	}
	list, err := rt.List(ctx)
	if err != nil || len(list) != 3 {
		t.Fatalf("List = %v (%v)", list, err)
	}
	for _, h := range hs {
		if err := rt.Release(ctx, h.ID, false); err != nil {
			t.Fatalf("release: %v", err)
		}
	}
}

func TestParkResumeAcrossTheContainerBoundary(t *testing.T) {
	rt := newRuntime(t)
	ctx := context.Background()
	g := core.Grant{UID: "g2", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20}
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g2", Epoch: 1, Seq: 1}, Deadline: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		talk(t, h.Endpoint, "incr")
	}
	talk(t, h.Endpoint, "dirty 4194304")
	t0 := time.Now()
	ref, err := rt.Park(ctx, h.ID, true)
	if err != nil {
		t.Fatalf("park: %v", err)
	}
	t.Logf("parked in %s -> %s", time.Since(t0).Round(time.Millisecond), ref)
	var m struct {
		Delta  bool   `json:"delta"`
		WBytes uint64 `json:"w_bytes"`
	}
	if data, err := os.ReadFile(filepath.Join(ref, "manifest.json")); err == nil {
		_ = json.Unmarshal(data, &m)
	}
	t.Logf("park is a delta over the containerised zygote: %v, %d KiB", m.Delta, m.WBytes>>10)
	if !m.Delta || m.WBytes > 8<<20 {
		t.Fatalf("expected a W-sized delta, got delta=%v w=%d", m.Delta, m.WBytes)
	}
	t0 = time.Now()
	h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref,
		Fence: core.Fence{GrantUID: "g2", Epoch: 1, Seq: 2}, Deadline: 5 * time.Second})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	t.Logf("resumed in %s", time.Since(t0).Round(time.Millisecond))
	if got := talk(t, h2.Endpoint, "get"); got != "3" {
		t.Fatalf("counter after resume = %q, want 3", got)
	}
	_ = rt.Release(ctx, h2.ID, true)
}
