//go:build linux

package hyperlighttest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	hlbackend "github.com/helayoty/fiberd/pkg/backend/hyperlight"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/runtime/host"
)

var (
	helperBin string
	guest     string
	cgRoot    = os.Getenv("FIBERD_CGROUP_ROOT")
)

func TestMain(m *testing.M) {
	if cgRoot == "" {
		cgRoot = "/sys/fs/cgroup/fiberd"
	}
	if f, err := os.OpenFile(filepath.Join(cgRoot, "cgroup.subtree_control"), os.O_WRONLY, 0); err != nil {
		fmt.Fprintf(os.Stderr, "skipping hyperlight tests: %s not writable (run under make linux-test)\n", cgRoot)
		os.Exit(0)
	} else {
		_ = f.Close()
	}
	dir, err := os.MkdirTemp("", "fakehelper")
	if err != nil {
		panic(err)
	}
	helperBin = filepath.Join(dir, "fakehelper")
	build := exec.Command("go", "build", "-o", helperBin, "../../hack/hyperlight/fakehelper")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "skipping hyperlight tests: cannot build fakehelper: %v\n", err)
		os.Exit(0)
	}
	guest = filepath.Join(dir, "guest.bin")
	_ = os.WriteFile(guest, []byte("fake guest"), 0o644)
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func newRuntime(t *testing.T) core.Runtime {
	t.Helper()
	name := fmt.Sprintf("hl%d", time.Now().UnixNano()%1_000_000)
	rt, err := host.New(host.Config{
		Backend:    hlbackend.New(hlbackend.Options{Helper: helperBin, Guest: guest}),
		Templates:  map[string]string{"default": "guest --init-ms 20"},
		CgroupRoot: filepath.Join(cgRoot, name),
		RunDir:     filepath.Join("/tmp", "fz-"+name),
		DeltaDir:   filepath.Join(t.TempDir(), "deltas"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rt.(interface{ Close() }).Close() })
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

func TestHelperProtocol(t *testing.T) {
	rt := newRuntime(t)
	if rt.Tier() != core.TierSnapshot {
		t.Fatalf("tier = %s, want FIBER_SNAPSHOT", rt.Tier())
	}
	ctx := context.Background()
	g := core.Grant{UID: "g1", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 8 << 20}
	t0 := time.Now()
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	t.Logf("helper warm in %s", time.Since(t0).Round(time.Millisecond))

	var hs []core.FiberHandle
	for i := 1; i <= 3; i++ {
		h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g1", Epoch: 1, Seq: uint64(i)}, Deadline: time.Second,
			Payload: []byte(`{"dirty_bytes": 1048576}`)})
		if err != nil {
			t.Fatalf("clone %d: %v", i, err)
		}
		if got := talk(t, h.Endpoint, "ping"); got != "pong" {
			t.Fatalf("ping = %q", got)
		}
		if got := talk(t, h.Endpoint, "fence"); got != h.ID {
			t.Fatalf("fence = %q", got)
		}
		hs = append(hs, h)
	}
	// W comes from the helper: the payload's 1 MiB, then what the fiber dirties.
	time.Sleep(20 * time.Millisecond)
	st, err := rt.Stats(ctx, hs[0].ID)
	if err != nil || st.WUsedBytes != 1<<20 {
		t.Fatalf("W after birth = %d (%v), want 1 MiB", st.WUsedBytes, err)
	}
	talk(t, hs[0].Endpoint, "dirty 2097152")
	time.Sleep(20 * time.Millisecond)
	if st, _ := rt.Stats(ctx, hs[0].ID); st.WUsedBytes != 3<<20 {
		t.Fatalf("W after dirtying = %d, want 3 MiB", st.WUsedBytes)
	}
	// Over budget: the host kills it and reports oom.
	talk(t, hs[1].Endpoint, "dirty 16777216")
	select {
	case e := <-rt.Exits():
		if e.FiberID != hs[1].ID || e.Reason != "oom" {
			t.Fatalf("exit = %+v, want oom for %s", e, hs[1].ID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no oom exit for the fiber over budget")
	}
	// A late fiber is a miss.
	_, err = rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "g1", Epoch: 1, Seq: 9}, Deadline: 100 * time.Millisecond,
		Payload: []byte(`{"ready_delay_ms": 500}`)})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("late fiber: %v, want deadline exceeded", err)
	}
	for _, h := range []core.FiberHandle{hs[0], hs[2]} {
		if err := rt.Release(ctx, h.ID, false); err != nil {
			t.Fatalf("release: %v", err)
		}
	}
}

func TestParkResumeThroughTheHelper(t *testing.T) {
	rt := newRuntime(t)
	ctx := context.Background()
	g := core.Grant{UID: "g2", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 8 << 20}
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
	talk(t, h.Endpoint, "dirty 4096")
	ref, err := rt.Park(ctx, h.ID, true)
	if err != nil {
		t.Fatalf("park: %v", err)
	}
	if _, err := os.Stat(filepath.Join(ref, "state.json")); err != nil {
		t.Fatalf("park wrote no state: %v", err)
	}
	if _, err := os.Stat(strings.TrimPrefix(h.Endpoint, "unix://")); err == nil {
		t.Fatal("endpoint still present after park")
	}
	h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref,
		Fence: core.Fence{GrantUID: "g2", Epoch: 1, Seq: 2}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if got := talk(t, h2.Endpoint, "get"); got != "3" {
		t.Fatalf("counter after resume = %q, want 3", got)
	}
	if got := talk(t, h2.Endpoint, "fence"); got != h2.ID {
		t.Fatalf("fence after resume = %q, want %q", got, h2.ID)
	}
	// Non-sync park ends the fiber; resume again keeps accumulating.
	talk(t, h2.Endpoint, "incr")
	ref2, err := rt.Park(ctx, h2.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	h3, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref2,
		Fence: core.Fence{GrantUID: "g2", Epoch: 1, Seq: 3}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if got := talk(t, h3.Endpoint, "get"); got != "4" {
		t.Fatalf("counter after second resume = %q, want 4", got)
	}
	_ = rt.Release(ctx, h3.ID, true)
}
