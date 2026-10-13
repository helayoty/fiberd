//go:build linux && integration

package hosttest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/runtime/host"
	"github.com/helayoty/fiberd/pkg/sys/cgroup"
	"github.com/helayoty/fiberd/tests/internal/testenv"
)

const mib = 1 << 20

// cgRoot is the cgroup subtree the dev container delegates to the tests.
var cgRoot string

func TestMain(m *testing.M) {
	cgRoot = testenv.RequireCgroupRoot("host")
	os.Exit(m.Run())
}

var cgroupSeq atomic.Int64

// testCgroupRoot is a fresh delegated subtree for one runtime, removed
// with everything under it when the test ends.
func testCgroupRoot(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(cgRoot, fmt.Sprintf("hosttest-%d-%d", os.Getpid(), cgroupSeq.Add(1)))
	t.Cleanup(func() { removeCgroupTree(cgroup.Dir{Path: dir}) })
	return dir
}

// removeCgroupTree kills and removes d and every cgroup under it.
func removeCgroupTree(d cgroup.Dir) {
	if !d.Exists() {
		return
	}
	_ = d.Kill()
	children, _ := d.Children("")
	for _, c := range children {
		removeCgroupTree(c)
	}
	for i := 0; i < 50; i++ {
		if err := d.Remove(); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// testConfig is a runtime configuration over be with every path under
// the test's temp dir and a fresh cgroup subtree.
func testConfig(t *testing.T, be backend.Backend) host.Config {
	t.Helper()
	root := t.TempDir()
	return host.Config{Backend: be, Templates: map[string]string{"default": "/bin/true --template"},
		CgroupRoot: testCgroupRoot(t), RunDir: filepath.Join(root, "run"), DeltaDir: filepath.Join(root, "deltas"),
		TemplateCache: filepath.Join(root, "cache")}
}

// newRuntime opens a runtime over be, closed when the test ends.
func newRuntime(t *testing.T, be backend.Backend, mod func(*host.Config)) *host.Runtime {
	t.Helper()
	cfg := testConfig(t, be)
	if mod != nil {
		mod(&cfg)
	}
	r, err := host.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(r.Close)
	return r
}

// prepared is a runtime with g warm and one fiber of it running under
// fence g/1/1.
func prepared(t *testing.T, be backend.Backend, g core.Grant, mod func(*host.Config)) (*host.Runtime, core.FiberHandle) {
	t.Helper()
	r := newRuntime(t, be, mod)
	ctx := context.Background()
	if err := r.PrepareTemplate(ctx, g); err != nil {
		t.Fatalf("PrepareTemplate: %v", err)
	}
	h, err := r.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}})
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	return r, h
}

// leafOf is the cgroup of the fiber under the runtime's root.
func leafOf(r *host.Runtime, grantUID, leaf string) cgroup.Dir {
	return cgroup.Root(r.CgroupRoot()).Child(grantUID).Child(leaf)
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitExit takes the next fiber exit the runtime reports.
func waitExit(t *testing.T, r *host.Runtime) core.FiberExit {
	t.Helper()
	select {
	case e := <-r.Exits():
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("no fiber exit reported")
		return core.FiberExit{}
	}
}

// startSleeper runs a process of the test's own inside leaf, so the leaf
// has a live task charged to it. The shell moves itself into the leaf
// before it execs, so what the task maps is the leaf's. It is killed and
// reaped when the test ends.
func startSleeper(t *testing.T, leaf cgroup.Dir) int {
	t.Helper()
	return startInLeaf(t, leaf, "exec sleep 300")
}

// startInLeaf runs a shell command of the test's own inside leaf.
func startInLeaf(t *testing.T, leaf cgroup.Dir, command string) int {
	t.Helper()
	cmd := exec.Command("sh", "-c", "echo $$ > "+filepath.Join(leaf.Path, "cgroup.procs")+" && "+command)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start task: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	waitFor(t, "the task to enter "+leaf.Path, func() bool {
		pids, _ := leaf.Procs()
		for _, p := range pids {
			if p == cmd.Process.Pid {
				return true
			}
		}
		return false
	})
	return cmd.Process.Pid
}

// cgFile reads one file of a cgroup.
func cgFile(t *testing.T, d cgroup.Dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(d.Path, name))
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(d.Path, name), err)
	}
	return string(b[:len(b)-1]) // trailing newline
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
