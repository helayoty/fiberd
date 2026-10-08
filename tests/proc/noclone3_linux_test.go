//go:build linux

package proctest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
	procbackend "github.com/helayoty/fiberd/pkg/backend/proc"
	"github.com/helayoty/fiberd/pkg/core"
)

var (
	noClone3Once sync.Once
	noClone3Bin  string
	noClone3Err  error
)

// noClone3 builds the launcher in testdata/noclone3.c once per test
// binary, beside refzygote, and returns its path.
func noClone3(t *testing.T) string {
	t.Helper()
	noClone3Once.Do(func() {
		noClone3Bin = filepath.Join(filepath.Dir(zygoteBin), "noclone3")
		build := exec.Command("gcc", "-O2", "-o", noClone3Bin, "testdata/noclone3.c")
		if out, err := build.CombinedOutput(); err != nil {
			noClone3Err = fmt.Errorf("%w: %s", err, out)
		}
	})
	if noClone3Err != nil {
		t.Skipf("cannot build noclone3: %v", noClone3Err)
	}
	return noClone3Bin
}

// tempCgroup makes an empty cgroup under the test root and returns it
// with an open descriptor of it, as the host hands the zygote a fiber's
// leaf. The cleanup kills whatever is left in it and removes it.
func tempCgroup(t *testing.T, name string) (path string, fd int) {
	t.Helper()
	path = filepath.Join(cgRoot, fmt.Sprintf("%s-%d-%d", name, os.Getpid(), time.Now().UnixNano()%1_000_000))
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	t.Cleanup(func() {
		_ = os.WriteFile(filepath.Join(path, "cgroup.kill"), []byte("1"), 0)
		for i := 0; i < 100; i++ {
			if err := os.Remove(path); err == nil || os.IsNotExist(err) {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Logf("cgroup %s not removed", path)
	})
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	return path, fd
}

// expectFallbackFiber checks from the outside that a fiber born without
// clone3 carries the launcher's filter, so clone3 really was ENOSYS for the
// zygote. It must be as confined as a clone3 birth, the init of its own
// pid namespace with its capabilities gone and the hidden directory covered.
func expectFallbackFiber(t *testing.T, ep string, pid int) {
	t.Helper()
	if got := talk(t, ep, "status Seccomp"); got != "2" {
		t.Fatalf("fiber Seccomp = %q, want 2 (the noclone3 filter must be on the zygote and its fibers)", got)
	}
	if got := talk(t, ep, "pid"); got != "1" {
		t.Fatalf("fiber sees itself as pid %s, want 1: the legacy clone carries the pid namespace", got)
	}
	ours, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid))
	if err != nil {
		t.Fatal(err)
	}
	if ours == theirs {
		t.Fatalf("fiber pid namespace %s is the test's: want one of its own", theirs)
	}
	if got := talk(t, ep, "status CapEff"); got != "0000000000000000" {
		t.Fatalf("fiber CapEff = %q, want none", got)
	}
	if got := talk(t, ep, "read "+filepath.Join(hiddenDir, "secret")); got != "-" {
		t.Fatalf("read of the hidden secret = %q, want - (covered: the legacy clone carries the mount namespace)", got)
	}
}

// TestForkFallbackWithoutClone3 pins that, without clone3, birth takes the
// legacy clone with the same namespace flags, and the child joins its leaf
// cgroup through the passed descriptor before it touches memory. A child
// that cannot reach its leaf ends with exit 125 rather than run charged to
// the zygote's cgroup. The noclone3 launcher hides clone3 from the zygote.
func TestForkFallbackWithoutClone3(t *testing.T) {
	if !hasCap(t, procStatus(t, os.Getpid(), "CapEff"), capSysAdmin) {
		t.Skip("the test lacks CAP_SYS_ADMIN: the fiber's namespaces would be refused")
	}
	launcher := noClone3(t)
	cases := []struct {
		name string
		run  func(t *testing.T)
	}{
		{name: "the child joins its leaf after the legacy clone", run: func(t *testing.T) {
			dir := t.TempDir()
			be, w := warmArgv(t, dir, "gf", []string{launcher, zygoteBin, "--heap-mb", "16"}, []string{hiddenDir})
			leaf, fd := tempCgroup(t, "nc3")
			f, err := cloneFallback(t, be, w, dir, "gf/1-1", fd, "")
			if err != nil {
				t.Fatalf("clone: %v", err)
			}
			ep := filepath.Join(dir, "gf-1-1.sock")
			if got := talk(t, ep, "ping"); got != "pong" {
				t.Fatalf("ping = %q", got)
			}
			expectFallbackFiber(t, ep, f.PID)
			// The fiber's own PPid is 0, because its parent is outside its
			// pid namespace. The host's view names the zygote.
			zygotePID := atoiOrFatal(t, "fiber's PPid", procStatus(t, f.PID, "PPid"))
			fiberCG, zygoteCG := cgroupOf(t, f.PID), cgroupOf(t, zygotePID)
			if fiberCG == zygoteCG || filepath.Base(fiberCG) != filepath.Base(leaf) {
				t.Fatalf("fiber cgroup %q, zygote's %q, want the fiber in the leaf %s", fiberCG, zygoteCG, leaf)
			}
			found := false
			for _, p := range readPIDs(t, filepath.Join(leaf, "cgroup.procs")) {
				found = found || p == f.PID
			}
			if !found {
				t.Fatalf("fiber %d not in %s/cgroup.procs", f.PID, leaf)
			}
		}},
		{name: "a leaf the child cannot reach ends it with exit 125", run: func(t *testing.T) {
			dir := t.TempDir()
			be, w := warmArgv(t, dir, "gx", []string{launcher, zygoteBin, "--heap-mb", "16"}, nil)
			// This leaf is gone by the time the child is born. The
			// descriptor is open but the directory behind it is removed, so
			// openat(fd, "cgroup.procs") fails and the child must end
			// rather than run in the zygote's cgroup.
			gone, fd := tempCgroup(t, "nc3gone")
			if err := os.Remove(gone); err != nil {
				t.Fatalf("remove %s: %v", gone, err)
			}
			_, err := cloneFallback(t, be, w, dir, "gx/1-1", fd, "")
			// The ERROR names the code and what it stands for, so the
			// agent's log needs no table of the zygote's exit codes.
			if err == nil || !strings.Contains(err.Error(), "died before ready: exit:125 (could not join its cgroup leaf)") {
				t.Fatalf("clone into a removed leaf = %v, want the child's exit 125 and its reason", err)
			}
			// The zygote serves on, and a reachable leaf works.
			leaf, fd2 := tempCgroup(t, "nc3ok")
			f, err := cloneFallback(t, be, w, dir, "gx/1-2", fd2, "")
			if err != nil {
				t.Fatalf("clone after the failed one: %v", err)
			}
			if got := cgroupOf(t, f.PID); filepath.Base(got) != filepath.Base(leaf) {
				t.Fatalf("fiber cgroup %q, want the leaf %s", got, leaf)
			}
		}},
		{name: "the legacy clone's child is confined like clone3's: an uncoverable HIDE path that appeared after READY ends it", run: func(t *testing.T) {
			dir := t.TempDir()
			// The HIDE path does not exist when the zygote prepares its
			// namespace, so each child looks for it at birth. A regular
			// file cannot be covered with a tmpfs, so mount_ns fails on
			// the fallback path exactly as on the clone3 one, after the
			// child has joined its leaf.
			file := filepath.Join(dir, "a-file")
			be, w := warmArgv(t, dir, "gm", []string{launcher, zygoteBin, "--heap-mb", "16"}, []string{file})
			if err := os.WriteFile(file, []byte("visible\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, fd := tempCgroup(t, "nc3hide")
			_, err := cloneFallback(t, be, w, dir, "gm/1-1", fd, "")
			if err == nil || !strings.Contains(err.Error(), "died before ready: exit:113 (could not cover a HIDE path that appeared after READY)") {
				t.Fatalf("clone with an uncoverable HIDE path = %v, want the child's exit 113 and its reason", err)
			}
		}},
		{name: "a child that misuses the readiness pipe is killed and reaped, and the zygote serves on", run: func(t *testing.T) {
			dir := t.TempDir()
			be, w := warmArgv(t, dir, "gk", []string{launcher, zygoteBin, "--heap-mb", "16"}, nil)
			_, fd := tempCgroup(t, "nc3kill")
			// With ready_misuse 2 the fiber closes fd 3 and runs on without
			// reporting. The zygote kills it, waits for it without
			// blocking its loop, and answers the CLONE with an ERROR.
			_, err := cloneFallback(t, be, w, dir, "gk/1-1", fd, `{"ready_misuse":2}`)
			if err == nil || !strings.Contains(err.Error(), "closed the readiness pipe without reporting ready; killed") {
				t.Fatalf("clone of a fiber that closes the pipe = %v, want it killed", err)
			}
			_, fd2 := tempCgroup(t, "nc3after")
			if _, err := cloneFallback(t, be, w, dir, "gk/1-2", fd2, ""); err != nil {
				t.Fatalf("clone after the killed one: %v", err)
			}
			if got := talk(t, filepath.Join(dir, "gk-1-2.sock"), "ping"); got != "pong" {
				t.Fatalf("ping = %q", got)
			}
		}},
		{name: "host runtime: leaf, endpoint, park and resume", run: func(t *testing.T) {
			rt := newRuntimeFrom(t, nil, launcher+" "+zygoteBin+" --heap-mb 32")
			ctx := context.Background()
			g := core.Grant{UID: "gh", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "gh", Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
			if err != nil {
				t.Fatalf("clone: %v", err)
			}
			if got := talk(t, h.Endpoint, "ping"); got != "pong" {
				t.Fatalf("ping = %q", got)
			}
			pid := peerPID(t, h.Endpoint)
			expectFallbackFiber(t, h.Endpoint, pid)
			zygotePID := atoiOrFatal(t, "fiber's PPid", procStatus(t, pid, "PPid"))
			fiberCG, zygoteCG := cgroupOf(t, pid), cgroupOf(t, zygotePID)
			// The runtime's leaf for fence 1/1 sits beside the zygote's
			// cgroup under the grant's.
			if filepath.Base(fiberCG) != "f-1-1" || filepath.Base(zygoteCG) != "zygote" || filepath.Dir(fiberCG) != filepath.Dir(zygoteCG) {
				t.Fatalf("fiber cgroup %q, zygote's %q, want <grant>/f-1-1 beside <grant>/zygote", fiberCG, zygoteCG)
			}
			if got := talk(t, h.Endpoint, "incr"); got != "1" {
				t.Fatalf("incr = %q", got)
			}
			if rt.Tier() < core.TierCheckpoint {
				t.Skipf("criu not usable here; runtime offers %v, park and resume not checked", rt.Tier())
			}
			ref, err := rt.Park(ctx, h.ID, true)
			if err != nil {
				t.Fatalf("park: %v", err)
			}
			h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: "gh", Epoch: 1, Seq: 2}, Deadline: 5 * time.Second})
			if err != nil {
				t.Fatalf("resume: %v", err)
			}
			if got := talk(t, h2.Endpoint, "get"); got != "1" {
				t.Fatalf("counter after resume = %q, want 1", got)
			}
			if err := rt.Release(ctx, h2.ID, true); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, tc.run)
	}
}

// cloneFallback forks one fiber of w into the cgroup behind fd, serving
// a unix socket under dir, with every confinement asked for and the
// given birth payload.
func cloneFallback(t *testing.T, be *procbackend.Backend, w backend.Warm, dir, fence string, fd int, payload string) (backend.Fiber, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return be.Clone(ctx, w.ID, backend.FiberSpec{
		Fence:    fence,
		Endpoint: filepath.Join(dir, strings.ReplaceAll(fence, "/", "-")+".sock"),
		CgroupFD: fd,
		Deadline: 2 * time.Second,
		OwnPIDNS: true,
		Payload:  []byte(payload),
	})
}
