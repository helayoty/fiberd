//go:build linux && integration

package proctest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
	procbackend "github.com/helayoty/fiberd/pkg/backend/proc"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/runtime/host"
)

// mountPointsOf lists the mount points in pid's mount namespace.
func mountPointsOf(t *testing.T, pid int) []string {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		t.Fatal(err)
	}
	var points []string
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) >= 5 {
			points = append(points, f[4])
		}
	}
	return points
}

// mountTemplatesTmpfs mounts a tmpfs at dir as the gVisor backend mounts
// its templates directory, with a template image in it.
func mountTemplatesTmpfs(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount(backend.MountSourcePrefix+"templates", dir, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "mode=0700"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "template.img"), []byte("another home's template memory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// bindRoot binds the host's / at dir, private, as a proc home's restore
// root is.
func bindRoot(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount("/", dir, "", syscall.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount("", dir, "", syscall.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
}

// TestOtherHomesMountsLeaveTheFiber pins that a proc fiber's namespace
// carries no mount another fiberd home made in the same mount namespace,
// so a park survives that home taking its mount down. The gVisor
// backend's templates tmpfs and a proc home's restore root (a bind of /)
// are copied from the host when the zygote takes its namespace, and criu
// recorded them at park (regression: the resume failed with "Can't stat
// mountpoint" once the other home had closed, and a tmpfs that home had
// detached meanwhile was written whole into the proc fiber's checkpoint,
// template images included). A mount made after the zygote prepared
// never arrives, since its namespace is private.
func TestOtherHomesMountsLeaveTheFiber(t *testing.T) {
	ctx := context.Background()
	base := filepath.Join("/tmp", fmt.Sprintf("fz-other-%d", os.Getpid()))
	cases := []struct {
		name string
		// mount sets the other home's mount up at dir, before the
		// runtime opens unless after is set.
		mount func(t *testing.T, dir string)
		after bool
	}{
		{name: "the gVisor templates tmpfs", mount: mountTemplatesTmpfs},
		{name: "a restore root in production's name", mount: bindRoot},
		{name: "a restore root in the test suites' name", mount: bindRoot},
		{name: "a templates tmpfs mounted after the zygote prepared", mount: mountTemplatesTmpfs, after: true},
	}
	dirs := []string{
		filepath.Join(base, "gvisor", "gv1", "templates"),
		filepath.Join(base, "private", "root"),
		filepath.Join(base, "fiberd-root-424242"),
		filepath.Join(base, "gvisor", "gv2", "templates"),
	}
	// The mounts' parent is shared, so a mount made later would propagate
	// to every namespace that still shares it.
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount(base, base, "", syscall.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount("", base, "", syscall.MS_SHARED, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, d := range dirs {
			_ = syscall.Unmount(d, syscall.MNT_DETACH)
		}
		_ = syscall.Unmount(base, syscall.MNT_DETACH)
		_ = os.RemoveAll(base)
	})
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := dirs[i]
			if !tc.after {
				tc.mount(t, dir)
			}
			rt := newRuntime(t)
			if rt.Tier() < core.TierCheckpoint {
				t.Skip("criu not usable here; runtime offers", rt.Tier())
			}
			g := core.Grant{UID: "oth", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			if tc.after {
				tc.mount(t, dir)
			}
			if _, mounted := mountAt(t, dir); !mounted {
				t.Fatalf("%s is not mounted in the host namespace", dir)
			}
			h1, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "oth", Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			talk(t, h1.Endpoint, "incr")
			pid := peerPID(t, h1.Endpoint)
			for _, p := range mountPointsOf(t, pid) {
				if p == dir {
					t.Fatalf("fiber %d carries the other home's mount at %s", pid, dir)
				}
			}
			ref, err := rt.Park(ctx, h1.ID, true)
			if err != nil {
				t.Fatalf("park: %v", err)
			}
			// The other home closes: its mount goes and so does its
			// directory.
			if err := syscall.Unmount(dir, syscall.MNT_DETACH); err != nil {
				t.Fatal(err)
			}
			if err := os.RemoveAll(dir); err != nil {
				t.Fatal(err)
			}
			h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: "oth", Epoch: 1, Seq: 2}, Deadline: 5 * time.Second})
			if err != nil {
				t.Fatalf("resume after the other home closed: %v", err)
			}
			if got := talk(t, h2.Endpoint, "get"); got != "1" {
				t.Fatalf("resumed fiber get = %q, want 1", got)
			}
			if err := rt.Release(ctx, h2.ID, true); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// newHome opens a proc home of its own, named name, with its own run,
// delta and template directories and the restore root at rootBind, so
// two homes in one test share nothing but the mount namespace.
func newHome(t *testing.T, name, rootBind string) core.Runtime {
	t.Helper()
	run := filepath.Join("/tmp", fmt.Sprintf("fz-%s-%d", name, os.Getpid()))
	dir := filepath.Join(suiteDir, name)
	rt, err := newHost(host.Config{
		Backend:       procbackend.New(procbackend.Options{RootBind: rootBind}),
		Templates:     map[string]string{"default": zygoteBin + " --heap-mb 32"},
		CgroupRoot:    filepath.Join(cgRoot, fmt.Sprintf("%s%d-%d", name, os.Getpid(), time.Now().UnixNano()%1_000_000)),
		RunDir:        run,
		DeltaDir:      filepath.Join(dir, "deltas"),
		TemplateCache: filepath.Join(dir, "templates"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		rt.(interface{ Close() }).Close()
		_ = os.RemoveAll(run)
		_ = os.RemoveAll(dir)
	})
	return rt
}

// TestTwoProcHomesShareANamespace pins the same with two real proc homes
// in one mount namespace, each with a restore root of its own as two
// fiberd processes on one host have. Home A resumes a fiber, which binds
// its restore root. Home B, warmed afterwards, parks a fiber. Home A
// closes and takes its root with it. Home B's resume must still go
// through (regression: B's fiber carried A's root, and criu could not
// restore it once A had unmounted it).
func TestTwoProcHomesShareANamespace(t *testing.T) {
	ctx := context.Background()
	base := filepath.Join("/tmp", fmt.Sprintf("fz-two-%d", os.Getpid()))
	cases := []struct {
		name  string
		rootA string
		rootB string
	}{
		{name: "roots in production's name", rootA: filepath.Join(base, "a", "private", "root"), rootB: filepath.Join(base, "b", "private", "root")},
		{name: "roots in the suites' name", rootA: filepath.Join(base, "fiberd-root-1000001"), rootB: filepath.Join(base, "fiberd-root-1000002")},
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rtA := newHome(t, "a", tc.rootA)
			if rtA.Tier() < core.TierCheckpoint {
				t.Skip("criu not usable here; runtime offers", rtA.Tier())
			}
			g := core.Grant{UID: "twa", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20}
			if err := rtA.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			a1, err := rtA.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: "twa", Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			refA, err := rtA.Park(ctx, a1.ID, true)
			if err != nil {
				t.Fatalf("park on A: %v", err)
			}
			a2, err := rtA.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: refA, Fence: core.Fence{GrantUID: "twa", Epoch: 1, Seq: 2}, Deadline: 5 * time.Second})
			if err != nil {
				t.Fatalf("resume on A: %v", err)
			}
			if _, mounted := mountAt(t, tc.rootA); !mounted {
				t.Fatalf("A's restore root %s is not mounted after a resume", tc.rootA)
			}

			rtB := newHome(t, "b", tc.rootB)
			gB := core.Grant{UID: "twb", TemplateDigest: "sha256:ref", WBudgetBytes: 64 << 20}
			if err := rtB.PrepareTemplate(ctx, gB); err != nil {
				t.Fatal(err)
			}
			b1, err := rtB.Clone(ctx, core.CloneSpec{Grant: gB, Fence: core.Fence{GrantUID: "twb", Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			talk(t, b1.Endpoint, "incr")
			for _, p := range mountPointsOf(t, peerPID(t, b1.Endpoint)) {
				if p == tc.rootA {
					t.Fatalf("B's fiber carries A's restore root %s", tc.rootA)
				}
			}
			refB, err := rtB.Park(ctx, b1.ID, true)
			if err != nil {
				t.Fatalf("park on B: %v", err)
			}

			if err := rtA.Release(ctx, a2.ID, true); err != nil {
				t.Fatal(err)
			}
			rtA.(interface{ Close() }).Close()
			if _, mounted := mountAt(t, tc.rootA); mounted {
				t.Fatalf("A's restore root %s is still mounted after Close", tc.rootA)
			}

			b2, err := rtB.Clone(ctx, core.CloneSpec{Grant: gB, Source: core.SourceDelta, Ref: refB, Fence: core.Fence{GrantUID: "twb", Epoch: 1, Seq: 2}, Deadline: 5 * time.Second})
			if err != nil {
				t.Fatalf("resume on B after A closed: %v", err)
			}
			if got := talk(t, b2.Endpoint, "get"); got != "1" {
				t.Fatalf("resumed fiber get = %q, want 1", got)
			}
			if err := rtB.Release(ctx, b2.ID, true); err != nil {
				t.Fatal(err)
			}
		})
	}
}
