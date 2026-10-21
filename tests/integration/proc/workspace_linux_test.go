//go:build linux && integration

package proctest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/runtime/host"
	"github.com/helayoty/fiberd/pkg/runtime/host/wsfs"
)

// mountSourcesOf maps each mount point in pid's mount namespace to its
// source, the field after the file system type.
func mountSourcesOf(t *testing.T, pid int) map[string]string {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		before, after, ok := strings.Cut(line, " - ")
		bf, af := strings.Fields(before), strings.Fields(after)
		if ok && len(bf) >= 5 && len(af) >= 2 {
			sources[bf[4]] = af[1]
		}
	}
	return sources
}

// files is the runtime's file store.
func files(t *testing.T, rt core.Runtime) core.FileStore {
	t.Helper()
	fs, ok := rt.(core.FileStore)
	if !ok {
		t.Fatal("the runtime moves no files")
	}
	return fs
}

// upload puts body at path in the fiber's workspace.
func upload(t *testing.T, rt core.Runtime, fiberID, path, body string) {
	t.Helper()
	if _, err := files(t, rt).Upload(context.Background(), fiberID, path, int64(len(body)), 0o644, nil, strings.NewReader(body)); err != nil {
		t.Fatalf("upload %s: %v", path, err)
	}
}

// download reads path from the fiber's workspace.
func download(t *testing.T, rt core.Runtime, fiberID, path string) string {
	t.Helper()
	f, err := files(t, rt).Download(context.Background(), fiberID, path, 0)
	if err != nil {
		t.Fatalf("download %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// resume brings ref back under the grant as the next fence.
func resume(t *testing.T, rt core.Runtime, g core.Grant, ref string, seq uint64) core.FiberHandle {
	t.Helper()
	h, err := rt.Clone(context.Background(), core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: seq}, Deadline: 5 * time.Second})
	if err != nil {
		t.Fatalf("resume %s: %v", ref, err)
	}
	return h
}

// workspaceGrant is a grant whose fibers get a workspace.
func workspaceGrant(uid string, disk uint64) core.Grant {
	return core.Grant{UID: uid, TemplateDigest: "sha256:ref", FiberMax: 2, WBudgetBytes: 64 << 20, DiskBudgetBytes: disk}
}

// TestWorkspaceRoundTrip pins the whole path of a file: uploaded from the
// host, read by the fiber at /workspace, written by the fiber, parked
// into workspace.tar, resumed into a fresh workspace, and downloaded
// with the same bytes. A fiber of a grant without a disk budget sees an
// empty /workspace it cannot write.
func TestWorkspaceRoundTrip(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		sync bool
	}{
		{name: "async park"},
		{name: "sync park", sync: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRuntime(t)
			if rt.Tier() < core.TierCheckpoint {
				t.Skip("criu not usable here")
			}
			g := workspaceGrant("gws", 1<<20)
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
			if err != nil {
				t.Fatalf("clone: %v", err)
			}
			if got := talk(t, h.Endpoint, "stat "+backend.WorkspaceMount); got != "dir" {
				t.Fatalf("stat /workspace = %q, want dir", got)
			}
			upload(t, rt, h.ID, "in/data.txt", "first line\nsecond\n")
			if got := talk(t, h.Endpoint, "read "+backend.WorkspaceMount+"/in/data.txt"); got != "first line" {
				t.Fatalf("the fiber read %q, want the uploaded file's first line", got)
			}
			if got := talk(t, h.Endpoint, "write "+backend.WorkspaceMount+"/result.txt hello from the fiber"); got != "ok" {
				t.Fatalf("the fiber's write = %q", got)
			}
			if got := download(t, rt, h.ID, "result.txt"); got != "hello from the fiber\n" {
				t.Fatalf("download before the park = %q", got)
			}
			infos, err := files(t, rt).ListFiles(ctx, h.ID, "")
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, i := range infos {
				names = append(names, i.Path)
			}
			if strings.Join(names, " ") != "in result.txt" {
				t.Fatalf("ListFiles = %v", names)
			}
			ref, err := rt.Park(ctx, h.ID, tc.sync)
			if err != nil {
				t.Fatalf("park: %v", err)
			}
			if _, err := os.Stat(filepath.Join(ref, "workspace.tar")); err != nil {
				t.Fatalf("the delta carries no workspace.tar: %v", err)
			}
			h2 := resume(t, rt, g, ref, 2)
			defer func() { _ = rt.Release(ctx, h2.ID, true) }()
			if got := talk(t, h2.Endpoint, "read "+backend.WorkspaceMount+"/in/data.txt"); got != "first line" {
				t.Fatalf("after the resume the fiber read %q", got)
			}
			if got := download(t, rt, h2.ID, "result.txt"); got != "hello from the fiber\n" {
				t.Fatalf("download after the resume = %q", got)
			}
			if got := talk(t, h2.Endpoint, "write "+backend.WorkspaceMount+"/after.txt written after the resume"); got != "ok" {
				t.Fatalf("the resumed fiber's write = %q", got)
			}
			if got := download(t, rt, h2.ID, "after.txt"); got != "written after the resume\n" {
				t.Fatalf("download of the resumed fiber's file = %q", got)
			}
		})
	}
}

// TestWorkspaceNone pins what a fiber of a grant without a disk budget
// sees at /workspace: the empty mount point, root's and mode 0, which
// it cannot write as fiberd's uid with no capability. The file calls
// answer that it has no workspace.
func TestWorkspaceNone(t *testing.T) {
	ctx := context.Background()
	rt := newRuntime(t)
	// A fiber with a workspace first, so the mount point exists.
	withWS := workspaceGrant("gws", 1<<20)
	if err := rt.PrepareTemplate(ctx, withWS); err != nil {
		t.Fatal(err)
	}
	hw, err := rt.Clone(ctx, core.CloneSpec{Grant: withWS, Fence: core.Fence{GrantUID: withWS.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	defer func() { _ = rt.Release(ctx, hw.ID, false) }()
	g := workspaceGrant("gnone", 0)
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	defer func() { _ = rt.Release(ctx, h.ID, false) }()
	cases := []struct {
		name string
		line string
		want string
	}{
		{name: "the mount point is a directory", line: "stat " + backend.WorkspaceMount, want: "dir"},
		{name: "nothing can be written in it", line: "wopen " + backend.WorkspaceMount + "/x", want: "EACCES"},
		{name: "nothing can be made in it", line: "mkdir " + backend.WorkspaceMount + "/d", want: "EACCES"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := talk(t, h.Endpoint, tc.line); got != tc.want {
				t.Fatalf("%s = %q, want %q", tc.line, got, tc.want)
			}
		})
	}
	if _, err := files(t, rt).Upload(ctx, h.ID, "a.txt", 1, 0o644, nil, strings.NewReader("x")); !errors.Is(err, core.ErrNoWorkspace) {
		t.Fatalf("Upload = %v, want ErrNoWorkspace", err)
	}
}

// TestWorkspaceHeldOpen pins that a file the fiber keeps open across a
// park is where the restored fiber expects it, with its offset, since
// criu restores open files by path and the resume unpacks the archive
// before the restore.
func TestWorkspaceHeldOpen(t *testing.T) {
	ctx := context.Background()
	rt := newRuntime(t)
	if rt.Tier() < core.TierCheckpoint {
		t.Skip("criu not usable here")
	}
	g := workspaceGrant("gheld", 1<<20)
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	for _, line := range []string{"hold " + backend.WorkspaceMount + "/held.txt", "held write first"} {
		if got := talk(t, h.Endpoint, line); got != "ok" {
			t.Fatalf("%s = %q", line, got)
		}
	}
	ref, err := rt.Park(ctx, h.ID, false)
	if err != nil {
		t.Fatalf("park: %v", err)
	}
	h2 := resume(t, rt, g, ref, 2)
	defer func() { _ = rt.Release(ctx, h2.ID, true) }()
	if got := talk(t, h2.Endpoint, "held write second"); got != "ok" {
		t.Fatalf("held write after the resume = %q", got)
	}
	if got := talk(t, h2.Endpoint, "held read"); got != "first" {
		t.Fatalf("held read after the resume = %q, want first", got)
	}
	if got := download(t, rt, h2.ID, "held.txt"); got != "first\nsecond\n" {
		t.Fatalf("held.txt after the resume = %q, want both lines in order", got)
	}
}

// hostPID is the fiber's root process as the host sees it, the one
// process in its leaf before it forks anything.
func hostPID(t *testing.T, rt core.Runtime, g core.Grant, epoch, seq int) int {
	t.Helper()
	procs := strings.Fields(leafProcs(t, rt, g, epoch, seq))
	if len(procs) == 0 {
		t.Fatal("the fiber's leaf holds no process")
	}
	pid, err := strconv.Atoi(procs[0])
	if err != nil {
		t.Fatal(err)
	}
	return pid
}

// procState is the state letter of pid in /proc/<pid>/stat, "" once
// the process is gone.
func procState(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return ""
	}
	// "pid (comm) S ...", with comm possibly holding spaces.
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 >= len(s) {
		return ""
	}
	return s[i+2 : i+3]
}

// TestWorkspaceWriteRacesPark proves the capture runs with the fiber
// stopped (--leave-stopped). A thread of the fiber appends numbered
// lines to a workspace file through the park. The restored fiber goes
// on from the count the dump saw, so the file must hold every line
// once, in order. A capture taken with the fiber running would hold
// lines past that count, which the restored fiber writes again. The
// fiber's state is sampled through the park as well, and it must be
// seen stopped.
func TestWorkspaceWriteRacesPark(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		sync bool
	}{
		{name: "async park"},
		{name: "sync park", sync: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := newRuntime(t)
			if rt.Tier() < core.TierCheckpoint {
				t.Skip("criu not usable here")
			}
			g := workspaceGrant("grace", 4<<20)
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
			if err != nil {
				t.Fatalf("clone: %v", err)
			}
			pid := hostPID(t, rt, g, 1, 1)
			if got := talk(t, h.Endpoint, "scribble "+backend.WorkspaceMount+"/log"); got != "ok" {
				t.Fatalf("scribble = %q", got)
			}
			// Some lines before the park, so the race is on.
			for {
				n, _ := strconv.Atoi(talk(t, h.Endpoint, "scribbled"))
				if n >= 50 {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			// Sample the fiber's state through the park. It must be seen
			// stopped (T) at some point: that is when the capture runs.
			stop := make(chan struct{})
			var wg sync.WaitGroup
			var mu sync.Mutex
			seen := map[string]int{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					if st := procState(pid); st != "" {
						mu.Lock()
						seen[st]++
						mu.Unlock()
					}
					time.Sleep(200 * time.Microsecond)
				}
			}()
			ref, err := rt.Park(ctx, h.ID, tc.sync)
			close(stop)
			wg.Wait()
			if err != nil {
				t.Fatalf("park: %v", err)
			}
			mu.Lock()
			stopped := seen["T"] + seen["t"]
			mu.Unlock()
			t.Logf("fiber states sampled through the park: %v", seen)
			if stopped == 0 {
				t.Fatalf("the fiber was never seen stopped through the park, states %v", seen)
			}
			h2 := resume(t, rt, g, ref, 2)
			defer func() { _ = rt.Release(ctx, h2.ID, true) }()
			// Let the restored thread write on, then stop it.
			time.Sleep(100 * time.Millisecond)
			reply := talk(t, h2.Endpoint, "scribble stop")
			count, err := strconv.Atoi(strings.TrimPrefix(reply, "ok "))
			if err != nil || count < 50 {
				t.Fatalf("scribble stop = %q", reply)
			}
			lines := strings.Split(strings.TrimSuffix(download(t, rt, h2.ID, "log"), "\n"), "\n")
			if len(lines) != count {
				t.Fatalf("the log holds %d lines, the fiber wrote %d: the capture did not match the dump", len(lines), count)
			}
			for i, l := range lines {
				if l != strconv.Itoa(i+1) {
					t.Fatalf("line %d is %q, want %d: the capture did not match the dump", i+1, l, i+1)
				}
			}
			t.Logf("%d lines, every one once and in order", count)
		})
	}
}

// TestWorkspaceBudget pins that an upload past the grant's disk budget
// is refused before a byte lands, counting what fiberd already wrote.
func TestWorkspaceBudget(t *testing.T) {
	ctx := context.Background()
	rt := newRuntime(t)
	g := workspaceGrant("gbudget", 4096)
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	defer func() { _ = rt.Release(ctx, h.ID, false) }()
	cases := []struct {
		name    string
		path    string
		size    int
		wantErr error
	}{
		{name: "a file over the budget", path: "big", size: 5000, wantErr: wsfs.ErrBudget},
		{name: "a file under it lands", path: "a", size: 3000},
		{name: "a second file past what is left", path: "b", size: 2000, wantErr: wsfs.ErrBudget},
		{name: "one that fits what is left lands", path: "c", size: 1000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.Repeat("x", tc.size)
			_, err := files(t, rt).Upload(ctx, h.ID, tc.path, int64(tc.size), 0o644, nil, strings.NewReader(body))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Upload = %v, want %v", err, tc.wantErr)
			}
			want := "ENOENT"
			if tc.wantErr == nil {
				want = "file"
			}
			if got := talk(t, h.Endpoint, "stat "+backend.WorkspaceMount+"/"+tc.path); got != want {
				t.Fatalf("the fiber sees %s as %q, want %q", tc.path, got, want)
			}
		})
	}
}

// TestWorkspacePrivate pins that a fiber sees its own workspace alone.
// Another fiber of the same grant finds nothing of it at /workspace, the
// directory holding every workspace is hidden, and no fiber's mount
// table names it.
func TestWorkspacePrivate(t *testing.T) {
	ctx := context.Background()
	wsDir := filepath.Join(suiteDir, "private-workspaces")
	rt, err := newHost(host.Config{
		Templates:    map[string]string{"default": zygoteBin + " --heap-mb 32"},
		CgroupRoot:   filepath.Join(cgRoot, fmt.Sprintf("tp%d-%d", os.Getpid(), time.Now().UnixNano()%1_000_000)),
		RunDir:       filepath.Join("/tmp", "fz-"+fmt.Sprint(os.Getpid())),
		WorkspaceDir: wsDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rt.(interface{ Close() }).Close)
	g := workspaceGrant("gpriv", 1<<20)
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	a, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatalf("clone a: %v", err)
	}
	defer func() { _ = rt.Release(ctx, a.ID, false) }()
	b, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 2}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatalf("clone b: %v", err)
	}
	defer func() { _ = rt.Release(ctx, b.ID, false) }()
	upload(t, rt, a.ID, "secret", "a's alone\n")
	aRoot := filepath.Join(wsDir, g.UID, "1-1", "root")
	cases := []struct {
		name     string
		endpoint string
		line     string
		want     string
	}{
		{name: "a reads its own file", endpoint: a.Endpoint, line: "read " + backend.WorkspaceMount + "/secret", want: "a's alone"},
		{name: "b finds nothing at the same path", endpoint: b.Endpoint, line: "stat " + backend.WorkspaceMount + "/secret", want: "ENOENT"},
		{name: "b cannot reach a's root on the host", endpoint: b.Endpoint, line: "stat " + aRoot, want: "ENOENT"},
		{name: "a cannot reach its own root on the host either", endpoint: a.Endpoint, line: "stat " + aRoot, want: "ENOENT"},
		{name: "the directory of every workspace is covered", endpoint: b.Endpoint, line: "stat " + filepath.Join(wsDir, g.UID), want: "ENOENT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := talk(t, tc.endpoint, tc.line); got != tc.want {
				t.Fatalf("%s = %q, want %q", tc.line, got, tc.want)
			}
		})
	}
	for _, f := range []struct {
		name string
		pid  int
	}{{"a", hostPID(t, rt, g, 1, 1)}, {"b", hostPID(t, rt, g, 1, 2)}} {
		points := mountPointsOf(t, f.pid)
		n := 0
		for _, p := range points {
			if p == backend.WorkspaceMount {
				n++
			}
			if strings.HasPrefix(p, wsDir+"/") {
				t.Fatalf("fiber %s's mount table names %s under the workspace directory", f.name, p)
			}
		}
		if n != 1 {
			t.Fatalf("fiber %s's mount table names %s %d times, want once: %v", f.name, backend.WorkspaceMount, n, points)
		}
	}
}

// TestWorkspaceOnForeignMount pins that the zygote's drop of other homes'
// mounts, every file system whose source starts with fiberd-, leaves a
// fiber its own workspace when the workspace directory itself sits on
// such a mount. The bind the fiber gets is a detached copy fiberd makes
// in its own namespace, and the zygote never sees it, so the fiber reads
// its files while the tmpfs is gone from its table. A park then names
// the bind external and resumes.
func TestWorkspaceOnForeignMount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mounts a tmpfs, which needs root")
	}
	ctx := context.Background()
	wsDir := filepath.Join("/tmp", fmt.Sprintf("fz-wsfs-%d", os.Getpid()))
	if err := os.MkdirAll(wsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount(backend.MountSourcePrefix+"workspaces", wsDir, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "mode=0700"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Unmount(wsDir, syscall.MNT_DETACH)
		_ = os.Remove(wsDir)
	})
	rt, err := newHost(host.Config{
		Templates:    map[string]string{"default": zygoteBin + " --heap-mb 32"},
		CgroupRoot:   filepath.Join(cgRoot, fmt.Sprintf("tf%d-%d", os.Getpid(), time.Now().UnixNano()%1_000_000)),
		RunDir:       filepath.Join("/tmp", "fz-"+fmt.Sprint(os.Getpid())),
		WorkspaceDir: wsDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rt.(interface{ Close() }).Close)
	if rt.Tier() < core.TierCheckpoint {
		t.Skip("criu not usable here")
	}
	g := workspaceGrant("gforeign", 1<<20)
	if err := rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	upload(t, rt, h.ID, "on-tmpfs.txt", "kept\n")
	if got := talk(t, h.Endpoint, "read "+backend.WorkspaceMount+"/on-tmpfs.txt"); got != "kept" {
		t.Fatalf("the fiber read %q, want its own workspace on the foreign mount", got)
	}
	// The directory is covered, like every hidden path, so it is a
	// mount point in the fiber's table, and the foreign tmpfs behind it
	// is gone. The one mount from a fiberd- source left is the fiber's
	// own workspace, a bind that carries its file system's source, which
	// the zygote never saw: the drop ran before the fiber was born, and
	// the bind was made in fiberd's namespace.
	for point, src := range mountSourcesOf(t, hostPID(t, rt, g, 1, 1)) {
		switch {
		case point == backend.WorkspaceMount && src != backend.MountSourcePrefix+"workspaces":
			t.Fatalf("the fiber's workspace comes from %q, want the tmpfs it lives on", src)
		case point != backend.WorkspaceMount && strings.HasPrefix(src, backend.MountSourcePrefix):
			t.Fatalf("the fiber's mount table holds %s from %s, which the zygote should have dropped", point, src)
		}
	}
	if got := talk(t, h.Endpoint, "stat "+filepath.Join(wsDir, g.UID)); got != "ENOENT" {
		t.Fatalf("the fiber sees the workspace directory on the tmpfs as %q, want it covered", got)
	}
	ref, err := rt.Park(ctx, h.ID, false)
	if err != nil {
		t.Fatalf("park: %v", err)
	}
	h2 := resume(t, rt, g, ref, 2)
	defer func() { _ = rt.Release(ctx, h2.ID, true) }()
	if got := talk(t, h2.Endpoint, "read "+backend.WorkspaceMount+"/on-tmpfs.txt"); got != "kept" {
		t.Fatalf("after the resume the fiber read %q", got)
	}
}
