//go:build linux && integration

package runctest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
	runcbackend "github.com/helayoty/fiberd/pkg/backend/runc"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/runtime/host"
	"github.com/helayoty/fiberd/pkg/sys/cgroup"
)

// The tests here pin what the runc launcher does with the kernel and the
// runc binary: the bundle it writes and what it prepares around it, the
// root filesystem copy shifted onto the grant's ids, the hold a restored
// fiber keeps on that copy, the control channel in the container's
// network namespace, and the host pid of a fiber the zygote names by a
// number in its own namespace. Their unit halves run over fakes in
// pkg/backend/runc.

// grantFor is a grant of the reference template.
func grantFor(uid string) core.Grant {
	return core.Grant{UID: uid, TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20}
}

// warmed is a home with grant g's zygote up.
func warmed(t *testing.T, mod func(*runcbackend.Options, *host.Config), g core.Grant) *home {
	t.Helper()
	hm := newHome(t, mod)
	if err := hm.rt.PrepareTemplate(context.Background(), g); err != nil {
		t.Fatalf("prepare %s: %v", g.UID, err)
	}
	return hm
}

// clone forks one fiber of g on hm and checks it serves.
func clone(t *testing.T, hm *home, g core.Grant, seq uint64) core.FiberHandle {
	t.Helper()
	h, err := hm.rt.Clone(context.Background(), core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: seq}, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatalf("clone %s/%d: %v", g.UID, seq, err)
	}
	if got := talk(t, h.Endpoint, "ping"); got != "pong" {
		t.Fatalf("ping = %q", got)
	}
	return h
}

// ownerOf is the uid and gid of path.
func ownerOf(t *testing.T, path string) (uid, gid int) {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	return int(st.Uid), int(st.Gid)
}

// TestHostPIDTranslation checks that a fiber the zygote reports by a pid
// in the container's namespace is known to the host by the pid in its
// leaf, the one whose NSpid shows the container's number one level down,
// and that a kill reaches that process.
func TestHostPIDTranslation(t *testing.T) {
	cases := []struct {
		name string
	}{{name: "the leaf's pid is the fiber, and Kill ends it"}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := grantFor("pid")
			hm := warmed(t, nil, g)
			h := clone(t, hm, g, 1)
			fence := core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}
			pid := hm.fiberPID(t, fence)
			ids := strings.Fields(statusField(t, pid, "NSpid"))
			if len(ids) < 2 || ids[0] != strconv.Itoa(pid) || ids[1] == ids[0] {
				t.Fatalf("NSpid of %d = %v, want the host pid first and the container's number below it", pid, ids)
			}
			// The fiber sees itself as the init of its own namespace, the
			// level below the container's.
			if got := talk(t, h.Endpoint, "pid"); got != "1" || ids[len(ids)-1] != "1" {
				t.Fatalf("fiber pid = %q, NSpid %v, want 1 at the bottom", got, ids)
			}
			if err := hm.rt.Release(context.Background(), h.ID, false); err != nil {
				t.Fatalf("release: %v", err)
			}
			waitFor(t, "the fiber's host process to end", func() bool {
				return gone(fmt.Sprintf("/proc/%d", pid)) || statusField(t, pid, "State")[0] == 'Z'
			})
		})
	}
}

// bundleConfig is the part of the bundle's config.json the tests read.
type bundleConfig struct {
	Root struct {
		Path string `json:"path"`
	} `json:"root"`
	Mounts []struct {
		Destination string `json:"destination"`
		Source      string `json:"source"`
	} `json:"mounts"`
	Linux struct {
		CgroupsPath string `json:"cgroupsPath"`
	} `json:"linux"`
}

// mountOf is a mount of pid's namespace: its root in the filesystem, its
// options and the filesystem type.
type mountOf struct{ root, opts, fstype string }

// mountsOf lists pid's mounts by mount point.
func mountsOf(t *testing.T, pid int) map[string]mountOf {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]mountOf{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		sep := -1
		for i, w := range f {
			if w == "-" {
				sep = i
				break
			}
		}
		if sep < 6 || sep+1 >= len(f) {
			continue
		}
		out[f[4]] = mountOf{root: f[3], opts: f[5], fstype: f[sep+1]}
	}
	return out
}

// TestCommandPreparesTheBundle checks what Command makes for a grant's
// container besides its spec: the bundle naming the rootfs copy, the run
// directory and the zygote's leaf, runc's own log beside the bundle, the
// /sys bind of the host's top sysfs mount alone, read-only, in the
// container and not in fiberd's namespace, and a container runc knows.
func TestCommandPreparesTheBundle(t *testing.T) {
	g := grantFor("bundle")
	hm := warmed(t, nil, g)
	bundle := filepath.Join(hm.stateDir, "bundles", "w-"+g.UID)
	data, err := os.ReadFile(filepath.Join(bundle, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg bundleConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	zpid := hm.zygotePID(t, g.UID)
	cases := []struct {
		name  string
		check func(t *testing.T)
	}{
		{name: "the bundle names the copy, the run directory and the zygote's leaf", check: func(t *testing.T) {
			if want := filepath.Join(hm.stateDir, "rootfs", "w-"+g.UID); cfg.Root.Path != want {
				t.Errorf("root = %q, want %q", cfg.Root.Path, want)
			}
			hostSrc := ""
			for _, m := range cfg.Mounts {
				if m.Destination == "/host" {
					hostSrc = m.Source
				}
			}
			if want := filepath.Join(hm.runDir, g.UID); hostSrc != want {
				t.Errorf("/host mount source = %q, want %q", hostSrc, want)
			}
			if want := strings.TrimPrefix(filepath.Join(hm.cgRoot, g.UID, "fibers", "zygote"), "/sys/fs/cgroup"); cfg.Linux.CgroupsPath != want {
				t.Errorf("cgroupsPath = %q, want %q", cfg.Linux.CgroupsPath, want)
			}
		}},
		{name: "runc's log is beside the bundle, not in it", check: func(t *testing.T) {
			logPath := bundle + ".runc.log"
			if _, err := os.Stat(logPath); err != nil {
				t.Errorf("runc log: %v", err)
			}
			if _, err := os.Stat(filepath.Join(bundle, filepath.Base(logPath))); err == nil {
				t.Error("runc's log is inside the bundle")
			}
		}},
		{name: "the container's /sys is the top sysfs mount alone, read-only", check: func(t *testing.T) {
			mounts := mountsOf(t, zpid)
			sys, ok := mounts["/sys"]
			if !ok || sys.fstype != "sysfs" || sys.root != "/" {
				t.Fatalf("/sys in the container = %+v, want a bind of sysfs's root", sys)
			}
			for _, o := range []string{"ro", "nosuid", "nodev", "noexec"} {
				if !strings.Contains(","+sys.opts+",", ","+o+",") {
					t.Errorf("/sys options %q lack %s", sys.opts, o)
				}
			}
			// runc masks /sys/firmware with a mount of its own, so what
			// must be absent is the host's cgroup hierarchy.
			for point := range mounts {
				if point == "/sys/fs/cgroup" || strings.HasPrefix(point, "/sys/fs/cgroup/") {
					t.Errorf("the host's cgroup mount came with the bind: %s", point)
				}
			}
			sysDir := filepath.Join(hm.stateDir, "sys")
			for point := range mountsOf(t, os.Getpid()) {
				if point == sysDir || strings.HasPrefix(point, sysDir+"/") {
					t.Errorf("fiberd's own namespace has the /sys bind at %s", point)
				}
			}
		}},
		{name: "runc knows the container by the zygote's pid", check: func(t *testing.T) {
			out, err := exec.Command("runc", "--root", filepath.Join(hm.stateDir, "root"), "state", "w-"+g.UID).Output()
			if err != nil {
				t.Fatalf("runc state: %v", err)
			}
			var st struct {
				PID int `json:"pid"`
			}
			if err := json.Unmarshal(out, &st); err != nil || st.PID != zpid {
				t.Fatalf("runc state = %s (%v), want pid %d", out, err, zpid)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, tc.check)
	}
}

// grantCgroup makes a grant's cgroup under the test root, as the host
// does, and removes it with everything under it when the test ends.
func grantCgroup(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(cgRoot, fmt.Sprintf("%s-%d-%d", name, os.Getpid(), time.Now().UnixNano()%1_000_000))
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	t.Cleanup(func() { removeTree(t, cgroup.Dir{Path: path}) })
	return path
}

// leaf makes an empty cgroup under the grant's and returns it with an
// open descriptor, as the host hands the backend a zygote's or a fiber's
// leaf.
func leaf(t *testing.T, parent, name string) (string, int) {
	t.Helper()
	path := filepath.Join(parent, name)
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	return path, fd
}

// removeTree kills and removes d and every cgroup under it, which runc
// may have made for its container.
func removeTree(t *testing.T, d cgroup.Dir) {
	t.Helper()
	if !d.Exists() {
		return
	}
	_ = d.Kill()
	children, _ := d.Children("")
	for _, c := range children {
		removeTree(t, c)
	}
	waitFor(t, "the cgroup "+d.Path+" to be removable", func() bool { return d.Remove() == nil })
}

// delegate hands a cgroup to the grant's mapped root, as the host does
// with the grant's directory and every leaf, so the container's zygote
// can place a fiber in a leaf through their common ancestor.
func delegate(t *testing.T, be backend.Backend, grant, path string) {
	t.Helper()
	uid, err := be.(backend.IDMapper).MappedRoot(grant)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(filepath.Join(path, "cgroup.procs"), int(uid), -1); err != nil {
		t.Fatal(err)
	}
}

// TestReleaseKeepsRestoredCopy drives the backend itself, below the host,
// which ends a grant's fibers with its engine. Releasing the zygote keeps
// the grant's root filesystem copy while a fiber restored on this home
// still runs in its range, and the copy goes with the last user.
func TestReleaseKeepsRestoredCopy(t *testing.T) {
	cases := []struct {
		name     string
		restored bool
	}{
		{name: "a restored fiber keeps the copy past the zygote's release", restored: true},
		{name: "nothing restored, the copy goes with the zygote"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name := fmt.Sprintf("keep%d", time.Now().UnixNano()%1_000_000)
			be, err := runcbackend.New(runcbackend.Options{Rootfs: rootfs, StateDir: filepath.Join(work, name)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(be.Close)
			if be.Tier() < core.TierCheckpoint {
				t.Skip("criu not usable here")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			dir := filepath.Join("/tmp", "fz-"+name, "keep")
			t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(dir)) })
			gcg := grantCgroup(t, "keep")
			delegate(t, be, "keep", gcg)
			_, zfd := leaf(t, gcg, "zygote")
			w, err := be.Warm(ctx, backend.WarmSpec{GrantUID: "keep", Template: backend.Template{Argv: []string{"/bin/refzygote", "--heap-mb", "16"}},
				CgroupFD: zfd, ProbeCgroupFD: -1, WorkDir: dir})
			if err != nil {
				t.Fatalf("warm: %v", err)
			}
			copyDir := filepath.Join(work, name, "rootfs", "w-keep")
			if gone(copyDir) {
				t.Fatalf("no rootfs copy at %s after the warm", copyDir)
			}
			var restored backend.Fiber
			ep := filepath.Join(dir, "f.sock")
			if tc.restored {
				fl, ffd := leaf(t, gcg, "f-1-1")
				delegate(t, be, "keep", fl)
				f, err := be.Clone(ctx, w.ID, backend.FiberSpec{Generation: 1, Fence: "keep/1-1", Endpoint: ep, CgroupFD: ffd, Deadline: 2 * time.Second, OwnPIDNS: true})
				if err != nil {
					t.Fatalf("clone: %v", err)
				}
				defer func() { _ = f.Channel.Close() }()
				talk(t, ep, "incr")
				images := filepath.Join(t.TempDir(), "images")
				if err := be.Park(ctx, f.ID, backend.ParkSpec{Dir: images}); err != nil {
					t.Fatalf("park: %v", err)
				}
				if e := <-be.Exits(); e.FiberID != f.ID {
					t.Fatalf("exit = %+v, want the parked fiber", e)
				}
				// The host unlinks the parked socket before the restore
				// binds it again.
				_ = os.Remove(ep)
				rl, rfd := leaf(t, gcg, "f-2-1")
				delegate(t, be, "keep", rl)
				restored, err = be.Resume(ctx, backend.ResumeSpec{Dir: images, Fence: "keep/2-1", Endpoint: ep, CgroupFD: rfd, Deadline: 10 * time.Second, WarmID: "keep", WorkDir: dir, Generation: 2})
				if err != nil {
					t.Fatalf("resume: %v", err)
				}
				defer func() { _ = restored.Channel.Close() }()
				if got := talk(t, ep, "get"); got != "1" {
					t.Fatalf("counter after resume = %q, want 1", got)
				}
			}
			be.Unwarm(w.ID)
			if e := <-be.Exits(); e.WarmID != w.ID {
				t.Fatalf("exit = %+v, want the warm instance gone", e)
			}
			if !tc.restored {
				waitFor(t, "the copy to go with the zygote", func() bool { return gone(copyDir) })
				return
			}
			if gone(copyDir) {
				t.Fatalf("%s was removed from under the restored fiber", copyDir)
			}
			if got := talk(t, ep, "get"); got != "1" {
				t.Fatalf("the restored fiber answers %q after the zygote's release, want 1", got)
			}
			if err := be.Kill(restored.ID); err != nil {
				t.Fatalf("kill: %v", err)
			}
			if e := <-be.Exits(); e.FiberID != restored.ID {
				t.Fatalf("exit = %+v, want the restored fiber", e)
			}
			waitFor(t, "the copy to go with the last fiber", func() bool { return gone(copyDir) })
		})
	}
}

// privateRootfs is a copy of the shared rootfs with a file owned by low
// ids the copy shifts, a symlink and a fifo the copy skips.
func privateRootfs(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "rootfs")
	if out, err := exec.Command("cp", "-a", rootfs, dir).CombinedOutput(); err != nil {
		t.Fatalf("copy the rootfs: %v: %s", err, out)
	}
	for _, step := range []func() error{
		func() error { return os.MkdirAll(filepath.Join(dir, "etc"), 0o755) },
		func() error { return os.WriteFile(filepath.Join(dir, "etc", "passwd"), []byte("root"), 0o600) },
		func() error { return os.Lchown(filepath.Join(dir, "etc", "passwd"), 5, 7) },
		func() error { return os.Symlink("bin/refzygote", filepath.Join(dir, "z")) },
		func() error { return syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o600) },
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestRootfsCopy checks the grant's copy of the root filesystem: every
// owner shifted into the grant's range, symlinks kept, fifos skipped, the
// mount points owned by the mapped root, and the marker that says what it
// is a copy of. A copy left with another marker is remade.
func TestRootfsCopy(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T, hm *home, g core.Grant, src, copyDir string, start int)
	}{
		{name: "a fresh copy", run: func(t *testing.T, hm *home, g core.Grant, src, copyDir string, start int) {
			if uid, gid := ownerOf(t, filepath.Join(copyDir, "etc", "passwd")); uid != start+5 || gid != start+7 {
				t.Errorf("passwd owner = %d:%d, want shifted %d:%d", uid, gid, start+5, start+7)
			}
			if uid, _ := ownerOf(t, filepath.Join(copyDir, "bin", "refzygote")); uid != start {
				t.Errorf("refzygote owner = %d, want the mapped root %d", uid, start)
			}
			if link, err := os.Readlink(filepath.Join(copyDir, "z")); err != nil || link != "bin/refzygote" {
				t.Errorf("symlink z = %q, %v", link, err)
			}
			if !gone(filepath.Join(copyDir, "fifo")) {
				t.Error("the fifo was copied")
			}
			for _, d := range []string{"proc", "dev", "sys", "host", "tmp", "fiberd/template"} {
				if uid, _ := ownerOf(t, filepath.Join(copyDir, d)); uid != start {
					t.Errorf("mount point %s owner = %d, want %d", d, uid, start)
				}
			}
			b, err := os.ReadFile(filepath.Join(copyDir, ".fiberd-rootfs.json"))
			if err != nil {
				t.Fatalf("marker: %v", err)
			}
			var rec struct {
				Source string `json:"source"`
				Start  int    `json:"start"`
				Count  int    `json:"count"`
			}
			if err := json.Unmarshal(b, &rec); err != nil {
				t.Fatal(err)
			}
			if rec.Source != src || rec.Start != start || rec.Count != runcbackend.SlotIDs {
				t.Errorf("marker = %+v, want source %s start %d count %d", rec, src, start, runcbackend.SlotIDs)
			}
		}},
		{name: "a copy left with another marker is remade", run: func(t *testing.T, hm *home, g core.Grant, _, copyDir string, start int) {
			hm.killZygote(t, g.UID)
			waitFor(t, "the copy to go with the zygote", func() bool { return gone(copyDir) })
			if err := os.MkdirAll(copyDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(copyDir, ".fiberd-rootfs.json"), []byte(`{"source":"/elsewhere","start":1,"count":1}`), 0o644); err != nil {
				t.Fatal(err)
			}
			sentinel := filepath.Join(copyDir, "sentinel")
			if err := os.WriteFile(sentinel, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := hm.rt.PrepareTemplate(context.Background(), g); err != nil {
				t.Fatalf("prepare again: %v", err)
			}
			if !gone(sentinel) {
				t.Error("a copy with another marker was kept")
			}
			if uid, _ := ownerOf(t, filepath.Join(copyDir, "bin", "refzygote")); uid != start {
				t.Errorf("remade copy's refzygote owner = %d, want %d", uid, start)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := grantFor("copy")
			private := privateRootfs(t)
			hm := warmed(t, func(ro *runcbackend.Options, _ *host.Config) { ro.Rootfs = private }, g)
			tc.run(t, hm, g, private, filepath.Join(hm.stateDir, "rootfs", "w-"+g.UID), hm.mappedRoot(t, g.UID))
		})
	}
}

// socketInodes lists the unix socket inodes of pid's network namespace.
func socketInodes(t *testing.T, pid int) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/unix", pid))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for i, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 7 {
			continue
		}
		out[f[6]] = true
	}
	return out
}

// TestChannelInContainerNetns checks that the zygote's control socket is
// a pair made in the container's network namespace, where a checkpoint
// of the zygote finds it, and that a resumed fiber's fresh namespace has
// its loopback up.
func TestChannelInContainerNetns(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T, hm *home, g core.Grant)
	}{
		{name: "the rebound control socket lives in the container's namespace", run: func(t *testing.T, hm *home, g core.Grant) {
			zpid := hm.zygotePID(t, g.UID)
			if nsOf(t, zpid, "net") == nsOf(t, os.Getpid(), "net") {
				t.Fatal("the zygote shares the host's network namespace")
			}
			link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/3", zpid))
			if err != nil {
				t.Fatal(err)
			}
			ino := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			if ino == link {
				t.Fatalf("the zygote's fd 3 is %q, not a socket", link)
			}
			if !socketInodes(t, zpid)[ino] {
				t.Fatalf("socket %s is not in the container's namespace", ino)
			}
			if socketInodes(t, os.Getpid())[ino] {
				t.Fatalf("socket %s is in the host's namespace", ino)
			}
		}},
		{name: "a resumed fiber's loopback is up", run: func(t *testing.T, hm *home, g core.Grant) {
			ctx := context.Background()
			h := clone(t, hm, g, 1)
			ref, err := hm.rt.Park(ctx, h.ID, true)
			if err != nil {
				t.Fatalf("park: %v", err)
			}
			fence := core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 2}
			h2, err := hm.rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: fence, Deadline: 5 * time.Second})
			if err != nil {
				t.Fatalf("resume: %v", err)
			}
			defer func() { _ = hm.rt.Release(ctx, h2.ID, true) }()
			pid := hm.fiberPID(t, fence)
			if nsOf(t, pid, "net") == nsOf(t, hm.zygotePID(t, g.UID), "net") {
				t.Fatal("the restored fiber shares the zygote's network namespace")
			}
			out, err := exec.Command("nsenter", "-t", strconv.Itoa(pid), "-n", "ip", "-o", "link", "show", "lo").CombinedOutput()
			if err != nil {
				t.Fatalf("ip link in the namespace of %d: %v: %s", pid, err, out)
			}
			if !strings.Contains(string(out), ",UP") && !strings.Contains(string(out), "<UP") {
				t.Fatalf("the restored fiber's loopback is down: %s", out)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := grantFor("netns")
			tc.run(t, warmed(t, nil, g), g)
		})
	}
}
