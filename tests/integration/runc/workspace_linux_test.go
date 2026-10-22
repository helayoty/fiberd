//go:build linux && integration

package runctest

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
	runcbackend "github.com/helayoty/fiberd/pkg/backend/runc"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/runtime/host"
	"github.com/helayoty/fiberd/pkg/sys/criu"
)

// The tests here pin workspaces on runc (#33, stage 4). A fiber of a
// grant with a disk budget is born into its own copy of the container's
// mount namespace and moves its workspace onto /workspace there. Its
// park names that mount and every file it still holds through the
// container's mounts (fiberd-foreign.json), and its resume hands both
// back. The proc suite pins the same flows on proc
// (tests/integration/proc/workspace_linux_test.go), and the Python
// suite parks a dynamic template's fiber with many foreign files
// (tests/integration/python/workspace_linux_test.go).

// wsGrant is a grant of the reference template with the disk budget
// given, none for 0.
func wsGrant(uid string, disk uint64) core.Grant {
	g := grantFor(uid)
	g.DiskBudgetBytes = disk
	return g
}

// wsHome is a runc home with its workspaces beside its deltas, in a
// directory the test knows. mod, when set, adjusts the options after.
func wsHome(t *testing.T, mod func(*runcbackend.Options, *host.Config)) (*home, string) {
	t.Helper()
	var wsDir string
	hm := newHome(t, func(ro *runcbackend.Options, hc *host.Config) {
		hc.WorkspaceDir = filepath.Join(filepath.Dir(hc.DeltaDir), "workspaces")
		if mod != nil {
			mod(ro, hc)
		}
		wsDir = hc.WorkspaceDir
	})
	return hm, wsDir
}

// wsRoot is the host directory a fiber's workspace tree lives in.
func wsRoot(wsDir string, f core.Fence) string {
	return filepath.Join(wsDir, f.GrantUID, fmt.Sprintf("%d-%d", f.Epoch, f.Seq), "root")
}

// fileStore is the runtime's file store.
func fileStore(t *testing.T, rt core.Runtime) core.FileStore {
	t.Helper()
	fs, ok := rt.(core.FileStore)
	if !ok {
		t.Fatal("the runtime moves no files")
	}
	return fs
}

// upload puts body at rel in the fiber's workspace.
func upload(t *testing.T, rt core.Runtime, fiberID, rel, body string) {
	t.Helper()
	if _, err := fileStore(t, rt).Upload(context.Background(), fiberID, rel, int64(len(body)), 0o644, nil, strings.NewReader(body)); err != nil {
		t.Fatalf("upload %s: %v", rel, err)
	}
}

// download reads rel from the fiber's workspace.
func download(t *testing.T, rt core.Runtime, fiberID, rel string) string {
	t.Helper()
	f, err := fileStore(t, rt).Download(context.Background(), fiberID, rel, 0)
	if err != nil {
		t.Fatalf("download %s: %v", rel, err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// resumeWS brings ref back under g as the next fence and returns the
// error rather than failing, for the resumes a test expects refused.
func resumeWS(rt core.Runtime, g core.Grant, ref string, seq uint64) (core.FiberHandle, error) {
	return rt.Clone(context.Background(), core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref,
		Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: seq}, Deadline: 10 * time.Second})
}

// foreignEntry is one file of fiberd-foreign.json, the fields read here.
type foreignEntry struct {
	Key   string `json:"key"`
	Path  string `json:"path"`
	Mount string `json:"mount"`
}

// foreignRecord reads fiberd-foreign.json beside the images in ref.
func foreignRecord(t *testing.T, ref string) []foreignEntry {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(ref, "fiberd-foreign.json"))
	if err != nil {
		t.Fatalf("the park recorded no foreign files: %v", err)
	}
	var list []foreignEntry
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatalf("fiberd-foreign.json: %v", err)
	}
	return list
}

// mountCount is how many times point is a mount point in pid's table.
func mountCount(t *testing.T, pid int, point string) int {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) > 4 && f[4] == point {
			n++
		}
	}
	return n
}

// rootfsCopy is the grant's root filesystem copy on the home.
func (h *home) rootfsCopy(grant string) string {
	return filepath.Join(h.stateDir, "rootfs", "w-"+grant)
}

// TestWorkspaceRoundTrip pins the whole path of a file on runc, as the
// proc suite does on proc. A file uploaded from the host is read by the
// fiber at /workspace, the fiber writes beside it and overwrites it,
// the park puts the tree in workspace.tar, the resume unpacks it into a
// fresh workspace, and the download gives the same bytes. The fiber
// owns its tree: every file on the host is the grant's mapped root's,
// before and after the resume. A file the fiber holds open through the
// park keeps its offset and content, and the park records the
// template's own text as held through the container's root mount.
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
			hm, wsDir := wsHome(t, nil)
			g := wsGrant("gws", 1<<20)
			if err := hm.rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			h := clone(t, hm, g, 1)
			mapped := hm.mappedRoot(t, g.UID)
			if got := talk(t, h.Endpoint, "stat "+backend.WorkspaceMount); got != "dir" {
				t.Fatalf("stat /workspace = %q, want dir", got)
			}
			upload(t, hm.rt, h.ID, "in/data.txt", "first line\nsecond\n")
			steps := []struct{ line, want string }{
				{line: "read " + backend.WorkspaceMount + "/in/data.txt", want: "first line"},
				{line: "write " + backend.WorkspaceMount + "/result.txt hello from the fiber", want: "ok"},
				// Uploaded as the mapped root, so the fiber, root inside,
				// may write over it. Host root's would read as nobody's.
				{line: "write " + backend.WorkspaceMount + "/in/data.txt overwritten by the fiber", want: "ok"},
				{line: "hold " + backend.WorkspaceMount + "/held.txt", want: "ok"},
				{line: "held write first", want: "ok"},
			}
			for _, s := range steps {
				if got := talk(t, h.Endpoint, s.line); got != s.want {
					t.Fatalf("%s = %q, want %q", s.line, got, s.want)
				}
			}
			for rel, want := range map[string]string{"in/data.txt": "overwritten by the fiber\n", "result.txt": "hello from the fiber\n"} {
				if got := download(t, hm.rt, h.ID, rel); got != want {
					t.Fatalf("download %s before the park = %q, want %q", rel, got, want)
				}
			}
			owned := func(when, root string, rels ...string) {
				t.Helper()
				for _, rel := range rels {
					if uid, gid := ownerOf(t, filepath.Join(root, rel)); uid != mapped || gid != mapped {
						t.Errorf("%s: %s/%s is %d:%d on the host, want the mapped root %d", when, root, rel, uid, gid, mapped)
					}
				}
			}
			owned("born", wsRoot(wsDir, core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}), ".", "in", "in/data.txt", "result.txt", "held.txt")
			ref, err := hm.rt.Park(ctx, h.ID, tc.sync)
			if err != nil {
				t.Fatalf("park: %v", err)
			}
			if _, err := os.Stat(filepath.Join(ref, "workspace.tar")); err != nil {
				t.Fatalf("the delta carries no workspace.tar: %v", err)
			}
			text := false
			for _, e := range foreignRecord(t, ref) {
				if e.Path == "/bin/refzygote" && e.Mount == "rootfs" {
					text = true
				}
			}
			if !text {
				t.Fatalf("fiberd-foreign.json = %+v, want /bin/refzygote on the rootfs mount, the fiber's own text", foreignRecord(t, ref))
			}
			h2, err := resumeWS(hm.rt, g, ref, 2)
			if err != nil {
				t.Fatalf("resume: %v", err)
			}
			defer func() { _ = hm.rt.Release(ctx, h2.ID, true) }()
			after := []struct{ line, want string }{
				{line: "read " + backend.WorkspaceMount + "/in/data.txt", want: "overwritten by the fiber"},
				{line: "held write second", want: "ok"},
				{line: "held read", want: "first"},
				{line: "write " + backend.WorkspaceMount + "/after.txt written after the resume", want: "ok"},
			}
			for _, s := range after {
				if got := talk(t, h2.Endpoint, s.line); got != s.want {
					t.Fatalf("after the resume %s = %q, want %q", s.line, got, s.want)
				}
			}
			for rel, want := range map[string]string{
				"in/data.txt": "overwritten by the fiber\n",
				"result.txt":  "hello from the fiber\n",
				"held.txt":    "first\nsecond\n", // the held file's offset carried on
				"after.txt":   "written after the resume\n",
			} {
				if got := download(t, hm.rt, h2.ID, rel); got != want {
					t.Errorf("download %s after the resume = %q, want %q", rel, got, want)
				}
			}
			owned("resumed", wsRoot(wsDir, core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 2}), ".", "in", "in/data.txt", "result.txt", "held.txt", "after.txt")
		})
	}
}

// TestWorkspaceBesideNone pins what a fiber without a workspace sees in
// the container of a grant whose other fibers have one. It shares the
// container's namespace, where /workspace is fiberd's empty mount point,
// host root's and mode 0, so it can neither write there nor reach
// anything under it, a sibling's files included. Its sibling has
// /workspace mounted once in a namespace of its own, and neither the
// container init nor the plain fiber has any mount there. The clone
// without a disk budget is the same grant's, as fiberd sends it once
// the budget is gone.
func TestWorkspaceBesideNone(t *testing.T) {
	ctx := context.Background()
	hm, _ := wsHome(t, nil)
	g := wsGrant("gmix", 1<<20)
	if err := hm.rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	none := g
	none.DiskBudgetBytes = 0
	a := clone(t, hm, g, 1)
	defer func() { _ = hm.rt.Release(ctx, a.ID, false) }()
	b := clone(t, hm, none, 2)
	defer func() { _ = hm.rt.Release(ctx, b.ID, false) }()
	upload(t, hm.rt, a.ID, "secret", "a's alone\n")
	cases := []struct {
		name     string
		endpoint string
		line     string
		want     string
	}{
		{name: "a reads its own file", endpoint: a.Endpoint, line: "read " + backend.WorkspaceMount + "/secret", want: "a's alone"},
		{name: "b sees the mount point as a directory", endpoint: b.Endpoint, line: "stat " + backend.WorkspaceMount, want: "dir"},
		{name: "b cannot write in it", endpoint: b.Endpoint, line: "wopen " + backend.WorkspaceMount + "/x", want: "EACCES"},
		{name: "b cannot make anything in it", endpoint: b.Endpoint, line: "mkdir " + backend.WorkspaceMount + "/d", want: "EACCES"},
		// Mode 0 refuses the lookup itself, so nothing under it is
		// reachable, and a's file is not there to find in any case.
		{name: "b reaches nothing of a's", endpoint: b.Endpoint, line: "stat " + backend.WorkspaceMount + "/secret", want: "EACCES"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := talk(t, tc.endpoint, tc.line); got != tc.want {
				t.Fatalf("%s = %q, want %q", tc.line, got, tc.want)
			}
		})
	}
	if _, err := fileStore(t, hm.rt).Upload(ctx, b.ID, "a.txt", 1, 0o644, nil, strings.NewReader("x")); !errors.Is(err, core.ErrNoWorkspace) {
		t.Fatalf("Upload to b = %v, want ErrNoWorkspace", err)
	}
	zyg := hm.zygotePID(t, g.UID)
	apid := hm.fiberPID(t, core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1})
	bpid := hm.fiberPID(t, core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 2})
	tables := []struct {
		name   string
		pid    int
		mounts int
		ownNS  bool // a mount namespace other than the container's
	}{
		{name: "the container init", pid: zyg},
		{name: "the fiber with a workspace", pid: apid, mounts: 1, ownNS: true},
		{name: "the fiber without one", pid: bpid},
	}
	for _, tc := range tables {
		t.Run(tc.name+"'s mount table", func(t *testing.T) {
			if n := mountCount(t, tc.pid, backend.WorkspaceMount); n != tc.mounts {
				t.Errorf("%s is a mount point %d times, want %d", backend.WorkspaceMount, n, tc.mounts)
			}
			if own := nsOf(t, tc.pid, "mnt") != nsOf(t, zyg, "mnt"); own != tc.ownNS {
				t.Errorf("own mount namespace = %v, want %v", own, tc.ownNS)
			}
		})
	}
	var st syscall.Stat_t
	point := filepath.Join(hm.rootfsCopy(g.UID), strings.TrimPrefix(backend.WorkspaceMount, "/"))
	if err := syscall.Lstat(point, &st); err != nil {
		t.Fatal(err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR || st.Mode&0o7777 != 0 || int(st.Uid) != os.Geteuid() {
		t.Fatalf("%s is mode %#o owner %d, want a mode 0 directory of fiberd's uid %d", point, st.Mode, st.Uid, os.Geteuid())
	}
}

// TestWorkspaceMountRefused pins that a fiber cannot take its workspace
// off /workspace or move it, born or resumed. The kernel would let it,
// since a runc fiber holds CAP_SYS_ADMIN over its own mount namespace,
// so the refusal is the filters'. The fiber without a workspace in the
// same container is refused too: it shares the container's namespace,
// where the gate would let it move the container's mounts under its
// siblings. The workspace is still there afterwards.
func TestWorkspaceMountRefused(t *testing.T) {
	ctx := context.Background()
	hm, _ := wsHome(t, nil)
	g := wsGrant("gmnt", 1<<20)
	if err := hm.rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	none := g
	none.DiskBudgetBytes = 0
	h := clone(t, hm, g, 1)
	plain := clone(t, hm, none, 2)
	defer func() { _ = hm.rt.Release(ctx, plain.ID, false) }()
	upload(t, hm.rt, h.ID, "marker", "still here\n")
	probes := []struct{ line, want string }{
		{line: "status Seccomp", want: "2"},
		{line: "probe umount-workspace", want: "EPERM"},
		{line: "probe move-mount-workspace", want: "EPERM"},
		{line: "probe mount", want: "EPERM"},
		{line: "read " + backend.WorkspaceMount + "/marker", want: "still here"},
	}
	check := func(when, endpoint string, lines []struct{ line, want string }) {
		for _, p := range lines {
			t.Run(when+"/"+p.line, func(t *testing.T) {
				if got := talk(t, endpoint, p.line); got != p.want {
					t.Errorf("%s = %q, want %q", p.line, got, p.want)
				}
			})
		}
	}
	check("born", h.Endpoint, probes)
	check("without a workspace", plain.Endpoint, probes[:4])
	h2 := parkResume(t, hm.rt, g, h, 3)
	defer func() { _ = hm.rt.Release(ctx, h2.ID, true) }()
	check("resumed", h2.Endpoint, probes)
}

// TestWorkspaceMountPointSwapped pins what a fiber can do to its grant's
// workspace mount point, which it may rename since the root filesystem
// copy is its grant's. A fiber without a workspace swaps /workspace for
// a link to a directory it owns. The next workspace clone fails with the
// child's workspace exit, since move_mount follows no link at its
// target, and nothing is mounted at the link's target. Only the grant's
// own clones break.
func TestWorkspaceMountPointSwapped(t *testing.T) {
	ctx := context.Background()
	hm, _ := wsHome(t, nil)
	g := wsGrant("gswap", 1<<20)
	if err := hm.rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	// A workspace clone works before the swap.
	first := clone(t, hm, g, 1)
	if err := hm.rt.Release(ctx, first.ID, false); err != nil {
		t.Fatalf("release: %v", err)
	}
	none := g
	none.DiskBudgetBytes = 0
	sib := clone(t, hm, none, 2)
	defer func() { _ = hm.rt.Release(ctx, sib.ID, false) }()
	steps := []struct{ line, want string }{
		{line: "rename " + backend.WorkspaceMount + " " + backend.WorkspaceMount + ".old", want: "ok"},
		{line: "symlink /tmp " + backend.WorkspaceMount, want: "ok"},
	}
	for _, s := range steps {
		if got := talk(t, sib.Endpoint, s.line); got != s.want {
			t.Fatalf("%s = %q, want %q", s.line, got, s.want)
		}
	}
	link := filepath.Join(hm.rootfsCopy(g.UID), strings.TrimPrefix(backend.WorkspaceMount, "/"))
	if target, err := os.Readlink(link); err != nil || target != "/tmp" {
		t.Fatalf("%s = %q, %v, want the sibling's link to /tmp", link, target, err)
	}
	_, err := hm.rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 3}, Deadline: 2 * time.Second})
	if err == nil || !strings.Contains(err.Error(), "died before ready: exit:127 (could not mount its workspace at /workspace)") {
		t.Fatalf("clone after the swap = %v, want the child's workspace exit", err)
	}
	zyg := hm.zygotePID(t, g.UID)
	for _, point := range []string{"/tmp", backend.WorkspaceMount, backend.WorkspaceMount + ".old"} {
		if n := mountCount(t, zyg, point); n != 0 {
			t.Errorf("%s is a mount point %d times in the container, want none", point, n)
		}
	}
	if got := talk(t, sib.Endpoint, "ping"); got != "pong" {
		t.Fatalf("the sibling's ping after the failed clone = %q", got)
	}
}

// cutCriu stands in for criu through Options.Commander. It runs the real
// binary for every call and drops one --external value from a dump that
// carries it, keeping the dump's log, so a test learns what criu says to
// the backend's own arguments with that one missing.
type cutCriu struct {
	value string // the --external value dropped

	mu   sync.Mutex
	logs []string // the log of each dump run without the value
}

func (c *cutCriu) Output(ctx context.Context, args []string) ([]byte, error) {
	kept, cut := dropExternal(args, c.value)
	out, err := exec.CommandContext(ctx, "criu", kept...).CombinedOutput()
	if cut {
		b, _ := os.ReadFile(logOf(kept))
		c.mu.Lock()
		c.logs = append(c.logs, string(b))
		c.mu.Unlock()
	}
	return out, err
}

// Start refuses, since the test that cuts a dump restores nothing.
func (c *cutCriu) Start([]string, []*os.File, int) (criu.Process, error) {
	return nil, errors.New("cutCriu restores nothing")
}

// dumpLogs is the log of every dump run without the value.
func (c *cutCriu) dumpLogs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string{}, c.logs...)
}

// dropExternal is args without the pair "--external value", and whether
// it was there.
func dropExternal(args []string, value string) ([]string, bool) {
	var kept []string
	cut := false
	for i := 0; i < len(args); i++ {
		if args[i] == "--external" && i+1 < len(args) && args[i+1] == value {
			cut = true
			i++
			continue
		}
		kept = append(kept, args[i])
	}
	return kept, cut
}

// logOf is where criu writes the log of a call with args, its
// --log-file inside its -D directory.
func logOf(args []string) string {
	dir, name := "", ""
	for i := 0; i+1 < len(args); i++ {
		switch args[i] {
		case "-D":
			dir = args[i+1]
		case "--log-file":
			name = args[i+1]
		}
	}
	return filepath.Join(dir, name)
}

// dropFromArchive rewrites workspace.tar in ref without the entry rel, as
// a delta whose archive lost a file would be. A local delta carries no
// signature and its archive no digest the resume checks, so the resume
// unpacks what is left and criu meets the gap.
func dropFromArchive(t *testing.T, ref, rel string) {
	t.Helper()
	p := filepath.Join(ref, "workspace.tar")
	in, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	tr, tw := tar.NewReader(bytes.NewReader(in)), tar.NewWriter(&out)
	dropped := false
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		if path.Clean(strings.TrimPrefix(hdr.Name, "./")) == rel {
			dropped = true
			continue
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(tw, tr); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if !dropped {
		t.Fatalf("%s holds no %s", p, rel)
	}
	if err := os.WriteFile(p, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestWorkspaceRefusedByCriu pins the three refusals the spike found,
// proven against criu itself on the backend's own arguments, so a
// change that made criu accept any of them would show here. Each case
// takes the least invasive way to the one thing missing.
//
//   - A dump without the workspace name. The backend always names it, so
//     the only way is to drop that one pair from its arguments, through
//     the exported Options.Commander, which runs the real criu with
//     everything else as the backend built it. criu cannot tell the
//     workspace mount's root without the name.
//   - A restore without the mount. The delta loses workspace.tar and is
//     resumed under the grant without a disk budget, so the backend
//     itself builds a restore with no workspace to name, as it would for
//     a fiber that never had one. criu has no mapping for the mount the
//     images hold.
//   - A restore whose workspace lacks a file the fiber held open. The
//     archive loses that file (dropFromArchive). criu finds nothing at
//     the path it must reopen.
//
// No case runs criu from the test by hand, so none depends on copying
// the backend's argument list, which grows with each foreign file.
func TestWorkspaceRefusedByCriu(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		// cut, when set, is dropped from the fiber's dump, and the park
		// must fail with want in criu's dump log.
		cut string
		// tamper changes the delta before the resume, which must fail
		// with want in criu's restore log.
		tamper func(t *testing.T, ref string)
		// bare resumes under the grant with no disk budget.
		bare bool
		want string
	}{
		{name: "a dump without the workspace name", cut: "mnt[" + backend.WorkspaceMount + "]:ws", want: "proper root mount"},
		{name: "a restore without the workspace mount", bare: true, want: "No mapping for",
			tamper: func(t *testing.T, ref string) {
				if err := os.Remove(filepath.Join(ref, "workspace.tar")); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "a restore whose workspace lacks a file held open", want: "held.txt",
			tamper: func(t *testing.T, ref string) { dropFromArchive(t, ref, "held.txt") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cutter *cutCriu
			hm, _ := wsHome(t, func(ro *runcbackend.Options, _ *host.Config) {
				if tc.cut != "" {
					cutter = &cutCriu{value: tc.cut}
					ro.Commander = cutter
				}
			})
			g := wsGrant("gcriu", 1<<20)
			if err := hm.rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			h := clone(t, hm, g, 1)
			upload(t, hm.rt, h.ID, "keep.txt", "kept\n")
			for _, line := range []string{"hold " + backend.WorkspaceMount + "/held.txt", "held write first"} {
				if got := talk(t, h.Endpoint, line); got != "ok" {
					t.Fatalf("%s = %q", line, got)
				}
			}
			ref, err := hm.rt.Park(ctx, h.ID, false)
			if cutter != nil {
				if err == nil || !strings.Contains(err.Error(), "criu dump") {
					t.Fatalf("park with %s dropped = %q, %v, want criu's refusal", tc.cut, ref, err)
				}
				logs := cutter.dumpLogs()
				if len(logs) == 0 {
					t.Fatalf("no dump ran without %s", tc.cut)
				}
				if !strings.Contains(logs[len(logs)-1], tc.want) {
					t.Fatalf("criu's dump log does not say %q:\n%s", tc.want, logs[len(logs)-1])
				}
				return
			}
			if err != nil {
				t.Fatalf("park: %v", err)
			}
			tc.tamper(t, ref)
			rg := g
			if tc.bare {
				rg.DiskBudgetBytes = 0
			}
			h2, err := resumeWS(hm.rt, rg, ref, 2)
			if err == nil {
				_ = hm.rt.Release(ctx, h2.ID, true)
				t.Fatal("the resume went through")
			}
			if !strings.Contains(err.Error(), "criu restore") {
				t.Fatalf("resume = %v, want criu's refusal", err)
			}
			b, rerr := os.ReadFile(filepath.Join(ref, "restore.log"))
			if rerr != nil {
				t.Fatalf("criu's restore log: %v (resume: %v)", rerr, err)
			}
			if !strings.Contains(string(b), tc.want) {
				t.Fatalf("criu's restore log does not say %q:\n%s", tc.want, b)
			}
		})
	}
}

// propagationOf is the optional fields of the mount at point in pid's
// table, such as "shared:7", "" for none, and false when point is no
// mount there.
func propagationOf(t *testing.T, pid int, point string) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		t.Fatal(err)
	}
	found, opt := false, ""
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 7 || f[4] != point {
			continue
		}
		var tags []string
		for _, w := range f[6:] {
			if w == "-" {
				break
			}
			tags = append(tags, w)
		}
		found, opt = true, strings.Join(tags, " ")
	}
	return opt, found
}

// TestWorkspaceSharedStateDir pins a fiber's workspace private on a host
// whose runc state directory, which holds the root filesystem copies,
// sits on a shared mount. The runc child cannot make its namespace
// private, since the runc program refuses mount. The bundle's rslave
// root keeps a move in one fiber's copy from reaching its siblings, the
// container or the host. Two workspace fibers of one grant each see
// their own workspace alone, mounted once, the container init sees
// neither, and the host has no mount at the copy's /workspace.
func TestWorkspaceSharedStateDir(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("mounts a bind, which needs root")
	}
	ctx := context.Background()
	shared := filepath.Join(work, fmt.Sprintf("shared%d", time.Now().UnixNano()%1_000_000))
	if err := os.MkdirAll(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount(shared, shared, "", syscall.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Unmount(shared, syscall.MNT_DETACH)
		_ = os.RemoveAll(shared)
	})
	// Private first, so the bind gets a peer group of its own rather than
	// joining its parent's.
	for _, flags := range []uintptr{syscall.MS_PRIVATE, syscall.MS_SHARED | syscall.MS_REC} {
		if err := syscall.Mount("", shared, "", flags, ""); err != nil {
			t.Fatal(err)
		}
	}
	if opt, ok := propagationOf(t, os.Getpid(), shared); !ok || !strings.Contains(opt, "shared:") {
		t.Fatalf("%s propagation = %q (mounted %v), want shared", shared, opt, ok)
	}
	hm, _ := wsHome(t, func(ro *runcbackend.Options, _ *host.Config) { ro.StateDir = filepath.Join(shared, "state") })
	g := wsGrant("gshared", 1<<20)
	if err := hm.rt.PrepareTemplate(ctx, g); err != nil {
		t.Fatal(err)
	}
	a := clone(t, hm, g, 1)
	defer func() { _ = hm.rt.Release(ctx, a.ID, false) }()
	b := clone(t, hm, g, 2)
	defer func() { _ = hm.rt.Release(ctx, b.ID, false) }()
	upload(t, hm.rt, a.ID, "a.txt", "a's\n")
	upload(t, hm.rt, b.ID, "b.txt", "b's\n")
	cases := []struct {
		name     string
		endpoint string
		line     string
		want     string
	}{
		{name: "a reads its own file", endpoint: a.Endpoint, line: "read " + backend.WorkspaceMount + "/a.txt", want: "a's"},
		{name: "b reads its own file", endpoint: b.Endpoint, line: "read " + backend.WorkspaceMount + "/b.txt", want: "b's"},
		{name: "a finds nothing of b's", endpoint: a.Endpoint, line: "stat " + backend.WorkspaceMount + "/b.txt", want: "ENOENT"},
		{name: "b finds nothing of a's", endpoint: b.Endpoint, line: "stat " + backend.WorkspaceMount + "/a.txt", want: "ENOENT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := talk(t, tc.endpoint, tc.line); got != tc.want {
				t.Fatalf("%s = %q, want %q", tc.line, got, tc.want)
			}
		})
	}
	tables := []struct {
		name   string
		pid    int
		point  string
		mounts int
	}{
		{name: "fiber a", pid: hm.fiberPID(t, core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}), point: backend.WorkspaceMount, mounts: 1},
		{name: "fiber b", pid: hm.fiberPID(t, core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 2}), point: backend.WorkspaceMount, mounts: 1},
		{name: "the container init", pid: hm.zygotePID(t, g.UID), point: backend.WorkspaceMount},
		{name: "the host", pid: os.Getpid(), point: filepath.Join(hm.rootfsCopy(g.UID), strings.TrimPrefix(backend.WorkspaceMount, "/"))},
	}
	for _, tc := range tables {
		t.Run(tc.name+"'s mount table", func(t *testing.T) {
			if n := mountCount(t, tc.pid, tc.point); n != tc.mounts {
				t.Errorf("%s is a mount point %d times, want %d", tc.point, n, tc.mounts)
			}
		})
	}
}
