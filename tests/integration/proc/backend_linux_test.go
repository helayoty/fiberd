//go:build linux && integration

package proctest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
	procbackend "github.com/helayoty/fiberd/pkg/backend/proc"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/sys/criu"
)

// The tests here drive the fork backend itself against the kernel: a
// zygote born in a cgroup, criu dumping it and its fibers with their
// mounts named, the exec of a verified descriptor, and the bind of / that
// restores need. Their unit halves run over fakes in pkg/backend/proc.

// openProc opens a fork backend the test closes.
func openProc(t *testing.T, o procbackend.Options) *procbackend.Backend {
	t.Helper()
	be := procbackend.NewBackend(o)
	t.Cleanup(be.Close)
	return be
}

// warmRef starts refzygote for grant under dir, in the cgroup fd names.
func warmRef(t *testing.T, be *procbackend.Backend, grant, dir string, fd int) backend.Warm {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	w, err := be.Warm(ctx, backend.WarmSpec{
		GrantUID: grant, Template: backend.Template{Argv: []string{zygoteBin, "--heap-mb", "16"}},
		CgroupFD: fd, ProbeCgroupFD: -1, WorkDir: dir, Hide: []string{hiddenDir},
	})
	if err != nil {
		t.Fatalf("warm %s: %v", grant, err)
	}
	return w
}

// cloneRef forks one fiber of w serving a socket under dir.
func cloneRef(t *testing.T, be *procbackend.Backend, w backend.Warm, dir, fence string, fd int) (backend.Fiber, string) {
	t.Helper()
	ep := filepath.Join(dir, strings.ReplaceAll(fence, "/", "-")+".sock")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f, err := be.Clone(ctx, w.ID, backend.FiberSpec{Generation: 1, Fence: fence, Endpoint: ep, CgroupFD: fd, Deadline: 2 * time.Second, OwnPIDNS: true})
	if err != nil {
		t.Fatalf("clone %s: %v", fence, err)
	}
	t.Cleanup(func() { _ = f.Channel.Close() })
	if got := talk(t, ep, "ping"); got != "pong" {
		t.Fatalf("ping = %q", got)
	}
	return f, ep
}

// needCheckpoint skips a test that needs criu where it is not usable.
func needCheckpoint(t *testing.T, be *procbackend.Backend) {
	t.Helper()
	if be.Tier() < core.TierCheckpoint {
		t.Skipf("criu not usable here; the backend offers %s", be.Tier())
	}
}

// readPIDs reads a cgroup.procs file.
func readPIDs(t *testing.T, path string) []int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var pids []int
	for _, f := range strings.Fields(string(data)) {
		var p int
		if _, err := fmt.Sscan(f, &p); err == nil {
			pids = append(pids, p)
		}
	}
	return pids
}

// TestWarmInCgroup checks that the zygote is born in the cgroup the host
// hands over, and in the host's own without one.
func TestWarmInCgroup(t *testing.T) {
	cases := []struct {
		name string
		leaf bool
	}{
		{name: "zygote lands in the leaf", leaf: true},
		{name: "no leaf keeps it in the host's cgroup"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := openProc(t, procbackend.Options{RootBind: filepath.Join(t.TempDir(), "root")})
			fd := -1
			leaf := ""
			if tc.leaf {
				leaf, fd = tempCgroup(t, "warm")
			}
			w := warmRef(t, be, "g", filepath.Join(t.TempDir(), "g"), fd)
			if !tc.leaf {
				if got := cgroupOf(t, w.PID); got != cgroupOf(t, os.Getpid()) {
					t.Fatalf("zygote cgroup = %s, want the host's %s", got, cgroupOf(t, os.Getpid()))
				}
				return
			}
			if got := readPIDs(t, filepath.Join(leaf, "cgroup.procs")); len(got) != 1 || got[0] != w.PID {
				t.Fatalf("cgroup.procs = %v, want just the zygote %d", got, w.PID)
			}
		})
	}
}

// TestCheckpointWarmExternalSocket checks that the zygote is dumped while
// it keeps running, with its control socket named external, so the host's
// end outside the tree does not fail the dump, and with the mounts of the
// namespace it prepared named the way a fiber's are.
func TestCheckpointWarmExternalSocket(t *testing.T) {
	cases := []struct {
		name string
	}{{name: "the zygote serves on after its self-checkpoint"}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := openProc(t, procbackend.Options{RootBind: filepath.Join(t.TempDir(), "root")})
			needCheckpoint(t, be)
			dir := filepath.Join(t.TempDir(), "g")
			w := warmRef(t, be, "g", dir, -1)
			images := filepath.Join(t.TempDir(), "images")
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := be.CheckpointWarm(ctx, w.ID, images); err != nil {
				t.Fatalf("CheckpointWarm: %v", err)
			}
			if pages, _ := filepath.Glob(filepath.Join(images, "pages-*.img")); len(pages) == 0 {
				t.Fatalf("no page images in %s", images)
			}
			// The zygote prepared a mount namespace of its own, so its
			// single-file mounts and its run directory bind are recorded
			// for the restore to bind by name.
			if _, err := os.Stat(filepath.Join(images, criu.MountsFile)); err != nil {
				t.Fatalf("%s not recorded: %v", criu.MountsFile, err)
			}
			if mp := runDirRecordIn(t, images); mp != dir {
				t.Fatalf("run directory record = %q, want %s", mp, dir)
			}
			if err := syscall.Kill(w.PID, 0); err != nil {
				t.Fatalf("the zygote is gone after a dump that should leave it running: %v", err)
			}
			cloneRef(t, be, w, dir, "g/1-1", -1)
		})
	}
}

// runDirRecordIn reads the mount point a checkpoint recorded for its
// grant's run directory.
func runDirRecordIn(t *testing.T, images string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(images, "fiberd-rundir.json"))
	if err != nil {
		t.Fatalf("run directory record: %v", err)
	}
	var rec struct {
		MountPoint string `json:"mountpoint"`
	}
	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatal(err)
	}
	return rec.MountPoint
}

// TestExecThroughVerifiedFD checks that an exec through /proc/self/fd/4
// runs the bytes the descriptor was opened on, even after the path was
// swapped, for a script as for a binary, and that a registry template's
// zygote is exec'd that way with its path still named by /proc.
func TestExecThroughVerifiedFD(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T)
	}{
		{name: "a swapped script still runs the verified bytes", run: func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "zygote")
			if err := os.WriteFile(path, []byte("#!/bin/sh\necho verified\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			if err := os.WriteFile(path+".new", []byte("#!/bin/sh\necho swapped\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(path+".new", path); err != nil {
				t.Fatal(err)
			}
			devnull, err := os.Open(os.DevNull)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = devnull.Close() }()
			// As in Warm, the descriptor is passed as fd 4, after a
			// stand-in for the control socket at fd 3.
			cmd := exec.Command(path)
			cmd.ExtraFiles = []*os.File{devnull, f}
			cmd.Path = "/proc/self/fd/4"
			out, err := cmd.Output()
			if err != nil || strings.TrimSpace(string(out)) != "verified" {
				t.Fatalf("exec through the descriptor = %q %v, want the verified bytes", out, err)
			}
		}},
		{name: "a registry template's zygote runs from the verified descriptor", run: func(t *testing.T) {
			be := openProc(t, procbackend.Options{RootBind: filepath.Join(t.TempDir(), "root")})
			exe := filepath.Join(t.TempDir(), "cache", "zygote")
			copyFile(t, zygoteBin, exe)
			dir := filepath.Join(t.TempDir(), "g")
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			w, err := be.Warm(ctx, backend.WarmSpec{
				GrantUID: "g", CgroupFD: -1, ProbeCgroupFD: -1, WorkDir: dir, Hide: []string{hiddenDir},
				Template: backend.Template{Argv: []string{exe, "--heap-mb", "16"}, Dir: filepath.Dir(exe), Digest: "sha256:test", ZygoteSHA256: sha256Hex(t, exe)},
			})
			if err != nil {
				t.Fatalf("warm: %v", err)
			}
			// The path is what /proc names, and the zygote keeps the
			// descriptor it was exec'd through as fd 4.
			if got, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", w.PID)); err != nil || got != exe {
				t.Fatalf("zygote exe = %q (%v), want %q", got, err, exe)
			}
			if got, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/4", w.PID)); err != nil || got != exe {
				t.Fatalf("zygote fd 4 = %q (%v), want the verified %q", got, err, exe)
			}
			cloneRef(t, be, w, dir, "g/1-1", -1)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, tc.run)
	}
}

// copyFile copies src to dst, executable.
func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		t.Fatal(err)
	}
}

// sha256Hex is the hex SHA-256 of a file's bytes.
func sha256Hex(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// TestParkNamesOwnMounts checks that a fiber in a mount namespace of its
// own is dumped with its single-file mounts recorded and its run directory
// bind recorded by name, and that a dump whose records cannot be written
// is refused before criu runs.
func TestParkNamesOwnMounts(t *testing.T) {
	cases := []struct {
		name    string
		images  func(t *testing.T) string
		wantErr string
	}{
		{name: "the mounts and the run directory are recorded", images: func(t *testing.T) string { return filepath.Join(t.TempDir(), "images") }},
		{name: "records under a file are refused", wantErr: "mounts of", images: func(t *testing.T) string {
			parent := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(parent, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(parent, "images")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := openProc(t, procbackend.Options{RootBind: filepath.Join(t.TempDir(), "root")})
			needCheckpoint(t, be)
			dir := filepath.Join(t.TempDir(), "g")
			w := warmRef(t, be, "g", dir, -1)
			f, _ := cloneRef(t, be, w, dir, "g/1-1", -1)
			images := tc.images(t)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			err := be.Park(ctx, f.ID, backend.ParkSpec{Dir: images})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Park = %v, want %q", err, tc.wantErr)
				}
				if err := syscall.Kill(f.PID, 0); err != nil {
					t.Fatalf("a refused park ended the fiber: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Park: %v", err)
			}
			if _, err := os.Stat(filepath.Join(images, criu.MountsFile)); err != nil {
				t.Fatalf("%s not recorded: %v", criu.MountsFile, err)
			}
			if mp := runDirRecordIn(t, images); mp != dir {
				t.Fatalf("run directory record = %q, want %s", mp, dir)
			}
			// Without Sync the dump ends the tree, and the zygote reports it.
			select {
			case e := <-be.Exits():
				if e.FiberID != f.ID {
					t.Fatalf("exit = %+v, want the parked fiber", e)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no exit for the parked fiber")
			}
		})
	}
}

// recordingCriu stands in for criu through Options.Commander. It is
// criu 4.2.1, passes check, records every call and starts restores that hold until the test
// ends, so what the backend mounts around a restore can be checked
// without a tree to restore.
type recordingCriu struct {
	calls []string
	procs []*heldProcess
}

func (r *recordingCriu) Output(_ context.Context, args []string) ([]byte, error) {
	r.calls = append(r.calls, strings.Join(args, " "))
	if len(args) == 1 && args[0] == "--version" {
		return []byte("Version: 4.2.1\n"), nil
	}
	return nil, nil
}

func (r *recordingCriu) Start(args []string, files []*os.File, cgroupFD int) (criu.Process, error) {
	r.calls = append(r.calls, strings.Join(args, " "))
	for i, a := range args {
		if a == "--pidfile" && i+1 < len(args) {
			if err := os.WriteFile(args[i+1], []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
				return nil, err
			}
		}
	}
	p := &heldProcess{done: make(chan struct{})}
	r.procs = append(r.procs, p)
	return p, nil
}

// last is the most recent call.
func (r *recordingCriu) last() string {
	if len(r.calls) == 0 {
		return ""
	}
	return r.calls[len(r.calls)-1]
}

// release ends every restore, as the trees exiting would.
func (r *recordingCriu) release() {
	for _, p := range r.procs {
		p.end()
	}
}

// heldProcess is a restore that waits to be ended.
type heldProcess struct {
	once sync.Once
	done chan struct{}
}

func (p *heldProcess) Pid() int    { return os.Getpid() }
func (p *heldProcess) Kill() error { p.end(); return nil }
func (p *heldProcess) Wait() error { <-p.done; return nil }
func (p *heldProcess) end()        { p.once.Do(func() { close(p.done) }) }

// mountsCheckpoint is a checkpoint directory of a tree with a mount
// namespace and the run directory record given, "" for none.
func mountsCheckpoint(t *testing.T, runDir string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, criu.MountsFile), []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if runDir != "" {
		if err := os.WriteFile(filepath.Join(dir, "fiberd-rundir.json"), []byte(runDir), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// pairBorrow stands in for pidfd_getfd under a recorded restore, whose
// "tree" is this process: it hands out ends of one pair of the test's
// own, the read end for fd 4 and the peer for fd 5, as the restored
// fiber would hold them.
func pairBorrow(t *testing.T) func(pid, fd int) (*os.File, error) {
	t.Helper()
	sv, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	// The restored fiber, played here: it takes the resume's record off
	// its end and acks under the record's fence, which Resume waits for.
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, backend.RecordMax)
		for {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
			n, _, _, _, err := syscall.Recvmsg(sv[0], buf, nil, syscall.MSG_DONTWAIT)
			if err != nil {
				continue
			}
			if inc, err := backend.ParseIncarnation(buf[:n]); err == nil {
				_ = syscall.Sendmsg(sv[0], backend.Record(backend.RecordAck, inc.Fence), nil, nil, syscall.MSG_DONTWAIT|syscall.MSG_NOSIGNAL)
			}
		}
	}()
	t.Cleanup(func() { close(stop); <-done; _ = syscall.Close(sv[0]); _ = syscall.Close(sv[1]) })
	return func(_ int, fd int) (*os.File, error) {
		end := sv[0]
		if fd == 5 {
			end = sv[1]
		}
		dup, err := syscall.Dup(end)
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(dup), "borrowed"), nil
	}
}

// resumeOn restores the checkpoint in dir on be for grant g2.
func resumeOn(t *testing.T, be *procbackend.Backend, dir, workDir string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f, err := be.Resume(ctx, backend.ResumeSpec{Dir: dir, Fence: "g/2-1", Endpoint: filepath.Join(workDir, "ep.sock"), CgroupFD: -1, WarmID: "g", WorkDir: workDir, Generation: 2})
	if err == nil {
		t.Cleanup(func() { _ = f.Channel.Close() })
	}
	return err
}

// TestResumeBindsRunDir checks that a checkpoint with a mount namespace is
// restored with the restore root bound, private, as criu's --root, and
// its run directory mount bound to the resuming grant's directory. The
// bind goes when the backend closes, whether or not the restore went
// through.
func TestResumeBindsRunDir(t *testing.T) {
	cases := []struct {
		name     string
		record   string // the run directory record, "" for none
		prepare  func(t *testing.T, rootBind string)
		refused  bool // the root was refused before any mount
		wantArgs []string
		wantErr  string
	}{
		{name: "the restore root and the run directory are bound", record: `{"mountpoint":"/tmp/fz-a/g"}`,
			wantArgs: []string{"--root ROOT --external mnt[]", "--external mnt[rundir]:WORK"}},
		{name: "a checkpoint without a run directory binds the root alone", wantArgs: []string{"--root ROOT --external mnt[]"}},
		{name: "a malformed run directory record is refused after the root is bound", record: "nonsense", wantErr: "malformed"},
		// A path the backend cannot trust is refused before any mount: a
		// directory someone else owns is theirs to replace, and a mount
		// already there is another instance's.
		{name: "someone else's directory is refused", refused: true, wantErr: "owned by uid 1000", prepare: func(t *testing.T, rootBind string) {
			if err := os.Mkdir(rootBind, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(rootBind, 1000, 1000); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a mount point of something else is refused", refused: true, wantErr: "already a mount point", prepare: func(t *testing.T, rootBind string) {
			if err := os.Mkdir(rootBind, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mount(filepath.Dir(rootBind), rootBind, "", syscall.MS_BIND, ""); err != nil {
				t.Fatal(err)
			}
			unmountLater(t, rootBind)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc := &recordingCriu{}
			t.Cleanup(rc.release)
			rootBind := filepath.Join(t.TempDir(), "root")
			if tc.prepare != nil {
				tc.prepare(t, rootBind)
			}
			be := openProc(t, procbackend.Options{RootBind: rootBind, Commander: rc, Borrow: pairBorrow(t)})
			dir := mountsCheckpoint(t, tc.record)
			workDir := filepath.Join(t.TempDir(), "g2")
			err := resumeOn(t, be, dir, workDir)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Resume = %v, want %q", err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatalf("Resume: %v", err)
			}
			if tc.refused {
				// Nothing was mounted over it, and Close leaves it alone.
				before, _ := mountAt(t, rootBind)
				be.Close()
				after, mounted := mountAt(t, rootBind)
				if (tc.wantErr == "already a mount point") != mounted || strings.Join(before, " ") != strings.Join(after, " ") {
					t.Fatalf("mount at %s changed around a refused resume: %v then %v (mounted %v)", rootBind, before, after, mounted)
				}
				return
			}
			if err == nil {
				restore := rc.last()
				for _, want := range tc.wantArgs {
					want = strings.NewReplacer("ROOT", rootBind, "WORK", workDir).Replace(want)
					if !strings.Contains(restore, want) {
						t.Fatalf("criu restore %q lacks %q", restore, want)
					}
				}
				// The resuming grant's directory is made for the bind,
				// and only then.
				if _, err := os.Stat(workDir); (err == nil) != (tc.record != "") {
					t.Fatalf("the resuming grant's directory: %v, want it made only with a run directory to bind", err)
				}
			}
			opts, mounted := mountAt(t, rootBind)
			if !mounted {
				t.Fatalf("%s is not mounted while the checkpoint is resumed on it", rootBind)
			}
			for _, o := range opts {
				if strings.HasPrefix(o, "shared:") || strings.HasPrefix(o, "master:") {
					t.Fatalf("restore root propagates: %v", opts)
				}
			}
			if _, err := os.Stat(filepath.Join(rootBind, "proc")); err != nil {
				t.Fatalf("the bind does not show /: %v", err)
			}
			be.Close()
			if _, mounted := mountAt(t, rootBind); mounted {
				t.Fatalf("%s still mounted after Close", rootBind)
			}
			if _, err := os.Lstat(rootBind); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("Lstat %s after Close = %v, want not exist", rootBind, err)
			}
		})
	}
}

// TestRootBindShared checks that backends naming the same restore root
// share one bind, which the last to close unmounts, and that a backend
// resuming twice holds it once.
func TestRootBindShared(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T, dir string, a, b *procbackend.Backend, images string)
	}{
		{name: "two backends, the last one unmounts", run: func(t *testing.T, dir string, a, b *procbackend.Backend, images string) {
			for _, be := range []*procbackend.Backend{a, b} {
				if err := resumeOn(t, be, images, filepath.Join(t.TempDir(), "g2")); err != nil {
					t.Fatal(err)
				}
			}
			a.Close()
			if _, mounted := mountAt(t, dir); !mounted {
				t.Fatal("the first close unmounted a bind the second backend holds")
			}
			b.Close()
		}},
		{name: "holding twice is holding once", run: func(t *testing.T, _ string, a, _ *procbackend.Backend, images string) {
			for i := 0; i < 2; i++ {
				if err := resumeOn(t, a, images, filepath.Join(t.TempDir(), "g2")); err != nil {
					t.Fatal(err)
				}
			}
			a.Close()
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc := &recordingCriu{}
			t.Cleanup(rc.release)
			dir := filepath.Join(t.TempDir(), "root")
			a := openProc(t, procbackend.Options{RootBind: dir, Commander: rc, Borrow: pairBorrow(t)})
			b := openProc(t, procbackend.Options{RootBind: dir, Commander: rc, Borrow: pairBorrow(t)})
			tc.run(t, dir, a, b, mountsCheckpoint(t, ""))
			if _, mounted := mountAt(t, dir); mounted {
				t.Fatalf("%s still mounted", dir)
			}
			if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("Lstat %s = %v, want not exist", dir, err)
			}
		})
	}
}

// bindSlash binds / at point for a test, records the holder given, and
// unmounts whatever is left there when the test ends.
func bindSlash(t *testing.T, point, holder string) {
	t.Helper()
	if err := os.MkdirAll(point, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount("/", point, "", syscall.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	unmountLater(t, point)
	if holder != "" {
		if err := os.WriteFile(point+".pid", []byte(holder), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// unmountLater detaches every bind at point when the test ends and
// removes the directory and its holder file.
func unmountLater(t *testing.T, point string) {
	t.Helper()
	t.Cleanup(func() {
		for i := 0; i < 16; i++ {
			if _, mounted := mountAt(t, point); !mounted {
				break
			}
			if err := syscall.Unmount(point, syscall.MNT_DETACH); err != nil {
				t.Errorf("unmount %s: %v", point, err)
				return
			}
		}
		_ = os.Remove(point)
		_ = os.Remove(point + ".pid")
	})
}

// TestReapStaleRoots checks that binds of / a dead run left at this
// configuration's path, and at dead pids' default paths beside it, are
// unmounted when the backend opens. Binds a live process records, binds
// that are not of /, and binds elsewhere stay.
func TestReapStaleRoots(t *testing.T) {
	impossible := strconv.Itoa(1<<22 + 1) // past any pid_max
	cases := []struct {
		name  string
		setup func(t *testing.T, base string) (opt procbackend.Options, stay, reaped []string)
	}{
		{name: "a stale bind at the configured path goes", setup: func(t *testing.T, base string) (procbackend.Options, []string, []string) {
			dir := filepath.Join(base, "root")
			bindSlash(t, dir, "")
			return procbackend.Options{RootBind: dir}, nil, []string{dir}
		}},
		{name: "a live holder keeps its bind", setup: func(t *testing.T, base string) (procbackend.Options, []string, []string) {
			dir := filepath.Join(base, "root")
			bindSlash(t, dir, "1\n")
			return procbackend.Options{RootBind: dir}, []string{dir}, nil
		}},
		{name: "a dead holder's bind goes", setup: func(t *testing.T, base string) (procbackend.Options, []string, []string) {
			dir := filepath.Join(base, "root")
			bindSlash(t, dir, impossible)
			return procbackend.Options{RootBind: dir}, nil, []string{dir}
		}},
		{name: "stacked binds come off one per pass", setup: func(t *testing.T, base string) (procbackend.Options, []string, []string) {
			dir := filepath.Join(base, "root")
			bindSlash(t, dir, "")
			bindSlash(t, dir, "")
			return procbackend.Options{RootBind: dir}, nil, []string{dir}
		}},
		{name: "a bind that is not of / stays, as does one elsewhere", setup: func(t *testing.T, base string) (procbackend.Options, []string, []string) {
			dir := filepath.Join(base, "root")
			other := filepath.Join(base, "unrelated")
			bindSlash(t, other, "")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mount(base, dir, "", syscall.MS_BIND, ""); err != nil {
				t.Fatal(err)
			}
			unmountLater(t, dir)
			return procbackend.Options{RootBind: dir}, []string{dir, other}, nil
		}},
		{name: "the default root reaps a dead sibling and keeps a live one", setup: func(t *testing.T, _ string) (procbackend.Options, []string, []string) {
			dead := filepath.Join(os.TempDir(), "fiberd-root-"+impossible)
			live := filepath.Join(os.TempDir(), "fiberd-root-1")
			bindSlash(t, dead, "")
			bindSlash(t, live, "")
			return procbackend.Options{}, []string{live}, []string{dead}
		}},
		{name: "a configured root leaves siblings alone", setup: func(t *testing.T, base string) (procbackend.Options, []string, []string) {
			dead := filepath.Join(base, "fiberd-root-"+impossible)
			bindSlash(t, dead, "")
			return procbackend.Options{RootBind: filepath.Join(base, "root")}, []string{dead}, nil
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			opt, stay, reaped := tc.setup(t, base)
			be := openProc(t, opt)
			be.Close()
			for _, p := range stay {
				if _, mounted := mountAt(t, p); !mounted {
					t.Errorf("%s was unmounted, want it kept", p)
				}
			}
			for _, p := range reaped {
				if _, mounted := mountAt(t, p); mounted {
					t.Errorf("%s is still mounted, want it reaped", p)
				}
				if _, err := os.Lstat(p); err == nil {
					t.Errorf("%s still exists, want it removed", p)
				}
			}
		})
	}
}
