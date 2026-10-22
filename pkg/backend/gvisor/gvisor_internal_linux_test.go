//go:build linux

package gvisor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
)

// newFake opens a backend over an in-process fake runsc. Everything it
// starts is ended when the test is.
func newFake(t *testing.T, k knobs) (*Backend, *fakeRunsc) {
	t.Helper()
	return newFakeMax(t, k, 0)
}

// newFakeMax is newFake with the restore bound set (0 for the default).
func newFakeMax(t *testing.T, k knobs, maxRestores int) (*Backend, *fakeRunsc) {
	t.Helper()
	f := newFakeRunsc(k)
	rootfs := filepath.Join(t.TempDir(), "rootfs")
	if err := os.Mkdir(rootfs, 0o755); err != nil {
		t.Fatal(err)
	}
	// A short state directory. The pool socket lives under it, and a unix
	// socket path is at most 108 bytes, which a test's TempDir can pass.
	state, err := os.MkdirTemp("", "gv")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(state) })
	b := newBackend(Options{Runsc: "runsc", Rootfs: rootfs, StateDir: filepath.Join(state, "state"), MaxRestores: maxRestores}, f.run, newFakeTmpfs().ops())
	b.await = f.awaitExit
	if b.Tier() != core.TierSnapshot {
		t.Fatalf("Tier = %s (%v), want FIBER_SNAPSHOT over the fake", b.Tier(), b.ProbeErr())
	}
	t.Cleanup(func() { endFake(t, b, f) })
	return b, f
}

// endFake is the fixture's teardown: knobs reset (so a kill scripted to
// fail cannot hold Close to its bound), Close, then whatever the fake
// still runs is ended.
func endFake(t *testing.T, b *Backend, f *fakeRunsc) {
	t.Helper()
	f.setKnobs(knobs{})
	b.Close()
	f.endAll()
	if !reapersDone(b, time.Second) {
		t.Error("a reaper is still running after Close")
	}
}

// reapersDone reports whether every reaper has finished within the bound.
func reapersDone(b *Backend, bound time.Duration) bool {
	done := make(chan struct{})
	go func() {
		b.reapers.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(bound):
		return false
	}
}

// waitFor polls cond until it holds or the bound passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// waitExit takes the next exit the backend reports.
func waitExit(t *testing.T, b *Backend) backend.Exit {
	t.Helper()
	select {
	case e := <-b.Exits():
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("no exit reported")
		return backend.Exit{}
	}
}

// warmCID is the container id of the registered warm instance id.
func warmCID(t *testing.T, b *Backend, id string) string {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	w := b.warms[id]
	if w == nil {
		t.Fatalf("no warm instance %q", id)
	}
	return w.cid
}

// boxCID is the container id of the registered fiber id.
func boxCID(t *testing.T, b *Backend, id string) string {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	x := b.boxes[id]
	if x == nil {
		t.Fatalf("no fiber %q", id)
	}
	return x.cid
}

// lastField is the last space-separated word of a recorded call, which is
// the container id of a run or restore.
func lastField(call string) string {
	f := strings.Fields(call)
	if len(f) == 0 {
		return ""
	}
	return f[len(f)-1]
}

// warmed is a backend with the template for grant g warm.
func warmed(t *testing.T, k knobs) (*Backend, *fakeRunsc, backend.Warm, string) {
	t.Helper()
	b, f := newFake(t, k)
	workDir := filepath.Join(t.TempDir(), "g")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "g", Template: backend.Template{Argv: []string{"/bin/refzygote", "--gvisor"}}, CgroupFD: -1, ProbeCgroupFD: -1, WorkDir: workDir})
	if err != nil {
		t.Fatalf("Warm: %v", err)
	}
	return b, f, w, workDir
}

// cloned is warmed plus one fiber serving on <workDir>/ep.sock.
func cloned(t *testing.T, k knobs) (*Backend, *fakeRunsc, string, backend.Fiber) {
	t.Helper()
	b, f, w, workDir := warmed(t, k)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fb, err := b.Clone(ctx, w.ID, backend.FiberSpec{Fence: "g/1-1", Endpoint: filepath.Join(workDir, "ep.sock"), CgroupFD: -1, Deadline: 2 * time.Second, Generation: 1})
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	return b, f, workDir, fb
}

// dialable reports whether a unix socket accepts a connection.
func dialable(path string) bool {
	c, err := net.DialTimeout("unix", path, 100*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// findCall is the first recorded runsc invocation containing every part.
func findCall(calls []string, parts ...string) string {
	for _, c := range calls {
		if containsAll(c, parts) {
			return c
		}
	}
	return ""
}

// lastRestored is the cid of the last restore recorded, which is the
// sandbox the call under test brought up, after the footprint probe's.
func lastRestored(calls []string) string {
	last := ""
	for _, c := range calls {
		if strings.Contains(c, "restore --detach") {
			last = lastField(c)
		}
	}
	return last
}

// restoresStarted counts the restores recorded, the footprint probe's
// among them.
func restoresStarted(calls []string) int {
	n := 0
	for _, c := range calls {
		if strings.Contains(c, "restore --detach") {
			n++
		}
	}
	return n
}

// claimClosed dials the pool socket, sends what it is given (nothing for
// "") and reports whether the backend closed the connection within the
// bound, as it does for a claim it refuses.
func claimClosed(t *testing.T, sock string, claim []byte, bound time.Duration) bool {
	t.Helper()
	c, err := net.Dial("unixpacket", sock)
	if err != nil {
		t.Fatalf("dial %s: %v", sock, err)
	}
	defer func() { _ = c.Close() }()
	if len(claim) > 0 {
		if _, err := c.Write(claim); err != nil {
			t.Fatal(err)
		}
	}
	_ = c.SetReadDeadline(time.Now().Add(bound))
	n, err := c.Read(make([]byte, 1))
	return n == 0 && err != nil && !errors.Is(err, os.ErrDeadlineExceeded)
}

// poolSocketOf is the path of the warm instance's pool socket.
func poolSocketOf(t *testing.T, b *Backend, id string) string {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	w := b.warms[id]
	if w == nil {
		t.Fatalf("no warm instance %q", id)
	}
	return filepath.Join(w.channel, poolSocket)
}

// TestNew checks that the tier is FIBER_SNAPSHOT only with a runsc that
// answers and a rootfs directory, and the version is read from runsc
// through the seam. The facts the backend states about itself do not
// depend on either. The templates tmpfs is TestTemplatesTmpfs.
func TestNew(t *testing.T) {
	cases := []struct {
		name        string
		knobs       knobs
		opt         func(t *testing.T, rootfs, state string) Options
		wantTier    core.Tier
		wantVersion string
		wantRunsc   string
		wantWhy     string // in ProbeErr, "" for none
		wantSweep   bool   // the root was listed for leftovers
	}{
		{name: "runsc and rootfs", opt: func(_ *testing.T, rootfs, state string) Options {
			return Options{Runsc: "/opt/runsc", Rootfs: rootfs, StateDir: state}
		},
			wantTier: core.TierSnapshot, wantVersion: fakeVersion, wantRunsc: "/opt/runsc", wantSweep: true},
		{name: "runsc missing", knobs: knobs{Fail: map[string]bool{"version": true}}, opt: func(_ *testing.T, rootfs, state string) Options {
			return Options{Runsc: "/nowhere/runsc", Rootfs: rootfs, StateDir: state}
		}, wantRunsc: "/nowhere/runsc", wantWhy: "runsc /nowhere/runsc unavailable"},
		{name: "rootfs missing", opt: func(t *testing.T, _, state string) Options {
			return Options{Runsc: "/opt/runsc", Rootfs: filepath.Join(t.TempDir(), "none"), StateDir: state}
		}, wantVersion: fakeVersion, wantRunsc: "/opt/runsc", wantWhy: "rootfs unusable", wantSweep: true},
		{name: "rootfs is a file", opt: func(t *testing.T, _, state string) Options {
			f := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(f, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return Options{Runsc: "/opt/runsc", Rootfs: f, StateDir: state}
		}, wantVersion: fakeVersion, wantRunsc: "/opt/runsc", wantWhy: "is not a directory", wantSweep: true},
		{name: "default runsc", opt: func(_ *testing.T, rootfs, state string) Options { return Options{Rootfs: rootfs, StateDir: state} },
			wantTier: core.TierSnapshot, wantRunsc: "runsc", wantVersion: fakeVersion, wantSweep: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRunsc(tc.knobs)
			opt := tc.opt(t, t.TempDir(), t.TempDir())
			b := newBackend(opt, f.run, newFakeTmpfs().ops())
			t.Cleanup(b.Close)
			if b.Tier() != tc.wantTier {
				t.Fatalf("Tier = %s, want %s", b.Tier(), tc.wantTier)
			}
			why := b.ProbeErr()
			switch {
			case tc.wantWhy == "" && why != nil:
				t.Fatalf("ProbeErr = %v, want nil", why)
			case tc.wantWhy != "" && (why == nil || !strings.Contains(why.Error(), tc.wantWhy)):
				t.Fatalf("ProbeErr = %v, want one mentioning %q", why, tc.wantWhy)
			}
			if b.version != tc.wantVersion {
				t.Fatalf("version = %q, want %q", b.version, tc.wantVersion)
			}
			if b.opt.Runsc != tc.wantRunsc {
				t.Fatalf("Runsc = %q, want %q", b.opt.Runsc, tc.wantRunsc)
			}
			if b.opt.StateDir != opt.StateDir {
				t.Fatalf("StateDir = %q, want %q", b.opt.StateDir, opt.StateDir)
			}
			calls := f.calls()
			if findCall(calls, "--version") == "" {
				t.Fatalf("no version probe among\n%s", strings.Join(calls, "\n"))
			}
			if (findCall(calls, "list -quiet") != "") != tc.wantSweep {
				t.Fatalf("sweep %v, want %v among\n%s", !tc.wantSweep, tc.wantSweep, strings.Join(calls, "\n"))
			}
			p := b.Platform()
			if p.Kernel != "gvisor-"+b.version || p.Libc != "rootfs-"+filepath.Base(opt.Rootfs) {
				t.Fatalf("Platform = %+v", p)
			}
			c, r := b.DefaultDeadlines("")
			if b.Name() != "gvisor" || !b.IsolatesTenants() || b.FiberOverheadBytes() != 0 || b.WCounter() != "shmem" ||
				strings.Join(b.EndpointSchemes(), ",") != "unix" || c != createDeadline || r != resumeDeadline {
				t.Fatalf("facts: name=%s isolates=%v overhead=%d counter=%s schemes=%v deadlines=%s/%s",
					b.Name(), b.IsolatesTenants(), b.FiberOverheadBytes(), b.WCounter(), b.EndpointSchemes(), c, r)
			}
		})
	}
}

// TestRunsc checks that every runsc command carries the global flags, a failure
// names the command and the tail of its output, a detached command's
// output goes through a file that is removed again, and a deadline that
// ends the command is reported as the deadline.
func TestRunsc(t *testing.T) {
	cases := []struct {
		name     string
		knobs    knobs
		stateDir string // "" for the backend's, "missing" for one that is not there
		timeout  time.Duration
		args     []string
		wantErr  error
		wantText string
		wantOut  string
	}{
		{name: "success", args: []string{"--version"}, wantOut: "runsc version " + fakeVersion},
		{name: "failure keeps the tail", args: []string{"state", "nothing"}, wantText: `runsc state: exit status 1: fake runsc: container "nothing" does not exist`},
		// A crash's cause is on its first line and runsc's own error on
		// its last, so a long output keeps both ends and loses the middle.
		{name: "a long output keeps its head and its tail", knobs: knobs{Fail: map[string]bool{"state": true}, LongOutput: true}, args: []string{"state", "x"},
			wantText: "exit status 1: " + clipped(longOutput+"fake runsc: state failed")},
		{name: "detached output through a file", args: []string{"state", "--detach", "x"}, wantText: `container "x" does not exist`, wantOut: `container "x" does not exist`},
		{name: "detached without a state directory", stateDir: "missing", args: []string{"state", "--detach", "x"}, wantErr: os.ErrNotExist},
		{name: "deadline ends the command", knobs: knobs{SlowRestore: 3 * time.Second}, timeout: 100 * time.Millisecond,
			args: []string{"restore", "--detach", "--image-path", "IMG", "--bundle", "B", "x"}, wantErr: context.DeadlineExceeded, wantText: "runsc restore"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, f := newFake(t, tc.knobs)
			if err := os.MkdirAll(b.opt.StateDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if tc.stateDir == "missing" {
				b.opt.StateDir = filepath.Join(t.TempDir(), "missing")
			}
			img := t.TempDir()
			if err := os.WriteFile(filepath.Join(img, imageFile), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			args := append([]string(nil), tc.args...)
			for i := range args {
				args[i] = strings.NewReplacer("IMG", img, "B", t.TempDir()).Replace(args[i])
			}
			timeout := 5 * time.Second
			if tc.timeout > 0 {
				timeout = tc.timeout
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			out, err := b.runsc(ctx, -1, args...)
			if tc.wantErr == nil && tc.wantText == "" {
				if err != nil {
					t.Fatalf("runsc: %v", err)
				}
			} else if err == nil || (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) || !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("runsc = %v, want %q (errors.Is %v)", err, tc.wantText, tc.wantErr)
			}
			if !strings.Contains(out, tc.wantOut) {
				t.Fatalf("output %q, want it to contain %q", out, tc.wantOut)
			}
			if tc.stateDir == "" {
				if left, _ := filepath.Glob(filepath.Join(b.opt.StateDir, "runsc-*.out")); len(left) != 0 {
					t.Fatalf("output files left: %v", left)
				}
			}
			calls := f.calls()
			want := strings.Join(append(b.globalArgs(), args...), " ")
			got := findCall(calls, want)
			if tc.stateDir == "missing" {
				want, got = "", findCall(calls, strings.Join(tc.args, " ")) // never ran
			}
			if got != want {
				t.Fatalf("runsc was invoked as %q, want %q", got, want)
			}
		})
	}
}

// clipped is s as a runsc error keeps it: its first clipHead bytes, then
// its last clipTail, with the cause ("panic: the cause") in the head and
// runsc's own error in the tail.
func clipped(s string) string {
	out := s[:clipHead] + " ... " + s[len(s)-clipTail:]
	if !strings.HasPrefix(out, "panic: the cause") || !strings.HasSuffix(out, "state failed") {
		panic("clipped: the fixture does not hold the cause and the error")
	}
	return out
}

// TestWriteBundle checks the OCI spec every sandbox is created or restored
// with. The run directory is /host, fiberd directory is read-only at
// /fiberd/channel in every sandbox, and the self-checkpoint annotations
// are there only for a template with images.
func TestWriteBundle(t *testing.T) {
	cases := []struct {
		name     string
		env      []string
		images   string
		template string
		dir      func(t *testing.T) string
		wantErr  bool
	}{
		{name: "fiber bundle", env: []string{"FIBERD_TOKEN=" + strings.Repeat("ab", 16)}},
		{name: "template with self-checkpoint", images: "/img"},
		{name: "registry template bound read-only", template: "/state/templates/g/template"},
		{name: "directory under a file", dir: func(t *testing.T) string {
			f := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(f, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(f, "bundle")
		}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &Backend{opt: Options{Rootfs: "/rootfs"}}
			dir := filepath.Join(t.TempDir(), "bundle")
			if tc.dir != nil {
				dir = tc.dir(t)
			}
			err := b.writeBundle(dir, []string{"/bin/refzygote", "--gvisor"}, tc.env, "/run/g", "/state/channel/w-g-1", tc.images, tc.template)
			if (err != nil) != tc.wantErr {
				t.Fatalf("writeBundle = %v, want error %v", err, tc.wantErr)
			}
			if err != nil {
				return
			}
			data, err := os.ReadFile(filepath.Join(dir, "config.json"))
			if err != nil {
				t.Fatal(err)
			}
			var s spec
			if err := json.Unmarshal(data, &s); err != nil {
				t.Fatal(err)
			}
			wantEnv := append([]string{"PATH=/bin:/usr/bin"}, tc.env...)
			if s.OCIVersion != "1.0.2" || s.Process.Cwd != "/" || strings.Join(s.Process.Args, " ") != "/bin/refzygote --gvisor" ||
				strings.Join(s.Process.Env, " ") != strings.Join(wantEnv, " ") || s.Root.Path != "/rootfs" || s.Hostname != "fiber" {
				t.Fatalf("spec = %+v", s)
			}
			// The rootfs is shared by every sandbox of every grant and
			// served with fiberd's credentials, so it is read-only.
			if !s.Root.Readonly {
				t.Fatalf("root = %+v, want read-only", s.Root)
			}
			var mounts []string
			for _, m := range s.Mounts {
				mounts = append(mounts, m.Destination+":"+m.Type+":"+m.Source+":"+strings.Join(m.Options, ","))
			}
			// fiberd directory is read-only, after /host, in every
			// sandbox, since a restore's mounts must match the checkpoint's.
			wantMounts := "/proc:proc:proc: /dev:tmpfs:tmpfs: /tmp:tmpfs:tmpfs: /host:bind:/run/g:rbind,rw /fiberd/channel:bind:/state/channel/w-g-1:bind,ro,nosuid,nodev"
			if tc.template != "" {
				// Read-only, after /host, at the fixed path every home uses.
				wantMounts += " /fiberd/template:bind:" + tc.template + ":bind,ro,nosuid,nodev"
			}
			if got := strings.Join(mounts, " "); got != wantMounts {
				t.Fatalf("mounts = %s, want %s", got, wantMounts)
			}
			var ns []string
			for _, n := range s.Linux.Namespaces {
				ns = append(ns, n.Type)
			}
			if got := strings.Join(ns, ","); got != "pid,mount,ipc,uts" {
				t.Fatalf("namespaces = %s", got)
			}
			if tc.images == "" {
				if s.Annotations != nil {
					t.Fatalf("annotations = %v, want none", s.Annotations)
				}
			} else if s.Annotations["dev.gvisor.internal.checkpoint.path"] != tc.images ||
				s.Annotations["dev.gvisor.internal.checkpoint.enable"] != "true" || s.Annotations["dev.gvisor.internal.checkpoint.resume"] != "true" {
				t.Fatalf("annotations = %v", s.Annotations)
			}
		})
	}
}

// TestCID checks that a fence or grant uid becomes a runsc container id.
func TestCID(t *testing.T) {
	cases := []struct{ in, want string }{
		{"g/1-1", "g-1-1"},
		{"sha256:abc def", "sha256-abc-def"},
		{"plain", "plain"},
		{"a_b.c-D9", "a_b.c-D9"},
		{"t@x+y,z", "t-x-y-z"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := cid(tc.in); got != tc.want {
				t.Fatalf("cid(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestWaitFile covers a file that appears, a file that goes, and a deadline.
func TestWaitFile(t *testing.T) {
	cases := []struct {
		name    string
		gone    bool
		exists  bool // at the start
		act     bool // create (or remove) it a moment later
		wantErr error
	}{
		{name: "appears", act: true},
		{name: "already there", exists: true},
		{name: "goes", gone: true, exists: true, act: true},
		{name: "already gone", gone: true},
		{name: "never appears", wantErr: context.DeadlineExceeded},
		{name: "never goes", gone: true, exists: true, wantErr: context.DeadlineExceeded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "f")
			if tc.exists {
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.act {
				time.AfterFunc(30*time.Millisecond, func() {
					if tc.gone {
						_ = os.Remove(path)
					} else {
						_ = os.WriteFile(path, nil, 0o600)
					}
				})
			}
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			if err := waitFile(ctx, path, tc.gone); !errors.Is(err, tc.wantErr) {
				t.Fatalf("waitFile = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestWaitEndpoint covers a socket that starts accepting, a sandbox that
// exits first, or the deadline passes.
func TestWaitEndpoint(t *testing.T) {
	cases := []struct {
		name     string
		listen   bool // a listener appears a moment later
		exit     bool // the sandbox's done closes a moment later
		wantErr  error
		wantText string
	}{
		{name: "serves", listen: true},
		{name: "sandbox exits first", exit: true, wantText: "sandbox exited before serving"},
		{name: "deadline", wantErr: context.DeadlineExceeded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ep := filepath.Join(t.TempDir(), "ep.sock")
			done := make(chan struct{})
			if tc.listen {
				time.AfterFunc(30*time.Millisecond, func() {
					ln, err := net.Listen("unix", ep)
					if err != nil {
						return
					}
					t.Cleanup(func() { _ = ln.Close() })
				})
			}
			if tc.exit {
				time.AfterFunc(30*time.Millisecond, func() { close(done) })
			}
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			err := waitEndpoint(ctx, ep, done)
			if tc.wantErr == nil && tc.wantText == "" {
				if err != nil {
					t.Fatalf("waitEndpoint: %v", err)
				}
				return
			}
			if err == nil || (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) || !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("waitEndpoint = %v, want %q (errors.Is %v)", err, tc.wantText, tc.wantErr)
			}
		})
	}
}

// cgroupFiles is a directory fd whose files stand in for a leaf's.
func cgroupFiles(t *testing.T, files map[string]string) int {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	d, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return int(d.Fd())
}

// TestLeafDiag checks what is said about a fiber's leaf after a failed start,
// from the files the kernel keeps there.
func TestLeafDiag(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		noFD  bool
		want  string
	}{
		{name: "no leaf", noFD: true, want: "no leaf"},
		{name: "a leaf that killed its fiber", files: map[string]string{
			"memory.events": "low 0\nhigh 2\noom_kill 1\n", "memory.peak": "67108864\n", "memory.max": "max\n",
			"memory.stat": "anon 4096\nshmem 8192\nfile 0\n", "memory.current": "12288\n",
		}, want: "leaf: oom_kill=1 peak=67108864 max=max shmem=8192 current=12288"},
		{name: "a leaf without the files", files: map[string]string{}, want: "leaf: oom_kill=? peak=? max=? shmem=0 current=0"},
		{name: "a stat without the counter", files: map[string]string{"memory.stat": "anon 4096\n"}, want: "leaf: oom_kill=? peak=? max=? shmem=0 current=0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fd := -1
			if !tc.noFD {
				fd = cgroupFiles(t, tc.files)
			}
			if got := leafDiag(fd); got != tc.want {
				t.Fatalf("leafDiag = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestWarm checks that the template sandbox runs, drops its marker, is
// checkpointed in place, and is reported gone when it exits. Every failure
// before that leaves no sandbox behind.
func TestWarm(t *testing.T) {
	cases := []struct {
		name     string
		knobs    knobs
		tier     core.Tier
		argv     []string
		workDir  func(t *testing.T, b *Backend) string
		stateDir func(t *testing.T, b *Backend)
		timeout  time.Duration
		started  bool // the template sandbox was started before the failure
		wantErr  error
		wantText string
	}{
		{name: "template comes up", argv: []string{"/bin/refzygote", "--gvisor"}, tier: core.TierSnapshot},
		{name: "runsc or rootfs unavailable", argv: []string{"/bin/refzygote"}, tier: core.TierWarm, wantText: "runsc or rootfs unavailable"},
		{name: "empty command", tier: core.TierSnapshot, wantText: "empty template command"},
		{name: "run directory under a file", argv: []string{"/bin/refzygote"}, tier: core.TierSnapshot, workDir: func(t *testing.T, _ *Backend) string {
			f := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(f, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(f, "g")
		}, wantText: "not a directory"},
		{name: "template directory under a file", argv: []string{"/bin/refzygote"}, tier: core.TierSnapshot, stateDir: func(t *testing.T, b *Backend) {
			// New made the directory. Something replaced it since.
			if err := os.RemoveAll(b.templatesDir()); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(b.templatesDir(), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, wantText: "not a directory"},
		{name: "run fails", argv: []string{"/bin/refzygote"}, tier: core.TierSnapshot, knobs: knobs{Fail: map[string]bool{"run": true}}, wantText: "runsc run: exit status 1: fake runsc: run failed"},
		{name: "template never ready", argv: []string{"/bin/refzygote"}, tier: core.TierSnapshot, knobs: knobs{NoMarker: true}, timeout: 300 * time.Millisecond,
			started: true, wantErr: context.DeadlineExceeded, wantText: "template did not become ready"},
		{name: "template checkpoint fails", argv: []string{"/bin/refzygote"}, tier: core.TierSnapshot, knobs: knobs{Fail: map[string]bool{"checkpoint": true}},
			started: true, wantText: "template checkpoint: gvisor: runsc checkpoint"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, f := newFake(t, tc.knobs)
			b.tier = tc.tier
			workDir := filepath.Join(t.TempDir(), "g")
			if tc.workDir != nil {
				workDir = tc.workDir(t, b)
			}
			if tc.stateDir != nil {
				tc.stateDir(t, b)
			}
			timeout := 5 * time.Second
			if tc.timeout > 0 {
				timeout = tc.timeout
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			w, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "g", Template: backend.Template{Argv: tc.argv}, CgroupFD: -1, ProbeCgroupFD: -1, WorkDir: workDir})
			if tc.wantErr != nil || tc.wantText != "" {
				if err == nil || (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) || !strings.Contains(err.Error(), tc.wantText) {
					t.Fatalf("Warm = %v, want %q (errors.Is %v)", err, tc.wantText, tc.wantErr)
				}
				b.mu.Lock()
				n := len(b.warms)
				b.mu.Unlock()
				if n != 0 {
					t.Fatalf("%d templates registered after a failed warm", n)
				}
				calls := f.calls()
				if tc.started {
					// Started, so it must have been ended by a delete after
					// the run.
					ran := false
					for _, c := range calls {
						if strings.Contains(c, "run --detach") {
							ran = true
						} else if ran && strings.Contains(c, "delete -force w-g-") {
							ran = false
						}
					}
					if ran {
						t.Fatalf("the template was started and never deleted:\n%s", strings.Join(calls, "\n"))
					}
				}
				if started := lastField(findCall(calls, "run --detach")); started != "" && f.alive(started) {
					t.Fatalf("the template sandbox %s is still running after a failed warm", started)
				}
				return
			}
			if err != nil {
				t.Fatalf("Warm: %v", err)
			}
			wc := warmCID(t, b, "g")
			if pid := f.pidOf(wc); pid == 0 || w.ID != "g" || w.PID != pid || w.Bytes != 0 || w.TotalBytes != 0 {
				t.Fatalf("Warm = %+v, want id g and the sandbox pid %d", w, pid)
			}
			tdir := filepath.Join(b.opt.StateDir, "templates", wc)
			if _, err := os.Stat(filepath.Join(tdir, "images", imageFile)); err != nil {
				t.Fatalf("template image not written: %v", err)
			}
			calls := f.calls()
			for _, want := range []string{
				"run --detach --bundle " + filepath.Join(tdir, "bundle") + " " + wc,
				"checkpoint --leave-running --image-path " + filepath.Join(tdir, "images") + " " + wc,
				"state " + wc,
			} {
				if findCall(calls, want) == "" {
					t.Fatalf("no runsc call %q among\n%s", want, strings.Join(calls, "\n"))
				}
			}
			cfgJSON, err := os.ReadFile(filepath.Join(tdir, "bundle", "config.json"))
			if err != nil || !strings.Contains(string(cfgJSON), `"FIBERD_FENCE=none"`) || !strings.Contains(string(cfgJSON), `"source": "`+workDir+`"`) {
				t.Fatalf("template bundle = %s (%v)", cfgJSON, err)
			}
			b.Unwarm("nobody")
			b.Unwarm(w.ID)
			if f.alive(wc) {
				t.Fatal("the template sandbox survived Unwarm")
			}
			// The reaper cleans up after it and says nothing, since the
			// instance is already unregistered. An end the host asked for
			// through Unwarm is not news to it.
			waitFor(t, "the reaper's delete", func() bool {
				calls := f.calls()
				return len(calls) > 0 && strings.HasSuffix(calls[len(calls)-1], "delete -force "+wc)
			})
			// Checked once the reaper is done, so no exit is still on its way.
			if !reapersDone(b, 5*time.Second) {
				t.Fatal("a reaper is still running")
			}
			select {
			case e := <-b.Exits():
				t.Fatalf("unexpected exit %+v after Unwarm", e)
			default:
			}
			b.mu.Lock()
			n := len(b.warms)
			b.mu.Unlock()
			if n != 0 {
				t.Fatalf("%d templates registered after Unwarm", n)
			}
			// The image and the staged copy went with the sandbox.
			if _, err := os.Stat(tdir); err == nil {
				t.Fatalf("%s is still there after Unwarm and its reaper", tdir)
			}
			// The grant can be warmed again, as the host does once the
			// template is gone. The new incarnation has a cid of its own.
			w2, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "g", Template: backend.Template{Argv: tc.argv}, CgroupFD: -1, ProbeCgroupFD: -1, WorkDir: workDir})
			if err != nil {
				t.Fatalf("second Warm: %v", err)
			}
			if wc2 := warmCID(t, b, "g"); w2.PID == w.PID || wc2 == wc || !f.alive(wc2) {
				t.Fatalf("second Warm = %+v cid %s, want a new live sandbox with a cid other than %s", w2, wc2, wc)
			}
			select {
			case e := <-b.Exits():
				t.Fatalf("unexpected exit %+v", e)
			default:
			}
		})
	}
}

// TestProbeFootprint checks that the template image is restored once into the
// probe cgroup as a fiber would be, measured serving from the leaf's
// counters (a seeded directory here, a real leaf in tests/integration/gvisor), and
// ended, leaving nothing behind. A probe that cannot restore or serve
// measures nothing, and one without a cgroup runs all the same, since it
// is where late binding is detected, and measures nothing.
func TestProbeFootprint(t *testing.T) {
	leaf := map[string]string{"memory.stat": "anon 4096\nshmem 8192\nfile 0\n", "memory.current": "12288\n"}
	cases := []struct {
		name      string
		knobs     knobs
		noCgroup  bool
		noSandbox bool // the restore failed, so there was nothing to end
		wantBytes uint64
		wantTotal uint64
		wantLog   string
		wantAlso  string // a second part of the same line
	}{
		{name: "measured serving in the leaf", wantBytes: 8192, wantTotal: 12288},
		{name: "no probe cgroup", noCgroup: true},
		{name: "restore fails", knobs: knobs{Fail: map[string]bool{"restore": true}}, noSandbox: true, wantLog: "footprint probe: gvisor: runsc restore"},
		// The line says the sandbox outlived the cap without serving, so a
		// template hung after its restore reads as that and not as slow.
		{name: "never serves", knobs: knobs{NoServe: true}, wantLog: "probe did not serve: context deadline exceeded (", wantAlso: "after its restore, sandbox still running)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fd := -1
			if !tc.noCgroup {
				fd = cgroupFiles(t, leaf)
			}
			var logs bytes.Buffer
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(os.Stderr) })
			b, f := newFake(t, tc.knobs)
			workDir := filepath.Join(t.TempDir(), "g")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			w, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "g", Template: backend.Template{Argv: []string{"/bin/refzygote"}}, CgroupFD: -1, ProbeCgroupFD: fd, WorkDir: workDir})
			if err != nil {
				t.Fatalf("Warm: %v", err)
			}
			if w.Bytes != tc.wantBytes || w.TotalBytes != tc.wantTotal {
				t.Fatalf("Warm measured %d/%d bytes, want %d/%d", w.Bytes, w.TotalBytes, tc.wantBytes, tc.wantTotal)
			}
			for _, want := range []string{tc.wantLog, tc.wantAlso} {
				if want != "" && !strings.Contains(logs.String(), want) {
					t.Fatalf("log = %q, want %q", logs.String(), want)
				}
			}
			calls := f.calls()
			tdir := filepath.Join(b.opt.StateDir, "templates", warmCID(t, b, "g"))
			probe := warmCID(t, b, "g") + "-probe"
			restore := "restore --detach --pid-file " + filepath.Join(tdir, "probe-bundle", "pid") + " --image-path " + filepath.Join(tdir, "images") + " --bundle " + filepath.Join(tdir, "probe-bundle") + " " + probe
			if findCall(calls, restore) == "" {
				t.Fatalf("no probe restore among\n%s", strings.Join(calls, "\n"))
			}
			if got := f.cgroupOf(restore); got != fd {
				t.Fatalf("the probe was restored in cgroup fd %d, want the probe cgroup %d", got, fd)
			}
			if !tc.noSandbox {
				for _, want := range []string{"kill " + probe + " KILL", "delete -force " + probe} {
					if findCall(calls, want) == "" {
						t.Fatalf("no %q among\n%s", want, strings.Join(calls, "\n"))
					}
				}
			}
			if f.alive(probe) {
				t.Fatal("the probe sandbox is still alive")
			}
			for _, left := range []string{filepath.Join(tdir, "probe-bundle"), filepath.Join(workDir, "probe.sock")} {
				if _, err := os.Lstat(left); err == nil {
					t.Fatalf("%s left behind", left)
				}
			}
		})
	}
}

// TestSizeDeadline checks how a measured restore sizes a default deadline:
// the floor when the scaled measurement is under it, deadlineFactor times
// the measurement above it, and never more than deadlineCap.
func TestSizeDeadline(t *testing.T) {
	cases := []struct {
		name     string
		measured time.Duration
		floor    time.Duration
		want     time.Duration
	}{
		{name: "nothing measured keeps the floor", floor: createDeadline, want: createDeadline},
		{name: "a quick restore keeps the floor", measured: 100 * time.Millisecond, floor: createDeadline, want: createDeadline},
		{name: "a restore at the floor's quarter keeps the floor", measured: 125 * time.Millisecond, floor: createDeadline, want: createDeadline},
		{name: "a slower restore is scaled", measured: 300 * time.Millisecond, floor: createDeadline, want: 1200 * time.Millisecond},
		{name: "the resume floor is higher", measured: 300 * time.Millisecond, floor: resumeDeadline, want: resumeDeadline},
		{name: "a slow restore scales the resume too", measured: 800 * time.Millisecond, floor: resumeDeadline, want: 3200 * time.Millisecond},
		{name: "a pathological restore is capped", measured: 3 * time.Second, floor: createDeadline, want: deadlineCap},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sizeDeadline(tc.measured, tc.floor); got != tc.want {
				t.Fatalf("sizeDeadline(%s, %s) = %s, want %s", tc.measured, tc.floor, got, tc.want)
			}
		})
	}
}

// TestDefaultDeadlines checks that a warm instance's default deadlines
// come from how long its footprint probe took to restore and serve: the
// floors for a quick template, more for a slow one, and the floors again
// for an instance whose probe measured nothing, one that was unwarmed,
// or one the backend never had.
func TestDefaultDeadlines(t *testing.T) {
	cases := []struct {
		name      string
		knobs     knobs
		unwarm    bool
		id        string // the instance asked about, "" for the warm one
		createMin time.Duration
		createMax time.Duration
		resume    time.Duration
	}{
		{name: "a quick template keeps the floors", createMin: createDeadline, createMax: createDeadline, resume: resumeDeadline},
		{name: "a slow restore raises the create deadline", knobs: knobs{SlowRestore: 200 * time.Millisecond},
			createMin: 800 * time.Millisecond, createMax: resumeDeadline, resume: resumeDeadline},
		{name: "a probe that measured nothing keeps the floors", knobs: knobs{Fail: map[string]bool{"restore": true}},
			createMin: createDeadline, createMax: createDeadline, resume: resumeDeadline},
		{name: "an unwarmed instance keeps the floors", knobs: knobs{SlowRestore: 200 * time.Millisecond}, unwarm: true,
			createMin: createDeadline, createMax: createDeadline, resume: resumeDeadline},
		{name: "an instance the backend never had gets the floors", knobs: knobs{SlowRestore: 200 * time.Millisecond}, id: "other",
			createMin: createDeadline, createMax: createDeadline, resume: resumeDeadline},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, _, w, _ := warmed(t, tc.knobs)
			id := w.ID
			if tc.id != "" {
				id = tc.id
			}
			if tc.unwarm {
				b.Unwarm(w.ID)
			}
			c, r := b.DefaultDeadlines(id)
			if c < tc.createMin || c > tc.createMax || r != tc.resume {
				t.Fatalf("DefaultDeadlines = %s/%s, want create in [%s, %s] and resume %s", c, r, tc.createMin, tc.createMax, tc.resume)
			}
		})
	}
}

// TestProbeWithoutABundle checks that a probe whose bundle cannot be written
// measures nothing and runs nothing.
func TestProbeWithoutABundle(t *testing.T) {
	cases := []struct {
		name string
	}{{name: "template directory is a file"}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, f := newFake(t, knobs{})
			tdir := filepath.Join(t.TempDir(), "tdir")
			if err := os.WriteFile(tdir, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			// The probe's bundle goes under dir, which is a file. Without
			// dir it would go under the working directory, where the
			// outcome depends on who may write there.
			w := &warm{id: "g", cid: "w-g", argv: []string{"/bin/refzygote"}, workDir: t.TempDir(), dir: tdir, images: filepath.Join(tdir, "images"), pending: map[string]*box{}}
			shmem, total := b.probeFootprint(context.Background(), w, cgroupFiles(t, nil))
			if shmem != 0 || total != 0 {
				t.Fatalf("probeFootprint = %d/%d, want nothing", shmem, total)
			}
			if c := findCall(f.calls(), "w-g-probe"); c != "" {
				t.Fatalf("runsc ran for a probe without a bundle: %s", c)
			}
		})
	}
}

// TestClone checks that a fiber is a sandbox restored from the template image
// with a one-shot token in its environment and nothing else, handed its
// fence, endpoint, payload and a fresh seed in one record on the channel
// it dials, serving before Clone returns, and its end is reported with
// the sandbox's status. A template that polls the spec environment
// instead (spec) gets the fence, endpoint and payload there. With the
// sandbox pid unknown (noPID), the status is what `runsc wait` says.
func TestClone(t *testing.T) {
	cases := []struct {
		name       string
		knobs      knobs
		payload    []byte
		session    string
		spec       bool
		noPID      bool
		wantStatus string
	}{
		{name: "exit 0", wantStatus: "exit:0"},
		{name: "payload and a signal", payload: []byte{1, 2, 3}, knobs: knobs{ExitStatus: 137}, wantStatus: "signal:9"},
		{name: "a session with a space, hex on the channel", session: "conv 42", wantStatus: "exit:0"},
		{name: "wait says nothing readable", knobs: knobs{BadWaitJSON: true, NoPidFile: true, Fail: map[string]bool{"state": true}}, noPID: true, wantStatus: "exit:?"},
		{name: "template that polls the spec environment", payload: []byte{1, 2, 3}, session: "conv 42", knobs: knobs{NoToken: true}, spec: true, wantStatus: "exit:0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, f, w, workDir := warmed(t, tc.knobs)
			ep := filepath.Join(workDir, "ep.sock")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			fb, err := b.Clone(ctx, w.ID, backend.FiberSpec{Fence: "g/1-1", Endpoint: ep, CgroupFD: -1, Deadline: 2 * time.Second, Payload: tc.payload, Session: tc.session, Generation: 1})
			if err != nil {
				t.Fatalf("Clone: %v", err)
			}
			fc := boxCID(t, b, "g/1-1")
			pid := f.pidOf(fc)
			if tc.noPID {
				pid = 0
			} else if pid == 0 {
				t.Fatal("the fiber sandbox recorded no pid")
			}
			if fb.ID != "g/1-1" || fb.PID != pid {
				t.Fatalf("Clone = %+v, want g/1-1 with the sandbox pid %d", fb, pid)
			}
			if !dialable(ep) {
				t.Fatalf("%s does not accept connections", ep)
			}
			bundle := b.bundleDir(fc)
			cfgJSON, err := os.ReadFile(filepath.Join(bundle, "config.json"))
			if err != nil {
				t.Fatal(err)
			}
			token, records := f.channelOf(fc)
			if tc.spec {
				for _, want := range []string{`"FIBERD_FENCE=g/1-1"`, `"FIBERD_ENDPOINT=/host/ep.sock"`, `"FIBERD_PAYLOAD=010203"`, `"FIBERD_SESSION=conv 42"`} {
					if !strings.Contains(string(cfgJSON), want) {
						t.Fatalf("bundle lacks %s:\n%s", want, cfgJSON)
					}
				}
				if len(records) != 0 {
					t.Fatalf("a template that polls the spec was handed %v on the channel", records)
				}
			} else {
				checkIdentity(t, cfgJSON, token, records, 1, "clone", "g/1-1", "/host/ep.sock", tc.payload, tc.session)
			}
			tdir := filepath.Join(b.opt.StateDir, "templates", warmCID(t, b, "g"))
			calls := f.calls()
			if findCall(calls, "restore --detach --pid-file "+filepath.Join(bundle, "pid")+" --image-path "+filepath.Join(tdir, "images")+" --bundle "+bundle+" "+fc) == "" {
				t.Fatalf("no restore among\n%s", strings.Join(calls, "\n"))
			}
			if err := b.Kill("nobody"); err != nil {
				t.Fatalf("Kill of an unknown fiber = %v", err)
			}
			if err := b.Kill("g/1-1"); err != nil {
				t.Fatalf("Kill: %v", err)
			}
			if e := waitExit(t, b); e != (backend.Exit{FiberID: "g/1-1", Status: tc.wantStatus}) {
				t.Fatalf("exit = %+v, want %s", e, tc.wantStatus)
			}
			if _, err := os.Stat(bundle); err == nil {
				t.Fatal("the bundle was kept after the exit")
			}
			b.mu.Lock()
			n := len(b.boxes)
			b.mu.Unlock()
			if n != 0 {
				t.Fatalf("%d boxes left after the exit", n)
			}
		})
	}
}

// TestCloneRefusals checks what Clone refuses or cannot bring up, and the
// sandbox it ends when the fiber never serves, never claims its token or
// acks with another fence. after is set once the template is warm, so
// the probe saw a template that binds late.
func TestCloneRefusals(t *testing.T) {
	cases := []struct {
		name     string
		knobs    knobs
		after    *knobs
		warmID   string
		endpoint string // relative to the run directory unless absolute
		bundles  bool   // the state directory's bundles entry is a file
		deadline time.Duration
		wantErr  error
		wantText string
		wantKill bool
	}{
		{name: "unknown template", warmID: "nobody", endpoint: "ep.sock", wantText: `no warm template "nobody"`},
		{name: "endpoint outside the run directory", endpoint: "/elsewhere/ep.sock", wantText: "outside the grant's run directory"},
		{name: "bundle cannot be written", endpoint: "ep.sock", bundles: true, wantText: "not a directory"},
		{name: "restore fails", endpoint: "ep.sock", knobs: knobs{Fail: map[string]bool{"restore": true}}, wantText: "runsc restore: exit status 1: fake runsc: restore failed (no leaf)"},
		{name: "never serves", endpoint: "ep.sock", knobs: knobs{NoServe: true}, deadline: 300 * time.Millisecond, wantErr: context.DeadlineExceeded, wantText: "g/1-1 did not serve", wantKill: true},
		{name: "restore misses the deadline", endpoint: "ep.sock", knobs: knobs{SlowRestore: 3 * time.Second}, deadline: 100 * time.Millisecond, wantErr: context.DeadlineExceeded, wantText: "runsc restore"},
		{name: "never sends its token", endpoint: "ep.sock", after: &knobs{NoToken: true}, deadline: 300 * time.Millisecond, wantErr: context.DeadlineExceeded, wantText: "g/1-1 sent no token", wantKill: true},
		{name: "sends a token nobody minted", endpoint: "ep.sock", after: &knobs{WrongToken: true}, deadline: 2 * time.Second, wantText: "g/1-1 exited before sending its token", wantKill: true},
		{name: "acks with another fence", endpoint: "ep.sock", after: &knobs{BadAck: true}, deadline: 2 * time.Second, wantText: "g/1-1: ack names", wantKill: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, f, w, workDir := warmed(t, tc.knobs)
			if tc.after != nil {
				f.setKnobs(*tc.after)
			}
			warmID := w.ID
			if tc.warmID != "" {
				warmID = tc.warmID
			}
			ep := tc.endpoint
			if !filepath.IsAbs(ep) {
				ep = filepath.Join(workDir, ep)
			}
			if tc.bundles {
				if err := os.WriteFile(filepath.Join(b.opt.StateDir, "bundles"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := b.Clone(ctx, warmID, backend.FiberSpec{Fence: "g/1-1", Endpoint: ep, CgroupFD: -1, Deadline: tc.deadline, Generation: 1})
			if err == nil || (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) || !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("Clone = %v, want %q (errors.Is %v)", err, tc.wantText, tc.wantErr)
			}
			if tc.wantKill {
				// The reaper may have unregistered the box already, so
				// its cid comes from the restore that started it.
				fc := lastRestored(f.calls())
				if findCall(f.calls(), "kill "+fc+" KILL") == "" {
					t.Fatal("a fiber that never served was not killed")
				}
				if f.alive(fc) {
					t.Fatal("the sandbox of a fiber that never served is still running")
				}
			}
			// A refused clone leaves no bundle: a restore that failed has
			// no reaper to take it, and one that was killed has its reaper.
			if !tc.bundles {
				bundles := filepath.Join(b.opt.StateDir, "bundles")
				waitFor(t, "the bundle to go", func() bool {
					ents, _ := os.ReadDir(bundles)
					return len(ents) == 0
				})
			}
		})
	}
}

// TestRestoreBound checks that at most Options.MaxRestores `runsc
// restore` processes run at once, that the default is the CPUs this
// process may use, and that a clone whose deadline passes while it waits
// for a slot misses as one whose restore ran too long does.
func TestRestoreBound(t *testing.T) {
	cases := []struct {
		name     string
		max      int // 0 for the default
		clones   int
		slow     time.Duration // how long each restore holds its slot
		first    time.Duration // the first clone's deadline
		deadline time.Duration // every other clone's deadline
		wantPeak int           // 0 for the default bound
		wantMiss int           // clones that miss their deadline
		wantText string        // in every miss
	}{
		{name: "one at a time", max: 1, clones: 3, slow: 30 * time.Millisecond, first: 2 * time.Second, deadline: 2 * time.Second, wantPeak: 1},
		{name: "two at a time", max: 2, clones: 5, slow: 30 * time.Millisecond, first: 2 * time.Second, deadline: 2 * time.Second, wantPeak: 2},
		{name: "the bound is the knob, not the fake", max: 5, clones: 5, slow: 200 * time.Millisecond, first: 2 * time.Second, deadline: 2 * time.Second, wantPeak: 5},
		{name: "the default is the CPUs", clones: 1, first: 2 * time.Second, deadline: 2 * time.Second},
		{name: "the deadline covers the wait for a slot", max: 1, clones: 2, slow: 300 * time.Millisecond, first: 2 * time.Second, deadline: 100 * time.Millisecond,
			wantPeak: 1, wantMiss: 1, wantText: "waited for a restore slot"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, f := newFakeMax(t, knobs{SlowRestore: tc.slow}, tc.max)
			wantBound := tc.max
			if wantBound == 0 {
				wantBound = max(1, runtime.GOMAXPROCS(0))
			}
			if cap(b.restores) != wantBound {
				t.Fatalf("restore bound = %d, want %d", cap(b.restores), wantBound)
			}
			workDir := filepath.Join(t.TempDir(), "g")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			w, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "g", Template: backend.Template{Argv: []string{"/bin/refzygote", "--gvisor"}}, CgroupFD: -1, ProbeCgroupFD: -1, WorkDir: workDir})
			if err != nil {
				t.Fatalf("Warm: %v", err)
			}
			errs := make([]error, tc.clones)
			var wg sync.WaitGroup
			for i := range tc.clones {
				deadline := tc.deadline
				if i == 0 {
					deadline = tc.first
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, errs[i] = b.Clone(ctx, w.ID, backend.FiberSpec{Fence: fmt.Sprintf("g/1-%d", i), Endpoint: filepath.Join(workDir, fmt.Sprintf("ep%d.sock", i)), CgroupFD: -1, Deadline: deadline, Generation: 1})
				}()
				if i == 0 {
					// The first clone holds a slot before any other asks.
					waitFor(t, "the first restore to start", func() bool { return restoresStarted(f.calls()) >= 2 })
				}
			}
			wg.Wait()
			misses := 0
			for _, err := range errs {
				if err == nil {
					continue
				}
				if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), tc.wantText) {
					t.Fatalf("Clone = %v, want a deadline miss saying %q", err, tc.wantText)
				}
				misses++
			}
			if misses != tc.wantMiss {
				t.Fatalf("%d clones missed, want %d: %v", misses, tc.wantMiss, errs)
			}
			if tc.wantPeak > 0 && f.peakRestores() != tc.wantPeak {
				t.Fatalf("peak restores in flight = %d, want %d", f.peakRestores(), tc.wantPeak)
			}
		})
	}
}

// TestBundleOutsideRunDir pins that a fiber's bundle is written under
// the state directory, never under the grant's run directory. Every
// sandbox of the grant has that directory as /host, read and write, so
// a bundle there could be rewritten by a sibling before runsc read it,
// and a name there may be a link a sandbox planted for fiberd to
// write through. Here the run directory's "bundles" entry is planted
// before the clone, as a sandbox could plant it.
func TestBundleOutsideRunDir(t *testing.T) {
	cases := []struct {
		name  string
		plant func(t *testing.T, workDir, victim string)
	}{
		{name: "a link to a directory of the planter's choice", plant: func(t *testing.T, workDir, victim string) {
			if err := os.Symlink(victim, filepath.Join(workDir, "bundles")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a plain file, so nothing could be made under it", plant: func(t *testing.T, workDir, _ string) {
			if err := os.WriteFile(filepath.Join(workDir, "bundles"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, _, w, workDir := warmed(t, knobs{})
			victim := filepath.Join(t.TempDir(), "victim")
			if err := os.Mkdir(victim, 0o755); err != nil {
				t.Fatal(err)
			}
			tc.plant(t, workDir, victim)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ep := filepath.Join(workDir, "ep.sock")
			if _, err := b.Clone(ctx, w.ID, backend.FiberSpec{Fence: "g/1-1", Endpoint: ep, CgroupFD: -1, Deadline: 2 * time.Second, Generation: 1}); err != nil {
				t.Fatalf("Clone: %v", err)
			}
			fc := boxCID(t, b, "g/1-1")
			bundle := b.bundleDir(fc)
			if rel, err := filepath.Rel(workDir, bundle); err == nil && !strings.HasPrefix(rel, "..") {
				t.Fatalf("bundle %s is under the run directory %s", bundle, workDir)
			}
			if _, err := os.Stat(filepath.Join(bundle, "config.json")); err != nil {
				t.Fatalf("bundle under the state directory: %v", err)
			}
			if ents, _ := os.ReadDir(victim); len(ents) != 0 {
				t.Fatalf("fiberd wrote through the planted link: %v", ents)
			}
			if err := b.Kill("g/1-1"); err != nil {
				t.Fatalf("Kill: %v", err)
			}
			waitExit(t, b)
		})
	}
}

// TestParkAndResume checks that a park asks the workload to close its
// endpoint, checkpoints the sandbox (which ends it) and keeps the bundle
// beside the image. A resume brings the image back under a new fence and
// endpoint, handed over on the channel as a clone's are, or in the spec
// environment for a template that polls it.
func TestParkAndResume(t *testing.T) {
	cases := []struct {
		name  string
		knobs knobs
		spec  bool
	}{
		{name: "park, then resume under a new fence"},
		// The reaper removes the bundle as soon as the sandbox is gone,
		// which is before a real checkpoint returns. The bundle must be
		// beside the image all the same.
		{name: "checkpoint outlasts the reaper's cleanup", knobs: knobs{SlowCheckpt: 300 * time.Millisecond}},
		{name: "template that polls the spec environment", knobs: knobs{NoToken: true}, spec: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, f, workDir, _ := cloned(t, tc.knobs)
			fc := boxCID(t, b, "g/1-1")
			dir := filepath.Join(t.TempDir(), "park")
			if err := b.Park(context.Background(), "g/1-1", backend.ParkSpec{Dir: dir}); err != nil {
				t.Fatalf("Park: %v", err)
			}
			waitFor(t, "the reaper to remove the bundle", func() bool {
				_, err := os.Stat(b.bundleDir(fc))
				return err != nil
			})
			calls := f.calls()
			for _, want := range []string{"kill " + fc + " USR1", "checkpoint --image-path " + dir + " --direct " + fc} {
				if findCall(calls, want) == "" {
					t.Fatalf("no %q among\n%s", want, strings.Join(calls, "\n"))
				}
			}
			if c := findCall(calls, "checkpoint", "--direct "+fc); strings.Contains(c, "--leave-running") {
				t.Fatalf("a park left the sandbox running: %s", c)
			}
			for _, name := range []string{imageFile, "config.json"} {
				if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
					t.Fatalf("%s not in the park image: %v", name, err)
				}
			}
			if e := waitExit(t, b); e != (backend.Exit{FiberID: "g/1-1", Status: "exit:0"}) {
				t.Fatalf("exit = %+v, want the parked fiber's end", e)
			}
			if dialable(filepath.Join(workDir, "ep.sock")) {
				t.Fatal("the parked fiber's endpoint still serves")
			}
			ep := filepath.Join(workDir, "ep2.sock")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			fb, err := b.Resume(ctx, backend.ResumeSpec{Dir: dir, Fence: "g/2-1", Endpoint: ep, CgroupFD: -1, Deadline: 2 * time.Second, WarmID: "g", WorkDir: workDir, Session: "S", Generation: 2})
			if err != nil {
				t.Fatalf("Resume: %v", err)
			}
			fc2 := boxCID(t, b, "g/2-1")
			if pid := f.pidOf(fc2); pid == 0 || fb.ID != "g/2-1" || fb.PID != pid || !dialable(ep) {
				t.Fatalf("Resume = %+v (pid %d), want g/2-1 serving on %s", fb, pid, ep)
			}
			if findCall(f.calls(), "restore --detach --pid-file "+filepath.Join(b.bundleDir(fc2), "pid")+" --image-path "+dir+" --bundle "+b.bundleDir(fc2)+" --direct "+fc2) == "" {
				t.Fatal("the resume did not restore the park image")
			}
			cfgJSON, err := os.ReadFile(filepath.Join(b.bundleDir(fc2), "config.json"))
			if err != nil || !strings.Contains(string(cfgJSON), `"/bin/refzygote"`) {
				t.Fatalf("resumed bundle = %s (%v)", cfgJSON, err)
			}
			token, records := f.channelOf(fc2)
			if tc.spec {
				if !strings.Contains(string(cfgJSON), `"FIBERD_FENCE=g/2-1"`) || len(records) != 0 {
					t.Fatalf("resumed bundle = %s, channel records %v", cfgJSON, records)
				}
			} else {
				checkIdentity(t, cfgJSON, token, records, 2, "resume", "g/2-1", "/host/ep2.sock", nil, "S")
			}
			if err := b.Kill("g/2-1"); err != nil {
				t.Fatalf("Kill: %v", err)
			}
			if e := waitExit(t, b); e != (backend.Exit{FiberID: "g/2-1", Status: "exit:0"}) {
				t.Fatalf("exit = %+v", e)
			}
		})
	}
}

// TestParkRefusals covers a park of an unknown fiber, one whose workload cannot
// be signalled, one that keeps its endpoint, and one whose checkpoint
// fails. The wait for the endpoint is the spec's deadline, and without
// one the resume deadline this backend advises for the grant's warm
// instance, never a number of the park's own.
func TestParkRefusals(t *testing.T) {
	cases := []struct {
		name     string
		before   knobs // the fiber is born with these
		after    knobs // set once it is up
		fiber    string
		noBundle bool // the fiber's bundle is gone
		deadline time.Duration
		// tookMin and tookMax bound the wait, when the row is about it.
		tookMin, tookMax time.Duration
		wantErr          error
		wantText         string
	}{
		{name: "unknown fiber", fiber: "nobody", wantText: `unknown fiber "nobody"`},
		{name: "bundle gone", fiber: "g/1-1", noBundle: true, wantText: "config.json: no such file"},
		{name: "workload cannot be signalled", fiber: "g/1-1", after: knobs{Fail: map[string]bool{"kill": true}}, wantText: "runsc kill"},
		{name: "endpoint stays open, waited for the spec's deadline", fiber: "g/1-1", before: knobs{IgnoreUSR1: true}, after: knobs{IgnoreUSR1: true},
			deadline: 150 * time.Millisecond, tookMin: 150 * time.Millisecond, tookMax: time.Second,
			wantErr: context.DeadlineExceeded, wantText: "did not close its endpoint for the checkpoint"},
		{name: "endpoint stays open, waited for the floor without a deadline", fiber: "g/1-1", before: knobs{IgnoreUSR1: true}, after: knobs{IgnoreUSR1: true},
			tookMin: resumeDeadline, tookMax: resumeDeadline + time.Second,
			wantErr: context.DeadlineExceeded, wantText: "did not close its endpoint for the checkpoint"},
		// A slow template raises the advised resume deadline to four
		// times its restore, which is what the park then waits.
		{name: "endpoint stays open, waited for the advised deadline without one", fiber: "g/1-1", before: knobs{IgnoreUSR1: true, SlowRestore: 600 * time.Millisecond}, after: knobs{IgnoreUSR1: true},
			tookMin: deadlineFactor * 600 * time.Millisecond, tookMax: deadlineFactor*600*time.Millisecond + 2*time.Second,
			wantErr: context.DeadlineExceeded, wantText: "did not close its endpoint for the checkpoint"},
		{name: "checkpoint fails", fiber: "g/1-1", after: knobs{Fail: map[string]bool{"checkpoint": true}}, wantText: "runsc checkpoint"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, f, _, _ := cloned(t, tc.before)
			fc := boxCID(t, b, "g/1-1")
			f.setKnobs(tc.after)
			if tc.noBundle {
				if err := os.RemoveAll(b.bundleDir(fc)); err != nil {
					t.Fatal(err)
				}
			}
			t0 := time.Now()
			err := b.Park(context.Background(), tc.fiber, backend.ParkSpec{Dir: filepath.Join(t.TempDir(), "park"), Deadline: tc.deadline})
			took := time.Since(t0)
			if err == nil || (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) || !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("Park = %v, want %q (errors.Is %v)", err, tc.wantText, tc.wantErr)
			}
			if tc.tookMax > 0 && (took < tc.tookMin || took > tc.tookMax) {
				t.Fatalf("the park waited %s, want between %s and %s", took, tc.tookMin, tc.tookMax)
			}
			if !f.alive(fc) {
				t.Fatal("a refused park ended the fiber")
			}
		})
	}
}

// TestResumeRefusals checks that a park image without its bundle, or with one
// that cannot be read, is not resumed, and neither is one under a grant
// with no warm instance, whose pool socket the resumed sandbox would dial.
func TestResumeRefusals(t *testing.T) {
	cases := []struct {
		name     string
		config   string // "" for none
		wantText string
	}{
		{name: "no bundle beside the image", wantText: "park image without its bundle"},
		{name: "unreadable bundle", config: "{nonsense", wantText: "invalid character"},
		{name: "no warm instance to resume under", config: `{"process":{"args":["/bin/refzygote"]}}`, wantText: `no warm template "g" to resume under`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := newFake(t, knobs{})
			dir := t.TempDir()
			if tc.config != "" {
				if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(tc.config), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := b.Resume(context.Background(), backend.ResumeSpec{Dir: dir, Fence: "g/2-1", Endpoint: filepath.Join(t.TempDir(), "ep.sock"), CgroupFD: -1, WarmID: "g", Generation: 2})
			if err == nil || !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("Resume = %v, want %q", err, tc.wantText)
			}
		})
	}
}

// TestClose checks that closing kills the template, every fiber and every
// pooled sandbox, and each is reported gone.
func TestClose(t *testing.T) {
	cases := []struct {
		name   string
		pooled bool
	}{
		{name: "template and fiber"},
		{name: "template, fiber and a pooled sandbox", pooled: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, f, _, _ := cloned(t, knobs{})
			cids := []string{warmCID(t, b, "g"), boxCID(t, b, "g/1-1")}
			want := map[backend.Exit]bool{{WarmID: "g", Status: "template sandbox exited"}: true, {FiberID: "g/1-1", Status: "exit:0"}: true}
			if tc.pooled {
				p, err := b.Pool(context.Background(), "g", backend.PoolSpec{CgroupFD: -1, Deadline: 2 * time.Second})
				if err != nil {
					t.Fatalf("Pool: %v", err)
				}
				cids = append(cids, p.ID)
				want[backend.Exit{PooledID: p.ID, Status: "exit:0"}] = true
			}
			b.Close()
			got := map[backend.Exit]bool{}
			for range want {
				got[waitExit(t, b)] = true
			}
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("exits = %v, want %v", got, want)
			}
			for _, cid := range cids {
				if f.alive(cid) {
					t.Fatalf("%s is still running after Close", cid)
				}
			}
		})
	}
}

// TestReapersFinishBeforeTeardown pins that Close returns only once its
// reapers are done (the flake of 698b7c6, fixed in the backend). A
// reaper's delete is held at the gate, Close must still be waiting then,
// and once the gate opens it returns with every delete recorded and no
// goroutine left. An Unwarm'd template reports no Exit, so the reaper
// count is the signal.
func TestReapersFinishBeforeTeardown(t *testing.T) {
	cases := []struct {
		name  string
		start func(t *testing.T, b *Backend, workDir string) []string // the cids it leaves to Close
		held  func(t *testing.T, b *Backend)                          // ends the sandbox whose delete the gate holds, or nothing for Close to
	}{
		{name: "template and fiber", start: func(t *testing.T, b *Backend, workDir string) []string {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := b.Clone(ctx, "g", backend.FiberSpec{Fence: "g/1-1", Endpoint: filepath.Join(workDir, "ep.sock"), CgroupFD: -1, Deadline: 2 * time.Second, Generation: 1}); err != nil {
				t.Fatalf("Clone: %v", err)
			}
			return []string{warmCID(t, b, "g"), boxCID(t, b, "g/1-1")}
		}},
		{name: "unwarmed template", start: func(t *testing.T, b *Backend, _ string) []string {
			return []string{warmCID(t, b, "g")}
		}, held: func(_ *testing.T, b *Backend) { b.Unwarm("g") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, f, _, workDir := warmed(t, knobs{})
			cids := tc.start(t, b, workDir)
			gate := f.holdNextDelete()
			closed := make(chan struct{})
			if tc.held != nil {
				tc.held(t, b)
			}
			go func() {
				b.Close()
				close(closed)
			}()
			<-gate.claimed
			select {
			case <-closed:
				t.Fatal("Close returned while a reaper's delete was still to run")
			default:
			}
			close(gate.open)
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("Close did not return once the reapers could finish")
			}
			calls := f.calls()
			for _, cid := range cids {
				if findCall(calls, "delete -force "+cid) == "" {
					t.Fatalf("the reaper of %s had not deleted it when Close returned", cid)
				}
			}
			if !reapersDone(b, time.Second) {
				t.Fatal("a reaper is still counted after Close")
			}
			goleak.VerifyNone(t)
			if n := len(f.calls()) - len(calls); n != 0 {
				t.Fatalf("%d runsc calls after Close", n)
			}
		})
	}
}

// TestReaperNeedsNoProcess checks that a sandbox with a known pid is
// waited for without a `runsc wait` process, since the reaper holds a
// pidfd, and that its death is still reported once, with the status of
// the sandbox process itself because the backend is its parent here.
// Only a sandbox whose pid runsc could not say is waited for by `runsc
// wait`.
func TestReaperNeedsNoProcess(t *testing.T) {
	cases := []struct {
		name       string
		knobs      knobs
		wantWait   bool // a `runsc wait` ran for the fiber
		wantStatus string
	}{
		{name: "exit", knobs: knobs{ExitStatus: 3}, wantStatus: "exit:3"},
		{name: "signal", knobs: knobs{ExitStatus: 143}, wantStatus: "signal:15"},
		{name: "pid unknown", knobs: knobs{ExitStatus: 3, NoPidFile: true, Fail: map[string]bool{"state": true}}, wantWait: true, wantStatus: "exit:3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, f, _, _ := cloned(t, tc.knobs)
			fc := boxCID(t, b, "g/1-1")
			if err := b.Kill("g/1-1"); err != nil {
				t.Fatalf("Kill: %v", err)
			}
			if e := waitExit(t, b); e != (backend.Exit{FiberID: "g/1-1", Status: tc.wantStatus}) {
				t.Fatalf("exit = %+v, want status %s", e, tc.wantStatus)
			}
			waitFor(t, "the reaper's delete", func() bool { return findCall(f.calls(), "delete -force "+fc) != "" })
			if got := findCall(f.calls(), "wait "+fc) != ""; got != tc.wantWait {
				t.Fatalf("a `runsc wait` ran for the fiber: %v, want %v, among\n%s", got, tc.wantWait, strings.Join(f.calls(), "\n"))
			}
			select {
			case e := <-b.Exits():
				t.Fatalf("the fiber's death was reported again: %+v", e)
			default:
			}
		})
	}
}

// TestPidOf checks the sandbox pid from `runsc state`, or 0 when runsc
// cannot say.
func TestPidOf(t *testing.T) {
	cases := []struct {
		name  string
		cid   string
		knobs knobs
		want  func(f *fakeRunsc, wc string) int
	}{
		{name: "running sandbox", cid: "WARM", want: func(f *fakeRunsc, wc string) int { return f.pidOf(wc) }},
		{name: "unknown sandbox", cid: "nobody", want: func(*fakeRunsc, string) int { return 0 }},
		{name: "state fails", cid: "WARM", knobs: knobs{Fail: map[string]bool{"state": true}}, want: func(*fakeRunsc, string) int { return 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, f, _, _ := warmed(t, knobs{})
			wc := warmCID(t, b, "g")
			f.setKnobs(tc.knobs)
			want := tc.want(f, wc)
			if tc.name == "running sandbox" && want == 0 {
				t.Fatal("the running sandbox recorded no pid")
			}
			cid := strings.ReplaceAll(tc.cid, "WARM", wc)
			if got := b.pidOf(context.Background(), cid); got != want {
				t.Fatalf("pidOf(%s) = %d, want %d", cid, got, want)
			}
		})
	}
}

// TestNewCID checks that every incarnation gets a cid of its own, the kind
// and name stay readable, a long name is cut to a hash within runsc's limit,
// and what runsc refuses in a name is replaced.
func TestNewCID(t *testing.T) {
	long := strings.Repeat("abcdefghij", 10)
	cases := []struct {
		name     string
		kind     string
		in       string
		want     string // "" when only the shape is checked
		wantLen  int    // the whole id's length when want is ""
		wantHash bool   // the name was cut and ends in a hash
	}{
		{name: "warm", kind: "w", in: "g", want: "w-g-1"},
		{name: "fiber", kind: "f", in: "g/1-1", want: "f-g-1-1-2"},
		{name: "characters runsc refuses", kind: "f", in: "g:1 2@x", want: "f-g-1-2-x-3"},
		{name: "long name", kind: "w", in: long, wantLen: maxCID, wantHash: true},
		{name: "name that just fits", kind: "w", in: strings.Repeat("x", maxCID-len("w--5")), want: "w-" + strings.Repeat("x", maxCID-len("w--5")) + "-5"},
	}
	b := &Backend{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := b.newCID(tc.kind, tc.in)
			if tc.want != "" && got != tc.want {
				t.Fatalf("newCID(%s, %q) = %q, want %q", tc.kind, tc.in, got, tc.want)
			}
			if tc.want == "" && len(got) != tc.wantLen {
				t.Fatalf("newCID(%s, %q) = %q (%d bytes), want %d", tc.kind, tc.in, got, len(got), tc.wantLen)
			}
			if tc.wantHash {
				sum := sha256.Sum256([]byte(tc.in))
				if !strings.HasPrefix(got, tc.kind+"-"+tc.in[:20]) || !strings.Contains(got, "-"+hex.EncodeToString(sum[:4])+"-") {
					t.Fatalf("newCID(%s, long) = %q, want the name's head and its hash", tc.kind, got)
				}
			}
			if cid(got) != got || len(got) > maxCID {
				t.Fatalf("newCID = %q is not a container id runsc accepts", got)
			}
		})
	}
}

// TestSweep checks that opening the backend ends every sandbox a previous
// life left in its root, and leaves them alone when runsc cannot list them.
func TestSweep(t *testing.T) {
	cases := []struct {
		name     string
		knobs    knobs
		wantGone bool
	}{
		{name: "leftovers are deleted", wantGone: true},
		{name: "runsc cannot list", knobs: knobs{Fail: map[string]bool{"list": true}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRunsc(tc.knobs)
			t.Cleanup(f.endAll)
			// A sandbox of a previous life, started outside any backend.
			old := &Backend{opt: Options{Rootfs: "/rootfs"}}
			bundle := filepath.Join(t.TempDir(), "bundle")
			if err := old.writeBundle(bundle, []string{"/bin/refzygote"}, []string{"FIBERD_FENCE=none"}, t.TempDir(), t.TempDir(), "", ""); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if _, err := f.startSandbox("w-old-7", bundle, knobs{}, &out); err != nil || !f.alive("w-old-7") {
				t.Fatalf("the leftover sandbox did not start: %v %s", err, out.String())
			}
			// What the previous life left on disk: a fiber's bundle and a
			// template's directory, and a stray file beside them.
			state := filepath.Join(t.TempDir(), "state")
			stale := []string{filepath.Join(state, "bundles", "f-old-9"), filepath.Join(state, "templates", "w-old-7", "images"), filepath.Join(state, "channel", "w-old-7")}
			for _, d := range stale {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(d, "x"), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			b := newBackend(Options{Runsc: "runsc", Rootfs: t.TempDir(), StateDir: state}, f.run, newFakeTmpfs().ops())
			t.Cleanup(b.Close)
			left := 0
			for _, sub := range []string{"bundles", "templates", "channel"} {
				ents, _ := os.ReadDir(filepath.Join(state, sub))
				left += len(ents)
			}
			if tc.wantGone {
				if f.alive("w-old-7") || findCall(f.calls(), "delete -force w-old-7") == "" {
					t.Fatal("the leftover was not deleted through runsc")
				}
				if left != 0 {
					t.Fatalf("%d stale bundle or template directories left after the sweep", left)
				}
				return
			}
			if !f.alive("w-old-7") || findCall(f.calls(), "delete") != "" {
				t.Fatal("something was deleted without a listing")
			}
			if left != len(stale) {
				t.Fatalf("%d of %d directories left without a listing, want all of them", left, len(stale))
			}
		})
	}
}

// TestCIDReuse checks that a reaper's late delete cannot touch a successor
// under the same grant or fence. The reaper deletes once the sandbox has
// exited, which can be long after the host warmed or cloned again. The
// successor has a cid of its own. The gate holds the delete until the
// successor is up.
func TestCIDReuse(t *testing.T) {
	cases := []struct {
		name string
		// first starts the sandbox and returns its cid. again ends it and
		// starts its successor, returning the successor's cid and bundle
		// ("" when there is none).
		first func(t *testing.T, b *Backend, workDir string) string
		again func(t *testing.T, b *Backend, gate *deleteGate, workDir string) (string, string)
		// settle ends the successor and waits for its reaper, so nothing
		// still writes into the test's directories when they go.
		settle func(t *testing.T, b *Backend, f *fakeRunsc, second string)
	}{
		{name: "template warmed again after Unwarm",
			first: func(t *testing.T, b *Backend, _ string) string { return warmCID(t, b, "g") },
			again: func(t *testing.T, b *Backend, gate *deleteGate, workDir string) (string, string) {
				b.Unwarm("g")
				<-gate.claimed
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if _, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "g", Template: backend.Template{Argv: []string{"/bin/refzygote", "--gvisor"}}, CgroupFD: -1, ProbeCgroupFD: -1, WorkDir: workDir}); err != nil {
					t.Fatalf("second Warm: %v", err)
				}
				// The successor's own template directory, which the
				// first's reaper must not take with its own.
				cid := warmCID(t, b, "g")
				return cid, filepath.Join(b.opt.StateDir, "templates", cid, "bundle")
			},
			settle: func(t *testing.T, b *Backend, f *fakeRunsc, second string) {
				b.Unwarm("g")
				waitFor(t, "the successor's reaper", func() bool { return findCall(f.calls(), "delete -force "+second) != "" })
			}},
		{name: "fiber cloned again under its fence after Kill",
			first: func(t *testing.T, b *Backend, workDir string) string {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if _, err := b.Clone(ctx, "g", backend.FiberSpec{Fence: "g/1-1", Endpoint: filepath.Join(workDir, "ep.sock"), CgroupFD: -1, Deadline: 2 * time.Second, Generation: 1}); err != nil {
					t.Fatalf("Clone: %v", err)
				}
				return boxCID(t, b, "g/1-1")
			},
			again: func(t *testing.T, b *Backend, gate *deleteGate, workDir string) (string, string) {
				if err := b.Kill("g/1-1"); err != nil {
					t.Fatalf("Kill: %v", err)
				}
				<-gate.claimed
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if _, err := b.Clone(ctx, "g", backend.FiberSpec{Fence: "g/1-1", Endpoint: filepath.Join(workDir, "ep.sock"), CgroupFD: -1, Deadline: 2 * time.Second, Generation: 1}); err != nil {
					t.Fatalf("second Clone: %v", err)
				}
				cid := boxCID(t, b, "g/1-1")
				return cid, b.bundleDir(cid)
			},
			settle: func(t *testing.T, b *Backend, _ *fakeRunsc, _ string) {
				if err := b.Kill("g/1-1"); err != nil {
					t.Fatalf("Kill: %v", err)
				}
				waitExit(t, b)
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, f, _, workDir := warmed(t, knobs{})
			first := tc.first(t, b, workDir)
			gate := f.holdNextDelete()
			second, bundle := tc.again(t, b, gate, workDir)
			if !f.alive(second) {
				t.Fatalf("the successor %s is not running", second)
			}
			// The old reaper's delete lands here.
			close(gate.open)
			<-gate.passed
			if !f.alive(second) {
				t.Fatalf("the late delete of %s ended its successor %s", first, second)
			}
			if bundle != "" {
				if _, err := os.Stat(filepath.Join(bundle, "config.json")); err != nil {
					t.Fatalf("the late reaper removed the successor's bundle: %v", err)
				}
			}
			// The first's own directory goes with it. The reaper removes it
			// after the delete returns, so wait for that.
			waitFor(t, "the reaper to remove the template directory of "+first, func() bool {
				_, err := os.Stat(filepath.Join(b.opt.StateDir, "templates", first))
				return os.IsNotExist(err)
			})
			if second == first {
				t.Fatalf("the successor reuses cid %s", first)
			}
			tc.settle(t, b, f, second)
		})
	}
}

// isHex reports whether s is n hex characters.
func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// checkIdentity checks a late-binding restore: its bundle carries the
// token the sandbox claimed with and nothing of the fiber, and the one
// incarnation record on the channel names the generation, kind, fence,
// endpoint, payload and session, carries no identity (no sandbox serves
// handoff) and a fresh seed of backend.SeedBytes.
func checkIdentity(t *testing.T, cfgJSON []byte, token string, records [][]string, generation int, kind, fence, endpoint string, payload []byte, session string) {
	t.Helper()
	if !isHex(token, 2*tokenBytes) || !strings.Contains(string(cfgJSON), `"FIBERD_TOKEN=`+token+`"`) {
		t.Fatalf("bundle token %q:\n%s", token, cfgJSON)
	}
	for _, name := range []string{"FIBERD_FENCE", "FIBERD_ENDPOINT", "FIBERD_PAYLOAD", "FIBERD_SESSION"} {
		if strings.Contains(string(cfgJSON), name) {
			t.Fatalf("bundle names %s, which belongs on the channel:\n%s", name, cfgJSON)
		}
	}
	if len(records) != 1 || len(records[0]) != backend.IncarnationFields {
		t.Fatalf("channel records = %v, want one identity of %d fields", records, backend.IncarnationFields)
	}
	ph := "-"
	if len(payload) > 0 {
		ph = hex.EncodeToString(payload)
	}
	sh := "-"
	if session != "" {
		sh = hex.EncodeToString([]byte(session))
	}
	got := records[0]
	want := []string{strconv.Itoa(generation), kind, fence, endpoint, ph, sh, "-", "-", "-", "-", ""}
	for i := 0; i < backend.IncarnationFields-1; i++ {
		if got[i] != want[i] {
			t.Fatalf("identity field %d = %q, want %q (record %v)", i, got[i], want[i], got)
		}
	}
	if !isHex(got[backend.IncarnationFields-1], 2*backend.SeedBytes) {
		t.Fatalf("identity seed = %q, want %d hex characters", got[backend.IncarnationFields-1], 2*backend.SeedBytes)
	}
}

// TestProbeDetectsLateBinding checks that the footprint probe, whose spec
// carries a token and the probe's fence and endpoint both, tells a
// template that dials the pool socket from one that polls the spec
// environment, measures either serving, and that Pool refuses the
// latter's warm instance.
func TestProbeDetectsLateBinding(t *testing.T) {
	leaf := map[string]string{"memory.stat": "anon 4096\nshmem 8192\nfile 0\n", "memory.current": "12288\n"}
	cases := []struct {
		name       string
		knobs      knobs
		wantNoPool bool
	}{
		{name: "template sends a token"},
		{name: "template polls the spec", knobs: knobs{NoToken: true}, wantNoPool: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(os.Stderr) })
			b, f := newFake(t, tc.knobs)
			workDir := filepath.Join(t.TempDir(), "g")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			w, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "g", Template: backend.Template{Argv: []string{"/bin/refzygote"}}, CgroupFD: -1, ProbeCgroupFD: cgroupFiles(t, leaf), WorkDir: workDir})
			if err != nil {
				t.Fatalf("Warm: %v", err)
			}
			if w.Bytes != 8192 || w.TotalBytes != 12288 {
				t.Fatalf("Warm measured %d/%d bytes, want the probe serving", w.Bytes, w.TotalBytes)
			}
			b.mu.Lock()
			noPool := b.warms["g"].noPool
			b.mu.Unlock()
			if noPool != tc.wantNoPool || strings.Contains(logs.String(), "has no pool") != tc.wantNoPool {
				t.Fatalf("noPool = %v, log %q, want %v", noPool, logs.String(), tc.wantNoPool)
			}
			probe := warmCID(t, b, "g") + "-probe"
			_, records := f.channelOf(probe)
			if (len(records) == 0) != tc.wantNoPool {
				t.Fatalf("probe channel records = %v, noPool %v", records, tc.wantNoPool)
			}
			p, err := b.Pool(ctx, "g", backend.PoolSpec{CgroupFD: -1, Deadline: 2 * time.Second})
			if errors.Is(err, backend.ErrNoPool) != tc.wantNoPool {
				t.Fatalf("Pool = %+v, %v, want ErrNoPool %v", p, err, tc.wantNoPool)
			}
			if err == nil {
				b.Discard(p.ID)
				waitExit(t, b)
			}
		})
	}
}

// TestPoolBind checks a sandbox restored ahead of its fiber: Pool waits
// for it to claim its token on the pool socket and Bind hands it the
// identity, with a fresh seed, on that held connection, then waits for
// the ack and the endpoint. An unknown, repeated or missing claim is
// closed, no token under the deadline kills the sandbox, and a bad or
// missing ack kills what is the fiber by then. after is set once the
// template is warm, so the probe saw a template that binds late. A
// sandbox that ends before its restore returns still reports its own
// status.
func TestPoolBind(t *testing.T) {
	cases := []struct {
		name        string
		after       knobs
		deadline    time.Duration
		wantPoolErr string
		wantExit    string // how the sandbox of a failed Pool ended
		wantWait    bool   // its reaper asked `runsc wait`, having no pid
		wantBindErr string
		// A connection of the test's own, made once the sandbox holds its
		// claim: it repeats the sandbox's token, or says nothing. Either
		// must be closed.
		repeat, silent bool
	}{
		{name: "token claimed, identity handed out"},
		{name: "unknown token", after: knobs{WrongToken: true}, wantPoolErr: "exited before sending its token", wantExit: "exit:122"},
		// The sandbox gives up before its restore returns. Its own status
		// still comes back, from the pid runsc wrote or from `runsc wait`.
		{name: "unknown token, ended before the restore returned", after: knobs{WrongToken: true, EndsFirst: true}, wantPoolErr: "exited before sending its token", wantExit: "exit:122"},
		{name: "unknown token, ended before the restore returned, no pid file", after: knobs{WrongToken: true, EndsFirst: true, NoPidFile: true}, wantPoolErr: "exited before sending its token", wantExit: "exit:122", wantWait: true},
		{name: "repeated token is closed", repeat: true},
		{name: "a connection that sends no token is closed", silent: true},
		{name: "no token before the deadline", after: knobs{NoToken: true}, deadline: 300 * time.Millisecond, wantPoolErr: "sent no token: context deadline exceeded", wantExit: "exit:0"},
		{name: "ack with the wrong fence", after: knobs{BadAck: true}, wantBindErr: "g/1-1: ack names"},
		{name: "no ack", after: knobs{NoAck: true}, deadline: 300 * time.Millisecond, wantBindErr: "g/1-1: no ack: context deadline exceeded"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, f, w, workDir := warmed(t, knobs{})
			f.setKnobs(tc.after)
			deadline := 2 * time.Second
			if tc.deadline > 0 {
				deadline = tc.deadline
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			p, err := b.Pool(ctx, w.ID, backend.PoolSpec{CgroupFD: -1, Deadline: deadline})
			if tc.wantPoolErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantPoolErr) {
					t.Fatalf("Pool = %+v, %v, want %q", p, err, tc.wantPoolErr)
				}
				pc := lastRestored(f.calls())
				if findCall(f.calls(), "kill "+pc+" KILL") == "" || f.alive(pc) {
					t.Fatal("the sandbox that never claimed its token was not killed")
				}
				// Its end is reported under the pooled id, as a fiber's is
				// after a failed Clone, and the host drops what it does
				// not know.
				if e := waitExit(t, b); e != (backend.Exit{PooledID: pc, Status: tc.wantExit}) {
					t.Fatalf("exit = %+v, want pooled %s with %s", e, pc, tc.wantExit)
				}
				if got := findCall(f.calls(), "wait "+pc) != ""; got != tc.wantWait {
					t.Fatalf("a `runsc wait` ran for %s: %v, want %v", pc, got, tc.wantWait)
				}
				b.mu.Lock()
				n := len(b.pooled)
				b.mu.Unlock()
				if n != 0 {
					t.Fatalf("%d pooled sandboxes registered after a failed Pool", n)
				}
				return
			}
			if err != nil {
				t.Fatalf("Pool: %v", err)
			}
			pid := f.pidOf(p.ID)
			if !strings.HasPrefix(p.ID, "p-g-") || pid == 0 || p.PID != pid {
				t.Fatalf("Pool = %+v, want a p-g- id with the sandbox pid %d", p, pid)
			}
			token, records := f.channelOf(p.ID)
			if len(records) != 0 {
				t.Fatalf("before Bind the channel carried %v", records)
			}
			if tc.repeat || tc.silent {
				sock := poolSocketOf(t, b, "g")
				var claim []byte
				if tc.repeat {
					claim = backend.Record(backend.RecordClaim, token)
				}
				if !claimClosed(t, sock, claim, 2*claimWait) {
					t.Fatal("the backend kept the connection")
				}
				if !f.alive(p.ID) {
					t.Fatal("the pooled sandbox was ended by a stray claim")
				}
			}
			ep := filepath.Join(workDir, "ep.sock")
			fb, err := b.Bind(ctx, p.ID, backend.FiberSpec{Fence: "g/1-1", Endpoint: ep, CgroupFD: -1, Deadline: deadline, Payload: []byte{1, 2}, Session: "conv 42", Generation: 1})
			if tc.wantBindErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantBindErr) {
					t.Fatalf("Bind = %+v, %v, want %q", fb, err, tc.wantBindErr)
				}
				if findCall(f.calls(), "kill "+p.ID+" KILL") == "" || f.alive(p.ID) {
					t.Fatal("the sandbox was not killed after the failed hand-out")
				}
				// The sandbox kept its pooled id, so its end is never
				// mistaken for a fiber's born under the fence meanwhile.
				if e := waitExit(t, b); e.PooledID != p.ID || e.FiberID != "" {
					t.Fatalf("exit = %+v, want the pooled sandbox %s", e, p.ID)
				}
				b.mu.Lock()
				pooled, known := len(b.pooled), b.boxes["g/1-1"] != nil
				b.mu.Unlock()
				if pooled != 0 || known {
					t.Fatalf("after the failed Bind %d pooled and the fence registered %v", pooled, known)
				}
				return
			}
			if err != nil {
				t.Fatalf("Bind: %v", err)
			}
			if fb.ID != "g/1-1" || fb.PID != pid || !dialable(ep) {
				t.Fatalf("Bind = %+v, want g/1-1 with pid %d serving on %s", fb, pid, ep)
			}
			cfgJSON, err := os.ReadFile(filepath.Join(b.bundleDir(p.ID), "config.json"))
			if err != nil {
				t.Fatal(err)
			}
			_, records = f.channelOf(p.ID)
			checkIdentity(t, cfgJSON, token, records, 1, "clone", "g/1-1", "/host/ep.sock", []byte{1, 2}, "conv 42")
			b.mu.Lock()
			pooled, known := len(b.pooled), b.boxes["g/1-1"] != nil
			b.mu.Unlock()
			if pooled != 0 || !known {
				t.Fatalf("after Bind %d pooled and the fiber registered %v", pooled, known)
			}
			if err := b.Kill("g/1-1"); err != nil {
				t.Fatalf("Kill: %v", err)
			}
			if e := waitExit(t, b); e != (backend.Exit{FiberID: "g/1-1", Status: "exit:0"}) {
				t.Fatalf("exit = %+v", e)
			}
		})
	}
}

// TestPooledEnds checks how a pooled sandbox ends before Bind: dying on
// its own or discarded, its end is reported under its pooled id, and
// Pool and Bind refuse what they do not know.
func TestPooledEnds(t *testing.T) {
	cases := []struct {
		name string
		end  func(t *testing.T, b *Backend, f *fakeRunsc, id string)
		want string // the exit status, "" when no exit is expected
	}{
		{name: "dies before Bind", end: func(_ *testing.T, _ *Backend, f *fakeRunsc, id string) { f.endWith(id, 122) }, want: "exit:122"},
		{name: "discarded", end: func(_ *testing.T, b *Backend, _ *fakeRunsc, id string) { b.Discard(id) }, want: "exit:0"},
		{name: "unknown ids are refused", end: func(t *testing.T, b *Backend, _ *fakeRunsc, _ string) {
			if _, err := b.Pool(context.Background(), "nobody", backend.PoolSpec{CgroupFD: -1}); err == nil || !strings.Contains(err.Error(), `no warm template "nobody"`) {
				t.Fatalf("Pool of an unknown template = %v", err)
			}
			if _, err := b.Bind(context.Background(), "nobody", backend.FiberSpec{Fence: "g/1-1", CgroupFD: -1, Generation: 1}); err == nil || !strings.Contains(err.Error(), `no pooled sandbox "nobody"`) {
				t.Fatalf("Bind of an unknown sandbox = %v", err)
			}
			b.Discard("nobody")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, f, w, _ := warmed(t, knobs{})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			p, err := b.Pool(ctx, w.ID, backend.PoolSpec{CgroupFD: -1, Deadline: 2 * time.Second})
			if err != nil {
				t.Fatalf("Pool: %v", err)
			}
			tc.end(t, b, f, p.ID)
			if tc.want == "" {
				if !f.alive(p.ID) {
					t.Fatal("the pooled sandbox was ended")
				}
				b.Discard(p.ID)
				waitExit(t, b)
				return
			}
			if e := waitExit(t, b); e != (backend.Exit{PooledID: p.ID, Status: tc.want}) {
				t.Fatalf("exit = %+v, want pooled %s with %s", e, p.ID, tc.want)
			}
			b.mu.Lock()
			n := len(b.pooled) + len(b.boxes)
			b.mu.Unlock()
			if n != 0 {
				t.Fatalf("%d sandboxes registered after the end", n)
			}
			if _, err := b.Bind(ctx, p.ID, backend.FiberSpec{Fence: "g/1-1", CgroupFD: -1, Generation: 1}); err == nil {
				t.Fatal("Bind of an ended pooled sandbox succeeded")
			}
		})
	}
}

// TestPoolFlood checks the bound on unclaimed connections. Any sandbox
// of the grant can open connections to the pool socket and say nothing.
// At most unclaimedMax are held, each for claimWait, one more closes
// the oldest at once, and a real claim gets through meanwhile.
func TestPoolFlood(t *testing.T) {
	cases := []struct {
		name  string
		flood int // silent connections, the last unclaimedMax of which are held
	}{
		{name: "twice the bound", flood: 2 * unclaimedMax},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, _, w, _ := warmed(t, knobs{})
			sock := poolSocketOf(t, b, "g")
			var flood []net.Conn
			for i := 0; i < tc.flood; i++ {
				c, err := net.Dial("unixpacket", sock)
				if err != nil {
					t.Fatalf("dial %d: %v", i, err)
				}
				flood = append(flood, c)
			}
			defer func() {
				for _, c := range flood {
					_ = c.Close()
				}
			}()
			// The held ones stay open until claimWait. The rest must be
			// gone well before that.
			closed := 0
			for _, c := range flood {
				_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				if n, err := c.Read(make([]byte, 1)); n == 0 && err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
					closed++
				}
			}
			if closed != tc.flood-unclaimedMax {
				t.Fatalf("%d of %d silent connections were closed at once, want the %d over the bound", closed, tc.flood, tc.flood-unclaimedMax)
			}
			b.mu.Lock()
			held := len(b.warms["g"].unclaimed)
			b.mu.Unlock()
			if held != unclaimedMax {
				t.Fatalf("%d unclaimed connections held, want %d", held, unclaimedMax)
			}
			// A sandbox restored under the flood still claims in time.
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			p, err := b.Pool(ctx, w.ID, backend.PoolSpec{CgroupFD: -1, Deadline: 2 * time.Second})
			if err != nil {
				t.Fatalf("Pool under a flood: %v", err)
			}
			b.Discard(p.ID)
			waitExit(t, b)
		})
	}
}

// TestFillsYieldToClones checks that a pool restore never costs a clone
// its deadline: a clone takes a slot as it comes, a pool restore starts
// only while no clone waits or runs, one at a time, and the clone that
// arrives while one runs cuts it short.
func TestFillsYieldToClones(t *testing.T) {
	cases := []struct {
		name string
		max  int
		slow time.Duration // how long each restore holds its slot
		run  func(t *testing.T, b *Backend, f *fakeRunsc, w backend.Warm, workDir string)
	}{
		{name: "a running fill is cut short when a clone asks", max: 1, slow: 300 * time.Millisecond,
			run: func(t *testing.T, b *Backend, f *fakeRunsc, w backend.Warm, workDir string) {
				const slow = 300 * time.Millisecond
				ctx := context.Background()
				var wg sync.WaitGroup
				var perr error
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, perr = b.Pool(ctx, w.ID, backend.PoolSpec{CgroupFD: -1, Deadline: 2 * time.Second})
				}()
				// The probe's restore is the first, the fill's the second.
				waitFor(t, "the fill's restore to start", func() bool { return restoresStarted(f.calls()) >= 2 })
				// The clone's own restore takes slow, so queueing behind the
				// fill's would take twice that.
				t0 := time.Now()
				_, err := b.Clone(ctx, w.ID, backend.FiberSpec{Fence: "g/1-1", Endpoint: filepath.Join(workDir, "ep.sock"), CgroupFD: -1, Deadline: 2 * time.Second, Generation: 1})
				if err != nil {
					t.Fatalf("Clone behind a fill = %v, want it served at once", err)
				}
				if took := time.Since(t0); took >= 2*slow {
					t.Fatalf("Clone took %s, so it queued behind the fill's whole restore", took)
				}
				wg.Wait()
				if !errors.Is(perr, backend.ErrYielded) {
					t.Fatalf("Pool = %v, want ErrYielded", perr)
				}
				if f.peakRestores() != 1 {
					t.Fatalf("peak restores in flight = %d, want 1", f.peakRestores())
				}
			}},
		{name: "a fill waits while a clone restores", max: 2, slow: 100 * time.Millisecond,
			run: func(t *testing.T, b *Backend, f *fakeRunsc, w backend.Warm, workDir string) {
				ctx := context.Background()
				var wg sync.WaitGroup
				var cerr error
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, cerr = b.Clone(ctx, w.ID, backend.FiberSpec{Fence: "g/1-1", Endpoint: filepath.Join(workDir, "ep.sock"), CgroupFD: -1, Deadline: 2 * time.Second, Generation: 1})
				}()
				waitFor(t, "the clone's restore to start", func() bool { return restoresStarted(f.calls()) >= 2 })
				if _, err := b.Pool(ctx, w.ID, backend.PoolSpec{CgroupFD: -1, Deadline: 2 * time.Second}); err != nil {
					t.Fatalf("Pool: %v", err)
				}
				wg.Wait()
				if cerr != nil {
					t.Fatalf("Clone: %v", cerr)
				}
				if f.peakRestores() != 1 {
					t.Fatalf("peak restores in flight = %d, want 1: the fill ran beside the clone", f.peakRestores())
				}
			}},
		{name: "a fill waits behind a clone waiting for a slot", max: 1, slow: 100 * time.Millisecond,
			run: func(t *testing.T, b *Backend, f *fakeRunsc, w backend.Warm, workDir string) {
				ctx := context.Background()
				var wg sync.WaitGroup
				errs := make([]error, 2)
				for i := range 2 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						_, errs[i] = b.Clone(ctx, w.ID, backend.FiberSpec{Fence: fmt.Sprintf("g/1-%d", i), Endpoint: filepath.Join(workDir, fmt.Sprintf("ep%d.sock", i)), CgroupFD: -1, Deadline: 2 * time.Second, Generation: 1})
					}()
					if i == 0 {
						waitFor(t, "the first clone's restore to start", func() bool { return restoresStarted(f.calls()) >= 2 })
					}
				}
				// The second clone has queued for the slot well within this.
				time.Sleep(30 * time.Millisecond)
				if _, err := b.Pool(ctx, w.ID, backend.PoolSpec{CgroupFD: -1, Deadline: 2 * time.Second}); err != nil {
					t.Fatalf("Pool: %v", err)
				}
				wg.Wait()
				for i, err := range errs {
					if err != nil {
						t.Fatalf("Clone %d: %v", i, err)
					}
				}
				if last := lastRestored(f.calls()); !strings.HasPrefix(last, "p-") {
					t.Fatalf("last restore was %s, want the pool's after both clones", last)
				}
			}},
		{name: "fills run one at a time", max: 3, slow: 50 * time.Millisecond,
			run: func(t *testing.T, b *Backend, f *fakeRunsc, w backend.Warm, workDir string) {
				ctx := context.Background()
				var wg sync.WaitGroup
				errs := make([]error, 2)
				for i := range 2 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						_, errs[i] = b.Pool(ctx, w.ID, backend.PoolSpec{CgroupFD: -1, Deadline: 2 * time.Second})
					}()
				}
				wg.Wait()
				for i, err := range errs {
					if err != nil {
						t.Fatalf("Pool %d: %v", i, err)
					}
				}
				if f.peakRestores() != 1 {
					t.Fatalf("peak restores in flight = %d, want 1", f.peakRestores())
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, f := newFakeMax(t, knobs{SlowRestore: tc.slow}, tc.max)
			workDir := filepath.Join(t.TempDir(), "g")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			w, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "g", Template: backend.Template{Argv: []string{"/bin/refzygote", "--gvisor"}}, CgroupFD: -1, ProbeCgroupFD: -1, WorkDir: workDir})
			if err != nil {
				t.Fatalf("Warm: %v", err)
			}
			tc.run(t, b, f, w, workDir)
		})
	}
}

// TestRestorePidFile checks that a restore learns its sandbox's pid from
// the file runsc writes, so no `runsc state` process sits on a birth's
// path, and asks `runsc state` only when the file is not there.
func TestRestorePidFile(t *testing.T) {
	cases := []struct {
		name      string
		knobs     knobs
		wantState bool // a `state` call for the fiber's sandbox
	}{
		{name: "the pid comes from the file"},
		{name: "a missing file falls back to state", knobs: knobs{NoPidFile: true}, wantState: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, f, _, fb := cloned(t, tc.knobs)
			fc := boxCID(t, b, fb.ID)
			if want := f.pidOf(fc); fb.PID == 0 || fb.PID != want {
				t.Fatalf("Fiber.PID = %d, want the sandbox's %d", fb.PID, want)
			}
			calls := f.calls()
			if r := findCall(calls, "restore --detach", fc); !strings.Contains(r, "--pid-file "+filepath.Join(b.bundleDir(fc), "pid")) {
				t.Fatalf("restore = %q, want --pid-file under the bundle", r)
			}
			if got := findCall(calls, "state "+fc) != ""; got != tc.wantState {
				t.Fatalf("a state call for the fiber = %v, want %v", got, tc.wantState)
			}
		})
	}
}

// TestFootprintBeforeHandOut checks that every birth reports what its leaf
// counted on the W counter before the sandbox took its identity, which is
// the sandbox's own fixed footprint. The template's probe is one restore
// of the image and another settles MiB away from it, which on amd64 CI let
// a fiber dirty 4 MiB over a 1 MiB budget unseen (C6). A pooled sandbox is
// counted at its hand-out, not at its restore, and a resume counts the
// image it brought back.
func TestFootprintBeforeHandOut(t *testing.T) {
	leaf := map[string]string{"memory.stat": "anon 4096\nshmem 8192\nfile 0\n", "memory.current": "12288\n"}
	cases := []struct {
		name     string
		knobs    knobs
		pooled   bool
		resume   bool
		noCgroup bool
		want     uint64
	}{
		{name: "a clone counts its leaf once restored and claimed", want: 8192},
		{name: "a template that polls its spec counts its leaf once restored", knobs: knobs{NoToken: true}, want: 8192},
		{name: "a pooled sandbox counts its leaf at its hand-out", pooled: true, want: 8192},
		{name: "a resume counts the image it brought back", resume: true, want: 8192},
		{name: "without a cgroup nothing is counted", noCgroup: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fd := -1
			if !tc.noCgroup {
				fd = cgroupFiles(t, leaf)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var fb backend.Fiber
			var err error
			switch {
			case tc.pooled:
				b, _, w, workDir := warmed(t, tc.knobs)
				// The pool leaf counted less when the sandbox was restored
				// into it, and the hand-out reads the leaf again.
				pfd := cgroupFiles(t, map[string]string{"memory.stat": "shmem 4096\n"})
				p, perr := b.Pool(ctx, w.ID, backend.PoolSpec{CgroupFD: pfd, Deadline: 2 * time.Second})
				if perr != nil {
					t.Fatalf("Pool: %v", perr)
				}
				fb, err = b.Bind(ctx, p.ID, backend.FiberSpec{Fence: "g/1-1", Endpoint: filepath.Join(workDir, "ep.sock"), CgroupFD: fd, Deadline: 2 * time.Second, Generation: 1})
			case tc.resume:
				b, _, workDir, _ := cloned(t, tc.knobs)
				fc := boxCID(t, b, "g/1-1")
				dir := filepath.Join(t.TempDir(), "park")
				if perr := b.Park(ctx, "g/1-1", backend.ParkSpec{Dir: dir}); perr != nil {
					t.Fatalf("Park: %v", perr)
				}
				waitFor(t, "the reaper to remove the bundle", func() bool {
					_, serr := os.Stat(b.bundleDir(fc))
					return serr != nil
				})
				waitExit(t, b)
				fb, err = b.Resume(ctx, backend.ResumeSpec{Dir: dir, Fence: "g/2-1", Endpoint: filepath.Join(workDir, "ep2.sock"), CgroupFD: fd, Deadline: 2 * time.Second, WarmID: "g", WorkDir: workDir, Generation: 2})
			default:
				b, _, w, workDir := warmed(t, tc.knobs)
				fb, err = b.Clone(ctx, w.ID, backend.FiberSpec{Fence: "g/1-1", Endpoint: filepath.Join(workDir, "ep.sock"), CgroupFD: fd, Deadline: 2 * time.Second, Generation: 1})
			}
			if err != nil {
				t.Fatalf("birth: %v", err)
			}
			if fb.Footprint != tc.want {
				t.Fatalf("Footprint = %d, want %d", fb.Footprint, tc.want)
			}
		})
	}
}

// TestHandOutGeneration checks that the identity record carries the
// generation the host gave, whether the sandbox was restored for the
// clone or handed out of the pool. The backend counts nothing itself.
// The old backend wrote "2" for every clone and "0" for every resume,
// which the rows above 1 catch. A generation below 1 is no incarnation,
// and the template would exit on it, so it is refused by name instead.
func TestHandOutGeneration(t *testing.T) {
	cases := []struct {
		name       string
		pooled     bool // Pool then Bind, instead of Clone
		generation int
		wantErr    string
	}{
		{name: "a clone restored on demand is 1", generation: 1},
		{name: "a pooled sandbox handed out is 1", pooled: true, generation: 1},
		{name: "a clone the host counts as 7", generation: 7},
		{name: "a pooled hand-out the host counts as 42", pooled: true, generation: 42},
		{name: "a clone with no generation is refused", wantErr: "g/1-1: generation 0 is not an incarnation"},
		{name: "a pooled hand-out with no generation is refused", pooled: true, wantErr: "g/1-1: generation 0 is not an incarnation"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, f, w, workDir := warmed(t, knobs{})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			spec := backend.FiberSpec{Fence: "g/1-1", Endpoint: filepath.Join(workDir, "ep.sock"), CgroupFD: -1, Deadline: 2 * time.Second, Generation: tc.generation}
			var cid string
			var err error
			if tc.pooled {
				p, perr := b.Pool(ctx, w.ID, backend.PoolSpec{CgroupFD: -1, Deadline: 2 * time.Second})
				if perr != nil {
					t.Fatalf("Pool: %v", perr)
				}
				_, err = b.Bind(ctx, p.ID, spec)
				cid = p.ID
			} else {
				_, err = b.Clone(ctx, w.ID, spec)
				if err == nil {
					cid = boxCID(t, b, "g/1-1")
				}
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("hand-out: %v", err)
			}
			_, records := f.channelOf(cid)
			if len(records) != 1 || len(records[0]) != backend.IncarnationFields {
				t.Fatalf("channel records = %v, want one identity", records)
			}
			if got := records[0][0]; got != strconv.Itoa(tc.generation) {
				t.Fatalf("identity generation = %q, want %d", got, tc.generation)
			}
		})
	}
}
