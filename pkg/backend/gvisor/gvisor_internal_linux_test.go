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
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
)

// newFake opens a backend over the fake runsc with a rootfs directory of
// its own. Everything it starts is ended when the test is.
func newFake(t *testing.T, k knobs) (*Backend, string) {
	t.Helper()
	bin, cfg := fakeRunscBin(t, k)
	b := New(Options{Runsc: bin, Rootfs: filepath.Join(t.TempDir(), "rootfs"), StateDir: filepath.Join(t.TempDir(), "state")}).(*Backend)
	if err := os.Mkdir(b.opt.Rootfs, 0o755); err != nil {
		t.Fatal(err)
	}
	// New looked for the rootfs before it existed. Set the tier a real
	// opening would find.
	b.tier = core.TierSnapshot
	t.Cleanup(func() {
		b.Close()
		endAllSandboxes(t, cfg)
	})
	return b, cfg
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
func warmed(t *testing.T, k knobs) (*Backend, string, backend.Warm, string) {
	t.Helper()
	b, cfg := newFake(t, k)
	workDir := filepath.Join(t.TempDir(), "g")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "g", Template: backend.Template{Argv: []string{"/bin/refzygote", "--gvisor"}}, CgroupFD: -1, ProbeCgroupFD: -1, WorkDir: workDir})
	if err != nil {
		t.Fatalf("Warm: %v", err)
	}
	return b, cfg, w, workDir
}

// cloned is warmed plus one fiber serving on <workDir>/ep.sock.
func cloned(t *testing.T, k knobs) (*Backend, string, string, backend.Fiber) {
	t.Helper()
	b, cfg, w, workDir := warmed(t, k)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f, err := b.Clone(ctx, w.ID, backend.FiberSpec{Fence: "g/1-1", Endpoint: filepath.Join(workDir, "ep.sock"), CgroupFD: -1, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	return b, cfg, workDir, f
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
		ok := true
		for _, p := range parts {
			if !strings.Contains(c, p) {
				ok = false
			}
		}
		if ok {
			return c
		}
	}
	return ""
}

// TestNew checks that the tier is FIBER_SNAPSHOT only with a runsc that
// answers and a rootfs directory, the version is read from runsc, and the
// defaults fill in. The facts the backend states about itself do not depend
// on either.
func TestNew(t *testing.T) {
	bin, _ := fakeRunscBin(t, knobs{})
	rootfs := t.TempDir()
	cases := []struct {
		name        string
		opt         func(t *testing.T) Options
		wantTier    core.Tier
		wantVersion string
		wantRunsc   string
		wantState   string
		wantWhy     string // in ProbeErr, "" for none
	}{
		{name: "runsc and rootfs", opt: func(*testing.T) Options { return Options{Runsc: bin, Rootfs: rootfs, StateDir: "/s"} },
			wantTier: core.TierSnapshot, wantVersion: fakeVersion, wantRunsc: bin, wantState: "/s"},
		{name: "runsc missing", opt: func(t *testing.T) Options {
			return Options{Runsc: filepath.Join(t.TempDir(), "none"), Rootfs: rootfs, StateDir: "/s"}
		}, wantRunsc: "NONE", wantState: "/s", wantWhy: "unavailable"},
		{name: "rootfs missing", opt: func(t *testing.T) Options {
			return Options{Runsc: bin, Rootfs: filepath.Join(t.TempDir(), "none"), StateDir: "/s"}
		}, wantVersion: fakeVersion, wantRunsc: bin, wantState: "/s", wantWhy: "rootfs unusable"},
		{name: "rootfs is a file", opt: func(t *testing.T) Options {
			f := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(f, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return Options{Runsc: bin, Rootfs: f, StateDir: "/s"}
		}, wantVersion: fakeVersion, wantRunsc: bin, wantState: "/s", wantWhy: "is not a directory"},
		{name: "defaults", opt: func(t *testing.T) Options { return Options{Rootfs: filepath.Join(t.TempDir(), "none")} },
			wantRunsc: "runsc", wantState: "/var/lib/fiberd/gvisor", wantVersion: "ANY", wantWhy: "ANY"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opt := tc.opt(t)
			b := New(opt).(*Backend)
			t.Cleanup(b.Close)
			if b.Tier() != tc.wantTier {
				t.Fatalf("Tier = %s, want %s", b.Tier(), tc.wantTier)
			}
			why := b.ProbeErr()
			switch {
			case tc.wantWhy == "ANY":
			case tc.wantWhy == "" && why != nil:
				t.Fatalf("ProbeErr = %v, want nil", why)
			case tc.wantWhy != "" && (why == nil || !strings.Contains(why.Error(), tc.wantWhy)):
				t.Fatalf("ProbeErr = %v, want one mentioning %q", why, tc.wantWhy)
			}
			if tc.wantVersion != "ANY" && b.version != tc.wantVersion {
				t.Fatalf("version = %q, want %q", b.version, tc.wantVersion)
			}
			if tc.wantRunsc != "NONE" && b.opt.Runsc != tc.wantRunsc {
				t.Fatalf("Runsc = %q, want %q", b.opt.Runsc, tc.wantRunsc)
			}
			if b.opt.StateDir != tc.wantState {
				t.Fatalf("StateDir = %q, want %q", b.opt.StateDir, tc.wantState)
			}
			p := b.Platform()
			if p.Kernel != "gvisor-"+b.version || p.Libc != "rootfs-"+filepath.Base(opt.Rootfs) {
				t.Fatalf("Platform = %+v", p)
			}
			c, r := b.DefaultDeadlines()
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
		{name: "a long tail is cut", knobs: knobs{Fail: map[string]bool{"state": true}, LongOutput: true}, args: []string{"state", "x"},
			wantText: "exit status 1: ..." + tail400(strings.Repeat("x", 600)+"fake runsc: state failed")},
		{name: "detached output through a file", args: []string{"state", "--detach", "x"}, wantText: `container "x" does not exist`, wantOut: `container "x" does not exist`},
		{name: "detached without a state directory", stateDir: "missing", args: []string{"state", "--detach", "x"}, wantErr: os.ErrNotExist},
		{name: "deadline ends the command", knobs: knobs{SlowRestore: 3 * time.Second}, timeout: 500 * time.Millisecond,
			args: []string{"restore", "--detach", "--image-path", "IMG", "--bundle", "B", "x"}, wantErr: context.DeadlineExceeded, wantText: "runsc restore"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := newFake(t, tc.knobs)
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
			if tc.args[0] != "--version" {
				calls := runscCalls(t, filepath.Dir(b.opt.Runsc))
				want := "--root=" + filepath.Join(b.opt.StateDir, "root") + " --platform=systrap --network=none --ignore-cgroups --host-uds=all --overlay2=none --app-huge-pages=false " + strings.Join(args, " ")
				got := findCall(calls, want)
				if tc.stateDir == "missing" {
					want, got = "", findCall(calls, strings.Join(tc.args, " ")) // never ran
				}
				if got != want {
					t.Fatalf("runsc was invoked as %q, want %q", got, want)
				}
			}
		})
	}
}

// tail400 is the last 400 bytes of s, as a runsc error keeps them.
func tail400(s string) string { return s[len(s)-400:] }

// TestWriteBundle checks the OCI spec every sandbox is created or restored
// with. The run directory is /host, and the self-checkpoint annotations
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
		{name: "fiber bundle", env: []string{"FIBERD_FENCE=g/1-1", "FIBERD_ENDPOINT=/host/ep.sock"}},
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
			err := b.writeBundle(dir, []string{"/bin/refzygote", "--gvisor"}, tc.env, "/run/g", tc.images, tc.template)
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
			var mounts []string
			for _, m := range s.Mounts {
				mounts = append(mounts, m.Destination+":"+m.Type+":"+m.Source+":"+strings.Join(m.Options, ","))
			}
			wantMounts := "/proc:proc:proc: /dev:tmpfs:tmpfs: /tmp:tmpfs:tmpfs: /host:bind:/run/g:rbind,rw"
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
			if err := os.MkdirAll(b.opt.StateDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(b.opt.StateDir, "templates"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, wantText: "not a directory"},
		{name: "run fails", argv: []string{"/bin/refzygote"}, tier: core.TierSnapshot, knobs: knobs{Fail: map[string]bool{"run": true}}, wantText: "runsc run: exit status 1: fake runsc: run failed"},
		{name: "template never ready", argv: []string{"/bin/refzygote"}, tier: core.TierSnapshot, knobs: knobs{NoMarker: true}, timeout: time.Second,
			started: true, wantErr: context.DeadlineExceeded, wantText: "template did not become ready"},
		{name: "template checkpoint fails", argv: []string{"/bin/refzygote"}, tier: core.TierSnapshot, knobs: knobs{Fail: map[string]bool{"checkpoint": true}},
			started: true, wantText: "template checkpoint: gvisor: runsc checkpoint"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, cfg := newFake(t, tc.knobs)
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
				if tc.started {
					// Started, so it must have been ended by a delete after
					// the run.
					calls := runscCalls(t, cfg)
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
				started := lastField(findCall(runscCalls(t, cfg), "run --detach"))
				waitFor(t, "the template sandbox to be gone", func() bool { return !sandboxAlive(cfg, started) })
				return
			}
			if err != nil {
				t.Fatalf("Warm: %v", err)
			}
			wc := warmCID(t, b, "g")
			st, serr := readState(cfg, wc)
			if serr != nil || w.ID != "g" || w.PID != st.PID || w.Bytes != 0 || w.TotalBytes != 0 {
				t.Fatalf("Warm = %+v, want id g and the sandbox pid %d (%v)", w, st.PID, serr)
			}
			tdir := filepath.Join(b.opt.StateDir, "templates", "g")
			if _, err := os.Stat(filepath.Join(tdir, "images", imageFile)); err != nil {
				t.Fatalf("template image not written: %v", err)
			}
			// The reaper's wait starts in the background.
			waitFor(t, "the reaper's wait", func() bool { return findCall(runscCalls(t, cfg), "wait "+wc) != "" })
			calls := runscCalls(t, cfg)
			for _, want := range []string{
				"run --detach --bundle " + filepath.Join(tdir, "bundle") + " " + wc,
				"checkpoint --leave-running --image-path " + filepath.Join(tdir, "images") + " --direct " + wc,
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
			waitFor(t, "the template sandbox to be gone", func() bool { return !sandboxAlive(cfg, wc) })
			// The reaper cleans up after it and says nothing, since the
			// instance is already unregistered. An end the host asked for
			// through Unwarm is not news to it.
			waitFor(t, "the reaper's delete", func() bool {
				return len(runscCalls(t, cfg)) > 0 && strings.HasSuffix(runscCalls(t, cfg)[len(runscCalls(t, cfg))-1], "delete -force "+wc)
			})
			select {
			case e := <-b.Exits():
				t.Fatalf("unexpected exit %+v after Unwarm", e)
			case <-time.After(100 * time.Millisecond):
			}
			b.mu.Lock()
			n := len(b.warms)
			b.mu.Unlock()
			if n != 0 {
				t.Fatalf("%d templates registered after Unwarm", n)
			}
			// The grant can be warmed again, as the host does once the
			// template is gone. The new incarnation has a cid of its own.
			w2, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "g", Template: backend.Template{Argv: tc.argv}, CgroupFD: -1, ProbeCgroupFD: -1, WorkDir: workDir})
			if err != nil {
				t.Fatalf("second Warm: %v", err)
			}
			if wc2 := warmCID(t, b, "g"); w2.PID == w.PID || wc2 == wc || !sandboxAlive(cfg, wc2) {
				t.Fatalf("second Warm = %+v cid %s, want a new live sandbox with a cid other than %s", w2, wc2, wc)
			}
			select {
			case e := <-b.Exits():
				t.Fatalf("unexpected exit %+v", e)
			case <-time.After(100 * time.Millisecond):
			}
		})
	}
}

// cgroupLeaf makes a cgroup under the delegated root and opens it, or
// skips. The cleanup waits for the leaf to empty and removes it.
func cgroupLeaf(t *testing.T) int {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	root := os.Getenv("FIBERD_CGROUP_ROOT")
	if root == "" {
		root = "/sys/fs/cgroup/fiberd"
	}
	if f, err := os.OpenFile(filepath.Join(root, "cgroup.subtree_control"), os.O_WRONLY, 0); err != nil {
		t.Skipf("no delegated cgroup at %s", root)
	} else {
		_ = f.Close()
	}
	dir := filepath.Join(root, fmt.Sprintf("gvisor-unit-%d-%d", os.Getpid(), time.Now().UnixNano()))
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Close(fd)
		waitFor(t, "the emptied leaf to be removable", func() bool { return os.Remove(dir) == nil })
	})
	return fd
}

// TestProbeFootprint checks that the template image is restored once into the
// probe cgroup as a fiber would be, measured serving, and ended, leaving
// nothing in the leaf or the run directory. A probe that cannot restore or
// serve measures nothing.
func TestProbeFootprint(t *testing.T) {
	cases := []struct {
		name     string
		knobs    knobs
		noCgroup bool
		wantLog  string
	}{
		{name: "measured serving in the leaf"},
		{name: "no probe cgroup", noCgroup: true},
		{name: "restore fails", knobs: knobs{Fail: map[string]bool{"restore": true}}, wantLog: "footprint probe: gvisor: runsc restore"},
		{name: "never serves", knobs: knobs{NoServe: true}, wantLog: "footprint probe did not serve: context deadline exceeded"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fd := -1
			if !tc.noCgroup {
				fd = cgroupLeaf(t)
			}
			var logs bytes.Buffer
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(os.Stderr) })
			b, cfg := newFake(t, tc.knobs)
			workDir := filepath.Join(t.TempDir(), "g")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			w, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "g", Template: backend.Template{Argv: []string{"/bin/refzygote"}}, CgroupFD: -1, ProbeCgroupFD: fd, WorkDir: workDir})
			if err != nil {
				t.Fatalf("Warm: %v", err)
			}
			if tc.noCgroup || tc.wantLog != "" {
				if w.Bytes != 0 || w.TotalBytes != 0 {
					t.Fatalf("Warm measured %d/%d bytes, want nothing", w.Bytes, w.TotalBytes)
				}
			} else if w.TotalBytes == 0 || w.Bytes > w.TotalBytes {
				t.Fatalf("Warm measured shmem %d of %d bytes, want a footprint", w.Bytes, w.TotalBytes)
			}
			if tc.wantLog != "" && !strings.Contains(logs.String(), tc.wantLog) {
				t.Fatalf("log = %q, want %q", logs.String(), tc.wantLog)
			}
			calls := runscCalls(t, cfg)
			if tc.noCgroup {
				if findCall(calls, "-probe") != "" {
					t.Fatal("a probe ran without a probe cgroup")
				}
				return
			}
			tdir := filepath.Join(b.opt.StateDir, "templates", "g")
			probe := warmCID(t, b, "g") + "-probe"
			if findCall(calls, "restore --detach --image-path "+filepath.Join(tdir, "images")+" --bundle "+filepath.Join(tdir, "probe-bundle")+" --direct "+probe) == "" {
				t.Fatalf("no probe restore among\n%s", strings.Join(calls, "\n"))
			}
			for _, want := range []string{"kill " + probe + " KILL", "wait " + probe, "delete -force " + probe} {
				if findCall(calls, want) == "" {
					t.Fatalf("no %q among\n%s", want, strings.Join(calls, "\n"))
				}
			}
			if sandboxAlive(cfg, probe) {
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

// TestProbeWithoutABundle checks that a probe whose bundle cannot be written
// measures nothing and runs nothing.
func TestProbeWithoutABundle(t *testing.T) {
	cases := []struct {
		name string
	}{{name: "template directory is a file"}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, cfg := newFake(t, knobs{})
			tdir := filepath.Join(t.TempDir(), "tdir")
			if err := os.WriteFile(tdir, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			w := &warm{id: "g", cid: "w-g", argv: []string{"/bin/refzygote"}, workDir: t.TempDir(), images: filepath.Join(tdir, "images")}
			shmem, total := b.probeFootprint(context.Background(), w, cgroupFiles(t, nil))
			if shmem != 0 || total != 0 {
				t.Fatalf("probeFootprint = %d/%d, want nothing", shmem, total)
			}
			if c := findCall(runscCalls(t, cfg), "w-g-probe"); c != "" {
				t.Fatalf("runsc ran for a probe without a bundle: %s", c)
			}
		})
	}
}

// TestClone checks that a fiber is a sandbox restored from the template image
// with the fence, endpoint and payload in its environment, serving before
// Clone returns, and its end is reported with runsc's status.
func TestClone(t *testing.T) {
	cases := []struct {
		name       string
		knobs      knobs
		payload    []byte
		wantStatus string
	}{
		{name: "exit 0", wantStatus: "exit:0"},
		{name: "payload and a signal", payload: []byte{1, 2, 3}, knobs: knobs{ExitStatus: 137}, wantStatus: "signal:9"},
		{name: "wait says nothing readable", knobs: knobs{BadWaitJSON: true}, wantStatus: "exit:?"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, cfg, w, workDir := warmed(t, tc.knobs)
			ep := filepath.Join(workDir, "ep.sock")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			f, err := b.Clone(ctx, w.ID, backend.FiberSpec{Fence: "g/1-1", Endpoint: ep, CgroupFD: -1, Deadline: 2 * time.Second, Payload: tc.payload})
			if err != nil {
				t.Fatalf("Clone: %v", err)
			}
			fc := boxCID(t, b, "g/1-1")
			st, serr := readState(cfg, fc)
			if serr != nil || f.ID != "g/1-1" || f.PID != st.PID {
				t.Fatalf("Clone = %+v, want g/1-1 with the sandbox pid %d (%v)", f, st.PID, serr)
			}
			if !dialable(ep) {
				t.Fatalf("%s does not accept connections", ep)
			}
			bundle := b.bundleDir(fc)
			cfgJSON, err := os.ReadFile(filepath.Join(bundle, "config.json"))
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`"FIBERD_FENCE=g/1-1"`, `"FIBERD_ENDPOINT=/host/ep.sock"`} {
				if !strings.Contains(string(cfgJSON), want) {
					t.Fatalf("bundle lacks %s:\n%s", want, cfgJSON)
				}
			}
			if strings.Contains(string(cfgJSON), "FIBERD_PAYLOAD=010203") != (len(tc.payload) > 0) {
				t.Fatalf("bundle payload: %s", cfgJSON)
			}
			tdir := filepath.Join(b.opt.StateDir, "templates", "g")
			calls := runscCalls(t, cfg)
			if findCall(calls, "restore --detach --image-path "+filepath.Join(tdir, "images")+" --bundle "+bundle+" --direct "+fc) == "" {
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
// sandbox it ends when the fiber never serves.
func TestCloneRefusals(t *testing.T) {
	cases := []struct {
		name     string
		knobs    knobs
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
		// Deadlines here are wide enough that a loaded runner's fork and
		// exec of the fake runsc do not fire them first.
		{name: "never serves", endpoint: "ep.sock", knobs: knobs{NoServe: true}, deadline: time.Second, wantErr: context.DeadlineExceeded, wantText: "g/1-1 did not serve", wantKill: true},
		{name: "restore misses the deadline", endpoint: "ep.sock", knobs: knobs{SlowRestore: 3 * time.Second}, deadline: 500 * time.Millisecond, wantErr: context.DeadlineExceeded, wantText: "runsc restore"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, cfg, w, workDir := warmed(t, tc.knobs)
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
			_, err := b.Clone(ctx, warmID, backend.FiberSpec{Fence: "g/1-1", Endpoint: ep, CgroupFD: -1, Deadline: tc.deadline})
			if err == nil || (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) || !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("Clone = %v, want %q (errors.Is %v)", err, tc.wantText, tc.wantErr)
			}
			if tc.wantKill {
				fc := boxCID(t, b, "g/1-1")
				if findCall(runscCalls(t, cfg), "kill "+fc+" KILL") == "" {
					t.Fatal("a fiber that never served was not killed")
				}
				waitFor(t, "the sandbox to be gone", func() bool { return !sandboxAlive(cfg, fc) })
			}
		})
	}
}

// TestBundleOutsideRunDir pins that a fiber's bundle is written under
// the state directory, never under the grant's run directory. Every
// sandbox of the grant has that directory as /host, read and write, so
// a bundle there could be rewritten by a sibling before runsc read it,
// and a name there may be a link a sandbox planted for the agent to
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
			if _, err := b.Clone(ctx, w.ID, backend.FiberSpec{Fence: "g/1-1", Endpoint: ep, CgroupFD: -1, Deadline: 2 * time.Second}); err != nil {
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
				t.Fatalf("the agent wrote through the planted link: %v", ents)
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
// endpoint.
func TestParkAndResume(t *testing.T) {
	cases := []struct {
		name  string
		knobs knobs
	}{
		{name: "park, then resume under a new fence"},
		// The reaper removes the bundle as soon as the sandbox is gone,
		// which is before a real checkpoint returns. The bundle must be
		// beside the image all the same.
		{name: "checkpoint outlasts the reaper's cleanup", knobs: knobs{SlowCheckpt: 300 * time.Millisecond}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, cfg, workDir, _ := cloned(t, tc.knobs)
			fc := boxCID(t, b, "g/1-1")
			dir := filepath.Join(t.TempDir(), "park")
			if err := b.Park(context.Background(), "g/1-1", backend.ParkSpec{Dir: dir}); err != nil {
				t.Fatalf("Park: %v", err)
			}
			if _, err := os.Stat(b.bundleDir(fc)); err == nil {
				waitFor(t, "the reaper to remove the bundle", func() bool {
					_, err := os.Stat(b.bundleDir(fc))
					return err != nil
				})
			}
			calls := runscCalls(t, cfg)
			for _, want := range []string{"kill " + fc + " USR1", "checkpoint --image-path " + dir + " --direct " + fc} {
				if findCall(calls, want) == "" {
					t.Fatalf("no %q among\n%s", want, strings.Join(calls, "\n"))
				}
			}
			if c := findCall(calls, "checkpoint", "--direct "+fc); strings.Contains(c, "--leave-running") {
				t.Fatalf("a park left the sandbox running: %s", c)
			}
			for _, f := range []string{imageFile, "config.json"} {
				if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
					t.Fatalf("%s not in the park image: %v", f, err)
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
			f, err := b.Resume(ctx, backend.ResumeSpec{Dir: dir, Fence: "g/2-1", Endpoint: ep, CgroupFD: -1, Deadline: 2 * time.Second, WarmID: "g", WorkDir: workDir})
			if err != nil {
				t.Fatalf("Resume: %v", err)
			}
			fc2 := boxCID(t, b, "g/2-1")
			st, serr := readState(cfg, fc2)
			if serr != nil || f.ID != "g/2-1" || f.PID != st.PID || !dialable(ep) {
				t.Fatalf("Resume = %+v (%v), want g/2-1 serving on %s", f, serr, ep)
			}
			if findCall(runscCalls(t, cfg), "restore --detach --image-path "+dir+" --bundle "+b.bundleDir(fc2)+" --direct "+fc2) == "" {
				t.Fatal("the resume did not restore the park image")
			}
			cfgJSON, err := os.ReadFile(filepath.Join(b.bundleDir(fc2), "config.json"))
			if err != nil || !strings.Contains(string(cfgJSON), `"/bin/refzygote"`) || !strings.Contains(string(cfgJSON), `"FIBERD_FENCE=g/2-1"`) {
				t.Fatalf("resumed bundle = %s (%v)", cfgJSON, err)
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
// fails.
func TestParkRefusals(t *testing.T) {
	cases := []struct {
		name     string
		before   knobs // the fiber is born with these
		after    knobs // set once it is up
		fiber    string
		noBundle bool // the fiber's bundle is gone
		wantErr  error
		wantText string
	}{
		{name: "unknown fiber", fiber: "nobody", wantText: `unknown fiber "nobody"`},
		{name: "bundle gone", fiber: "g/1-1", noBundle: true, wantText: "config.json: no such file"},
		{name: "workload cannot be signalled", fiber: "g/1-1", after: knobs{Fail: map[string]bool{"kill": true}}, wantText: "runsc kill"},
		{name: "endpoint stays open", fiber: "g/1-1", before: knobs{IgnoreUSR1: true}, wantErr: context.DeadlineExceeded, wantText: "did not close its endpoint for the checkpoint"},
		{name: "checkpoint fails", fiber: "g/1-1", after: knobs{Fail: map[string]bool{"checkpoint": true}}, wantText: "runsc checkpoint"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, cfg, _, _ := cloned(t, tc.before)
			fc := boxCID(t, b, "g/1-1")
			setKnobs(t, cfg, tc.after)
			t.Cleanup(func() { setKnobs(t, cfg, knobs{}) })
			if tc.noBundle {
				if err := os.RemoveAll(b.bundleDir(fc)); err != nil {
					t.Fatal(err)
				}
			}
			err := b.Park(context.Background(), tc.fiber, backend.ParkSpec{Dir: filepath.Join(t.TempDir(), "park")})
			if err == nil || (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) || !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("Park = %v, want %q (errors.Is %v)", err, tc.wantText, tc.wantErr)
			}
			if !sandboxAlive(cfg, fc) {
				t.Fatal("a refused park ended the fiber")
			}
		})
	}
}

// TestResumeRefusals checks that a park image without its bundle, or with one
// that cannot be read, is not resumed.
func TestResumeRefusals(t *testing.T) {
	cases := []struct {
		name     string
		config   string // "" for none
		wantText string
	}{
		{name: "no bundle beside the image", wantText: "park image without its bundle"},
		{name: "unreadable bundle", config: "{nonsense", wantText: "invalid character"},
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
			_, err := b.Resume(context.Background(), backend.ResumeSpec{Dir: dir, Fence: "g/2-1", Endpoint: filepath.Join(t.TempDir(), "ep.sock"), CgroupFD: -1})
			if err == nil || !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("Resume = %v, want %q", err, tc.wantText)
			}
		})
	}
}

// TestClose checks that closing kills the template and every fiber, and each is
// reported gone.
func TestClose(t *testing.T) {
	cases := []struct {
		name string
	}{{name: "template and fiber"}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, cfg, _, _ := cloned(t, knobs{})
			cids := []string{warmCID(t, b, "g"), boxCID(t, b, "g/1-1")}
			b.Close()
			got := map[backend.Exit]bool{}
			for i := 0; i < 2; i++ {
				got[waitExit(t, b)] = true
			}
			want := map[backend.Exit]bool{{WarmID: "g", Status: "template sandbox exited"}: true, {FiberID: "g/1-1", Status: "exit:0"}: true}
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("exits = %v, want %v", got, want)
			}
			for _, cid := range cids {
				waitFor(t, cid+" to be gone", func() bool { return !sandboxAlive(cfg, cid) })
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
		want  func(cfg, wc string) int
	}{
		{name: "running sandbox", cid: "WARM", want: func(cfg, wc string) int { st, _ := readState(cfg, wc); return st.PID }},
		{name: "unknown sandbox", cid: "nobody", want: func(string, string) int { return 0 }},
		{name: "state fails", cid: "WARM", knobs: knobs{Fail: map[string]bool{"state": true}}, want: func(string, string) int { return 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, cfg, _, _ := warmed(t, knobs{})
			wc := warmCID(t, b, "g")
			setKnobs(t, cfg, tc.knobs)
			t.Cleanup(func() { setKnobs(t, cfg, knobs{}) })
			want := tc.want(cfg, wc)
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
			bin, cfg := fakeRunscBin(t, tc.knobs)
			t.Cleanup(func() { endAllSandboxes(t, cfg) })
			// A sandbox of a previous life, started outside any backend.
			old := &Backend{opt: Options{Rootfs: "/rootfs"}}
			bundle := filepath.Join(t.TempDir(), "bundle")
			if err := old.writeBundle(bundle, []string{"/bin/refzygote"}, []string{"FIBERD_FENCE=none"}, t.TempDir(), "", ""); err != nil {
				t.Fatal(err)
			}
			if code := startSandbox(cfg, "w-old-7", bundle); code != 0 || !sandboxAlive(cfg, "w-old-7") {
				t.Fatalf("the leftover sandbox did not start (%d)", code)
			}
			b := New(Options{Runsc: bin, Rootfs: t.TempDir(), StateDir: filepath.Join(t.TempDir(), "state")}).(*Backend)
			t.Cleanup(b.Close)
			if tc.wantGone {
				waitFor(t, "the leftover to be gone", func() bool { return !sandboxAlive(cfg, "w-old-7") })
				if findCall(runscCalls(t, cfg), "delete -force w-old-7") == "" {
					t.Fatal("the leftover was not deleted through runsc")
				}
				return
			}
			if !sandboxAlive(cfg, "w-old-7") || findCall(runscCalls(t, cfg), "delete") != "" {
				t.Fatal("something was deleted without a listing")
			}
		})
	}
}

// TestCIDReuse checks that a reaper's late delete cannot touch a successor
// under the same grant or fence. The reaper deletes after `runsc wait`
// returns, which can be long after the host warmed or cloned again. The
// successor has a cid of its own. The gate holds the delete until the
// successor is up.
func TestCIDReuse(t *testing.T) {
	cases := []struct {
		name string
		// first starts the sandbox and returns its cid. again ends it and
		// starts its successor, returning the successor's cid and bundle
		// ("" when there is none).
		first func(t *testing.T, b *Backend, workDir string) string
		again func(t *testing.T, b *Backend, cfg, workDir string) (string, string)
		// settle ends the successor and waits for its reaper, so nothing
		// still writes into the test's directories when they go.
		settle func(t *testing.T, b *Backend, cfg, second string)
	}{
		{name: "template warmed again after Unwarm",
			first: func(t *testing.T, b *Backend, _ string) string { return warmCID(t, b, "g") },
			again: func(t *testing.T, b *Backend, cfg, workDir string) (string, string) {
				b.Unwarm("g")
				waitFor(t, "the reaper's delete to be held", func() bool { _, err := os.Stat(filepath.Join(cfg, gateClaimed)); return err == nil })
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if _, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "g", Template: backend.Template{Argv: []string{"/bin/refzygote", "--gvisor"}}, CgroupFD: -1, ProbeCgroupFD: -1, WorkDir: workDir}); err != nil {
					t.Fatalf("second Warm: %v", err)
				}
				return warmCID(t, b, "g"), ""
			},
			settle: func(t *testing.T, b *Backend, cfg, second string) {
				b.Unwarm("g")
				waitFor(t, "the successor's reaper", func() bool { return findCall(runscCalls(t, cfg), "delete -force "+second) != "" })
			}},
		{name: "fiber cloned again under its fence after Kill",
			first: func(t *testing.T, b *Backend, workDir string) string {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if _, err := b.Clone(ctx, "g", backend.FiberSpec{Fence: "g/1-1", Endpoint: filepath.Join(workDir, "ep.sock"), CgroupFD: -1, Deadline: 2 * time.Second}); err != nil {
					t.Fatalf("Clone: %v", err)
				}
				return boxCID(t, b, "g/1-1")
			},
			again: func(t *testing.T, b *Backend, cfg, workDir string) (string, string) {
				if err := b.Kill("g/1-1"); err != nil {
					t.Fatalf("Kill: %v", err)
				}
				waitFor(t, "the reaper's delete to be held", func() bool { _, err := os.Stat(filepath.Join(cfg, gateClaimed)); return err == nil })
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if _, err := b.Clone(ctx, "g", backend.FiberSpec{Fence: "g/1-1", Endpoint: filepath.Join(workDir, "ep.sock"), CgroupFD: -1, Deadline: 2 * time.Second}); err != nil {
					t.Fatalf("second Clone: %v", err)
				}
				cid := boxCID(t, b, "g/1-1")
				return cid, b.bundleDir(cid)
			},
			settle: func(t *testing.T, b *Backend, _, _ string) {
				if err := b.Kill("g/1-1"); err != nil {
					t.Fatalf("Kill: %v", err)
				}
				waitExit(t, b)
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, cfg, _, workDir := warmed(t, knobs{})
			first := tc.first(t, b, workDir)
			setKnobs(t, cfg, knobs{GateDelete: true})
			second, bundle := tc.again(t, b, cfg, workDir)
			if !sandboxAlive(cfg, second) {
				t.Fatalf("the successor %s is not running", second)
			}
			// The old reaper's delete lands here.
			if err := os.WriteFile(filepath.Join(cfg, gateOpen), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			waitFor(t, "the held delete to run", func() bool { _, err := os.Stat(filepath.Join(cfg, gatePassed)); return err == nil })
			if !sandboxAlive(cfg, second) {
				t.Fatalf("the late delete of %s ended its successor %s", first, second)
			}
			if bundle != "" {
				if _, err := os.Stat(filepath.Join(bundle, "config.json")); err != nil {
					t.Fatalf("the late reaper removed the successor's bundle: %v", err)
				}
			}
			if second == first {
				t.Fatalf("the successor reuses cid %s", first)
			}
			tc.settle(t, b, cfg, second)
		})
	}
}
