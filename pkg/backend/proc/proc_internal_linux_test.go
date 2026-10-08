//go:build linux

package proc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
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
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/sys/criu"
)

// criuKnobs script the fake criu. They set what `check` and `dump` exit
// with, and how `restore` behaves. "yes" writes the pid file and waits for
// the release file, "no" fails at once, and "hang" never writes one.
type criuKnobs struct {
	checkExit   int
	dumpExit    int
	restore     string
	restoreExit int
}

// fakeCRIU writes a criu that records every invocation to <dir>/criu.log
// and behaves as the knobs say. The restore it starts stays alive, as the
// restored tree's parent would, until <dir>/release exists.
func fakeCRIU(t *testing.T, k criuKnobs) (bin, dir string) {
	t.Helper()
	dir = t.TempDir()
	if k.restore == "" {
		k.restore = "yes"
	}
	script := fmt.Sprintf(`#!/bin/sh
echo "$@" >> %[1]q
case "$1" in
check) exit %[2]d ;;
dump) exit %[3]d ;;
restore)
  pidfile=""; prev=""
  for a in "$@"; do if [ "$prev" = "--pidfile" ]; then pidfile=$a; fi; prev=$a; done
  case %[4]q in
  no) exit 1 ;;
  hang) while :; do sleep 0.01; done ;;
  esac
  echo $$ > "$pidfile"
  while [ ! -e %[5]q ]; do sleep 0.01; done
  exit %[6]d ;;
esac
exit 0
`, filepath.Join(dir, "criu.log"), k.checkExit, k.dumpExit, k.restore, filepath.Join(dir, "release"), k.restoreExit)
	bin = filepath.Join(dir, "criu")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, dir
}

// criuCalls is every recorded criu invocation, one per line.
func criuCalls(t *testing.T, dir string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "criu.log"))
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

// release lets the fake criu's restore end.
func release(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "release"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
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

// recvLines is what the fake zygote in workDir has read so far.
func recvLines(workDir string) []string {
	b, err := os.ReadFile(filepath.Join(workDir, recvLog))
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

// waitRecv waits until the fake zygote has read a line containing want
// and returns everything it read.
func waitRecv(t *testing.T, workDir, want string) []string {
	t.Helper()
	var lines []string
	waitFor(t, "the zygote to read "+want, func() bool {
		lines = recvLines(workDir)
		for _, l := range lines {
			if strings.Contains(l, want) {
				return true
			}
		}
		return false
	})
	return lines
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

// noExit asserts nothing is reported within a short while.
func noExit(t *testing.T, b *Backend) {
	t.Helper()
	select {
	case e := <-b.Exits():
		t.Fatalf("unexpected exit %+v", e)
	case <-time.After(100 * time.Millisecond):
	}
}

// fakeArgv is the test binary as a scripted zygote.
func fakeArgv(t *testing.T, script string, pid int) []string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return []string{exe, fakeZygoteArg, script, strconv.Itoa(pid)}
}

// hold starts the test binary doing nothing, with the clone flags and
// extra files given, and ends it when the test does.
func hold(t *testing.T, flags uintptr, extra ...*os.File) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, holdArg)
	cmd.ExtraFiles = extra
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if flags != 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: flags}
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd
}

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root (namespaces, mounts)")
	}
}

// cgroupLeaf makes a cgroup under the delegated root and opens it. It
// skips where there is none. The cleanup waits for the leaf to empty,
// then removes it.
func cgroupLeaf(t *testing.T) int {
	t.Helper()
	root := os.Getenv("FIBERD_CGROUP_ROOT")
	if root == "" {
		root = "/sys/fs/cgroup/fiberd"
	}
	if f, err := os.OpenFile(filepath.Join(root, "cgroup.subtree_control"), os.O_WRONLY, 0); err != nil {
		t.Skipf("no delegated cgroup at %s", root)
	} else {
		_ = f.Close()
	}
	dir := filepath.Join(root, fmt.Sprintf("proc-unit-%d-%d", os.Getpid(), time.Now().UnixNano()))
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Close(fd)
		// A killed process leaves the leaf populated until its last
		// thread is gone, a moment after cgroup.procs stops listing it.
		waitFor(t, "the emptied leaf to be removable", func() bool { return os.Remove(dir) == nil })
	})
	return fd
}

// fakeLauncher starts the scripted zygote the way a launcher would and
// records what the backend tells it.
type fakeLauncher struct {
	commandErr, channelErr, pidErr, restoreExtraErr, restoredErr error
	ownPair                                                      bool // Channel moves the conversation onto a pair of its own
	endpointRoot                                                 string

	mu       sync.Mutex
	calls    []string
	own      *os.File // the host's end of the launcher's own pair
	ownChild *os.File // the zygote's, closed here once it has started
}

func (l *fakeLauncher) record(s string) {
	l.mu.Lock()
	l.calls = append(l.calls, s)
	l.mu.Unlock()
}

func (l *fakeLauncher) recorded() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.calls...)
}

func (l *fakeLauncher) Name() string { return "fake" }

func (l *fakeLauncher) Command(spec backend.WarmSpec, argv []string, ctl, logf *os.File) (*exec.Cmd, error) {
	l.record("command")
	if l.commandErr != nil {
		return nil, l.commandErr
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = spec.WorkDir
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.ExtraFiles = []*os.File{ctl}
	if l.ownPair {
		fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		l.own = os.NewFile(uintptr(fds[0]), "own-ctl")
		l.ownChild = os.NewFile(uintptr(fds[1]), "own-ctl-child")
		cmd.ExtraFiles = []*os.File{l.ownChild}
	}
	return cmd, nil
}

func (l *fakeLauncher) Channel(_ context.Context, _ backend.WarmSpec, _ *exec.Cmd, boot *net.UnixConn) (*net.UnixConn, error) {
	l.record("channel")
	if l.channelErr != nil {
		return nil, l.channelErr
	}
	if !l.ownPair {
		return boot, nil
	}
	_ = l.ownChild.Close() // the started zygote holds its own copy
	c, err := net.FileConn(l.own)
	_ = l.own.Close()
	if err != nil {
		return nil, err
	}
	return c.(*net.UnixConn), nil
}

func (l *fakeLauncher) Socketpair(_ backend.WarmSpec, pid int, typ int) ([2]int, error) {
	l.record("socketpair:" + strconv.Itoa(pid))
	return syscall.Socketpair(syscall.AF_UNIX, typ|syscall.SOCK_CLOEXEC, 0)
}

func (l *fakeLauncher) PID(_ context.Context, _ backend.WarmSpec, cmd *exec.Cmd) (int, error) {
	l.record("pid")
	if l.pidErr != nil {
		return 0, l.pidErr
	}
	return cmd.Process.Pid, nil
}

func (l *fakeLauncher) Restored(_ backend.WarmSpec, pid int) error {
	l.record("restored:" + strconv.Itoa(pid))
	return l.restoredErr
}
func (l *fakeLauncher) RestoredGone(backend.WarmSpec) { l.record("restoredGone") }
func (l *fakeLauncher) Release(backend.WarmSpec)      { l.record("release") }
func (l *fakeLauncher) Endpoint(_ backend.WarmSpec, p string) string {
	return filepath.Join(l.endpointRoot, filepath.Base(p))
}
func (l *fakeLauncher) DumpExtra(backend.WarmSpec, string) ([]string, error) {
	return []string{"--dump-extra"}, nil
}
func (l *fakeLauncher) RestoreExtra(_ backend.WarmSpec, dir string) ([]string, error) {
	l.record("restoreExtra:" + dir)
	if l.restoreExtraErr != nil {
		return nil, l.restoreExtraErr
	}
	return []string{"--restore-extra"}, nil
}

// TestBackendFacts checks what the backend says about itself, with and without
// criu and with a launcher naming it.
func TestBackendFacts(t *testing.T) {
	cases := []struct {
		name      string
		checkExit int
		launcher  Launcher
		wantName  string
		wantTier  core.Tier
	}{
		{name: "criu passes", wantName: "proc", wantTier: core.TierCheckpoint},
		{name: "criu check fails", checkExit: 1, wantName: "proc", wantTier: core.TierWarm},
		{name: "a launcher names the backend", launcher: &fakeLauncher{}, wantName: "fake", wantTier: core.TierCheckpoint},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin, _ := fakeCRIU(t, criuKnobs{checkExit: tc.checkExit})
			b := New(Options{CRIU: bin, Launcher: tc.launcher, RootBind: filepath.Join(t.TempDir(), "root")})
			t.Cleanup(b.Close)
			if b.Name() != tc.wantName || b.Tier() != tc.wantTier {
				t.Fatalf("Name=%s Tier=%s, want %s %s", b.Name(), b.Tier(), tc.wantName, tc.wantTier)
			}
			if got := b.(backend.Handoffer).Handoff(); !got {
				t.Fatal("Handoff() = false, want true")
			}
			if got := strings.Join(b.(*Backend).EndpointSchemes(), ","); got != "unix,tcp" {
				t.Fatalf("EndpointSchemes = %s, want unix,tcp", got)
			}
		})
	}
}

// TestWarmRefusals checks every way Warm fails before the zygote serves.
// Nothing is left registered, and the launcher is released.
func TestWarmRefusals(t *testing.T) {
	cases := []struct {
		name     string
		script   string
		argv     []string // overrides the scripted zygote
		workDir  func(t *testing.T) string
		hide     []string
		timeout  time.Duration
		launcher *fakeLauncher
		wantErr  error
		wantText string
	}{
		{name: "empty command", argv: []string{}, wantText: "empty zygote command"},
		{name: "run directory under a file", script: "never", workDir: func(t *testing.T) string {
			f := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(f, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(f, "g")
		}, wantText: "not a directory"},
		{name: "zygote log is a directory", script: "never", workDir: func(t *testing.T) string {
			d := t.TempDir()
			if err := os.Mkdir(filepath.Join(d, "zygote.log"), 0o755); err != nil {
				t.Fatal(err)
			}
			return d
		}, wantText: "is a directory"},
		{name: "command does not exist", argv: []string{"/nonexistent/zygote"}, wantText: "start zygote"},
		{name: "greets with something other than READY", script: "notready", wantErr: ErrZygote, wantText: `expected READY, got "HELLO"`},
		// The zygote could not build the mount namespace its fibers copy
		// and said so instead of READY. The old backend only knew READY
		// first and the reason after it, so the warm went through and
		// the home reported a template ready that refused every clone.
		{name: "could not prepare its mount namespace", script: "unprepared", wantErr: ErrZygote,
			wantText: "could not prepare the mount namespace its fibers need: the zygote could not cover a HIDE path (/var/lib/fiberd/templates: Permission denied)"},
		{name: "exits before READY", script: "quit", wantText: "did not become ready"},
		{name: "never says READY", script: "silent", timeout: 100 * time.Millisecond, wantErr: context.DeadlineExceeded},
		{name: "a relative hide path", script: "never", hide: []string{"relative/dir"}, wantText: "cannot hide"},
		{name: "a run directory with whitespace", script: "never", workDir: func(t *testing.T) string {
			return filepath.Join(t.TempDir(), "with space", "g")
		}, wantText: "want an absolute path without whitespace"},
		{name: "a hide path with whitespace", script: "never", hide: []string{"/with space"}, wantText: "cannot hide"},
		{name: "launcher cannot build the command", script: "never", launcher: &fakeLauncher{commandErr: errors.New("no rootfs")}, wantText: "no rootfs"},
		{name: "launcher has no channel", script: "never", launcher: &fakeLauncher{channelErr: errors.New("no pair")}, wantText: "control channel for g: no pair"},
		{name: "launcher cannot find the pid", script: "never", launcher: &fakeLauncher{pidErr: errors.New("no init")}, wantText: "no init"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin, _ := fakeCRIU(t, criuKnobs{})
			var launcher Launcher
			if tc.launcher != nil {
				launcher = tc.launcher
			}
			b := NewBackend(Options{CRIU: bin, Launcher: launcher, RootBind: filepath.Join(t.TempDir(), "root")})
			t.Cleanup(b.Close)
			argv := tc.argv
			if argv == nil {
				argv = fakeArgv(t, tc.script, impossiblePID(t))
			}
			workDir := t.TempDir()
			if tc.workDir != nil {
				workDir = tc.workDir(t)
			}
			timeout := 5 * time.Second
			if tc.timeout > 0 {
				timeout = tc.timeout
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			_, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "g", Template: backend.Template{Argv: argv}, CgroupFD: -1, ProbeCgroupFD: -1, WorkDir: workDir, Hide: tc.hide})
			if err == nil {
				t.Fatal("Warm succeeded, want an error")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("Warm = %v, want errors.Is %v", err, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("Warm = %v, want it to mention %q", err, tc.wantText)
			}
			b.mu.Lock()
			n := len(b.zygotes)
			b.mu.Unlock()
			if n != 0 {
				t.Fatalf("%d zygotes registered after a failed warm, want none", n)
			}
			if tc.launcher != nil {
				calls := tc.launcher.recorded()
				if tc.launcher.commandErr == nil && calls[len(calls)-1] != "release" {
					t.Fatalf("launcher calls = %v, want release last", calls)
				}
			}
			// The zygote it killed is reaped too, not left a zombie of
			// this process for every warm that failed.
			waitFor(t, "no zombie children", func() bool { return len(zombieChildren(t)) == 0 })
		})
	}
}

// zombieChildren lists this process's children that have exited and
// not been waited for.
func zombieChildren(t *testing.T) []int {
	t.Helper()
	ents, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	var zombies []int
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		stat, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		// "<pid> (<comm>) <state> <ppid> ...", and comm may hold anything.
		rest := string(stat)
		if i := strings.LastIndex(rest, ")"); i >= 0 {
			rest = rest[i+1:]
		}
		f := strings.Fields(rest)
		if len(f) >= 2 && f[0] == "Z" && f[1] == strconv.Itoa(os.Getpid()) {
			zombies = append(zombies, pid)
		}
	}
	return zombies
}

// TestWarmTellsTheZygoteItsPaths checks that a zygote the backend starts is
// told what to hide and drop and its run directory, in that order, then
// PREPARE mntns, all before it is expected to say READY. A launcher's
// zygote is told only PREPARE none, since its fibers get no mount
// namespace, and the launcher names its pid and may move the
// conversation onto its own channel.
func TestWarmTellsTheZygoteItsPaths(t *testing.T) {
	cases := []struct {
		name     string
		hide     []string
		devices  []string
		launcher *fakeLauncher
	}{
		{name: "hide two paths", hide: []string{"/var/lib/secret", "/etc/keys/"}},
		{name: "nothing to hide"},
		{name: "devices reach the engine's environment", devices: []string{"/dev/nvidia0", "/dev/nvidia1"}},
		{name: "launcher on the boot channel", launcher: &fakeLauncher{}},
		{name: "launcher on its own channel", launcher: &fakeLauncher{ownPair: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin, _ := fakeCRIU(t, criuKnobs{})
			rootBind := filepath.Join(t.TempDir(), "root")
			var launcher Launcher
			if tc.launcher != nil {
				launcher = tc.launcher
			}
			b := NewBackend(Options{CRIU: bin, Launcher: launcher, RootBind: rootBind})
			t.Cleanup(b.Close)
			workDir := filepath.Join(t.TempDir(), "g")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			w, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "g", Template: backend.Template{Argv: fakeArgv(t, "never", impossiblePID(t))}, CgroupFD: -1, ProbeCgroupFD: -1, WorkDir: workDir, Hide: tc.hide, Devices: tc.devices})
			if err != nil {
				t.Fatalf("Warm: %v", err)
			}
			b.mu.Lock()
			z := b.zygotes[w.ID]
			b.mu.Unlock()
			if z == nil || w.ID != "g" || w.PID != z.cmd.Process.Pid || z.pid != w.PID {
				t.Fatalf("Warm = %+v, zygote %+v, want id g and the process pid", w, z)
			}
			if tc.launcher != nil {
				// No paths, since its fibers share the container's
				// namespace, and no CLONE has been sent.
				if got := waitRecv(t, workDir, "PREPARE"); strings.Join(got, "\n") != "PREPARE none" {
					t.Fatalf("a launcher's zygote read %q, want PREPARE none alone", got)
				}
				if calls := tc.launcher.recorded(); strings.Join(calls, ",") != "command,channel,pid" {
					t.Fatalf("launcher calls = %v, want command,channel,pid", calls)
				}
				return
			}
			var want []string
			if len(tc.devices) > 0 {
				want = append(want, "ENV FIBERD_DEVICES="+strings.Join(tc.devices, ","))
			}
			for _, h := range tc.hide {
				want = append(want, "HIDE "+filepath.Clean(h))
			}
			want = append(want, "DROP "+rootBind, "RUNDIR "+filepath.Dir(workDir)+" "+workDir, "PREPARE mntns")
			got := waitRecv(t, workDir, "PREPARE")
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Fatalf("the zygote read\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
		})
	}
}

// TestWarmInCgroup checks that the zygote is born in the cgroup the host
// hands over.
func TestWarmInCgroup(t *testing.T) {
	cases := []struct {
		name string
	}{{name: "zygote lands in the leaf"}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fd := cgroupLeaf(t)
			bin, _ := fakeCRIU(t, criuKnobs{})
			b := NewBackend(Options{CRIU: bin, RootBind: filepath.Join(t.TempDir(), "root")})
			t.Cleanup(b.Close)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			w, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "g", Template: backend.Template{Argv: fakeArgv(t, "never", impossiblePID(t))}, CgroupFD: fd, ProbeCgroupFD: -1, WorkDir: t.TempDir()})
			if err != nil {
				t.Fatalf("Warm: %v", err)
			}
			procs, err := os.ReadFile(fmt.Sprintf("/proc/self/fd/%d/cgroup.procs", fd))
			if err != nil {
				t.Fatal(err)
			}
			if strings.TrimSpace(string(procs)) != strconv.Itoa(w.PID) {
				t.Fatalf("cgroup.procs = %q, want just the zygote %d", procs, w.PID)
			}
		})
	}
}

// warmed is a backend with one scripted zygote up for grant g.
func warmed(t *testing.T, script string, pid int, launcher Launcher) (*Backend, backend.Warm, string) {
	t.Helper()
	bin, _ := fakeCRIU(t, criuKnobs{})
	b := NewBackend(Options{CRIU: bin, Launcher: launcher, RootBind: filepath.Join(t.TempDir(), "root")})
	t.Cleanup(b.Close)
	workDir := filepath.Join(t.TempDir(), "g")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "g", Template: backend.Template{Argv: fakeArgv(t, script, pid)}, CgroupFD: -1, ProbeCgroupFD: -1, WorkDir: workDir})
	if err != nil {
		t.Fatalf("Warm: %v", err)
	}
	return b, w, workDir
}

// TestCloneLine checks that the CLONE line carries the fence, the endpoint as
// the zygote sees it, the deadline in ms, the payload in hex and the
// confinement options, and the cgroup and handoff descriptors ride with it.
func TestCloneLine(t *testing.T) {
	cases := []struct {
		name     string
		spec     backend.FiberSpec
		cgroup   bool // pass a cgroup fd
		handoff  bool
		launcher *fakeLauncher
		wantLine string // after "CLONE g/1-1 ", with EP for the endpoint path
		wantFDs  int
	}{
		{name: "defaults", spec: backend.FiberSpec{}, wantLine: "EP 50 - mntns,nocaps"},
		{name: "deadline, payload and own pid namespace", spec: backend.FiberSpec{Deadline: 1500 * time.Millisecond, Payload: []byte{0xde, 0xad}, OwnPIDNS: true},
			wantLine: "EP 1500 dead pidns,mntns,nocaps"},
		{name: "cgroup and handoff descriptors", spec: backend.FiberSpec{Deadline: time.Second}, cgroup: true, handoff: true,
			wantLine: "EP 1000 - mntns,nocaps,handoff", wantFDs: 2},
		{name: "launcher maps a unix endpoint and keeps capabilities", spec: backend.FiberSpec{Deadline: time.Second, OwnPIDNS: true}, launcher: &fakeLauncher{endpointRoot: "/run/inside"},
			wantLine: "/run/inside/ep.sock 1000 - pidns"},
		{name: "launcher leaves a tcp endpoint alone", spec: backend.FiberSpec{Deadline: time.Second, Endpoint: "tcp://0.0.0.0:9000"}, launcher: &fakeLauncher{endpointRoot: "/run/inside"},
			wantLine: "tcp://0.0.0.0:9000 1000 -"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var launcher Launcher
			if tc.launcher != nil {
				launcher = tc.launcher
			}
			b, w, workDir := warmed(t, "never", impossiblePID(t), launcher)
			spec := tc.spec
			spec.Fence = "g/1-1"
			if spec.Endpoint == "" {
				spec.Endpoint = filepath.Join(workDir, "ep.sock")
			}
			spec.CgroupFD = -1
			if tc.cgroup {
				d, err := os.Open(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = d.Close() }()
				spec.CgroupFD = int(d.Fd())
			}
			if tc.handoff {
				fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				spec.Handoff = os.NewFile(uintptr(fds[0]), "handoff")
				defer func() { _ = spec.Handoff.Close(); _ = syscall.Close(fds[1]) }()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			f, err := b.Clone(ctx, w.ID, spec)
			if err != nil {
				t.Fatalf("Clone: %v", err)
			}
			wantPID := impossiblePID(t)
			if tc.launcher != nil {
				wantPID = 0 // never a host pid without a cgroup to translate it in
			}
			if f.ID != "g/1-1" || f.PID != wantPID {
				t.Fatalf("Clone = %+v, want g/1-1 pid %d", f, wantPID)
			}
			lines := waitRecv(t, workDir, "CLONE ")
			var cloneLine string
			fdsLine := ""
			for i, l := range lines {
				if strings.HasPrefix(l, "CLONE ") {
					cloneLine = strings.TrimRight(l, " ") // no options is an empty last field
					if i+1 < len(lines) && strings.HasPrefix(lines[i+1], "FDS ") {
						fdsLine = lines[i+1]
					}
				}
			}
			want := "CLONE g/1-1 " + strings.Replace(tc.wantLine, "EP", filepath.Join(workDir, "ep.sock"), 1)
			if cloneLine != want {
				t.Fatalf("zygote read %q, want %q", cloneLine, want)
			}
			wantFDs := ""
			if tc.wantFDs > 0 {
				wantFDs = "FDS " + strconv.Itoa(tc.wantFDs)
			}
			if fdsLine != wantFDs {
				t.Fatalf("descriptors with CLONE: %q, want %q", fdsLine, wantFDs)
			}
		})
	}
}

// TestCloneReplies checks that every answer a zygote can give to CLONE, and
// the zygote dying instead, are errors the caller can name. The grant's warm
// instance is reported gone when the zygote is.
func TestCloneReplies(t *testing.T) {
	cases := []struct {
		name     string
		script   string
		wantErr  error
		wantText string
		wantGone bool // an Exit for the warm instance
		wantLog  string
	}{
		{name: "ERROR names the reason", script: "error", wantErr: ErrZygote, wantText: "deadline exceeded before ready"},
		{name: "a refused path is logged, the clone refused", script: "refuse", wantErr: ErrZygote, wantText: "refused: the mount namespace", wantLog: "zygote for g: DROP refused: by the script"},
		{name: "a pid the backend cannot name", script: "malformed", wantErr: ErrZygote, wantText: `malformed "CLONED g/1-1 abc"`},
		{name: "a CLONED without a pid", script: "short", wantErr: ErrZygote, wantText: "malformed"},
		{name: "noise before the answer is tolerated", script: "noise"},
		{name: "the zygote dies", script: "die", wantErr: ErrZygote, wantText: "zygote exited", wantGone: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(os.Stderr) })
			pid := impossiblePID(t)
			b, w, workDir := warmed(t, tc.script, pid, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			f, err := b.Clone(ctx, w.ID, backend.FiberSpec{Fence: "g/1-1", Endpoint: filepath.Join(workDir, "ep.sock"), CgroupFD: -1, Deadline: time.Second})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Clone = %v, want errors.Is %v", err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("Clone = %v, want it to mention %q", err, tc.wantText)
			}
			if err == nil && (f.ID != "g/1-1" || f.PID != pid) {
				t.Fatalf("Clone = %+v, want g/1-1 pid %d", f, pid)
			}
			if tc.wantGone {
				if e := waitExit(t, b); e != (backend.Exit{WarmID: "g", Status: "zygote exited"}) {
					t.Fatalf("exit = %+v, want the warm instance gone", e)
				}
			} else {
				noExit(t, b)
			}
			if tc.wantLog != "" {
				waitFor(t, "the log line", func() bool { return strings.Contains(logs.String(), tc.wantLog) })
			}
			b.mu.Lock()
			nf, z := len(b.fibers), b.zygotes[w.ID]
			b.mu.Unlock()
			npend := 0
			if z != nil {
				z.pmu.Lock()
				npend = len(z.pend)
				z.pmu.Unlock()
			}
			wantFibers := 0
			if err == nil {
				wantFibers = 1
			}
			if nf != wantFibers || npend != 0 {
				t.Fatalf("fibers=%d pending=%d, want %d and 0", nf, npend, wantFibers)
			}
		})
	}
}

// TestCloneWithoutAZygoteToAnswer checks that no warm instance, a control
// channel that cannot be written, and a zygote already gone when the reply is
// awaited are each errors with nothing left pending.
func TestCloneWithoutAZygoteToAnswer(t *testing.T) {
	cases := []struct {
		name     string
		inject   func(t *testing.T, b *Backend) string // registers a zygote, returns its id
		wantErr  error
		wantText string
	}{
		{name: "unknown warm instance", inject: func(*testing.T, *Backend) string { return "nobody" }, wantText: `no warm instance "nobody"`},
		{name: "control channel closed", inject: func(t *testing.T, b *Backend) string {
			c := pairConn(t)
			_ = c.Close()
			b.zygotes["g"] = &zygote{id: "g", ctl: c, pend: map[string]*pending{}, gone: make(chan struct{})}
			return "g"
		}, wantText: "send CLONE"},
		{name: "zygote gone before it answers", inject: func(t *testing.T, b *Backend) string {
			gone := make(chan struct{})
			close(gone)
			b.zygotes["g"] = &zygote{id: "g", ctl: pairConn(t), pend: map[string]*pending{}, gone: gone}
			return "g"
		}, wantErr: ErrZygote, wantText: "zygote exited"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &Backend{zygotes: map[string]*zygote{}, fibers: map[string]*fiber{}, byPID: map[pidKey]*fiber{}}
			id := tc.inject(t, b)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := b.Clone(ctx, id, backend.FiberSpec{Fence: "g/1-1", Endpoint: "/run/g/ep.sock", CgroupFD: -1})
			if err == nil || !strings.Contains(err.Error(), tc.wantText) || (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) {
				t.Fatalf("Clone = %v, want %q (errors.Is %v)", err, tc.wantText, tc.wantErr)
			}
			if z := b.zygotes[id]; z != nil && len(z.pend) != 0 {
				t.Fatalf("%d clones left pending", len(z.pend))
			}
		})
	}
}

// pairConn is one end of a unix stream pair whose other end nobody reads.
func pairConn(t *testing.T) *net.UnixConn {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fds[0]), "pair")
	c, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(); _ = syscall.Close(fds[1]) })
	return c.(*net.UnixConn)
}

// TestDeviceReports checks that an engine's DEVICE lines are the warm
// instance's usage and capacity and each fiber's slice, which EVICT asks it
// to drop. Without an engine there is nothing to report or evict.
func TestDeviceReports(t *testing.T) {
	cases := []struct {
		name   string
		script string
		engine bool
	}{
		{name: "engine reports and evicts", script: "device", engine: true},
		{name: "no engine", script: "never"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pid := impossiblePID(t)
			b, w, workDir := warmed(t, tc.script, pid, nil)
			if _, _, ok := b.WarmDevice("nobody"); ok {
				t.Fatal("WarmDevice of an unknown instance reported something")
			}
			if _, ok := b.FiberDevice("g/9-9"); ok {
				t.Fatal("FiberDevice of an unknown fiber reported something")
			}
			if err := b.EvictDevice("g/9-9"); err == nil || !strings.Contains(err.Error(), "no engine") {
				t.Fatalf("EvictDevice of an unknown fiber = %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := b.Clone(ctx, w.ID, backend.FiberSpec{Fence: "g/1-1", Endpoint: filepath.Join(workDir, "ep.sock"), CgroupFD: -1, Deadline: time.Second}); err != nil {
				t.Fatalf("Clone: %v", err)
			}
			if !tc.engine {
				if _, _, ok := b.WarmDevice(w.ID); ok {
					t.Fatal("WarmDevice reported without an engine")
				}
				if _, ok := b.FiberDevice("g/1-1"); ok {
					t.Fatal("FiberDevice reported without an engine")
				}
				return
			}
			waitFor(t, "the warm instance's report", func() bool {
				used, capacity, ok := b.WarmDevice(w.ID)
				return ok && used == 100 && capacity == 1000
			})
			waitFor(t, "the fiber's slice", func() bool {
				n, ok := b.FiberDevice("g/1-1")
				return ok && n == 42
			})
			if err := b.EvictDevice("g/1-1"); err != nil {
				t.Fatalf("EvictDevice: %v", err)
			}
			waitRecv(t, workDir, "EVICT g/1-1")
			waitFor(t, "the slice to go", func() bool {
				n, ok := b.FiberDevice("g/1-1")
				return ok && n == 0
			})
		})
	}
}

// TestEvictWithoutAChannel checks that an EVICT that cannot reach the
// engine is an error naming the send, not a lost request.
func TestEvictWithoutAChannel(t *testing.T) {
	cases := []struct {
		name string
	}{{name: "control channel closed"}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := pairConn(t)
			_ = c.Close()
			b := &Backend{zygotes: map[string]*zygote{"g": {id: "g", ctl: c}}, fibers: map[string]*fiber{"f": {id: "f", warmID: "g"}}}
			if err := b.EvictDevice("f"); err == nil || !strings.Contains(err.Error(), "send EVICT") {
				t.Fatalf("EvictDevice = %v, want a send error", err)
			}
		})
	}
}

// TestUnwarm checks that ending a warm instance kills its zygote and reports
// the instance gone once. An unknown id is nothing to do.
func TestUnwarm(t *testing.T) {
	cases := []struct {
		name  string
		known bool
	}{
		{name: "known instance", known: true},
		{name: "unknown instance"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, w, _ := warmed(t, "never", impossiblePID(t), nil)
			b.mu.Lock()
			z := b.zygotes[w.ID]
			b.mu.Unlock()
			id := w.ID
			if !tc.known {
				id = "nobody"
			}
			b.Unwarm(id)
			if !tc.known {
				noExit(t, b)
				return
			}
			if e := waitExit(t, b); e != (backend.Exit{WarmID: "g", Status: "zygote exited"}) {
				t.Fatalf("exit = %+v, want the warm instance gone", e)
			}
			waitFor(t, "the zygote to die", func() bool { return errors.Is(syscall.Kill(z.pid, 0), syscall.ESRCH) })
			b.mu.Lock()
			n := len(b.zygotes)
			b.mu.Unlock()
			if n != 0 {
				t.Fatalf("%d zygotes left, want none", n)
			}
		})
	}
}

// TestSocketpair checks that without a launcher any pair does. With one the
// pair is the launcher's, for the instance named, and there must be one.
func TestSocketpair(t *testing.T) {
	cases := []struct {
		name     string
		launcher *fakeLauncher
		warmID   string
		wantErr  string
	}{
		{name: "no launcher", warmID: "anything"},
		{name: "launcher, known instance", launcher: &fakeLauncher{}, warmID: "g"},
		{name: "launcher, unknown instance", launcher: &fakeLauncher{}, warmID: "nobody", wantErr: `no warm instance "nobody"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var launcher Launcher
			if tc.launcher != nil {
				launcher = tc.launcher
			}
			b, w, _ := warmed(t, "never", impossiblePID(t), launcher)
			fds, err := b.Socketpair(tc.warmID, syscall.SOCK_SEQPACKET)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Socketpair = %v %v, want %q", fds, err, tc.wantErr)
				}
				return
			}
			if err != nil || fds[0] < 0 || fds[1] < 0 {
				t.Fatalf("Socketpair = %v %v", fds, err)
			}
			_ = syscall.Close(fds[0])
			_ = syscall.Close(fds[1])
			if tc.launcher != nil {
				calls := tc.launcher.recorded()
				if want := "socketpair:" + strconv.Itoa(w.PID); calls[len(calls)-1] != want {
					t.Fatalf("launcher calls = %v, want %s last", calls, want)
				}
			}
		})
	}
}

// TestCheckpointWarm checks that the zygote is dumped running, with its control
// socket external, plus whatever the launcher's container needs.
func TestCheckpointWarm(t *testing.T) {
	cases := []struct {
		name     string
		launcher *fakeLauncher
		warmID   string
		wantErr  string
	}{
		{name: "plain zygote", warmID: "g"},
		{name: "launcher adds its arguments", launcher: &fakeLauncher{}, warmID: "g"},
		{name: "unknown instance", warmID: "nobody", wantErr: `no warm instance "nobody"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var launcher Launcher
			if tc.launcher != nil {
				launcher = tc.launcher
			}
			b, w, _ := warmed(t, "never", impossiblePID(t), launcher)
			criuDir := filepath.Dir(b.opt.CRIU)
			dir := t.TempDir()
			err := b.CheckpointWarm(context.Background(), tc.warmID, dir)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("CheckpointWarm = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("CheckpointWarm: %v", err)
			}
			ino, err := criu.SocketInode(w.PID, 3)
			if err != nil {
				t.Fatal(err)
			}
			calls := criuCalls(t, criuDir)
			dump := calls[len(calls)-1]
			for _, want := range []string{"dump ", " -t " + strconv.Itoa(w.PID) + " ", " -D " + dir + " ", "--leave-running", "--external unix[" + ino + "]"} {
				if !strings.Contains(dump, want) {
					t.Fatalf("criu dump %q lacks %q", dump, want)
				}
			}
			if strings.Contains(dump, "--dump-extra") != (tc.launcher != nil) {
				t.Fatalf("criu dump %q: launcher arguments present = %v", dump, tc.launcher != nil)
			}
		})
	}
}

// fakeCgroup is a directory whose cgroup.procs lists the pids given, for
// hostPID to read through an fd.
func fakeCgroup(t *testing.T, pids ...int) int {
	t.Helper()
	dir := t.TempDir()
	var sb strings.Builder
	for _, p := range pids {
		sb.WriteString(strconv.Itoa(p) + "\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(sb.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return int(d.Fd())
}

// TestHostPIDTranslation checks pid translation with a launcher. The
// zygote's pid is a number in its own namespace. The host's pid is the
// process in the fiber's leaf whose NSpid shows that number one level
// down. Processes gone from the leaf or without that level are skipped.
func TestHostPIDTranslation(t *testing.T) {
	requireRoot(t)
	child := hold(t, syscall.CLONE_NEWPID)
	cases := []struct {
		name     string
		procs    func() []int
		reported int
		want     func() int
	}{
		{name: "the init of its namespace", procs: func() []int { return []int{impossiblePID(t), os.Getpid(), child.Process.Pid} }, reported: 1, want: func() int { return child.Process.Pid }},
		{name: "a number nobody has", procs: func() []int { return []int{child.Process.Pid} }, reported: 2, want: func() int { return 0 }},
		{name: "an empty leaf", procs: func() []int { return nil }, reported: 1, want: func() int { return 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &Backend{opt: Options{Launcher: &fakeLauncher{}}}
			if got := b.hostPID(fakeCgroup(t, tc.procs()...), tc.reported); got != tc.want() {
				t.Fatalf("hostPID = %d, want %d", got, tc.want())
			}
		})
	}
}

// TestKillSignalsTheTranslatedPID checks that a launcher's fiber is signalled
// under the host pid Clone found for it, never the number the zygote
// reported.
func TestKillSignalsTheTranslatedPID(t *testing.T) {
	requireRoot(t)
	cases := []struct {
		name string
	}{{name: "kill reaches the fiber's host process"}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			child := hold(t, syscall.CLONE_NEWPID)
			b, w, workDir := warmed(t, "never", 1, &fakeLauncher{endpointRoot: "/inside"})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			f, err := b.Clone(ctx, w.ID, backend.FiberSpec{Fence: "g/1-1", Endpoint: filepath.Join(workDir, "ep.sock"), CgroupFD: fakeCgroup(t, child.Process.Pid), Deadline: time.Second})
			if err != nil {
				t.Fatalf("Clone: %v", err)
			}
			if f.PID != child.Process.Pid {
				t.Fatalf("Clone pid = %d, want the host's %d for the namespace's 1", f.PID, child.Process.Pid)
			}
			if err := b.Kill("g/1-1"); err != nil {
				t.Fatalf("Kill: %v", err)
			}
			err = child.Wait()
			var ee *exec.ExitError
			if !errors.As(err, &ee) || ee.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatalf("the child ended with %v, want SIGKILL", err)
			}
		})
	}
}

// mountPointOf picks a mount point of pid's namespace other than /.
func mountPointOf(t *testing.T, pid int) string {
	t.Helper()
	ents, err := readMountinfoOf(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if e.point != "/" {
			return e.point
		}
	}
	t.Fatal("no mount point to pick")
	return ""
}

// TestPark checks that a fiber is dumped with its own mount namespace's
// mounts named (and its run directory bind recorded), its handoff channel
// external, running on with Sync, through the launcher's arguments when it
// has one. What cannot be dumped is refused before criu runs.
func TestPark(t *testing.T) {
	requireRoot(t)
	cases := []struct {
		name      string
		knobs     criuKnobs
		launcher  bool
		zygote    bool // the launcher's zygote is registered
		flags     uintptr
		runDir    string // "mount" picks one of the fiber's mounts
		handoff   bool   // the fiber serves handoff
		channel   bool   // and holds its channel at fd 4
		sync      bool
		fiber     bool   // register the fiber at all
		dirIs     string // a directory already at this name in the image directory, or "file" for the image directory's parent
		wantErr   string
		wantArgs  []string
		wantFiles []string
		noFiles   []string
	}{
		{name: "shares the host's mount namespace", fiber: true, wantArgs: []string{"dump", "--ext-unix-sk"}, noFiles: []string{runDirFile, criu.MountsFile}},
		{name: "own mount namespace with the run directory bound", fiber: true, flags: syscall.CLONE_NEWNS, runDir: "mount",
			wantArgs: []string{"--external mnt[]", "mnt[RUNDIR]:rundir"}, wantFiles: []string{runDirFile, criu.MountsFile}},
		{name: "own mount namespace, run directory not mounted", fiber: true, flags: syscall.CLONE_NEWNS, runDir: "/nowhere/g",
			wantArgs: []string{"--external mnt[]"}, wantFiles: []string{criu.MountsFile}, noFiles: []string{runDirFile}},
		{name: "handoff channel is external", fiber: true, handoff: true, channel: true, wantArgs: []string{"--external unix[INO]"}, wantFiles: []string{handoffFile}},
		{name: "handoff fiber without a channel", fiber: true, handoff: true, wantErr: "handoff channel of f"},
		{name: "sync keeps it running", fiber: true, sync: true, wantArgs: []string{"--leave-running"}},
		{name: "criu fails", fiber: true, knobs: criuKnobs{dumpExit: 1}, wantErr: "criu dump"},
		{name: "launcher names the container's mounts", fiber: true, launcher: true, zygote: true, wantArgs: []string{"--dump-extra"}},
		{name: "unknown fiber", wantErr: `unknown fiber "f"`},
		{name: "criu unavailable", fiber: true, knobs: criuKnobs{checkExit: 1}, wantErr: "park needs FIBER_CHECKPOINT"},
		{name: "run directory record cannot be written", fiber: true, flags: syscall.CLONE_NEWNS, runDir: "mount", dirIs: runDirFile, wantErr: "is a directory"},
		{name: "handoff record cannot be written", fiber: true, handoff: true, channel: true, dirIs: handoffFile, wantErr: "is a directory"},
		{name: "image directory under a file", fiber: true, handoff: true, channel: true, dirIs: "file", wantErr: "not a directory"},
		{name: "mounts cannot be recorded", fiber: true, flags: syscall.CLONE_NEWNS, dirIs: "file", wantErr: "mounts of f"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin, criuDir := fakeCRIU(t, tc.knobs)
			var launcher Launcher
			if tc.launcher {
				launcher = &fakeLauncher{}
			}
			b := NewBackend(Options{CRIU: bin, Launcher: launcher, RootBind: filepath.Join(t.TempDir(), "root")})
			t.Cleanup(b.Close)
			var extra []*os.File
			if tc.channel {
				fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				devnull, err := os.Open(os.DevNull)
				if err != nil {
					t.Fatal(err)
				}
				channel := os.NewFile(uintptr(fds[0]), "handoff")
				defer func() { _ = devnull.Close(); _ = channel.Close(); _ = syscall.Close(fds[1]) }()
				extra = []*os.File{devnull, channel} // fd 3, fd 4
			}
			child := hold(t, tc.flags, extra...)
			pid := child.Process.Pid
			runDir := tc.runDir
			if runDir == "mount" {
				runDir = mountPointOf(t, pid)
			}
			if tc.fiber {
				b.fibers["f"] = &fiber{id: "f", pid: pid, warmID: "g", runDir: runDir, handoff: tc.handoff}
			}
			if tc.zygote {
				// A zygote by record only, for the launcher's arguments.
				// Close must not find it.
				b.zygotes["g"] = &zygote{id: "g", spec: backend.WarmSpec{GrantUID: "g"}}
				t.Cleanup(func() { delete(b.zygotes, "g") })
			}
			dir := filepath.Join(t.TempDir(), "parent", "img")
			if tc.dirIs != "file" {
				if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			switch tc.dirIs {
			case "":
			case "file":
				if err := os.WriteFile(filepath.Dir(dir), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.MkdirAll(filepath.Join(dir, tc.dirIs), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			err := b.Park(context.Background(), "f", backend.ParkSpec{Dir: dir, Sync: tc.sync})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Park = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Park: %v", err)
			}
			calls := criuCalls(t, criuDir)
			dump := calls[len(calls)-1]
			if !strings.Contains(dump, " -t "+strconv.Itoa(pid)+" ") || !strings.Contains(dump, " -D "+dir+" ") {
				t.Fatalf("criu dump %q names neither pid %d nor %s", dump, pid, dir)
			}
			ino := ""
			if tc.channel {
				if ino, err = criu.SocketInode(pid, handoffFD); err != nil {
					t.Fatal(err)
				}
			}
			for _, want := range tc.wantArgs {
				want = strings.NewReplacer("RUNDIR", runDir, "INO", ino).Replace(want)
				if !strings.Contains(dump, want) {
					t.Fatalf("criu dump %q lacks %q", dump, want)
				}
			}
			if !tc.sync && strings.Contains(dump, "--leave-running") {
				t.Fatalf("criu dump %q leaves the tree running without Sync", dump)
			}
			for _, f := range tc.wantFiles {
				data, err := os.ReadFile(filepath.Join(dir, f))
				if err != nil {
					t.Fatalf("%s not written: %v", f, err)
				}
				switch f {
				case runDirFile:
					var rec runDirRecord
					if json.Unmarshal(data, &rec) != nil || rec.MountPoint != runDir {
						t.Fatalf("%s = %s, want mountpoint %s", f, data, runDir)
					}
				case handoffFile:
					var rec handoffRecord
					if json.Unmarshal(data, &rec) != nil || rec.Inode != ino {
						t.Fatalf("%s = %s, want inode %s", f, data, ino)
					}
				}
			}
			for _, f := range tc.noFiles {
				if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
					t.Fatalf("%s written, want none", f)
				}
			}
		})
	}
}

// TestHandoffInherit checks that a checkpoint of a handoff fiber names the
// inode its channel had, and a resume must bring a replacement. Any other
// checkpoint takes none.
func TestHandoffInherit(t *testing.T) {
	cases := []struct {
		name    string
		record  string // "" for no file
		channel bool
		want    string
		wantErr string
	}{
		{name: "no record, no channel"},
		{name: "record and channel", record: `{"inode":"12345"}`, channel: true, want: "--inherit-fd fd[3]:socket:[12345]"},
		{name: "channel for a checkpoint without one", channel: true, wantErr: "no handoff channel to replace"},
		{name: "record without a channel", record: `{"inode":"12345"}`, wantErr: "needs a channel"},
		{name: "malformed record", record: `{"inode":""}`, channel: true, wantErr: "malformed"},
		{name: "unreadable record", record: "dir", channel: true, wantErr: "is a directory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			switch tc.record {
			case "":
			case "dir":
				if err := os.Mkdir(filepath.Join(dir, handoffFile), 0o755); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(filepath.Join(dir, handoffFile), []byte(tc.record), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var ch *os.File
			if tc.channel {
				var err error
				if ch, err = os.Open(os.DevNull); err != nil {
					t.Fatal(err)
				}
				defer func() { _ = ch.Close() }()
			}
			args, files, err := handoffInherit(dir, ch)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("handoffInherit = %v %v %v, want %q", args, files, err, tc.wantErr)
				}
				return
			}
			if err != nil || strings.Join(args, " ") != tc.want {
				t.Fatalf("handoffInherit = %v %v, want %q", args, err, tc.want)
			}
			wantFiles := 0
			if tc.channel {
				wantFiles = 1
			}
			if len(files) != wantFiles || (wantFiles == 1 && files[0] != ch) {
				t.Fatalf("files = %v, want the channel only when given", files)
			}
		})
	}
}

// writeMounts records a dump with a mount namespace and no file mounts.
func writeMounts(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, criu.MountsFile), []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestResume checks that a checkpoint is restored under the resuming grant's
// directory, with the restore root bound when it has a mount namespace,
// its handoff channel replaced, and its end reported as the fiber's exit.
// A launcher is told of the tree it prepared for, and when it is gone.
func TestResume(t *testing.T) {
	requireRoot(t)
	cases := []struct {
		name      string
		knobs     criuKnobs
		launcher  *fakeLauncher
		setup     func(t *testing.T, dir, rootBind string)
		spec      backend.ResumeSpec
		handoff   bool
		kill      bool
		wantErr   error
		wantText  string
		wantArgs  []string
		wantExit  string
		wantCalls string
		wantRoot  bool
	}{
		{name: "plain checkpoint", wantArgs: []string{"restore ", "--pidfile"}, wantExit: "exit:0"},
		{name: "mount namespace binds the restore root and run directory", setup: func(t *testing.T, dir, _ string) {
			writeMounts(t, dir)
			if err := os.WriteFile(filepath.Join(dir, runDirFile), []byte(`{"mountpoint":"/tmp/fz-a/g"}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}, wantArgs: []string{"--root ROOT --external mnt[]", "--external mnt[rundir]:WORK"}, wantExit: "exit:0", wantRoot: true},
		{name: "mount namespace with a malformed run directory record", setup: func(t *testing.T, dir, _ string) {
			writeMounts(t, dir)
			if err := os.WriteFile(filepath.Join(dir, runDirFile), []byte(`nonsense`), 0o600); err != nil {
				t.Fatal(err)
			}
		}, wantText: "malformed", wantRoot: true},
		{name: "restore root refused", setup: func(t *testing.T, dir, rootBind string) {
			writeMounts(t, dir)
			if err := os.Symlink("/", rootBind); err != nil {
				t.Fatal(err)
			}
		}, wantText: "restore root"},
		{name: "malformed mounts record", setup: func(t *testing.T, dir, _ string) {
			if err := os.WriteFile(filepath.Join(dir, criu.MountsFile), []byte(`nonsense`), 0o600); err != nil {
				t.Fatal(err)
			}
		}, wantText: criu.MountsFile},
		{name: "handoff channel replaced", setup: func(t *testing.T, dir, _ string) {
			if err := os.WriteFile(filepath.Join(dir, handoffFile), []byte(`{"inode":"777"}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}, handoff: true, wantArgs: []string{"--inherit-fd fd[3]:socket:[777]"}, wantExit: "exit:0"},
		{name: "handoff checkpoint without a channel", setup: func(t *testing.T, dir, _ string) {
			if err := os.WriteFile(filepath.Join(dir, handoffFile), []byte(`{"inode":"777"}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}, wantText: "needs a channel"},
		{name: "restore fails", knobs: criuKnobs{restore: "no"}, wantText: "criu restore failed"},
		{name: "restore misses the deadline", knobs: criuKnobs{restore: "hang"}, spec: backend.ResumeSpec{Deadline: 200 * time.Millisecond}, wantErr: context.DeadlineExceeded},
		{name: "the tree exits with an error", knobs: criuKnobs{restoreExit: 3}, wantExit: "exit:exit status 3"},
		{name: "the tree is killed", kill: true, wantExit: "exit:signal: killed"},
		{name: "criu unavailable", knobs: criuKnobs{checkExit: 1}, wantText: "resume needs FIBER_CHECKPOINT"},
		{name: "launcher restores in its container", launcher: &fakeLauncher{}, wantArgs: []string{"--restore-extra"}, wantExit: "exit:0",
			wantCalls: "restoreExtra:DIR,restored:PID,restoredGone"},
		{name: "launcher restore without a run directory takes the endpoint's", launcher: &fakeLauncher{restoredErr: errors.New("mounts")}, spec: backend.ResumeSpec{WorkDir: "-"},
			wantArgs: []string{"--restore-extra"}, wantExit: "exit:0", wantCalls: "restoreExtra:DIR,restored:PID,restoredGone"},
		{name: "launcher cannot prepare the restore", launcher: &fakeLauncher{restoreExtraErr: errors.New("no rootfs")}, wantText: "no rootfs", wantCalls: "restoreExtra:DIR"},
		{name: "launcher prepared, restore fails", launcher: &fakeLauncher{}, knobs: criuKnobs{restore: "no"}, wantText: "criu restore failed", wantCalls: "restoreExtra:DIR,restoredGone"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin, criuDir := fakeCRIU(t, tc.knobs)
			var launcher Launcher
			if tc.launcher != nil {
				launcher = tc.launcher
			}
			rootBind := filepath.Join(t.TempDir(), "root")
			b := NewBackend(Options{CRIU: bin, Launcher: launcher, RootBind: rootBind})
			t.Cleanup(b.Close)
			dir := t.TempDir()
			if tc.setup != nil {
				tc.setup(t, dir, rootBind)
			}
			workDir := filepath.Join(t.TempDir(), "g2")
			spec := tc.spec
			spec.Dir, spec.Fence, spec.CgroupFD, spec.WarmID = dir, "g/2-1", -1, "g"
			spec.Endpoint = filepath.Join(workDir, "ep.sock")
			switch spec.WorkDir {
			case "":
				spec.WorkDir = workDir
			case "-":
				spec.WorkDir = ""
			}
			if tc.handoff {
				fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				spec.Handoff = os.NewFile(uintptr(fds[0]), "handoff")
				defer func() { _ = spec.Handoff.Close(); _ = syscall.Close(fds[1]) }()
			}
			f, err := b.Resume(context.Background(), spec)
			if tc.wantErr != nil || tc.wantText != "" {
				if err == nil || (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) || !strings.Contains(err.Error(), tc.wantText) {
					t.Fatalf("Resume = %v, want %q (errors.Is %v)", err, tc.wantText, tc.wantErr)
				}
			} else if err != nil {
				t.Fatalf("Resume: %v", err)
			}
			if err == nil {
				if f.ID != "g/2-1" || f.PID <= 0 {
					t.Fatalf("Resume = %+v, want g/2-1 with criu's pid", f)
				}
				calls := criuCalls(t, criuDir)
				restore := calls[len(calls)-1]
				for _, want := range tc.wantArgs {
					want = strings.NewReplacer("ROOT", rootBind, "WORK", workDir).Replace(want)
					if !strings.Contains(restore, want) {
						t.Fatalf("criu restore %q lacks %q", restore, want)
					}
				}
				if tc.kill {
					if err := b.Kill("g/2-1"); err != nil {
						t.Fatalf("Kill: %v", err)
					}
				} else {
					release(t, criuDir)
				}
				if e := waitExit(t, b); e != (backend.Exit{FiberID: "g/2-1", Status: tc.wantExit}) {
					t.Fatalf("exit = %+v, want %s", e, tc.wantExit)
				}
				b.mu.Lock()
				n := len(b.fibers)
				b.mu.Unlock()
				if n != 0 {
					t.Fatalf("%d fibers left after the exit, want none", n)
				}
			}
			if tc.wantRoot {
				if !mountedAt(os.Getpid(), rootBind) {
					t.Fatalf("restore root %s not mounted", rootBind)
				}
				b.Close()
				if mountedAt(os.Getpid(), rootBind) {
					t.Fatalf("restore root %s still mounted after Close", rootBind)
				}
			}
			if tc.launcher != nil {
				want := strings.NewReplacer("DIR", dir, "PID", strconv.Itoa(f.PID)).Replace(tc.wantCalls)
				waitFor(t, "launcher calls "+want, func() bool { return strings.Join(tc.launcher.recorded(), ",") == want })
			}
		})
	}
}

// TestFinishAndForgetOnce checks that a fiber's exit is reported once, and a
// fiber forgotten or replaced under its fence is not touched again.
func TestFinishAndForgetOnce(t *testing.T) {
	cases := []struct {
		name     string
		second   func(b *Backend, f *fiber)
		wantExit int
	}{
		{name: "finish twice reports once", second: func(b *Backend, f *fiber) { b.finish(f, "exit:1") }, wantExit: 1},
		{name: "forget after finish is nothing", second: func(b *Backend, f *fiber) { b.forget(f) }, wantExit: 1},
		{name: "finish of a replaced fiber leaves the new one", second: func(b *Backend, f *fiber) {
			b.fibers[f.id] = &fiber{id: f.id, zpid: 9, warmID: "g"}
			b.byPID[pidKey{"g", 9}] = b.fibers[f.id]
			b.finish(f, "exit:2")
		}, wantExit: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &Backend{fibers: map[string]*fiber{}, byPID: map[pidKey]*fiber{}, exits: make(chan backend.Exit, 8)}
			f := &fiber{id: "f", zpid: 7, warmID: "g"}
			b.fibers[f.id] = f
			b.byPID[pidKey{"g", 7}] = f
			b.finish(f, "exit:0")
			tc.second(b, f)
			if len(b.exits) != tc.wantExit {
				t.Fatalf("%d exits reported, want %d", len(b.exits), tc.wantExit)
			}
			if e := <-b.exits; e != (backend.Exit{FiberID: "f", Status: "exit:0"}) {
				t.Fatalf("exit = %+v", e)
			}
			if _, ok := b.byPID[pidKey{"g", 7}]; ok {
				t.Fatal("the finished fiber is still in byPID")
			}
		})
	}
}

// pagemapHeader is the 8 magic bytes a pagemap image starts with.
var pagemapHeader = []byte{0x19, 0x43, 0x56, 0x54, 0x01, 0x00, 0x00, 0x00}

// writeCheckpoint writes a one-task checkpoint with one present page of
// fill at the second page address.
func writeCheckpoint(t *testing.T, dir string, fill byte) {
	t.Helper()
	msg := func(fields ...[2]uint64) []byte {
		var m []byte
		for _, f := range fields {
			m = binary.AppendUvarint(m, f[0]<<3)
			m = binary.AppendUvarint(m, f[1])
		}
		return append(binary.LittleEndian.AppendUint32(nil, uint32(len(m))), m...)
	}
	img := append([]byte{}, pagemapHeader...)
	img = append(img, msg([2]uint64{1, 1})...)
	img = append(img, msg([2]uint64{1, criu.PageSize}, [2]uint64{2, 1}, [2]uint64{4, criu.PEPresent})...)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pagemap-1.img"), img, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pages-1.img"), bytes.Repeat([]byte{fill}, int(criu.PageSize)), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestDeltaCodec checks that the backend's delta codec is criu's. A
// checkpoint is computed as a delta over the parent, recognised as one, read
// back and merged whole again. Anything but a criu parent is refused.
func TestDeltaCodec(t *testing.T) {
	cases := []struct {
		name      string
		childFill byte
		wantBytes uint64 // the delta's
	}{
		{name: "same page as the parent is dropped", childFill: 'a', wantBytes: 0},
		{name: "a changed page is kept", childFill: 'b', wantBytes: criu.PageSize},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &Backend{}
			parentDir, dir := filepath.Join(t.TempDir(), "p"), filepath.Join(t.TempDir(), "c")
			writeCheckpoint(t, parentDir, 'a')
			writeCheckpoint(t, dir, tc.childFill)
			if n, err := b.ImageBytes(dir); err != nil || n != criu.PageSize {
				t.Fatalf("ImageBytes = %d %v, want one page", n, err)
			}
			if _, err := b.ImageBytes(filepath.Join(dir, "missing")); err == nil {
				t.Fatal("ImageBytes of a missing directory succeeded")
			}
			if _, err := b.LoadParent(t.TempDir()); err == nil {
				t.Fatal("LoadParent of an empty directory succeeded")
			}
			parent, err := b.LoadParent(parentDir)
			if err != nil {
				t.Fatalf("LoadParent: %v", err)
			}
			t.Cleanup(parent.(*criu.Parent).Close)
			if _, err := b.Compute(dir, notAParent{}); err == nil || !strings.Contains(err.Error(), "not a criu checkpoint") {
				t.Fatalf("Compute over a foreign parent = %v", err)
			}
			if err := b.Merge(dir, notAParent{}); err == nil || !strings.Contains(err.Error(), "not a criu checkpoint") {
				t.Fatalf("Merge over a foreign parent = %v", err)
			}
			if _, err := b.Compute(t.TempDir(), parent); err == nil {
				t.Fatal("Compute of an empty directory succeeded")
			}
			if b.HasDelta(dir) {
				t.Fatal("HasDelta before Compute")
			}
			if _, err := b.ReadDeltaInfo(dir); err == nil {
				t.Fatal("ReadDeltaInfo before Compute succeeded")
			}
			info, err := b.Compute(dir, parent)
			if err != nil {
				t.Fatalf("Compute: %v", err)
			}
			if info.ParentSHA256 != parent.(*criu.Parent).SHA256() || info.Bytes != tc.wantBytes {
				t.Fatalf("Compute = %+v, want parent %s and %d bytes", info, parent.(*criu.Parent).SHA256(), tc.wantBytes)
			}
			if !b.HasDelta(dir) {
				t.Fatal("HasDelta after Compute = false")
			}
			if read, err := b.ReadDeltaInfo(dir); err != nil || read != info {
				t.Fatalf("ReadDeltaInfo = %+v %v, want %+v", read, err, info)
			}
			if err := b.Merge(dir, parent); err != nil {
				t.Fatalf("Merge: %v", err)
			}
			if b.HasDelta(dir) {
				t.Fatal("HasDelta after Merge")
			}
			pages, err := os.ReadFile(filepath.Join(dir, "pages-1.img"))
			if err != nil || !bytes.Equal(pages, bytes.Repeat([]byte{tc.childFill}, int(criu.PageSize))) {
				t.Fatalf("merged pages are not the child's own (%d bytes, %v)", len(pages), err)
			}
		})
	}
}

type notAParent struct{}

func (notAParent) SHA256() string { return "" }
func (notAParent) Close()         {}

// TestMountinfo checks the mount table reader, its escape decoding, and the
// questions asked of it (is this a mount point, is this a dead sibling's
// restore root).
func TestMountinfo(t *testing.T) {
	t.Run("unescape", func(t *testing.T) {
		cases := []struct{ in, want string }{
			{"/plain", "/plain"},
			{`/with\040space`, "/with space"},
			{`/tab\011and\134backslash`, "/tab\tand\\backslash"},
			{`/short\04`, `/short\04`},
			{`/not\0z0octal`, `/not\0z0octal`},
			{`/trailing\`, `/trailing\`},
		}
		for _, tc := range cases {
			t.Run(tc.in, func(t *testing.T) {
				if got := unescapeMount(tc.in); got != tc.want {
					t.Fatalf("unescapeMount(%q) = %q, want %q", tc.in, got, tc.want)
				}
			})
		}
	})
	t.Run("read", func(t *testing.T) {
		cases := []struct {
			name    string
			content string // "" for a missing file
			want    []mountEntry
			wantErr bool
		}{
			{name: "missing file", wantErr: true},
			{name: "entries with options before the separator", content: "36 35 98:0 /mnt1 /mnt\\0402 rw,noatime master:1 - ext3 /dev/root rw\nshort line\n37 35 0:5 / /proc rw - proc proc rw\n",
				want: []mountEntry{{dev: "98:0", root: "/mnt1", point: "/mnt 2", opts: []string{"master:1"}}, {dev: "0:5", root: "/", point: "/proc"}}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "mountinfo")
				if tc.content != "" {
					if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				got, err := readMountinfoOf(path)
				if (err != nil) != tc.wantErr {
					t.Fatalf("readMountinfoOf = %v %v", got, err)
				}
				if fmt.Sprint(got) != fmt.Sprint(tc.want) {
					t.Fatalf("readMountinfoOf = %+v, want %+v", got, tc.want)
				}
			})
		}
	})
	t.Run("mountedAt", func(t *testing.T) {
		cases := []struct {
			name  string
			pid   int
			point string
			want  bool
		}{
			{name: "/proc in our namespace", pid: os.Getpid(), point: "/proc", want: true},
			{name: "a path that is no mount", pid: os.Getpid(), point: filepath.Join(os.TempDir(), "nowhere"), want: false},
			{name: "no such process", pid: impossiblePID(t), point: "/proc", want: false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if got := mountedAt(tc.pid, tc.point); got != tc.want {
					t.Fatalf("mountedAt(%d, %s) = %v, want %v", tc.pid, tc.point, got, tc.want)
				}
			})
		}
	})
	t.Run("deadSibling", func(t *testing.T) {
		dir := "/tmp/" + rootName + "100"
		cases := []struct {
			name  string
			point string
			want  bool
		}{
			{name: "a dead pid's root beside ours", point: "/tmp/" + rootName + strconv.Itoa(impossiblePID(t)), want: true},
			{name: "a live pid's root", point: "/tmp/" + rootName + strconv.Itoa(os.Getpid()), want: false},
			{name: "another directory", point: "/var/" + rootName + strconv.Itoa(impossiblePID(t)), want: false},
			{name: "another name", point: "/tmp/other-" + strconv.Itoa(impossiblePID(t)), want: false},
			{name: "not a number", point: "/tmp/" + rootName + "abc", want: false},
			{name: "a leading zero is not a pid", point: "/tmp/" + rootName + "0" + strconv.Itoa(impossiblePID(t)), want: false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if got := deadSibling(dir, tc.point); got != tc.want {
					t.Fatalf("deadSibling(%s, %s) = %v, want %v", dir, tc.point, got, tc.want)
				}
			})
		}
	})
}

// isMounted reports whether this namespace has a mount at point.
func isMounted(point string) bool { return mountedAt(os.Getpid(), point) }

// unmountLater detaches a bind the test made if it is still there.
func unmountLater(t *testing.T, point string) {
	t.Helper()
	t.Cleanup(func() {
		for isMounted(point) {
			if err := syscall.Unmount(point, syscall.MNT_DETACH); err != nil {
				t.Errorf("unmount %s: %v", point, err)
				return
			}
		}
		_ = os.Remove(point)
		_ = os.Remove(holderFile(point))
	})
}

// TestMountRoot checks that the restore root is a private bind of / at a leaf
// this process made and checked. A path it cannot trust is refused, and a
// directory it made for a refused mount goes again.
func TestMountRoot(t *testing.T) {
	requireRoot(t)
	cases := []struct {
		name    string
		dir     func(t *testing.T, base string) string
		wantErr string
	}{
		{name: "fresh leaf", dir: func(_ *testing.T, base string) string { return filepath.Join(base, "root") }},
		{name: "existing empty directory", dir: func(t *testing.T, base string) string {
			d := filepath.Join(base, "root")
			if err := os.Mkdir(d, 0o700); err != nil {
				t.Fatal(err)
			}
			return d
		}},
		{name: "relative path", dir: func(*testing.T, string) string { return "relative/root" }, wantErr: "absolute"},
		{name: "name too long", dir: func(_ *testing.T, base string) string { return filepath.Join(base, strings.Repeat("r", 300)) }, wantErr: "file name too long"},
		{name: "parent is a file", dir: func(t *testing.T, base string) string {
			f := filepath.Join(base, "file")
			if err := os.WriteFile(f, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(f, "root")
		}, wantErr: "not a directory"},
		{name: "a symlink", dir: func(t *testing.T, base string) string {
			d := filepath.Join(base, "root")
			if err := os.Symlink("/", d); err != nil {
				t.Fatal(err)
			}
			return d
		}, wantErr: "is a symlink"},
		{name: "a regular file", dir: func(t *testing.T, base string) string {
			d := filepath.Join(base, "root")
			if err := os.WriteFile(d, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return d
		}, wantErr: "not a directory"},
		{name: "someone else's directory", dir: func(t *testing.T, base string) string {
			d := filepath.Join(base, "root")
			if err := os.Mkdir(d, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(d, 1000, 1000); err != nil {
				t.Fatal(err)
			}
			return d
		}, wantErr: "owned by uid 1000"},
		{name: "already a mount point", dir: func(t *testing.T, base string) string {
			d := filepath.Join(base, "root")
			if err := os.Mkdir(d, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mount(base, d, "", syscall.MS_BIND, ""); err != nil {
				t.Fatal(err)
			}
			unmountLater(t, d)
			return d
		}, wantErr: "already a mount point"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			dir := tc.dir(t, base)
			if filepath.IsAbs(dir) {
				unmountLater(t, dir)
			}
			existed := false
			if _, err := os.Lstat(dir); err == nil {
				existed = true
			}
			rootMu.Lock()
			err := mountRoot(dir)
			rootMu.Unlock()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("mountRoot = %v, want %q", err, tc.wantErr)
				}
				if _, serr := os.Lstat(dir); !existed && serr == nil {
					t.Fatal("a directory made for the refused mount was left behind")
				}
				return
			}
			if err != nil {
				t.Fatalf("mountRoot: %v", err)
			}
			if !isMounted(dir) {
				t.Fatalf("%s is not a mount point", dir)
			}
			// A bind of / shows the root's entries, and the holder file
			// names this process.
			if _, err := os.Stat(filepath.Join(dir, "proc")); err != nil {
				t.Fatalf("the bind does not show /: %v", err)
			}
			if !heldByLiveProcess(holderFile(dir), 0) {
				t.Fatal("the holder file does not name this live process")
			}
			ents, err := readMountinfo()
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range ents {
				if e.point == dir && strings.Contains(strings.Join(e.opts, " "), "shared:") {
					t.Fatalf("the restore root is shared: %v", e.opts)
				}
			}
		})
	}
}

// TestRootBindShared checks that backends naming the same restore root share
// one bind, which the last to close unmounts. A backend without one has
// nothing to give up.
func TestRootBindShared(t *testing.T) {
	requireRoot(t)
	cases := []struct {
		name  string
		setup func(t *testing.T, dir string, a, b *Backend)
	}{
		{name: "two backends, the last one unmounts", setup: func(t *testing.T, dir string, a, b *Backend) {
			if err := a.bindRoot(); err != nil {
				t.Fatal(err)
			}
			if err := b.bindRoot(); err != nil {
				t.Fatal(err)
			}
			if err := a.bindRoot(); err != nil { // holding twice is holding once
				t.Fatal(err)
			}
			a.unbindRoot()
			if !isMounted(dir) {
				t.Fatal("the first close unmounted a bind the second backend holds")
			}
			b.unbindRoot()
		}},
		{name: "never bound", setup: func(_ *testing.T, _ string, a, _ *Backend) { a.unbindRoot() }},
		{name: "in the table but not mounted", setup: func(t *testing.T, dir string, a, _ *Backend) {
			var logs bytes.Buffer
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(os.Stderr) })
			a.rootHeld = true
			rootMu.Lock()
			rootBinds[dir] = &rootBind{refs: 1}
			rootMu.Unlock()
			a.unbindRoot()
			if !strings.Contains(logs.String(), "unmount restore root "+dir) {
				t.Fatalf("log = %q, want the failed unmount", logs.String())
			}
		}},
		{name: "held but not in the table", setup: func(_ *testing.T, _ string, a, _ *Backend) {
			a.rootHeld = true
			a.unbindRoot()
			if a.rootHeld {
				t.Fatal("still held")
			}
		}},
		{name: "mount refused", setup: func(t *testing.T, dir string, a, _ *Backend) {
			if err := os.Symlink("/", dir); err != nil {
				t.Fatal(err)
			}
			if err := a.bindRoot(); err == nil || !strings.Contains(err.Error(), "restore root "+dir) {
				t.Fatalf("bindRoot over a symlink = %v", err)
			}
			if a.rootHeld {
				t.Fatal("a refused bind is held")
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "root")
			unmountLater(t, dir)
			a := &Backend{opt: Options{RootBind: dir}}
			b := &Backend{opt: Options{RootBind: dir}}
			tc.setup(t, dir, a, b)
			if isMounted(dir) {
				t.Fatalf("%s still mounted", dir)
			}
			rootMu.Lock()
			_, held := rootBinds[dir]
			rootMu.Unlock()
			if held {
				t.Fatal("the bind is still in the table")
			}
		})
	}
}

// bindSlash binds / at point for a test and records the holder given.
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
		if err := os.WriteFile(holderFile(point), []byte(holder), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestReapStaleRoots checks that binds of / a dead run left at this
// configuration's path, and at dead pids' default paths beside it, are
// unmounted. Binds a live process records, binds a backend here holds, binds
// that are not of /, and binds elsewhere stay.
func TestReapStaleRoots(t *testing.T) {
	requireRoot(t)
	cases := []struct {
		name     string
		siblings bool
		setup    func(t *testing.T, base, dir string) (stay, reaped []string)
	}{
		{name: "own path and a dead sibling go, the rest stays", siblings: true, setup: func(t *testing.T, base, dir string) ([]string, []string) {
			dead := filepath.Join(base, rootName+strconv.Itoa(impossiblePID(t)))
			live := filepath.Join(base, rootName+strconv.Itoa(os.Getpid()))
			other := filepath.Join(base, "unrelated")
			notSlash := filepath.Join(base, rootName+strconv.Itoa(impossiblePID(t)-1))
			bindSlash(t, dir, "")
			bindSlash(t, dead, "")
			bindSlash(t, live, "")
			bindSlash(t, other, "")
			if err := os.MkdirAll(notSlash, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mount(base, notSlash, "", syscall.MS_BIND, ""); err != nil {
				t.Fatal(err)
			}
			unmountLater(t, notSlash)
			return []string{live, other, notSlash}, []string{dir, dead}
		}},
		{name: "a live holder keeps its bind", setup: func(t *testing.T, _, dir string) ([]string, []string) {
			bindSlash(t, dir, "1\n")
			return []string{dir}, nil
		}},
		{name: "a dead holder's bind goes", setup: func(t *testing.T, _, dir string) ([]string, []string) {
			bindSlash(t, dir, strconv.Itoa(impossiblePID(t)))
			return nil, []string{dir}
		}},
		{name: "a bind a backend here holds stays", setup: func(t *testing.T, _, dir string) ([]string, []string) {
			bindSlash(t, dir, "")
			rootMu.Lock()
			rootBinds[dir] = &rootBind{refs: 1}
			rootMu.Unlock()
			t.Cleanup(func() {
				rootMu.Lock()
				delete(rootBinds, dir)
				rootMu.Unlock()
			})
			return []string{dir}, nil
		}},
		{name: "stacked binds come off one per pass", setup: func(t *testing.T, _, dir string) ([]string, []string) {
			bindSlash(t, dir, "")
			bindSlash(t, dir, "")
			return nil, []string{dir}
		}},
		{name: "siblings not asked for stay", setup: func(t *testing.T, base, _ string) ([]string, []string) {
			dead := filepath.Join(base, rootName+strconv.Itoa(impossiblePID(t)))
			bindSlash(t, dead, "")
			return []string{dead}, nil
		}},
		{name: "nothing to do", setup: func(*testing.T, string, string) ([]string, []string) { return nil, nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			dir := filepath.Join(base, "root")
			stay, gone := tc.setup(t, base, dir)
			reapStaleRoots(dir, tc.siblings)
			for _, p := range stay {
				if !isMounted(p) {
					t.Errorf("%s was unmounted, want it kept", p)
				}
			}
			for _, p := range gone {
				if isMounted(p) {
					t.Errorf("%s is still mounted, want it reaped", p)
				}
				if _, err := os.Lstat(p); err == nil {
					t.Errorf("%s still exists, want it removed", p)
				}
			}
		})
	}
}

// sha256Hex is the hex SHA-256 of a file's bytes.
func sha256Hex(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// TestOpenVerified checks that a registry template's executable is
// verified through the descriptor it is exec'd from: the bytes are hashed
// against what the host verified, a mismatch is refused, and an exec
// through the descriptor runs those bytes even after the path was
// swapped, for a script as for a binary.
func TestOpenVerified(t *testing.T) {
	cases := []struct {
		name    string
		sha     func(path string) string
		missing bool
		wantErr string
	}{
		{name: "the verified bytes", sha: func(p string) string { return sha256Hex(t, p) }},
		{name: "a hash the bytes do not match", sha: func(string) string { return strings.Repeat("0", 64) }, wantErr: "hashes to"},
		{name: "no file", sha: func(string) string { return strings.Repeat("0", 64) }, missing: true, wantErr: "no such file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "zygote")
			if !tc.missing {
				if err := os.WriteFile(path, []byte("#!/bin/sh\necho verified\n"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			f, err := openVerified(path, tc.sha(path))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("openVerified = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("openVerified: %v", err)
			}
			defer func() { _ = f.Close() }()
			// The path now leads elsewhere; the descriptor still runs what
			// was verified. As in Warm, the descriptor is passed as fd 4,
			// after a stand-in for the control socket at fd 3.
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
			cmd := exec.Command(path)
			cmd.ExtraFiles = []*os.File{devnull, f}
			cmd.Path = exeFDPath
			out, err := cmd.Output()
			if err != nil || strings.TrimSpace(string(out)) != "verified" {
				t.Fatalf("exec through the descriptor = %q %v, want the verified bytes", out, err)
			}
		})
	}
}

// TestWarmVerifiesRegistryTemplate checks that Warm refuses a registry
// template (one with a verified hash) whose executable no longer hashes
// to it, before anything starts, and runs one that does. A launcher's
// template is the launcher's to verify (runc stages its own copy).
func TestWarmVerifiesRegistryTemplate(t *testing.T) {
	cases := []struct {
		name     string
		sha      func(exe string) string
		launcher *fakeLauncher
		wantErr  string
	}{
		{name: "the executable the host verified", sha: func(exe string) string { return sha256Hex(t, exe) }},
		{name: "an executable that changed since", sha: func(string) string { return strings.Repeat("0", 64) }, wantErr: "hashes to"},
		{name: "a launcher verifies its own copy", sha: func(string) string { return strings.Repeat("0", 64) }, launcher: &fakeLauncher{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin, _ := fakeCRIU(t, criuKnobs{})
			var launcher Launcher
			if tc.launcher != nil {
				launcher = tc.launcher
			}
			b := NewBackend(Options{CRIU: bin, Launcher: launcher, RootBind: filepath.Join(t.TempDir(), "root")})
			t.Cleanup(b.Close)
			argv := fakeArgv(t, "never", impossiblePID(t))
			tpl := backend.Template{Argv: argv, Dir: filepath.Dir(argv[0]), Digest: "sha256:test", ZygoteSHA256: tc.sha(argv[0])}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			w, err := b.Warm(ctx, backend.WarmSpec{GrantUID: "g", Template: tpl, CgroupFD: -1, ProbeCgroupFD: -1, WorkDir: t.TempDir()})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Warm = %v, want %q", err, tc.wantErr)
				}
				b.mu.Lock()
				n := len(b.zygotes)
				b.mu.Unlock()
				if n != 0 {
					t.Fatalf("%d zygotes registered after a refused template, want none", n)
				}
				return
			}
			if err != nil {
				t.Fatalf("Warm: %v", err)
			}
			if tc.launcher != nil {
				return
			}
			// The zygote runs the file at the path, exec'd through the
			// verified descriptor, and the path is what /proc names.
			exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", w.PID))
			if err != nil || exe != argv[0] {
				t.Fatalf("zygote exe = %q (%v), want %q", exe, err, argv[0])
			}
		})
	}
}
