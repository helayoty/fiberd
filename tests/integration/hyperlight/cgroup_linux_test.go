//go:build linux && integration

package hyperlighttest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
	hlbackend "github.com/helayoty/fiberd/pkg/backend/hyperlight"
)

// TestHelperStartsInCgroup checks what only a real helper process shows:
// it is born in the grant's cgroup, and it is killed and reaped when the
// warm ends or fails. The backend's unit tests cover the rest of Warm
// over a helper run as a goroutine.
func TestHelperStartsInCgroup(t *testing.T) {
	cases := []struct {
		name  string
		guest string // the guest the helper is given, "" so it exits before READY
		run   func(t *testing.T, be backend.Backend, sp backend.WarmSpec, leaf string)
	}{
		{name: "the helper is born in the grant's cgroup and Unwarm reaps it", guest: guest,
			run: func(t *testing.T, be backend.Backend, sp backend.WarmSpec, leaf string) {
				w, err := be.Warm(warmCtx(t), sp)
				if err != nil {
					t.Fatalf("Warm: %v", err)
				}
				b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", w.PID))
				if err != nil || !strings.Contains(string(b), filepath.Base(leaf)) {
					t.Errorf("helper cgroup = %q, %v, want it under %s", b, err, leaf)
				}
				be.Unwarm(w.ID)
				waitGone(t, w.PID)
			}},
		{name: "Close reaps the helper", guest: guest,
			run: func(t *testing.T, be backend.Backend, sp backend.WarmSpec, _ string) {
				w, err := be.Warm(warmCtx(t), sp)
				if err != nil {
					t.Fatalf("Warm: %v", err)
				}
				be.Close()
				waitGone(t, w.PID)
			}},
		{name: "a helper that exits before READY leaves no zombie",
			run: func(t *testing.T, be backend.Backend, sp backend.WarmSpec, _ string) {
				before := children(t)
				_, err := be.Warm(warmCtx(t), sp)
				if !errors.Is(err, io.EOF) {
					t.Fatalf("Warm = %v, want EOF from a helper that exited", err)
				}
				noNewChildren(t, before)
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := hlbackend.New(hlbackend.Options{Helper: helperBin, Guest: tc.guest})
			t.Cleanup(be.Close)
			leaf, fd := cgroupLeaf(t)
			sp := backend.WarmSpec{GrantUID: "g1", WorkDir: filepath.Join(t.TempDir(), "run", "g1"), CgroupFD: fd, ProbeCgroupFD: -1}
			tc.run(t, be, sp, leaf)
		})
	}
}

// cgroupLeaf makes an empty cgroup under the delegated root and opens
// it. The cleanup removes it once the helper has left.
func cgroupLeaf(t *testing.T) (string, int) {
	t.Helper()
	dir := filepath.Join(cgRoot, fmt.Sprintf("hl-leaf-%d-%d", os.Getpid(), time.Now().UnixNano()%1_000_000))
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Close(fd)
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			if err := os.Remove(dir); err == nil || time.Now().After(deadline) {
				return
			}
		}
	})
	return dir, fd
}

// warmCtx is a context a Warm must finish within.
func warmCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// waitGone waits for pid to be reaped.
func waitGone(t *testing.T, pid int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("process %d is still there", pid)
		}
	}
}

// noNewChildren fails when a child this process did not have before is
// still there, alive or as a zombie nobody reaped, once a moment has
// passed.
func noNewChildren(t *testing.T, before []string) {
	t.Helper()
	had := map[string]bool{}
	for _, c := range before {
		had[strings.Fields(c)[0]] = true
	}
	var left []string
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		left = left[:0]
		for _, c := range children(t) {
			if !had[strings.Fields(c)[0]] {
				left = append(left, c)
			}
		}
		if len(left) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("children left behind: %v", left)
		}
	}
}

// children lists this process's children as "<pid> <comm> <state>".
func children(t *testing.T) []string {
	t.Helper()
	ents, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		// "<pid> (<comm>) <state> <ppid> ...", and comm may hold spaces.
		s := string(b)
		i := strings.LastIndexByte(s, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(s[i+1:])
		if len(f) < 2 || f[1] != fmt.Sprint(os.Getpid()) {
			continue
		}
		out = append(out, e.Name()+" "+s[strings.IndexByte(s, '(')+1:i]+" "+f[0])
	}
	return out
}
