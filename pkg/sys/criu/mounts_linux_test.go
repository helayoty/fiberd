//go:build linux

package criu_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/sys/criu"
)

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// mountNSChild starts a process in a mount namespace of its own that
// bind-mounts one regular file over another, and returns its pid and
// that mount point. The kernel refusing the namespace skips the test.
func mountNSChild(t *testing.T) (int, string) {
	t.Helper()
	dir := t.TempDir()
	src, dst, ready := filepath.Join(dir, "src"), filepath.Join(dir, "dst"), filepath.Join(dir, "ready")
	mustWrite(t, src, []byte("source"))
	mustWrite(t, dst, []byte("target"))
	cmd := exec.Command("sh", "-c",
		`mount --make-rprivate / && mount --bind "$1" "$2" && : > "$3" && exec sleep 60`, "sh", src, dst, ready)
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNS}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skipf("cannot make a mount namespace: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	waitFor(t, "the child's bind mount", 10*time.Second, func() bool {
		if err := syscall.Kill(cmd.Process.Pid, 0); err != nil {
			t.Fatalf("the child exited before mounting: %s", stderr.String())
		}
		_, err := os.Stat(ready)
		return err == nil
	})
	return cmd.Process.Pid, dst
}

// TestOwnMountNS checks that only a process in another mount namespace has
// one of its own, and a process that is not there has none.
func TestOwnMountNS(t *testing.T) {
	pid, _ := mountNSChild(t)
	cases := []struct {
		name string
		pid  int
		want bool
	}{
		{name: "ourselves", pid: os.Getpid()},
		{name: "a child in a new mount namespace", pid: pid, want: true},
		{name: "no such process", pid: math.MaxInt32},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := criu.OwnMountNS(tc.pid); got != tc.want {
				t.Fatalf("OwnMountNS(%d) = %v, want %v", tc.pid, got, tc.want)
			}
		})
	}
}

// TestDumpMounts checks that a tree in its own mount namespace has each of its
// single-file mounts named in the dump arguments and recorded beside
// the images, so RestoreMounts can hand them back by name. A tree in
// the caller's namespace needs nothing.
func TestDumpMounts(t *testing.T) {
	pid, mounted := mountNSChild(t)
	cases := []struct {
		name    string
		pid     int
		dir     func(t *testing.T) string
		wantNil bool
		wantIs  error
	}{
		{name: "a tree in the caller's namespace", pid: os.Getpid(), dir: func(t *testing.T) string { return t.TempDir() }, wantNil: true},
		{name: "file mounts are named and recorded", pid: pid, dir: func(t *testing.T) string { return filepath.Join(t.TempDir(), "images") }},
		{name: "the image directory cannot be made", pid: pid, dir: func(t *testing.T) string {
			f := filepath.Join(t.TempDir(), "file")
			mustWrite(t, f, nil)
			return filepath.Join(f, "images")
		}, wantIs: syscall.ENOTDIR},
		{name: "the sidecar cannot be written", pid: pid, dir: func(t *testing.T) string {
			dir := t.TempDir()
			mustMkdir(t, filepath.Join(dir, criu.MountsFile))
			return dir
		}, wantIs: syscall.EISDIR},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := tc.dir(t)
			args, err := criu.DumpMounts(tc.pid, dir)
			if tc.wantIs != nil {
				if !errors.Is(err, tc.wantIs) {
					t.Fatalf("DumpMounts = %q, %v, want %v", args, err, tc.wantIs)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantNil {
				if args != nil {
					t.Fatalf("DumpMounts = %q, want nil", args)
				}
				if _, err := os.Stat(filepath.Join(dir, criu.MountsFile)); err == nil {
					t.Fatal("a sidecar was written for a tree without a mount namespace")
				}
				return
			}
			if len(args) < 4 || args[0] != "--external" || args[1] != "mnt[]" {
				t.Fatalf("DumpMounts = %q, want --external mnt[] first and at least one file mount", args)
			}
			var recorded []struct{ Name, Path string }
			b, err := os.ReadFile(filepath.Join(dir, criu.MountsFile))
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(b, &recorded); err != nil {
				t.Fatal(err)
			}
			var restore []string
			found := false
			for i, fm := range recorded {
				if fm.Name != fmt.Sprintf("fm%d", i) {
					t.Fatalf("mount %d is named %q, want fm%d", i, fm.Name, i)
				}
				st, err := os.Stat(filepath.Join(fmt.Sprintf("/proc/%d/root", tc.pid), fm.Path))
				if err != nil || !st.Mode().IsRegular() {
					t.Fatalf("recorded mount %s is not a regular file in the tree: %v %v", fm.Path, st, err)
				}
				if want := "mnt[" + fm.Path + "]:" + fm.Name; args[2+2*i] != "--external" || args[3+2*i] != want {
					t.Fatalf("args for mount %d = %q, want --external %s", i, args[2+2*i:4+2*i], want)
				}
				restore = append(restore, "--external", "mnt["+fm.Name+"]:"+fm.Path)
				found = found || fm.Path == mounted
			}
			if !found {
				t.Fatalf("the bind-mounted file %s is not among %q", mounted, args)
			}
			for _, dirMount := range []string{"/", filepath.Dir(mounted)} {
				if slices.ContainsFunc(args, func(a string) bool { return strings.HasPrefix(a, "mnt["+dirMount+"]") }) {
					t.Fatalf("directory mount %s listed as a file mount in %q", dirMount, args)
				}
			}
			got, err := criu.RestoreMounts(dir, "/newroot")
			if want := append([]string{"--root", "/newroot", "--external", "mnt[]"}, restore...); err != nil || !slices.Equal(got, want) {
				t.Fatalf("RestoreMounts = %q, %v, want %q", got, err, want)
			}
		})
	}
}
