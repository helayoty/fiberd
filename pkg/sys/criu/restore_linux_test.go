//go:build linux

package criu_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/sys/criu"
)

// testCgroupLeaf makes a cgroup leaf under the delegated root the dev
// container provides and returns its path, or "" when there is none.
// The leaf is killed and removed at the end of the test.
func testCgroupLeaf(t *testing.T) string {
	t.Helper()
	root := os.Getenv("FIBERD_CGROUP_ROOT")
	if root == "" {
		root = "/sys/fs/cgroup/fiberd"
	}
	if f, err := os.OpenFile(filepath.Join(root, "cgroup.subtree_control"), os.O_WRONLY, 0); err != nil {
		return ""
	} else {
		_ = f.Close()
	}
	leaf := filepath.Join(root, "criu-test-"+strconv.Itoa(os.Getpid())+"-"+strings.Map(func(r rune) rune {
		if r == '/' || r == ' ' {
			return '_'
		}
		return r
	}, t.Name()))
	if err := os.Mkdir(leaf, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.WriteFile(filepath.Join(leaf, "cgroup.kill"), []byte("1"), 0o644)
		waitFor(t, "the cgroup leaf to empty", 10*time.Second, func() bool { return os.Remove(leaf) == nil })
	})
	return leaf
}

// TestRestoreWith: the tree is up once criu writes the pid file, which
// a stale one or a half-written one cannot fake. criu exiting first is
// the failure it reported, with its log. The context ends a restore
// that hangs. Extra arguments, descriptors and the cgroup all reach
// criu as promised.
func TestRestoreWith(t *testing.T) {
	common := []string{"restore", "--no-default-config", "-D", "DIR", "--pidfile", "DIR/restore.pid",
		"--ext-unix-sk", "--manage-cgroups=ignore", "-v2", "--log-file", "restore.log"}
	cases := []struct {
		name       string
		body       string
		extra      []string
		stalePID   string // written to restore.pid before the call
		file       string // handed to criu as descriptor 3
		cgroup     bool   // start criu in a cgroup leaf of the test's
		missingBin bool
		timeout    time.Duration
		wantPID    int // 0 for an error; -1 for the fake's own pid
		wantErr    []string
		wantNotErr []string
		wantIs     error
	}{
		{name: "the tree is up once the pid file is written",
			body: "echo 4242 > DIR/restore.pid; exec sleep 60", extra: []string{"--root", "/r"}, wantPID: 4242},
		{name: "a stale pid file is removed first and a half-written one retried", stalePID: "1\n",
			body: "echo garbage > DIR/restore.pid; sleep 0.05; echo 4242 > DIR/restore.pid; exec sleep 60", wantPID: 4242},
		{name: "criu fails with its log",
			body:    writeLog("restore.log", 10) + "exit 1",
			wantErr: []string{"criu restore failed: exit status 1", "\n  l03\n", "\n  l10"}, wantNotErr: []string{"l02"}},
		{name: "criu exits without a tree", body: "exit 0", wantErr: []string{"criu restore failed: exited"}},
		{name: "the context ends a hanging restore", body: "echo $$ > OUT; exec sleep 60", timeout: 100 * time.Millisecond,
			wantIs: context.DeadlineExceeded},
		{name: "binary missing", missingBin: true, wantErr: []string{"criu restore: "}, wantIs: fs.ErrNotExist},
		{name: "descriptor 3 reaches criu", file: "hello from fd 3",
			body: "cat <&3 > OUT; echo 4242 > DIR/restore.pid; exec sleep 60", wantPID: 4242},
		{name: "criu starts in the cgroup", cgroup: true, body: "echo $$ > DIR/restore.pid; exec sleep 60", wantPID: -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			args, out := filepath.Join(t.TempDir(), "args"), filepath.Join(dir, "out")
			o := criu.Options{Bin: filepath.Join(t.TempDir(), "criu")}
			if !tc.missingBin {
				o.Bin = fakeCriu(t, args, tc.body, dir, out)
			}
			if tc.stalePID != "" {
				mustWrite(t, filepath.Join(dir, "restore.pid"), []byte(tc.stalePID))
			}
			var files []*os.File
			if tc.file != "" {
				path := filepath.Join(dir, "fd3")
				mustWrite(t, path, []byte(tc.file))
				f, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = f.Close() }()
				files = append(files, f)
			}
			cgroupFD := -1
			leaf := ""
			if tc.cgroup {
				if leaf = testCgroupLeaf(t); leaf == "" {
					t.Skip("no writable delegated cgroup root")
				}
				f, err := os.Open(leaf)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = f.Close() }()
				cgroupFD = int(f.Fd())
			}
			ctx, cancel := context.WithCancel(context.Background())
			if tc.timeout > 0 {
				ctx, cancel = context.WithTimeout(context.Background(), tc.timeout)
			}
			defer cancel()

			r, err := o.RestoreWith(ctx, dir, cgroupFD, tc.extra, files)
			if r != nil {
				defer func() {
					_ = r.Cmd.Process.Kill()
					if werr := r.Wait(); werr == nil {
						t.Error("Wait = nil after killing criu, want its exit error")
					}
				}()
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("RestoreWith = %v, want %v", err, tc.wantIs)
			}
			for _, s := range tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), s) {
					t.Fatalf("RestoreWith = %q, want it to contain %q", err, s)
				}
			}
			for _, s := range tc.wantNotErr {
				if err != nil && strings.Contains(err.Error(), s) {
					t.Fatalf("RestoreWith = %q, want it without %q", err, s)
				}
			}
			if tc.wantPID == 0 {
				if err == nil {
					t.Fatal("RestoreWith = nil, want an error")
				}
				if tc.timeout > 0 {
					// The hanging fake was killed and reaped.
					b, rerr := os.ReadFile(out)
					if rerr != nil {
						t.Fatal(rerr)
					}
					pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
					waitFor(t, "the killed criu to go away", 5*time.Second, func() bool {
						return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
					})
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			wantPID := tc.wantPID
			if wantPID == -1 {
				wantPID = r.Cmd.Process.Pid
			}
			if r.PID != wantPID || r.Cmd == nil {
				t.Fatalf("Restored = pid %d cmd %v, want pid %d", r.PID, r.Cmd, wantPID)
			}
			want := slices.Clone(common)
			want[3], want[5] = dir, filepath.Join(dir, "restore.pid")
			want = append(want, tc.extra...)
			if got := recordedArgs(t, args); !slices.Equal(got, want) {
				t.Fatalf("criu ran with %q, want %q", got, want)
			}
			if tc.file != "" {
				if got, err := os.ReadFile(out); err != nil || string(got) != tc.file {
					t.Fatalf("criu read %q, %v from descriptor 3, want %q", got, err, tc.file)
				}
			}
			if tc.cgroup {
				procs, err := os.ReadFile(filepath.Join(leaf, "cgroup.procs"))
				if err != nil || !slices.Contains(strings.Fields(string(procs)), strconv.Itoa(r.PID)) {
					t.Fatalf("leaf holds %q, %v, want criu's pid %d", procs, err, r.PID)
				}
			}
		})
	}
}
