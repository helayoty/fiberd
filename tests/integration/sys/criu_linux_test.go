//go:build linux && integration

package systest

import (
	"context"
	"errors"
	"fmt"
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

// fakeCriu writes a shell script that stands in for the criu binary and
// returns its path. The script records criu's arguments, one per line,
// in the file at args and then runs body. The placeholders DIR and OUT
// in body are replaced by dir and out.
func fakeCriu(t *testing.T, args, body, dir, out string) string {
	t.Helper()
	body = strings.NewReplacer("DIR", dir, "OUT", out).Replace(body)
	// It is criu 4.2.1 unless the body answers --version itself first.
	script := "#!/bin/sh\n" + versionLine(body) + "printf '%s\\n' \"$@\" > '" + args + "'\n" + body + "\n"
	path := filepath.Join(t.TempDir(), "criu")
	mustWrite(t, path, []byte(script))
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// versionLine answers `criu --version` as 4.2.1, unless body starts with
// its own answer.
func versionLine(body string) string {
	if strings.HasPrefix(body, "[ \"$1\" = --version ]") {
		return ""
	}
	return "[ \"$1\" = --version ] && { echo 'Version: 4.2.1'; exit 0; }\n"
}

// recordedArgs reads the argument list a fake criu wrote.
func recordedArgs(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the fake criu did not record its arguments: %v", err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

// writeLog is a script fragment that writes n numbered lines, l01 and
// up, to the log file name under DIR.
func writeLog(name string, n int) string {
	var lines []string
	for i := 1; i <= n; i++ {
		lines = append(lines, fmt.Sprintf("l%02d", i))
	}
	return "printf '" + strings.Join(lines, `\n`) + `\n' > DIR/` + name + "\n"
}

// TestCriuCheckAndDump checks the default commander's run of `criu check`
// and `criu dump`: the binary is the one named or criu on PATH, the
// arguments reach it, its output comes back on failure, and a finished
// context ends it.
func TestCriuCheckAndDump(t *testing.T) {
	cases := []struct {
		name      string
		dump      bool   // DumpWith rather than Available
		body      string // the fake's script, "" for no binary at all
		fromPath  bool   // name no binary and find the fake as `criu` on PATH
		cancelled bool
		wantArgs  []string
		wantErr   string // substring of the error, "" for success
		wantIs    error
	}{
		{name: "check passes", body: "exit 0", wantArgs: []string{"check", "--no-default-config"}},
		{name: "the default binary is criu on PATH", body: "exit 0", fromPath: true, wantArgs: []string{"check", "--no-default-config"}},
		{name: "check fails with its output", body: "echo 'Error (cr-check.c:1): no mnt_id'; exit 1",
			wantArgs: []string{"check", "--no-default-config"},
			wantErr:  "criu check: exit status 1: Error (cr-check.c:1): no mnt_id"},
		{name: "a criu older than 4.2 is refused before the check", body: "[ \"$1\" = --version ] && { echo 'Version: 4.1.1'; exit 0; }\nexit 0",
			wantArgs: []string{"--version"}, wantErr: "criu 4.1 is older than 4.2"},
		{name: "binary missing", wantIs: fs.ErrNotExist},
		{name: "dump arguments reach criu and stderr comes back", dump: true, body: "echo nope >&2; exit 3",
			wantArgs: []string{"dump", "--no-default-config", "-t", "7", "-D", "DIR", "--ext-unix-sk", "--manage-cgroups=ignore",
				"-v2", "--log-file", "dump.log", "--leave-running", "--external", "unix[4242]"},
			wantErr: "criu dump pid 7: exit status 3: nope"},
		{name: "a finished context", dump: true, body: "exit 0", cancelled: true, wantIs: context.Canceled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "images")
			args := filepath.Join(t.TempDir(), "args")
			o := criu.Options{Bin: filepath.Join(t.TempDir(), "criu")}
			if tc.body != "" {
				o.Bin = fakeCriu(t, args, tc.body, dir, "")
			}
			if tc.fromPath {
				t.Setenv("PATH", filepath.Dir(o.Bin))
				o.Bin = ""
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancelled {
				cancel()
			}
			var err error
			if tc.dump {
				err = o.DumpWith(ctx, 7, dir, true, []string{"--external", "unix[4242]"})
			} else {
				err = o.Available(ctx)
			}
			if tc.wantIs != nil {
				if !errors.Is(err, tc.wantIs) {
					t.Fatalf("criu = %v, want %v", err, tc.wantIs)
				}
				return
			}
			if tc.wantErr == "" && err != nil {
				t.Fatalf("criu = %v, want nil", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("criu = %v, want an error containing %q", err, tc.wantErr)
			}
			want := slices.Clone(tc.wantArgs)
			if i := slices.Index(want, "DIR"); i >= 0 {
				want[i] = dir
			}
			if got := recordedArgs(t, args); !slices.Equal(got, want) {
				t.Fatalf("criu ran with %q, want %q", got, want)
			}
		})
	}
}

// TestCriuRestoreWith checks the default commander's run of `criu restore`
// as a process: the tree is up once the pid file is written, criu exiting
// first is the failure it reported with its log, the context kills a
// restore that hangs, and the wrapper, descriptors and the cgroup all reach
// criu as promised.
func TestCriuRestoreWith(t *testing.T) {
	common := []string{"restore", "--no-default-config", "-D", "DIR", "--pidfile", "DIR/restore.pid",
		"--ext-unix-sk", "--manage-cgroups=ignore", "-v2", "--log-file", "restore.log"}
	cases := []struct {
		name       string
		body       string
		extra      []string
		wrap       bool   // run through a wrapper that records itself and execs criu
		stalePID   string // written to restore.pid before the call
		file       string // handed to criu as descriptor 3
		cgroup     bool   // start criu in a cgroup leaf of the test's
		missingBin bool
		timeout    time.Duration
		wantPID    int // 0 for an error, -1 for the fake's own pid
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
		{name: "the wrapper runs first and execs criu", wrap: true,
			body: "echo 4242 > DIR/restore.pid; exec sleep 60", wantPID: 4242},
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
			if tc.wrap {
				o.Wrap = []string{"sh", "-c", `echo wrapped > "` + out + `"; exec "$@"`, "wrap"}
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
			var leaf string
			if tc.cgroup {
				d := testLeaf(t)
				leaf = d.Path
				f, err := d.Open()
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
					_ = r.Process.Kill()
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
				wantPID = r.Process.Pid()
			}
			if r.PID != wantPID || r.Process == nil {
				t.Fatalf("Restored = pid %d process %v, want pid %d", r.PID, r.Process, wantPID)
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
			if tc.wrap {
				if got, err := os.ReadFile(out); err != nil || string(got) != "wrapped\n" {
					t.Fatalf("the wrapper left %q, %v, want its mark", got, err)
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
