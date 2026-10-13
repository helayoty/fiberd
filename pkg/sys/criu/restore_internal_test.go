package criu

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestRestoreArgv checks the command line a restore runs: the named
// binary or criu on PATH, after the wrapper when there is one.
func TestRestoreArgv(t *testing.T) {
	cases := []struct {
		name string
		opt  Options
		args []string
		want []string
	}{
		{name: "criu on PATH", args: []string{"restore", "-D", "/img"}, want: []string{"criu", "restore", "-D", "/img"}},
		{name: "a named binary", opt: Options{Bin: "/opt/criu"}, args: []string{"check"}, want: []string{"/opt/criu", "check"}},
		{name: "through a wrapper", opt: Options{Bin: "/opt/criu", Wrap: []string{"wrap", "--sys"}}, args: []string{"restore"},
			want: []string{"wrap", "--sys", "/opt/criu", "restore"}},
		{name: "no arguments", opt: Options{Wrap: []string{"wrap"}}, want: []string{"wrap", "criu"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.opt.restoreArgv(tc.args); !slices.Equal(got, tc.want) {
				t.Fatalf("restoreArgv = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRestoreArgs checks the restore arguments the package promises, with
// the pid file beside the images and extra arguments last.
func TestRestoreArgs(t *testing.T) {
	common := []string{"restore", "--no-default-config", "-D", "/img", "--pidfile", "/img/restore.pid",
		"--ext-unix-sk", "--manage-cgroups=ignore", "-v2", "--log-file", "restore.log"}
	cases := []struct {
		name  string
		extra []string
		want  []string
	}{
		{name: "the common arguments", want: common},
		{name: "extra arguments last", extra: []string{"--root", "/r", "--inherit-fd", "fd[3]:x"},
			want: append(slices.Clone(common), "--root", "/r", "--inherit-fd", "fd[3]:x")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := restoreArgs("/img", tc.extra); !slices.Equal(got, tc.want) {
				t.Fatalf("restoreArgs = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestReadPidfile checks that only a whole positive pid counts as written.
func TestReadPidfile(t *testing.T) {
	cases := []struct {
		name    string
		content string
		missing bool
		want    int
		wantOK  bool
	}{
		{name: "missing", missing: true},
		{name: "empty"},
		{name: "not a number", content: "garbage\n"},
		{name: "zero", content: "0\n"},
		{name: "negative", content: "-3\n"},
		{name: "a pid with a newline", content: "4242\n", want: 4242, wantOK: true},
		{name: "a pid with spaces", content: " 7 ", want: 7, wantOK: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "restore.pid")
			if !tc.missing {
				if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, ok := readPidfile(path)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("readPidfile = %d, %v, want %d, %v", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// TestAwaitRestore checks that a written pid file is the tree being up, a
// half-written one is read again, criu ending first is its exit, and a
// finished context ends the wait.
func TestAwaitRestore(t *testing.T) {
	errExit := errors.New("exit status 1")
	cases := []struct {
		name      string
		content   string // the pid file before the call, "" for none
		later     string // the pid file written once the wait has started
		exit      error  // sent on done before the call
		ended     bool   // done carries exit
		cancelled bool
		want      int
		wantErr   error
		wantExit  bool // the error is "exited"
	}{
		{name: "the pid file is there", content: "4242\n", want: 4242},
		{name: "written while waiting", content: "42", later: "4242\n", want: 4242},
		{name: "criu failed first", ended: true, exit: errExit, wantErr: errExit},
		{name: "criu exited without a tree", ended: true, wantExit: true},
		{name: "a finished context", cancelled: true, wantErr: context.Canceled},
		{name: "the pid file wins over an exit", content: "4242\n", ended: true, exit: errExit, want: 4242},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pidfile := filepath.Join(t.TempDir(), "restore.pid")
			if tc.content != "" {
				if err := os.WriteFile(pidfile, []byte(tc.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan error, 1)
			if tc.ended {
				done <- tc.exit
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancelled {
				cancel()
			}
			type result struct {
				pid int
				err error
			}
			res := make(chan result, 1)
			go func() {
				pid, err := awaitRestore(ctx, pidfile, done)
				res <- result{pid, err}
			}()
			if tc.later != "" {
				if err := os.WriteFile(pidfile, []byte(tc.later), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			r := <-res
			switch {
			case tc.wantExit:
				if r.err == nil || r.err.Error() != "exited" {
					t.Fatalf("awaitRestore = %d, %v, want the exited error", r.pid, r.err)
				}
			case tc.wantErr != nil:
				if !errors.Is(r.err, tc.wantErr) {
					t.Fatalf("awaitRestore = %d, %v, want %v", r.pid, r.err, tc.wantErr)
				}
			default:
				if r.err != nil || r.pid != tc.want {
					t.Fatalf("awaitRestore = %d, %v, want %d", r.pid, r.err, tc.want)
				}
			}
		})
	}
}
