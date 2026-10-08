package criu_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/helayoty/fiberd/pkg/sys/criu"
)

// fakeCriu writes a shell script that stands in for the criu binary and
// returns its path. The script records criu's arguments, one per line,
// in the file at args and then runs body. The placeholders DIR and OUT
// in body are replaced by dir and out.
func fakeCriu(t *testing.T, args, body, dir, out string) string {
	t.Helper()
	body = strings.NewReplacer("DIR", dir, "OUT", out).Replace(body)
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + args + "'\n" + body + "\n"
	path := filepath.Join(t.TempDir(), "criu")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
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

// TestAvailable: `criu check` passing is availability, its output comes
// back on failure, and the binary is the one named or `criu` on PATH.
func TestAvailable(t *testing.T) {
	cases := []struct {
		name     string
		body     string // the fake's script; "" for no binary at all
		fromPath bool   // name no binary and find the fake as `criu` on PATH
		wantErr  string // substring of the error; "" for success
		wantIs   error
	}{
		{name: "check passes", body: "exit 0"},
		{name: "the default binary is criu on PATH", body: "exit 0", fromPath: true},
		{name: "check fails with its output", body: "echo 'Error (cr-check.c:1): no mnt_id'; exit 1",
			wantErr: "criu check: exit status 1: Error (cr-check.c:1): no mnt_id"},
		{name: "binary missing", wantIs: fs.ErrNotExist},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := filepath.Join(t.TempDir(), "args")
			o := criu.Options{Bin: filepath.Join(t.TempDir(), "criu")}
			if tc.body != "" {
				o.Bin = fakeCriu(t, args, tc.body, "", "")
			}
			if tc.fromPath {
				t.Setenv("PATH", filepath.Dir(o.Bin))
				o.Bin = ""
			}
			err := o.Available(context.Background())
			if tc.wantIs != nil {
				if !errors.Is(err, tc.wantIs) {
					t.Fatalf("Available = %v, want %v", err, tc.wantIs)
				}
				return
			}
			if tc.wantErr == "" && err != nil {
				t.Fatalf("Available = %v, want nil", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("Available = %v, want an error containing %q", err, tc.wantErr)
			}
			if got, want := recordedArgs(t, args), []string{"check", "--no-default-config"}; !slices.Equal(got, want) {
				t.Fatalf("criu ran with %q, want %q", got, want)
			}
		})
	}
}

// TestDumpWith: the image directory is made, criu gets the dump
// arguments the package promises, and a failure carries criu's output
// and the tail of its log.
func TestDumpWith(t *testing.T) {
	common := []string{"dump", "--no-default-config", "-t", "PID", "-D", "DIR",
		"--ext-unix-sk", "--manage-cgroups=ignore", "-v2", "--log-file", "dump.log"}
	cases := []struct {
		name         string
		pid          int
		leaveRunning bool
		extra        []string
		body         string
		log          int  // lines of dump.log the fake writes first; 0 for none
		dirUnderFile bool // the image directory has a regular file as parent
		cancelled    bool // the context is already done
		wantTail     []string
		wantErr      []string // substrings of the error; nil for success
		wantNotErr   []string
		wantIs       error
	}{
		{name: "the common arguments", pid: 1234, body: "exit 0"},
		{name: "leave running and extra arguments", pid: 7, leaveRunning: true,
			extra: []string{"--external", "unix[4242]"}, body: "exit 0",
			wantTail: []string{"--leave-running", "--external", "unix[4242]"}},
		{name: "failure carries the output and the last eight log lines", pid: 7, log: 10,
			body:    "echo 'Error: dump failed'; exit 1",
			wantErr: []string{"criu dump pid 7: exit status 1: Error: dump failed", "\n  l03\n", "\n  l10"}, wantNotErr: []string{"l02"}},
		{name: "a short log is kept whole", pid: 7, log: 2, body: "exit 1",
			wantErr: []string{"\n  l01\n  l02"}},
		{name: "failure without a log", pid: 7, body: "echo nope >&2; exit 3",
			wantErr: []string{"exit status 3: nope"}, wantNotErr: []string{"\n"}},
		{name: "the image directory cannot be made", dirUnderFile: true, body: "exit 0", wantIs: syscall.ENOTDIR},
		{name: "a finished context", cancelled: true, body: "exit 0", wantIs: context.Canceled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "images")
			if tc.dirUnderFile {
				if err := os.WriteFile(dir, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				dir = filepath.Join(dir, "images")
			}
			args := filepath.Join(t.TempDir(), "args")
			body := tc.body
			if tc.log > 0 {
				body = writeLog("dump.log", tc.log) + body
			}
			o := criu.Options{Bin: fakeCriu(t, args, body, dir, "")}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancelled {
				cancel()
			}
			err := o.DumpWith(ctx, tc.pid, dir, tc.leaveRunning, tc.extra)
			if tc.wantIs != nil {
				if !errors.Is(err, tc.wantIs) {
					t.Fatalf("DumpWith = %v, want %v", err, tc.wantIs)
				}
				return
			}
			if st, serr := os.Stat(dir); serr != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
				t.Fatalf("image directory: %v %v, want a private directory", st, serr)
			}
			if tc.wantErr == nil && err != nil {
				t.Fatalf("DumpWith = %v, want nil", err)
			}
			for _, s := range tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), s) {
					t.Fatalf("DumpWith = %q, want it to contain %q", err, s)
				}
			}
			for _, s := range tc.wantNotErr {
				if err != nil && strings.Contains(err.Error(), s) {
					t.Fatalf("DumpWith = %q, want it without %q", err, s)
				}
			}
			want := slices.Clone(common)
			want[3], want[5] = fmt.Sprint(tc.pid), dir
			want = append(want, tc.wantTail...)
			if got := recordedArgs(t, args); !slices.Equal(got, want) {
				t.Fatalf("criu ran with %q, want %q", got, want)
			}
		})
	}
}

// TestImageBytes: the pages files are summed and nothing else counts.
func TestImageBytes(t *testing.T) {
	cases := []struct {
		name    string
		files   map[string]int // name to size
		missing bool           // the directory does not exist
		want    uint64
	}{
		{name: "pages files summed, other images and names skipped",
			files: map[string]int{"pages-1.img": 100, "pages-2.img": 50, "pages-4.img": 0,
				"pagemap-1.img": 30, "pages-3.txt": 7, "inventory.img": 9, "mm-1.img": 11},
			want: 150},
		{name: "empty directory"},
		{name: "missing directory", missing: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.missing {
				dir = filepath.Join(dir, "none")
			}
			for name, size := range tc.files {
				if err := os.WriteFile(filepath.Join(dir, name), make([]byte, size), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := criu.ImageBytes(dir)
			if tc.missing {
				if !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("ImageBytes = %d, %v, want a missing-directory error", got, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("ImageBytes = %d, %v, want %d", got, err, tc.want)
			}
		})
	}
}
