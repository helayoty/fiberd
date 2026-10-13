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
	"sync"
	"syscall"
	"testing"

	"github.com/helayoty/fiberd/pkg/sys/criu"
)

// fakeCriu stands in for the criu binary behind Options.Commander. It
// records the arguments of every call and answers as the test says.
type fakeCriu struct {
	calls    [][]string
	out      []byte // what Output prints
	err      error  // what Output returns
	startErr error  // what Start returns
	pidfile  string // what Start writes to the restore pid file, "" for nothing
	exited   bool   // the restore has ended by the time Start returns
	exit     error  // what Wait returns for a restore that ended at Start
	files    []*os.File
	cgroupFD int
	proc     *fakeProcess
}

func (f *fakeCriu) Output(ctx context.Context, args []string) ([]byte, error) {
	f.calls = append(f.calls, args)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return f.out, f.err
}

func (f *fakeCriu) Start(args []string, files []*os.File, cgroupFD int) (criu.Process, error) {
	f.calls = append(f.calls, args)
	f.files, f.cgroupFD = files, cgroupFD
	if f.startErr != nil {
		return nil, f.startErr
	}
	if f.pidfile != "" {
		i := slices.Index(args, "--pidfile")
		if i < 0 || i+1 >= len(args) {
			return nil, fmt.Errorf("no --pidfile in %q", args)
		}
		if err := os.WriteFile(args[i+1], []byte(f.pidfile), 0o600); err != nil {
			return nil, err
		}
	}
	f.proc = &fakeProcess{pid: 777, released: make(chan struct{})}
	if f.exited {
		f.proc.release(f.exit)
	}
	return f.proc, nil
}

// fakeProcess is a started restore whose Wait blocks until released.
type fakeProcess struct {
	pid      int
	mu       sync.Mutex
	killed   bool
	exit     error
	once     sync.Once
	released chan struct{}
}

func (p *fakeProcess) Pid() int { return p.pid }

func (p *fakeProcess) Kill() error {
	p.mu.Lock()
	p.killed = true
	p.mu.Unlock()
	p.release(errors.New("signal: killed"))
	return nil
}

func (p *fakeProcess) Wait() error {
	<-p.released
	return p.exit
}

// release ends the process with err, once.
func (p *fakeProcess) release(err error) {
	p.once.Do(func() {
		p.exit = err
		close(p.released)
	})
}

func (p *fakeProcess) wasKilled() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.killed
}

// writeLog writes n numbered lines, l01 and up, to the log file name
// under dir.
func writeLog(t *testing.T, dir, name string, n int) {
	t.Helper()
	var lines []string
	for i := 1; i <= n; i++ {
		lines = append(lines, fmt.Sprintf("l%02d", i))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// wantErrorWith fails unless err contains every substring of want and
// none of notWant, or is nil when want is nil.
func wantErrorWith(t *testing.T, what string, err error, want, notWant []string) {
	t.Helper()
	if want == nil && err != nil {
		t.Fatalf("%s = %v, want nil", what, err)
	}
	for _, s := range want {
		if err == nil || !strings.Contains(err.Error(), s) {
			t.Fatalf("%s = %q, want it to contain %q", what, err, s)
		}
	}
	for _, s := range notWant {
		if err != nil && strings.Contains(err.Error(), s) {
			t.Fatalf("%s = %q, want it without %q", what, err, s)
		}
	}
}

// TestAvailable checks that `criu check` passing is availability, its output
// comes back on failure, and the context reaches the command.
func TestAvailable(t *testing.T) {
	cases := []struct {
		name      string
		out       string
		err       error
		cancelled bool   // the context is already done
		wantErr   string // substring of the error, "" for success
		wantIs    error
	}{
		{name: "check passes"},
		{name: "check fails with its output", out: "Error (cr-check.c:1): no mnt_id\n", err: errors.New("exit status 1"),
			wantErr: "criu check: exit status 1: Error (cr-check.c:1): no mnt_id"},
		{name: "binary missing", err: fs.ErrNotExist, wantIs: fs.ErrNotExist},
		{name: "a finished context", cancelled: true, wantIs: context.Canceled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeCriu{out: []byte(tc.out), err: tc.err}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancelled {
				cancel()
			}
			err := criu.Options{Commander: fake}.Available(ctx)
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("Available = %v, want %v", err, tc.wantIs)
			}
			if tc.wantErr == "" && tc.wantIs == nil && err != nil {
				t.Fatalf("Available = %v, want nil", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("Available = %v, want an error containing %q", err, tc.wantErr)
			}
			if want := [][]string{{"check", "--no-default-config"}}; !slices.EqualFunc(fake.calls, want, slices.Equal) {
				t.Fatalf("criu ran with %q, want %q", fake.calls, want)
			}
		})
	}
}

// TestDumpWith checks that the image directory is made, criu gets the dump
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
		out          string
		err          error
		log          int  // lines of dump.log written before the call, 0 for none
		dirUnderFile bool // the image directory has a regular file as parent
		cancelled    bool // the context is already done
		wantTail     []string
		wantErr      []string // substrings of the error, nil for success
		wantNotErr   []string
		wantIs       error
	}{
		{name: "the common arguments", pid: 1234},
		{name: "leave running and extra arguments", pid: 7, leaveRunning: true,
			extra:    []string{"--external", "unix[4242]"},
			wantTail: []string{"--leave-running", "--external", "unix[4242]"}},
		{name: "failure carries the output and the last eight log lines", pid: 7, log: 10,
			out: "Error: dump failed\n", err: errors.New("exit status 1"),
			wantErr: []string{"criu dump pid 7: exit status 1: Error: dump failed", "\n  l03\n", "\n  l10"}, wantNotErr: []string{"l02"}},
		{name: "a short log is kept whole", pid: 7, log: 2, err: errors.New("exit status 1"),
			wantErr: []string{"\n  l01\n  l02"}},
		{name: "failure without a log", pid: 7, out: "nope\n", err: errors.New("exit status 3"),
			wantErr: []string{"exit status 3: nope"}, wantNotErr: []string{"\n"}},
		{name: "the image directory cannot be made", dirUnderFile: true, wantIs: syscall.ENOTDIR},
		{name: "a finished context", cancelled: true, wantIs: context.Canceled, wantErr: []string{"criu dump pid 0: "}},
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
			if tc.log > 0 {
				writeLog(t, dir, "dump.log", tc.log)
			}
			fake := &fakeCriu{out: []byte(tc.out), err: tc.err}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancelled {
				cancel()
			}
			err := criu.Options{Commander: fake}.DumpWith(ctx, tc.pid, dir, tc.leaveRunning, tc.extra)
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("DumpWith = %v, want %v", err, tc.wantIs)
			}
			if tc.dirUnderFile {
				if len(fake.calls) != 0 {
					t.Fatalf("criu ran with %q, want no call without an image directory", fake.calls)
				}
				return
			}
			if st, serr := os.Stat(dir); serr != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
				t.Fatalf("image directory: %v %v, want a private directory", st, serr)
			}
			wantErrorWith(t, "DumpWith", err, tc.wantErr, tc.wantNotErr)
			want := slices.Clone(common)
			want[3], want[5] = fmt.Sprint(tc.pid), dir
			want = append(want, tc.wantTail...)
			if len(fake.calls) != 1 || !slices.Equal(fake.calls[0], want) {
				t.Fatalf("criu ran with %q, want %q", fake.calls, want)
			}
		})
	}
}

// TestRestoreWith checks that the tree is up once criu writes the pid file,
// which a stale one or a half-written one cannot fake. criu exiting first is
// the failure it reported, with its log. The context ends a restore that
// hangs. Extra arguments, descriptors and the cgroup all reach the
// commander, and Wait is criu's exit.
func TestRestoreWith(t *testing.T) {
	common := []string{"restore", "--no-default-config", "-D", "DIR", "--pidfile", "DIR/restore.pid",
		"--ext-unix-sk", "--manage-cgroups=ignore", "-v2", "--log-file", "restore.log"}
	errExit := errors.New("exit status 1")
	cases := []struct {
		name       string
		fake       fakeCriu
		extra      []string
		stalePID   string // written to restore.pid before the call
		withFile   bool   // hand a descriptor to criu
		cgroupFD   int
		log        int  // lines of restore.log written before the call
		cancelled  bool // the context is already done
		wantPID    int  // 0 for an error
		wantErr    []string
		wantNotErr []string
		wantIs     error
		wantKilled bool
	}{
		{name: "the tree is up once the pid file is written", fake: fakeCriu{pidfile: "4242\n"},
			extra: []string{"--root", "/r"}, cgroupFD: -1, wantPID: 4242},
		{name: "a stale pid file is removed first", fake: fakeCriu{exited: true}, stalePID: "1\n", cgroupFD: -1,
			wantErr: []string{"criu restore failed: exited"}},
		{name: "a half-written pid file is not a tree", fake: fakeCriu{pidfile: "garbage\n", exited: true, exit: errExit}, cgroupFD: -1,
			wantErr: []string{"criu restore failed: exit status 1"}},
		{name: "criu fails with its log", fake: fakeCriu{exited: true, exit: errExit}, log: 10, cgroupFD: -1,
			wantErr: []string{"criu restore failed: exit status 1", "\n  l03\n", "\n  l10"}, wantNotErr: []string{"l02"}},
		{name: "criu exits without a tree", fake: fakeCriu{exited: true}, cgroupFD: -1,
			wantErr: []string{"criu restore failed: exited"}},
		{name: "the context ends a hanging restore", cancelled: true, cgroupFD: -1,
			wantIs: context.Canceled, wantErr: []string{"context canceled"}, wantKilled: true},
		{name: "criu cannot start", fake: fakeCriu{startErr: fs.ErrNotExist}, cgroupFD: -1,
			wantErr: []string{"criu restore: "}, wantIs: fs.ErrNotExist},
		{name: "descriptors and the cgroup reach the commander", fake: fakeCriu{pidfile: "4242\n"},
			withFile: true, cgroupFD: 7, wantPID: 4242},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.stalePID != "" {
				if err := os.WriteFile(filepath.Join(dir, "restore.pid"), []byte(tc.stalePID), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.log > 0 {
				writeLog(t, dir, "restore.log", tc.log)
			}
			var files []*os.File
			if tc.withFile {
				f, err := os.Open(os.DevNull)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = f.Close() }()
				files = []*os.File{f}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancelled {
				cancel()
			}
			fake := tc.fake
			r, err := criu.Options{Commander: &fake}.RestoreWith(ctx, dir, tc.cgroupFD, tc.extra, files)
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("RestoreWith = %v, want %v", err, tc.wantIs)
			}
			wantErrorWith(t, "RestoreWith", err, tc.wantErr, tc.wantNotErr)
			if fake.proc != nil && fake.proc.wasKilled() != tc.wantKilled {
				t.Fatalf("criu killed: %v, want %v", fake.proc.wasKilled(), tc.wantKilled)
			}
			if fake.startErr != nil {
				return
			}
			want := slices.Clone(common)
			want[3], want[5] = dir, filepath.Join(dir, "restore.pid")
			want = append(want, tc.extra...)
			if len(fake.calls) != 1 || !slices.Equal(fake.calls[0], want) {
				t.Fatalf("criu ran with %q, want %q", fake.calls, want)
			}
			if !slices.Equal(fake.files, files) || fake.cgroupFD != tc.cgroupFD {
				t.Fatalf("criu started with files %v in cgroup %d, want %v and %d", fake.files, fake.cgroupFD, files, tc.cgroupFD)
			}
			if tc.wantPID == 0 {
				if r != nil {
					t.Fatalf("Restored = %+v with an error, want nil", r)
				}
				return
			}
			if r == nil || r.PID != tc.wantPID || r.Process != fake.proc {
				t.Fatalf("Restored = %+v, want pid %d and the started process", r, tc.wantPID)
			}
			fake.proc.release(errExit)
			if werr := r.Wait(); !errors.Is(werr, errExit) {
				t.Fatalf("Wait = %v, want criu's exit %v", werr, errExit)
			}
		})
	}
}

// TestImageBytes checks that the pages files are summed and nothing else
// counts.
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
