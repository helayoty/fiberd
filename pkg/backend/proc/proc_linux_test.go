//go:build linux

package proc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
)

// TestExitRightAfterCloneIsReported covers a zygote that answers CLONE and
// reports the fiber's exit in one write. The reader must have the fiber
// registered before it reads the EXITED line, or the exit is lost and
// the host waits forever for it. A CLONED that arrives after the caller
// gave up names a fiber nobody will hear of.
func TestExitRightAfterCloneIsReported(t *testing.T) {
	cases := []struct {
		name     string
		script   string
		deadline time.Duration // the caller's, 0 for generous
		wantErr  error         // from Clone
		wantExit bool          // an Exit for the fence
	}{
		{name: "exit right after CLONED", script: "early", wantExit: true},
		{name: "normal CLONED then later EXITED", script: "late", wantExit: true},
		{name: "CLONED after the caller gave up", script: "overdue", deadline: 50 * time.Millisecond, wantErr: context.DeadlineExceeded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakes(t)
			b := f.open(t, Options{})
			pid := impossiblePID(t)
			w, zy, workDir := f.warm(t, b, tc.script, pid)

			const fence = "g/1-1"
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if tc.deadline > 0 {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), tc.deadline)
			}
			defer cancel()
			fb, err := b.Clone(ctx, w.ID, backend.FiberSpec{Generation: 1, Fence: fence, Endpoint: filepath.Join(workDir, "ep.sock"), CgroupFD: -1, Deadline: time.Second})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Clone: err = %v, want %v", err, tc.wantErr)
			}
			if err == nil && (fb.ID != fence || fb.PID != pid) {
				t.Fatalf("Clone = %+v, want fence %s pid %d", fb, fence, pid)
			}

			want := backend.Exit{FiberID: fence, Status: "exit:3"}
			if tc.wantExit {
				if got := waitExit(t, b); got != want {
					t.Fatalf("exit = %+v, want %+v", got, want)
				}
			} else {
				// The overdue zygote answers now, then reports a device
				// line, which the reader handles after the lines before
				// it. Nothing was registered for the late CLONED, so the
				// EXITED after it finds no fiber and reports nothing.
				close(zy.gate)
				waitFor(t, "the device line after the late answer", func() bool {
					_, _, ok := b.WarmDevice(w.ID)
					return ok
				})
				if n := len(b.exits); n != 0 {
					t.Fatalf("%d exits reported for a fiber the caller never got", n)
				}
			}

			// The fiber is gone either way. There is nothing to signal,
			// and a Kill is not a kill(2) of some pid.
			if err := b.Kill(fence); err != nil && !errors.Is(err, syscall.ESRCH) {
				t.Fatalf("Kill after exit: %v", err)
			}
			b.mu.Lock()
			nf, np := len(b.fibers), len(b.byPID)
			b.mu.Unlock()
			if nf != 0 || np != 0 {
				t.Fatalf("fibers=%d byPID=%d left registered, want none", nf, np)
			}
		})
	}
}

// TestKillNeverSignalsAnUnknownPID checks that Kill refuses a fiber whose
// host pid the backend does not know, never guessing. kill(2) of 0 is this
// process group, and of a negative number a whole group.
func TestKillNeverSignalsAnUnknownPID(t *testing.T) {
	cases := []struct {
		name    string
		pid     int
		known   bool // the fence is registered
		wantErr bool
	}{
		{name: "unknown fence", known: false},
		{name: "pid 0", pid: 0, known: true, wantErr: true},
		{name: "negative pid", pid: -1, known: true, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &Backend{fibers: map[string]*fiber{}, byPID: map[pidKey]*fiber{}}
			if tc.known {
				b.fibers["f"] = &fiber{id: "f", pid: tc.pid}
			}
			err := b.Kill("f")
			if (err != nil) != tc.wantErr {
				t.Fatalf("Kill = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}

// TestParseCloned checks that the CLONED line names the fiber by fence and pid.
// Fields after those two are ignored.
func TestParseCloned(t *testing.T) {
	cases := []struct {
		name   string
		line   string
		wantOK bool
		fence  string
		pid    int
	}{
		{name: "fence and pid", line: "CLONED g/1-1 4242", wantOK: true, fence: "g/1-1", pid: 4242},
		{name: "trailing fields are ignored", line: "CLONED g/1-2 7 pidns=1 future", wantOK: true, fence: "g/1-2", pid: 7},
		{name: "no pid", line: "CLONED g/1-8"},
		{name: "pid is not a number", line: "CLONED g/1-9 abc"},
		{name: "pid zero is no fiber", line: "CLONED g/1-10 0"},
		{name: "negative pid is no fiber", line: "CLONED g/1-11 -5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fields := strings.Fields(tc.line)
			fence, pid, ok := parseCloned(fields[1:])
			if ok != tc.wantOK {
				t.Fatalf("parseCloned(%q) ok = %v, want %v", tc.line, ok, tc.wantOK)
			}
			if ok && (fence != tc.fence || pid != tc.pid) {
				t.Fatalf("parseCloned(%q) = %q %d, want %q %d", tc.line, fence, pid, tc.fence, tc.pid)
			}
		})
	}
}

// TestRunDirPair checks that the RUNDIR line names the directory holding
// every grant's run directory and the grant's own. A run directory the
// fiber could not be told about safely is refused before any warm.
func TestRunDirPair(t *testing.T) {
	cases := []struct {
		name, workDir string
		parent, own   string
		wantErr       string
	}{
		{name: "run directory under /run", workDir: "/run/fiberd/g1", parent: "/run/fiberd", own: "/run/fiberd/g1"},
		{name: "unclean path is cleaned", workDir: "/tmp//fz/g1/", parent: "/tmp/fz", own: "/tmp/fz/g1"},
		{name: "relative", workDir: "run/g1", wantErr: "absolute"},
		{name: "whitespace", workDir: "/run/fib erd/g1", wantErr: "whitespace"},
		{name: "right under the root", workDir: "/g1", wantErr: "right under /"},
		{name: "the root itself", workDir: "/", wantErr: "right under /"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parent, own, err := runDirPair(tc.workDir)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("runDirPair(%q) = %q %q %v, want an error mentioning %q", tc.workDir, parent, own, err, tc.wantErr)
				}
				return
			}
			if err != nil || parent != tc.parent || own != tc.own {
				t.Fatalf("runDirPair(%q) = %q %q %v, want %q %q", tc.workDir, parent, own, err, tc.parent, tc.own)
			}
		})
	}
}

// TestRunDirInherit checks that a checkpoint recording its run directory
// mount is restored with it bound to the resuming grant's directory. One
// without the record takes nothing.
func TestRunDirInherit(t *testing.T) {
	cases := []struct {
		name    string
		record  string // the file's content, "" for no file
		workDir string
		want    []string
		wantMP  string
		wantErr string
	}{
		{name: "no record", workDir: "/run/fiberd/g2"},
		{name: "record binds the resuming grant's directory", record: `{"mountpoint":"/tmp/fz-a/g1"}`, workDir: "/run/fiberd/g2",
			want: []string{"--external", "mnt[rundir]:/run/fiberd/g2"}, wantMP: "/tmp/fz-a/g1"},
		{name: "malformed record", record: `{"mountpoint":"relative"}`, workDir: "/run/fiberd/g2", wantErr: "malformed"},
		{name: "record without a run directory to bind", record: `{"mountpoint":"/tmp/fz-a/g1"}`, wantErr: "WorkDir"},
		{name: "record cannot be read", record: "dir", workDir: "/run/fiberd/g2", wantErr: "is a directory"},
		{name: "run directory cannot be made", record: `{"mountpoint":"/tmp/fz-a/g1"}`, workDir: "file/g2", wantErr: "not a directory"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			switch tc.record {
			case "":
			case "dir":
				if err := os.Mkdir(filepath.Join(dir, runDirFile), 0o755); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(filepath.Join(dir, runDirFile), []byte(tc.record), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			workDir := tc.workDir
			if workDir != "" {
				base := t.TempDir()
				if strings.HasPrefix(workDir, "file/") {
					// The run directory's parent is a regular file.
					if err := os.WriteFile(filepath.Join(base, "file"), nil, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				workDir = filepath.Join(base, workDir)
				for i := range tc.want {
					tc.want[i] = strings.Replace(tc.want[i], tc.workDir, workDir, 1)
				}
			}
			args, mp, err := runDirInherit(dir, workDir)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("runDirInherit = %v %q %v, want an error mentioning %q", args, mp, err, tc.wantErr)
				}
				return
			}
			if err != nil || mp != tc.wantMP || strings.Join(args, " ") != strings.Join(tc.want, " ") {
				t.Fatalf("runDirInherit = %v %q %v, want %v %q", args, mp, err, tc.want, tc.wantMP)
			}
			if mp != "" {
				if st, err := os.Stat(workDir); err != nil || !st.IsDir() {
					t.Fatalf("the resuming grant's directory %s was not made: %v", workDir, err)
				}
			}
		})
	}
}

// TestExitLandsOnTheReportingZygotesFiber covers two zygotes, each the init of
// a pid namespace, both report pid N for their fiber. An EXITED from one
// must end that one's fiber and leave the other's alone.
func TestExitLandsOnTheReportingZygotesFiber(t *testing.T) {
	cases := []struct {
		name     string
		scripts  [2]string // zygote 1 and 2. "late" exits, "never" does not
		wantExit int       // which zygote's fiber exits (1 or 2)
	}{
		{name: "first zygote's fiber exits", scripts: [2]string{"late", "never"}, wantExit: 1},
		{name: "second zygote's fiber exits", scripts: [2]string{"never", "late"}, wantExit: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakes(t)
			b := f.open(t, Options{})
			pid := impossiblePID(t)
			fences := [2]string{"g1/1-1", "g2/1-1"}
			for i := range fences {
				w, _, workDir := f.warmFor(t, b, "g"+strconv.Itoa(i+1), tc.scripts[i], pid)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_, err := b.Clone(ctx, w.ID, backend.FiberSpec{Generation: 1, Fence: fences[i], Endpoint: filepath.Join(workDir, "ep.sock"), CgroupFD: -1, Deadline: time.Second})
				cancel()
				if err != nil {
					t.Fatalf("clone %s: %v", fences[i], err)
				}
			}
			want := fences[tc.wantExit-1]
			other := fences[2-tc.wantExit]
			if got := waitExit(t, b); got.FiberID != want {
				t.Fatalf("exit for %s, want %s", got.FiberID, want)
			}
			b.mu.Lock()
			_, stillThere := b.fibers[other]
			b.mu.Unlock()
			if !stillThere {
				t.Fatalf("%s was finished by %s's exit", other, want)
			}
		})
	}
}

// TestAbandon checks that Clone giving up without a fiber leaves nothing behind
// whether the reader has answered yet or not. Whoever takes the pending
// entry sends once, so an abandon that finds the entry gone waits for
// that one send.
func TestAbandon(t *testing.T) {
	cases := []struct {
		name  string
		taken bool // the reader took the entry before abandon ran
		late  bool // and sends its reply only once abandon is waiting
	}{
		{name: "still pending, nobody will answer", taken: false},
		{name: "taken and answered already", taken: true},
		{name: "taken, answer in flight", taken: true, late: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &Backend{fibers: map[string]*fiber{}, byPID: map[pidKey]*fiber{}}
			z := &zygote{id: "g", pend: map[string]*pending{}}
			reply := make(chan cloneResult, 1)
			const fence = "g/1-1"
			done := make(chan struct{})
			if !tc.taken {
				z.pend[fence] = &pending{ch: reply}
			} else {
				fb := &fiber{id: fence, zpid: 7, warmID: z.id}
				b.fibers[fb.id] = fb
				b.byPID[pidKey{z.id, 7}] = fb
				send := func() { reply <- cloneResult{pid: 7, f: fb} }
				if tc.late {
					// The reply comes while abandon blocks on it.
					go func() {
						select {
						case <-done:
							t.Error("abandon returned before the reply")
						case <-time.After(20 * time.Millisecond):
						}
						send()
					}()
				} else {
					send()
				}
			}
			go func() { b.abandon(z, fence, reply); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("abandon did not return")
			}
			b.mu.Lock()
			nf, np, npend := len(b.fibers), len(b.byPID), len(z.pend)
			b.mu.Unlock()
			if nf != 0 || np != 0 || npend != 0 {
				t.Fatalf("fibers=%d byPID=%d pending=%d left, want none", nf, np, npend)
			}
		})
	}
}

// TestClonedPIDWithLauncher checks that the pid a launcher's zygote reports
// is the container's number, never a host pid to signal. Until Clone has
// translated it the fiber has none.
func TestClonedPIDWithLauncher(t *testing.T) {
	cases := []struct {
		name     string
		launcher Launcher
		wantPID  int
		killErr  bool
	}{
		{name: "no launcher keeps the reported pid", wantPID: 77, killErr: false},
		{name: "launcher leaves the host pid unknown", launcher: nopLauncher{}, wantPID: 0, killErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &Backend{opt: Options{Launcher: tc.launcher}, fibers: map[string]*fiber{}, byPID: map[pidKey]*fiber{}}
			z := &zygote{id: "g", pend: map[string]*pending{}}
			reply := make(chan cloneResult, 1)
			z.pend["f"] = &pending{ch: reply}
			b.cloned(z, "f", cloneResult{pid: 77})
			res := <-reply
			if res.f.pid != tc.wantPID || res.f.zpid != 77 {
				t.Fatalf("pid=%d zpid=%d, want pid %d zpid 77", res.f.pid, res.f.zpid, tc.wantPID)
			}
			// kill(2) of 77 would reach a real process. With a launcher the
			// fiber has no host pid and Kill refuses. Without one the pid
			// is the host's, so this case stops short of signalling.
			if tc.launcher != nil {
				if err := b.Kill("f"); (err != nil) != tc.killErr {
					t.Fatalf("Kill = %v, want error %v", err, tc.killErr)
				}
			}
		})
	}
}

// TestParkNeedsTheLaunchersZygote checks that a launcher's fiber whose zygote
// is gone cannot be dumped, since only the launcher names its container's
// mounts for criu.
func TestParkNeedsTheLaunchersZygote(t *testing.T) {
	cases := []struct {
		name string
		pid  int    // the fiber's host pid, 0 for unknown
		want string // in the error
	}{
		{name: "zygote gone", pid: 1 << 30, want: "zygote is gone"},
		{name: "host pid unknown", pid: 0, want: "no host pid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &Backend{opt: Options{Launcher: nopLauncher{}}, tier: core.TierCheckpoint,
				zygotes: map[string]*zygote{}, fibers: map[string]*fiber{}, byPID: map[pidKey]*fiber{}}
			b.fibers["f"] = &fiber{id: "f", pid: tc.pid, warmID: "gone"}
			err := b.Park(context.Background(), "f", backend.ParkSpec{Dir: t.TempDir()})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Park = %v, want an error mentioning %q", err, tc.want)
			}
		})
	}
}

// TestHeldByLiveProcess checks that the holder file beside a restore root says
// whether another live fiberd has it. Anything else means nobody does.
func TestHeldByLiveProcess(t *testing.T) {
	cases := []struct {
		name    string
		content string // "" for no file
		want    bool
	}{
		{name: "no file", want: false},
		{name: "a live process that is not us", content: "1\n", want: true},
		{name: "ourselves", content: strconv.Itoa(os.Getpid()), want: false},
		{name: "a dead pid", content: strconv.Itoa(impossiblePID(t)), want: false},
		{name: "garbage", content: "none", want: false},
		{name: "zero", content: "0", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pidfile := filepath.Join(t.TempDir(), "root.pid")
			if tc.content != "" {
				if err := os.WriteFile(pidfile, []byte(tc.content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if got := heldByLiveProcess(pidfile, os.Getpid()); got != tc.want {
				t.Fatalf("heldByLiveProcess(%q) = %v, want %v", tc.content, got, tc.want)
			}
		})
	}
}

// TestWarmNeverLogsThroughALink pins that the zygote's log is opened by
// name and never through a link. The grant's fibers write the run
// directory as uid 0, so one could plant zygote.log as a link to any
// file on the host, and the next warm of the grant (after the zygote
// died) would append the zygote's output there as root.
func TestWarmNeverLogsThroughALink(t *testing.T) {
	cases := []struct {
		name string
		// plant prepares the run directory's zygote.log.
		plant   func(t *testing.T, dir, victim string)
		wantErr string
	}{
		{name: "no log yet: made and appended", plant: func(*testing.T, string, string) {}},
		{name: "a regular log is appended", plant: func(t *testing.T, dir, _ string) {
			if err := os.WriteFile(filepath.Join(dir, "zygote.log"), []byte("earlier\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a link to another file is refused", plant: func(t *testing.T, dir, victim string) {
			if err := os.Symlink(victim, filepath.Join(dir, "zygote.log")); err != nil {
				t.Fatal(err)
			}
		}, wantErr: "zygote.log is a link"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "g")
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			victim := filepath.Join(t.TempDir(), "victim")
			if err := os.WriteFile(victim, []byte("untouched\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			tc.plant(t, dir, victim)
			f := newFakes(t)
			b := f.open(t, Options{})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := b.Warm(ctx, backend.WarmSpec{
				GrantUID:      "g",
				Template:      backend.Template{Argv: fakeArgv("early", impossiblePID(t))},
				CgroupFD:      -1,
				ProbeCgroupFD: -1,
				WorkDir:       dir,
			})
			switch {
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("Warm = %v, want an error mentioning %q", err, tc.wantErr)
			case tc.wantErr == "" && err != nil:
				t.Fatalf("Warm: %v", err)
			}
			if tc.wantErr != "" && len(f.spawn.started()) != 0 {
				t.Fatal("a zygote was started over a planted log")
			}
			if got, _ := os.ReadFile(victim); string(got) != "untouched\n" {
				t.Fatalf("the victim file reads %q, want it untouched", got)
			}
			st, lerr := os.Lstat(filepath.Join(dir, "zygote.log"))
			if lerr != nil {
				t.Fatal(lerr)
			}
			if (st.Mode()&os.ModeSymlink != 0) != (tc.wantErr != "") {
				t.Fatalf("zygote.log mode = %v after the warm", st.Mode())
			}
		})
	}
}
