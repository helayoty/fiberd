//go:build linux

package gvisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"go.uber.org/goleak"
)

// TestMain fails the package when a test leaves a goroutine behind, such
// as a reaper outliving Close.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// fakeRunsc is runsc and its sandboxes inside the test process, wired
// into a Backend through the run seam. A sandbox behaves as the reference
// zygote does under --gvisor: a template drops the ready marker on /host,
// a fiber serves its endpoint there and closes it on USR1. Each has a
// process of its own (a shell waiting on its stdin), so its pid is one
// the backend can hold a pidfd on and the reaper takes the path it
// takes with real runsc. The process ends as the ExitStatus knob says.
type fakeRunsc struct {
	mu       sync.Mutex
	knobs    knobs
	recorded []fakeCall
	boxes    map[string]*fakeSandbox // running, by cid
	gate     *deleteGate             // the next delete is held here, when set
	// restoring counts the restores in flight, and peak the most there
	// have been at once.
	restoring, peak int
}

// peakRestores is the most restores the fake has had in flight at once.
func (f *fakeRunsc) peakRestores() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.peak
}

const (
	fakeVersion = "release-20260817.0"
	imageFile   = "checkpoint.img"
)

// knobs script the fake runsc. They are read on every invocation, so a
// test can change them between calls (setKnobs).
type knobs struct {
	Fail       map[string]bool // commands that fail, out of version, list, delete, run, restore, checkpoint, state, kill and wait
	LongOutput bool            // a failing command prints more than the error tail keeps
	NoMarker   bool            // the template sandbox never drops its ready marker
	NoServe    bool            // a fiber sandbox never serves its endpoint
	IgnoreUSR1 bool            // a sandbox keeps its endpoint through a park request
	// SlowRestore is how long a restore takes before the sandbox is up.
	// The context ending cuts it short, as it kills a real runsc.
	SlowRestore time.Duration
	// SlowCheckpt is how long a checkpoint that ends the sandbox takes
	// after it is gone, as a real one's image flush and cleanup do.
	SlowCheckpt time.Duration
	// ExitStatus is how a sandbox ends: its process exits with it, or
	// dies by the signal it names above 128, and `wait` reports it.
	ExitStatus  int
	BadWaitJSON bool // `wait` prints something that is not JSON
}

// fakeCall is one recorded invocation: the arguments after the binary
// joined by spaces, and the cgroup it was started in.
type fakeCall struct {
	args     string
	cgroupFD int
}

// fakeSandbox is one running sandbox.
type fakeSandbox struct {
	cid      string
	pid      int
	proc     *os.Process    // the sandbox process, which the backend reaps
	stdin    io.WriteCloser // a line on it ends the process with its status
	endpoint string         // the host path it serves, "" for none
	ln       net.Listener
	done     chan struct{} // closed when the sandbox has ended
}

// deleteGate holds one `delete`: claimed closes when it is waiting, open
// lets it go, passed closes once it is done.
type deleteGate struct {
	claimed chan struct{}
	open    chan struct{}
	passed  chan struct{}
}

func newFakeRunsc(k knobs) *fakeRunsc {
	return &fakeRunsc{knobs: k, boxes: map[string]*fakeSandbox{}}
}

func (f *fakeRunsc) setKnobs(k knobs) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.knobs = k
}

// holdNextDelete arms the gate for the next `delete` the fake runs.
func (f *fakeRunsc) holdNextDelete() *deleteGate {
	g := &deleteGate{claimed: make(chan struct{}), open: make(chan struct{}), passed: make(chan struct{})}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gate = g
	return g
}

// calls is every recorded invocation, arguments joined by spaces.
func (f *fakeRunsc) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.recorded))
	for i, c := range f.recorded {
		out[i] = c.args
	}
	return out
}

// cgroupOf is the cgroup fd the first invocation containing every part
// was started in, or -2 when there is none.
func (f *fakeRunsc) cgroupOf(parts ...string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.recorded {
		if containsAll(c.args, parts) {
			return c.cgroupFD
		}
	}
	return -2
}

func containsAll(s string, parts []string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}

// alive reports whether the sandbox for cid runs.
func (f *fakeRunsc) alive(cid string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.boxes[cid]
	return ok
}

// pidOf is the running sandbox's pid, 0 when there is none.
func (f *fakeRunsc) pidOf(cid string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if x := f.boxes[cid]; x != nil {
		return x.pid
	}
	return 0
}

// endAll ends every sandbox still running, whatever the knobs said.
func (f *fakeRunsc) endAll() {
	f.mu.Lock()
	cids := make([]string, 0, len(f.boxes))
	for cid := range f.boxes {
		cids = append(cids, cid)
	}
	f.mu.Unlock()
	for _, cid := range cids {
		f.endSandbox(cid)
	}
}

// errExit is what a failed runsc process reports.
var errExit = errors.New("exit status 1")

// longOutput is what a failing command prints under LongOutput: more
// than an error keeps, with the cause on its first line.
var longOutput = "panic: the cause\n" + strings.Repeat("goroutine\n", 200)

// run is one runsc invocation, the global --flags first in args.
func (f *fakeRunsc) run(ctx context.Context, cgroupFD int, args []string, out io.Writer) error {
	f.mu.Lock()
	f.recorded = append(f.recorded, fakeCall{args: strings.Join(args, " "), cgroupFD: cgroupFD})
	k := f.knobs
	f.mu.Unlock()
	fail := func(what string) error {
		if k.LongOutput {
			// As a crashed Sentry prints: the cause first, then pages of
			// goroutines.
			_, _ = io.WriteString(out, longOutput)
		}
		_, _ = fmt.Fprintf(out, "fake runsc: %s failed\n", what)
		return errExit
	}
	for _, a := range args {
		if a == "--version" {
			if k.Fail["version"] {
				return fail("version")
			}
			_, _ = fmt.Fprintf(out, "runsc version %s\nspec: 1.1.0-rc.1\n", fakeVersion)
			return nil
		}
	}
	for len(args) > 0 && strings.HasPrefix(args[0], "--") {
		args = args[1:]
	}
	if len(args) == 0 {
		_, _ = fmt.Fprintln(out, "no command")
		return errExit
	}
	cmd, rest := args[0], args[1:]
	flag := func(name string) string {
		for i := range rest {
			if rest[i] == name && i+1 < len(rest) {
				return rest[i+1]
			}
		}
		return ""
	}
	has := func(name string) bool {
		for _, a := range rest {
			if a == name {
				return true
			}
		}
		return false
	}
	cid := ""
	if len(rest) > 0 {
		cid = rest[len(rest)-1]
		if cmd == "kill" && len(rest) >= 2 {
			cid = rest[len(rest)-2]
		}
	}
	if k.Fail[cmd] {
		return fail(cmd)
	}
	switch cmd {
	case "list":
		// With -quiet, one container id per line.
		f.mu.Lock()
		ids := make([]string, 0, len(f.boxes))
		for id := range f.boxes {
			ids = append(ids, id)
		}
		f.mu.Unlock()
		sort.Strings(ids)
		for _, id := range ids {
			_, _ = fmt.Fprintln(out, id)
		}
		return nil
	case "delete":
		f.mu.Lock()
		g := f.gate
		f.gate = nil
		f.mu.Unlock()
		if g != nil {
			close(g.claimed)
			<-g.open
		}
		// -force on a running container ends it first.
		f.endSandbox(cid)
		if g != nil {
			close(g.passed)
		}
		return nil
	case "run", "restore":
		if cmd == "restore" {
			f.mu.Lock()
			f.restoring++
			f.peak = max(f.peak, f.restoring)
			f.mu.Unlock()
			defer func() {
				f.mu.Lock()
				f.restoring--
				f.mu.Unlock()
			}()
			if _, err := os.Stat(filepath.Join(flag("--image-path"), imageFile)); err != nil {
				_, _ = fmt.Fprintf(out, "fake runsc: no image at %s\n", flag("--image-path"))
				return errExit
			}
			if k.SlowRestore > 0 {
				select {
				case <-time.After(k.SlowRestore):
				case <-ctx.Done():
					_, _ = fmt.Fprintln(out, "signal: killed")
					return ctx.Err()
				}
			}
		}
		return f.startSandbox(cid, flag("--bundle"), k, out)
	case "checkpoint":
		img := flag("--image-path")
		if err := os.MkdirAll(img, 0o755); err != nil {
			return fail("mkdir")
		}
		if err := os.WriteFile(filepath.Join(img, imageFile), []byte(cid), 0o644); err != nil {
			return fail("write image")
		}
		if has("--leave-running") {
			return nil
		}
		f.endSandbox(cid)
		if k.SlowCheckpt > 0 {
			select {
			case <-time.After(k.SlowCheckpt):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	case "state":
		pid := f.pidOf(cid)
		if pid == 0 {
			_, _ = fmt.Fprintf(out, "fake runsc: container %q does not exist\n", cid)
			return errExit
		}
		_, _ = fmt.Fprintf(out, `{"id": %q, "pid": %d, "status": "running"}`+"\n", cid, pid)
		return nil
	case "wait":
		f.mu.Lock()
		x := f.boxes[cid]
		f.mu.Unlock()
		if x != nil {
			select {
			case <-x.done:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if k.BadWaitJSON {
			_, _ = fmt.Fprintln(out, "not json")
		} else {
			_, _ = fmt.Fprintf(out, `{"id": %q, "exitStatus": %d}`+"\n", cid, k.ExitStatus)
		}
		return nil
	case "kill":
		f.mu.Lock()
		x := f.boxes[cid]
		f.mu.Unlock()
		if x == nil {
			_, _ = fmt.Fprintf(out, "fake runsc: container %q does not exist\n", cid)
			return errExit
		}
		if rest[len(rest)-1] == "USR1" {
			if !k.IgnoreUSR1 {
				x.closeEndpoint()
			}
			return nil
		}
		f.endSandbox(cid)
		return nil
	}
	_, _ = fmt.Fprintf(out, "fake runsc: unknown command %q\n", cmd)
	return errExit
}

// startSandbox brings up the sandbox for the bundle, as `runsc run
// --detach` returns with the sandbox up.
func (f *fakeRunsc) startSandbox(cid, bundle string, k knobs, out io.Writer) error {
	data, err := os.ReadFile(filepath.Join(bundle, "config.json"))
	if err != nil {
		_, _ = fmt.Fprintf(out, "fake runsc: bundle: %v\n", err)
		return errExit
	}
	var s spec
	if err := json.Unmarshal(data, &s); err != nil {
		_, _ = fmt.Fprintf(out, "fake runsc: bundle: %v\n", err)
		return errExit
	}
	host := ""
	for _, m := range s.Mounts {
		if m.Destination == "/host" {
			host = m.Source
		}
	}
	env := map[string]string{}
	for _, e := range s.Process.Env {
		if key, val, ok := strings.Cut(e, "="); ok {
			env[key] = val
		}
	}
	x := &fakeSandbox{cid: cid, done: make(chan struct{})}
	if env["FIBERD_FENCE"] == "none" {
		if !k.NoMarker {
			if err := os.WriteFile(filepath.Join(host, readyMarker), nil, 0o644); err != nil {
				_, _ = fmt.Fprintf(out, "fake runsc: marker: %v\n", err)
				return errExit
			}
		}
	} else if ep := env["FIBERD_ENDPOINT"]; ep != "" && !k.NoServe {
		x.endpoint = filepath.Join(host, strings.TrimPrefix(ep, "/host/"))
		ln, err := net.Listen("unix", x.endpoint)
		if err != nil {
			_, _ = fmt.Fprintf(out, "fake runsc: listen: %v\n", err)
			return errExit
		}
		x.ln = ln
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if old := f.boxes[cid]; old != nil {
		_, _ = fmt.Fprintf(out, "fake runsc: container %q exists\n", cid)
		if x.ln != nil {
			_ = x.ln.Close()
		}
		return errExit
	}
	// The sandbox process is a shell that exits with the status it is
	// handed once a line arrives on its stdin. The backend reaps it, or
	// nobody does when the reaper took the `runsc wait` path, so it is
	// never waited for here.
	cmd := exec.Command("sh", "-c", "read line; exit $0", strconv.Itoa(k.ExitStatus))
	stdin, err := cmd.StdinPipe()
	if err == nil {
		err = cmd.Start()
	}
	if err != nil {
		_, _ = fmt.Fprintf(out, "fake runsc: sandbox process: %v\n", err)
		if x.ln != nil {
			_ = x.ln.Close()
		}
		return errExit
	}
	x.proc, x.stdin, x.pid = cmd.Process, stdin, cmd.Process.Pid
	f.boxes[cid] = x
	return nil
}

// endSandbox ends the sandbox for cid, if it runs. Its process dies by
// the signal ExitStatus names above 128, or exits with ExitStatus.
func (f *fakeRunsc) endSandbox(cid string) {
	f.mu.Lock()
	x := f.boxes[cid]
	delete(f.boxes, cid)
	k := f.knobs
	f.mu.Unlock()
	if x == nil {
		return
	}
	if x.ln != nil {
		_ = x.ln.Close()
	}
	if k.ExitStatus > 128 {
		_ = x.proc.Signal(syscall.Signal(k.ExitStatus - 128))
	} else {
		_, _ = io.WriteString(x.stdin, "\n")
	}
	_ = x.stdin.Close()
	close(x.done)
}

// closeEndpoint is what the workload does on USR1: it stops serving and
// removes its socket, so the host sees the endpoint gone.
func (x *fakeSandbox) closeEndpoint() {
	if x.ln != nil {
		_ = x.ln.Close()
		_ = os.Remove(x.endpoint)
	}
}
