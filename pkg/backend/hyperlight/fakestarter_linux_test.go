//go:build linux

package hyperlight

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"go.uber.org/goleak"

	fakehelper "github.com/helayoty/fiberd/hack/hyperlight/fakehelper/helper"
	"github.com/helayoty/fiberd/pkg/backend"
)

// TestMain fails the package when a test leaves a goroutine behind, such
// as a reaper or a helper outliving Close.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

const (
	kvmIntel = "fiberd-hyperlight-helper/0.1.0 hyperlight_host/0.17.0 kvm GenuineIntel"
	fake     = fakehelper.Facts
)

// fakeStarter starts helpers inside the test process, wired into a
// Backend through the starter seam. version is what --version says and
// body what a started helper does over its control socket. A nil body
// runs hack/hyperlight/fakehelper's library, the helper conformance runs
// against.
type fakeStarter struct {
	version    string
	versionErr error
	startErr   error
	body       func(r *fakeRun)

	mu   sync.Mutex
	runs []*fakeRun
}

// fakeRun is one started helper: what it was given, and whether the
// backend killed and reaped it.
type fakeRun struct {
	args     []string
	workDir  string
	cgroupFD int
	log      *os.File // the helper's own copy of the log
	ctl      net.Conn
	pid      int
	killed   atomic.Bool
	waited   atomic.Bool
	done     chan struct{} // closed when the body has returned
}

func (s *fakeStarter) Version(context.Context) (string, error) {
	return s.version + "\n", s.versionErr
}

func (s *fakeStarter) Start(args []string, workDir string, cgroupFD int, logf, ctl *os.File) (process, error) {
	if s.startErr != nil {
		return nil, s.startErr
	}
	conn, err := net.FileConn(ctl)
	if err != nil {
		return nil, err
	}
	logFD, err := syscall.Dup(int(logf.Fd()))
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	s.mu.Lock()
	r := &fakeRun{args: args, workDir: workDir, cgroupFD: cgroupFD, log: os.NewFile(uintptr(logFD), "helper-log"),
		ctl: conn, pid: 40000 + len(s.runs), done: make(chan struct{})}
	s.runs = append(s.runs, r)
	s.mu.Unlock()
	body := s.body
	if body == nil {
		body = func(r *fakeRun) { _ = fakehelper.Serve(r.ctl, r.log, "") }
	}
	go func() {
		defer close(r.done)
		defer func() { _ = r.log.Close() }()
		defer func() { _ = r.ctl.Close() }()
		body(r)
	}()
	return r, nil
}

// started is every helper the starter has started so far.
func (s *fakeStarter) started() []*fakeRun {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*fakeRun(nil), s.runs...)
}

func (r *fakeRun) Pid() int { return r.pid }

// Kill closes the helper's control socket, which ends every body.
func (r *fakeRun) Kill() error {
	r.killed.Store(true)
	return r.ctl.Close()
}

func (r *fakeRun) Wait() error {
	<-r.done
	r.waited.Store(true)
	return nil
}

// hold blocks until the backend hangs up or kills the helper.
func (r *fakeRun) hold() { _, _ = io.Copy(io.Discard, r.ctl) }

// ready is a body that reports the facts and serves nothing.
func ready(facts string) func(r *fakeRun) {
	return func(r *fakeRun) {
		_, _ = fmt.Fprintf(r.ctl, "READY %s\n", facts)
		r.hold()
	}
}

// says is a fake starter whose helper reports facts on --version and on
// READY.
func says(facts string) *fakeStarter { return &fakeStarter{version: facts, body: ready(facts)} }

// newFake opens a backend over the starter. The cleanup closes the
// backend, waits for every helper it started to end, and fails the test
// on a goroutine left behind.
func newFake(t *testing.T, o Options, s *fakeStarter) *Backend {
	t.Helper()
	b := newBackend(o, s)
	t.Cleanup(func() {
		b.Close()
		for _, r := range s.started() {
			awaitRun(t, r)
		}
		goleak.VerifyNone(t)
	})
	return b
}

// awaitRun waits for a helper's body to return.
func awaitRun(t *testing.T, r *fakeRun) {
	t.Helper()
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("helper %d is still running", r.pid)
	}
}

// warmCtx is a context a Warm must finish within.
func warmCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// warmSpec is a warm of grant g1 with no cgroup.
func warmSpec(workDir string) backend.WarmSpec {
	return backend.WarmSpec{GrantUID: "g1", WorkDir: workDir, CgroupFD: -1, ProbeCgroupFD: -1}
}

// warmOf is the registered helper of a warm, for the tests.
func (b *Backend) warmOf(id string) (*helper, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	h, ok := b.warms[id]
	return h, ok
}

// talk sends one line to a fiber's endpoint and reads the reply.
func talk(t *testing.T, endpoint, line string) string {
	t.Helper()
	c, err := net.DialTimeout("unix", endpoint, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", endpoint, err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintln(c, line); err != nil {
		t.Fatalf("%s: %v", line, err)
	}
	reply, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("%s: %v", line, err)
	}
	return strings.TrimSpace(reply)
}

// awaitExit is the next exit the backend reports.
func awaitExit(t *testing.T, be backend.Backend) backend.Exit {
	t.Helper()
	select {
	case e := <-be.Exits():
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("no exit was reported")
		return backend.Exit{}
	}
}

// awaitW waits for the fiber's W to reach want.
func awaitW(t *testing.T, be backend.Backend, id string, want uint64) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		w, ok := be.(backend.WReporter).FiberW(id)
		if ok && w == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("FiberW(%s) = %d, %v, want %d", id, w, ok, want)
		}
	}
}

func await[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("nothing arrived")
		var zero T
		return zero
	}
}
