//go:build linux

package proc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/sys/criu"
)

// TestMain fails the package when a test leaves a goroutine behind, such
// as a reader or a restore outliving Close.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// fakeZygoteArg is the first word of a scripted zygote's command. The
// second is its script and the third the pid it reports in CLONED.
const fakeZygoteArg = "fake-zygote"

// fakeArgv is a scripted zygote's command line.
func fakeArgv(script string, pid int) []string {
	return []string{fakeZygoteArg, script, strconv.Itoa(pid)}
}

// impossiblePID is a number no process on this host can have, so a test
// that goes wrong can never signal a real one.
// channelOf keeps the host's end of a handoff fiber's channel, which
// the backend hands back from Clone and Resume, until the test ends,
// and says whether there was one.
func channelOf(t *testing.T, fb backend.Fiber) bool {
	t.Helper()
	if fb.Channel == nil {
		return false
	}
	t.Cleanup(func() { _ = fb.Channel.Close() })
	return true
}

func impossiblePID(t *testing.T) int {
	t.Helper()
	b, err := os.ReadFile("/proc/sys/kernel/pid_max")
	if err != nil {
		t.Fatal(err)
	}
	max, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return max + 1
}

// fakeSpawner stands in for cmd.Start through Options.spawn. It takes the
// zygote's end of the control pair from the command and serves the line
// protocol on it in a goroutine, as the script in the command's arguments
// says.
type fakeSpawner struct {
	startErr error
	base     int // the first zygote's pid, past pid_max

	mu   sync.Mutex
	runs []*fakeZygote
}

// fakeZygote is one spawned zygote: what Warm built, what it read, and
// whether the backend killed and reaped it.
type fakeZygote struct {
	cmd    *exec.Cmd
	script string
	zpid   string // what CLONED reports
	pid    int
	ctl    *net.UnixConn
	exeSHA string        // the hex SHA-256 of what fd 4 held, when the command had one
	gate   chan struct{} // the overdue script answers once it is closed
	done   chan struct{} // closed when the body has returned
	notify chan struct{} // a token per line read
	killed atomic.Bool
	waited atomic.Bool

	mu   sync.Mutex
	recv []string
	// channel is the fiber's end of the last channel a CLONE passed, the
	// last descriptor on the line, kept so a test can read the record
	// the backend queued on it. -1 before the first.
	channel int
}

func (s *fakeSpawner) spawn(cmd *exec.Cmd) (process, error) {
	if s.startErr != nil {
		return nil, s.startErr
	}
	if len(cmd.Args) < 3 || len(cmd.ExtraFiles) == 0 {
		return nil, fmt.Errorf("fake spawn: want a script and a control socket, got %v", cmd.Args)
	}
	conn, err := net.FileConn(cmd.ExtraFiles[0])
	if err != nil {
		return nil, err
	}
	exeSHA := ""
	if len(cmd.ExtraFiles) > 1 {
		// Warm closes its copy once the zygote has started, as the real
		// child holds its own across the exec.
		data, err := os.ReadFile(fmt.Sprintf("/proc/self/fd/%d", cmd.ExtraFiles[1].Fd()))
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		sum := sha256.Sum256(data)
		exeSHA = hex.EncodeToString(sum[:])
	}
	s.mu.Lock()
	z := &fakeZygote{cmd: cmd, script: cmd.Args[1], zpid: cmd.Args[2], pid: s.base + len(s.runs), ctl: conn.(*net.UnixConn), exeSHA: exeSHA, channel: -1,
		gate: make(chan struct{}), done: make(chan struct{}), notify: make(chan struct{}, 1)}
	s.runs = append(s.runs, z)
	s.mu.Unlock()
	go func() {
		defer close(z.done)
		defer func() { _ = z.ctl.Close() }()
		z.serve()
	}()
	return z, nil
}

// started is every zygote the spawner has started so far.
func (s *fakeSpawner) started() []*fakeZygote {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*fakeZygote(nil), s.runs...)
}

func (z *fakeZygote) Pid() int { return z.pid }

// Kill closes the zygote's end of the control socket, which ends its body.
func (z *fakeZygote) Kill() error {
	z.killed.Store(true)
	return z.ctl.Close()
}

func (z *fakeZygote) Wait() error {
	<-z.done
	z.waited.Store(true)
	return nil
}

// record keeps a line the zygote read and wakes a waiter.
func (z *fakeZygote) record(line string) {
	z.mu.Lock()
	z.recv = append(z.recv, line)
	z.mu.Unlock()
	select {
	case z.notify <- struct{}{}:
	default:
	}
}

// lines is what the zygote has read so far.
func (z *fakeZygote) lines() []string {
	z.mu.Lock()
	defer z.mu.Unlock()
	return append([]string(nil), z.recv...)
}

// waitRecv waits until the zygote has read a line containing want and
// returns everything it read.
func (z *fakeZygote) waitRecv(t *testing.T, want string) []string {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		lines := z.lines()
		for _, l := range lines {
			if strings.Contains(l, want) {
				return lines
			}
		}
		select {
		case <-z.notify:
		case <-z.done:
			t.Fatalf("the zygote ended having read %q, not %q", lines, want)
		case <-deadline:
			t.Fatalf("the zygote read %q, never %q", lines, want)
		}
	}
}

// serve speaks the line protocol the way libfiberzygote does
// (sdk/c/template/libfiberzygote.c), answering CLONE as the script names. Every
// line it reads is recorded, so a test can assert what the backend sent.
// The setup lines are read up to PREPARE before any answer, as
// read_setup does, so a script that ends on its answer never closes the
// socket while the backend is still writing them. Only quit reads
// nothing, as a zygote that died before it served.
//
//	early     CLONED and EXITED in one write, as fz_serve does when a fiber
//	          reports ready and exits within one poll iteration
//	late      CLONED, then EXITED in a write of its own
//	overdue   nothing until the gate is closed, then early
//	never     CLONED and no EXITED
//	error     ERROR <fence> deadline exceeded before ready
//	refuse    ERROR ? for every path line, then ERROR <fence> refused
//	malformed CLONED <fence> abc, a pid the backend cannot name
//	short     CLONED <fence>, no pid at all
//	noise     lines the reader must tolerate, then CLONED
//	die       ends on CLONE without answering
//	device    DEVICE lines for the warm instance and each fiber, dropped
//	          again on EVICT
//	notready  greets with something other than READY
//	silent    never says READY
//	quit      ends before READY
//	unprepared could not prepare its mount namespace: ERROR ? with the
//	          reason instead of READY, then ends, as libfiberzygote does
func (z *fakeZygote) serve() {
	for _, e := range z.cmd.Env {
		if strings.HasPrefix(e, "FIBERD_DEVICES=") {
			z.record("ENV " + e)
		}
	}
	say := func(s string) { _, _ = z.ctl.Write([]byte(s)) }
	if z.script == "quit" {
		return
	}
	setup, ok := z.readSetup()
	if !ok {
		return
	}
	switch z.script {
	case "unprepared":
		say("ERROR ? the zygote could not cover a HIDE path (/var/lib/fiberd/templates: Permission denied)\n")
		return
	case "notready":
		say("HELLO\n")
	case "silent":
	default:
		say("READY\n")
	}
	switch z.script {
	case "device":
		// A short DEVICE line carries nothing and is ignored.
		say("DEVICE - 100 1000\nDEVICE short\n")
	case "refuse":
		for _, line := range setup {
			say("ERROR ? " + strings.Fields(line)[0] + " refused: by the script\n")
		}
	}
	for {
		line, fds, err := recvLine(z.ctl)
		if err != nil {
			return // fiberd closed the socket, or killed the zygote
		}
		z.record(strings.TrimSuffix(line, "\n"))
		if len(fds) > 0 {
			z.record(fmt.Sprintf("FDS %d", len(fds)))
			z.keepChannel(fds)
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "CLONE":
		case "EVICT":
			if z.script == "device" && len(fields) >= 2 {
				say("DEVICE " + fields[1] + " 0 0\n")
			}
			continue
		default: // HIDE, DROP, RUNDIR, PREPARE
			if z.script == "refuse" {
				say("ERROR ? " + fields[0] + " refused: by the script\n")
			}
			continue
		}
		if len(fields) < 2 {
			continue
		}
		fence := fields[1]
		cloned := fmt.Sprintf("CLONED %s %s\n", fence, z.zpid)
		exited := fmt.Sprintf("EXITED %s exit:3\n", z.zpid)
		switch z.script {
		case "early":
			say(cloned + exited)
		case "late":
			say(cloned)
			say(exited)
		case "overdue":
			<-z.gate
			say(cloned + exited + "DEVICE - 1 1\n")
		case "never":
			say(cloned)
		case "error":
			say("ERROR " + fence + " deadline exceeded before ready\n")
		case "refuse":
			say("ERROR " + fence + " refused: the mount namespace cannot hide what fiberd asked (by the script)\n")
		case "malformed":
			say("CLONED " + fence + " abc\n")
		case "short":
			say("CLONED " + fence + "\n")
		case "noise":
			// A CLONED naming nothing, EXITED lines for no fiber and a
			// keyword from the future, before the real answer.
			say("CLONED\nEXITED 5\nEXITED\nFUTURE " + fence + "\n\n" + cloned)
		case "die":
			return
		case "device":
			say(cloned + "DEVICE " + fence + " 42 0\n")
		default:
			return
		}
	}
}

// readSetup reads and records the setup lines up to PREPARE and returns
// them, or false once the backend closed the socket first.
func (z *fakeZygote) readSetup() ([]string, bool) {
	var setup []string
	for {
		line, _, err := recvLine(z.ctl)
		if err != nil {
			return nil, false
		}
		line = strings.TrimSuffix(line, "\n")
		z.record(line)
		setup = append(setup, line)
		if strings.HasPrefix(line, "PREPARE ") {
			return setup, true
		}
	}
}

// recvLine reads one line a byte at a time, as libfiberzygote's recv_line
// does, so the descriptors passed with a message are counted against the
// line they came with. The fds are closed.
func recvLine(c *net.UnixConn) (line string, fds []int, err error) {
	var sb strings.Builder
	buf := make([]byte, 1)
	oob := make([]byte, 256)
	for {
		n, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
		if err != nil {
			return "", nil, err
		}
		if oobn > 0 {
			if msgs, err := syscall.ParseSocketControlMessage(oob[:oobn]); err == nil {
				for _, m := range msgs {
					got, _ := syscall.ParseUnixRights(&m)
					fds = append(fds, got...)
				}
			}
		}
		if n == 0 {
			continue
		}
		sb.WriteByte(buf[0])
		if buf[0] == '\n' {
			return sb.String(), fds, nil
		}
	}
}

// keepChannel keeps the last descriptor a line passed, the fiber's end
// of its channel, in place of the one kept before, and closes the rest.
func (z *fakeZygote) keepChannel(fds []int) {
	z.mu.Lock()
	defer z.mu.Unlock()
	for _, fd := range fds[:len(fds)-1] {
		_ = syscall.Close(fd)
	}
	if z.channel >= 0 {
		_ = syscall.Close(z.channel)
	}
	z.channel = fds[len(fds)-1]
}

// recordOn reads the record the backend queued on the channel the last
// CLONE passed the fake zygote, off the fiber's end as the library does.
func recordOn(t *testing.T, z *fakeZygote) backend.Incarnation {
	t.Helper()
	z.mu.Lock()
	fd := z.channel
	z.mu.Unlock()
	if fd < 0 {
		t.Fatal("no channel was passed with the CLONE")
	}
	buf := make([]byte, backend.RecordMax)
	n, _, _, _, err := syscall.Recvmsg(fd, buf, nil, syscall.MSG_DONTWAIT)
	if err != nil {
		t.Fatalf("read the record off the channel: %v", err)
	}
	inc, err := backend.ParseIncarnation(buf[:n])
	if err != nil {
		t.Fatalf("record on the channel: %v", err)
	}
	return inc
}

// criuKnobs say how the fake criu answers, so a table case can hold them.
type criuKnobs struct {
	version     string // what --version prints, "Version: 4.2.1" when empty
	checkErr    error  // what check fails with
	dumpErr     error  // what dump fails with
	dumpErrOnce bool   // and only the first dump
	restore     string // "" writes the pid file and waits, "no" fails at once, "hang" never writes one
	restoreErr  error  // what Wait returns once the restore is released
}

// fakeCriu stands in for the criu binary behind Options.Commander. It
// records every call and answers as its knobs say. A restore it starts
// stays alive, as the restored tree's parent would, until released.
type fakeCriu struct {
	criuKnobs
	restorePID int // the pid the restore writes

	mu    sync.Mutex
	calls [][]string
	procs []*fakeProcess
}

func (f *fakeCriu) Output(ctx context.Context, args []string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, args)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch args[0] {
	case "--version":
		if f.version == "" {
			return []byte("Version: 4.2.1\n"), nil
		}
		return []byte(f.version), nil
	case "check":
		if f.checkErr != nil {
			return []byte("Error (criu/cr-check.c): a feature is missing"), f.checkErr
		}
		return []byte("Looks good."), nil
	case "dump":
		err := f.dumpErr
		if f.dumpErrOnce {
			f.dumpErr = nil
		}
		return nil, err
	}
	return nil, fmt.Errorf("fake criu: unexpected %q", args)
}

func (f *fakeCriu) Start(args []string, files []*os.File, cgroupFD int) (criu.Process, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	call := append(append([]string{}, args...), fmt.Sprintf("files=%d", len(files)), fmt.Sprintf("cgroup=%d", cgroupFD))
	f.calls = append(f.calls, call)
	p := &fakeProcess{pid: f.restorePID, released: make(chan struct{})}
	f.procs = append(f.procs, p)
	switch f.restore {
	case "no":
		p.release(errors.New("exit status 1"))
	case "hang":
	default:
		i := slices.Index(args, "--pidfile")
		if i < 0 || i+1 >= len(args) {
			return nil, fmt.Errorf("no --pidfile in %q", args)
		}
		if err := os.WriteFile(args[i+1], []byte(strconv.Itoa(f.restorePID)+"\n"), 0o600); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// recorded is every call so far, one line each.
func (f *fakeCriu) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		out = append(out, strings.Join(c, " "))
	}
	return out
}

// last is the most recent call.
func (f *fakeCriu) last(t *testing.T) string {
	t.Helper()
	calls := f.recorded()
	if len(calls) == 0 {
		t.Fatal("criu was never called")
	}
	return calls[len(calls)-1]
}

// restored is every restore started so far.
func (f *fakeCriu) restored() []*fakeProcess {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*fakeProcess(nil), f.procs...)
}

// releaseAll ends every restore still running, as the restored trees
// exiting would.
func (f *fakeCriu) releaseAll() {
	for _, p := range f.restored() {
		p.release(f.restoreErr)
	}
}

// fakeProcess is a started restore whose Wait blocks until released.
type fakeProcess struct {
	pid      int
	exit     error
	once     sync.Once
	released chan struct{}
	killed   atomic.Bool
}

func (p *fakeProcess) Pid() int { return p.pid }

func (p *fakeProcess) Kill() error {
	p.killed.Store(true)
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

// fakes are what a backend under test runs on: zygotes as goroutines,
// criu as a recorder and /proc as a directory of the test's own.
type fakes struct {
	spawn *fakeSpawner
	criu  *fakeCriu
	proc  string
}

func newFakes(t *testing.T) *fakes {
	t.Helper()
	return &fakes{spawn: &fakeSpawner{base: impossiblePID(t) + 100}, criu: &fakeCriu{restorePID: impossiblePID(t) + 50}, proc: t.TempDir()}
}

// open opens a backend over the fakes. The cleanup closes it, ends every
// restore, waits for every zygote to end and fails the test on a
// goroutine left behind.
func (f *fakes) open(t *testing.T, o Options) *Backend {
	t.Helper()
	o.spawn, o.procRoot, o.Commander = f.spawn.spawn, f.proc, f.criu
	if o.RootBind == "" {
		o.RootBind = filepath.Join(t.TempDir(), "root")
	}
	b := NewBackend(o)
	t.Cleanup(func() {
		b.Close()
		f.criu.releaseAll()
		for _, z := range f.spawn.started() {
			select {
			case <-z.done:
			case <-time.After(5 * time.Second):
				t.Errorf("zygote %d is still running", z.pid)
			}
		}
		goleak.VerifyNone(t)
	})
	return b
}

// warm starts a scripted zygote for grant g, with its run directory under
// a temp dir, and returns the instance and the zygote.
func (f *fakes) warm(t *testing.T, b *Backend, script string, pid int) (backend.Warm, *fakeZygote, string) {
	t.Helper()
	return f.warmFor(t, b, "g", script, pid)
}

// warmFor is warm for a named grant, so two zygotes can be up at once.
func (f *fakes) warmFor(t *testing.T, b *Backend, grant, script string, pid int) (backend.Warm, *fakeZygote, string) {
	t.Helper()
	workDir := filepath.Join(t.TempDir(), grant)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	before := len(f.spawn.started())
	w, err := b.Warm(ctx, backend.WarmSpec{GrantUID: grant, Template: backend.Template{Argv: fakeArgv(script, pid)}, CgroupFD: -1, ProbeCgroupFD: -1, WorkDir: workDir})
	if err != nil {
		t.Fatalf("warm %s: %v", grant, err)
	}
	return w, f.spawn.started()[before], workDir
}

// socket plants, under the fake /proc, the socket a process holds on fd.
func (f *fakes) socket(t *testing.T, pid, fd int, inode string) {
	t.Helper()
	dir := filepath.Join(f.proc, strconv.Itoa(pid), "fd")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:["+inode+"]", filepath.Join(dir, strconv.Itoa(fd))); err != nil {
		t.Fatal(err)
	}
}

// status plants, under the fake /proc, a process whose NSpid line lists
// the pids given, the host's first.
func (f *fakes) status(t *testing.T, pids ...int) {
	t.Helper()
	dir := filepath.Join(f.proc, strconv.Itoa(pids[0]))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	sb.WriteString("Name:\tfiber\nNSpid:")
	for _, p := range pids {
		sb.WriteString("\t" + strconv.Itoa(p))
	}
	sb.WriteString("\nThreads:\t1\n")
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(sb.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// fakeCgroup is a directory whose cgroup.procs lists the pids given, for
// hostPID to read through an fd.
func fakeCgroup(t *testing.T, pids ...int) int {
	t.Helper()
	dir := t.TempDir()
	var sb strings.Builder
	for _, p := range pids {
		sb.WriteString(strconv.Itoa(p) + "\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(sb.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return int(d.Fd())
}

// waitFor polls cond until it holds or the deadline passes, for state the
// backend's reader updates with no channel to wait on.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// waitExit takes the next exit the backend reports.
func waitExit(t *testing.T, b *Backend) backend.Exit {
	t.Helper()
	select {
	case e := <-b.Exits():
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("no exit reported")
		return backend.Exit{}
	}
}

// pairConn is one end of a unix stream pair whose other end nobody reads.
func pairConn(t *testing.T) *net.UnixConn {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fds[0]), "pair")
	c, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(); _ = syscall.Close(fds[1]) })
	return c.(*net.UnixConn)
}

// fakeLauncher builds the scripted zygote's command the way a launcher
// would and records what the backend tells it.
type fakeLauncher struct {
	commandErr, channelErr, pidErr, restoreExtraErr, restoredErr error
	ownPair                                                      bool // Channel moves the conversation onto a pair of its own
	endpointRoot                                                 string
	pid                                                          int // what PID reports as the container's init

	mu       sync.Mutex
	calls    []string
	own      *os.File // the host's end of the launcher's own pair
	ownChild *os.File // the zygote's, closed here once it has started
}

func (l *fakeLauncher) record(s string) {
	l.mu.Lock()
	l.calls = append(l.calls, s)
	l.mu.Unlock()
}

func (l *fakeLauncher) recorded() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.calls...)
}

func (l *fakeLauncher) Name() string { return "fake" }

func (l *fakeLauncher) Command(spec backend.WarmSpec, argv []string, ctl, logf *os.File) (*exec.Cmd, error) {
	l.record("command")
	if l.commandErr != nil {
		return nil, l.commandErr
	}
	// A literal, not exec.Command: nothing here is started, the spawn
	// seam only reads the command.
	cmd := &exec.Cmd{Path: argv[0], Args: argv}
	cmd.Dir = spec.WorkDir
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.ExtraFiles = []*os.File{ctl}
	if l.ownPair {
		fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		l.own = os.NewFile(uintptr(fds[0]), "own-ctl")
		l.ownChild = os.NewFile(uintptr(fds[1]), "own-ctl-child")
		cmd.ExtraFiles = []*os.File{l.ownChild}
	}
	return cmd, nil
}

func (l *fakeLauncher) Channel(_ context.Context, _ backend.WarmSpec, _ *exec.Cmd, boot *net.UnixConn) (*net.UnixConn, error) {
	l.record("channel")
	if l.channelErr != nil {
		return nil, l.channelErr
	}
	if !l.ownPair {
		return boot, nil
	}
	_ = l.ownChild.Close() // the started zygote holds its own copy
	c, err := net.FileConn(l.own)
	_ = l.own.Close()
	if err != nil {
		return nil, err
	}
	return c.(*net.UnixConn), nil
}

func (l *fakeLauncher) Socketpair(_ backend.WarmSpec, pid int, typ int) ([2]int, error) {
	l.record("socketpair:" + strconv.Itoa(pid))
	return syscall.Socketpair(syscall.AF_UNIX, typ|syscall.SOCK_CLOEXEC, 0)
}

func (l *fakeLauncher) PID(context.Context, backend.WarmSpec, *exec.Cmd) (int, error) {
	l.record("pid")
	if l.pidErr != nil {
		return 0, l.pidErr
	}
	return l.pid, nil
}

func (l *fakeLauncher) Restored(_ backend.WarmSpec, pid int) error {
	l.record("restored:" + strconv.Itoa(pid))
	return l.restoredErr
}
func (l *fakeLauncher) RestoredGone(backend.WarmSpec) { l.record("restoredGone") }
func (l *fakeLauncher) Release(backend.WarmSpec)      { l.record("release") }
func (l *fakeLauncher) Endpoint(_ backend.WarmSpec, p string) string {
	return filepath.Join(l.endpointRoot, filepath.Base(p))
}
func (l *fakeLauncher) DumpExtra(backend.WarmSpec, string) ([]string, error) {
	return []string{"--dump-extra"}, nil
}
func (l *fakeLauncher) RestoreExtra(_ backend.WarmSpec, dir string) ([]string, error) {
	l.record("restoreExtra:" + dir)
	if l.restoreExtraErr != nil {
		return nil, l.restoreExtraErr
	}
	return []string{"--restore-extra"}, nil
}

// nopLauncher is a launcher that does nothing, for tests of the backend's
// own bookkeeping with one set.
type nopLauncher struct{}

func (nopLauncher) Name() string { return "nop" }
func (nopLauncher) Command(backend.WarmSpec, []string, *os.File, *os.File) (*exec.Cmd, error) {
	return nil, errors.New("unused")
}
func (nopLauncher) PID(context.Context, backend.WarmSpec, *exec.Cmd) (int, error) { return 0, nil }
func (nopLauncher) Channel(_ context.Context, _ backend.WarmSpec, _ *exec.Cmd, boot *net.UnixConn) (*net.UnixConn, error) {
	return boot, nil
}
func (nopLauncher) Socketpair(_ backend.WarmSpec, _ int, typ int) ([2]int, error) {
	return syscall.Socketpair(syscall.AF_UNIX, typ|syscall.SOCK_CLOEXEC, 0)
}
func (nopLauncher) Restored(backend.WarmSpec, int) error                    { return nil }
func (nopLauncher) RestoredGone(backend.WarmSpec)                           {}
func (nopLauncher) Release(backend.WarmSpec)                                {}
func (nopLauncher) Endpoint(_ backend.WarmSpec, p string) string            { return p }
func (nopLauncher) DumpExtra(backend.WarmSpec, string) ([]string, error)    { return nil, nil }
func (nopLauncher) RestoreExtra(backend.WarmSpec, string) ([]string, error) { return nil, nil }
