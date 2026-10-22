//go:build linux

package hyperlight

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
)

// TestParseFacts checks that the four facts parse, or what is wrong with them.
func TestParseFacts(t *testing.T) {
	cases := []struct {
		name    string
		tokens  []string
		want    facts
		wantErr string
	}{
		{name: "four facts", tokens: strings.Fields(kvmIntel),
			want: facts{helper: "fiberd-hyperlight-helper/0.1.0", hyperlight: "hyperlight_host/0.17.0", hypervisor: "kvm", cpu: "GenuineIntel"}},
		{name: "none", tokens: nil, wantErr: "want 4 facts"},
		{name: "three", tokens: []string{"h", "hl", "kvm"}, wantErr: "want 4 facts"},
		{name: "five", tokens: []string{"h", "hl", "kvm", "cpu", "more"}, wantErr: "want 4 facts"},
		{name: "an empty fact", tokens: []string{"h", "", "kvm", "cpu"}, wantErr: "empty fact"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseFacts(tc.tokens)
			if tc.wantErr != "" {
				if !errors.Is(err, ErrHelper) || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("parseFacts = %v, want ErrHelper containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("parseFacts = %+v, %v, want %+v", got, err, tc.want)
			}
		})
	}
}

// TestPlatform checks the facts in the parity fields, or that nothing can
// be warmed here.
func TestPlatform(t *testing.T) {
	cases := []struct {
		name    string
		starter *fakeStarter
		want    artifact.Platform
	}{
		{name: "a usable helper", starter: says(kvmIntel),
			want: artifact.Platform{Kernel: "hyperlight-hyperlight_host/0.17.0", Libc: "fiberd-hyperlight-helper/0.1.0+kvm+GenuineIntel"}},
		{name: "the fake helper", starter: says(fake), want: artifact.Platform{Kernel: "hyperlight-none", Libc: "fakehelper/2+none+none"}},
		{name: "no usable helper", starter: &fakeStarter{versionErr: errors.New("exit status 1")}, want: artifact.Platform{Kernel: "hyperlight-unusable", Libc: "n/a"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := newFake(t, Options{Helper: "helper"}, tc.starter)
			if got := be.Platform(); got != tc.want {
				t.Fatalf("Platform = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestSurface checks what the backend tells the host about itself.
func TestSurface(t *testing.T) {
	be := newFake(t, Options{Helper: "helper"}, says(kvmIntel))
	cases := []struct {
		name  string
		check func(t *testing.T)
	}{
		{name: "the name", check: func(t *testing.T) {
			if be.Name() != "hyperlight" {
				t.Fatalf("Name = %q", be.Name())
			}
		}},
		{name: "fibers are tenants behind a hypervisor", check: func(t *testing.T) {
			if !be.IsolatesTenants() {
				t.Fatal("IsolatesTenants = false")
			}
		}},
		{name: "fibers have no workspace, so a grant with a disk budget is refused", check: func(t *testing.T) {
			if _, ok := any(be).(backend.WorkspaceHolder); ok {
				t.Fatal("hyperlight implements backend.WorkspaceHolder, but its guest has no file system")
			}
		}},
		{name: "the deadlines", check: func(t *testing.T) {
			if c, r := be.DefaultDeadlines(""); c != 500*time.Millisecond || r != 2*time.Second {
				t.Fatalf("DefaultDeadlines = %s, %s", c, r)
			}
		}},
		{name: "a fiber costs a whole sandbox", check: func(t *testing.T) {
			if got := be.FiberOverheadBytes(); got != 0 {
				t.Fatalf("FiberOverheadBytes = %d, want 0 (measure it)", got)
			}
		}},
		{name: "W of a fiber it does not know", check: func(t *testing.T) {
			if w, ok := be.FiberW("nope"); ok || w != 0 {
				t.Fatalf("FiberW = %d, %v, want unknown", w, ok)
			}
		}},
		{name: "exits are delivered on one channel", check: func(t *testing.T) {
			first, second := be.Exits(), be.Exits()
			if first == nil || first != second {
				t.Fatal("Exits is not one channel")
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, tc.check)
	}
}

// TestDeadlineMS checks the deadline the helper is told, in milliseconds.
func TestDeadlineMS(t *testing.T) {
	cases := []struct {
		name string
		d    time.Duration
		want int64
	}{
		{name: "none means the create deadline", d: 0, want: 500},
		{name: "negative means the create deadline", d: -time.Second, want: 500},
		{name: "a deadline", d: 1500 * time.Millisecond, want: 1500},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := deadlineMS(tc.d); got != tc.want {
				t.Fatalf("deadlineMS(%s) = %d, want %d", tc.d, got, tc.want)
			}
		})
	}
}

// TestPayloadHex checks the payload as one field, "-" for none.
func TestPayloadHex(t *testing.T) {
	cases := []struct {
		name string
		p    []byte
		want string
	}{
		{name: "none", p: nil, want: "-"},
		{name: "empty", p: []byte{}, want: "-"},
		{name: "bytes", p: []byte("hi"), want: "6869"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := payloadHex(tc.p); got != tc.want {
				t.Fatalf("payloadHex(%q) = %q, want %q", tc.p, got, tc.want)
			}
		})
	}
}

// TestFakeHelperProtocol drives the backend over hack/hyperlight's fake
// helper, run as a goroutine over the control socket, in the order of a
// grant's life. That is warm, clone, W, park, kill, resume, and the ends
// of fibers and of the helper itself. Each step builds on the one
// before, so a failure stops the sequence.
func TestFakeHelperProtocol(t *testing.T) {
	guest := filepath.Join(t.TempDir(), "guest.bin")
	if err := os.WriteFile(guest, []byte("fake guest"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &fakeStarter{version: fake}
	be := newFake(t, Options{Helper: "fakehelper", Guest: guest}, s)
	work := filepath.Join(t.TempDir(), "run", "g1")
	park := filepath.Join(t.TempDir(), "park")
	ep := func(fence string) string { return filepath.Join(work, fence+".sock") }
	ctx := context.Background()
	var warm backend.Warm

	steps := []struct {
		name string
		run  func(t *testing.T)
	}{
		{name: "Warm: the fake reports its facts and the tier is FIBER_SNAPSHOT", run: func(t *testing.T) {
			if be.Tier() != core.TierSnapshot {
				t.Fatalf("tier = %s", be.Tier())
			}
			var err error
			warm, err = be.Warm(warmCtx(t), backend.WarmSpec{GrantUID: "g1", WorkDir: work, CgroupFD: -1, ProbeCgroupFD: -1,
				Template: backend.Template{Argv: []string{"guest", "--init-ms", "5"}}})
			if err != nil {
				t.Fatal(err)
			}
			if warm.ID != "g1" || warm.PID <= 0 {
				t.Fatalf("Warm = %+v", warm)
			}
		}},
		{name: "Clone: the fiber serves its endpoint under its fence", run: func(t *testing.T) {
			f, err := be.Clone(ctx, "g1", backend.FiberSpec{Fence: "f1", Endpoint: ep("f1"), CgroupFD: -1, Deadline: time.Second,
				Payload: []byte(`{"dirty_bytes": 1048576}`), Generation: 1})
			if err != nil {
				t.Fatal(err)
			}
			if f.ID != "f1" || f.PID != 0 {
				t.Fatalf("Clone = %+v, want f1 without a process", f)
			}
			if got := talk(t, ep("f1"), "ping"); got != "pong" {
				t.Fatalf("ping = %q", got)
			}
			if got := talk(t, ep("f1"), "fence"); got != "f1" {
				t.Fatalf("fence = %q", got)
			}
			if got := talk(t, ep("f1"), "kind") + " " + talk(t, ep("f1"), "generation"); got != "clone 1" {
				t.Fatalf("kind and generation = %q, want \"clone 1\"", got)
			}
		}},
		{name: "W: what the payload dirtied, then what the guest dirties", run: func(t *testing.T) {
			awaitW(t, be, "f1", 1<<20)
			if got := talk(t, ep("f1"), "dirty 4096"); got != "ok 4096" {
				t.Fatalf("dirty = %q", got)
			}
			awaitW(t, be, "f1", 1<<20+4096)
		}},
		{name: "Park with sync: the state is written and the fiber keeps running", run: func(t *testing.T) {
			talk(t, ep("f1"), "incr")
			talk(t, ep("f1"), "incr")
			if err := be.Park(ctx, "f1", backend.ParkSpec{Dir: park, Sync: true}); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(park, "state.json")); err != nil {
				t.Fatalf("no state: %v", err)
			}
			if st, err := os.Stat(filepath.Join(park, "pages.bin")); err != nil || st.Size() != 1<<20+4096 {
				t.Fatalf("pages = %v, %v, want the dirtied bytes", st, err)
			}
			if _, err := os.Stat(ep("f1")); err == nil {
				t.Fatal("the endpoint is still there after the park")
			}
			if _, ok := be.FiberW("f1"); !ok {
				t.Fatal("the fiber is gone after a sync park")
			}
		}},
		{name: "Kill: EXITED is reported and the fiber forgotten", run: func(t *testing.T) {
			if err := be.Kill("f1"); err != nil {
				t.Fatal(err)
			}
			if e := awaitExit(t, be); e != (backend.Exit{FiberID: "f1", Status: "exit:137"}) {
				t.Fatalf("exit = %+v", e)
			}
			if _, ok := be.FiberW("f1"); ok {
				t.Fatal("the fiber is still known after its exit")
			}
		}},
		{name: "Resume: the parked state comes back under a new fence", run: func(t *testing.T) {
			f, err := be.Resume(ctx, backend.ResumeSpec{Dir: park, Fence: "f2", Endpoint: ep("f2"), CgroupFD: -1, Deadline: 2 * time.Second, WarmID: "g1", WorkDir: work, Generation: 2})
			if err != nil {
				t.Fatal(err)
			}
			if f.ID != "f2" {
				t.Fatalf("Resume = %+v", f)
			}
			if got := talk(t, ep("f2"), "get"); got != "2" {
				t.Fatalf("counter after resume = %q, want 2", got)
			}
			if got := talk(t, ep("f2"), "fence"); got != "f2" {
				t.Fatalf("fence after resume = %q", got)
			}
			if got := talk(t, ep("f2"), "kind") + " " + talk(t, ep("f2"), "generation"); got != "resume 2" {
				t.Fatalf("kind and generation after resume = %q, want \"resume 2\"", got)
			}
			awaitW(t, be, "f2", 1<<20+4096)
		}},
		{name: "Park without sync ends the fiber", run: func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "park2")
			if err := be.Park(ctx, "f2", backend.ParkSpec{Dir: dir}); err != nil {
				t.Fatal(err)
			}
			if e := awaitExit(t, be); e != (backend.Exit{FiberID: "f2", Status: "exit:0"}) {
				t.Fatalf("exit = %+v", e)
			}
			if _, err := os.Stat(filepath.Join(dir, "state.json")); err != nil {
				t.Fatalf("no state: %v", err)
			}
		}},
		{name: "Clone past its deadline is a miss and the fiber is forgotten", run: func(t *testing.T) {
			_, err := be.Clone(ctx, "g1", backend.FiberSpec{Fence: "f3", Endpoint: ep("f3"), CgroupFD: -1, Deadline: 100 * time.Millisecond,
				Payload: []byte(`{"ready_delay_ms": 3000}`), Generation: 1})
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Clone = %v, want the deadline exceeded", err)
			}
			if _, ok := be.FiberW("f3"); ok {
				t.Fatal("a fiber that missed is still known")
			}
		}},
		{name: "Resume from an empty directory is the helper's error", run: func(t *testing.T) {
			_, err := be.Resume(ctx, backend.ResumeSpec{Dir: filepath.Join(t.TempDir(), "nothing"), Fence: "f4", Endpoint: ep("f4"), CgroupFD: -1, WarmID: "g1", Generation: 2})
			if !errors.Is(err, ErrHelper) || !strings.Contains(err.Error(), "state.json") {
				t.Fatalf("Resume = %v, want ErrHelper about state.json", err)
			}
			if _, ok := be.FiberW("f4"); ok {
				t.Fatal("a fiber that failed to resume is still known")
			}
		}},
		{name: "Clone and Resume under a warm that is not there", run: func(t *testing.T) {
			if _, err := be.Clone(ctx, "g9", backend.FiberSpec{Fence: "f5", Endpoint: ep("f5"), CgroupFD: -1}); err == nil || !strings.Contains(err.Error(), `no warm helper "g9"`) {
				t.Fatalf("Clone = %v", err)
			}
			if _, err := be.Resume(ctx, backend.ResumeSpec{Fence: "f5", WarmID: "g9", CgroupFD: -1}); err == nil || !strings.Contains(err.Error(), `no warm helper "g9"`) {
				t.Fatalf("Resume = %v", err)
			}
		}},
		{name: "Park and Kill of a fiber that is not there", run: func(t *testing.T) {
			if err := be.Park(ctx, "f9", backend.ParkSpec{Dir: t.TempDir()}); err == nil || !strings.Contains(err.Error(), `unknown fiber "f9"`) {
				t.Fatalf("Park = %v", err)
			}
			if err := be.Kill("f9"); err != nil {
				t.Fatalf("Kill = %v, want nothing to do", err)
			}
		}},
		{name: "Unwarm: the helper is ended and its exit reported, with its fibers as orphans", run: func(t *testing.T) {
			f, err := be.Clone(ctx, "g1", backend.FiberSpec{Fence: "f6", Endpoint: ep("f6"), CgroupFD: -1, Deadline: time.Second, Generation: 1})
			if err != nil {
				t.Fatal(err)
			}
			be.Unwarm("g1")
			awaitRun(t, s.started()[0])
			got := []backend.Exit{awaitExit(t, be), awaitExit(t, be)}
			want := []backend.Exit{{FiberID: f.ID, Status: "signal:helper"}, {WarmID: "g1", Status: "helper exited"}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("exits = %+v, want %+v", got, want)
			}
			// The helper took its sandboxes with it.
			if _, err := os.Stat(ep("f6")); err == nil {
				t.Fatal("the orphan's endpoint is still there")
			}
			if _, err := be.Clone(ctx, "g1", backend.FiberSpec{Fence: "f7", Endpoint: ep("f7"), CgroupFD: -1}); err == nil {
				t.Fatal("a clone under the unwarmed helper succeeded")
			}
			be.Unwarm("g1") // nothing to do twice
		}},
	}
	for _, s := range steps {
		if !t.Run(s.name, s.run) {
			t.Fatalf("stopping after %q", s.name)
		}
	}
}

// pipe is an in-process helper. The backend's end is h.ctl, and the test
// reads commands from and writes replies to the other.
type pipe struct {
	b      *Backend
	h      *helper
	theirs *net.UnixConn
	rd     *bufio.Reader
	last   string // the last command line heard by TestCommands
}

// sameLine is got against want, where want's SEED stands for any 32
// hex bytes: a CLONE or RESUME carries a seed drawn per call.
func sameLine(got, want string) bool {
	g, w := strings.Fields(got), strings.Fields(want)
	if len(g) != len(w) {
		return false
	}
	for i := range w {
		if w[i] == "SEED" {
			if b, err := hex.DecodeString(g[i]); err != nil || len(b) != backend.SeedBytes {
				return false
			}
			continue
		}
		if g[i] != w[i] {
			return false
		}
	}
	return true
}

// seedOf is the last field of a CLONE or RESUME line.
func seedOf(line string) string {
	f := strings.Fields(line)
	return f[len(f)-1]
}

// newPipe wires a helper over a socketpair and starts the read loop.
func newPipe(t *testing.T) *pipe {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	conn := func(fd int, name string) *net.UnixConn {
		f := os.NewFile(uintptr(fd), name)
		defer func() { _ = f.Close() }()
		c, err := net.FileConn(f)
		if err != nil {
			t.Fatal(err)
		}
		return c.(*net.UnixConn)
	}
	ours, theirs := conn(fds[0], "ours"), conn(fds[1], "theirs")
	// Closing both ends is what ends the read loop, so the leak check
	// runs after it (cleanups run last registered first).
	t.Cleanup(func() { goleak.VerifyNone(t) })
	t.Cleanup(func() { _ = ours.Close(); _ = theirs.Close() })
	b := &Backend{warms: map[string]*helper{}, fibers: map[string]*fiber{}, exits: make(chan backend.Exit, 16), tier: core.TierSnapshot}
	h := &helper{id: "g1", ctl: ours, pend: map[string]chan reply{}, gone: make(chan struct{})}
	b.warms[h.id] = h
	go b.read(h, bufio.NewReader(ours))
	return &pipe{b: b, h: h, theirs: theirs, rd: bufio.NewReader(theirs)}
}

// fiber registers a fiber of the helper.
func (p *pipe) fiber(id string) {
	p.b.mu.Lock()
	p.b.fibers[id] = &fiber{id: id, warmID: p.h.id}
	p.b.mu.Unlock()
}

// say writes helper lines to the backend.
func (p *pipe) say(t *testing.T, lines ...string) {
	t.Helper()
	for _, l := range lines {
		if _, err := p.theirs.Write([]byte(l + "\n")); err != nil {
			t.Fatal(err)
		}
	}
}

// hear reads the next command line the backend sent.
func (p *pipe) hear(t *testing.T) string {
	t.Helper()
	_ = p.theirs.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := p.rd.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the backend's command: %v", err)
	}
	return strings.TrimSuffix(line, "\n")
}

// hangUp is the helper exiting, which closes its end of the socket.
func (p *pipe) hangUp() { _ = p.theirs.Close() }

// asked runs ask in the background.
type asked struct {
	r   reply
	err error
}

func (p *pipe) ask(ctx context.Context, fence, line string) <-chan asked {
	ch := make(chan asked, 1)
	go func() {
		r, err := p.b.ask(ctx, p.h, fence, []byte(line))
		ch <- asked{r, err}
	}()
	return ch
}

// TestReadLoop covers every line the helper may send, well formed or not, and
// what the helper hanging up does to what is pending.
func TestReadLoop(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T, p *pipe)
	}{
		{name: "a line too short to mean anything is skipped", run: func(t *testing.T, p *pipe) {
			got := p.ask(context.Background(), "f", "CLONE f /ep 500 -")
			if line := p.hear(t); line != "CLONE f /ep 500 -" {
				t.Fatalf("sent %q", line)
			}
			p.say(t, "", "JUNK", "CLONED f")
			if a := await(t, got); a.err != nil {
				t.Fatalf("ask = %v", a.err)
			}
		}},
		{name: "PARKED carries the bytes", run: func(t *testing.T, p *pipe) {
			got := p.ask(context.Background(), "f", "PARK f /d 1")
			p.hear(t)
			p.say(t, "PARKED f 42")
			if a := await(t, got); a.err != nil || a.r.bytes != 42 {
				t.Fatalf("ask = %+v, %v", a.r, a.err)
			}
		}},
		{name: "PARKED with bytes that are not a number", run: func(t *testing.T, p *pipe) {
			got := p.ask(context.Background(), "f", "PARK f /d 1")
			p.hear(t)
			p.say(t, "PARKED f lots")
			if a := await(t, got); a.err != nil || a.r.bytes != 0 {
				t.Fatalf("ask = %+v, %v", a.r, a.err)
			}
		}},
		{name: "PARKED without bytes is still the answer", run: func(t *testing.T, p *pipe) {
			got := p.ask(context.Background(), "f", "PARK f /d 1")
			p.hear(t)
			p.say(t, "PARKED f")
			if a := await(t, got); a.err != nil || a.r.bytes != 0 {
				t.Fatalf("ask = %+v, %v", a.r, a.err)
			}
		}},
		{name: "ERROR carries the helper's text", run: func(t *testing.T, p *pipe) {
			got := p.ask(context.Background(), "f", "CLONE f /ep 500 -")
			p.hear(t)
			p.say(t, "ERROR f bind: address in use")
			if a := await(t, got); !errors.Is(a.err, ErrHelper) || !strings.Contains(a.err.Error(), "bind: address in use") {
				t.Fatalf("ask = %v", a.err)
			}
		}},
		{name: "a reply for a fence nobody waits on is dropped", run: func(t *testing.T, p *pipe) {
			p.say(t, "CLONED stray", "ERROR stray gone", "PARKED stray 1")
			got := p.ask(context.Background(), "f", "CLONE f /ep 500 -")
			p.hear(t)
			p.say(t, "CLONED f")
			if a := await(t, got); a.err != nil {
				t.Fatalf("ask after stray replies = %v", a.err)
			}
		}},
		{name: "W of a known fiber is recorded, a short or unknown one dropped", run: func(t *testing.T, p *pipe) {
			p.fiber("f")
			p.say(t, "W nobody 99", "W f", "W f 7")
			awaitW(t, p.b, "f", 7)
			p.say(t, "W f 9")
			awaitW(t, p.b, "f", 9)
			if w, ok := p.b.FiberW("nobody"); ok || w != 0 {
				t.Fatalf("FiberW(nobody) = %d, %v", w, ok)
			}
		}},
		{name: "EXITED with and without a status, and for a fiber unknown", run: func(t *testing.T, p *pipe) {
			p.fiber("a")
			p.fiber("b")
			p.say(t, "EXITED nobody exit:0", "EXITED a", "EXITED b signal:KILL")
			if e := awaitExit(t, p.b); e != (backend.Exit{FiberID: "a", Status: "exit:?"}) {
				t.Fatalf("first exit = %+v, want a's with an unknown status", e)
			}
			if e := awaitExit(t, p.b); e != (backend.Exit{FiberID: "b", Status: "signal:KILL"}) {
				t.Fatalf("second exit = %+v", e)
			}
			if _, ok := p.b.FiberW("a"); ok {
				t.Fatal("a is still known after its exit")
			}
		}},
		{name: "the helper hangs up: pending asks fail, fibers are orphans, the warm is gone", run: func(t *testing.T, p *pipe) {
			p.fiber("f")
			got := p.ask(context.Background(), "f", "PARK f /d 0")
			p.hear(t)
			p.hangUp()
			if a := await(t, got); !errors.Is(a.err, ErrHelper) || !strings.Contains(a.err.Error(), "helper exited") {
				t.Fatalf("ask = %v", a.err)
			}
			exits := []backend.Exit{awaitExit(t, p.b), awaitExit(t, p.b)}
			want := []backend.Exit{{FiberID: "f", Status: "signal:helper"}, {WarmID: "g1", Status: "helper exited"}}
			if !reflect.DeepEqual(exits, want) {
				t.Fatalf("exits = %+v, want %+v", exits, want)
			}
			if _, ok := p.b.warmOf("g1"); ok {
				t.Fatal("the warm is still registered")
			}
			if _, ok := p.b.FiberW("f"); ok {
				t.Fatal("the orphan is still known")
			}
			await(t, p.h.gone)
		}},
		{name: "a helper replaced before it hung up leaves the new one alone", run: func(t *testing.T, p *pipe) {
			other := &helper{id: "g1"}
			p.b.mu.Lock()
			p.b.warms["g1"] = other
			p.b.mu.Unlock()
			p.hangUp()
			if e := awaitExit(t, p.b); e != (backend.Exit{WarmID: "g1", Status: "helper exited"}) {
				t.Fatalf("exit = %+v", e)
			}
			if h, ok := p.b.warmOf("g1"); !ok || h != other {
				t.Fatal("the replacement was removed")
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, newPipe(t)) })
	}
}

// TestAsk checks one command per fence in flight, and the ways waiting
// ends.
func TestAsk(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T, p *pipe)
	}{
		{name: "a second command on a fence in flight is refused", run: func(t *testing.T, p *pipe) {
			first := p.ask(context.Background(), "f", "PARK f /d 1")
			p.hear(t)
			_, err := p.b.ask(context.Background(), p.h, "f", []byte("KILL f"))
			if err == nil || !strings.Contains(err.Error(), "still in flight") {
				t.Fatalf("second ask = %v", err)
			}
			p.say(t, "PARKED f 1")
			if a := await(t, first); a.err != nil {
				t.Fatalf("first ask = %v", a.err)
			}
		}},
		{name: "the caller gives up, and the fence is free again", run: func(t *testing.T, p *pipe) {
			ctx, cancel := context.WithCancel(context.Background())
			got := p.ask(ctx, "f", "PARK f /d 1")
			p.hear(t)
			cancel()
			if a := await(t, got); !errors.Is(a.err, context.Canceled) {
				t.Fatalf("ask = %v", a.err)
			}
			again := p.ask(context.Background(), "f", "PARK f /d 1")
			p.hear(t)
			p.say(t, "PARKED f 1")
			if a := await(t, again); a.err != nil {
				t.Fatalf("ask after a cancelled one = %v", a.err)
			}
		}},
		{name: "a socket the backend closed", run: func(t *testing.T, p *pipe) {
			_ = p.h.ctl.Close()
			_, err := p.b.ask(context.Background(), p.h, "f", []byte("KILL f"))
			if err == nil || !strings.Contains(err.Error(), "send:") {
				t.Fatalf("ask = %v", err)
			}
			again := p.ask(context.Background(), "f", "KILL f")
			if a := await(t, again); a.err == nil || strings.Contains(a.err.Error(), "in flight") {
				t.Fatalf("the failed send left the fence in flight: %v", a.err)
			}
		}},
		{name: "the helper exits while asked", run: func(t *testing.T, p *pipe) {
			got := p.ask(context.Background(), "f", "PARK f /d 1")
			p.hear(t)
			p.hangUp()
			if a := await(t, got); !errors.Is(a.err, ErrHelper) {
				t.Fatalf("ask = %v", a.err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, newPipe(t)) })
	}
}

// TestCommands checks the line each operation sends, and what its reply or
// its absence becomes.
func TestCommands(t *testing.T) {
	cases := []struct {
		name     string
		setup    func(t *testing.T, p *pipe, dir string)
		do       func(ctx context.Context, p *pipe, dir string) error
		wantLine string // "" when nothing must be sent
		reply    string // "" to leave the backend waiting
		after    string // a line expected after the reply
		wantDir  bool   // the park directory is made
		wantIs   error
		wantErr  string
		check    func(t *testing.T, p *pipe)
	}{
		{name: "CLONE with the defaults", wantLine: "CLONE f /ep 500 - 1 SEED", reply: "CLONED f",
			do: func(ctx context.Context, p *pipe, _ string) error {
				_, err := p.b.Clone(ctx, "g1", backend.FiberSpec{Fence: "f", Endpoint: "/ep", CgroupFD: -1, Generation: 1})
				return err
			},
			check: func(t *testing.T, p *pipe) {
				if _, ok := p.b.FiberW("f"); !ok {
					t.Fatal("the cloned fiber is not known")
				}
			}},
		{name: "CLONE with a deadline, a payload and a later generation", wantLine: "CLONE f /ep 1500 6869 3 SEED", reply: "CLONED f",
			do: func(ctx context.Context, p *pipe, _ string) error {
				_, err := p.b.Clone(ctx, "g1", backend.FiberSpec{Fence: "f", Endpoint: "/ep", CgroupFD: -1, Deadline: 1500 * time.Millisecond, Payload: []byte("hi"), Generation: 3})
				return err
			}},
		{name: "CLONE without a generation is refused before anything is sent", wantErr: "generation 0 is not an incarnation",
			do: func(ctx context.Context, p *pipe, _ string) error {
				_, err := p.b.Clone(ctx, "g1", backend.FiberSpec{Fence: "f", Endpoint: "/ep", CgroupFD: -1})
				return err
			},
			check: func(t *testing.T, p *pipe) {
				if _, ok := p.b.FiberW("f"); ok {
					t.Fatal("a fiber that was refused is known")
				}
			}},
		{name: "two CLONEs carry two seeds", wantLine: "CLONE f /ep 500 - 1 SEED", reply: "CLONED f",
			do: func(ctx context.Context, p *pipe, _ string) error {
				_, err := p.b.Clone(ctx, "g1", backend.FiberSpec{Fence: "f", Endpoint: "/ep", CgroupFD: -1, Generation: 1})
				return err
			},
			check: func(t *testing.T, p *pipe) {
				first := p.last
				done := make(chan error, 1)
				go func() {
					_, err := p.b.Clone(context.Background(), "g1", backend.FiberSpec{Fence: "f2", Endpoint: "/ep2", CgroupFD: -1, Generation: 1})
					done <- err
				}()
				second := p.hear(t)
				p.say(t, "CLONED f2")
				if err := await(t, done); err != nil {
					t.Fatal(err)
				}
				if seedOf(first) == seedOf(second) {
					t.Fatalf("both CLONEs carry the seed %s", seedOf(first))
				}
			}},
		{name: "CLONE refused by the helper: the fiber is forgotten and killed to be sure", wantLine: "CLONE f /ep 500 - 1 SEED", reply: "ERROR f no memory", after: "KILL f",
			wantIs: ErrHelper, wantErr: "no memory",
			do: func(ctx context.Context, p *pipe, _ string) error {
				_, err := p.b.Clone(ctx, "g1", backend.FiberSpec{Fence: "f", Endpoint: "/ep", CgroupFD: -1, Generation: 1})
				return err
			},
			check: func(t *testing.T, p *pipe) {
				if _, ok := p.b.FiberW("f"); ok {
					t.Fatal("the refused fiber is still known")
				}
			}},
		{name: "CLONE past its deadline", wantLine: "CLONE f /ep 50 - 1 SEED", after: "KILL f", wantIs: context.DeadlineExceeded,
			do: func(ctx context.Context, p *pipe, _ string) error {
				_, err := p.b.Clone(ctx, "g1", backend.FiberSpec{Fence: "f", Endpoint: "/ep", CgroupFD: -1, Deadline: 50 * time.Millisecond, Generation: 1})
				return err
			}},
		{name: "RESUME carries the parked generation plus one", wantLine: "RESUME f DIR /ep 2000 2 SEED", reply: "CLONED f",
			do: func(ctx context.Context, p *pipe, dir string) error {
				_, err := p.b.Resume(ctx, backend.ResumeSpec{Fence: "f", Dir: dir, Endpoint: "/ep", CgroupFD: -1, Deadline: 2 * time.Second, WarmID: "g1", Generation: 2})
				return err
			}},
		{name: "RESUME without a generation is refused before anything is sent", wantErr: "generation 0 is not an incarnation",
			do: func(ctx context.Context, p *pipe, dir string) error {
				_, err := p.b.Resume(ctx, backend.ResumeSpec{Fence: "f", Dir: dir, Endpoint: "/ep", CgroupFD: -1, WarmID: "g1"})
				return err
			}},
		{name: "PARK with sync", wantLine: "PARK f DIR 1", reply: "PARKED f 10", wantDir: true,
			setup: func(_ *testing.T, p *pipe, _ string) { p.fiber("f") },
			do: func(ctx context.Context, p *pipe, dir string) error {
				return p.b.Park(ctx, "f", backend.ParkSpec{Dir: dir, Sync: true})
			},
			check: func(t *testing.T, p *pipe) {
				if _, ok := p.b.FiberW("f"); !ok {
					t.Fatal("a sync park forgot the fiber")
				}
			}},
		{name: "PARK without sync makes the directory", wantLine: "PARK f DIR 0", reply: "PARKED f 10", wantDir: true,
			setup: func(_ *testing.T, p *pipe, _ string) { p.fiber("f") },
			do: func(ctx context.Context, p *pipe, dir string) error {
				return p.b.Park(ctx, "f", backend.ParkSpec{Dir: dir})
			}},
		{name: "PARK refused by the helper", wantLine: "PARK f DIR 0", reply: "ERROR f unknown fiber", wantIs: ErrHelper, wantErr: "unknown fiber",
			setup: func(_ *testing.T, p *pipe, _ string) { p.fiber("f") },
			do: func(ctx context.Context, p *pipe, dir string) error {
				return p.b.Park(ctx, "f", backend.ParkSpec{Dir: dir})
			}},
		{name: "PARK that gets no answer before the caller's deadline", wantLine: "PARK f DIR 0", wantIs: ErrHelper,
			wantErr: "no answer to PARK f before the caller's deadline: context deadline exceeded",
			setup:   func(_ *testing.T, p *pipe, _ string) { p.fiber("f") },
			do: func(ctx context.Context, p *pipe, dir string) error {
				ctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
				defer cancel()
				return p.b.Park(ctx, "f", backend.ParkSpec{Dir: dir})
			}},
		{name: "PARK that gets no answer within its own timeout", wantLine: "PARK f DIR 0", wantIs: ErrHelper,
			wantErr: "no answer to PARK f within 50ms",
			setup: func(t *testing.T, p *pipe, _ string) {
				p.fiber("f")
				was := parkTimeout
				parkTimeout = 50 * time.Millisecond
				t.Cleanup(func() { parkTimeout = was })
			},
			do: func(ctx context.Context, p *pipe, dir string) error {
				return p.b.Park(ctx, "f", backend.ParkSpec{Dir: dir})
			}},
		{name: "PARK whose caller gives up", wantLine: "PARK f DIR 0", wantIs: context.Canceled,
			setup: func(_ *testing.T, p *pipe, _ string) { p.fiber("f") },
			do: func(ctx context.Context, p *pipe, dir string) error {
				ctx, cancel := context.WithCancel(ctx)
				cancel()
				return p.b.Park(ctx, "f", backend.ParkSpec{Dir: dir})
			}},
		{name: "PARK into a directory that cannot be made", wantErr: "not a directory",
			setup: func(t *testing.T, p *pipe, dir string) {
				p.fiber("f")
				if err := os.WriteFile(filepath.Dir(dir), nil, 0o644); err != nil {
					t.Fatal(err)
				}
			},
			do: func(ctx context.Context, p *pipe, dir string) error {
				return p.b.Park(ctx, "f", backend.ParkSpec{Dir: dir})
			}},
		{name: "PARK of a fiber whose helper is gone", wantErr: `no helper for "f"`,
			setup: func(_ *testing.T, p *pipe, _ string) {
				p.b.mu.Lock()
				p.b.fibers["f"] = &fiber{id: "f", warmID: "g-gone"}
				p.b.mu.Unlock()
			},
			do: func(ctx context.Context, p *pipe, dir string) error {
				return p.b.Park(ctx, "f", backend.ParkSpec{Dir: dir})
			}},
		{name: "KILL", wantLine: "KILL f",
			setup: func(_ *testing.T, p *pipe, _ string) { p.fiber("f") },
			do:    func(_ context.Context, p *pipe, _ string) error { return p.b.Kill("f") }},
		{name: "KILL over a socket the backend closed", wantErr: "closed",
			setup: func(t *testing.T, p *pipe, _ string) {
				p.fiber("f")
				// The read loop sees the close and forgets the warm. The
				// helper is put back so Kill reaches the socket.
				_ = p.h.ctl.Close()
				await(t, p.h.gone)
				p.b.mu.Lock()
				p.b.warms[p.h.id] = p.h
				p.b.fibers["f"] = &fiber{id: "f", warmID: p.h.id}
				p.b.mu.Unlock()
			},
			do: func(_ context.Context, p *pipe, _ string) error { return p.b.Kill("f") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newPipe(t)
			dir := filepath.Join(t.TempDir(), "park", "f")
			if tc.setup != nil {
				tc.setup(t, p, dir)
			}
			done := make(chan error, 1)
			go func() { done <- tc.do(context.Background(), p, dir) }()
			if tc.wantLine != "" {
				got, want := p.hear(t), strings.ReplaceAll(tc.wantLine, "DIR", dir)
				if !sameLine(got, want) {
					t.Fatalf("sent %q, want %q", got, want)
				}
				p.last = got
				if tc.reply != "" {
					p.say(t, tc.reply)
				}
			}
			err := await(t, done)
			if tc.after != "" {
				if got := p.hear(t); got != tc.after {
					t.Fatalf("after the reply the backend sent %q, want %q", got, tc.after)
				}
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("err = %v, want %v", err, tc.wantIs)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want an error containing %q", err, tc.wantErr)
			}
			if tc.wantIs == nil && tc.wantErr == "" && err != nil {
				t.Fatalf("err = %v", err)
			}
			if tc.wantDir {
				if _, err := os.Stat(dir); err != nil {
					t.Fatalf("the park directory was not made: %v", err)
				}
			}
			if tc.check != nil {
				tc.check(t, p)
			}
		})
	}
}
