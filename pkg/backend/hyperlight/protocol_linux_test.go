//go:build linux

package hyperlight

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
)

// fakeHelperBin is hack/hyperlight/fakehelper, built once for the run.
// It is the helper the backend is tested against where no hypervisor is.
var fakeHelperBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "fiberd-hyperlight-unit")
	if err != nil {
		panic(err)
	}
	fakeHelperBin = filepath.Join(dir, "fakehelper")
	build := exec.Command("go", "build", "-o", fakeHelperBin, "../../../hack/hyperlight/fakehelper")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "cannot build the fake helper: %v\n", err)
		fakeHelperBin = ""
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// shellHelper writes a helper that answers `--version` with the kvm
// facts and otherwise runs body with the control socket as fd 3 and the
// run directory as its working directory.
func shellHelper(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "helper")
	script := "#!/bin/sh\nif [ \"$1\" = --version ]; then echo '" + kvmIntel + "'; exit 0; fi\n" + body + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// readyThenWait is a helper body that says READY and serves nothing.
const readyThenWait = "echo 'READY " + kvmIntel + "' >&3\nexec cat <&3 >/dev/null"

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
		name       string
		versionCmd string
		want       artifact.Platform
	}{
		{name: "a usable helper", versionCmd: says(kvmIntel),
			want: artifact.Platform{Kernel: "hyperlight-hyperlight_host/0.17.0", Libc: "fiberd-hyperlight-helper/0.1.0+kvm+GenuineIntel"}},
		{name: "the fake helper", versionCmd: says(fake), want: artifact.Platform{Kernel: "hyperlight-none", Libc: "fakehelper/1+none+none"}},
		{name: "no usable helper", versionCmd: "exit 1", want: artifact.Platform{Kernel: "hyperlight-unusable", Libc: "n/a"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := New(Options{Helper: fakeHelper(t, tc.versionCmd, kvmIntel)})
			if got := be.(backend.Platformer).Platform(); got != tc.want {
				t.Fatalf("Platform = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestSurface checks what the backend tells the host about itself.
func TestSurface(t *testing.T) {
	be := New(Options{Helper: fakeHelper(t, says(kvmIntel), kvmIntel)})
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
			if !be.(backend.Isolator).IsolatesTenants() {
				t.Fatal("IsolatesTenants = false")
			}
		}},
		{name: "the deadlines", check: func(t *testing.T) {
			if c, r := be.(backend.DeadlineAdvisor).DefaultDeadlines(); c != 500*time.Millisecond || r != 2*time.Second {
				t.Fatalf("DefaultDeadlines = %s, %s", c, r)
			}
		}},
		{name: "a fiber costs a whole sandbox", check: func(t *testing.T) {
			if got := be.(backend.Overheader).FiberOverheadBytes(); got != 0 {
				t.Fatalf("FiberOverheadBytes = %d, want 0 (measure it)", got)
			}
		}},
		{name: "W of a fiber it does not know", check: func(t *testing.T) {
			if w, ok := be.(backend.WReporter).FiberW("nope"); ok || w != 0 {
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

// warmCtx is a context a Warm must finish within.
func warmCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// waitGone waits for pid to be reaped.
func waitGone(t *testing.T, pid int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("process %d is still there", pid)
		}
	}
}

// TestWarm checks how the helper is started, and every way it fails to
// come up.
func TestWarm(t *testing.T) {
	cases := []struct {
		name    string
		body    string // the shell helper's body after --version
		opt     func(t *testing.T, helper string) Options
		setup   func(t *testing.T, be backend.Backend, sp *backend.WarmSpec, helper string)
		ctx     func(t *testing.T) context.Context
		wantIs  error
		wantErr string
		check   func(t *testing.T, be backend.Backend, sp backend.WarmSpec, w backend.Warm)
	}{
		{name: "the template's arguments follow the guest", body: "echo \"$@\" > args\n" + readyThenWait,
			opt: func(t *testing.T, helper string) Options {
				guest := filepath.Join(t.TempDir(), "guest.bin")
				if err := os.WriteFile(guest, []byte("guest"), 0o644); err != nil {
					t.Fatal(err)
				}
				return Options{Helper: helper, Guest: guest}
			},
			setup: func(_ *testing.T, _ backend.Backend, sp *backend.WarmSpec, _ string) {
				sp.Template.Argv = []string{"guest", "--init-ms", "5"}
			},
			check: func(t *testing.T, be backend.Backend, sp backend.WarmSpec, w backend.Warm) {
				if w.ID != sp.GrantUID || w.PID <= 0 {
					t.Errorf("Warm = %+v", w)
				}
				b, err := os.ReadFile(filepath.Join(sp.WorkDir, "args"))
				if err != nil || strings.TrimSpace(string(b)) != "--guest "+be.(*Backend).opt.Guest+" --init-ms 5" {
					t.Errorf("helper args = %q, %v", b, err)
				}
			}},
		{name: "a bare template passes nothing", body: "echo \"$@\" > args\n" + readyThenWait,
			setup: func(_ *testing.T, _ backend.Backend, sp *backend.WarmSpec, _ string) {
				sp.Template.Argv = []string{"guest"}
			},
			check: func(t *testing.T, _ backend.Backend, sp backend.WarmSpec, _ backend.Warm) {
				if b, err := os.ReadFile(filepath.Join(sp.WorkDir, "args")); err != nil || strings.TrimSpace(string(b)) != "" {
					t.Errorf("helper args = %q, %v, want none", b, err)
				}
			}},
		{name: "the helper's output goes to the zygote log", body: "echo hello from the helper\n" + readyThenWait,
			check: func(t *testing.T, _ backend.Backend, sp backend.WarmSpec, _ backend.Warm) {
				if b, err := os.ReadFile(filepath.Join(sp.WorkDir, "zygote.log")); err != nil || !strings.Contains(string(b), "hello from the helper") {
					t.Errorf("zygote.log = %q, %v", b, err)
				}
			}},
		{name: "the helper is born in the grant's cgroup", body: readyThenWait,
			setup: func(t *testing.T, _ backend.Backend, sp *backend.WarmSpec, _ string) {
				name := fmt.Sprintf("fiberd-unit-hl-%d", os.Getpid())
				p := filepath.Join("/sys/fs/cgroup", name)
				if err := os.Mkdir(p, 0o755); err != nil {
					t.Skipf("cannot make a cgroup: %v", err)
				}
				t.Cleanup(func() { _ = os.Remove(p) })
				f, err := os.Open(p)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = f.Close() })
				sp.CgroupFD = int(f.Fd())
			},
			check: func(t *testing.T, be backend.Backend, sp backend.WarmSpec, w backend.Warm) {
				b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", w.PID))
				if err != nil || !strings.Contains(string(b), fmt.Sprintf("fiberd-unit-hl-%d", os.Getpid())) {
					t.Errorf("helper cgroup = %q, %v", b, err)
				}
				// The cgroup must be empty before its directory can go.
				be.Unwarm(w.ID)
				waitGone(t, w.PID)
			}},
		{name: "no usable helper", body: readyThenWait, wantErr: "helper or guest unavailable",
			opt: func(_ *testing.T, helper string) Options { return Options{Helper: helper + "-missing"} }},
		{name: "the run directory cannot be made", body: readyThenWait, wantErr: "not a directory",
			setup: func(t *testing.T, _ backend.Backend, sp *backend.WarmSpec, _ string) {
				if err := os.WriteFile(filepath.Dir(sp.WorkDir), nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "the log cannot be opened", body: readyThenWait, wantErr: "is a directory",
			setup: func(t *testing.T, _ backend.Backend, sp *backend.WarmSpec, _ string) {
				if err := os.MkdirAll(filepath.Join(sp.WorkDir, "zygote.log"), 0o755); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "the helper cannot be started", body: readyThenWait, wantErr: "start helper",
			setup: func(t *testing.T, _ backend.Backend, _ *backend.WarmSpec, helper string) {
				if err := os.Chmod(helper, 0o644); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "the helper exits before READY", body: "exit 3", wantIs: io.EOF, wantErr: "did not become ready"},
		{name: "the helper says something else first", body: "echo HELLO >&3\n" + readyThenWait, wantIs: ErrHelper, wantErr: "expected READY"},
		{name: "the caller gives up", body: "exec sleep 30", wantIs: context.DeadlineExceeded,
			ctx: func(t *testing.T) context.Context {
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				t.Cleanup(cancel)
				return ctx
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			helper := shellHelper(t, tc.body)
			opt := Options{Helper: helper}
			if tc.opt != nil {
				opt = tc.opt(t, helper)
			}
			be := New(opt)
			defer be.Close()
			sp := backend.WarmSpec{GrantUID: "g1", WorkDir: filepath.Join(t.TempDir(), "run", "g1"), CgroupFD: -1, ProbeCgroupFD: -1}
			if tc.setup != nil {
				tc.setup(t, be, &sp, helper)
			}
			ctx := warmCtx(t)
			if tc.ctx != nil {
				ctx = tc.ctx(t)
			}
			before := children(t)
			w, err := be.Warm(ctx, sp)
			if tc.wantErr != "" || tc.wantIs != nil {
				if err == nil {
					t.Fatalf("Warm = %+v, want an error (%s %v)", w, tc.wantErr, tc.wantIs)
				}
				if tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Warm = %v, want an error containing %q", err, tc.wantErr)
				}
				if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
					t.Fatalf("Warm = %v, want %v", err, tc.wantIs)
				}
				if _, ok := be.(*Backend).warmOf(sp.GrantUID); ok {
					t.Fatal("a warm that failed is registered")
				}
				// The helper it started, if any, is killed and reaped.
				noNewChildren(t, before)
				return
			}
			if err != nil {
				t.Fatalf("Warm: %v", err)
			}
			tc.check(t, be, sp, w)
			be.Close()
			waitGone(t, w.PID)
		})
	}
}

// noNewChildren fails when a child this process did not have before is
// still there, alive or as a zombie nobody reaped, once a moment has
// passed.
func noNewChildren(t *testing.T, before []string) {
	t.Helper()
	had := map[string]bool{}
	for _, c := range before {
		had[strings.Fields(c)[0]] = true
	}
	var left []string
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		left = left[:0]
		for _, c := range children(t) {
			if !had[strings.Fields(c)[0]] {
				left = append(left, c)
			}
		}
		if len(left) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("children left behind: %v", left)
		}
	}
}

// children lists this process's children as "<pid> <comm> <state>".
func children(t *testing.T) []string {
	t.Helper()
	ents, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		// "<pid> (<comm>) <state> <ppid> ...", and comm may hold spaces.
		s := string(b)
		i := strings.LastIndexByte(s, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(s[i+1:])
		if len(f) < 2 || f[1] != fmt.Sprint(os.Getpid()) {
			continue
		}
		out = append(out, e.Name()+" "+s[strings.IndexByte(s, '(')+1:i]+" "+f[0])
	}
	return out
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

// TestFakeHelperProtocol drives the backend over hack/hyperlight's fake
// helper, in the order of a grant's life. That is warm, clone, W, park,
// kill, resume, and the ends of fibers and of the helper itself. Each
// step builds on the one before, so a failure stops the sequence.
func TestFakeHelperProtocol(t *testing.T) {
	if fakeHelperBin == "" {
		t.Fatal("the fake helper did not build")
	}
	guest := filepath.Join(t.TempDir(), "guest.bin")
	if err := os.WriteFile(guest, []byte("fake guest"), 0o644); err != nil {
		t.Fatal(err)
	}
	be := New(Options{Helper: fakeHelperBin, Guest: guest})
	defer be.Close()
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
				Payload: []byte(`{"dirty_bytes": 1048576}`)})
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
			if _, ok := be.(backend.WReporter).FiberW("f1"); !ok {
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
			if _, ok := be.(backend.WReporter).FiberW("f1"); ok {
				t.Fatal("the fiber is still known after its exit")
			}
		}},
		{name: "Resume: the parked state comes back under a new fence", run: func(t *testing.T) {
			f, err := be.Resume(ctx, backend.ResumeSpec{Dir: park, Fence: "f2", Endpoint: ep("f2"), CgroupFD: -1, Deadline: 2 * time.Second, WarmID: "g1", WorkDir: work})
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
				Payload: []byte(`{"ready_delay_ms": 3000}`)})
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Clone = %v, want the deadline exceeded", err)
			}
			if _, ok := be.(backend.WReporter).FiberW("f3"); ok {
				t.Fatal("a fiber that missed is still known")
			}
		}},
		{name: "Resume from an empty directory is the helper's error", run: func(t *testing.T) {
			_, err := be.Resume(ctx, backend.ResumeSpec{Dir: filepath.Join(t.TempDir(), "nothing"), Fence: "f4", Endpoint: ep("f4"), CgroupFD: -1, WarmID: "g1"})
			if !errors.Is(err, ErrHelper) || !strings.Contains(err.Error(), "state.json") {
				t.Fatalf("Resume = %v, want ErrHelper about state.json", err)
			}
			if _, ok := be.(backend.WReporter).FiberW("f4"); ok {
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
			f, err := be.Clone(ctx, "g1", backend.FiberSpec{Fence: "f6", Endpoint: ep("f6"), CgroupFD: -1, Deadline: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			be.Unwarm("g1")
			waitGone(t, warm.PID)
			got := []backend.Exit{awaitExit(t, be), awaitExit(t, be)}
			want := []backend.Exit{{FiberID: f.ID, Status: "signal:helper"}, {WarmID: "g1", Status: "helper exited"}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("exits = %+v, want %+v", got, want)
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
		r, err := p.b.ask(ctx, p.h, fence, line)
		ch <- asked{r, err}
	}()
	return ch
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
			_, err := p.b.ask(context.Background(), p.h, "f", "KILL f")
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
			_, err := p.b.ask(context.Background(), p.h, "f", "KILL f")
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
		{name: "CLONE with the defaults", wantLine: "CLONE f /ep 500 -", reply: "CLONED f",
			do: func(ctx context.Context, p *pipe, _ string) error {
				_, err := p.b.Clone(ctx, "g1", backend.FiberSpec{Fence: "f", Endpoint: "/ep", CgroupFD: -1})
				return err
			},
			check: func(t *testing.T, p *pipe) {
				if _, ok := p.b.FiberW("f"); !ok {
					t.Fatal("the cloned fiber is not known")
				}
			}},
		{name: "CLONE with a deadline and a payload", wantLine: "CLONE f /ep 1500 6869", reply: "CLONED f",
			do: func(ctx context.Context, p *pipe, _ string) error {
				_, err := p.b.Clone(ctx, "g1", backend.FiberSpec{Fence: "f", Endpoint: "/ep", CgroupFD: -1, Deadline: 1500 * time.Millisecond, Payload: []byte("hi")})
				return err
			}},
		{name: "CLONE refused by the helper: the fiber is forgotten and killed to be sure", wantLine: "CLONE f /ep 500 -", reply: "ERROR f no memory", after: "KILL f",
			wantIs: ErrHelper, wantErr: "no memory",
			do: func(ctx context.Context, p *pipe, _ string) error {
				_, err := p.b.Clone(ctx, "g1", backend.FiberSpec{Fence: "f", Endpoint: "/ep", CgroupFD: -1})
				return err
			},
			check: func(t *testing.T, p *pipe) {
				if _, ok := p.b.FiberW("f"); ok {
					t.Fatal("the refused fiber is still known")
				}
			}},
		{name: "CLONE past its deadline", wantLine: "CLONE f /ep 50 -", after: "KILL f", wantIs: context.DeadlineExceeded,
			do: func(ctx context.Context, p *pipe, _ string) error {
				_, err := p.b.Clone(ctx, "g1", backend.FiberSpec{Fence: "f", Endpoint: "/ep", CgroupFD: -1, Deadline: 50 * time.Millisecond})
				return err
			}},
		{name: "RESUME", wantLine: "RESUME f DIR /ep 2000", reply: "CLONED f",
			do: func(ctx context.Context, p *pipe, dir string) error {
				_, err := p.b.Resume(ctx, backend.ResumeSpec{Fence: "f", Dir: dir, Endpoint: "/ep", CgroupFD: -1, Deadline: 2 * time.Second, WarmID: "g1"})
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
				if got, want := p.hear(t), strings.ReplaceAll(tc.wantLine, "DIR", dir); got != want {
					t.Fatalf("sent %q, want %q", got, want)
				}
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
