package firecracker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/helayoty/fiberd/bench/compare"
)

// TestMain fails the package when a test leaves a goroutine behind,
// such as a handler's waiter outliving Release.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// call is one API request the fake Firecracker saw.
type call struct {
	Method, Path string
	Body         map[string]any
}

// fakeLauncher serves the Firecracker API on the socket, records every
// call, writes snapshot files on /snapshot/create and points Addr at a
// loopback counter. It answers 500 on refuse. Its handler listens on
// the UFFD socket, or by handlerMode refuses to start or exits before
// listening.
type fakeLauncher struct {
	mu          sync.Mutex
	calls       []call
	addr        string
	refuse      string
	handlerMode string
}

const (
	vmRSS      = 3 << 20
	handlerRSS = 1 << 20
)

type fakeVM struct {
	srv  *http.Server
	addr string
}

func (v *fakeVM) Addr() string        { return v.addr }
func (v *fakeVM) Pid() int            { return os.Getpid() }
func (v *fakeVM) RSS() (int64, error) { return vmRSS, nil }
func (v *fakeVM) Kill() error         { return v.srv.Close() }

func (l *fakeLauncher) Start(_ context.Context, _ int, sock string) (VM, error) {
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		l.mu.Lock()
		l.calls = append(l.calls, call{r.Method, r.URL.Path, body})
		l.mu.Unlock()
		if r.URL.Path == "/snapshot/create" {
			for _, k := range []string{"snapshot_path", "mem_file_path"} {
				_ = os.WriteFile(body[k].(string), []byte("x"), 0o644)
			}
		}
		if r.URL.Path == l.refuse {
			http.Error(w, "fault", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})}
	go func() { _ = srv.Serve(ln) }()
	return &fakeVM{srv: srv, addr: l.addr}, nil
}

type fakeHandler struct {
	ln     net.Listener
	once   sync.Once
	exited chan error
}

func (l *fakeLauncher) Handler(_ context.Context, sock, _ string) (Handler, error) {
	h := &fakeHandler{exited: make(chan error, 1)}
	switch l.handlerMode {
	case "refuse":
		return nil, errors.New("no such file or directory")
	case "exit":
		h.end(errors.New("exit status 2: no memory file"))
		return h, nil
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	h.ln = ln
	return h, nil
}

func (h *fakeHandler) end(err error) {
	h.once.Do(func() {
		if h.ln != nil {
			_ = h.ln.Close()
		}
		h.exited <- err
	})
}

func (h *fakeHandler) Pid() int            { return 2 }
func (h *fakeHandler) RSS() (int64, error) { return handlerRSS, nil }
func (h *fakeHandler) Kill() error         { h.end(errors.New("signal: killed")); return nil }
func (h *fakeHandler) Wait() error         { return <-h.exited }

func (l *fakeLauncher) paths() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, c := range l.calls {
		out = append(out, c.Method+" "+c.Path)
	}
	return out
}

func (l *fakeLauncher) last(path string) map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := len(l.calls) - 1; i >= 0; i-- {
		if l.calls[i].Path == path {
			return l.calls[i].Body
		}
	}
	return nil
}

// counter is the guest's HTTP server.
func counter(t *testing.T) (ip string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = bufio.NewReader(c).ReadString('\n')
			_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n1\n"))
			_ = c.Close()
		}
	}()
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port
}

// newAdapter wires an Adapter to a fake launcher. Whatever a test
// leaves running is released at cleanup.
func newAdapter(t *testing.T, uffd bool, slots int) (*Adapter, *fakeLauncher) {
	t.Helper()
	ip, port := counter(t)
	l := &fakeLauncher{addr: ip}
	// Socket paths must stay short, so the work dir is under /tmp.
	work, err := os.MkdirTemp("/tmp", "fc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(work) })
	o := Options{Kernel: "vmlinux", Rootfs: "rootfs.ext4", SnapshotDir: filepath.Join(work, "snap"), WorkDir: work,
		Port: port, MaxSlots: slots, Poll: time.Millisecond, Launch: l}
	if uffd {
		o.UFFDHandler = "handler"
	}
	a, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for id := range a.vms {
			_ = a.Release(context.Background(), compare.Handle{ID: id})
		}
	})
	return a, l
}

func TestSetupAndActivate(t *testing.T) {
	cases := []struct {
		name        string
		uffd        bool
		wantBackend string
		wantRSS     int64
	}{
		{name: "file backend", wantBackend: "File", wantRSS: vmRSS},
		{name: "uffd variant", uffd: true, wantBackend: "Uffd", wantRSS: vmRSS + handlerRSS},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, l := newAdapter(t, tc.uffd, 4)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := a.Setup(ctx); err != nil {
				t.Fatal(err)
			}
			want := []string{"PUT /machine-config", "PUT /boot-source", "PUT /drives/rootfs", "PUT /network-interfaces/eth0",
				"PUT /actions", "PATCH /vm", "PUT /snapshot/create"}
			if got := l.paths(); strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("boot calls %v, want %v", got, want)
			}
			if _, err := os.Stat(a.vmstate(a.o.SnapshotDir)); err != nil {
				t.Fatalf("snapshot not written: %v", err)
			}
			// A second Setup finds the snapshot and boots nothing.
			if err := a.Setup(ctx); err != nil || len(l.paths()) != len(want) {
				t.Errorf("second setup: err %v, calls %d", err, len(l.paths()))
			}
			h, err := a.Activate(ctx, "a")
			if err != nil {
				t.Fatal(err)
			}
			load := l.last("/snapshot/load")
			be := load["mem_backend"].(map[string]any)
			if be["backend_type"] != tc.wantBackend || load["resume_vm"] != true || load["snapshot_path"] != a.vmstate(a.o.SnapshotDir) {
				t.Errorf("load params %v", load)
			}
			if tc.uffd && !strings.HasSuffix(be["backend_path"].(string), "uffd-0.sock") {
				t.Errorf("uffd backend path %v", be["backend_path"])
			}
			h, fb, err := a.Ready(ctx, h)
			if err != nil {
				t.Fatal(err)
			}
			if fb.IsZero() || h.Meta["slot"] != "0" {
				t.Errorf("handle %+v", h)
			}
			if n, err := a.Density(ctx, []compare.Handle{h}); err != nil || n != tc.wantRSS {
				t.Errorf("density %d, %v, want %d", n, err, tc.wantRSS)
			}
			if err := a.Park(ctx, h); err != nil {
				t.Fatal(err)
			}
			if len(a.slots) != 1 || a.vms["a"] == nil || a.vms["a"].vm != nil {
				t.Errorf("park should keep the slot and no process: slots %v vms %v", a.slots, a.vms)
			}
			nh, err := a.Resume(ctx, h)
			if err != nil {
				t.Fatal(err)
			}
			if nh.Meta["slot"] != "0" || !strings.Contains(l.last("/snapshot/load")["snapshot_path"].(string), "park-a") {
				t.Errorf("resume handle %+v load %v", nh, l.last("/snapshot/load"))
			}
			if err := a.Release(ctx, nh); err != nil {
				t.Fatal(err)
			}
			if len(a.slots) != 0 || len(a.vms) != 0 {
				t.Errorf("release left slots %v vms %v", a.slots, a.vms)
			}
		})
	}
}

func TestNew(t *testing.T) {
	cases := []struct {
		name    string
		o       Options
		wantErr bool
	}{
		{name: "a missing kernel is refused", o: Options{Rootfs: "r", SnapshotDir: "s", WorkDir: "w"}, wantErr: true},
		{name: "defaults fill the rest", o: Options{Kernel: "k", Rootfs: "r", SnapshotDir: "s", WorkDir: "w"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := New(tc.o)
			if (err != nil) != tc.wantErr {
				t.Fatalf("New = %v", err)
			}
			if tc.wantErr {
				return
			}
			if _, ok := a.launch.(*execLauncher); !ok || a.o.Port != 8080 || a.o.MaxSlots != 256 || !strings.Contains(a.o.BootArgs, "--port 8080 --ifup eth0=172.16.0.2/30") {
				t.Errorf("defaults %+v, launcher %T", a.o, a.launch)
			}
		})
	}
}

func TestActivateRefusals(t *testing.T) {
	cases := []struct {
		name        string
		handlerMode string
		refuse      string
		want        string
	}{
		{name: "a handler that cannot start", handlerMode: "refuse", want: "uffd handler: no such file"},
		{name: "a handler that exits before listening", handlerMode: "exit", want: "exited before listening: exit status 2: no memory file"},
		{name: "a refused snapshot load", refuse: "/snapshot/load", want: "PUT /snapshot/load: 500 Internal Server Error: fault"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, l := newAdapter(t, true, 2)
			l.handlerMode, l.refuse = tc.handlerMode, tc.refuse
			ctx := context.Background()
			if err := a.Setup(ctx); err != nil {
				t.Fatal(err)
			}
			_, err := a.Activate(ctx, "a")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Activate = %v, want an error with %q", err, tc.want)
			}
			if len(a.slots) != 0 || len(a.vms) != 0 {
				t.Errorf("refusal left slots %v vms %v", a.slots, a.vms)
			}
		})
	}
}

func TestSlots(t *testing.T) {
	cases := []struct {
		name  string
		slots int
		want  int // successful activations
	}{
		{name: "one slot, second activation refused", slots: 1, want: 1},
		{name: "three slots", slots: 3, want: 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := newAdapter(t, false, tc.slots)
			ctx := context.Background()
			if err := a.Setup(ctx); err != nil {
				t.Fatal(err)
			}
			ok := 0
			for i := range tc.slots + 1 {
				if _, err := a.Activate(ctx, string(rune('a'+i))); err == nil {
					ok++
				}
			}
			if ok != tc.want {
				t.Errorf("activations %d, want %d", ok, tc.want)
			}
		})
	}
}

func TestLoadParamsAndNamespace(t *testing.T) {
	a := &Adapter{}
	cases := []struct {
		name string
		uffd string
		slot int
		want string
	}{
		{name: "file", slot: 0, want: "File"},
		{name: "uffd", uffd: "/tmp/u.sock", slot: 7, want: "Uffd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := a.LoadParams("/snap", tc.uffd)
			be := p["mem_backend"].(map[string]any)
			if be["backend_type"] != tc.want {
				t.Errorf("backend %v", be)
			}
			if tc.uffd != "" && be["backend_path"] != tc.uffd {
				t.Errorf("backend path %v", be["backend_path"])
			}
			if Namespace(tc.slot) != "fc-"+string(rune('0'+tc.slot)) {
				t.Errorf("namespace %s", Namespace(tc.slot))
			}
		})
	}
}

func TestRSS(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("rss reads /proc")
	}
	cases := []struct {
		name    string
		pid     int
		wantErr bool
	}{
		{name: "the test process", pid: os.Getpid()},
		{name: "no such process", pid: math.MaxInt32, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, err := rss(tc.pid)
			if (err != nil) != tc.wantErr || (!tc.wantErr && n <= 0) {
				t.Fatalf("rss = %d, %v", n, err)
			}
		})
	}
}

func TestWaitSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "fcw-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	live := filepath.Join(dir, "live.sock")
	ln, err := net.Listen("unix", live)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	dead := make(chan error, 1)
	dead <- errors.New("exit status 2")
	cases := []struct {
		name    string
		path    string
		exited  chan error
		timeout time.Duration
		want    string // empty means no error
	}{
		{name: "a listening socket answers", path: live, timeout: time.Second},
		{name: "a handler that exits is reported at once", path: filepath.Join(dir, "none.sock"), exited: dead, timeout: time.Minute, want: "exited before listening"},
		{name: "no socket and no exit waits for the deadline", path: filepath.Join(dir, "none.sock"), timeout: 50 * time.Millisecond, want: "deadline exceeded"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
			defer cancel()
			start := time.Now()
			err := waitSocket(ctx, tc.path, tc.exited)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("waitSocket = %v, want nil", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("waitSocket = %v, want an error with %q", err, tc.want)
			}
			if tc.exited != nil && time.Since(start) > 5*time.Second {
				t.Fatalf("an exited handler took %v to report", time.Since(start))
			}
		})
	}
}

func TestParkedRelease(t *testing.T) {
	cases := []struct {
		name string
		park bool
	}{
		{name: "a parked instance released frees its slot", park: true},
		{name: "resume of an instance that is not parked is refused"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := newAdapter(t, false, 2)
			ctx := context.Background()
			if err := a.Setup(ctx); err != nil {
				t.Fatal(err)
			}
			h, err := a.Activate(ctx, "a")
			if err != nil {
				t.Fatal(err)
			}
			if tc.park {
				if err := a.Park(ctx, h); err != nil {
					t.Fatal(err)
				}
			} else if _, err := a.Resume(ctx, h); err == nil || !strings.Contains(err.Error(), "not parked") {
				t.Fatalf("Resume = %v, want a refusal", err)
			}
			if err := a.Release(ctx, h); err != nil {
				t.Fatal(err)
			}
			if len(a.slots) != 0 || len(a.vms) != 0 {
				t.Errorf("release left slots %v vms %v", a.slots, a.vms)
			}
		})
	}
}

func TestStaleBootSocket(t *testing.T) {
	cases := []struct {
		name  string
		stale bool
	}{
		{name: "a boot.sock left by a killed run is removed before the boot", stale: true},
		{name: "a clean work dir"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := newAdapter(t, false, 1)
			if tc.stale {
				if err := os.WriteFile(filepath.Join(a.o.WorkDir, "boot.sock"), nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := a.Setup(context.Background()); err != nil {
				t.Fatalf("Setup = %v", err)
			}
		})
	}
}
