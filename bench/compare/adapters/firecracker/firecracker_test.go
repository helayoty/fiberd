package firecracker

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/helayoty/fiberd/bench/compare"
)

// TestMain doubles as the UFFD handler the adapter execs in the uffd
// case: it listens on the socket it is given and waits to be killed.
func TestMain(m *testing.M) {
	if sock := os.Getenv("COMPARE_FC_FAKE_UFFD"); sock != "" {
		if _, err := net.Listen("unix", os.Args[1]); err != nil {
			os.Exit(2)
		}
		select {}
	}
	os.Exit(m.Run())
}

// call is one API request the fake Firecracker saw.
type call struct {
	Method, Path string
	Body         map[string]any
}

// fakeLauncher serves the Firecracker API on the socket, records every
// call, writes snapshot files on /snapshot/create and points Addr at a
// loopback counter.
type fakeLauncher struct {
	t     *testing.T
	mu    sync.Mutex
	calls []call
	addr  string
}

type fakeVM struct {
	srv  *http.Server
	addr string
}

func (v *fakeVM) Addr() string { return v.addr }
func (v *fakeVM) Pid() int     { return os.Getpid() }
func (v *fakeVM) Kill() error  { return v.srv.Close() }

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
		w.WriteHeader(http.StatusNoContent)
	})}
	go func() { _ = srv.Serve(ln) }()
	return &fakeVM{srv: srv, addr: l.addr}, nil
}

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

func newAdapter(t *testing.T, uffd bool, slots int) (*Adapter, *fakeLauncher) {
	t.Helper()
	ip, port := counter(t)
	l := &fakeLauncher{t: t, addr: ip}
	// Socket paths must stay short, so the work dir is under /tmp.
	work, err := os.MkdirTemp("/tmp", "fc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(work) })
	o := Options{Kernel: "vmlinux", Rootfs: "rootfs.ext4", SnapshotDir: filepath.Join(work, "snap"), WorkDir: work,
		Port: port, MaxSlots: slots, Poll: time.Millisecond, Launch: l}
	if uffd {
		o.UFFDHandler = os.Args[0]
		t.Setenv("COMPARE_FC_FAKE_UFFD", "1")
	}
	a, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return a, l
}

func TestSetupAndActivate(t *testing.T) {
	cases := []struct {
		name        string
		uffd        bool
		wantBackend string
	}{
		{name: "file backend", wantBackend: "File"},
		{name: "uffd variant", uffd: true, wantBackend: "Uffd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, l := newAdapter(t, tc.uffd, 4)
			// The uffd case execs this test binary as the handler. On a
			// loaded macOS host that exec was seen to take over 10 s, so
			// the bound is generous. A pass takes well under a second.
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
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
			// Density reads /proc, so it is checked on Linux only.
			if runtime.GOOS == "linux" {
				n, err := a.Density(ctx, []compare.Handle{h})
				if err != nil || n <= 0 {
					t.Errorf("density %d, %v", n, err)
				}
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
