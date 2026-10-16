package fiberd

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/sdk/go/client"

	"github.com/helayoty/fiberd/bench/compare"
)

// home is a fake Fibers service. Every Clone answers with the endpoint
// of one loopback counter that speaks both framings, in the scheme the
// test asks for. A session cloned again after a Park is a RESUME.
type home struct {
	grantv1.UnimplementedFibersServer
	endpoint string
	mu       sync.Mutex
	seq      uint64
	parked   map[string]bool // session
	released []string
	clones   []string
	watch    []*grantv1.Status // what Watch sends, then it idles
}

func (h *home) Watch(_ *emptypb.Empty, s grantv1.Fibers_WatchServer) error {
	h.mu.Lock()
	lines := h.watch
	h.mu.Unlock()
	for _, st := range lines {
		if err := s.Send(st); err != nil {
			return err
		}
	}
	<-s.Context().Done()
	return nil
}

func (h *home) Clone(_ context.Context, req *grantv1.CloneRequest) (*grantv1.CloneResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if req.GetGrantJwt() == "" {
		return nil, status.Error(codes.Unauthenticated, "no grant")
	}
	h.seq++
	h.clones = append(h.clones, req.GetSession())
	kind := grantv1.CloneKind_CREATE
	if h.parked[req.GetSession()] {
		kind = grantv1.CloneKind_RESUME
		delete(h.parked, req.GetSession())
	}
	return &grantv1.CloneResponse{FiberId: fmt.Sprintf("f%d", h.seq), Endpoint: h.endpoint, Kind: kind,
		Fence: &grantv1.Fence{GrantUid: "g", Epoch: 1, Seq: h.seq}}, nil
}

func (h *home) Park(_ context.Context, req *grantv1.ParkRequest) (*emptypb.Empty, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	// The adapter names sessions s-<id>, and parks by fiber id. The fake
	// has one live session per test, so every park parks the last clone.
	h.parked[h.clones[len(h.clones)-1]] = true
	return &emptypb.Empty{}, nil
}

func (h *home) Release(_ context.Context, req *grantv1.ReleaseRequest) (*emptypb.Empty, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.released = append(h.released, req.GetFiberId())
	return &emptypb.Empty{}, nil
}

// counter answers "incr" with "1" and any HTTP request with a 200.
func counter(t *testing.T, network string) string {
	t.Helper()
	addr := "127.0.0.1:0"
	if network == "unix" {
		// Socket paths must stay short, so not under t.TempDir on macOS.
		dir, err := os.MkdirTemp("/tmp", "cmp-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		addr = dir + "/f.sock"
	}
	ln, err := net.Listen(network, addr)
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
			line, _ := bufio.NewReader(c).ReadString('\n')
			if strings.HasPrefix(line, "incr") {
				_, _ = c.Write([]byte("1\n"))
			} else {
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n1\n"))
			}
			_ = c.Close()
		}
	}()
	if network == "unix" {
		return "unix://" + addr
	}
	return "tcp://" + ln.Addr().String()
}

func serve(t *testing.T, h *home) *client.Client {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	grantv1.RegisterFibersServer(gs, h)
	go func() { _ = gs.Serve(ln) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	return client.New(conn)
}

func TestAdapter(t *testing.T) {
	cases := []struct {
		name       string
		network    string
		framing    compare.Framing
		wantScheme string
		wantErr    string
	}{
		{name: "http over a unix endpoint", network: "unix", framing: compare.HTTP},
		{name: "http over a tcp endpoint", network: "tcp", framing: compare.HTTP},
		{name: "line framing, what hyperlight speaks", network: "unix", framing: compare.Line},
		{name: "want tcp, got unix", network: "unix", framing: compare.HTTP, wantScheme: "tcp", wantErr: "scheme unix, want tcp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &home{endpoint: counter(t, tc.network), parked: map[string]bool{}}
			a, err := New(context.Background(), Options{Client: serve(t, h), Framing: tc.framing, WantScheme: tc.wantScheme,
				Mint: func() (string, error) { return "jwt", nil }})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := a.Setup(ctx); err != nil {
				if tc.wantErr != "" && strings.Contains(err.Error(), tc.wantErr) {
					return
				}
				t.Fatal(err)
			}
			if tc.wantErr != "" {
				t.Fatal("want an error")
			}
			if len(h.released) != 1 {
				t.Errorf("setup should clone once and release once, released %v", h.released)
			}
			hd, err := a.Activate(ctx, "r1-b1-0")
			if err != nil {
				t.Fatal(err)
			}
			if hd.Addr != h.endpoint || hd.Meta["session"] != "s-r1-b1-0" || hd.Meta["fence"] != "g/1/2" {
				t.Errorf("handle %+v", hd)
			}
			hd, fb, err := a.Ready(ctx, hd)
			if err != nil {
				t.Fatal(err)
			}
			if fb.IsZero() || hd.Meta["attempts"] != "0" {
				t.Errorf("first request should be the measurement: %+v %v", hd, fb)
			}
			if err := a.Park(ctx, hd); err != nil {
				t.Fatal(err)
			}
			nh, err := a.Resume(ctx, hd)
			if err != nil {
				t.Fatal(err)
			}
			if nh.Meta["kind"] != "RESUME" || nh.ID == hd.ID {
				t.Errorf("resumed handle %+v", nh)
			}
			if h.clones[len(h.clones)-1] != "s-r1-b1-0" {
				t.Errorf("resume cloned session %q, want the parked one", h.clones[len(h.clones)-1])
			}
			if err := a.Release(ctx, nh); err != nil {
				t.Fatal(err)
			}
			if h.released[len(h.released)-1] != nh.ID {
				t.Errorf("released %v, want %s last", h.released, nh.ID)
			}
		})
	}
}

func TestGrant(t *testing.T) {
	cases := []struct {
		name    string
		opt     Options
		wantIso string
		wantErr bool
	}{
		{name: "defaults", opt: Options{NodeID: "n", WBudget: 64 << 20, Isolation: "TRUSTED"}, wantIso: "TRUSTED"},
		{name: "untrusted for the sandboxed class", opt: Options{NodeID: "n", Isolation: "UNTRUSTED"}, wantIso: "UNTRUSTED"},
		{name: "bad isolation", opt: Options{NodeID: "n", Isolation: "sorta"}, wantErr: true},
		{name: "fibers.warm for the pooled row", opt: Options{NodeID: "n", Isolation: "UNTRUSTED", FiberWarm: 2}, wantIso: "UNTRUSTED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &Adapter{o: tc.opt, uid: "u"}
			g, err := a.Grant()
			if (err != nil) != tc.wantErr {
				t.Fatalf("err %v, want error %v", err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if g.Policy.Isolation.String() != tc.wantIso || g.Audience != "n" || g.TemplateDigest != "sha256:compare" || g.WBudgetBytes != tc.opt.WBudget || g.FiberWarm != tc.opt.FiberWarm {
				t.Errorf("grant %+v", g)
			}
		})
	}
}

func TestRefill(t *testing.T) {
	cases := []struct {
		name    string
		warm    int
		pooled  []uint32 // the grant's pooled counts, in Watch order
		wantErr string
	}{
		{name: "no fibers.warm waits for nothing", warm: 0},
		{name: "full once the count reaches warm", warm: 2, pooled: []uint32{0, 1, 2}},
		{name: "a pool that never fills times out", warm: 2, pooled: []uint32{1}, wantErr: "has 1 of 2 pooled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &home{parked: map[string]bool{}}
			a, err := New(context.Background(), Options{Client: serve(t, h), FiberWarm: tc.warm, RefillWait: 300 * time.Millisecond,
				Mint: func() (string, error) { return "jwt", nil }})
			if err != nil {
				t.Fatal(err)
			}
			// Another grant's full pool must not count.
			h.watch = []*grantv1.Status{{GrantUid: "other", Pooled: 9}}
			for _, n := range tc.pooled {
				h.watch = append(h.watch, &grantv1.Status{GrantUid: a.uid, Pooled: n})
			}
			err = a.Refill(context.Background())
			if tc.wantErr == "" && err != nil {
				t.Fatal(err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestDensity(t *testing.T) {
	handle := func(fence string) compare.Handle { return compare.Handle{Meta: map[string]string{"fence": fence}} }
	cases := []struct {
		name     string
		warm     int
		cgroups  map[string]int64 // memory.current under the grant dir
		bare     []string         // leaves without a memory.current
		hs       []compare.Handle
		standing int64
		bytes    int64
		wantErr  string
	}{
		{
			name:     "no pool: the zygote stands, the fibers' leaves are charged",
			cgroups:  map[string]int64{"": 1000, "zygote": 100, "f-1-2": 10, "f-1-3": 20},
			hs:       []compare.Handle{handle("g/1/2"), handle("g/1/3")},
			standing: 100, bytes: 30,
		},
		{
			// p-3 went to the second fiber. p-10 sorts after p-3, so the
			// order is numeric, not by name.
			name:     "pool: the newest leaves stand idle, the oldest went to fibers",
			warm:     2,
			cgroups:  map[string]int64{"": 1000, "zygote": 100, "f-1-2": 10, "pool": 700, "pool/p-3": 200, "pool/p-10": 300, "pool/p-11": 400},
			hs:       []compare.Handle{handle("g/1/2"), handle("g/1/3")},
			standing: 800, bytes: 210,
		},
		{
			name:     "no fiber leaves at all, as hyperlight: the subtree beyond the zygote",
			cgroups:  map[string]int64{"": 1000, "zygote": 100},
			hs:       []compare.Handle{handle("g/1/2")},
			standing: 100, bytes: 900,
		},
		{
			name:     "one fiber leaf missing beside another: an error, not the grant-wide bytes",
			cgroups:  map[string]int64{"": 1000, "zygote": 100, "f-1-2": 10},
			hs:       []compare.Handle{handle("g/1/2"), handle("g/1/3")},
			standing: 100, wantErr: "1 of 2 fibers have no cgroup leaf",
		},
		{
			name:     "more fibers without a leaf than the pool had: an error",
			warm:     1,
			cgroups:  map[string]int64{"": 1000, "zygote": 100, "pool": 200, "pool/p-1": 200},
			hs:       []compare.Handle{handle("g/1/2"), handle("g/1/3")},
			standing: 300, wantErr: "2 of 2 fibers have no cgroup leaf",
		},
		{
			name:     "an unreadable fiber leaf: an error, not the grant-wide bytes",
			cgroups:  map[string]int64{"": 1000, "zygote": 100},
			bare:     []string{"f-1-2"},
			hs:       []compare.Handle{handle("g/1/2")},
			standing: 100, wantErr: "memory.current",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &home{parked: map[string]bool{}}
			root := t.TempDir()
			a, err := New(context.Background(), Options{Client: serve(t, h), FiberWarm: tc.warm, CgroupRoot: root,
				Mint: func() (string, error) { return "jwt", nil }})
			if err != nil {
				t.Fatal(err)
			}
			h.watch = []*grantv1.Status{{GrantUid: a.uid, Pooled: uint32(tc.warm)}}
			for dir, n := range tc.cgroups {
				d := filepath.Join(root, a.uid, dir)
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(d, "memory.current"), []byte(fmt.Sprintf("%d\n", n)), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			for _, dir := range tc.bare {
				if err := os.MkdirAll(filepath.Join(root, a.uid, dir), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			standing, err := a.Density(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			if standing != tc.standing {
				t.Errorf("standing %d, want %d", standing, tc.standing)
			}
			bytes, err := a.Density(ctx, tc.hs)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("bytes %d err %v, want an error with %q", bytes, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if bytes != tc.bytes {
				t.Errorf("bytes %d, want %d", bytes, tc.bytes)
			}
		})
	}
}

func TestLeafName(t *testing.T) {
	cases := []struct{ fence, want string }{
		{"g/1/7", "f-1-7"},
		{"g/12/345", "f-12-345"},
		{"odd", "odd"},
	}
	for _, tc := range cases {
		t.Run(tc.fence, func(t *testing.T) {
			if got := LeafName(tc.fence); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}
