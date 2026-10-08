package shim_test

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/consumer"
)

// fakeHome is a Fibers server on a TCP port. It records what the shim
// asks of it and answers with the errors a test scripts.
type fakeHome struct {
	grantv1.UnimplementedFibersServer

	addr string

	mu       sync.Mutex
	cloneErr error // returned by Clone when set
	stopErr  error // returned by Park and Release when set
	clones   []*grantv1.CloneRequest
	parks    []string
	releases []string
}

func newFakeHome(t *testing.T) *fakeHome {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &fakeHome{addr: lis.Addr().String()}
	gs := grpc.NewServer()
	grantv1.RegisterFibersServer(gs, h)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	return h
}

// client dials the home as the shim's default DialHome would.
func (h *fakeHome) client(t *testing.T) *consumer.Client {
	t.Helper()
	c, err := consumer.Dial(context.Background(), h.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func (h *fakeHome) Clone(_ context.Context, r *grantv1.CloneRequest) (*grantv1.CloneResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cloneErr != nil {
		return nil, h.cloneErr
	}
	h.clones = append(h.clones, r)
	n := uint64(len(h.clones))
	return &grantv1.CloneResponse{
		FiberId:  fmt.Sprintf("fiber-%d", n),
		Endpoint: "tcp://127.0.0.1:7000",
		Fence:    &grantv1.Fence{GrantUid: "g", Epoch: 1, Seq: n},
		Kind:     grantv1.CloneKind_CREATE,
	}, nil
}

func (h *fakeHome) Park(_ context.Context, r *grantv1.ParkRequest) (*emptypb.Empty, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.parks = append(h.parks, r.GetFiberId())
	return &emptypb.Empty{}, h.stopErr
}

func (h *fakeHome) Release(_ context.Context, r *grantv1.ReleaseRequest) (*emptypb.Empty, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.releases = append(h.releases, r.GetFiberId())
	return &emptypb.Empty{}, h.stopErr
}

// script sets the home's answers.
func (h *fakeHome) script(cloneErr, stopErr error) {
	h.mu.Lock()
	h.cloneErr, h.stopErr = cloneErr, stopErr
	h.mu.Unlock()
}

// reset forgets what the home was asked and its scripted answers.
func (h *fakeHome) reset() {
	h.mu.Lock()
	h.cloneErr, h.stopErr = nil, nil
	h.clones, h.parks, h.releases = nil, nil, nil
	h.mu.Unlock()
}

// seen returns copies of what the home was asked.
func (h *fakeHome) seen() (clones []*grantv1.CloneRequest, parks, releases []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*grantv1.CloneRequest(nil), h.clones...),
		append([]string(nil), h.parks...), append([]string(nil), h.releases...)
}

// missErr is the status a home sends for a miss, with its Miss detail.
func missErr(t *testing.T, c codes.Code, code grantv1.MissCode) error {
	t.Helper()
	st, err := status.New(c, "miss").WithDetails(&grantv1.Miss{Code: code, Issuer: "https://issuer.test"})
	if err != nil {
		t.Fatal(err)
	}
	return st.Err()
}
