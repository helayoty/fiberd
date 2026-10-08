package activator_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/consumer"
)

// fakeHome is a scriptable home. Clone and Park run the hooks a case sets,
// so every miss and failure the activator handles can be produced on
// demand. A Clone that succeeds is a CREATE of a fiber whose endpoint is
// "test://<session>" (or endpoint, when set).
type fakeHome struct {
	grantv1.UnimplementedFibersServer
	clone    func(ctx context.Context, req *grantv1.CloneRequest) error
	park     func(req *grantv1.ParkRequest) error
	endpoint string

	mu     sync.Mutex
	clones []*grantv1.CloneRequest
	parks  chan string // the fiber IDs Park was called for
}

func (h *fakeHome) Clone(ctx context.Context, req *grantv1.CloneRequest) (*grantv1.CloneResponse, error) {
	h.mu.Lock()
	h.clones = append(h.clones, req)
	n := len(h.clones)
	h.mu.Unlock()
	if h.clone != nil {
		if err := h.clone(ctx, req); err != nil {
			return nil, err
		}
	}
	ep := h.endpoint
	if ep == "" {
		ep = "test://" + req.GetSession()
	}
	return &grantv1.CloneResponse{
		FiberId:  fmt.Sprintf("%s#%d", req.GetSession(), n),
		Endpoint: ep,
		Fence:    &grantv1.Fence{GrantUid: "g", Epoch: 1, Seq: uint64(n)},
		Kind:     grantv1.CloneKind_CREATE,
	}, nil
}

func (h *fakeHome) Park(_ context.Context, req *grantv1.ParkRequest) (*emptypb.Empty, error) {
	select {
	case h.parks <- req.GetFiberId():
	default:
	}
	if h.park != nil {
		if err := h.park(req); err != nil {
			return nil, err
		}
	}
	return &emptypb.Empty{}, nil
}

// cloneCount is how many Clones the home has served or refused.
func (h *fakeHome) cloneCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clones)
}

// waitPark waits for the activator to ask the home to park a fiber.
func (h *fakeHome) waitPark(t *testing.T) string {
	t.Helper()
	select {
	case id := <-h.parks:
		return id
	case <-time.After(5 * time.Second):
		t.Fatal("no Park reached the home")
		return ""
	}
}

// startFake serves h over an in-memory connection and returns a client
// of it.
func startFake(t *testing.T, h *fakeHome) *consumer.Client {
	t.Helper()
	h.parks = make(chan string, 64)
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	grantv1.RegisterFibersServer(gs, h)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	c := consumer.New(conn)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// missErr is the gRPC error a home returns for a miss.
func missErr(t *testing.T, c codes.Code, msg string, m *grantv1.Miss) error {
	t.Helper()
	st, err := status.New(c, msg).WithDetails(m)
	if err != nil {
		t.Fatal(err)
	}
	return st.Err()
}

// lineGuest answers each protocol line with "got:<line>". The line
// "hold" is answered only once release is closed, and entered then
// receives the endpoint it came in on, so a test knows which fiber is
// busy.
type lineGuest struct {
	entered chan string
	release chan struct{}
}

func newLineGuest() *lineGuest {
	return &lineGuest{entered: make(chan string, 64), release: make(chan struct{})}
}

func (g *lineGuest) serve(ep string, c net.Conn) {
	defer func() { _ = c.Close() }()
	r := bufio.NewReader(c)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if line == "hold" {
			g.entered <- ep
			<-g.release
		}
		if _, err := fmt.Fprintln(c, "got:"+line); err != nil {
			return
		}
	}
}

func (g *lineGuest) dial(_ context.Context, ep string) (net.Conn, error) {
	a, b := net.Pipe()
	go g.serve(ep, b)
	return a, nil
}

// waitEntered waits for a "hold" line to reach the guest and returns the
// endpoint it reached.
func (g *lineGuest) waitEntered(t *testing.T) string {
	t.Helper()
	select {
	case ep := <-g.entered:
		return ep
	case <-time.After(5 * time.Second):
		t.Fatal("the held request never reached the guest")
		return ""
	}
}

// errDial is a dialer whose fiber is never reachable.
var errDial = errors.New("connection refused")

func failDial(context.Context, string) (net.Conn, error) { return nil, errDial }
