package activator_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/helayoty/fiberd/pkg/consumer"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/rpc"
	"github.com/helayoty/fiberd/pkg/runtime/stub"

	"github.com/helayoty/fiberd/examples/knative/activator"
)

// A stub home in process, and a fake "guest" behind every endpoint the
// stub hands out: a line server that counts, keyed by endpoint so each
// fiber has its own state.
type world struct {
	agent  *core.Agent
	health *core.SourceHealth
	client *consumer.Client
	mu     sync.Mutex
	guests map[string]*guest
}

type guest struct {
	mu      sync.Mutex
	counter int
}

func (g *guest) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	r := bufio.NewReader(c)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		g.mu.Lock()
		var reply string
		switch strings.TrimSpace(line) {
		case "ping":
			reply = "pong"
		case "incr":
			g.counter++
			reply = fmt.Sprint(g.counter)
		default:
			reply = "?"
		}
		g.mu.Unlock()
		_, _ = fmt.Fprintln(c, reply)
	}
}

// dial gives the activator a connection to the guest of an endpoint.
func (w *world) dial(_ context.Context, ep string) (net.Conn, error) {
	w.mu.Lock()
	g, ok := w.guests[ep]
	if !ok {
		g = &guest{}
		w.guests[ep] = g
	}
	w.mu.Unlock()
	a, b := net.Pipe()
	go g.serve(b)
	return a, nil
}

func newWorld(t *testing.T) *world {
	t.Helper()
	health := core.NewSourceHealth(10*time.Second, time.Now())
	ag := &core.Agent{
		NodeID: "home-a", Ledger: core.NewLedger(1), Budget: core.NewBudget(1000, 256<<20),
		Runtime: stub.NewWithTier(core.TierSnapshot), Audit: core.NopAuditor{}, Verify: grant.InsecureJSONVerifier{},
		Health: health, StatusInterval: 20 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go ag.Run(ctx)
	lis := bufconn.Listen(1 << 20)
	gs := rpc.NewGRPCServer(&rpc.Server{Agent: ag, Issuer: "https://issuer.test", RetryAfter: 1 * time.Second})
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
	return &world{agent: ag, health: health, client: c, guests: map[string]*guest{}}
}

func jsonGrant(t *testing.T, g core.Grant) string {
	t.Helper()
	b, err := protojson.Marshal(grant.ToProto(g))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func call(t *testing.T, srv *httptest.Server, path, body string) (string, http.Header, int) {
	t.Helper()
	var req *http.Request
	var err error
	if body == "" {
		req, err = http.NewRequest(http.MethodGet, srv.URL+path, nil)
	} else {
		req, err = http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(body))
	}
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(b)), resp.Header, resp.StatusCode
}

func TestScaleFromZeroAttachParkResume(t *testing.T) {
	w := newWorld(t)
	g := jsonGrant(t, core.Grant{UID: "rev-a", Audience: "home-a", FiberMax: 4})
	act, err := activator.New(w.client, activator.Config{
		Revisions: []activator.Revision{{Name: "hello", Grant: g}},
		Idle:      200 * time.Millisecond, Dial: w.dial,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go act.Run(ctx)
	srv := httptest.NewServer(act)
	defer srv.Close()

	// First request: scale from zero is a CREATE, in the same request.
	body, hdr, code := call(t, srv, "/hello", "")
	if code != 200 || body != "pong" || hdr.Get("X-Fiberd-Clone") != "CREATE" {
		t.Fatalf("first = %d %q %v", code, body, hdr)
	}
	// Second: attaches to the same fiber; the guest's state carries.
	body, hdr, _ = call(t, srv, "/hello", "incr")
	if body != "1" || hdr.Get("X-Fiberd-Clone") != "ATTACH" {
		t.Fatalf("second = %q %v", body, hdr)
	}
	call(t, srv, "/hello", "incr")
	// Idle: the activator parks the revision; the ledger shows it parked.
	deadline := time.Now().Add(3 * time.Second)
	for {
		st, _ := w.agent.Ledger.Status("rev-a")
		if st.Parked == 1 && st.Running == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("revision not parked when idle: %+v", st)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Next request resumes it under a new fence.
	body, hdr, code = call(t, srv, "/hello", "")
	if code != 200 || hdr.Get("X-Fiberd-Clone") != "RESUME" || !strings.HasSuffix(hdr.Get("X-Fiberd-Fence"), "/1/2") {
		t.Fatalf("after idle = %d %q %v", code, body, hdr)
	}
}

func TestMissesBecomeKnativeFallbacks(t *testing.T) {
	w := newWorld(t)
	// Two revisions on one grant that allows a single fiber.
	g := jsonGrant(t, core.Grant{UID: "rev-b", Audience: "home-a", FiberMax: 1})
	act, err := activator.New(w.client, activator.Config{
		Revisions: []activator.Revision{{Name: "one", Grant: g}, {Name: "two", Grant: g}}, Dial: w.dial,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(act)
	defer srv.Close()
	if _, _, code := call(t, srv, "/one", ""); code != 200 {
		t.Fatalf("first revision = %d", code)
	}
	// An idle fiber takes the next request instead of a second clone.
	if _, hdr, _ := call(t, srv, "/one", ""); hdr.Get("X-Fiberd-Clone") != "ATTACH" {
		t.Fatalf("second request to a served revision = %v, want ATTACH", hdr)
	}
	// The other revision needs a second fiber; the grant allows one: with
	// the lane healthy that is DEFERRED, the ordinary path.
	body, _, code := call(t, srv, "/two", "")
	if code != 503 || !strings.Contains(body, "deferred") {
		t.Fatalf("over capacity = %d %q, want 503 deferred", code, body)
	}
	// Lane down: SHED with Retry-After.
	w.health.MarkSync(time.Now().Add(-time.Hour))
	body, hdr, code := call(t, srv, "/two", "")
	if code != 503 || !strings.Contains(body, "shed") || hdr.Get("Retry-After") != "1" {
		t.Fatalf("lane down = %d %q retry=%q", code, body, hdr.Get("Retry-After"))
	}
	if _, _, code := call(t, srv, "/nope", ""); code != 404 {
		t.Fatalf("unknown revision = %d", code)
	}
}

func TestHTTPModeProxiesToTheGuest(t *testing.T) {
	w := newWorld(t)
	g := jsonGrant(t, core.Grant{UID: "rev-c", Audience: "home-a", FiberMax: 1})
	// An HTTP guest behind the endpoint.
	guestSrv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(rw, "hello from %s", r.URL.Path)
	}))
	defer guestSrv.Close()
	dial := func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", strings.TrimPrefix(guestSrv.URL, "http://"))
	}
	act, err := activator.New(w.client, activator.Config{
		Revisions: []activator.Revision{{Name: "web", Grant: g, Mode: "http"}}, Dial: dial,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(act)
	defer srv.Close()
	body, hdr, code := call(t, srv, "/web/items/7", "")
	if code != 200 || body != "hello from /items/7" || hdr.Get("X-Fiberd-Clone") != "CREATE" {
		t.Fatalf("http mode = %d %q %v", code, body, hdr)
	}
}
