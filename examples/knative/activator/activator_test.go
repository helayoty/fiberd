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
	"github.com/helayoty/fiberd/pkg/core/coretest"
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
		Runtime: stub.NewWithTier(core.TierSnapshot), Verify: grant.InsecureJSONVerifier{},
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

// waitParked waits for the activator to park an idle grant's one fiber.
func waitParked(t *testing.T, w *world, uid string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		st, _ := coretest.GrantStatus(w.agent.Ledger, uid)
		if st.Parked == 1 && st.Running == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("revision not parked when idle: %+v", st)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestActivator runs scenarios. Each is one activator over a stub home, fed
// a sequence of requests, and each step names what its request must get
// back. A scenario's steps share its activator and run in order.
func TestActivator(t *testing.T) {
	type step struct {
		name       string
		before     func(t *testing.T, w *world) // changes the world first. May be nil
		path, body string                       // the request. An empty body is a GET
		code       int
		reply      string // the exact body, unchecked when empty
		replyHas   string // a substring of the body, unchecked when empty
		clone      string // X-Fiberd-Clone, unchecked when empty
		fence      string // suffix of X-Fiberd-Fence, unchecked when empty
		retryAfter string // Retry-After, unchecked when empty
	}
	cases := []struct {
		name   string
		config func(t *testing.T, w *world) activator.Config
		steps  []step
	}{
		{
			name: "scale from zero, attach, park when idle, resume",
			config: func(t *testing.T, w *world) activator.Config {
				g := jsonGrant(t, core.Grant{UID: "rev-a", Audience: "home-a", FiberMax: 4})
				return activator.Config{Revisions: []activator.Revision{{Name: "hello", Grant: g}}, Idle: 200 * time.Millisecond, Dial: w.dial}
			},
			steps: []step{
				{name: "the first request scales from zero: a CREATE in the same request",
					path: "/hello", code: 200, reply: "pong", clone: "CREATE"},
				{name: "the second attaches to the same fiber; the guest's state carries",
					path: "/hello", body: "incr", code: 200, reply: "1", clone: "ATTACH"},
				{name: "the third still counts on the same guest",
					path: "/hello", body: "incr", code: 200, reply: "2", clone: "ATTACH"},
				{name: "once parked when idle, the next request resumes it under a new fence",
					before: func(t *testing.T, w *world) { waitParked(t, w, "rev-a") },
					path:   "/hello", code: 200, reply: "pong", clone: "RESUME", fence: "/1/2"},
			},
		},
		{
			// Two revisions on one grant that allows a single fiber.
			name: "misses become Knative fallbacks",
			config: func(t *testing.T, w *world) activator.Config {
				g := jsonGrant(t, core.Grant{UID: "rev-b", Audience: "home-a", FiberMax: 1})
				return activator.Config{Revisions: []activator.Revision{{Name: "one", Grant: g}, {Name: "two", Grant: g}}, Dial: w.dial}
			},
			steps: []step{
				{name: "the first revision is served", path: "/one", code: 200, clone: "CREATE"},
				{name: "an idle fiber takes the next request instead of a second clone",
					path: "/one", code: 200, clone: "ATTACH"},
				{name: "the other revision needs a second fiber the grant lacks: with the lane healthy, 503 deferred",
					path: "/two", code: 503, replyHas: "deferred"},
				{name: "with the lane down, 503 shed with Retry-After",
					before: func(_ *testing.T, w *world) { w.health.MarkSync(time.Now().Add(-time.Hour)) },
					path:   "/two", code: 503, replyHas: "shed", retryAfter: "1"},
				{name: "an unknown revision is 404", path: "/nope", code: 404},
			},
		},
		{
			name: "http mode proxies to the guest",
			config: func(t *testing.T, w *world) activator.Config {
				g := jsonGrant(t, core.Grant{UID: "rev-c", Audience: "home-a", FiberMax: 1})
				// An HTTP guest behind the endpoint.
				guestSrv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
					_, _ = fmt.Fprintf(rw, "hello from %s", r.URL.Path)
				}))
				t.Cleanup(guestSrv.Close)
				dial := func(ctx context.Context, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "tcp", strings.TrimPrefix(guestSrv.URL, "http://"))
				}
				return activator.Config{Revisions: []activator.Revision{{Name: "web", Grant: g, Mode: "http"}}, Dial: dial}
			},
			steps: []step{
				{name: "the request path past the revision reaches the guest",
					path: "/web/items/7", code: 200, reply: "hello from /items/7", clone: "CREATE"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			act, err := activator.New(w.client, tc.config(t, w))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go act.Run(ctx)
			srv := httptest.NewServer(act)
			defer srv.Close()
			for _, st := range tc.steps {
				ok := t.Run(st.name, func(t *testing.T) {
					if st.before != nil {
						st.before(t, w)
					}
					body, hdr, code := call(t, srv, st.path, st.body)
					if code != st.code ||
						(st.reply != "" && body != st.reply) ||
						(st.replyHas != "" && !strings.Contains(body, st.replyHas)) ||
						(st.clone != "" && hdr.Get("X-Fiberd-Clone") != st.clone) ||
						(st.fence != "" && !strings.HasSuffix(hdr.Get("X-Fiberd-Fence"), st.fence)) ||
						(st.retryAfter != "" && hdr.Get("Retry-After") != st.retryAfter) {
						t.Fatalf("%s %s = %d %q %v, want %d body %q (has %q) clone %q fence *%s retry-after %q",
							st.path, st.body, code, body, hdr, st.code, st.reply, st.replyHas, st.clone, st.fence, st.retryAfter)
					}
				})
				if !ok {
					return // later steps build on this one
				}
			}
		})
	}
}
