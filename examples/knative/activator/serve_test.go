package activator_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/consumer"

	"github.com/helayoty/fiberd/examples/knative/activator"
)

// serve runs one request through the activator and returns the response.
func serve(act http.Handler, method, target, body string) *httptest.ResponseRecorder {
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	rec := httptest.NewRecorder()
	act.ServeHTTP(rec, httptest.NewRequest(method, target, r))
	return rec
}

// newActivator builds an activator over client and runs its idle parker
// for the length of the test.
func newActivator(t *testing.T, client *consumer.Client, cfg activator.Config) *activator.Activator {
	t.Helper()
	act, err := activator.New(client, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { act.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return act
}

// tcpLineGuest serves g on a real TCP port and returns its endpoint.
func tcpLineGuest(t *testing.T, g *lineGuest) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	ep := "tcp://" + lis.Addr().String()
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go g.serve(ep, c)
		}
	}()
	return ep
}

func TestNew(t *testing.T) {
	cases := []struct {
		name    string
		revs    []activator.Revision
		dial    func(context.Context, string) (net.Conn, error)
		tcp     bool   // the home hands out a real TCP endpoint
		wantErr string // a substring of New's error, "" for success
		// For a config New accepts, one request goes to each of the first
		// revision's sessions in order. Each must be served by the named
		// session and get the reply.
		sessions []string
		reply    string
	}{
		{name: "no revisions is refused", wantErr: "no revisions"},
		{name: "a revision without a name is refused",
			revs: []activator.Revision{{Grant: "g"}}, wantErr: "needs a name and a grant"},
		{name: "a revision without a grant is refused",
			revs: []activator.Revision{{Name: "a"}}, wantErr: "needs a name and a grant"},
		{name: "an unknown mode is refused, not served as line",
			revs: []activator.Revision{{Name: "a", Grant: "g", Mode: "htp"}}, wantErr: `mode "htp"`},
		{name: "a revision named twice is refused, not silently replaced",
			revs: []activator.Revision{{Name: "a", Grant: "g1"}, {Name: "a", Grant: "g2"}}, wantErr: `"a" twice`},
		{name: "no concurrency means one fiber, no mode means line",
			revs:     []activator.Revision{{Name: "hello", Grant: "g", Concurrency: -3}},
			dial:     newLineGuest().dial,
			sessions: []string{"hello-0", "hello-0"}, reply: "got:ping"},
		{name: "no dialer means the endpoint is dialled as the home gave it",
			revs: []activator.Revision{{Name: "hello", Grant: "g", Mode: "line"}},
			tcp:  true, sessions: []string{"hello-0"}, reply: "got:ping"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := &fakeHome{}
			if tc.tcp {
				home.endpoint = tcpLineGuest(t, newLineGuest())
			}
			client := startFake(t, home)
			act, err := activator.New(client, activator.Config{Revisions: tc.revs, Dial: tc.dial})
			if tc.wantErr != "" {
				if act != nil || err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("New = %v, %v, want error with %q", act, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for i, want := range tc.sessions {
				rec := serve(act, http.MethodGet, "/"+tc.revs[0].Name, "")
				if got := rec.Header().Get("X-Fiberd-Session"); rec.Code != 200 || got != want ||
					strings.TrimSpace(rec.Body.String()) != tc.reply {
					t.Fatalf("request %d = %d %q on %q, want 200 %q on %q", i, rec.Code, rec.Body, got, tc.reply, want)
				}
			}
			if got := home.cloneCount(); got != 1 {
				t.Fatalf("home saw %d clones, want 1 (later requests attach)", got)
			}
		})
	}
}

// TestMiss checks that each way a Clone can miss reaches the caller as
// the Knative fallback it stands for.
func TestMiss(t *testing.T) {
	cases := []struct {
		name     string
		err      func(t *testing.T) error
		code     int
		bodyHas  string
		header   map[string]string // "" means the header must be absent
		grantJWT string
	}{
		{name: "shed is 503 with the home's Retry-After",
			err: func(t *testing.T) error {
				return missErr(t, codes.ResourceExhausted, "lane down", &grantv1.Miss{Code: grantv1.MissCode_SHED, RetryAfterS: 7})
			},
			code: 503, bodyHas: "shed: ", header: map[string]string{"Retry-After": "7", "X-Fiberd-Preferred-Home": ""}},
		{name: "deferred is 503 naming the home that holds the session",
			err: func(t *testing.T) error {
				return missErr(t, codes.Unavailable, "parked elsewhere", &grantv1.Miss{Code: grantv1.MissCode_DEFERRED_FALLBACK, PreferredHome: "home-b"})
			},
			code: 503, bodyHas: "deferred: take the ordinary path: parked elsewhere",
			header: map[string]string{"X-Fiberd-Preferred-Home": "home-b", "Retry-After": ""}},
		{name: "deferred with no known home names none",
			err: func(t *testing.T) error {
				return missErr(t, codes.Unavailable, "full", &grantv1.Miss{Code: grantv1.MissCode_DEFERRED_FALLBACK})
			},
			code: 503, bodyHas: "deferred: take the ordinary path: full", header: map[string]string{"X-Fiberd-Preferred-Home": ""}},
		{name: "a tier gap is 412",
			err: func(*testing.T) error {
				return status.Error(codes.FailedPrecondition, "min_tier snapshot above home tier warm")
			},
			code: 412, bodyHas: "tier gap: min_tier snapshot above home tier warm"},
		{name: "any other failure is 502 with the home's reason",
			err:  func(*testing.T) error { return status.Error(codes.PermissionDenied, "grant revoked") },
			code: 502, bodyHas: "grant revoked"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			missing := tc.err(t)
			home := &fakeHome{clone: func(context.Context, *grantv1.CloneRequest) error { return missing }}
			act := newActivator(t, startFake(t, home), activator.Config{
				Revisions: []activator.Revision{{Name: "hello", Grant: "g"}}, Dial: newLineGuest().dial})
			rec := serve(act, http.MethodGet, "/hello", "")
			if rec.Code != tc.code || !strings.Contains(rec.Body.String(), tc.bodyHas) {
				t.Fatalf("got %d %q, want %d with %q", rec.Code, rec.Body, tc.code, tc.bodyHas)
			}
			for k, want := range tc.header {
				if got := rec.Header().Get(k); got != want {
					t.Errorf("%s = %q, want %q", k, got, want)
				}
			}
			if got := rec.Header().Get("X-Fiberd-Clone"); got != "" {
				t.Errorf("a miss carries X-Fiberd-Clone %q", got)
			}
		})
	}
}

// TestRoute checks which revision a request reaches and the path its
// guest sees.
func TestRoute(t *testing.T) {
	guest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "%s %s", r.Host, r.URL.Path)
	}))
	t.Cleanup(guest.Close)
	dial := func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", guest.Listener.Addr().String())
	}
	two := []activator.Revision{{Name: "hello", Grant: "g", Mode: "http"}, {Name: "web", Grant: "g", Mode: "http"}}
	one := []activator.Revision{{Name: "solo", Grant: "g", Mode: "http"}}
	cases := []struct {
		name    string
		revs    []activator.Revision
		target  string // a path, or an absolute URL that sets the Host
		host    string // overrides the Host when set
		code    int
		session string // X-Fiberd-Session, for a request that is served
		body    string // what the guest saw, as "<host> <path>"
	}{
		{name: "the first path segment names the revision and is stripped",
			revs: two, target: "/web/items/7", host: "10.0.0.1:8080",
			code: 200, session: "web-0", body: "10.0.0.1:8080 /items/7"},
		{name: "the revision's own path is the guest's root",
			revs: two, target: "/web", code: 200, session: "web-0", body: "example.com /"},
		{name: "the first label of the Host names the revision",
			revs: two, target: "/items", host: "web.default.example.com",
			code: 200, session: "web-0", body: "web.default.example.com /items"},
		{name: "a Host with a port routes the same",
			revs: two, target: "/items", host: "hello.default.example.com:8080",
			code: 200, session: "hello-0", body: "hello.default.example.com:8080 /items"},
		{name: "the path wins over the Host",
			revs: two, target: "/web/x", host: "hello.example.com",
			code: 200, session: "web-0", body: "hello.example.com /x"},
		{name: "an absolute URL with no path reaches the guest's root",
			revs: two, target: "http://web.example.com",
			code: 200, session: "web-0", body: "web.example.com /"},
		{name: "with several revisions an unknown one is 404",
			revs: two, target: "/nope", host: "10.0.0.1", code: 404},
		{name: "an only revision takes every request, path untouched",
			revs: one, target: "/anything/else", host: "10.0.0.1:80",
			code: 200, session: "solo-0", body: "10.0.0.1:80 /anything/else"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			act := newActivator(t, startFake(t, &fakeHome{}), activator.Config{Revisions: tc.revs, Dial: dial})
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			if tc.host != "" {
				req.Host = tc.host
			}
			rec := httptest.NewRecorder()
			act.ServeHTTP(rec, req)
			if rec.Code != tc.code {
				t.Fatalf("code = %d %q, want %d", rec.Code, rec.Body, tc.code)
			}
			if tc.code != 200 {
				if !strings.Contains(rec.Body.String(), "no such revision") {
					t.Fatalf("body = %q, want no such revision", rec.Body)
				}
				return
			}
			if got := rec.Header().Get("X-Fiberd-Session"); got != tc.session || rec.Body.String() != tc.body {
				t.Fatalf("served by %q with %q, want %q with %q", got, rec.Body, tc.session, tc.body)
			}
		})
	}
}

// TestProxyLine checks what reaches a line protocol guest and what comes
// back. A fiber that fails is dropped, so the next request clones a fresh
// one instead of reusing a dead endpoint.
func TestProxyLine(t *testing.T) {
	// pipeTo dials a guest that runs fn on its end of the connection.
	pipeTo := func(fn func(c net.Conn)) func(context.Context, string) (net.Conn, error) {
		return func(context.Context, string) (net.Conn, error) {
			a, b := net.Pipe()
			go func() { defer func() { _ = b.Close() }(); fn(b) }()
			return a, nil
		}
	}
	readLine := func(c net.Conn) { _, _ = bufioReadLine(c) }
	cases := []struct {
		name     string
		dial     func(context.Context, string) (net.Conn, error)
		method   string
		body     string
		code     int
		reply    string // the exact body for a 200, a substring otherwise
		wantGone bool
	}{
		{name: "a GET pings", dial: newLineGuest().dial,
			method: http.MethodGet, code: 200, reply: "got:ping"},
		{name: "the body's first line is the protocol line", dial: newLineGuest().dial,
			method: http.MethodPost, body: "  incr\nsecond line\n", code: 200, reply: "got:incr"},
		{name: "a blank body pings", dial: newLineGuest().dial,
			method: http.MethodPost, body: " \n\t", code: 200, reply: "got:ping"},
		{name: "a reply cut short of its newline still counts",
			dial: pipeTo(func(c net.Conn) {
				readLine(c)
				_, _ = io.WriteString(c, "partial")
			}),
			method: http.MethodGet, code: 200, reply: "partial"},
		{name: "an unreachable fiber is 502 and dropped", dial: failDial,
			method: http.MethodGet, code: 502, reply: "fiber unreachable: connection refused", wantGone: true},
		{name: "a fiber that will not take the line is 502 and dropped",
			dial: func(context.Context, string) (net.Conn, error) {
				a, b := net.Pipe()
				_ = b.Close()
				return a, nil
			},
			method: http.MethodGet, code: 502, reply: "fiber write: ", wantGone: true},
		{name: "a fiber that hangs up without a reply is 502 and dropped",
			dial:   pipeTo(readLine),
			method: http.MethodGet, code: 502, reply: "fiber reply: EOF", wantGone: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := &fakeHome{}
			act := newActivator(t, startFake(t, home), activator.Config{
				Revisions: []activator.Revision{{Name: "hello", Grant: "g"}}, Dial: tc.dial})
			rec := serve(act, tc.method, "/hello", tc.body)
			got := rec.Body.String()
			if rec.Code != tc.code ||
				(tc.code == 200 && (got != tc.reply+"\n" || rec.Header().Get("Content-Type") != "text/plain")) ||
				(tc.code != 200 && !strings.Contains(got, tc.reply)) {
				t.Fatalf("got %d %q (%s), want %d %q", rec.Code, got, rec.Header().Get("Content-Type"), tc.code, tc.reply)
			}
			wantKind, wantClones := "ATTACH", 1
			if tc.wantGone {
				wantKind, wantClones = "CREATE", 2
			}
			next := serve(act, http.MethodGet, "/hello", "")
			if got := next.Header().Get("X-Fiberd-Clone"); got != wantKind || home.cloneCount() != wantClones {
				t.Fatalf("next request is %s after %d clones, want %s after %d", got, home.cloneCount(), wantKind, wantClones)
			}
		})
	}
}

// bufioReadLine reads up to and including the first newline, one byte at
// a time so nothing past it is consumed.
func bufioReadLine(c net.Conn) (string, error) {
	var sb strings.Builder
	b := make([]byte, 1)
	for {
		if _, err := c.Read(b); err != nil {
			return sb.String(), err
		}
		sb.WriteByte(b[0])
		if b[0] == '\n' {
			return sb.String(), nil
		}
	}
}

// TestProxyHTTP checks that an HTTP guest's response reaches the caller as
// it was, that a guest that cannot be reached drops the fiber, and that no
// connection to a guest outlives its request.
func TestProxyHTTP(t *testing.T) {
	cases := []struct {
		name     string
		handler  http.HandlerFunc
		dial     bool // false when the guest is unreachable
		code     int
		bodyHas  string
		header   map[string]string
		wantGone bool
	}{
		{name: "the guest's status, headers and body pass through",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Guest", "teapot")
				w.WriteHeader(http.StatusTeapot)
				_, _ = fmt.Fprintf(w, "%s %s", r.Method, r.URL.Path)
			},
			dial: true, code: http.StatusTeapot, bodyHas: "GET /cup", header: map[string]string{"X-Guest": "teapot"}},
		{name: "an unreachable guest is 502 and the fiber dropped",
			code: 502, bodyHas: "fiber: ", wantGone: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var open atomic.Int64
			guest := httptest.NewUnstartedServer(tc.handler)
			guest.Config.ConnState = func(_ net.Conn, s http.ConnState) {
				switch s {
				case http.StateNew:
					open.Add(1)
				case http.StateClosed, http.StateHijacked:
					open.Add(-1)
				}
			}
			guest.Start()
			t.Cleanup(guest.Close)
			dial := failDial
			if tc.dial {
				dial = func(ctx context.Context, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "tcp", guest.Listener.Addr().String())
				}
			}
			home := &fakeHome{}
			act := newActivator(t, startFake(t, home), activator.Config{
				Revisions: []activator.Revision{{Name: "tea", Grant: "g", Mode: "http"}}, Dial: dial})
			rec := serve(act, http.MethodGet, "/tea/cup", "")
			if rec.Code != tc.code || !strings.Contains(rec.Body.String(), tc.bodyHas) {
				t.Fatalf("got %d %q, want %d with %q", rec.Code, rec.Body, tc.code, tc.bodyHas)
			}
			for k, want := range tc.header {
				if got := rec.Header().Get(k); got != want {
					t.Errorf("%s = %q, want %q", k, got, want)
				}
			}
			// Every connection to the guest closes once its request is
			// done. One left idle would hold a socket and two goroutines
			// for as long as the activator runs.
			deadline := time.Now().Add(3 * time.Second)
			for open.Load() != 0 {
				if time.Now().After(deadline) {
					t.Fatalf("%d connection(s) to the guest still open after the response", open.Load())
				}
				time.Sleep(5 * time.Millisecond)
			}
			wantKind := "ATTACH"
			if tc.wantGone {
				wantKind = "CREATE"
			}
			if got := serve(act, http.MethodGet, "/tea/cup", "").Header().Get("X-Fiberd-Clone"); got != wantKind {
				t.Fatalf("next request is %s, want %s", got, wantKind)
			}
		})
	}
}

// TestSlots checks how requests spread over a revision's fibers. A step
// that holds keeps its fiber busy until the scenario ends.
func TestSlots(t *testing.T) {
	type step struct {
		hold    bool
		session string // the session that serves the request
		kind    string // its X-Fiberd-Clone
	}
	cases := []struct {
		name        string
		concurrency int
		steps       []step
	}{
		{name: "an idle fiber takes the next request rather than a second clone",
			concurrency: 2,
			steps:       []step{{session: "hello-0", kind: "CREATE"}, {session: "hello-0", kind: "ATTACH"}}},
		{name: "a busy fiber makes the next request clone a second one",
			concurrency: 2,
			steps:       []step{{hold: true, session: "hello-0", kind: "CREATE"}, {session: "hello-1", kind: "CREATE"}}},
		{name: "with every fiber busy the least busy one takes the request",
			concurrency: 2,
			steps: []step{
				{hold: true, session: "hello-0", kind: "CREATE"},
				{hold: true, session: "hello-1", kind: "CREATE"},
				{hold: true, session: "hello-0", kind: "ATTACH"},
				{hold: true, session: "hello-1", kind: "ATTACH"},
				{session: "hello-0", kind: "ATTACH"},
			}},
		{name: "with one fiber every request shares it",
			concurrency: 1,
			steps:       []step{{hold: true, session: "hello-0", kind: "CREATE"}, {session: "hello-0", kind: "ATTACH"}}},
		{name: "no concurrency set means one fiber",
			concurrency: 0,
			steps:       []step{{hold: true, session: "hello-0", kind: "CREATE"}, {session: "hello-0", kind: "ATTACH"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			guest := newLineGuest()
			act := newActivator(t, startFake(t, &fakeHome{}), activator.Config{
				Revisions: []activator.Revision{{Name: "hello", Grant: "g", Concurrency: tc.concurrency}}, Dial: guest.dial})
			check := func(i int, rec *httptest.ResponseRecorder) {
				st := tc.steps[i]
				if s, k := rec.Header().Get("X-Fiberd-Session"), rec.Header().Get("X-Fiberd-Clone"); rec.Code != 200 || s != st.session || k != st.kind {
					t.Errorf("step %d = %d %s on %q, want 200 %s on %q", i, rec.Code, k, s, st.kind, st.session)
				}
			}
			var wg sync.WaitGroup
			held := map[int]*httptest.ResponseRecorder{}
			released := false
			release := func() {
				if !released {
					released = true
					close(guest.release)
					wg.Wait()
				}
			}
			defer release()
			for i, st := range tc.steps {
				if !st.hold {
					check(i, serve(act, http.MethodGet, "/hello", ""))
					continue
				}
				rec := httptest.NewRecorder()
				held[i] = rec
				wg.Add(1)
				go func() {
					defer wg.Done()
					act.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/hello", strings.NewReader("hold")))
				}()
				if ep := guest.waitEntered(t); ep != "test://"+st.session {
					t.Fatalf("step %d held %s, want test://%s", i, ep, st.session)
				}
			}
			release()
			for i, rec := range held {
				check(i, rec)
			}
		})
	}
}

// TestConcurrentRequests runs many requests at once over a revision's
// fibers. Run it with -race, because picking a fiber must read every
// slot's load under that slot's lock.
func TestConcurrentRequests(t *testing.T) {
	cases := []struct {
		name        string
		concurrency int
		requests    int
	}{
		{name: "one fiber", concurrency: 1, requests: 32},
		{name: "three fibers", concurrency: 3, requests: 96},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := &fakeHome{}
			act := newActivator(t, startFake(t, home), activator.Config{
				Revisions: []activator.Revision{{Name: "hello", Grant: "g", Concurrency: tc.concurrency}},
				Dial:      newLineGuest().dial})
			recs := make([]*httptest.ResponseRecorder, tc.requests)
			var wg sync.WaitGroup
			for i := range recs {
				wg.Add(1)
				go func() {
					defer wg.Done()
					recs[i] = serve(act, http.MethodGet, "/hello", "")
				}()
			}
			wg.Wait()
			for i, rec := range recs {
				s := rec.Header().Get("X-Fiberd-Session")
				var n int
				if _, err := fmt.Sscanf(s, "hello-%d", &n); err != nil || n >= tc.concurrency ||
					rec.Code != 200 || rec.Body.String() != "got:ping\n" {
					t.Fatalf("request %d = %d %q on %q", i, rec.Code, rec.Body, s)
				}
			}
			if got := home.cloneCount(); got > tc.concurrency {
				t.Fatalf("%d clones for %d fibers", got, tc.concurrency)
			}
		})
	}
}

// TestSlowHomeCall checks that a revision whose Clone or Park is slow
// holds up only its own requests. Another revision that is already
// serving answers at once.
func TestSlowHomeCall(t *testing.T) {
	cases := []struct {
		name string
		// slowClone blocks the slow revision's Clone, else its Park.
		slowClone bool
	}{
		{name: "a slow clone", slowClone: true},
		{name: "a slow park"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			unblock := make(chan struct{})
			entered := make(chan struct{}, 1)
			block := func(ctx context.Context) error {
				select {
				case entered <- struct{}{}:
				default:
				}
				select {
				case <-unblock:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			home := &fakeHome{}
			cfg := activator.Config{
				Revisions: []activator.Revision{{Name: "slow", Grant: "slow-g"}, {Name: "fast", Grant: "fast-g"}},
				Dial:      newLineGuest().dial,
			}
			if tc.slowClone {
				home.clone = func(ctx context.Context, req *grantv1.CloneRequest) error {
					if req.GetGrantJwt() == "slow-g" {
						return block(ctx)
					}
					return nil
				}
			} else {
				cfg.Idle = 20 * time.Millisecond
				home.park = func(req *grantv1.ParkRequest) error {
					if strings.HasPrefix(req.GetFiberId(), "slow-") {
						return block(context.Background())
					}
					return nil
				}
			}
			act := newActivator(t, startFake(t, home), cfg)

			var wg sync.WaitGroup
			defer wg.Wait()
			stop := sync.OnceFunc(func() { close(unblock) })
			defer stop()
			if rec := serve(act, http.MethodGet, "/fast", ""); rec.Code != 200 {
				t.Fatalf("warming fast = %d %q", rec.Code, rec.Body)
			}
			if !tc.slowClone {
				if rec := serve(act, http.MethodGet, "/slow", ""); rec.Code != 200 {
					t.Fatalf("warming slow = %d %q", rec.Code, rec.Body)
				}
			}
			// One request to slow starts its clone, or its park is under
			// way. Three more then queue behind it, waiting to pick a
			// fiber.
			for i := 0; i < 4; i++ {
				wg.Add(1)
				go func() { defer wg.Done(); serve(act, http.MethodGet, "/slow", "") }()
				if i == 0 {
					select {
					case <-entered:
					case <-time.After(5 * time.Second):
						t.Fatal("the slow call never reached the home")
					}
				}
			}
			waitGoroutines(t, "activator.(*Activator).pick(", 3)
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- serve(act, http.MethodGet, "/fast", "") }()
			select {
			case rec := <-done:
				if rec.Code != 200 {
					t.Fatalf("fast = %d %q", rec.Code, rec.Body)
				}
			case <-time.After(5 * time.Second):
				t.Error("fast waited on slow's home call")
				stop()
				<-done
			}
		})
	}
}

// waitGoroutines waits until at least n goroutines have fn on their
// stack.
func waitGoroutines(t *testing.T, fn string, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	buf := make([]byte, 1<<20)
	for {
		k := runtime.Stack(buf, true)
		if got := strings.Count(string(buf[:k]), fn); got >= n {
			return
		} else if time.Now().After(deadline) {
			t.Fatalf("%d goroutine(s) in %s, want %d", got, fn, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestParkIdle checks what happens to an idle fiber.
func TestParkIdle(t *testing.T) {
	cases := []struct {
		name     string
		idle     time.Duration
		parkErr  error
		wantKind string // of the request after the park
		clones   int    // the home's clones after that request
	}{
		{name: "an idle fiber is parked and the next request clones it back",
			idle: 20 * time.Millisecond, wantKind: "CREATE", clones: 2},
		{name: "an idle shorter than four nanoseconds still parks",
			idle: 3 * time.Nanosecond, wantKind: "CREATE", clones: 2},
		{name: "a fiber the home no longer knows is dropped",
			idle: 20 * time.Millisecond, parkErr: status.Error(codes.NotFound, "no such fiber"), wantKind: "CREATE", clones: 2},
		{name: "a failed park keeps the fiber serving",
			idle: 20 * time.Millisecond, parkErr: status.Error(codes.Unavailable, "checkpoint failed"), wantKind: "ATTACH", clones: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := &fakeHome{park: func(*grantv1.ParkRequest) error { return tc.parkErr }}
			act := newActivator(t, startFake(t, home), activator.Config{
				Revisions: []activator.Revision{{Name: "hello", Grant: "g"}}, Idle: tc.idle, Dial: newLineGuest().dial})
			if rec := serve(act, http.MethodGet, "/hello", ""); rec.Code != 200 {
				t.Fatalf("first request = %d %q", rec.Code, rec.Body)
			}
			if id := home.waitPark(t); id != "hello-0#1" {
				t.Fatalf("parked %q, want hello-0#1", id)
			}
			rec := serve(act, http.MethodGet, "/hello", "")
			if got := rec.Header().Get("X-Fiberd-Clone"); rec.Code != 200 || got != tc.wantKind || home.cloneCount() != tc.clones {
				t.Fatalf("after the park: %d %s with %d clones, want 200 %s with %d", rec.Code, got, home.cloneCount(), tc.wantKind, tc.clones)
			}
		})
	}
}
