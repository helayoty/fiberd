package ingress

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A fiber standing in: an HTTP server reached through a tcp endpoint URL.
func fakeFiber(t *testing.T, name string) (endpoint string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(TargetActorHeader) != "" || r.Header.Get(TargetPortHeader) != "" {
			http.Error(w, "routing headers leaked", http.StatusTeapot)
			return
		}
		_, _ = io.WriteString(w, name+" "+r.Method+" "+r.URL.Path+" host="+r.Host)
	}))
	t.Cleanup(srv.Close)
	return "tcp://" + strings.TrimPrefix(srv.URL, "http://")
}

func get(t *testing.T, srv *httptest.Server, actor string) (int, string, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/incr", nil)
	req.Host = "app.example"
	if actor != "" {
		req.Header.Set(TargetActorHeader, actor)
		req.Header.Set(TargetPortHeader, "9090")
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

// TestRoutesByTargetActor checks that requests route by the target-actor
// header to the actor's fiber. Steps run in order on one server. Each may
// activate or deactivate actors, then sends a request as the router would.
func TestRoutesByTargetActor(t *testing.T) {
	s, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s)
	defer srv.Close()
	one, two := fakeFiber(t, "one"), fakeFiber(t, "two")

	cases := []struct {
		name       string
		activate   map[string]string // name -> endpoint, in team-a
		deactivate string            // name, in team-a
		actor      string
		status     int
		body       string // checked when set
		stale      string // the stale-assignment header
		endpoint   bool   // Endpoint reports the actor at a tcp:// endpoint
		unknown    string // Endpoint reports this name in team-a as not active
	}{
		// With nothing active the request is misdirected, and the router re-resolves.
		{name: "an inactive actor is misdirected", actor: "team-a/counter-1", status: http.StatusMisdirectedRequest, stale: "true"},
		{name: "no actor header is misdirected", status: http.StatusMisdirectedRequest, stale: "true"},
		{name: "a malformed actor header is misdirected", actor: "bad", status: http.StatusMisdirectedRequest, stale: "true"},
		{name: "an actor header without an atespace is misdirected", actor: "/counter-1", status: http.StatusMisdirectedRequest, stale: "true"},
		{name: "an actor header with a nested name is misdirected", actor: "team-a/counter-1/x", status: http.StatusMisdirectedRequest, stale: "true"},
		// Two actors at once, each at its own fiber. Routing headers are stripped.
		{name: "two actors active: the first reaches its own fiber", activate: map[string]string{"counter-1": one, "counter-2": two},
			actor: "team-a/counter-1", status: http.StatusOK, body: "one POST /incr host=app.example", endpoint: true},
		{name: "two actors active: the second reaches its own fiber",
			actor: "team-a/counter-2", status: http.StatusOK, body: "two POST /incr host=app.example", endpoint: true},
		// A deactivated actor is misdirected again. The other one is unaffected.
		{name: "a deactivated actor is misdirected again", deactivate: "counter-1",
			actor: "team-a/counter-1", status: http.StatusMisdirectedRequest, stale: "true"},
		{name: "the other actor is unaffected by the first leaving",
			actor: "team-a/counter-2", status: http.StatusOK, body: "two POST /incr host=app.example", endpoint: true},
		{name: "a dead fiber is a bad gateway, not a misdirection", activate: map[string]string{"gone": "tcp://127.0.0.1:1"},
			actor: "team-a/gone", status: http.StatusBadGateway, endpoint: true},
		{name: "an actor activated again moves to its new fiber", activate: map[string]string{"counter-2": one},
			actor: "team-a/counter-2", status: http.StatusOK, body: "one POST /incr host=app.example", endpoint: true},
		{name: "a deactivated actor has no endpoint", actor: "team-a/counter-1", status: http.StatusMisdirectedRequest, stale: "true",
			unknown: "counter-1"},
	}
	for _, tc := range cases {
		if !t.Run(tc.name, func(t *testing.T) {
			for name, ep := range tc.activate {
				s.Activate("team-a", name, ep)
			}
			if tc.deactivate != "" {
				s.Deactivate("team-a", tc.deactivate)
			}
			st, body, hdr := get(t, srv, tc.actor)
			if st != tc.status || (tc.body != "" && body != tc.body) || hdr.Get(StaleAssignmentHeader) != tc.stale {
				t.Fatalf("%s: %d %q stale=%q, want %d %q stale=%q", tc.actor, st, body, hdr.Get(StaleAssignmentHeader), tc.status, tc.body, tc.stale)
			}
			if tc.unknown != "" {
				if ep, ok := s.Endpoint("team-a", tc.unknown); ok || ep != "" {
					t.Fatalf("Endpoint of %s = %q %v, want none", tc.unknown, ep, ok)
				}
			}
			if tc.endpoint {
				atespace, name, _ := strings.Cut(tc.actor, "/")
				if ep, ok := s.Endpoint(atespace, name); !ok || !strings.HasPrefix(ep, "tcp://") {
					t.Fatalf("Endpoint = %q %v", ep, ok)
				}
			}
		}) {
			t.FailNow()
		}
	}
}

// TestTLSMaterialIsChecked checks that TLS material is read at start.
// Missing bundles fail New, and no TLS material at all means plain HTTP.
func TestTLSMaterialIsChecked(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{name: "no bundles: plain HTTP"},
		{name: "missing bundles fail at start", cfg: Config{CredentialBundle: "/nonexistent/bundle.pem", TrustBundle: "/nonexistent/trust.pem"}, wantErr: true},
		{name: "a missing credential bundle alone fails at start", cfg: Config{CredentialBundle: "/nonexistent/bundle.pem"}, wantErr: true},
		{name: "a trust bundle without a credential bundle fails at start", cfg: Config{TrustBundle: "/nonexistent/trust.pem"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); (err != nil) != tc.wantErr {
				t.Fatalf("New err = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}

// TestLeavingAFiberClosesItsIdleConnections checks that an actor moved to
// another fiber, or taken off, lets go of the kept-alive connections to
// its old fiber.
func TestLeavingAFiberClosesItsIdleConnections(t *testing.T) {
	cases := []struct {
		name  string
		leave func(s *Server, next string)
	}{
		{"activated again on another fiber", func(s *Server, next string) { s.Activate("team-a", "counter", next) }},
		{"deactivated", func(s *Server, _ string) { s.Deactivate("team-a", "counter") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			closed := make(chan struct{}, 1)
			old := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "old")
			}))
			old.Config.ConnState = func(_ net.Conn, st http.ConnState) {
				if st == http.StateClosed {
					select {
					case closed <- struct{}{}:
					default:
					}
				}
			}
			old.Start()
			t.Cleanup(old.Close)
			s, err := New(Config{})
			if err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewServer(s)
			t.Cleanup(srv.Close)
			s.Activate("team-a", "counter", "tcp://"+old.Listener.Addr().String())
			if st, body, _ := get(t, srv, "team-a/counter"); st != http.StatusOK || body != "old" {
				t.Fatalf("through the old fiber: %d %q", st, body)
			}
			tc.leave(s, fakeFiber(t, "new"))
			select {
			case <-closed:
			case <-time.After(10 * time.Second):
				t.Fatal("the old fiber's idle connection stayed open")
			}
		})
	}
}
