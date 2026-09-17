package ingress

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

func TestRoutesByTargetActor(t *testing.T) {
	s, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s)
	defer srv.Close()

	// Nothing active: misdirected, and the router is told to re-resolve.
	st, _, hdr := get(t, srv, "team-a/counter-1")
	if st != http.StatusMisdirectedRequest || hdr.Get(StaleAssignmentHeader) != "true" {
		t.Fatalf("inactive actor: %d %v", st, hdr)
	}
	if st, _, _ := get(t, srv, ""); st != http.StatusMisdirectedRequest {
		t.Fatalf("no header: %d", st)
	}
	if st, _, _ := get(t, srv, "bad"); st != http.StatusMisdirectedRequest {
		t.Fatalf("malformed header: %d", st)
	}

	// Two actors at once, each at its own fiber; routing headers are stripped.
	s.Activate("team-a", "counter-1", fakeFiber(t, "one"))
	s.Activate("team-a", "counter-2", fakeFiber(t, "two"))
	st, body, _ := get(t, srv, "team-a/counter-1")
	if st != 200 || body != "one POST /incr host=app.example" {
		t.Fatalf("actor 1: %d %q", st, body)
	}
	if st, body, _ := get(t, srv, "team-a/counter-2"); st != 200 || body != "two POST /incr host=app.example" {
		t.Fatalf("actor 2: %d %q", st, body)
	}
	if ep, ok := s.Endpoint("team-a", "counter-1"); !ok || !strings.HasPrefix(ep, "tcp://") {
		t.Fatalf("Endpoint = %q %v", ep, ok)
	}

	// Deactivated: misdirected again, the other one unaffected.
	s.Deactivate("team-a", "counter-1")
	if st, _, hdr := get(t, srv, "team-a/counter-1"); st != http.StatusMisdirectedRequest || hdr.Get(StaleAssignmentHeader) != "true" {
		t.Fatalf("after deactivate: %d", st)
	}
	if st, _, _ := get(t, srv, "team-a/counter-2"); st != 200 {
		t.Fatalf("actor 2 after actor 1 left: %d", st)
	}

	// A dead fiber is a bad gateway, not a misdirection.
	s.Activate("team-a", "gone", "tcp://127.0.0.1:1")
	if st, _, hdr := get(t, srv, "team-a/gone"); st != http.StatusBadGateway || hdr.Get(StaleAssignmentHeader) != "" {
		t.Fatalf("dead fiber: %d %v", st, hdr)
	}
}

func TestTLSMaterialIsChecked(t *testing.T) {
	if _, err := New(Config{CredentialBundle: "/nonexistent/bundle.pem", TrustBundle: "/nonexistent/trust.pem"}); err == nil {
		t.Fatal("missing bundles must fail at start")
	}
}
