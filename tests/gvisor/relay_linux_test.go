//go:build linux

package gvisortest

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
	fiberendpoint "github.com/helayoty/fiberd/pkg/endpoint"
	"github.com/helayoty/fiberd/pkg/runtime/host"
)

// httpDo sends one request to a tcp endpoint's HTTP server and returns
// the trimmed body.
func httpDo(t *testing.T, method, ep, path string) string {
	t.Helper()
	e, err := fiberendpoint.Parse(ep)
	if err != nil || e.Scheme != "tcp" {
		t.Fatalf("endpoint %q: %+v %v", ep, e, err)
	}
	_, addr := e.Network()
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(method, "http://"+addr+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, ep+path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("%s %s: %d %q %v", method, ep+path, resp.StatusCode, body, err)
	}
	return strings.TrimSpace(string(body))
}

// TestRelayedTCPEndpoints: a gVisor home with an inet family. The
// sandbox has no network (--network=none) and serves a unix socket; the
// agent relays a port of the declared address to it. Callers do HTTP over
// the tcp endpoint, a park ends the relay, and a resume brings the fiber
// back on its parked port with its state.
func TestRelayedTCPEndpoints(t *testing.T) {
	cases := []struct {
		fam  fiberendpoint.Family
		host string
	}{{fiberendpoint.Inet4, "127.0.0.1"}, {fiberendpoint.Inet6, "::1"}}
	for _, c := range cases {
		t.Run(string(c.fam), func(t *testing.T) {
			if l, err := net.Listen("tcp", net.JoinHostPort(c.host, "0")); err != nil {
				t.Skipf("no %s loopback here: %v", c.fam, err)
			} else {
				_ = l.Close()
			}
			lo, hi := 42000, 42003
			rt := newRuntimeWith(t, "/bin/refzygote --heap-mb 64 --gvisor --http", func(cfg *host.Config) {
				cfg.Endpoints = fiberendpoint.Policy{Family: c.fam, Host: c.host, PortMin: lo, PortMax: hi}
			})
			if !rt.(*host.Runtime).Relays() {
				t.Fatal("a gVisor home with a tcp family must relay")
			}
			ctx := context.Background()
			g := core.Grant{UID: "relay-" + string(c.fam), TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			fence := func(seq uint64) core.Fence { return core.Fence{GrantUID: g.UID, Epoch: 1, Seq: seq} }
			t0 := time.Now()
			h1, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: fence(1), Deadline: 5 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("fiber 1 restored and relayed in %s: %s", time.Since(t0).Round(time.Millisecond), h1.Endpoint)
			e1, err := fiberendpoint.Parse(h1.Endpoint)
			if err != nil || e1.Scheme != "tcp" || e1.Host != c.host || e1.Port < lo || e1.Port > hi {
				t.Fatalf("endpoint %q parsed as %+v (%v), want tcp on %s in %d-%d", h1.Endpoint, e1, err, c.host, lo, hi)
			}
			if got := httpDo(t, http.MethodPost, h1.Endpoint, "/incr"); got != "1" {
				t.Fatalf("POST /incr = %q, want 1", got)
			}
			if got := httpDo(t, http.MethodGet, h1.Endpoint, "/count"); got != "1" {
				t.Fatalf("GET /count = %q, want 1", got)
			}
			if got := httpDo(t, http.MethodGet, h1.Endpoint, "/fence"); got != h1.ID {
				t.Fatalf("GET /fence = %q, want %s", got, h1.ID)
			}
			// A second fiber is another sandbox on another port.
			h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: fence(2), Deadline: 5 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			if h2.Endpoint == h1.Endpoint {
				t.Fatalf("two fibers on one endpoint: %s", h1.Endpoint)
			}
			if got := httpDo(t, http.MethodGet, h2.Endpoint, "/count"); got != "0" {
				t.Fatalf("fiber 2 GET /count = %q, want 0", got)
			}
			// Park ends the relay; resume brings it back on the parked port.
			ref, err := rt.Park(ctx, h1.ID, true)
			if err != nil {
				t.Fatalf("park: %v", err)
			}
			dctx, cancel := context.WithTimeout(ctx, time.Second)
			if conn, err := fiberendpoint.Dial(dctx, h1.Endpoint); err == nil {
				_ = conn.Close()
				t.Fatal("parked endpoint still accepts connections")
			}
			cancel()
			t0 = time.Now()
			h3, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: fence(3), Deadline: 10 * time.Second})
			if err != nil {
				t.Fatalf("resume: %v", err)
			}
			t.Logf("resumed in %s: %s", time.Since(t0).Round(time.Millisecond), h3.Endpoint)
			if h3.Endpoint != h1.Endpoint {
				t.Fatalf("resumed on %s, want the parked endpoint %s", h3.Endpoint, h1.Endpoint)
			}
			if got := httpDo(t, http.MethodGet, h3.Endpoint, "/count"); got != "1" {
				t.Fatalf("GET /count after resume = %q, want 1", got)
			}
			if got := httpDo(t, http.MethodPost, h3.Endpoint, "/incr"); got != "2" {
				t.Fatalf("POST /incr after resume = %q, want 2", got)
			}
			if got := httpDo(t, http.MethodGet, h3.Endpoint, "/fence"); got != h3.ID {
				t.Fatalf("GET /fence after resume = %q, want %s", got, h3.ID)
			}
			for _, h := range []core.FiberHandle{h2, h3} {
				if err := rt.Release(ctx, h.ID, true); err != nil {
					t.Fatal(err)
				}
			}
			dctx, cancel = context.WithTimeout(ctx, time.Second)
			defer cancel()
			if conn, err := fiberendpoint.Dial(dctx, h3.Endpoint); err == nil {
				_ = conn.Close()
				t.Fatal("released endpoint still accepts connections")
			}
		})
	}
}
