//go:build linux

package runctest

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

// TestRelayedTCPEndpoints: a runc home with an inet family. The grant's
// container has a loopback-only network namespace, so its fibers serve
// unix sockets under /host and the agent relays a port of the declared
// address to each. Callers do HTTP over the tcp endpoint, and a park and
// resume keep the fiber's state and port.
func TestRelayedTCPEndpoints(t *testing.T) {
	cases := []struct {
		fam  fiberendpoint.Family
		host string
	}{{fiberendpoint.Inet4, "127.0.0.1"}}
	for _, c := range cases {
		t.Run(string(c.fam), func(t *testing.T) {
			if l, err := net.Listen("tcp", net.JoinHostPort(c.host, "0")); err != nil {
				t.Skipf("no %s loopback here: %v", c.fam, err)
			} else {
				_ = l.Close()
			}
			lo, hi := 43000, 43003
			rt := newRuntimeWith(t, "/bin/refzygote --heap-mb 32 --http", func(cfg *host.Config) {
				cfg.Endpoints = fiberendpoint.Policy{Family: c.fam, Host: c.host, PortMin: lo, PortMax: hi}
			})
			if !rt.(*host.Runtime).Relays() {
				t.Fatal("a runc home with a tcp family must relay")
			}
			ctx := context.Background()
			g := core.Grant{UID: "relay-" + string(c.fam), TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 64 << 20}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			fence := func(seq uint64) core.Fence { return core.Fence{GrantUID: g.UID, Epoch: 1, Seq: seq} }
			h1, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: fence(1), Deadline: 2 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
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
			h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: fence(2), Deadline: 2 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			if h2.Endpoint == h1.Endpoint {
				t.Fatalf("two fibers on one endpoint: %s", h1.Endpoint)
			}
			if got := httpDo(t, http.MethodGet, h2.Endpoint, "/count"); got != "0" {
				t.Fatalf("fiber 2 GET /count = %q, want 0", got)
			}
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
			h3, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: fence(3), Deadline: 5 * time.Second})
			if err != nil {
				t.Fatalf("resume: %v", err)
			}
			if h3.Endpoint != h1.Endpoint {
				t.Fatalf("resumed on %s, want the parked endpoint %s", h3.Endpoint, h1.Endpoint)
			}
			if got := httpDo(t, http.MethodGet, h3.Endpoint, "/count"); got != "1" {
				t.Fatalf("GET /count after resume = %q, want 1", got)
			}
			// The restored process holds its birth fence. The new one is
			// the file the agent published beside its socket, under /host.
			if got := httpDo(t, http.MethodGet, h3.Endpoint, "/fence"); got != h3.ID {
				t.Fatalf("GET /fence after resume = %q, want %s", got, h3.ID)
			}
			for _, h := range []core.FiberHandle{h2, h3} {
				if err := rt.Release(ctx, h.ID, true); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
