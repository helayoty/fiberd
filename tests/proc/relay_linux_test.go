//go:build linux

package proctest

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	procbackend "github.com/helayoty/fiberd/pkg/backend/proc"
	"github.com/helayoty/fiberd/pkg/core"
	fiberendpoint "github.com/helayoty/fiberd/pkg/endpoint"
	"github.com/helayoty/fiberd/pkg/runtime/host"
)

// unixOnlyProc is the fork backend without its tcp scheme, so a tcp home
// over it relays as a gVisor, runc or Hyperlight home does. The zygote
// is the same, so the difference between it and the plain fork backend
// under a tcp policy is the relay alone.
type unixOnlyProc struct{ *procbackend.Backend }

func (unixOnlyProc) EndpointSchemes() []string { return []string{"unix"} }

// relayRuntime opens a tcp home over the fork backend, relayed or
// direct, with the given template.
func relayRuntime(t *testing.T, relayed bool, hostIP string, lo, hi int, template string) core.Runtime {
	t.Helper()
	if l, err := net.Listen("tcp", net.JoinHostPort(hostIP, "0")); err != nil {
		t.Skipf("no loopback for %s here: %v", hostIP, err)
	} else {
		_ = l.Close()
	}
	var be unixOnlyProc
	cfg := host.Config{
		Templates:  map[string]string{"default": template},
		CgroupRoot: filepath.Join(cgRoot, fmt.Sprintf("rl%d", time.Now().UnixNano()%1_000_000)),
		RunDir:     filepath.Join("/tmp", fmt.Sprintf("fz-rl%d", time.Now().UnixNano()%1_000_000)),
		DeltaDir:   t.TempDir(),
		Endpoints:  fiberendpoint.Policy{Family: fiberendpoint.Inet4, Host: hostIP, PortMin: lo, PortMax: hi},
	}
	if relayed {
		be.Backend = procbackend.NewBackend(procbackend.Options{})
		cfg.Backend = be
	}
	rt, err := newHost(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rt.(interface{ Close() }).Close() })
	if rt.(*host.Runtime).Relays() != relayed {
		t.Fatalf("Relays = %v, want %v", rt.(*host.Runtime).Relays(), relayed)
	}
	return rt
}

// TestRelayedTCPOverProc checks the relay with a real zygote: the fork
// backend stripped of its tcp scheme gets the unix socket and callers
// reach it over the relayed port, across a park and resume. The direct
// case is the control: same policy, the zygote binds the port itself.
func TestRelayedTCPOverProc(t *testing.T) {
	cases := []struct {
		name    string
		relayed bool
		lo, hi  int
		// newFence is whether the resumed fiber reports its new fence. A
		// relayed fiber serves a unix socket and reads the fence file the
		// agent publishes beside it. One on a tcp listener of its own has
		// no such path and keeps the fence it was born with.
		newFence bool
	}{
		{name: "direct: the zygote binds the port", lo: 44000, hi: 44003},
		{name: "relayed: the zygote binds a unix socket, the agent the port", relayed: true, lo: 44010, hi: 44013, newFence: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := relayRuntime(t, tc.relayed, "127.0.0.1", tc.lo, tc.hi, zygoteBin+" --heap-mb 16")
			ctx := context.Background()
			g := core.Grant{UID: "rl", TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 32 << 20}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			fence := func(seq uint64) core.Fence { return core.Fence{GrantUID: g.UID, Epoch: 1, Seq: seq} }
			h1, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: fence(1), Deadline: 2 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			if h1.Endpoint != fmt.Sprintf("tcp://127.0.0.1:%d", tc.lo) {
				t.Fatalf("endpoint = %s", h1.Endpoint)
			}
			if got := talk(t, h1.Endpoint, "ping"); got != "pong" {
				t.Fatalf("ping = %q", got)
			}
			if got := talk(t, h1.Endpoint, "fence"); got != h1.ID {
				t.Fatalf("fence = %q, want %s", got, h1.ID)
			}
			talk(t, h1.Endpoint, "incr")
			talk(t, h1.Endpoint, "incr")
			ref, err := rt.Park(ctx, h1.ID, true)
			if err != nil {
				t.Fatalf("park: %v", err)
			}
			dctx, cancel := context.WithTimeout(ctx, time.Second)
			if c, err := fiberendpoint.Dial(dctx, h1.Endpoint); err == nil {
				_ = c.Close()
				t.Fatal("parked endpoint still accepts connections")
			}
			cancel()
			h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: fence(2), Deadline: 5 * time.Second})
			if err != nil {
				t.Fatalf("resume: %v", err)
			}
			if h2.Endpoint != h1.Endpoint {
				t.Fatalf("resumed on %s, want %s", h2.Endpoint, h1.Endpoint)
			}
			if got := talk(t, h2.Endpoint, "get"); got != "2" {
				t.Fatalf("counter after resume = %q, want 2", got)
			}
			wantFence := h1.ID
			if tc.newFence {
				wantFence = h2.ID
			}
			if got := talk(t, h2.Endpoint, "fence"); got != wantFence {
				t.Fatalf("fence after resume = %q, want %s", got, wantFence)
			}
			if err := rt.Release(ctx, h2.ID, true); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestRelayOverheadNumbers measures what the relay adds to a request:
// HTTP GET /count against the reference zygote in --http mode, the zygote
// binding the tcp port itself (direct) against the same zygote on a unix
// socket behind the agent's relay. One connection reused (keep-alive)
// and one connection per request (accept and dial on every call). Runs
// are interleaved A/B, three of each, and the medians of the per-run
// p50s are reported. FIBERD_BENCH=1 enables it.
func TestRelayOverheadNumbers(t *testing.T) {
	if os.Getenv("FIBERD_BENCH") == "" {
		t.Skip("set FIBERD_BENCH=1 to run the relay overhead measurement")
	}
	ctx := context.Background()
	homes := []struct {
		name    string
		relayed bool
		lo, hi  int
		ep      string
	}{
		{name: "direct", lo: 44100, hi: 44103},
		{name: "relayed", relayed: true, lo: 44110, hi: 44113},
	}
	for i := range homes {
		rt := relayRuntime(t, homes[i].relayed, "127.0.0.1", homes[i].lo, homes[i].hi, zygoteBin+" --heap-mb 16 --http")
		g := core.Grant{UID: "bench-" + homes[i].name, TemplateDigest: "sha256:ref"}
		if err := rt.PrepareTemplate(ctx, g); err != nil {
			t.Fatal(err)
		}
		h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: core.Fence{GrantUID: g.UID, Epoch: 1, Seq: 1}, Deadline: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		homes[i].ep = h.Endpoint
	}
	shapes := []struct {
		name      string
		keepAlive bool
		n         int
	}{
		{name: "keep-alive, one connection", keepAlive: true, n: 2000},
		{name: "a connection per request", n: 500},
	}
	const runs = 3
	p50s := map[string][]time.Duration{} // "home/shape" -> per-run p50
	p99s := map[string][]time.Duration{}
	for run := 0; run < runs; run++ {
		for _, sh := range shapes {
			for _, h := range homes {
				// Warm up: the first requests pay for the connection and
				// the zygote's first accept.
				httpGetN(t, h.ep, sh.keepAlive, 50)
				lat := httpGetN(t, h.ep, sh.keepAlive, sh.n)
				key := h.name + " / " + sh.name
				p50s[key] = append(p50s[key], pctOf(lat, 0.5))
				p99s[key] = append(p99s[key], pctOf(lat, 0.99))
			}
		}
	}
	for _, sh := range shapes {
		var med [2]time.Duration
		for i, h := range homes {
			key := h.name + " / " + sh.name
			med[i] = median(p50s[key])
			t.Logf("%-40s p50 per run %v -> median %s; p99 per run %v", key, rounded(p50s[key]), med[i].Round(time.Microsecond), rounded(p99s[key]))
		}
		t.Logf("%-40s relay adds %s per request (%.2fx)", sh.name, (med[1] - med[0]).Round(time.Microsecond), float64(med[1])/float64(med[0]))
	}
}

// httpGetN does n GET /count requests against a tcp endpoint and returns
// each one's latency. With keepAlive one connection is reused.
func httpGetN(t *testing.T, ep string, keepAlive bool, n int) []time.Duration {
	t.Helper()
	e, err := fiberendpoint.Parse(ep)
	if err != nil {
		t.Fatal(err)
	}
	_, addr := e.Network()
	tr := &http.Transport{DisableKeepAlives: !keepAlive, MaxIdleConns: 1, MaxIdleConnsPerHost: 1}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	defer tr.CloseIdleConnections()
	url := "http://" + addr + "/count"
	lat := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		resp, err := client.Get(url)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) == "" {
			t.Fatalf("GET %s: %d %q %v", url, resp.StatusCode, body, err)
		}
		lat = append(lat, time.Since(start))
	}
	return lat
}

func pctOf(ds []time.Duration, p float64) time.Duration {
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[int(float64(len(s)-1)*p)]
}

func median(ds []time.Duration) time.Duration { return pctOf(ds, 0.5) }

func rounded(ds []time.Duration) []time.Duration {
	out := make([]time.Duration, len(ds))
	for i, d := range ds {
		out[i] = d.Round(time.Microsecond)
	}
	return out
}
