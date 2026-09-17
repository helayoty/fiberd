//go:build linux

package proctest

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/backend"
	"github.com/helayoty/fiberd/pkg/core"
	fiberendpoint "github.com/helayoty/fiberd/pkg/endpoint"
	"github.com/helayoty/fiberd/pkg/runtime/host"
)

// tcpRuntime opens the host runtime over the fork backend with tcp
// endpoints on the loopback of one family and a ten-port range.
func tcpRuntime(t *testing.T, fam fiberendpoint.Family, hostIP string, lo, hi int) core.Runtime {
	t.Helper()
	if l, err := net.Listen("tcp", net.JoinHostPort(hostIP, "0")); err != nil {
		t.Skipf("no %s loopback here: %v", fam, err)
	} else {
		_ = l.Close()
	}
	name := fmt.Sprintf("ep%s%d", fam, time.Now().UnixNano()%1_000_000)
	rt, err := newHost(host.Config{
		Templates:  map[string]string{"default": zygoteBin + " --heap-mb 16"},
		CgroupRoot: filepath.Join(cgRoot, name),
		RunDir:     filepath.Join("/tmp", "fz-"+name),
		DeltaDir:   t.TempDir(),
		Endpoints:  fiberendpoint.Policy{Family: fam, Host: hostIP, PortMin: lo, PortMax: hi},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rt.(interface{ Close() }).Close() })
	return rt
}

// TestTCPEndpoints: with an inet family declared, fibers serve on the
// declared address with a port each, callers dial the URL as given, a
// parked fiber resumes on the port it held, and released ports return
// to the range.
func TestTCPEndpoints(t *testing.T) {
	cases := []struct {
		fam  fiberendpoint.Family
		host string
	}{{fiberendpoint.Inet4, "127.0.0.1"}, {fiberendpoint.Inet6, "::1"}}
	for _, c := range cases {
		t.Run(string(c.fam), func(t *testing.T) {
			lo, hi := 41000, 41003
			rt := tcpRuntime(t, c.fam, c.host, lo, hi)
			ctx := context.Background()
			g := core.Grant{UID: "ep-" + string(c.fam), TemplateDigest: "sha256:ref", FiberMax: 8, WBudgetBytes: 32 << 20}
			if err := rt.PrepareTemplate(ctx, g); err != nil {
				t.Fatal(err)
			}
			fence := func(seq uint64) core.Fence { return core.Fence{GrantUID: g.UID, Epoch: 1, Seq: seq} }
			h1, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: fence(1), Deadline: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			e1, err := fiberendpoint.Parse(h1.Endpoint)
			if err != nil || e1.Scheme != "tcp" || e1.Host != c.host || e1.Port < lo || e1.Port > hi {
				t.Fatalf("endpoint %q parsed as %+v (%v), want tcp on %s in %d-%d", h1.Endpoint, e1, err, c.host, lo, hi)
			}
			if c.fam == fiberendpoint.Inet6 && !strings.Contains(h1.Endpoint, "[::1]") {
				t.Fatalf("IPv6 endpoint not bracketed: %s", h1.Endpoint)
			}
			if got := talk(t, h1.Endpoint, "ping"); got != "pong" {
				t.Fatalf("ping over %s = %q", h1.Endpoint, got)
			}
			h2, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: fence(2), Deadline: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			if h2.Endpoint == h1.Endpoint {
				t.Fatalf("two fibers on one endpoint: %s", h1.Endpoint)
			}
			talk(t, h1.Endpoint, "incr")
			talk(t, h1.Endpoint, "incr")

			// Park keeps the port for the restored listener.
			ref, err := rt.Park(ctx, h1.ID, true)
			if err != nil {
				t.Fatalf("park: %v", err)
			}
			if _, err := fiberendpoint.Dial(ctx, h1.Endpoint); err == nil {
				t.Fatal("parked endpoint still accepts connections")
			}
			h3, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Source: core.SourceDelta, Ref: ref, Fence: fence(3), Deadline: 5 * time.Second})
			if err != nil {
				t.Fatalf("resume: %v", err)
			}
			if h3.Endpoint != h1.Endpoint {
				t.Fatalf("resumed on %s, want the parked endpoint %s", h3.Endpoint, h1.Endpoint)
			}
			if got := talk(t, h3.Endpoint, "get"); got != "2" {
				t.Fatalf("counter after resume over tcp = %q, want 2", got)
			}

			// The range is the ceiling: four ports, two in use, two more
			// fit, a fifth fiber does not.
			var extra []core.FiberHandle
			for seq := uint64(4); seq <= 5; seq++ {
				h, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: fence(seq), Deadline: time.Second})
				if err != nil {
					t.Fatalf("clone %d: %v", seq, err)
				}
				extra = append(extra, h)
			}
			if _, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: fence(6), Deadline: time.Second}); err == nil || !strings.Contains(err.Error(), "no free endpoint port") {
				t.Fatalf("fifth fiber on a four-port range: err = %v, want no free port", err)
			}
			// Releasing one frees its port for the next.
			if err := rt.Release(ctx, extra[0].ID, false); err != nil {
				t.Fatal(err)
			}
			h6, err := rt.Clone(ctx, core.CloneSpec{Grant: g, Fence: fence(6), Deadline: time.Second})
			if err != nil {
				t.Fatalf("clone after release: %v", err)
			}
			if h6.Endpoint != extra[0].Endpoint {
				t.Fatalf("freed port not reused: got %s, freed %s", h6.Endpoint, extra[0].Endpoint)
			}
			for _, h := range []core.FiberHandle{h2, h3, extra[1], h6} {
				_ = rt.Release(ctx, h.ID, true)
			}
		})
	}
}

// unixOnly is a backend that does not say it can serve tcp endpoints.
type unixOnly struct{}

func (unixOnly) Name() string    { return "unixonly" }
func (unixOnly) Tier() core.Tier { return core.TierWarm }
func (unixOnly) Warm(context.Context, backend.WarmSpec) (backend.Warm, error) {
	return backend.Warm{}, backend.ErrUnsupported
}
func (unixOnly) Unwarm(string) {}
func (unixOnly) Clone(context.Context, string, backend.FiberSpec) (backend.Fiber, error) {
	return backend.Fiber{}, backend.ErrUnsupported
}
func (unixOnly) Park(context.Context, string, backend.ParkSpec) error { return backend.ErrUnsupported }
func (unixOnly) Resume(context.Context, backend.ResumeSpec) (backend.Fiber, error) {
	return backend.Fiber{}, backend.ErrUnsupported
}
func (unixOnly) Kill(string) error          { return nil }
func (unixOnly) Exits() <-chan backend.Exit { return nil }
func (unixOnly) Close()                     {}

// TestEndpointPolicyRefusedByBackend: a backend that only serves unix
// sockets is refused a tcp family at open, never at the first Clone.
func TestEndpointPolicyRefusedByBackend(t *testing.T) {
	_, err := host.New(host.Config{
		Backend:    unixOnly{},
		Templates:  map[string]string{"default": zygoteBin},
		CgroupRoot: filepath.Join(cgRoot, fmt.Sprintf("ep-refuse%d", time.Now().UnixNano()%1_000_000)),
		RunDir:     "/tmp/fz-ep-refuse",
		Endpoints:  fiberendpoint.Policy{Family: fiberendpoint.Inet4, Host: "127.0.0.1"},
	})
	if err == nil || !strings.Contains(err.Error(), "cannot serve tcp") {
		t.Fatalf("err = %v, want a refusal of tcp endpoints", err)
	}
}
