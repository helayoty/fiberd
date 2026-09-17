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
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/artifact"
	"github.com/helayoty/fiberd/pkg/core"
	fiberendpoint "github.com/helayoty/fiberd/pkg/endpoint"
	"github.com/helayoty/fiberd/pkg/runtime/host"
)

// httpTo sends one HTTP request to a fiber's endpoint (a unix socket or
// tcp URL) and returns the status and body.
func httpTo(t *testing.T, endpoint, method, path string) (int, string) {
	t.Helper()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return fiberendpoint.Dial(ctx, endpoint)
	}}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequest(method, "http://fiber"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b))
}

// An agent over a host runtime with a file delta registry of its own,
// warming the reference workload in HTTP mode.
func httpAgent(t *testing.T, home, registry string) (*core.Agent, host.Config, core.Grant) {
	t.Helper()
	cfg := host.Config{
		Templates:     map[string]string{"default": zygoteBin + " --heap-mb 8 --http"},
		CgroupRoot:    filepath.Join(cgRoot, home+fmt.Sprint(time.Now().UnixNano()%1_000_000)),
		RunDir:        filepath.Join("/tmp", "fz-"+home),
		DeltaDir:      t.TempDir(),
		TemplateCache: t.TempDir(),
		DeltaRegistry: registry,
		HomeID:        home,
	}
	rt, err := newHost(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if c, ok := rt.(interface{ Close() }); ok {
			c.Close()
		}
		_ = os.RemoveAll(cfg.RunDir)
	})
	g := core.Grant{UID: "x-" + home, Audience: home, TemplateDigest: "sha256:ref", FiberMax: 4, WBudgetBytes: 32 << 20, LeaseExpiry: time.Now().Add(time.Hour)}
	a := &core.Agent{NodeID: home, Ledger: core.NewLedger(1), Budget: core.NewBudget(1000, 1<<20),
		Runtime: rt, Audit: core.NopAuditor{}, Verify: tokenVerifier{"g": g},
		Health: core.NewSourceHealth(time.Minute, time.Now())}
	return a, cfg, g
}

// TestHTTPMode: the reference workload's --http framing serves the same
// counter over HTTP, and it survives a park and resume like the line
// protocol's.
func TestHTTPMode(t *testing.T) {
	ctx := context.Background()
	a, _, _ := httpAgent(t, "http-home", "")
	if a.Runtime.Tier() < core.TierCheckpoint {
		t.Skip("criu not usable here")
	}
	req := core.CloneRequest{GrantJWT: []byte("g"), Session: "web", Deadline: 5 * time.Second}
	r1, code, err := a.Clone(ctx, req)
	if err != nil || code != core.OK || r1.Kind != core.ActCreate {
		t.Fatalf("create: %v %d %v", err, code, r1.Kind)
	}
	if st, body := httpTo(t, r1.Endpoint, "GET", "/readyz"); st != 200 || body != "ok" {
		t.Fatalf("GET /readyz = %d %q", st, body)
	}
	httpTo(t, r1.Endpoint, "POST", "/incr")
	if st, body := httpTo(t, r1.Endpoint, "POST", "/"); st != 200 || body != "2" {
		t.Fatalf("POST / = %d %q, want 2", st, body)
	}
	if st, body := httpTo(t, r1.Endpoint, "GET", "/fence"); st != 200 || body != r1.FiberID {
		t.Fatalf("GET /fence = %d %q, want %s", st, body, r1.FiberID)
	}
	if st, body := httpTo(t, r1.Endpoint, "POST", "/dirty?bytes=1048576"); st != 200 || body != "ok 1048576" {
		t.Fatalf("POST /dirty = %d %q", st, body)
	}
	if st, _ := httpTo(t, r1.Endpoint, "GET", "/nothing"); st != 404 {
		t.Fatalf("GET /nothing = %d, want 404", st)
	}
	if _, code, err := a.Park(ctx, r1.FiberID, true); err != nil || code != core.OK {
		t.Fatalf("park: %v %d", err, code)
	}
	r2, code, err := a.Clone(ctx, req)
	if err != nil || code != core.OK || r2.Kind != core.ActResume {
		t.Fatalf("resume: %v %d %v", err, code, r2.Kind)
	}
	if st, body := httpTo(t, r2.Endpoint, "GET", "/count"); st != 200 || body != "2" {
		t.Fatalf("GET /count after resume = %d %q, want 2", st, body)
	}
	_, _ = a.Release(ctx, r2.FiberID, true)
}

// TestSessionExportImport: a session parked on home A leaves A as files
// (delta, parent, description), and arrives on home B under another
// name, where Clone resumes it with its state. Homes that share nothing
// but a way to move files, which is what a control plane with its own
// snapshot store gives fiberd.
func TestSessionExportImport(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	a, cfgA, gA := httpAgent(t, "exp-a", artifact.FileScheme+filepath.Join(root, "reg-a"))
	b, cfgB, gB := httpAgent(t, "exp-b", artifact.FileScheme+filepath.Join(root, "reg-b"))
	if b.Runtime.Tier() < core.TierCheckpoint {
		t.Skip("criu not usable here")
	}
	req := core.CloneRequest{GrantJWT: []byte("g"), Session: "S", Deadline: 5 * time.Second}

	r1, code, err := a.Clone(ctx, req)
	if err != nil || code != core.OK || r1.Kind != core.ActCreate {
		t.Fatalf("A create: %v %d %v", err, code, r1.Kind)
	}
	for i := 0; i < 3; i++ {
		httpTo(t, r1.Endpoint, "POST", "/incr")
	}
	if _, code, err := a.Park(ctx, r1.FiberID, true); err != nil || code != core.OK {
		t.Fatalf("A park: %v %d", err, code)
	}
	out := filepath.Join(root, "shipped")
	files, err := host.ExportDelta(ctx, cfgA, gA, "S", out)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	t.Logf("exported %v", files)
	var total int64
	for _, f := range files {
		st, err := os.Stat(filepath.Join(out, f))
		if err != nil {
			t.Fatal(err)
		}
		total += st.Size()
	}
	if len(files) != 3 {
		t.Fatalf("want delta, parent and info, got %v", files)
	}
	t.Logf("shipped %d bytes", total)

	// A no longer holds S: the same name is a fresh session there.
	r3, code, err := a.Clone(ctx, req)
	if err != nil || code != core.OK || r3.Kind != core.ActCreate {
		t.Fatalf("A after export: %v %d %v, want CREATE", err, code, r3.Kind)
	}
	if st, body := httpTo(t, r3.Endpoint, "GET", "/count"); st != 200 || body != "0" {
		t.Fatalf("A's fresh S count = %d %q", st, body)
	}
	_, _ = a.Release(ctx, r3.FiberID, true)

	// B imports it as S2 and resumes it there.
	if err := host.ImportDelta(ctx, cfgB, gB, "S2", out); err != nil {
		t.Fatalf("import: %v", err)
	}
	t0 := time.Now()
	r2, code, err := b.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g"), Session: "S2", Deadline: 5 * time.Second})
	if err != nil || code != core.OK {
		t.Fatalf("B clone: %v %d", err, code)
	}
	if r2.Kind != core.ActResume {
		t.Fatalf("B clone kind = %v, want RESUME", r2.Kind)
	}
	t.Logf("B resumed S2 in %s", time.Since(t0).Round(time.Millisecond))
	if st, body := httpTo(t, r2.Endpoint, "GET", "/count"); st != 200 || body != "3" {
		t.Fatalf("count on B = %d %q, want 3", st, body)
	}
	// The same shipped files imported under a third name: another
	// session from the same state (a template's golden state, many actors).
	if err := host.ImportDelta(ctx, cfgB, gB, "S3", out); err != nil {
		t.Fatalf("second import: %v", err)
	}
	r4, code, err := b.Clone(ctx, core.CloneRequest{GrantJWT: []byte("g"), Session: "S3", Deadline: 5 * time.Second})
	if err != nil || code != core.OK || r4.Kind != core.ActResume {
		t.Fatalf("B clone S3: %v %d %v", err, code, r4.Kind)
	}
	if st, body := httpTo(t, r4.Endpoint, "GET", "/count"); st != 200 || body != "3" {
		t.Fatalf("count of S3 on B = %d %q, want 3", st, body)
	}
	_, _ = b.Release(ctx, r2.FiberID, true)
	_, _ = b.Release(ctx, r4.FiberID, true)
}
