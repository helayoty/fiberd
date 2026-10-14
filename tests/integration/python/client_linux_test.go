//go:build linux && integration

package pythontest

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/rpc"
	"github.com/helayoty/fiberd/pkg/tlsconf"
	"github.com/helayoty/fiberd/pkg/tlsconf/tlsconftest"
)

// pyHome is fiberd's core and gRPC face over the proc backend with the
// Python reference template, what cmd/fiberd wires, served to the Python
// client on one address.
type pyHome struct {
	health *core.SourceHealth
	addr   string
	// tls holds the PEM files a dial_tls caller presents, nil in plaintext.
	tls map[string]string
}

// boundVerifier is the insecure JSON verifier with every grant bound to
// one caller certificate, as a signed grant with a cnf claim would be.
type boundVerifier struct{ thumbprint string }

func (v boundVerifier) Verify(ctx context.Context, token []byte) (core.Grant, error) {
	g, err := grant.InsecureJSONVerifier{}.Verify(ctx, token)
	g.CallerThumbprint = v.thumbprint
	return g, err
}

// serveHome starts the home in plaintext on a unix socket, or over mutual
// TLS on loopback with the grant bound to the owner certificate it writes.
func serveHome(t *testing.T, withTLS bool) *pyHome {
	t.Helper()
	rt := openProc(t, backends[0].template)
	h := &pyHome{health: core.NewSourceHealth(10*time.Second, time.Now())}
	var verify core.Verifier = grant.InsecureJSONVerifier{}
	var opts []grpc.ServerOption
	var lis net.Listener
	var err error
	if withTLS {
		dir := t.TempDir()
		ca := tlsconftest.NewCA(t, "ca")
		owner := ca.Client(t, "owner")
		cert, key := owner.Write(t, dir, "owner")
		caFile, _ := ca.Write(t, dir, "ca")
		h.tls = map[string]string{"cert": cert, "key": key, "ca": caFile}
		verify = boundVerifier{thumbprint: tlsconf.Thumbprint(owner.Cert)}
		opts = append(opts, grpc.Creds(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{ca.Server(t).TLS()},
			ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ca.Pool(),
		})))
		lis, err = net.Listen("tcp", "127.0.0.1:0")
		h.addr = ""
	} else {
		// Not t.TempDir(), whose path carries the test's name, since gRPC
		// splits a unix: target on commas.
		var dir string
		if dir, err = os.MkdirTemp("", "fzpyc"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		sock := filepath.Join(dir, "api.sock")
		lis, err = net.Listen("unix", sock)
		h.addr = "unix:" + sock
	}
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if h.addr == "" {
		h.addr = lis.Addr().String()
	}
	ag := &core.Core{
		NodeID: "node-a", Ledger: core.NewLedger(1), RateLimit: core.NewRateLimit(1000, 256<<20),
		Runtime: rt, Verify: verify, Health: h.health, StatusInterval: 50 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	go ag.Run(ctx)
	gs := rpc.NewGRPCServer(&rpc.Server{Core: ag, Issuer: "https://issuer.test", RetryAfter: 2 * time.Second}, opts...)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(func() {
		gs.Stop()
		cancel()
	})
	return h
}

// trusted marks g TRUSTED, since the proc backend does not isolate
// tenants and refuses an untrusted grant with a tier gap.
func trusted(g core.Grant) core.Grant {
	g.Policy.Isolation = core.Trusted
	return g
}

// step is one JSON line the Python caller prints.
type step struct {
	Step, ID, Kind, Session, Home, Reply, Type, Reason, Issuer, Latest string
	PreferredHome                                                      string `json:"preferred_home"`
	GrantUID                                                           string `json:"grant_uid"`
	Seq, Running                                                       uint64
	RetryAfter                                                         float64 `json:"retry_after"`
}

// runClient runs testdata/client.py for one scenario against h and
// returns its steps. The grant goes in on stdin, never on argv.
func runClient(t *testing.T, h *pyHome, scenario string, g core.Grant, session string) []step {
	t.Helper()
	token, err := protojson.Marshal(grant.ToProto(g))
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := json.Marshal(map[string]any{"addr": h.addr, "grant": string(token), "session": session, "tls": h.tls})
	cmd := exec.Command(python, filepath.Join(testdata, "client.py"), scenario)
	cmd.Stdin = bytes.NewReader(cfg)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	outb, err := cmd.Output()
	if err != nil {
		t.Fatalf("client.py %s: %v\n%s%s", scenario, err, outb, stderr.String())
	}
	var steps []step
	for _, line := range strings.Split(strings.TrimSpace(string(outb)), "\n") {
		var s step
		if err := json.Unmarshal([]byte(line), &s); err != nil {
			t.Fatalf("client.py %s printed %q: %v", scenario, line, err)
		}
		steps = append(steps, s)
	}
	return steps
}

// requireClient skips when the dev image lacks the client extra.
func requireClient(t *testing.T) {
	t.Helper()
	if out, err := exec.Command(python, "-c", "import grpc, google.protobuf").CombinedOutput(); err != nil {
		t.Skipf("fiberd.client needs grpcio and protobuf: %v\n%s", err, out)
	}
}

// TestClientLifecycle pins that a caller written with fiberd.client
// runs a session's whole life against a real home. It clones, dials the
// fiber and talks to it, parks, resumes under the next fence, releases,
// and finds the released fiber gone. Over mutual TLS the caller is the
// one the grant is bound to.
func TestClientLifecycle(t *testing.T) {
	requireClient(t)
	cases := []struct {
		name string
		tls  bool
	}{
		{name: "in plaintext over a unix socket"},
		{name: "over mutual TLS as the bound caller", tls: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := serveHome(t, tc.tls)
			g := trusted(core.Grant{UID: "gpyc", Audience: "node-a", Tenant: "acme", TemplateDigest: "sha256:pyref", FiberMax: 2, WBudgetBytes: 64 << 20})
			steps := runClient(t, h, "lifecycle", g, "conv 42")
			want := []step{
				{Step: "clone", Kind: "CREATE", Seq: 1, Session: "conv 42", Home: h.addr},
				{Step: "ping", Reply: "pong"},
				{Step: "park"},
				{Step: "clone", Kind: "RESUME", Seq: 2, Session: "conv 42", Home: h.addr},
				{Step: "ping", Reply: "pong"},
				{Step: "release"},
				{Step: "notfound"},
			}
			if len(steps) != len(want) {
				t.Fatalf("steps = %+v, want %d", steps, len(want))
			}
			for i, w := range want {
				got := steps[i]
				if w.Step == "clone" && got.ID != fmt.Sprintf("gpyc/1/%d", w.Seq) {
					t.Errorf("step %d: id = %q, want the fence gpyc/1/%d", i, got.ID, w.Seq)
				}
				got.ID, got.Reason = "", ""
				if got != w {
					t.Errorf("step %d = %+v, want %+v", i, got, w)
				}
			}
		})
	}
}

// TestClientMisses pins that the home's misses reach a Python caller as
// the typed exceptions. A full grant is Deferred while the issuer is
// reachable and Shed with the home's retry once it is not, and a grant
// above the home's tier is a TierGap before any fiber is made.
func TestClientMisses(t *testing.T) {
	requireClient(t)
	cases := []struct {
		name       string
		scenario   string
		minTier    core.Tier
		issuerDown bool
		want       step
	}{
		{name: "a full grant with the issuer reachable is Deferred from the issuer", scenario: "miss",
			want: step{Step: "miss", Type: "Deferred", Issuer: "https://issuer.test"}},
		{name: "a full grant with the issuer unreachable is Shed with retry 2s", scenario: "miss", issuerDown: true,
			want: step{Step: "miss", Type: "Shed", Issuer: "https://issuer.test", RetryAfter: 2}},
		{name: "min_tier above the home is TierGap, not a miss", scenario: "tiergap", minTier: core.TierSnapshot,
			want: step{Step: "miss", Type: "TierGap"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := serveHome(t, false)
			if tc.issuerDown {
				h.health.MarkSync(time.Now().Add(-time.Hour))
			}
			g := trusted(core.Grant{UID: "gpym", Audience: "node-a", TemplateDigest: "sha256:pyref", FiberMax: 1, WBudgetBytes: 64 << 20, MinTier: tc.minTier})
			steps := runClient(t, h, tc.scenario, g, "")
			var got step
			for _, s := range steps {
				if s.Step == "miss" {
					got = s
				}
			}
			if got.Reason == "" {
				t.Fatalf("steps = %+v, want a miss with the home's reason", steps)
			}
			got.Reason, got.PreferredHome = "", ""
			if got != tc.want {
				t.Fatalf("miss = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestClientWatch pins that the Watch stream reaches a Python caller as
// Status records with the grant's running count and latest fence.
func TestClientWatch(t *testing.T) {
	requireClient(t)
	h := serveHome(t, false)
	g := trusted(core.Grant{UID: "gpyw", Audience: "node-a", TemplateDigest: "sha256:pyref", FiberMax: 2, WBudgetBytes: 64 << 20})
	steps := runClient(t, h, "watch", g, "")
	for _, s := range steps {
		if s.Step == "status" {
			if s.GrantUID != "gpyw" || s.Running != 1 || s.Latest != "gpyw/1/1" {
				t.Fatalf("status = %+v, want gpyw running 1 at gpyw/1/1", s)
			}
			return
		}
	}
	t.Fatalf("steps = %+v, want a status", steps)
}
