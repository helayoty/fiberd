package consumer_test

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/helayoty/fiberd/pkg/consumer"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/rpc"
	"github.com/helayoty/fiberd/pkg/runtime/stub"
	"github.com/helayoty/fiberd/pkg/tlsconf"
	"github.com/helayoty/fiberd/pkg/tlsconf/tlsconftest"
)

// boundVerifier is the insecure JSON verifier with every grant bound to
// one caller certificate, as a signed grant with a cnf claim would be.
type boundVerifier struct{ thumbprint string }

func (v boundVerifier) Verify(ctx context.Context, token []byte) (core.Grant, error) {
	g, err := grant.InsecureJSONVerifier{}.Verify(ctx, token)
	g.CallerThumbprint = v.thumbprint
	return g, err
}

// tcpHome serves a home on a free loopback port, in plaintext when cfg is
// nil. It returns the address and the server, which the test may stop.
func tcpHome(t *testing.T, verify core.Verifier, cfg *tls.Config) (string, *grpc.Server) {
	t.Helper()
	ag := &core.Agent{
		NodeID: "node-a", Ledger: core.NewLedger(1), Budget: core.NewBudget(1000, 256<<20),
		Runtime: stub.New(), Verify: verify,
		Health: core.NewSourceHealth(10*time.Second, time.Now()), StatusInterval: 20 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go ag.Run(ctx)
	var opts []grpc.ServerOption
	if cfg != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(cfg)))
	}
	gs := rpc.NewGRPCServer(&rpc.Server{Agent: ag, Issuer: "https://issuer.test"}, opts...)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	return lis.Addr().String(), gs
}

// Dial reaches a plaintext home. DialTLS reaches a mutual-TLS home, and
// the certificate it presents is the caller a bound grant must name.
func TestDial(t *testing.T) {
	ca := tlsconftest.NewCA(t, "ca")
	owner, other := ca.Client(t, "owner"), ca.Client(t, "other")
	plainAddr, _ := tcpHome(t, grant.InsecureJSONVerifier{}, nil)
	tlsAddr, _ := tcpHome(t, boundVerifier{thumbprint: tlsconf.Thumbprint(owner.Cert)}, &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{ca.Server(t).TLS()},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ca.Pool(),
	})
	clientCfg := func(p tlsconftest.Pair) *tls.Config {
		return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: ca.Pool(), ServerName: "localhost", Certificates: []tls.Certificate{p.TLS()}}
	}
	g := jsonGrant(t, core.Grant{UID: "g1", Audience: "node-a", FiberMax: 4})

	cases := []struct {
		name     string
		dial     func(ctx context.Context) (*consumer.Client, error)
		wantDial string // substring of a dial error
		wantCode codes.Code
	}{
		{name: "plaintext dial clones", dial: func(ctx context.Context) (*consumer.Client, error) { return consumer.Dial(ctx, plainAddr) }},
		{name: "the bound caller clones over mutual TLS",
			dial: func(ctx context.Context) (*consumer.Client, error) {
				return consumer.DialTLS(ctx, tlsAddr, clientCfg(owner))
			}},
		{name: "another caller over mutual TLS is Unauthenticated",
			dial: func(ctx context.Context) (*consumer.Client, error) {
				return consumer.DialTLS(ctx, tlsAddr, clientCfg(other))
			},
			wantCode: codes.Unauthenticated},
		{name: "plaintext to a TLS home fails the call", dial: func(ctx context.Context) (*consumer.Client, error) { return consumer.Dial(ctx, tlsAddr) },
			wantCode: codes.Unavailable},
		{name: "a target that is not a URL fails to dial", dial: func(ctx context.Context) (*consumer.Client, error) { return consumer.Dial(ctx, "%zz") },
			wantDial: "invalid URL escape"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			c, err := tc.dial(ctx)
			if tc.wantDial != "" {
				if err == nil || c != nil || !strings.Contains(err.Error(), tc.wantDial) {
					t.Fatalf("dial = %v, %v, want an error containing %q", c, err, tc.wantDial)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			f, err := c.Clone(ctx, g, "", 0, nil)
			if status.Code(err) != tc.wantCode {
				t.Fatalf("clone = %+v, %v, want %v", f, err, tc.wantCode)
			}
			if err == nil && (f.ID == "" || f.Fence.GrantUID != "g1") {
				t.Fatalf("clone = %+v, want a fiber of g1", f)
			}
		})
	}
}

// Watch returns nil when its own context ends, and the stream's error
// when the home goes away or the client is already closed.
func TestWatchEnds(t *testing.T) {
	cases := []struct {
		name    string
		end     func(cancel context.CancelFunc, gs *grpc.Server)
		closed  bool // close the client before watching
		wantErr codes.Code
	}{
		{name: "the caller cancelling is a clean end", end: func(cancel context.CancelFunc, _ *grpc.Server) { cancel() }},
		{name: "the home stopping is an error", end: func(_ context.CancelFunc, gs *grpc.Server) { gs.Stop() }, wantErr: codes.Unavailable},
		{name: "a closed client cannot watch", closed: true, wantErr: codes.Canceled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, gs := tcpHome(t, grant.InsecureJSONVerifier{}, nil)
			c, err := consumer.Dial(context.Background(), addr)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := c.Clone(ctx, jsonGrant(t, core.Grant{UID: "g1", Audience: "node-a"}), "", 0, nil); err != nil {
				t.Fatal(err)
			}
			if tc.closed {
				_ = c.Close()
			} else {
				t.Cleanup(func() { _ = c.Close() })
			}
			watchCtx, stop := context.WithCancel(ctx)
			defer stop()
			seen := make(chan struct{}, 1)
			done := make(chan error, 1)
			go func() {
				done <- c.Watch(watchCtx, func(consumer.Status) {
					select {
					case seen <- struct{}{}:
					default:
					}
				})
			}()
			if !tc.closed {
				select {
				case <-seen:
				case <-ctx.Done():
					t.Fatal("no status before ending the watch")
				}
				tc.end(stop, gs)
			}
			select {
			case err := <-done:
				if tc.wantErr == codes.OK && err != nil || tc.wantErr != codes.OK && status.Code(err) != tc.wantErr {
					t.Fatalf("Watch = %v, want %v", err, tc.wantErr)
				}
			case <-ctx.Done():
				t.Fatal("Watch did not return")
			}
		})
	}
}

// The typed errors and the fence read as a log line should.
func TestText(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{name: "shed says when to retry", got: (&consumer.Shed{RetryAfter: 2 * time.Second}).Error(),
			want: "shed: control plane unreachable, retry after 2s"},
		{name: "deferred says why", got: (&consumer.Deferred{Reason: "grant full"}).Error(), want: "deferred: grant full"},
		{name: "deferred names where the session lives", got: (&consumer.Deferred{Reason: "too large", PreferredHome: "home-b"}).Error(),
			want: "deferred: too large (session lives on home-b)"},
		{name: "a tier gap says why", got: (&consumer.TierGap{Reason: "needs CHECKPOINT"}).Error(), want: "tier gap: needs CHECKPOINT"},
		{name: "a fence is grant, epoch and seq", got: consumer.Fence{GrantUID: "g1", Epoch: 3, Seq: 7}.String(), want: "g1/3/7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("text = %q, want %q", tc.got, tc.want)
			}
		})
	}
}
