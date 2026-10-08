package rpc_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/rpc"
	"github.com/helayoty/fiberd/pkg/tlsconf"
	"github.com/helayoty/fiberd/pkg/tlsconf/tlsconftest"
)

// fakeStream is a server stream that only knows its context.
type fakeStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s fakeStream) Context() context.Context { return s.ctx }

// plainAuth is the auth info of a peer on a non-TLS transport.
type plainAuth struct{}

func (plainAuth) AuthType() string { return "insecure" }

// Only a TLS peer with a certificate names a caller. Plaintext, a peer
// without TLS, and a TLS peer that sent no certificate leave the context
// without one. Unary and streaming calls agree.
func TestCallerInterceptors(t *testing.T) {
	leaf := tlsconftest.NewCA(t, "ca").Client(t, "c")
	withPeer := func(auth credentials.AuthInfo) context.Context {
		return peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{}, AuthInfo: auth})
	}
	cases := []struct {
		name string
		ctx  context.Context
		want string // thumbprint, "" for no caller
	}{
		{name: "no peer has no caller", ctx: context.Background()},
		{name: "a plaintext peer has no caller", ctx: withPeer(plainAuth{})},
		{name: "a peer without auth info has no caller", ctx: withPeer(nil)},
		{name: "a TLS peer without a certificate has no caller", ctx: withPeer(credentials.TLSInfo{})},
		{name: "a TLS peer with a certificate is the caller",
			ctx:  withPeer(credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf.Cert}}}),
			want: tlsconf.Thumbprint(leaf.Cert)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			check := func(via string, ctx context.Context) {
				c, ok := rpc.CallerFrom(ctx)
				if ok != (tc.want != "") || c.Thumbprint != tc.want {
					t.Fatalf("%s: caller = %+v, %v, want %q", via, c, ok, tc.want)
				}
			}
			_, err := rpc.CallerInterceptor()(tc.ctx, nil, nil, func(ctx context.Context, _ any) (any, error) {
				check("unary", ctx)
				return nil, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			err = rpc.CallerStreamInterceptor()(nil, fakeStream{ctx: tc.ctx}, nil, func(_ any, ss grpc.ServerStream) error {
				check("stream", ss.Context())
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Over a real mutual-TLS connection the certificate a caller presents is
// the identity the agent checks a bound grant against, on gRPC and on the
// JSON gateway alike.
func TestMutualTLSBindsGrantsToCallers(t *testing.T) {
	ca := tlsconftest.NewCA(t, "ca")
	owner, other := ca.Client(t, "owner"), ca.Client(t, "other")
	ownerX5t := tlsconf.Thumbprint(owner.Cert)
	h := newHarness(t, core.TierCheckpoint, func(a *core.Agent) { a.Verify = boundVerifier{thumbprint: ownerX5t} })
	scfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{ca.Server(t).TLS()},
		ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: ca.Pool()}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := rpc.NewGRPCServer(h.server, grpc.Creds(credentials.NewTLS(scfg)))
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	web := httptest.NewUnstartedServer((&rpc.Gateway{Server: h.server}).Handler())
	web.TLS = scfg
	web.StartTLS()
	t.Cleanup(web.Close)

	clientFor := func(t *testing.T, cert *tlsconftest.Pair) (grantv1.FibersClient, *tls.Config) {
		ccfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: ca.Pool(), ServerName: "localhost"}
		if cert != nil {
			ccfg.Certificates = []tls.Certificate{cert.TLS()}
		}
		conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(ccfg)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return grantv1.NewFibersClient(conn), ccfg
	}
	g := jsonGrant(t, core.Grant{UID: "g1", Audience: "node-a", FiberMax: 4})

	// The cases run in order. The owner's clone admits g1 for the rest.
	cases := []struct {
		name       string
		cert       *tlsconftest.Pair
		wantClone  codes.Code
		wantListed bool // the gateway shows g1 to this caller
	}{
		{name: "the bound caller clones and sees its grant", cert: &owner, wantClone: codes.OK, wantListed: true},
		{name: "another caller is refused and sees nothing", cert: &other, wantClone: codes.Unauthenticated},
		// Without a certificate there is no caller to bind, so the clone is
		// refused, and status is unfiltered as on plaintext.
		{name: "a TLS caller without a certificate is refused", wantClone: codes.Unauthenticated, wantListed: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			client, ccfg := clientFor(t, tc.cert)
			_, err := client.Clone(ctx, &grantv1.CloneRequest{GrantJwt: g})
			if status.Code(err) != tc.wantClone {
				t.Fatalf("clone = %v, want %v", err, tc.wantClone)
			}

			httpc := &http.Client{Transport: &http.Transport{TLSClientConfig: ccfg}}
			defer httpc.CloseIdleConnections()
			resp, err := httpc.Get(web.URL + "/v1/status")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			var sts []map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&sts); err != nil {
				t.Fatal(err)
			}
			if listed := len(sts) == 1 && sts[0]["grantUid"] == "g1"; listed != tc.wantListed {
				t.Fatalf("gateway status = %v, want g1 listed %v", sts, tc.wantListed)
			}
		})
	}
}
