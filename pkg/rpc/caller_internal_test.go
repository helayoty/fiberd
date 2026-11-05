package rpc

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	grantv1 "github.com/Azure/fiberd/api/grant/v1"
	"github.com/Azure/fiberd/pkg/tlsconf"
	"github.com/Azure/fiberd/pkg/tlsconf/tlsconftest"
)

// counted is tlsconf.CallerOf with a count of its calls.
func counted() (namer, *atomic.Int32) {
	n := new(atomic.Int32)
	return func(chain []*x509.Certificate) (tlsconf.Caller, bool) {
		n.Add(1)
		return tlsconf.CallerOf(chain)
	}, n
}

// outcome is what one request on a connection came to.
type outcome struct {
	caller  string // the thumbprint the handler saw, "" for none
	served  bool   // the handler ran
	refused bool   // Unauthenticated on gRPC, 401 on the gateway
}

func (o *outcome) see(ctx context.Context) {
	o.served = true
	c, _ := CallerFrom(ctx)
	o.caller = c.Thumbprint
}

// handshakeCtx is the context of a call on a connection the server
// credentials accepted from a peer that presented certs.
func handshakeCtx(name namer, certs []*x509.Certificate) context.Context {
	info := newServerCreds(&tls.Config{MinVersion: tls.VersionTLS13}, name).
		authInfo(credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: certs}})
	return peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{}, AuthInfo: info})
}

// unaryConn, streamConn and gatewayConn are each one accepted connection
// whose peer presented certs. The result sends one request on it.
func unaryConn(name namer, certs []*x509.Certificate) func() outcome {
	ctx := handshakeCtx(name, certs)
	return func() outcome {
		var out outcome
		_, err := CallerInterceptor()(ctx, nil, nil, func(ctx context.Context, _ any) (any, error) {
			out.see(ctx)
			return nil, nil
		})
		out.refused = status.Code(err) == codes.Unauthenticated
		return out
	}
}

func streamConn(name namer, certs []*x509.Certificate) func() outcome {
	ctx := handshakeCtx(name, certs)
	return func() outcome {
		var out outcome
		err := CallerStreamInterceptor()(nil, callerStream{ctx: ctx}, nil, func(_ any, ss grpc.ServerStream) error {
			out.see(ss.Context())
			return nil
		})
		out.refused = status.Code(err) == codes.Unauthenticated
		return out
	}
}

func gatewayConn(name namer, certs []*x509.Certificate) func() outcome {
	ctx := withConnPeer(context.Background(), name)
	return func() outcome {
		var out outcome
		req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
		req.TLS = &tls.ConnectionState{PeerCertificates: certs}
		rec := httptest.NewRecorder()
		(&Gateway{}).httpCaller(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			out.see(r.Context())
		})).ServeHTTP(rec, req)
		out.refused = rec.Code == http.StatusUnauthorized
		return out
	}
}

// A connection's peer is named once, when the connection is set up, and
// every request on it reads that name. A peer that presented a certificate
// and has no name is refused on each request. Served without a caller it
// would pass for plaintext and see every grant.
func TestConnectionNameIsReadByEveryRequest(t *testing.T) {
	ca := tlsconftest.NewCA(t, "ca")
	leaf := ca.Client(t, "c")
	conns := []struct {
		name string
		open func(name namer, certs []*x509.Certificate) func() outcome
	}{
		{name: "unary", open: unaryConn},
		{name: "stream", open: streamConn},
		{name: "gateway", open: gatewayConn},
	}
	cases := []struct {
		name        string
		certs       []*x509.Certificate
		want        string // thumbprint, "" for no caller
		wantRefused bool
	}{
		{name: "a peer with a certificate is the caller of every request",
			certs: []*x509.Certificate{leaf.Cert}, want: leaf.Thumbprint(t)},
		{name: "a connection whose peer cannot be named is refused and never served as plaintext",
			certs: []*x509.Certificate{ca.UnnamedClient(t).Cert}, wantRefused: true},
		{name: "a TLS peer without a certificate has no caller"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, c := range conns {
				t.Run(c.name, func(t *testing.T) {
					name, named := counted()
					request := c.open(name, tc.certs)
					want := outcome{caller: tc.want, served: !tc.wantRefused, refused: tc.wantRefused}
					for i := range 3 {
						if got := request(); got != want {
							t.Fatalf("request %d = %+v, want %+v", i, got, want)
						}
					}
					if n := named.Load(); n != 1 {
						t.Fatalf("peer named %d times, want once", n)
					}
				})
			}
		})
	}
}

// HTTP/2 serves the requests of one connection concurrently. However many
// of them arrive first, the peer is named once and each of them reads that
// name.
func TestGatewayHolderIsFilledOnce(t *testing.T) {
	ca := tlsconftest.NewCA(t, "ca")
	leaf := ca.Client(t, "c")
	const requests = 64
	cases := []struct {
		name  string
		certs []*x509.Certificate
		// wantPanics is how many requests the naming panics under. Such a
		// request gets no answer.
		wantPanics int
		want       outcome // of every request that got an answer
	}{
		{name: "the gateway holder is filled once under concurrent first requests",
			certs: []*x509.Certificate{leaf.Cert}, want: outcome{caller: leaf.Thumbprint(t), served: true}},
		{name: "a peer that cannot be named is refused by every first request",
			certs: []*x509.Certificate{ca.UnnamedClient(t).Cert}, want: outcome{refused: true}},
		{name: "a naming that panics leaves the connection refused",
			certs: []*x509.Certificate{leaf.Cert}, wantPanics: 1, want: outcome{refused: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name, named := counted()
			if tc.wantPanics > 0 {
				count := name
				name = func(chain []*x509.Certificate) (tlsconf.Caller, bool) {
					count(chain)
					panic("naming failed")
				}
			}
			request := gatewayConn(name, tc.certs)
			var (
				wg       sync.WaitGroup
				start    = make(chan struct{})
				got      [requests]outcome
				panicked atomic.Int32
			)
			for i := range requests {
				wg.Go(func() {
					defer func() {
						if recover() != nil {
							panicked.Add(1)
						}
					}()
					<-start
					got[i] = request()
				})
			}
			close(start)
			wg.Wait()

			unanswered := 0
			for i, o := range got {
				switch o {
				case tc.want:
				case outcome{}:
					unanswered++
				default:
					t.Fatalf("request %d = %+v, want %+v", i, o, tc.want)
				}
			}
			if n := int(panicked.Load()); n != tc.wantPanics || unanswered != tc.wantPanics {
				t.Fatalf("%d requests panicked and %d got no answer, want %d", n, unanswered, tc.wantPanics)
			}
			if n := named.Load(); n != 1 {
				t.Fatalf("peer named %d times under %d first requests, want once", n, requests)
			}
		})
	}
}

// callerEcho is a Fibers service whose Clone answers with the thumbprint
// of the caller it was handed, as the fiber id.
type callerEcho struct {
	grantv1.UnimplementedFibersServer
}

func (callerEcho) Clone(ctx context.Context, _ *grantv1.CloneRequest) (*grantv1.CloneResponse, error) {
	c, _ := CallerFrom(ctx)
	return &grantv1.CloneResponse{FiberId: c.Thumbprint}, nil
}

func serverTLS(t *testing.T, ca tlsconftest.Pair) *tls.Config {
	t.Helper()
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{ca.Server(t).TLS()},
		ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: ca.Pool()}
}

func clientTLS(ca tlsconftest.Pair, cert *tlsconftest.Pair) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: ca.Pool(), ServerName: "localhost"}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{cert.TLS()}
	}
	return cfg
}

// A dialFunc opens one connection to a served face as cert, or without a
// certificate for nil. Its result sends one request on that connection and
// reports the thumbprint of the caller the handler saw.
type dialFunc func(t *testing.T, cert *tlsconftest.Pair) func(context.Context) (string, error)

// serveGRPC serves callerEcho on loopback behind the caller interceptor,
// with name naming the peers of its TLS connections.
func serveGRPC(t *testing.T, ca tlsconftest.Pair, secure bool, name namer) dialFunc {
	t.Helper()
	opts := []grpc.ServerOption{grpc.ChainUnaryInterceptor(CallerInterceptor())}
	if secure {
		opts = append(opts, grpc.Creds(newServerCreds(serverTLS(t, ca), name)))
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(opts...)
	grantv1.RegisterFibersServer(gs, callerEcho{})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	return func(t *testing.T, cert *tlsconftest.Pair) func(context.Context) (string, error) {
		t.Helper()
		creds := insecure.NewCredentials()
		if secure {
			creds = credentials.NewTLS(clientTLS(ca, cert))
		}
		conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(creds))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		client := grantv1.NewFibersClient(conn)
		return func(ctx context.Context) (string, error) {
			resp, err := client.Clone(ctx, &grantv1.CloneRequest{})
			return resp.GetFiberId(), err
		}
	}
}

// serveGateway serves the gateway's caller middleware on loopback with the
// connection hook wired, over HTTP/2 for h2 and HTTP/1.1 otherwise.
func serveGateway(h2 bool) func(t *testing.T, ca tlsconftest.Pair, secure bool, name namer) dialFunc {
	major := 1
	if h2 {
		major = 2
	}
	return func(t *testing.T, ca tlsconftest.Pair, secure bool, name namer) dialFunc {
		t.Helper()
		echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, _ := CallerFrom(r.Context())
			_, _ = io.WriteString(w, c.Thumbprint)
		})
		srv := httptest.NewUnstartedServer((&Gateway{}).httpCaller(echo))
		srv.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
			return withConnPeer(ctx, name)
		}
		srv.EnableHTTP2 = h2
		if secure {
			srv.TLS = serverTLS(t, ca)
			srv.StartTLS()
		} else {
			srv.Start()
		}
		t.Cleanup(srv.Close)
		return func(t *testing.T, cert *tlsconftest.Pair) func(context.Context) (string, error) {
			t.Helper()
			tr := &http.Transport{ForceAttemptHTTP2: h2}
			if secure {
				tr.TLSClientConfig = clientTLS(ca, cert)
			}
			t.Cleanup(tr.CloseIdleConnections)
			client := &http.Client{Transport: tr}
			return func(ctx context.Context) (string, error) {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
				if err != nil {
					return "", err
				}
				resp, err := client.Do(req)
				if err != nil {
					return "", err
				}
				defer func() { _ = resp.Body.Close() }()
				// Read to the end, so the connection is kept for the next
				// request.
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return "", err
				}
				if resp.StatusCode != http.StatusOK || resp.ProtoMajor != major {
					return "", fmt.Errorf("GET = %s over %s, want 200 over HTTP/%d", resp.Status, resp.Proto, major)
				}
				return string(body), nil
			}
		}
	}
}

// Over real connections a peer is named once per connection, however many
// requests the connection carries, on gRPC and on the JSON gateway alike.
// The name follows the key of the certificate each connection presented.
func TestCallerIsNamedOncePerConnection(t *testing.T) {
	ca := tlsconftest.NewCA(t, "ca")
	owner, other := ca.Client(t, "owner"), ca.Client(t, "other")
	ownerTP, otherTP := owner.Thumbprint(t), other.Thumbprint(t)
	const requests = 8
	faces := []struct {
		name     string
		needsTLS bool
		serve    func(t *testing.T, ca tlsconftest.Pair, secure bool, name namer) dialFunc
	}{
		{name: "grpc", serve: serveGRPC},
		{name: "gateway", serve: serveGateway(false)},
		{name: "gateway over h2", needsTLS: true, serve: serveGateway(true)},
	}
	cases := []struct {
		name      string
		plaintext bool
		conns     []*tlsconftest.Pair // one connection each, nil presents no certificate
		want      []string            // the caller's thumbprint per connection, "" for none
		wantNamed int32
	}{
		{name: "the caller is named once for many requests on one connection",
			conns: []*tlsconftest.Pair{&owner}, want: []string{ownerTP}, wantNamed: 1},
		{name: "two connections with the same certificate name the same caller",
			conns: []*tlsconftest.Pair{&owner, &owner}, want: []string{ownerTP, ownerTP}, wantNamed: 2},
		{name: "a second connection with another key names another caller",
			conns: []*tlsconftest.Pair{&owner, &other}, want: []string{ownerTP, otherTP}, wantNamed: 2},
		{name: "a TLS connection without a certificate has no caller",
			conns: []*tlsconftest.Pair{nil}, want: []string{""}, wantNamed: 1},
		{name: "a plaintext connection has no caller", plaintext: true,
			conns: []*tlsconftest.Pair{nil}, want: []string{""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, f := range faces {
				// The gateway negotiates HTTP/2 in the TLS handshake.
				if tc.plaintext && f.needsTLS {
					continue
				}
				t.Run(f.name, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					name, named := counted()
					dial := f.serve(t, ca, !tc.plaintext, name)
					for i, cert := range tc.conns {
						call := dial(t, cert)
						for range requests {
							got, err := call(ctx)
							if err != nil {
								t.Fatalf("connection %d: %v", i, err)
							}
							if got != tc.want[i] {
								t.Fatalf("connection %d: caller = %q, want %q", i, got, tc.want[i])
							}
						}
					}
					if n := named.Load(); n != tc.wantNamed {
						t.Fatalf("peers named %d times over %d connections, want %d", n, len(tc.conns), tc.wantNamed)
					}
				})
			}
		})
	}
}

// The wrapper survives a clone, which the wrapped credentials would
// otherwise return bare. An auth info that is not TLS is handed on as it
// came.
func TestServerCredsAuthInfo(t *testing.T) {
	leaf := tlsconftest.NewCA(t, "ca").Client(t, "c")
	creds := newServerCreds(&tls.Config{MinVersion: tls.VersionTLS13}, tlsconf.CallerOf)
	handshake := credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf.Cert}}}
	_, plain, err := insecure.NewCredentials().ServerHandshake(nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		creds credentials.TransportCredentials
		in    credentials.AuthInfo
		want  string // the stored caller's thumbprint, "" when in passes through
	}{
		{name: "a TLS handshake stores the caller", creds: creds, in: handshake, want: leaf.Thumbprint(t)},
		{name: "a clone stores the caller too", creds: creds.Clone(), in: handshake, want: leaf.Thumbprint(t)},
		{name: "an auth info that is not TLS passes through", creds: creds, in: plain},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc, ok := tc.creds.(*serverCreds)
			if !ok {
				t.Fatalf("credentials are %T, want the naming wrapper", tc.creds)
			}
			if got := sc.Info().SecurityProtocol; got != "tls" {
				t.Fatalf("security protocol = %q, want tls", got)
			}
			out := sc.authInfo(tc.in)
			if tc.want == "" {
				if out != tc.in {
					t.Fatalf("auth info = %#v, want %#v untouched", out, tc.in)
				}
				return
			}
			info, ok := out.(*namedTLSInfo)
			if !ok {
				t.Fatalf("auth info is %T, want *namedTLSInfo", out)
			}
			if p := info.peer; !p.named || p.err != nil || p.caller.Thumbprint != tc.want {
				t.Fatalf("stored name = %+v, want caller %q", p, tc.want)
			}
		})
	}
}

// The auth info of a named connection still answers everything gRPC and
// its consumers ask of a TLS auth info.
func TestAuthInfoStillReadsAsTLS(t *testing.T) {
	leaf := tlsconftest.NewCA(t, "ca").Client(t, "c")
	info := newServerCreds(&tls.Config{MinVersion: tls.VersionTLS13}, tlsconf.CallerOf).authInfo(credentials.TLSInfo{
		State:          tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{leaf.Cert}},
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
	})
	cases := []struct {
		name  string
		check func() error
	}{
		{name: "its auth type is tls", check: func() error {
			if got := info.AuthType(); got != "tls" {
				return fmt.Errorf("AuthType() = %q", got)
			}
			return nil
		}},
		{name: "it reports the handshake's security level", check: func() error {
			leveled, ok := info.(interface {
				GetCommonAuthInfo() credentials.CommonAuthInfo
			})
			if !ok {
				return errors.New("no GetCommonAuthInfo")
			}
			if got := leveled.GetCommonAuthInfo().SecurityLevel; got != credentials.PrivacyAndIntegrity {
				return fmt.Errorf("security level = %v", got)
			}
			return nil
		}},
		{name: "channelz reads the peer certificate from it", check: func() error {
			cz, ok := info.(credentials.ChannelzSecurityInfo)
			if !ok {
				return errors.New("not a ChannelzSecurityInfo")
			}
			v, ok := cz.GetSecurityValue().(*credentials.TLSChannelzSecurityValue)
			if !ok || !bytes.Equal(v.RemoteCertificate, leaf.Cert.Raw) {
				return fmt.Errorf("GetSecurityValue() = %+v", cz.GetSecurityValue())
			}
			return nil
		}},
		{name: "it keeps the handshake's TLS state", check: func() error {
			tlsInfo, ok := info.(*namedTLSInfo)
			if !ok {
				return fmt.Errorf("auth info is %T, want *namedTLSInfo", info)
			}
			st := tlsInfo.State
			if st.Version != tls.VersionTLS13 || len(st.PeerCertificates) != 1 || st.PeerCertificates[0] != leaf.Cert {
				return fmt.Errorf("TLS state = %+v", st)
			}
			return nil
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.check(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
