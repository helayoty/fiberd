package rpc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"net"
	"testing"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/Azure/fiberd/pkg/tlsconf"
	"github.com/Azure/fiberd/pkg/tlsconf/tlsconftest"
)

var (
	// callerSink keeps each caller reachable so the compiler keeps the work.
	callerSink tlsconf.Caller

	errNoBenchCaller = errors.New("the handler saw no caller")
)

// BenchmarkCallerInterceptor is the work a unary call does to get its
// caller before the handler runs. "certificate hash" names the caller by
// a hash of its whole certificate and is the baseline. "key thumbprint per
// request" names it from its key on every call, and "per connection" reads
// the name its handshake stored.
//
//	go test -run '^$' -bench 'BenchmarkCallerInterceptor' -benchmem -count 6 ./pkg/rpc/
func BenchmarkCallerInterceptor(b *testing.B) {
	ca := tlsconftest.NewCA(b, "ca")
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	client := func() *x509.Certificate {
		return &x509.Certificate{Subject: pkix.Name{CommonName: "bench"},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	}
	cases := []struct {
		keyType string
		leaf    *x509.Certificate
	}{
		{keyType: "Ed25519", leaf: ca.IssueCert(b, client(), edPub)},
		{keyType: "ECDSA P-256", leaf: ca.Client(b, "p256").Cert},
		{keyType: "RSA 2048", leaf: ca.IssueCert(b, client(), &rsaKey.PublicKey)},
	}
	intercept := CallerInterceptor()
	handler := func(ctx context.Context, _ any) (any, error) {
		c, ok := CallerFrom(ctx)
		if !ok {
			return nil, errNoBenchCaller
		}
		callerSink = c
		return nil, nil
	}
	for _, tc := range cases {
		chain := []*x509.Certificate{tc.leaf}
		bare := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{},
			AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: chain}}})
		named := handshakeCtx(tlsconf.CallerOf, chain)
		b.Run(tc.keyType, func(b *testing.B) {
			b.Run("certificate hash", func(b *testing.B) {
				b.ReportAllocs()
				base := context.Background()
				for b.Loop() {
					sum := sha256.Sum256(tc.leaf.Raw)
					ctx := WithCaller(base, tlsconf.Caller{Thumbprint: base64.RawURLEncoding.EncodeToString(sum[:]), Cert: tc.leaf.Raw})
					c, ok := CallerFrom(ctx)
					if !ok {
						b.Fatal(errNoBenchCaller)
					}
					callerSink = c
				}
			})
			for _, run := range []struct {
				name string
				ctx  context.Context
			}{
				{name: "key thumbprint per request", ctx: bare},
				{name: "per connection", ctx: named},
			} {
				b.Run(run.name, func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						if _, err := intercept(run.ctx, nil, nil, handler); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}
