package tlsconf_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"testing"

	"github.com/Azure/fiberd/pkg/tlsconf"
	"github.com/Azure/fiberd/pkg/tlsconf/tlsconftest"
)

// benchSink keeps each result reachable so the compiler keeps the work.
var benchSink string

// BenchmarkThumbprint is what a connection pays once, at its handshake, to
// name its peer. "certificate hash" hashes the whole certificate and is
// the baseline. "key thumbprint" is the RFC 7638 thumbprint of the leaf's
// key, which names the caller.
//
//	go test -run '^$' -bench 'BenchmarkThumbprint' -benchmem -count 6 ./pkg/tlsconf/
func BenchmarkThumbprint(b *testing.B) {
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
	for _, tc := range cases {
		b.Run(tc.keyType, func(b *testing.B) {
			b.Run("certificate hash", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					sum := sha256.Sum256(tc.leaf.Raw)
					benchSink = base64.RawURLEncoding.EncodeToString(sum[:])
				}
			})
			b.Run("key thumbprint", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					tp, err := tlsconf.Thumbprint(tc.leaf)
					if err != nil {
						b.Fatal(err)
					}
					benchSink = tp
				}
			})
		})
	}
}
