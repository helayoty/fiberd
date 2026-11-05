package tlsconftest_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"slices"
	"testing"

	"github.com/Azure/fiberd/pkg/tlsconf"
	"github.com/Azure/fiberd/pkg/tlsconf/tlsconftest"
)

// Issued certificates verify against their CA for the use they were
// issued for, and survive a trip through PEM files.
func TestIssuedCertificatesVerify(t *testing.T) {
	ca := tlsconftest.NewCA(t, "ca")
	other := tlsconftest.NewCA(t, "other")
	cases := []struct {
		name    string
		leaf    tlsconftest.Pair
		roots   *x509.CertPool
		dns     string
		usage   x509.ExtKeyUsage
		wantErr bool
	}{
		{name: "a server certificate verifies for localhost", leaf: ca.Server(t), roots: ca.Pool(), dns: "localhost", usage: x509.ExtKeyUsageServerAuth},
		{name: "a server certificate verifies for 127.0.0.1", leaf: ca.Server(t), roots: ca.Pool(), dns: "127.0.0.1", usage: x509.ExtKeyUsageServerAuth},
		{name: "a client certificate verifies for client auth", leaf: ca.Client(t, "c"), roots: ca.Pool(), usage: x509.ExtKeyUsageClientAuth},
		{name: "a client certificate is not a server certificate", leaf: ca.Client(t, "c"), roots: ca.Pool(), usage: x509.ExtKeyUsageServerAuth, wantErr: true},
		{name: "another CA does not verify it", leaf: ca.Client(t, "c"), roots: other.Pool(), usage: x509.ExtKeyUsageClientAuth, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.leaf.Cert.Verify(x509.VerifyOptions{Roots: tc.roots, DNSName: tc.dns, KeyUsages: []x509.ExtKeyUsage{tc.usage}})
			if (err != nil) != tc.wantErr {
				t.Fatalf("Verify = %v, want error %v", err, tc.wantErr)
			}
			certFile, keyFile := tc.leaf.Write(t, t.TempDir(), "leaf")
			kp, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				t.Fatal(err)
			}
			if !kp.Leaf.Equal(tc.leaf.TLS().Leaf) {
				t.Fatal("the written pair does not load back as the same certificate")
			}
		})
	}
}

// A renewal is a new certificate over the leaf's key with the leaf's
// subject and usage, and IssueKey signs over the key it is given.
func TestIssueOverAKey(t *testing.T) {
	ca := tlsconftest.NewCA(t, "ca")
	client, server := ca.Client(t, "c"), ca.Server(t)
	given, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		got     tlsconftest.Pair
		wantKey *ecdsa.PrivateKey
		usage   x509.ExtKeyUsage
		renews  *x509.Certificate // a certificate whose serial got must not reuse
		keeps   *x509.Certificate // a certificate whose subject and names got must keep
	}{
		{name: "a renewal keeps the key and gets a new serial", got: ca.Renew(t, client), wantKey: client.Key,
			usage: x509.ExtKeyUsageClientAuth, renews: client.Cert},
		{name: "a renewal keeps the subject, names and usage", got: ca.Renew(t, server), wantKey: server.Key,
			usage: x509.ExtKeyUsageServerAuth, keeps: server.Cert},
		{name: "IssueKey over a given key carries that key", wantKey: given, usage: x509.ExtKeyUsageClientAuth,
			got: ca.IssueKey(t, &x509.Certificate{Subject: pkix.Name{CommonName: "k"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, given)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.got.Cert
			pub, ok := got.PublicKey.(*ecdsa.PublicKey)
			if tc.got.Key != tc.wantKey || !ok || !pub.Equal(&tc.wantKey.PublicKey) {
				t.Fatal("the certificate is not over the wanted key")
			}
			if _, err := got.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{tc.usage}}); err != nil {
				t.Fatalf("Verify = %v, want a certificate from the CA for %v", err, tc.usage)
			}
			if tc.renews != nil && got.SerialNumber.Cmp(tc.renews.SerialNumber) == 0 {
				t.Fatalf("serial = %v, want a new one", got.SerialNumber)
			}
			if k := tc.keeps; k != nil && (got.Subject.CommonName != k.Subject.CommonName ||
				!slices.Equal(got.DNSNames, k.DNSNames) || !slices.EqualFunc(got.IPAddresses, k.IPAddresses, net.IP.Equal)) {
				t.Fatalf("renewal = %q %v %v, want %q %v %v", got.Subject.CommonName, got.DNSNames, got.IPAddresses,
					k.Subject.CommonName, k.DNSNames, k.IPAddresses)
			}
		})
	}
}

// IssueCert puts a key Pair cannot hold in a certificate the CA vouches
// for.
func TestIssueCertOverAnyKey(t *testing.T) {
	ca := tlsconftest.NewCA(t, "ca")
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		pub  crypto.PublicKey
	}{
		{name: "an Ed25519 key", pub: edPub},
		{name: "an RSA key", pub: &rsaKey.PublicKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ca.IssueCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "k"},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, tc.pub)
			pub, ok := got.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
			if !ok || !pub.Equal(tc.pub) {
				t.Fatalf("certificate key = %T, want the given %T", got.PublicKey, tc.pub)
			}
			if _, err := got.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
				t.Fatalf("Verify = %v, want a client certificate from the CA", err)
			}
		})
	}
}

// The fixture's thumbprint is the one fiberd computes, so a test that
// binds a grant with it binds what a handshake names.
func TestThumbprintMatchesTLSConf(t *testing.T) {
	cases := []struct {
		name string
		pair tlsconftest.Pair
	}{
		{name: "a CA-issued pair", pair: tlsconftest.NewCA(t, "ca").Client(t, "c")},
		{name: "a self-signed pair", pair: tlsconftest.SelfSigned(t, &x509.Certificate{})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want, err := tlsconf.Thumbprint(tc.pair.Cert)
			if err != nil {
				t.Fatal(err)
			}
			if got := tc.pair.Thumbprint(t); got != want {
				t.Fatalf("Pair.Thumbprint = %q, want tlsconf's %q", got, want)
			}
		})
	}
}

// An unnamed client differs from a client only in its key, which fiberd
// cannot turn into a thumbprint. The CA vouches for both as clients.
func TestUnnamedClient(t *testing.T) {
	ca := tlsconftest.NewCA(t, "ca")
	cases := []struct {
		name           string
		leaf           tlsconftest.Pair
		wantThumbprint bool
	}{
		{name: "a client's key has a thumbprint", leaf: ca.Client(t, "c"), wantThumbprint: true},
		{name: "an unnamed client's key has no thumbprint", leaf: ca.UnnamedClient(t)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.leaf.Cert.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
				t.Fatalf("Verify = %v, want a client certificate from the CA", err)
			}
			if _, err := tlsconf.Thumbprint(tc.leaf.Cert); (err == nil) != tc.wantThumbprint {
				t.Fatalf("Thumbprint error = %v, want a thumbprint %v", err, tc.wantThumbprint)
			}
		})
	}
}
