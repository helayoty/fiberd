package tlsconftest_test

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/helayoty/fiberd/pkg/tlsconf/tlsconftest"
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
