// Package tlsconftest issues throwaway certificates for tests that need
// TLS or mutual TLS, in the spirit of net/http/httptest.
package tlsconftest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Pair is a certificate and its private key.
type Pair struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

var serial atomic.Int64

// SelfSigned issues tmpl signed by its own fresh key. It fills in the
// serial number and a validity window around now.
func SelfSigned(t testing.TB, tmpl *x509.Certificate) Pair {
	t.Helper()
	return issue(t, tmpl, nil, nil)
}

// NewCA is a self-signed certificate authority named name.
func NewCA(t testing.TB, name string) Pair {
	t.Helper()
	return SelfSigned(t, &x509.Certificate{Subject: pkix.Name{CommonName: name}, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true})
}

// Issue signs tmpl with p, which must be a CA.
func (p Pair) Issue(t testing.TB, tmpl *x509.Certificate) Pair {
	t.Helper()
	return issue(t, tmpl, &p, nil)
}

// IssueKey signs tmpl with p, which must be a CA, over key.
func (p Pair) IssueKey(t testing.TB, tmpl *x509.Certificate, key *ecdsa.PrivateKey) Pair {
	t.Helper()
	return issue(t, tmpl, &p, key)
}

// IssueCert signs tmpl with p, which must be a CA, over pub of any type.
func (p Pair) IssueCert(t testing.TB, tmpl *x509.Certificate, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	return sign(t, tmpl, p.Cert, p.Key, pub)
}

// Renew is a new certificate from p over leaf's key, with leaf's subject,
// names and usage, the way cert-manager renews without rotating the key.
func (p Pair) Renew(t testing.TB, leaf Pair) Pair {
	t.Helper()
	c := leaf.Cert
	return p.IssueKey(t, &x509.Certificate{Subject: c.Subject, DNSNames: c.DNSNames, IPAddresses: c.IPAddresses,
		URIs: c.URIs, EmailAddresses: c.EmailAddresses, KeyUsage: c.KeyUsage, ExtKeyUsage: c.ExtKeyUsage}, leaf.Key)
}

// Server is a server certificate from p for localhost and 127.0.0.1.
func (p Pair) Server(t testing.TB) Pair {
	t.Helper()
	return p.Issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "fiberd"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
}

// Client is a client certificate from p named cn.
func (p Pair) Client(t testing.TB, cn string) Pair {
	t.Helper()
	return p.Issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: cn},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
}

// UnnamedClient is a client certificate from p over a fresh P-224 key. Go
// issues and parses the curve, and the key has no RFC 7638 thumbprint, so
// the certificate names no caller.
func (p Pair) UnnamedClient(t testing.TB) Pair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return p.IssueKey(t, &x509.Certificate{Subject: pkix.Name{CommonName: "p224"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, key)
}

// TLS is p as a certificate to present in a handshake.
func (p Pair) TLS() tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{p.Cert.Raw}, PrivateKey: p.Key, Leaf: p.Cert}
}

// Pool is a pool holding only p.
func (p Pair) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.Cert)
	return pool
}

// Thumbprint is the RFC 7638 thumbprint of p's key, the cnf jkt of a
// grant bound to p. It is computed here because tlsconf's internal tests
// import this package, so importing tlsconf would be a cycle.
func (p Pair) Thumbprint(t testing.TB) string {
	t.Helper()
	tp, err := (&jose.JSONWebKey{Key: p.Cert.PublicKey}).Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(tp)
}

// CertPEM is the certificate in PEM.
func (p Pair) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.Cert.Raw})
}

// Write stores the certificate and key as PEM files name.crt and
// name.key in dir, and returns their paths.
func (p Pair) Write(t testing.TB, dir, name string) (certFile, keyFile string) {
	t.Helper()
	certFile, keyFile = filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	if err := os.WriteFile(certFile, p.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(p.Key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// issue signs tmpl over key, a fresh P-256 one when key is nil, with
// parent, or with key itself when parent is nil.
func issue(t testing.TB, tmpl *x509.Certificate, parent *Pair, key *ecdsa.PrivateKey) Pair {
	t.Helper()
	if key == nil {
		var err error
		if key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			t.Fatal(err)
		}
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.Cert, parent.Key
	}
	return Pair{Cert: sign(t, tmpl, signer, signerKey, &key.PublicKey), Key: key}
}

// sign fills in tmpl's serial number and validity window and signs it
// over pub with signer and signerKey.
func sign(t testing.TB, tmpl, signer *x509.Certificate, signerKey *ecdsa.PrivateKey, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	tmpl.SerialNumber = big.NewInt(serial.Add(1))
	tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, pub, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
