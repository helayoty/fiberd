// Package tlsconftest issues throwaway certificates for tests that need
// TLS or mutual TLS, in the spirit of net/http/httptest.
package tlsconftest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
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
	return issue(t, tmpl, nil)
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
	return issue(t, tmpl, &p)
}

// Server is a server certificate from p for localhost and 127.0.0.1.
func (p Pair) Server(t testing.TB) Pair {
	t.Helper()
	return p.Issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "agent"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
}

// Client is a client certificate from p named cn.
func (p Pair) Client(t testing.TB, cn string) Pair {
	t.Helper()
	return p.Issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: cn},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
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

func issue(t testing.TB, tmpl *x509.Certificate, parent *Pair) Pair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.SerialNumber = big.NewInt(serial.Add(1))
	tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.Cert, parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return Pair{Cert: cert, Key: key}
}
