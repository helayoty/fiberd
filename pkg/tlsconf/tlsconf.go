// Package tlsconf builds the control plane's TLS configurations, for the
// fiberd's mutual-TLS server and for the callers that dial it. It also
// names a caller from the certificate it presented.
//
// The server re-reads its certificate, key and client CA when the files
// change, so a renewal cert-manager writes in place is served without a
// restart. The files are checked at most once per second. A renewal
// that fails to load keeps the previous pair and pool.
package tlsconf

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/go-jose/go-jose/v4"
)

var (
	// ErrPartialTLS is a server or client given some of its TLS files but
	// not all of them.
	ErrPartialTLS = errors.New("tlsconf: TLS needs a certificate, a key and a CA together")
	// ErrNoTransport is a server given neither TLS files nor an explicit
	// plaintext opt-in.
	ErrNoTransport = errors.New("tlsconf: TLS is required: set a certificate, key and client CA, or opt in to plaintext explicitly")
	// ErrPlaintextWithTLS is a server given TLS files and the plaintext
	// opt-in at once.
	ErrPlaintextWithTLS = errors.New("tlsconf: plaintext and TLS are mutually exclusive")
)

// Server returns fiberd's server configuration. It requires TLS 1.3
// and a client certificate signed by clientCA on every connection. With
// plaintext set and no files it returns nil, which tells the caller to
// serve without TLS.
//
// The certificate, key and client CA are re-read when their files
// change, checked at most once per second, so a renewal written in
// place is served without a restart. A renewal that fails to load keeps
// the previous pair and pool. The files must load once here.
func Server(certFile, keyFile, clientCAFile string, plaintext bool) (*tls.Config, error) {
	set := certFile != "" || keyFile != "" || clientCAFile != ""
	switch {
	case plaintext && set:
		return nil, ErrPlaintextWithTLS
	case plaintext:
		return nil, nil
	case !set:
		return nil, ErrNoTransport
	case certFile == "" || keyFile == "" || clientCAFile == "":
		return nil, ErrPartialTLS
	}
	r, err := newReloader(certFile, keyFile, clientCAFile, time.Now, time.Second)
	if err != nil {
		return nil, err
	}
	return r.base(), nil
}

// Client returns a caller's TLS 1.3 configuration. It verifies fiberd
// against caFile and presents the caller's own certificate. With no files
// it returns nil, which tells the caller to dial in plaintext.
func Client(caFile, certFile, keyFile string) (*tls.Config, error) {
	set := caFile != "" || certFile != "" || keyFile != ""
	if !set {
		return nil, nil
	}
	if caFile == "" || certFile == "" || keyFile == "" {
		return nil, ErrPartialTLS
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("tlsconf: client certificate: %w", err)
	}
	pool, err := loadPool(caFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	}, nil
}

func loadPool(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tlsconf: CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("tlsconf: CA bundle %s holds no PEM certificate", path)
	}
	return pool, nil
}

// Caller is who is on the other end of a verified connection.
type Caller struct {
	// Thumbprint is the RFC 7638 thumbprint of the caller's public key,
	// the value of a grant's cnf jkt, so a renewed certificate with the
	// same key names the same caller.
	Thumbprint string
	// Cert is the DER certificate itself, the one a handoff fiber of a
	// grant bound to this caller is told to accept.
	Cert []byte
}

// CallerOf names the peer from its verified chain, whose leaf comes first.
// ok is false for an empty chain and for a leaf whose key has no
// thumbprint. A server must refuse the second, never serve it as a peer
// without identity.
func CallerOf(chain []*x509.Certificate) (Caller, bool) {
	if len(chain) == 0 {
		return Caller{}, false
	}
	tp, err := keyThumbprint(chain[0])
	if err != nil {
		return Caller{}, false
	}
	return Caller{Thumbprint: tp, Cert: chain[0].Raw}, true
}

// Thumbprint is the RFC 7638 thumbprint of a certificate's public key,
// the base64url SHA-256 of the key's canonical JWK, which is the value of
// a grant's cnf jkt. A key without a canonical JWK form, a P-224 one for
// example, is an error.
func Thumbprint(cert *x509.Certificate) (string, error) {
	tp, err := keyThumbprint(cert)
	if err != nil {
		return "", fmt.Errorf("tlsconf: %w", err)
	}
	return tp, nil
}

// keyThumbprint is Thumbprint with an error its caller prefixes.
func keyThumbprint(cert *x509.Certificate) (string, error) {
	tp, err := (&jose.JSONWebKey{Key: cert.PublicKey}).Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("certificate key has no JWK thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

// ThumbprintFile is Thumbprint of the first certificate in a PEM file.
func ThumbprintFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for {
		var blk *pem.Block
		if blk, b = pem.Decode(b); blk == nil {
			return "", fmt.Errorf("tlsconf: %s holds no PEM certificate", path)
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return "", fmt.Errorf("tlsconf: %s: %w", path, err)
		}
		tp, err := keyThumbprint(cert)
		if err != nil {
			return "", fmt.Errorf("tlsconf: %s: %w", path, err)
		}
		return tp, nil
	}
}
