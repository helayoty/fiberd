// Package tlsconf builds the control plane's TLS configurations, for the
// agent's mutual-TLS server and for the callers that dial it. It also
// names a caller from the certificate it presented.
package tlsconf

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
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

// Server returns the agent's server configuration. It requires TLS 1.3
// and a client certificate signed by clientCA on every connection. With
// plaintext set and no files it returns nil, which tells the caller to
// serve without TLS.
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
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("tlsconf: server certificate: %w", err)
	}
	pool, err := loadPool(clientCAFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}, nil
}

// Client returns a caller's TLS 1.3 configuration. It verifies the agent
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
	// Thumbprint is the base64url SHA-256 of the DER certificate, the
	// value of a grant's cnf x5t#S256 claim.
	Thumbprint string
}

// CallerOf names the peer from its verified chain, whose leaf comes first.
func CallerOf(chain []*x509.Certificate) (Caller, bool) {
	if len(chain) == 0 {
		return Caller{}, false
	}
	return Caller{Thumbprint: Thumbprint(chain[0])}, true
}

// Thumbprint is the RFC 8705 x5t#S256 of a certificate.
func Thumbprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
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
		return Thumbprint(cert), nil
	}
}
