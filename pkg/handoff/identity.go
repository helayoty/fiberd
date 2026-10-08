package handoff

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Suffix ends every server name a caller sends, as in <routing_key>.fiberd.
const Suffix = ".fiberd"

// Identity is the TLS identity a grant's handoff fibers serve with.
type Identity struct {
	CertPEM []byte // self-signed, for *.fiberd
	KeyPEM  []byte // PKCS #8 Ed25519 private key
	// KeySHA256 is the base64url SHA-256 of the certificate's
	// SubjectPublicKeyInfo. Callers pin it (CloneResponse
	// server_key_sha256).
	KeySHA256 string
}

// Derive makes the grant's identity from the home's handoff key. Every
// home with the same key derives the same identity for the same grant, so
// a session resumed on another home still holds the key its caller
// pinned.
func Derive(master []byte, grantUID string) (Identity, error) {
	if len(master) < 32 {
		return Identity{}, errors.New("handoff: key must be at least 32 bytes")
	}
	seed, err := hkdf.Key(sha256.New, master, nil, "fiberd-handoff-v1 "+grantUID, ed25519.SeedSize)
	if err != nil {
		return Identity{}, err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	// Fixed fields and a deterministic signature give the same
	// certificate on every home. Callers pin the key, not the validity
	// period.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fiberd handoff"},
		DNSNames:     []string{"*" + Suffix},
		NotBefore:    time.Unix(0, 0).UTC(),
		NotAfter:     time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return Identity{}, fmt.Errorf("handoff: certificate: %w", err)
	}
	pk, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return Identity{}, err
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return Identity{}, err
	}
	return Identity{
		CertPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}),
		KeySHA256: KeyPin(spki),
	}, nil
}

// KeyPin is the pin of a DER SubjectPublicKeyInfo, as Identity.KeySHA256.
func KeyPin(spki []byte) string {
	sum := sha256.Sum256(spki)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ClientConfig is a caller's TLS configuration for a handoff fiber. It
// names the fiber by its routing key and presents cert, the certificate
// the grant is bound to. The fiber refuses any other. It accepts only the
// server key whose pin the home returned with the clone.
func ClientConfig(routingKey, serverKeySHA256 string, cert tls.Certificate) *tls.Config {
	cfg := &tls.Config{
		ServerName: routingKey + Suffix,
		MinVersion: tls.VersionTLS13,
		// The fiber's certificate is self-signed, so the pin is the check.
		InsecureSkipVerify: true, //nolint:gosec // verified by VerifyPeerCertificate
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return ErrKeyMismatch
			}
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return fmt.Errorf("%w: %w", ErrKeyMismatch, err)
			}
			if KeyPin(leaf.RawSubjectPublicKeyInfo) != serverKeySHA256 {
				return ErrKeyMismatch
			}
			return nil
		},
	}
	if len(cert.Certificate) > 0 {
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg
}
