package grant

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/go-jose/go-jose/v4"
)

// Algorithms the protocol accepts. Anything else, including "none" and
// every symmetric algorithm, is rejected before the signature is looked
// at, so a key-confusion token cannot reach verification.
var AllowedAlgorithms = []jose.SignatureAlgorithm{jose.EdDSA, jose.ES256}

// GenerateKey creates a private signing key as a JWK with a thumbprint
// key id, ready for Sign and for publishing its public half in a JWKS.
func GenerateKey(alg jose.SignatureAlgorithm) (*jose.JSONWebKey, error) {
	var priv any
	switch alg {
	case jose.EdDSA:
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		priv = k
	case jose.ES256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		priv = k
	default:
		return nil, fmt.Errorf("grant: unsupported algorithm %q (want EdDSA or ES256)", alg)
	}
	jwk := &jose.JSONWebKey{Key: priv, Algorithm: string(alg), Use: "sig"}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	jwk.KeyID = base64.RawURLEncoding.EncodeToString(tp)
	return jwk, nil
}

// SaveKey writes the private JWK as JSON, readable by the owner only.
func SaveKey(path string, k *jose.JSONWebKey) error {
	b, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// LoadKey reads a JWK written by SaveKey (or any JWK JSON).
func LoadKey(path string) (*jose.JSONWebKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var k jose.JSONWebKey
	if err := json.Unmarshal(b, &k); err != nil {
		return nil, fmt.Errorf("grant: parse key %s: %w", path, err)
	}
	if !k.Valid() {
		return nil, fmt.Errorf("grant: key %s is not valid", path)
	}
	if k.KeyID == "" {
		return nil, errors.New("grant: key has no kid")
	}
	if k.Algorithm == "" {
		return nil, errors.New("grant: key has no alg")
	}
	return &k, nil
}

// PublicJWKS is the key set an issuer publishes: the public half of each
// key, kid and alg preserved.
func PublicJWKS(keys ...*jose.JSONWebKey) jose.JSONWebKeySet {
	set := jose.JSONWebKeySet{}
	for _, k := range keys {
		set.Keys = append(set.Keys, k.Public())
	}
	return set
}
