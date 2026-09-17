package grant

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/helayoty/fiberd/pkg/core"
)

// Issuer mints grants with one private key and publishes its public half
// the way verifiers expect: OIDC discovery at
// <URL>/.well-known/openid-configuration and the key set at
// <URL>/openid/v1/jwks. The reference issuer for every home; the
// Kubernetes controller wraps the same type.
type Issuer struct {
	Key *jose.JSONWebKey
	// URL is the issuer identifier: what goes in `iss`, and where
	// discovery is served.
	URL string
	Now func() time.Time
}

func (i *Issuer) now() time.Time {
	if i.Now != nil {
		return i.Now()
	}
	return time.Now()
}

// Mint signs g. g.Issuer is set to the issuer URL (a grant cannot claim
// another issuer); everything else is the caller's.
func (i *Issuer) Mint(g core.Grant) (string, error) {
	if i.Key == nil || i.URL == "" {
		return "", errors.New("grant: issuer needs a key and a URL")
	}
	g.Issuer = i.URL
	return Sign(g, i.Key, i.now())
}

// JWKS is the public key set.
func (i *Issuer) JWKS() jose.JSONWebKeySet { return PublicJWKS(i.Key) }

// Handler serves discovery and the JWKS. Mount it at the root of URL.
func (i *Issuer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                strings.TrimSuffix(i.URL, "/"),
			"jwks_uri":                              strings.TrimSuffix(i.URL, "/") + "/openid/v1/jwks",
			"id_token_signing_alg_values_supported": []string{i.Key.Algorithm},
			"response_types_supported":              []string{"id_token"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("GET /openid/v1/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=60")
		_ = json.NewEncoder(w).Encode(i.JWKS())
	})
	return mux
}

// PeekUID reads the grant UID (jti) WITHOUT verifying the token. Only for
// bookkeeping that never trusts the value, such as mapping a removed grant
// file back to the UID to revoke.
func PeekUID(token string) (string, error) {
	tok, err := jwt.ParseSigned(token, AllowedAlgorithms)
	if err != nil {
		return "", err
	}
	var std jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&std); err != nil {
		return "", err
	}
	return std.ID, nil
}
