package grant

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/helayoty/fiberd/pkg/core"
)

// Issuer mints grants and publishes its public keys the way verifiers
// expect, with OIDC discovery at <URL>/.well-known/openid-configuration
// and the key set at <URL>/openid/v1/jwks. It is the reference issuer for
// every home, and the Kubernetes controller wraps the same type.
//
// An issuer signs with Ring when Ring is set and with Key otherwise. The
// Kubernetes controller fills Ring from its Secret-backed KeyStore through
// LoadOrCreate, so a rotated key keeps verifying while its grants live.
type Issuer struct {
	// Key is the one signing key of an issuer without a Ring. It may be
	// nil when Ring is set.
	Key *jose.JSONWebKey
	// Ring, when set, holds every key the issuer publishes. Its Signing
	// key is the one Mint and Renew sign with.
	Ring KeyRing
	// URL is the issuer identifier. It is what goes in `iss`, and where
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

// signingKey is the key Mint and Renew sign with.
func (i *Issuer) signingKey() (*jose.JSONWebKey, error) {
	if (i.Key == nil && len(i.Ring) == 0) || i.URL == "" {
		return nil, errors.New("grant: issuer needs a key and a URL")
	}
	if len(i.Ring) > 0 {
		return i.Ring.Signing()
	}
	return i.Key, nil
}

// Mint signs g. g.Issuer is set to the issuer URL, since a grant cannot
// claim another issuer. Everything else is the caller's, and g must pass
// core.Grant.Validate.
func (i *Issuer) Mint(g core.Grant) (string, error) {
	if err := g.Validate(); err != nil {
		return "", fmt.Errorf("grant: invalid grant: %w", err)
	}
	key, err := i.signingKey()
	if err != nil {
		return "", err
	}
	g.Issuer = i.URL
	return Sign(g, key, i.now())
}

// Renew signs the grant in previous again for a fresh lease of the same
// length. previous must be a token this issuer signed with a key it still
// publishes, and its registered claims must agree with its grant claim as
// Verify requires. The lease length is exp minus iat of previous, so a
// token without either claim is refused. The renewed token has iat now
// and exp now plus that length, cut to whole seconds, and is signed with
// the current signing key.
//
// An expired previous token may still be renewed. Renewal is the lease's
// continuation, and whether a lapsed lease is continued is the issuer's
// decision. A home treats the lapse as capacity it no longer holds until
// the renewed token arrives.
func (i *Issuer) Renew(previous string, now time.Time) (string, error) {
	key, err := i.signingKey()
	if err != nil {
		return "", err
	}
	tok, err := parse(previous)
	if err != nil {
		return "", err
	}
	kid := tok.Headers[0].KeyID
	if kid == "" {
		return "", ErrNoKID
	}
	set := i.JWKS()
	pubs := set.Key(kid)
	if len(pubs) == 0 {
		return "", fmt.Errorf("%w %q at this issuer", ErrUnknownKey, kid)
	}
	// The payload is read before the signature is checked only to learn
	// the audience Verify must match. verifyParsed then authenticates the
	// same payload, so std is trusted once it returns.
	var std jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&std); err != nil {
		return "", fmt.Errorf("grant: parse claims: %w", err)
	}
	var aud string
	if len(std.Audience) == 1 {
		aud = std.Audience[0]
	}
	g, err := verifyParsed(tok, &pubs[0], VerifyOptions{Audience: aud, Issuer: i.URL})
	if err != nil {
		return "", err
	}
	if std.Expiry == nil || std.IssuedAt == nil {
		return "", errors.New("grant: renew needs a token with exp and iat")
	}
	lease := std.Expiry.Time().Sub(std.IssuedAt.Time())
	if lease <= 0 {
		return "", fmt.Errorf("grant: renew needs a positive lease, the token's is %s", lease)
	}
	at := now.Truncate(time.Second)
	g.LeaseExpiry = at.Add(lease)
	if err := g.Validate(); err != nil {
		return "", fmt.Errorf("grant: invalid grant: %w", err)
	}
	return Sign(g, key, at)
}

// JWKS is the public key set. It is every key of Ring when Ring is set,
// else the public half of Key.
func (i *Issuer) JWKS() jose.JSONWebKeySet {
	if len(i.Ring) > 0 {
		return i.Ring.Public()
	}
	if i.Key == nil {
		return jose.JSONWebKeySet{}
	}
	return PublicJWKS(i.Key)
}

// algs lists every distinct alg in the key set, in key set order.
func algs(set jose.JSONWebKeySet) []string {
	out := []string{}
	for _, k := range set.Keys {
		if k.Algorithm != "" && !slices.Contains(out, k.Algorithm) {
			out = append(out, k.Algorithm)
		}
	}
	return out
}

// Handler serves discovery and the JWKS. Mount it at the root of URL.
func (i *Issuer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                strings.TrimSuffix(i.URL, "/"),
			"jwks_uri":                              strings.TrimSuffix(i.URL, "/") + "/openid/v1/jwks",
			"id_token_signing_alg_values_supported": algs(i.JWKS()),
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
// file back to the UID to revoke. It bounds the token's size and algorithm
// as Verify does, before any parsing.
func PeekUID(token string) (string, error) {
	tok, err := parse(token)
	if err != nil {
		return "", err
	}
	var std jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&std); err != nil {
		return "", err
	}
	return std.ID, nil
}

// PeekExpiry reads the lease expiry (exp) WITHOUT verifying the token.
// Only for bookkeeping that never trusts the value, such as deciding
// whether a grant file left on disk is worth starting on before the
// file is delivered and verified. It bounds the token's size and
// algorithm as Verify does, before any parsing. A token without exp is
// an error.
func PeekExpiry(token string) (time.Time, error) {
	tok, err := parse(token)
	if err != nil {
		return time.Time{}, err
	}
	var std jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&std); err != nil {
		return time.Time{}, err
	}
	if std.Expiry == nil {
		return time.Time{}, errors.New("grant: token has no exp")
	}
	return std.Expiry.Time(), nil
}
