package grant

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"google.golang.org/protobuf/encoding/protojson"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/core"
)

// The token layout. Registered claims mirror the grant so any JWT-aware
// middlebox can read iss/aud/exp/jti without knowing the protocol; the
// `grant` claim carries the full CapacityGrant as protobuf JSON and is the
// authoritative content. The two must agree, or the token is malformed.
//
//	{
//	  "iss": <grant.issuer>,   "aud": <grant.audience>,
//	  "exp": <grant.lease_expiry>, "iat": <now>, "jti": <grant.grant_uid>,
//	  "grant": { ...CapacityGrant as protojson... }
//	}
//
// exp is NOT enforced by Verify. Expiry is lease non-renewal, which the
// ledger turns into a capacity miss keyed on control-plane health (SHED
// or DEFERRED_FALLBACK); an Unauthenticated error would send the caller
// down the wrong path. The lease is copied into Grant.LeaseExpiry.

type grantClaim struct {
	Grant json.RawMessage `json:"grant"`
}

var (
	ErrNoKID          = errors.New("grant: token has no kid header")
	ErrClaimMismatch  = errors.New("grant: registered claims disagree with the grant claim")
	ErrWrongAudience  = errors.New("grant: audience mismatch")
	ErrWrongIssuer    = errors.New("grant: issuer mismatch")
	ErrMissingGrant   = errors.New("grant: token carries no grant claim")
	ErrKeyMismatchAlg = errors.New("grant: key algorithm does not match token")
)

// Sign mints the token for g with key (a private JWK from GenerateKey or
// LoadKey). The key's kid lands in the header so verifiers can pick it
// from a JWKS.
func Sign(g core.Grant, key *jose.JSONWebKey, now time.Time) (string, error) {
	if g.UID == "" || g.Issuer == "" || g.Audience == "" {
		return "", errors.New("grant: uid, issuer and audience are required to sign")
	}
	if key == nil || key.IsPublic() {
		return "", errors.New("grant: signing needs a private key")
	}
	alg := jose.SignatureAlgorithm(key.Algorithm)
	if !allowed(alg) {
		return "", fmt.Errorf("grant: key alg %q not allowed", key.Algorithm)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return "", err
	}
	body, err := protojson.Marshal(ToProto(g))
	if err != nil {
		return "", err
	}
	std := jwt.Claims{
		Issuer:   g.Issuer,
		Audience: jwt.Audience{g.Audience},
		IssuedAt: jwt.NewNumericDate(now),
		ID:       g.UID,
	}
	if !g.LeaseExpiry.IsZero() {
		std.Expiry = jwt.NewNumericDate(g.LeaseExpiry)
	}
	return jwt.Signed(signer).Claims(std).Claims(grantClaim{Grant: body}).Serialize()
}

// Header is what Parse reads before any verification: enough to choose
// a key.
type Header struct {
	KeyID     string
	Algorithm jose.SignatureAlgorithm
}

// Parse reads the header without verifying anything. The algorithm
// allow-list is enforced here already, so an unsupported alg never
// reaches key lookup.
func Parse(token string) (Header, error) {
	tok, err := jwt.ParseSigned(token, AllowedAlgorithms)
	if err != nil {
		return Header{}, fmt.Errorf("grant: parse: %w", err)
	}
	if len(tok.Headers) != 1 {
		return Header{}, errors.New("grant: token must carry exactly one signature")
	}
	h := tok.Headers[0]
	if h.KeyID == "" {
		return Header{}, ErrNoKID
	}
	return Header{KeyID: h.KeyID, Algorithm: jose.SignatureAlgorithm(h.Algorithm)}, nil
}

// VerifyOptions constrain Verify. Audience is required: a home only
// accepts grants addressed to it. Issuer, when set, must match.
type VerifyOptions struct {
	Audience string
	Issuer   string
}

// Verify checks the signature with pub (a public JWK), then the
// registered claims against opts and against the grant claim, and returns
// the grant. It does not reject an expired token; see the package note.
func Verify(token string, pub *jose.JSONWebKey, opts VerifyOptions) (core.Grant, error) {
	tok, err := jwt.ParseSigned(token, AllowedAlgorithms)
	if err != nil {
		return core.Grant{}, fmt.Errorf("grant: parse: %w", err)
	}
	if len(tok.Headers) != 1 {
		return core.Grant{}, errors.New("grant: token must carry exactly one signature")
	}
	if pub == nil {
		return core.Grant{}, errors.New("grant: no key")
	}
	if pub.Algorithm != "" && pub.Algorithm != tok.Headers[0].Algorithm {
		return core.Grant{}, ErrKeyMismatchAlg
	}
	var std jwt.Claims
	var gc grantClaim
	if err := tok.Claims(pub, &std, &gc); err != nil {
		return core.Grant{}, fmt.Errorf("grant: signature: %w", err)
	}
	if len(gc.Grant) == 0 {
		return core.Grant{}, ErrMissingGrant
	}
	var p grantv1.CapacityGrant
	if err := protojson.Unmarshal(gc.Grant, &p); err != nil {
		return core.Grant{}, fmt.Errorf("grant: decode grant claim: %w", err)
	}
	g := FromProto(&p)

	// Registered claims are the cross-check; the grant claim is the content.
	if std.ID != g.UID || std.Issuer != g.Issuer || len(std.Audience) != 1 || std.Audience[0] != g.Audience {
		return core.Grant{}, ErrClaimMismatch
	}
	if (std.Expiry == nil) != g.LeaseExpiry.IsZero() || (std.Expiry != nil && !std.Expiry.Time().Equal(g.LeaseExpiry.Truncate(time.Second))) {
		return core.Grant{}, fmt.Errorf("%w: exp vs lease_expiry", ErrClaimMismatch)
	}
	if opts.Audience == "" || g.Audience != opts.Audience {
		return core.Grant{}, fmt.Errorf("%w: token for %q, this home is %q", ErrWrongAudience, g.Audience, opts.Audience)
	}
	if opts.Issuer != "" && g.Issuer != opts.Issuer {
		return core.Grant{}, fmt.Errorf("%w: token from %q, expected %q", ErrWrongIssuer, g.Issuer, opts.Issuer)
	}
	return g, nil
}

func allowed(alg jose.SignatureAlgorithm) bool {
	for _, a := range AllowedAlgorithms {
		if a == alg {
			return true
		}
	}
	return false
}
