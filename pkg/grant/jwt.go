package grant

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
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
//
// A grant bound to a caller also carries the RFC 8705 confirmation
// claim, copied into Grant.CallerThumbprint.

type grantClaim struct {
	Grant json.RawMessage `json:"grant"`
	Cnf   *cnfClaim       `json:"cnf,omitempty"`
}

type cnfClaim struct {
	X5tS256 string `json:"x5t#S256"`
}

// MaxTokenBytes bounds a token before any parsing.
const MaxTokenBytes = 8 << 10

// Sign mints the token for g with key (a private JWK from GenerateKey or
// LoadKey). The key's kid lands in the header so verifiers can pick it
// from a JWKS.
func Sign(g core.Grant, key *jose.JSONWebKey, now time.Time) (string, error) {
	if g.UID == "" || g.Issuer == "" || g.Audience == "" {
		return "", errors.New("grant: uid, issuer and audience are required to sign")
	}
	// Every home would refuse this UID or tenant, so the issuer learns at
	// mint time.
	if err := checkUID(g.UID); err != nil {
		return "", err
	}
	if err := checkTenant(g.Tenant); err != nil {
		return "", err
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
	gc := grantClaim{Grant: body}
	if g.CallerThumbprint != "" {
		gc.Cnf = &cnfClaim{X5tS256: g.CallerThumbprint}
	}
	return jwt.Signed(signer).Claims(std).Claims(gc).Serialize()
}

// parse reads the token without verifying anything. The algorithm
// allow-list is enforced here already, so an unsupported alg never
// reaches key lookup. The token has exactly one header.
func parse(token string) (*jwt.JSONWebToken, error) {
	if len(token) > MaxTokenBytes {
		return nil, ErrTokenTooLarge
	}
	tok, err := jwt.ParseSigned(token, AllowedAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("grant: parse: %w", err)
	}
	if len(tok.Headers) != 1 {
		return nil, errors.New("grant: token must carry exactly one signature")
	}
	return tok, nil
}

// VerifyOptions constrain Verify. Audience is required: a home only
// accepts grants addressed to it. Issuer, when set, must match. MaxLease,
// when set, bounds the signed lifetime (exp - iat). A grant missing either
// claim is then refused.
type VerifyOptions struct {
	Audience string
	Issuer   string
	MaxLease time.Duration
}

// Verify checks the signature with pub (a public JWK), then the
// registered claims against opts and against the grant claim, and returns
// the grant. It does not reject an expired token; see the package note.
func Verify(token string, pub *jose.JSONWebKey, opts VerifyOptions) (core.Grant, error) {
	tok, err := parse(token)
	if err != nil {
		return core.Grant{}, err
	}
	return verifyParsed(tok, pub, opts)
}

// verifyParsed is Verify on a token parse already read.
func verifyParsed(tok *jwt.JSONWebToken, pub *jose.JSONWebKey, opts VerifyOptions) (core.Grant, error) {
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
	if gc.Cnf != nil {
		if gc.Cnf.X5tS256 == "" {
			return core.Grant{}, errors.New("grant: cnf claim carries no x5t#S256")
		}
		g.CallerThumbprint = gc.Cnf.X5tS256
	}

	// Registered claims are the cross-check; the grant claim is the content.
	if err := checkUID(g.UID); err != nil {
		return core.Grant{}, err
	}
	if err := checkTenant(g.Tenant); err != nil {
		return core.Grant{}, err
	}
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
	if opts.MaxLease > 0 {
		if std.Expiry == nil || std.IssuedAt == nil {
			return core.Grant{}, fmt.Errorf("%w: grant has no exp or iat", ErrLeaseTooLong)
		}
		if life := std.Expiry.Time().Sub(std.IssuedAt.Time()); life > opts.MaxLease {
			return core.Grant{}, fmt.Errorf("%w: %s, at most %s", ErrLeaseTooLong, life, opts.MaxLease)
		}
	}
	return g, nil
}

// uidPattern is the Kubernetes DNS-1123 label rule. The UID becomes a
// cgroup and run-directory name beside kernel files like memory.max, so it
// must be one plain path segment ("." and ".." never match). Lowercase keeps
// names distinct on case-insensitive filesystems. The length bound keeps
// paths under the unix socket limit.
var uidPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// checkUID is the single check every verified grant passes through.
func checkUID(uid string) error {
	if uid == "" {
		return ErrEmptyGrant
	}
	if !uidPattern.MatchString(uid) {
		return fmt.Errorf("%w: %q", ErrBadUID, uid)
	}
	return nil
}

// tenantPattern bounds a tenant name: one path segment of letters,
// digits, ".", "_" and "-", at most 253 characters. It becomes the first
// half of the session domain "<tenant>/<class or digest>", so "/" and
// whitespace are out and the domain splits at its first "/" without
// ambiguity. A Kubernetes namespace and a Slurm account both fit.
var tenantPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`)

// checkTenant is the single check every verified grant's tenant passes
// through. Empty is allowed: such a grant runs anonymous fibers only.
func checkTenant(tenant string) error {
	if tenant != "" && !tenantPattern.MatchString(tenant) {
		return fmt.Errorf("%w: %q", ErrBadTenant, tenant)
	}
	return nil
}

func allowed(alg jose.SignatureAlgorithm) bool {
	for _, a := range AllowedAlgorithms {
		if a == alg {
			return true
		}
	}
	return false
}
