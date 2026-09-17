package grant

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

// Verifier implements core.Verifier against a JWKS Cache. It never makes
// a control-plane round trip on the request path beyond a rate-limited
// key refresh: known keys verify from memory.
//
// Two failures are not authentication failures but reachability ones, and
// are reported wrapped in core.ErrVerifyUnavailable so the agent answers
// SHED (back off) instead of Unauthenticated (give up):
//
//   - the key set was never loaded and the issuer cannot be reached;
//   - the key set is older than MaxStale (the lease TTL): a rotation or
//     revocation could have been missed for longer than any grant lives,
//     so nothing is trusted until a refresh succeeds.
type Verifier struct {
	Cache    *Cache
	Audience string
	// Issuer defaults to Cache.IssuerURL.
	Issuer string
	// MaxStale is how old the key set may be (default one hour). Set it
	// to the lease TTL grants are minted with.
	MaxStale time.Duration
	Now      func() time.Time
}

var ErrJWKSStale = errors.New("grant: key set older than the lease TTL")

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Verifier) maxStale() time.Duration {
	if v.MaxStale > 0 {
		return v.MaxStale
	}
	return time.Hour
}

func (v *Verifier) Verify(ctx context.Context, token []byte) (core.Grant, error) {
	hdr, err := Parse(string(token))
	if err != nil {
		return core.Grant{}, err
	}
	key, err := v.Cache.Key(ctx, hdr.KeyID)
	if err != nil {
		if errors.Is(err, ErrNeverLoaded) {
			return core.Grant{}, fmt.Errorf("%w: %w", core.ErrVerifyUnavailable, err)
		}
		return core.Grant{}, err
	}
	if age := v.now().Sub(v.Cache.LastRefresh()); age > v.maxStale() {
		// Try once (rate-limited); if still stale, refuse.
		_, _ = v.Cache.RefreshIfDue(ctx)
		if age = v.now().Sub(v.Cache.LastRefresh()); age > v.maxStale() {
			return core.Grant{}, fmt.Errorf("%w: %w (age %s)", core.ErrVerifyUnavailable, ErrJWKSStale, age.Round(time.Second))
		}
		if key, err = v.Cache.Key(ctx, hdr.KeyID); err != nil {
			return core.Grant{}, err
		}
	}
	issuer := v.Issuer
	if issuer == "" {
		issuer = v.Cache.IssuerURL
	}
	return Verify(string(token), key, VerifyOptions{Audience: v.Audience, Issuer: issuer})
}
