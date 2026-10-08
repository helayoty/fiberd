package grant_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
)

// The Verifier's own decisions, beyond what TestJWKSOffline covers. An
// unparsable or kid-less token is an auth failure. The default staleness
// bound is one hour. A key rotated out during the staleness refresh is
// unknown. A cache whose startup load failed stays unavailable inside the
// rate limit instead of calling every kid unknown.
func TestVerifierVerify(t *testing.T) {
	k1, _ := grant.GenerateKey(jose.EdDSA)
	k2, _ := grant.GenerateKey(jose.EdDSA)
	noKid := *k1
	noKid.KeyID = ""
	ctx := context.Background()

	cases := []struct {
		name string
		// setup runs with the issuer up and the cache cold, and returns
		// the token. It may warm the cache or change the issuer.
		setup       func(t *testing.T, is *issuer, c *grant.Cache) []byte
		maxStale    time.Duration
		age         time.Duration // verifier and cache clock past the start
		wantOK      bool
		want        error // errors.Is target, nil only requires failure
		unavailable bool  // the error must also be ErrVerifyUnavailable
	}{
		{name: "garbage is not a token",
			setup: func(*testing.T, *issuer, *grant.Cache) []byte { return []byte("garbage") }},
		{name: "a token without a kid cannot pick a key",
			setup: func(t *testing.T, is *issuer, _ *grant.Cache) []byte {
				return is.mint(t, &noKid, core.Grant{UID: "g1", Audience: "node-a"})
			},
			want: grant.ErrNoKID},
		{name: "keys under an hour old verify by default",
			setup: warm(k1), age: 59 * time.Minute, wantOK: true},
		{name: "keys over an hour old are stale by default",
			setup: warm(k1), age: 61 * time.Minute, want: grant.ErrJWKSStale, unavailable: true},
		{name: "a kid rotated out by the staleness refresh is unknown",
			setup: func(t *testing.T, is *issuer, c *grant.Cache) []byte {
				tok := warm(k1)(t, is, c)
				is.mu.Lock()
				is.keys = []*jose.JSONWebKey{k2}
				is.mu.Unlock()
				is.down.Store(false)
				return tok
			},
			maxStale: time.Minute, age: 2 * time.Minute, want: grant.ErrUnknownKey},
		{name: "a failed startup load stays unavailable inside the rate limit",
			setup: func(t *testing.T, is *issuer, c *grant.Cache) []byte {
				is.down.Store(true)
				if err := c.Refresh(ctx); err == nil {
					t.Fatal("startup refresh with the issuer down succeeded")
				}
				return is.mint(t, k1, core.Grant{UID: "g1", Audience: "node-a"})
			},
			want: grant.ErrNeverLoaded, unavailable: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			is := newIssuer(t, k1)
			start := time.Now()
			cache := &grant.Cache{IssuerURL: is.srv.URL, MinRefresh: time.Minute, Now: func() time.Time { return start }}
			tok := tc.setup(t, is, cache)
			at := start.Add(tc.age)
			cache.Now = func() time.Time { return at }
			v := &grant.Verifier{Cache: cache, Audience: "node-a", MaxStale: tc.maxStale, Now: cache.Now}

			g, err := v.Verify(ctx, tok)
			if tc.wantOK {
				if err != nil || g.UID != "g1" {
					t.Fatalf("Verify = %+v, %v, want grant g1", g, err)
				}
				return
			}
			if err == nil {
				t.Fatal("verified, want a refusal")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("Verify = %v, want %v", err, tc.want)
			}
			if errors.Is(err, core.ErrVerifyUnavailable) != tc.unavailable {
				t.Fatalf("Verify = %v, unavailable = %v, want %v", err, !tc.unavailable, tc.unavailable)
			}
		})
	}
}

// warm loads the cache while the issuer is up, mints a grant with key,
// then takes the issuer down.
func warm(key *jose.JSONWebKey) func(*testing.T, *issuer, *grant.Cache) []byte {
	return func(t *testing.T, is *issuer, c *grant.Cache) []byte {
		t.Helper()
		if err := c.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
		is.down.Store(true)
		return is.mint(t, key, core.Grant{UID: "g1", Audience: "node-a"})
	}
}
