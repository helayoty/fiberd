package grant_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
	"github.com/helayoty/fiberd/pkg/runtime/stub"
)

// The agent with the real verifier: a signed grant is admitted and served;
// a signed but expired grant is a capacity miss keyed on lane health (the
// C4 rule), and an unverifiable one (stale keys, issuer gone) is SHED,
// never Unauthenticated.
func TestAgentWithJWKSVerifier(t *testing.T) {
	k, _ := grant.GenerateKey(jose.ES256)
	is := newIssuer(t, k)
	now := time.Now()
	cache := &grant.Cache{IssuerURL: is.srv.URL, MinRefresh: time.Hour, Now: func() time.Time { return now }}
	v := &grant.Verifier{Cache: cache, Audience: "node-a", MaxStale: time.Hour, Now: func() time.Time { return now }}
	health := core.NewSourceHealth(10*time.Second, time.Now())
	a := &core.Agent{
		NodeID: "node-a", Ledger: core.NewLedger(1), Budget: core.NewBudget(1000, 1<<20),
		Runtime: stub.New(), Audit: core.NopAuditor{}, Verify: v, Health: health,
	}
	ctx := context.Background()
	clone := func(tok []byte) (core.StatusCode, error) {
		_, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: tok, Deadline: time.Second})
		return code, err
	}

	good := is.mint(t, k, core.Grant{UID: "g-ok", Audience: "node-a", FiberMax: 2, LeaseExpiry: now.Add(time.Hour)})
	if code, err := clone(good); code != core.OK {
		t.Fatalf("signed grant: %d %v", code, err)
	}

	expired := is.mint(t, k, core.Grant{UID: "g-exp", Audience: "node-a", LeaseExpiry: now.Add(-time.Minute)})
	if code, err := clone(expired); code != core.DeferredFallback || !errors.Is(err, core.ErrGrantExpired) {
		t.Fatalf("expired, lane healthy: %d %v, want DeferredFallback", code, err)
	}
	health.MarkSync(time.Now().Add(-time.Minute))
	if code, err := clone(expired); code != core.Shed || !errors.Is(err, core.ErrGrantExpired) {
		t.Fatalf("expired, lane stale: %d %v, want Shed", code, err)
	}

	other, _ := grant.GenerateKey(jose.ES256)
	forged := is.mint(t, other, core.Grant{UID: "g-forged", Audience: "node-a", LeaseExpiry: now.Add(time.Hour)})
	if code, err := clone(forged); code != core.Unauthenticated || !errors.Is(err, grant.ErrUnknownKey) {
		t.Fatalf("unknown key: %d %v, want Unauthenticated", code, err)
	}

	// Keys older than MaxStale with the issuer unreachable: SHED with the
	// unavailability error, not Unauthenticated.
	is.down.Store(true)
	later := now.Add(2 * time.Hour)
	v.Now = func() time.Time { return later }
	cache.Now = v.Now
	cache.MinRefresh = time.Nanosecond
	if code, err := clone(good); code != core.Shed || !errors.Is(err, core.ErrVerifyUnavailable) {
		t.Fatalf("stale keys, issuer down: %d %v, want Shed ErrVerifyUnavailable", code, err)
	}
}
