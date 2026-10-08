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
// never Unauthenticated. The steps share one agent and run in order. Each
// step's before hook moves the lane, the issuer or the clock.
func TestAgentWithJWKSVerifier(t *testing.T) {
	k, _ := grant.GenerateKey(jose.ES256)
	other, _ := grant.GenerateKey(jose.ES256)
	is := newIssuer(t, k)
	now := time.Now()
	cache := &grant.Cache{IssuerURL: is.srv.URL, MinRefresh: time.Hour, Now: func() time.Time { return now }}
	v := &grant.Verifier{Cache: cache, Audience: "node-a", MaxStale: time.Hour, Now: func() time.Time { return now }}
	health := core.NewSourceHealth(10*time.Second, time.Now())
	a := &core.Agent{
		NodeID: "node-a", Ledger: core.NewLedger(1), Budget: core.NewBudget(1000, 1<<20),
		Runtime: stub.New(), Verify: v, Health: health,
	}
	ctx := context.Background()

	good := is.mint(t, k, core.Grant{UID: "g-ok", Audience: "node-a", FiberMax: 2, LeaseExpiry: now.Add(time.Hour)})
	expired := is.mint(t, k, core.Grant{UID: "g-exp", Audience: "node-a", LeaseExpiry: now.Add(-time.Minute)})
	forged := is.mint(t, other, core.Grant{UID: "g-forged", Audience: "node-a", LeaseExpiry: now.Add(time.Hour)})

	steps := []struct {
		name     string
		before   func()
		token    []byte
		wantCode core.StatusCode
		wantErr  error // errors.Is target, nil requires no error
	}{
		{name: "a signed grant is served", token: good, wantCode: core.OK},
		{name: "an expired grant with the lane healthy defers", token: expired,
			wantCode: core.DeferredFallback, wantErr: core.ErrGrantExpired},
		{name: "an expired grant with the lane stale is shed",
			before: func() { health.MarkSync(time.Now().Add(-time.Minute)) },
			token:  expired, wantCode: core.Shed, wantErr: core.ErrGrantExpired},
		{name: "a grant signed by an unknown key is unauthenticated", token: forged,
			wantCode: core.Unauthenticated, wantErr: grant.ErrUnknownKey},
		// Keys older than MaxStale with the issuer down shed with the
		// unavailability error, not Unauthenticated.
		{name: "stale keys with the issuer down shed instead of refusing",
			before: func() {
				is.down.Store(true)
				later := now.Add(2 * time.Hour)
				v.Now = func() time.Time { return later }
				cache.Now = v.Now
				cache.MinRefresh = time.Nanosecond
			},
			token: good, wantCode: core.Shed, wantErr: core.ErrVerifyUnavailable},
	}
	for _, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			if st.before != nil {
				st.before()
			}
			_, code, err := a.Clone(ctx, core.CloneRequest{GrantJWT: st.token, Deadline: time.Second})
			if code != st.wantCode {
				t.Fatalf("code = %d (%v), want %d", code, err, st.wantCode)
			}
			if !errors.Is(err, st.wantErr) {
				t.Fatalf("err = %v, want %v", err, st.wantErr)
			}
		})
	}
}
