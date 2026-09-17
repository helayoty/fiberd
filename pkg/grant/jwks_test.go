package grant_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
)

// issuer is a fake OIDC issuer: discovery + JWKS, with a swappable key set
// and hit counters.
type issuer struct {
	srv      *httptest.Server
	mu       sync.Mutex
	keys     []*jose.JSONWebKey
	jwksHits atomic.Int32
	discHits atomic.Int32
	down     atomic.Bool
}

func newIssuer(t *testing.T, keys ...*jose.JSONWebKey) *issuer {
	t.Helper()
	is := &issuer{keys: keys}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		is.discHits.Add(1)
		if is.down.Load() {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": is.srv.URL, "jwks_uri": is.srv.URL + "/openid/v1/jwks"})
	})
	mux.HandleFunc("/openid/v1/jwks", func(w http.ResponseWriter, _ *http.Request) {
		is.jwksHits.Add(1)
		if is.down.Load() {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		is.mu.Lock()
		set := grant.PublicJWKS(is.keys...)
		is.mu.Unlock()
		_ = json.NewEncoder(w).Encode(set)
	})
	is.srv = httptest.NewServer(mux)
	t.Cleanup(is.srv.Close)
	return is
}

func (is *issuer) rotate(k *jose.JSONWebKey) {
	is.mu.Lock()
	defer is.mu.Unlock()
	is.keys = append(is.keys, k)
}

func (is *issuer) mint(t *testing.T, key *jose.JSONWebKey, g core.Grant) []byte {
	t.Helper()
	g.Issuer = is.srv.URL
	tok, err := grant.Sign(g, key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return []byte(tok)
}

func TestJWKSDiscoveryRotationAndRateLimit(t *testing.T) {
	k1, _ := grant.GenerateKey(jose.EdDSA)
	k2, _ := grant.GenerateKey(jose.ES256)
	is := newIssuer(t, k1)
	cache := &grant.Cache{IssuerURL: is.srv.URL, MinRefresh: time.Hour}
	v := &grant.Verifier{Cache: cache, Audience: "node-a", MaxStale: time.Hour}
	ctx := context.Background()
	g := core.Grant{UID: "g1", Audience: "node-a", FiberMax: 1}

	if _, err := v.Verify(ctx, is.mint(t, k1, g)); err != nil {
		t.Fatalf("first verify (cold cache, issuer up): %v", err)
	}
	if is.discHits.Load() != 1 || is.jwksHits.Load() != 1 {
		t.Fatalf("discovery/jwks hits = %d/%d, want 1/1", is.discHits.Load(), is.jwksHits.Load())
	}
	if _, err := v.Verify(ctx, is.mint(t, k1, g)); err != nil {
		t.Fatalf("second verify: %v", err)
	}
	if is.jwksHits.Load() != 1 {
		t.Fatalf("known kid must verify from memory; jwks hits = %d", is.jwksHits.Load())
	}

	// Unknown kid before the issuer published it: ErrUnknownKey, and no
	// refetch because the last load was inside MinRefresh. A flood of bad
	// kids cannot hammer the issuer.
	for i := 0; i < 3; i++ {
		_, err := v.Verify(ctx, is.mint(t, k2, g))
		if !errors.Is(err, grant.ErrUnknownKey) {
			t.Fatalf("unknown kid = %v, want ErrUnknownKey", err)
		}
		if errors.Is(err, core.ErrVerifyUnavailable) {
			t.Fatalf("unknown kid with a fresh cache must be an auth failure, not unavailability: %v", err)
		}
	}
	if is.jwksHits.Load() != 1 {
		t.Fatalf("jwks hits = %d, want 1 (rate-limited)", is.jwksHits.Load())
	}

	// Rotation: issuer publishes k2; once the rate limit passes, the
	// unknown kid triggers exactly one refresh and verifies. Discovery is
	// not repeated: jwks_uri is remembered.
	is.rotate(k2)
	cache.MinRefresh = time.Nanosecond
	if _, err := v.Verify(ctx, is.mint(t, k2, g)); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	if is.jwksHits.Load() != 2 || is.discHits.Load() != 1 {
		t.Fatalf("jwks/discovery hits = %d/%d, want 2/1", is.jwksHits.Load(), is.discHits.Load())
	}
}

func TestJWKSOffline(t *testing.T) {
	k, _ := grant.GenerateKey(jose.EdDSA)
	g := core.Grant{UID: "g1", Audience: "node-a"}
	ctx := context.Background()

	t.Run("cold cache, issuer down: unavailable", func(t *testing.T) {
		is := newIssuer(t, k)
		tok := is.mint(t, k, g)
		is.down.Store(true)
		v := &grant.Verifier{Cache: &grant.Cache{IssuerURL: is.srv.URL}, Audience: "node-a"}
		_, err := v.Verify(ctx, tok)
		if !errors.Is(err, core.ErrVerifyUnavailable) || !errors.Is(err, grant.ErrNeverLoaded) {
			t.Fatalf("err = %v, want ErrVerifyUnavailable wrapping ErrNeverLoaded", err)
		}
	})

	t.Run("warm cache, issuer down: verifies", func(t *testing.T) {
		is := newIssuer(t, k)
		cache := &grant.Cache{IssuerURL: is.srv.URL}
		if err := cache.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
		is.down.Store(true)
		v := &grant.Verifier{Cache: cache, Audience: "node-a", MaxStale: time.Hour}
		if _, err := v.Verify(ctx, is.mint(t, k, g)); err != nil {
			t.Fatalf("warm cache must verify offline: %v", err)
		}
		// Expired grant offline: verifies (the ledger turns the lease into
		// the miss code); no network needed to know it is past.
		exp := g
		exp.LeaseExpiry = time.Now().Add(-time.Minute)
		got, err := v.Verify(ctx, is.mint(t, k, exp))
		if err != nil || !got.Expired(time.Now()) {
			t.Fatalf("expired offline: %v expired=%v", err, got.Expired(time.Now()))
		}
	})

	t.Run("cache older than MaxStale: unavailable even for a known kid", func(t *testing.T) {
		is := newIssuer(t, k)
		now := time.Now()
		cache := &grant.Cache{IssuerURL: is.srv.URL, MinRefresh: time.Hour, Now: func() time.Time { return now }}
		if err := cache.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
		is.down.Store(true)
		v := &grant.Verifier{Cache: cache, Audience: "node-a", MaxStale: 10 * time.Minute,
			Now: func() time.Time { return now.Add(11 * time.Minute) }}
		_, err := v.Verify(ctx, is.mint(t, k, g))
		if !errors.Is(err, core.ErrVerifyUnavailable) || !errors.Is(err, grant.ErrJWKSStale) {
			t.Fatalf("err = %v, want ErrVerifyUnavailable wrapping ErrJWKSStale", err)
		}
		// Issuer back: the stale check refreshes and verification resumes.
		is.down.Store(false)
		cache.MinRefresh = time.Nanosecond
		cache.Now = v.Now
		if _, err := v.Verify(ctx, is.mint(t, k, g)); err != nil {
			t.Fatalf("after issuer returns: %v", err)
		}
	})

	t.Run("discovery issuer mismatch is refused", func(t *testing.T) {
		is := newIssuer(t, k)
		cache := &grant.Cache{IssuerURL: is.srv.URL + "/other"}
		if err := cache.Refresh(ctx); err == nil {
			t.Fatal("discovery with a mismatched issuer must fail")
		}
	})
}

// A burst of verifications for a kid the cache has never seen must all
// succeed on the one refresh they share, not race the rate limit into
// "no key": the herder mints a grant, announces it on the lane and
// clones with it in the same instant.
func TestJWKSConcurrentMissesShareOneRefresh(t *testing.T) {
	k, err := grant.GenerateKey(jose.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	is := newIssuer(t, k)
	c := &grant.Cache{IssuerURL: is.srv.URL}
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Key(context.Background(), k.KeyID); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent miss: %v", err)
	}
	if hits := is.jwksHits.Load(); hits != 1 {
		t.Fatalf("jwks fetched %d times, want once", hits)
	}
}
