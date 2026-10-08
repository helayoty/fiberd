package grant_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

// One verifier runs against one issuer in order. Discovery and the key set
// are fetched once and known kids verify from memory. Unknown kids inside
// MinRefresh are refused without a refetch. A rotated kid triggers exactly
// one refresh once the rate limit passes.
func TestJWKSDiscoveryRotationAndRateLimit(t *testing.T) {
	k1, _ := grant.GenerateKey(jose.EdDSA)
	k2, _ := grant.GenerateKey(jose.ES256)
	is := newIssuer(t, k1)
	cache := &grant.Cache{IssuerURL: is.srv.URL, MinRefresh: time.Hour}
	v := &grant.Verifier{Cache: cache, Audience: "node-a", MaxStale: time.Hour}
	ctx := context.Background()
	g := core.Grant{UID: "g1", Audience: "node-a", FiberMax: 1}

	steps := []struct {
		name     string
		before   func()
		key      *jose.JSONWebKey
		repeat   int   // verifications in this step, 0 means one
		wantErr  error // errors.Is target, nil requires success
		wantDisc int32 // cumulative discovery hits after the step
		wantJWKS int32 // cumulative jwks hits after the step
	}{
		{name: "cold cache with the issuer up discovers and fetches once", key: k1, wantDisc: 1, wantJWKS: 1},
		{name: "a known kid verifies from memory", key: k1, wantDisc: 1, wantJWKS: 1},
		// An unknown kid is not refetched while the last load is inside
		// MinRefresh, so a flood of bad kids cannot hammer the issuer.
		{name: "unknown kids inside MinRefresh are refused without a refetch", key: k2, repeat: 3,
			wantErr: grant.ErrUnknownKey, wantDisc: 1, wantJWKS: 1},
		// Discovery is not repeated because jwks_uri is remembered.
		{name: "a rotated kid triggers exactly one refresh once the rate limit passes",
			before: func() {
				is.rotate(k2)
				cache.MinRefresh = time.Nanosecond
			},
			key: k2, wantDisc: 1, wantJWKS: 2},
	}
	for _, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			if st.before != nil {
				st.before()
			}
			for i := 0; i < max(st.repeat, 1); i++ {
				_, err := v.Verify(ctx, is.mint(t, st.key, g))
				if !errors.Is(err, st.wantErr) {
					t.Fatalf("verify = %v, want %v", err, st.wantErr)
				}
				// The issuer is up throughout, so an unknown kid with a fresh
				// cache is an auth failure, never unavailability.
				if errors.Is(err, core.ErrVerifyUnavailable) {
					t.Fatalf("verify = %v, want an auth failure, not unavailability", err)
				}
			}
			if d, j := is.discHits.Load(), is.jwksHits.Load(); d != st.wantDisc || j != st.wantJWKS {
				t.Fatalf("discovery/jwks hits = %d/%d, want %d/%d", d, j, st.wantDisc, st.wantJWKS)
			}
		})
	}
}

// The cache with the issuer unreachable. A cold cache cannot verify. A warm
// one verifies offline until the key set is older than MaxStale, and
// recovers once the issuer returns. Expired grants verify too, because the
// ledger turns a past lease into the miss code. A discovery document naming
// another issuer is refused outright.
func TestJWKSOffline(t *testing.T) {
	k, _ := grant.GenerateKey(jose.EdDSA)
	ctx := context.Background()

	cases := []struct {
		name           string
		issuerPath     string // appended to the issuer URL the cache trusts
		warm           bool   // refresh the cache while the issuer is up
		wantRefreshErr bool   // that refresh must fail and nothing further runs
		maxStale       time.Duration
		age            time.Duration // verifier clock past the refresh
		lease          time.Duration // lease expiry from now, 0 is none
		want           []error       // errors.Is targets, empty requires success
		wantExpired    bool
		recovers       bool // issuer returns and the next verify must succeed
	}{
		{name: "cold cache, issuer down: unavailable, never loaded",
			want: []error{core.ErrVerifyUnavailable, grant.ErrNeverLoaded}},
		{name: "warm cache, issuer down: verifies", warm: true, maxStale: time.Hour},
		{name: "warm cache, issuer down: an expired grant verifies and reports its lease past",
			warm: true, maxStale: time.Hour, lease: -time.Minute, wantExpired: true},
		{name: "cache older than MaxStale: unavailable even for a known kid, until the issuer returns",
			warm: true, maxStale: 10 * time.Minute, age: 11 * time.Minute,
			want: []error{core.ErrVerifyUnavailable, grant.ErrJWKSStale}, recovers: true},
		{name: "discovery issuer mismatch is refused", issuerPath: "/other", warm: true, wantRefreshErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			is := newIssuer(t, k)
			now := time.Now()
			cache := &grant.Cache{IssuerURL: is.srv.URL + tc.issuerPath, MinRefresh: time.Hour, Now: func() time.Time { return now }}
			if tc.warm {
				err := cache.Refresh(ctx)
				if tc.wantRefreshErr {
					if err == nil {
						t.Fatal("refresh = nil, want an error")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			g := core.Grant{UID: "g1", Audience: "node-a"}
			if tc.lease != 0 {
				g.LeaseExpiry = now.Add(tc.lease)
			}
			tok := is.mint(t, k, g)
			is.down.Store(true)
			at := now.Add(tc.age)
			v := &grant.Verifier{Cache: cache, Audience: "node-a", MaxStale: tc.maxStale, Now: func() time.Time { return at }}

			got, err := v.Verify(ctx, tok)
			if len(tc.want) == 0 && err != nil {
				t.Fatalf("verify = %v, want success", err)
			}
			for _, w := range tc.want {
				if !errors.Is(err, w) {
					t.Fatalf("verify = %v, want it to wrap %v", err, w)
				}
			}
			if err == nil && got.Expired(at) != tc.wantExpired {
				t.Fatalf("Expired = %v, want %v", got.Expired(at), tc.wantExpired)
			}
			if tc.recovers {
				is.down.Store(false)
				cache.MinRefresh = time.Nanosecond
				cache.Now = v.Now
				if _, err := v.Verify(ctx, is.mint(t, k, g)); err != nil {
					t.Fatalf("after issuer returns: %v", err)
				}
			}
		})
	}
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
	cases := []struct {
		name    string
		callers int
	}{
		{name: "a single cold miss fetches the key set once", callers: 1},
		{name: "a burst of concurrent cold misses shares that one fetch", callers: 16},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			is := newIssuer(t, k)
			c := &grant.Cache{IssuerURL: is.srv.URL}
			var wg sync.WaitGroup
			errs := make(chan error, tc.callers)
			for i := 0; i < tc.callers; i++ {
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
		})
	}
}

// A refresh that cannot produce a usable key set fails, leaves the cache
// unloaded and does not fire OnRefresh. A good one skips keys a verifier
// must not use and reports its time to the hook.
func TestCacheRefresh(t *testing.T) {
	good, _ := grant.GenerateKey(jose.EdDSA)
	priv, _ := grant.GenerateKey(jose.ES256)
	noKid, _ := grant.GenerateKey(jose.EdDSA)
	noKidPub := noKid.Public()
	noKidPub.KeyID = ""
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()

	// The handlers see the server URL through self, set once it exists.
	type handlers struct {
		disc func(w http.ResponseWriter, self string)
		jwks func(w http.ResponseWriter)
	}
	discOK := func(w http.ResponseWriter, self string) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": self + "/", "jwks_uri": self + "/jwks"})
	}
	jwksOf := func(keys ...jose.JSONWebKey) func(http.ResponseWriter) {
		return func(w http.ResponseWriter) { _ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: keys}) }
	}

	cases := []struct {
		name       string
		issuerURL  string // overrides the test server when set
		h          handlers
		wantErr    string
		wantKey    string // a kid that must resolve after success
		wantNoKeys []string
	}{
		{name: "a set with unusable keys keeps only the usable ones",
			h:       handlers{disc: discOK, jwks: jwksOf(good.Public(), *priv, noKidPub)},
			wantKey: good.KeyID, wantNoKeys: []string{priv.KeyID}},
		{name: "a set of only unusable keys fails",
			h: handlers{disc: discOK, jwks: jwksOf(*priv, noKidPub)}, wantErr: "no usable public keys"},
		{name: "an empty set fails",
			h: handlers{disc: discOK, jwks: jwksOf()}, wantErr: "no usable public keys"},
		{name: "a cache without an issuer URL fails", issuerURL: "-", wantErr: "no issuer URL"},
		{name: "a malformed issuer URL fails", issuerURL: "http://bad\x00host", wantErr: "invalid control character"},
		{name: "an unreachable issuer fails", issuerURL: closed.URL, wantErr: "discovery"},
		{name: "a discovery document that is not JSON fails",
			h: handlers{disc: func(w http.ResponseWriter, _ string) { _, _ = w.Write([]byte("<html>")) }}, wantErr: "discovery"},
		{name: "a discovery document for another issuer fails",
			h: handlers{disc: func(w http.ResponseWriter, self string) {
				_ = json.NewEncoder(w).Encode(map[string]string{"issuer": "https://evil.test", "jwks_uri": self + "/jwks"})
			}}, wantErr: "does not match"},
		{name: "a discovery document without jwks_uri fails",
			h: handlers{disc: func(w http.ResponseWriter, self string) {
				_ = json.NewEncoder(w).Encode(map[string]string{"issuer": self})
			}}, wantErr: "no jwks_uri"},
		{name: "a key set answered with an error status fails",
			h:       handlers{disc: discOK, jwks: func(w http.ResponseWriter) { http.Error(w, "boom", http.StatusInternalServerError) }},
			wantErr: "http 500"},
		{name: "a key set cut short fails",
			h: handlers{disc: discOK, jwks: func(w http.ResponseWriter) {
				w.Header().Set("Content-Length", "4096")
				_, _ = w.Write([]byte(`{"keys":[`))
				w.(http.Flusher).Flush()
				panic(http.ErrAbortHandler)
			}},
			wantErr: "unexpected EOF"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var self string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/.well-known/openid-configuration" && tc.h.disc != nil:
					tc.h.disc(w, self)
				case r.URL.Path == "/jwks" && tc.h.jwks != nil:
					tc.h.jwks(w)
				default:
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(srv.Close)
			self = srv.URL
			url := srv.URL
			switch tc.issuerURL {
			case "":
			case "-":
				url = ""
			default:
				url = tc.issuerURL
			}
			var hooked []time.Time
			c := &grant.Cache{IssuerURL: url, MinRefresh: time.Hour, OnRefresh: func(at time.Time) { hooked = append(hooked, at) }}

			err := c.Refresh(context.Background())
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Refresh = %v, want an error containing %q", err, tc.wantErr)
				}
				if !c.LastRefresh().IsZero() || len(hooked) != 0 {
					t.Fatalf("failed refresh left LastRefresh %v and %d hook calls", c.LastRefresh(), len(hooked))
				}
				// A verifier asking for any key now sees the outage, not a bad kid.
				if _, err := c.Key(context.Background(), "any"); !errors.Is(err, grant.ErrNeverLoaded) {
					t.Fatalf("Key after a failed load = %v, want ErrNeverLoaded", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(hooked) != 1 || !hooked[0].Equal(c.LastRefresh()) {
				t.Fatalf("hook calls = %v, want one at LastRefresh %v", hooked, c.LastRefresh())
			}
			if _, err := c.Key(context.Background(), tc.wantKey); err != nil {
				t.Fatalf("Key(%s) = %v", tc.wantKey, err)
			}
			for _, kid := range tc.wantNoKeys {
				if _, err := c.Key(context.Background(), kid); !errors.Is(err, grant.ErrUnknownKey) {
					t.Fatalf("Key(%s) = %v, want ErrUnknownKey", kid, err)
				}
			}
		})
	}
}

// Run loads the set at once, keeps refreshing on its ticker through
// failures, and returns when its context ends.
func TestCacheRun(t *testing.T) {
	k, _ := grant.GenerateKey(jose.EdDSA)
	cases := []struct {
		name      string
		down      bool
		wantHooks int   // OnRefresh calls to wait for before cancelling
		wantReqs  int32 // issuer requests to wait for
	}{
		{name: "an issuer that is up is refreshed on every tick", wantHooks: 3, wantReqs: 3},
		{name: "an issuer that is down is retried on every tick", down: true, wantReqs: 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			is := newIssuer(t, k)
			is.down.Store(tc.down)
			hooks := make(chan time.Time, 16)
			c := &grant.Cache{IssuerURL: is.srv.URL, OnRefresh: func(at time.Time) {
				select {
				case hooks <- at:
				default:
				}
			}}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { c.Run(ctx, time.Millisecond); close(done) }()

			deadline := time.After(10 * time.Second)
			for got := 0; got < tc.wantHooks; got++ {
				select {
				case <-hooks:
				case <-deadline:
					t.Fatalf("saw %d refreshes, want %d", got, tc.wantHooks)
				}
			}
			// A down issuer never fires the hook, so count its attempts.
			for is.jwksHits.Load()+is.discHits.Load() < tc.wantReqs {
				select {
				case <-deadline:
					t.Fatalf("issuer saw %d requests, want %d", is.jwksHits.Load()+is.discHits.Load(), tc.wantReqs)
				case <-time.After(time.Millisecond):
				}
			}
			cancel()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("Run did not return after cancel")
			}
			if tc.down && len(hooks) != 0 {
				t.Fatalf("a down issuer fired OnRefresh %d times", len(hooks))
			}
		})
	}
}
