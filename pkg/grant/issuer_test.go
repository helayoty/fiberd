package grant_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
)

// serveIssuer mounts an Issuer at the root of a test server whose URL
// is the issuer identifier.
func serveIssuer(t *testing.T, key *jose.JSONWebKey, now func() time.Time) *grant.Issuer {
	t.Helper()
	is := &grant.Issuer{Key: key, Now: now}
	var h http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	is.URL = srv.URL + "/"
	h = is.Handler()
	return is
}

// The reference issuer is what a Cache and Verifier expect. A grant it
// mints verifies through its own discovery and key set, with the issuer
// claim forced to its URL and iat taken from its clock.
func TestIssuerServesItsOwnVerifier(t *testing.T) {
	cases := []struct {
		name string
		alg  jose.SignatureAlgorithm
		now  func() time.Time // nil uses the wall clock
	}{
		{name: "an EdDSA issuer on the wall clock", alg: jose.EdDSA},
		{name: "an ES256 issuer on a fixed clock", alg: jose.ES256, now: func() time.Time { return time.Unix(1_700_000_000, 0) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := grant.GenerateKey(tc.alg)
			if err != nil {
				t.Fatal(err)
			}
			is := serveIssuer(t, key, tc.now)
			at := time.Now()
			if tc.now != nil {
				at = tc.now()
			}
			tok, err := is.Mint(core.Grant{UID: "g-1", Issuer: "https://someone-else", Audience: "node-a",
				LeaseExpiry: at.Add(10 * time.Minute)})
			if err != nil {
				t.Fatal(err)
			}
			// The wall clock may tick a second between at and Mint.
			if iat, _ := claims(t, tok)["iat"].(float64); int64(iat) < at.Unix() || int64(iat) > at.Unix()+1 {
				t.Fatalf("iat = %v, want the issuer clock %d", iat, at.Unix())
			}
			cache := &grant.Cache{IssuerURL: is.URL}
			v := &grant.Verifier{Cache: cache, Audience: "node-a", MaxLease: 10 * time.Minute,
				Now: func() time.Time { return cache.LastRefresh() }}
			g, err := v.Verify(context.Background(), []byte(tok))
			if err != nil {
				t.Fatalf("verify against the issuer's own endpoints: %v", err)
			}
			if g.Issuer != is.URL || g.UID != "g-1" {
				t.Fatalf("verified grant = %+v, want issuer %q and uid g-1", g, is.URL)
			}

			set := is.JWKS()
			if len(set.Keys) != 1 || !set.Keys[0].IsPublic() || set.Keys[0].KeyID != key.KeyID {
				t.Fatalf("JWKS = %+v, want the public half of kid %s only", set, key.KeyID)
			}
		})
	}
}

// claims decodes a token's payload without verifying it.
func claims(t *testing.T, tok string) map[string]any {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// The discovery document and key set are served with the fields and
// headers OIDC clients rely on, and only for GET.
func TestIssuerHandler(t *testing.T) {
	key, err := grant.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	is := serveIssuer(t, key, nil)
	base := strings.TrimSuffix(is.URL, "/")

	cases := []struct {
		name       string
		method     string
		path       string
		wantStatus int
		wantCache  string
		check      func(t *testing.T, body []byte)
	}{
		{name: "discovery names the issuer without a trailing slash and the jwks uri",
			method: http.MethodGet, path: "/.well-known/openid-configuration", wantStatus: http.StatusOK,
			check: func(t *testing.T, body []byte) {
				var d map[string]any
				if err := json.Unmarshal(body, &d); err != nil {
					t.Fatal(err)
				}
				if d["issuer"] != base || d["jwks_uri"] != base+"/openid/v1/jwks" {
					t.Fatalf("discovery = %v", d)
				}
				if algs, _ := d["id_token_signing_alg_values_supported"].([]any); len(algs) != 1 || algs[0] != "ES256" {
					t.Fatalf("algs = %v, want [ES256]", d["id_token_signing_alg_values_supported"])
				}
			}},
		{name: "the key set is public and cacheable",
			method: http.MethodGet, path: "/openid/v1/jwks", wantStatus: http.StatusOK, wantCache: "public, max-age=60",
			check: func(t *testing.T, body []byte) {
				var set jose.JSONWebKeySet
				if err := json.Unmarshal(body, &set); err != nil {
					t.Fatal(err)
				}
				if len(set.Keys) != 1 || !set.Keys[0].IsPublic() || strings.Contains(string(body), `"d"`) {
					t.Fatalf("jwks leaks private material or is wrong: %s", body)
				}
			}},
		{name: "a POST to the key set is refused", method: http.MethodPost, path: "/openid/v1/jwks", wantStatus: http.StatusMethodNotAllowed},
		{name: "an unknown path is not found", method: http.MethodGet, path: "/token", wantStatus: http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, base+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			if got := resp.Header.Get("Cache-Control"); got != tc.wantCache {
				t.Fatalf("Cache-Control = %q, want %q", got, tc.wantCache)
			}
			if tc.check == nil {
				return
			}
			if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
				t.Fatalf("Content-Type = %q, want application/json", ct)
			}
			var body json.RawMessage
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			tc.check(t, body)
		})
	}
}

func TestIssuerMintRefuses(t *testing.T) {
	key, err := grant.GenerateKey(jose.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	g := core.Grant{UID: "g-1", Audience: "node-a"}
	cases := []struct {
		name string
		is   *grant.Issuer
	}{
		{name: "an issuer without a key", is: &grant.Issuer{URL: "https://issuer.test"}},
		{name: "an issuer without a URL", is: &grant.Issuer{Key: key}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := tc.is.Mint(g)
			if err == nil || tok != "" || !strings.Contains(err.Error(), "needs a key and a URL") {
				t.Fatalf("Mint = %q, %v, want a refusal", tok, err)
			}
		})
	}
}

// PeekUID reads jti without trusting the token, so even a token signed by
// a stranger yields its UID, and only an unparsable one fails.
func TestPeekUID(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	stranger, err := grant.GenerateKey(jose.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := grant.Sign(sample(now), stranger, now)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	notJSON := enc([]byte(`{"alg":"EdDSA","kid":"k"}`)) + "." + enc([]byte("not json")) + "." + enc([]byte("sig"))
	hs := enc([]byte(`{"alg":"HS256"}`)) + "." + enc([]byte(`{"jti":"g-1"}`)) + "." + enc([]byte("sig"))

	cases := []struct {
		name    string
		token   string
		want    string
		wantErr bool
	}{
		{name: "a token signed by anyone yields its jti", token: forged, want: "g-1"},
		{name: "garbage fails", token: "not-a-jwt", wantErr: true},
		{name: "a payload that is not JSON fails", token: notJSON, wantErr: true},
		{name: "a disallowed algorithm fails", token: hs, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := grant.PeekUID(tc.token)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("PeekUID = %q, %v, want %q (error %v)", got, err, tc.want, tc.wantErr)
			}
		})
	}
}
