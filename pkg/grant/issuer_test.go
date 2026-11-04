package grant_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/Azure/fiberd/pkg/core"
	"github.com/Azure/fiberd/pkg/grant"
)

// serveIssuer mounts an Issuer at the root of a test server whose URL
// is the issuer identifier.
func serveIssuer(t *testing.T, key *jose.JSONWebKey, now func() time.Time) *grant.Issuer {
	t.Helper()
	return serve(t, &grant.Issuer{Key: key, Now: now})
}

// serve mounts is at the root of a test server and sets its URL to the
// server's.
func serve(t *testing.T, is *grant.Issuer) *grant.Issuer {
	t.Helper()
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
				LeaseExpiry: at.Add(10 * time.Minute).Truncate(time.Second)})
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
	// A well-formed token padded past the size limit. Verify refuses it
	// before parsing, and so must the peek, or the limit is no bound.
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: stranger}, nil)
	if err != nil {
		t.Fatal(err)
	}
	big, err := jwt.Signed(signer).Claims(map[string]any{"jti": "g-1", "pad": strings.Repeat("x", grant.MaxTokenBytes)}).Serialize()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		token   string
		want    string
		wantErr bool
		wantIs  error // the error wanted, when one in particular is due
	}{
		{name: "a token signed by anyone yields its jti", token: forged, want: "g-1"},
		{name: "garbage fails", token: "not-a-jwt", wantErr: true},
		{name: "a payload that is not JSON fails", token: notJSON, wantErr: true},
		{name: "a disallowed algorithm fails", token: hs, wantErr: true},
		{name: "a token over the size limit fails unparsed", token: big, wantErr: true, wantIs: grant.ErrTokenTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := grant.PeekUID(tc.token)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("PeekUID = %q, %v, want %q (error %v)", got, err, tc.want, tc.wantErr)
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("PeekUID = %v, want %v", err, tc.wantIs)
			}
		})
	}
}

// PeekExpiry reads exp without trusting the token, so even a token signed
// by a stranger yields its expiry, and a token without exp or one that
// does not parse fails.
func TestPeekExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	stranger, err := grant.GenerateKey(jose.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	withExp, err := grant.Sign(sample(now), stranger, now)
	if err != nil {
		t.Fatal(err)
	}
	g := sample(now)
	g.LeaseExpiry = time.Time{}
	withoutExp, err := grant.Sign(g, stranger, now)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	hs := enc([]byte(`{"alg":"HS256"}`)) + "." + enc([]byte(`{"exp":1700000600}`)) + "." + enc([]byte("sig"))
	// A token with an exp padded past the size limit. Verify refuses it
	// before parsing, and so must the peek, or the limit is no bound.
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: stranger}, nil)
	if err != nil {
		t.Fatal(err)
	}
	big, err := jwt.Signed(signer).Claims(map[string]any{"exp": 1_700_000_600, "pad": strings.Repeat("x", grant.MaxTokenBytes)}).Serialize()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		token   string
		want    time.Time
		wantErr bool
		wantIs  error // the error wanted, when one in particular is due
	}{
		{name: "a token signed by anyone yields its exp", token: withExp, want: sample(now).LeaseExpiry},
		{name: "a token without exp fails", token: withoutExp, wantErr: true},
		{name: "garbage fails", token: "not-a-jwt", wantErr: true},
		{name: "a disallowed algorithm fails", token: hs, wantErr: true},
		{name: "a token over the size limit fails unparsed", token: big, wantErr: true, wantIs: grant.ErrTokenTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := grant.PeekExpiry(tc.token)
			if (err != nil) != tc.wantErr || !got.Equal(tc.want) {
				t.Fatalf("PeekExpiry = %s, %v, want %s (error %v)", got, err, tc.want, tc.wantErr)
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Fatalf("PeekExpiry = %v, want %v", err, tc.wantIs)
			}
		})
	}
}

// issueT0 is a whole second, so a lease from it is whole seconds too.
var issueT0 = time.Unix(1_700_000_000, 0).UTC()

// Mint refuses a grant Validate refuses, before anything is signed.
func TestIssuerMintValidates(t *testing.T) {
	key, err := grant.GenerateKey(jose.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	is := &grant.Issuer{Key: key, URL: "https://issuer.test", Now: func() time.Time { return issueT0 }}
	cases := []struct {
		name    string
		mutate  func(g *core.Grant)
		wantErr string
	}{
		{name: "a valid grant is minted"},
		{name: "a digest that holds whitespace", mutate: func(g *core.Grant) { g.TemplateDigest = "sha256:abc def" }, wantErr: "templateDigest"},
		{name: "a fractional lease expiry", mutate: func(g *core.Grant) { g.LeaseExpiry = g.LeaseExpiry.Add(250 * time.Millisecond) }, wantErr: "leaseExpiry"},
		{name: "a negative fiberMax", mutate: func(g *core.Grant) { g.FiberMax = -1 }, wantErr: "fiberMax -1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := sample(issueT0)
			if tc.mutate != nil {
				tc.mutate(&g)
			}
			tok, err := is.Mint(g)
			if tc.wantErr == "" {
				if err != nil || tok == "" {
					t.Fatalf("Mint = %q, %v, want a token", tok, err)
				}
				return
			}
			if err == nil || tok != "" || !strings.HasPrefix(err.Error(), "grant: invalid grant: ") || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Mint = %q, %v, want an invalid grant error holding %q", tok, err, tc.wantErr)
			}
		})
	}
}

// An issuer with a Ring signs with its newest key and publishes every
// key, so a verifier still trusts grants the older key signed.
func TestIssuerRing(t *testing.T) {
	newest := ringKey(t, jose.EdDSA)
	older := ringKey(t, jose.ES256)
	ring := grant.KeyRing{{JWK: newest}, {JWK: older, SignedUntil: until(ringNow)}}
	is := serve(t, &grant.Issuer{Ring: ring, Now: func() time.Time { return issueT0 }})
	base := strings.TrimSuffix(is.URL, "/")

	cases := []struct {
		name  string
		check func(t *testing.T)
	}{
		{name: "Mint signs with the newest key", check: func(t *testing.T) {
			tok, err := is.Mint(sample(issueT0))
			if err != nil {
				t.Fatal(err)
			}
			h, err := grant.Parse(tok)
			if err != nil || h.KeyID != newest.KeyID || h.Algorithm != jose.EdDSA {
				t.Fatalf("header = %+v, %v, want kid %s", h, err, newest.KeyID)
			}
			pub := newest.Public()
			if _, err := grant.Verify(tok, &pub, grant.VerifyOptions{Audience: "node-a", Issuer: is.URL}); err != nil {
				t.Fatalf("verify with the newest key: %v", err)
			}
		}},
		{name: "the JWKS lists both keys, public only", check: func(t *testing.T) {
			set := is.JWKS()
			var kids []string
			for i := range set.Keys {
				if !set.Keys[i].IsPublic() {
					t.Errorf("JWKS key %q is private", set.Keys[i].KeyID)
				}
				kids = append(kids, set.Keys[i].KeyID)
			}
			if !slices.Equal(kids, []string{newest.KeyID, older.KeyID}) {
				t.Fatalf("JWKS kids = %v, want %v", kids, []string{newest.KeyID, older.KeyID})
			}
		}},
		{name: "discovery lists the alg of each key", check: func(t *testing.T) {
			resp, err := http.Get(base + "/.well-known/openid-configuration")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			var d struct {
				Algs []string `json:"id_token_signing_alg_values_supported"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(d.Algs, []string{"EdDSA", "ES256"}) {
				t.Fatalf("algs = %v, want [EdDSA ES256]", d.Algs)
			}
		}},
		{name: "a ring whose newest key is retired mints nothing", check: func(t *testing.T) {
			retired := &grant.Issuer{URL: is.URL, Ring: grant.KeyRing{{JWK: newest, SignedUntil: until(ringNow)}}}
			if tok, err := retired.Mint(sample(issueT0)); err == nil || tok != "" || !strings.Contains(err.Error(), "retired") {
				t.Fatalf("Mint = %q, %v, want a refusal naming the retired key", tok, err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, tc.check)
	}
}

// craft signs claims with key the way Sign would not, to build tokens
// Renew must refuse. A nil std.IssuedAt leaves iat out.
func craft(t *testing.T, key any, alg jose.SignatureAlgorithm, std jwt.Claims, g core.Grant) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := protojson.Marshal(grant.ToProto(g))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.Signed(signer).Claims(std).Claims(map[string]any{"grant": json.RawMessage(body)}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// Renew signs the same grant again for a fresh lease of the same length,
// and only for a token this issuer signed whose claims agree.
func TestIssuerRenew(t *testing.T) {
	const url = "https://issuer.test"
	current := ringKey(t, jose.EdDSA)
	retired := ringKey(t, jose.ES256)
	stranger := ringKey(t, jose.EdDSA)
	sameKID := stranger
	sameKID.KeyID = current.KeyID
	// esSameKID names the issuer's EdDSA key but signs with ES256.
	esSameKID := ringKey(t, jose.ES256)
	esSameKID.KeyID = current.KeyID
	is := &grant.Issuer{
		Ring: grant.KeyRing{{JWK: current}, {JWK: retired, SignedUntil: until(issueT0)}},
		URL:  url, Now: func() time.Time { return issueT0 },
	}
	g := sample(issueT0) // a ten minute lease
	g.Issuer = url
	const lease = 10 * time.Minute

	mint := func(g core.Grant) string {
		tok, err := is.Mint(g)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	sign := func(g core.Grant, key jose.JSONWebKey) string {
		tok, err := grant.Sign(g, &key, issueT0)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	minted := mint(g)
	noLease := g
	noLease.LeaseExpiry = time.Time{}
	elsewhere := g
	elsewhere.Issuer = "https://elsewhere.test"
	std := jwt.Claims{Issuer: url, Audience: jwt.Audience{"node-a"}, ID: g.UID, Expiry: jwt.NewNumericDate(g.LeaseExpiry)}
	otherJTI := std
	otherJTI.ID = "g-2"
	otherJTI.IssuedAt = jwt.NewNumericDate(issueT0)
	// zeroLease has iat equal to exp, which still matches the grant's lease
	// expiry.
	zeroLease := std
	zeroLease.IssuedAt = jwt.NewNumericDate(g.LeaseExpiry)
	// tampered is minted with its grant claim edited after signing.
	parts := strings.Split(minted, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatal(err)
	}
	m["grant"].(map[string]any)["tenant"] = "team-b"
	edited, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(edited) + "." + parts[2]

	cases := []struct {
		name  string
		token string
		at    time.Time
		is    *grant.Issuer // nil uses is
		// wantErr is a substring of the error, empty for a renewal.
		wantErr   string
		wantErrIs error
	}{
		{name: "the grant is kept and iat and exp move by the same lease", token: minted, at: issueT0.Add(7*time.Minute + 500*time.Millisecond)},
		{name: "an expired token is renewed", token: minted, at: issueT0.Add(time.Hour)},
		{name: "a token from the retired key is renewed with the newest", token: sign(g, retired), at: issueT0.Add(5 * time.Minute)},
		{name: "a token signed by a stranger", token: sign(g, stranger), at: issueT0, wantErrIs: grant.ErrUnknownKey},
		{name: "a stranger's key reusing the issuer's kid", token: sign(g, sameKID), at: issueT0, wantErr: "grant: signature"},
		{name: "a tampered grant claim", token: tampered, at: issueT0, wantErr: "grant: signature"},
		{name: "an ES256 token naming the issuer's EdDSA kid", token: craft(t, &esSameKID, jose.ES256, otherJTI, g), at: issueT0, wantErrIs: grant.ErrKeyMismatchAlg},
		{name: "a token whose exp equals its iat", token: craft(t, &current, jose.EdDSA, zeroLease, g), at: issueT0, wantErr: "renew needs a positive lease"},
		{name: "a jti that disagrees with the grant claim", token: craft(t, &current, jose.EdDSA, otherJTI, g), at: issueT0, wantErrIs: grant.ErrClaimMismatch},
		{name: "a token another issuer named", token: sign(elsewhere, current), at: issueT0, wantErrIs: grant.ErrWrongIssuer},
		{name: "a token without exp", token: mint(noLease), at: issueT0, wantErr: "exp and iat"},
		{name: "a token without iat", token: craft(t, &current, jose.EdDSA, std, g), at: issueT0, wantErr: "exp and iat"},
		{name: "a token without a kid", token: craft(t, current.Key, jose.EdDSA, otherJTI, g), at: issueT0, wantErrIs: grant.ErrNoKID},
		{name: "garbage", token: "not-a-jwt", at: issueT0, wantErr: "grant: parse"},
		{name: "an issuer without a key", token: minted, at: issueT0, is: &grant.Issuer{URL: url}, wantErr: "needs a key and a URL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			renewer := is
			if tc.is != nil {
				renewer = tc.is
			}
			tok, err := renewer.Renew(tc.token, tc.at)
			if tc.wantErr != "" || tc.wantErrIs != nil {
				if err == nil || tok != "" {
					t.Fatalf("Renew = %q, %v, want a refusal", tok, err)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("Renew error %q does not hold %q", err, tc.wantErr)
				}
				if tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs) {
					t.Errorf("Renew error %q does not wrap %q", err, tc.wantErrIs)
				}
				return
			}
			if err != nil {
				t.Fatalf("Renew: %v", err)
			}
			if h, err := grant.Parse(tok); err != nil || h.KeyID != current.KeyID {
				t.Fatalf("renewed header = %+v, %v, want the newest kid %s", h, err, current.KeyID)
			}
			c := claims(t, tok)
			at := tc.at.Truncate(time.Second)
			iat, _ := c["iat"].(float64)
			exp, _ := c["exp"].(float64)
			if int64(iat) != at.Unix() || int64(exp) != at.Add(lease).Unix() {
				t.Fatalf("iat, exp = %v, %v, want %d, %d", iat, exp, at.Unix(), at.Add(lease).Unix())
			}
			if c["jti"] != g.UID || c["iss"] != url || c["aud"] != "node-a" {
				t.Fatalf("registered claims = %v, want jti %s, iss %s and aud node-a", c, g.UID, url)
			}
			pub := current.Public()
			got, err := grant.Verify(tok, &pub, grant.VerifyOptions{Audience: "node-a", Issuer: url, MaxLease: lease})
			if err != nil {
				t.Fatalf("verify the renewed token: %v", err)
			}
			want := g
			want.LeaseExpiry = at.Add(lease)
			if got != want {
				t.Fatalf("renewed grant\n got %+v\nwant %+v", got, want)
			}
		})
	}
}
