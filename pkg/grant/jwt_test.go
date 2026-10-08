package grant_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
)

func sample(now time.Time) core.Grant {
	return core.Grant{
		UID: "g-1", Issuer: "https://issuer.test", Audience: "node-a",
		TemplateDigest: "sha256:abc", FiberMax: 4, FiberWarm: 1, WBudgetBytes: 1 << 20,
		MinTier: core.TierWarm, LeaseExpiry: now.Add(10 * time.Minute).Truncate(time.Second),
		Policy:           core.Policy{Durability: core.Sync, PSISomeAvg10Park: 20, Isolation: core.Trusted, EndpointMode: core.EndpointHandoff},
		CallerThumbprint: "x5t-of-the-caller",
		DeviceBudget:     core.DeviceBudget{Bytes: 1 << 30, Class: "gpu"},
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	cases := []struct {
		name string
		alg  jose.SignatureAlgorithm
	}{
		{name: "an EdDSA key signs, verifies and survives a save and reload", alg: jose.EdDSA},
		{name: "an ES256 key signs, verifies and survives a save and reload", alg: jose.ES256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := grant.GenerateKey(tc.alg)
			if err != nil {
				t.Fatal(err)
			}
			g := sample(now)
			tok, err := grant.Sign(g, key, now)
			if err != nil {
				t.Fatal(err)
			}
			h, err := grant.Parse(tok)
			if err != nil || h.KeyID != key.KeyID || h.Algorithm != tc.alg {
				t.Fatalf("parse = %+v %v, want kid %s alg %s", h, err, key.KeyID, tc.alg)
			}
			pub := key.Public()
			got, err := grant.Verify(tok, &pub, grant.VerifyOptions{Audience: "node-a", Issuer: "https://issuer.test"})
			if err != nil {
				t.Fatal(err)
			}
			if got != g {
				t.Fatalf("round trip\n got %+v\nwant %+v", got, g)
			}
			// Persist and reload the private key; still signs and verifies.
			path := filepath.Join(t.TempDir(), "key.json")
			if err := grant.SaveKey(path, key); err != nil {
				t.Fatal(err)
			}
			loaded, err := grant.LoadKey(path)
			if err != nil {
				t.Fatal(err)
			}
			tok2, err := grant.Sign(g, loaded, now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := grant.Verify(tok2, &pub, grant.VerifyOptions{Audience: "node-a"}); err != nil {
				t.Fatalf("verify with reloaded key: %v", err)
			}
		})
	}
}

// Verify accepts a well-formed grant signed by the given key and refuses
// everything else. That covers a wrong audience, issuer, key or algorithm,
// a tampered, unsigned or oversized token, a lease longer than allowed, and
// a jti that disagrees with grant_uid. An expired lease is not an auth
// error. It verifies, and the ledger turns it into the miss code.
func TestVerify(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	key, _ := grant.GenerateKey(jose.EdDSA)
	other, _ := grant.GenerateKey(jose.EdDSA)
	ecKey, _ := grant.GenerateKey(jose.ES256)
	pub := key.Public()
	g := sample(now)
	good, err := grant.Sign(g, key, now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(good, ".")
	unleased := sample(now)
	unleased.LeaseExpiry = time.Time{}
	noLease, err := grant.Sign(unleased, key, now)
	if err != nil {
		t.Fatal(err)
	}
	lapsed := sample(now)
	lapsed.LeaseExpiry = now.Add(-time.Hour)
	expired, err := grant.Sign(lapsed, ecKey, now)
	if err != nil {
		t.Fatal(err)
	}
	// withUID forges the sample under uid with the right key. Sign refuses
	// a non-DNS-1123 UID, so the claims are rewritten instead.
	withUID := func(uid string) string { return reuid(t, good, key, uid) }
	// edited re-signs good honestly after edit, so only the edit is at fault.
	edited := func(edit func(map[string]any)) string { return rewrite(t, good, key, edit) }
	noGrant := edited(func(m map[string]any) { delete(m, "grant") })
	badGrant := edited(func(m map[string]any) { m["grant"] = map[string]any{"fibers": "many"} })
	emptyCnf := edited(func(m map[string]any) { m["cnf"] = map[string]any{"x5t#S256": ""} })
	noExp := edited(func(m map[string]any) { delete(m, "exp") })
	laterExp := edited(func(m map[string]any) { m["exp"] = m["exp"].(float64) + 60 })
	noIat := edited(func(m map[string]any) { delete(m, "iat") })
	twoAud := edited(func(m map[string]any) { m["aud"] = []string{"node-a", "node-b"} })

	cases := []struct {
		name        string
		token       string
		pub         *jose.JSONWebKey
		opts        grant.VerifyOptions
		want        error  // errors.Is target, or nil to only require failure
		wantMsg     string // substring the error must carry, when there is no sentinel
		wantOK      bool
		wantExpired bool // on success, the verified lease is already past
	}{
		{name: "good", token: good, pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}, wantOK: true},
		{name: "wrong audience", token: good, pub: &pub, opts: grant.VerifyOptions{Audience: "node-b"}, want: grant.ErrWrongAudience},
		{name: "empty audience option", token: good, pub: &pub, opts: grant.VerifyOptions{}, want: grant.ErrWrongAudience},
		{name: "wrong issuer", token: good, pub: &pub, opts: grant.VerifyOptions{Audience: "node-a", Issuer: "https://other"}, want: grant.ErrWrongIssuer},
		{name: "no key", token: good, pub: nil, opts: grant.VerifyOptions{Audience: "node-a"}, wantMsg: "no key"},
		{name: "a token without the grant claim", token: noGrant, pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}, want: grant.ErrMissingGrant},
		{name: "a grant claim that is not a CapacityGrant", token: badGrant, pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}, wantMsg: "decode grant claim"},
		{name: "a cnf claim without a thumbprint", token: emptyCnf, pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}, wantMsg: "x5t#S256"},
		{name: "a lease without exp", token: noExp, pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}, want: grant.ErrClaimMismatch},
		{name: "an exp that disagrees with the lease", token: laterExp, pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}, want: grant.ErrClaimMismatch},
		{name: "two audiences", token: twoAud, pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}, want: grant.ErrClaimMismatch},
		{name: "no iat under a max lease", token: noIat, pub: &pub, opts: grant.VerifyOptions{Audience: "node-a", MaxLease: time.Hour}, want: grant.ErrLeaseTooLong},
		{name: "wrong key", token: good, pub: ptr(other.Public()), opts: grant.VerifyOptions{Audience: "node-a"}},
		{name: "key alg mismatch", token: good, pub: ptr(ecKey.Public()), opts: grant.VerifyOptions{Audience: "node-a"}, want: grant.ErrKeyMismatchAlg},
		{name: "tampered payload", token: parts[0] + "." + tamper(t, parts[1]) + "." + parts[2], pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}},
		{name: "alg none", token: algNone(parts[1]), pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}},
		{name: "alg HS256 with public key bytes", token: hs256(t, parts[1], pub), pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}},
		{name: "garbage", token: "not.a.jwt", pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}},
		{name: "oversized token is refused before parsing", token: good + strings.Repeat("A", grant.MaxTokenBytes), pub: &pub,
			opts: grant.VerifyOptions{Audience: "node-a"}, want: grant.ErrTokenTooLarge},
		{name: "lease within max", token: good, pub: &pub, opts: grant.VerifyOptions{Audience: "node-a", MaxLease: 10 * time.Minute}, wantOK: true},
		{name: "lease above max", token: good, pub: &pub, opts: grant.VerifyOptions{Audience: "node-a", MaxLease: 5 * time.Minute}, want: grant.ErrLeaseTooLong},
		{name: "no lease under a max", token: noLease, pub: &pub, opts: grant.VerifyOptions{Audience: "node-a", MaxLease: time.Hour}, want: grant.ErrLeaseTooLong},
		{name: "no lease without a max", token: noLease, pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}, wantOK: true},
		{name: "expired token still verifies and reports its lease past", token: expired, pub: ptr(ecKey.Public()),
			opts: grant.VerifyOptions{Audience: "node-a"}, wantOK: true, wantExpired: true},
		// Re-signed honestly with the same key so only the mismatch is at fault.
		{name: "jti that disagrees with grant_uid", token: reclaim(t, good, key, "someone-else"), pub: &pub,
			opts: grant.VerifyOptions{Audience: "node-a"}, want: grant.ErrClaimMismatch},
		// The UID lands in cgroup and run-dir paths and the zygote line,
		// so it must be a DNS-1123 label.
		{name: "a UUID uid verifies", token: withUID("0b8e6c1e-4f5a-4d2b-9c3e-1a2b3c4d5e6f"), pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}, wantOK: true},
		{name: "a substrate uid verifies", token: withUID("at-0123abcd"), pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}, wantOK: true},
		{name: "a storm uid verifies", token: withUID("storm-123"), pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}, wantOK: true},
		{name: "a conformance uid verifies", token: withUID("c1-13311bb7"), pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}, wantOK: true},
		{name: "a 63-character uid verifies", token: withUID(strings.Repeat("a", 63)), pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}, wantOK: true},
		{name: "a 64-character uid is refused", token: withUID(strings.Repeat("a", 64)), pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}, want: grant.ErrBadUID},
		{name: "an uppercase uid is refused", token: withUID("G-1"), pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}, want: grant.ErrBadUID},
		{name: "a uid with an underscore is refused", token: withUID("g_1"), pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}, want: grant.ErrBadUID},
		{name: "a uid with a dot is refused", token: withUID("g.1"), pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}, want: grant.ErrBadUID},
		{name: "a dot-dot uid is refused", token: withUID(".."), pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}, want: grant.ErrBadUID},
		{name: "a leading hyphen is refused", token: withUID("-g1"), pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}, want: grant.ErrBadUID},
		{name: "a trailing hyphen is refused", token: withUID("g1-"), pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}, want: grant.ErrBadUID},
		{name: "a path-traversal uid is refused", token: withUID("../etc"), pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}, want: grant.ErrBadUID},
		{name: "a uid with a slash is refused", token: withUID("a/b"), pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}, want: grant.ErrBadUID},
		{name: "a uid with a space or newline is refused", token: withUID("a b\nCLONE x"), pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}, want: grant.ErrBadUID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := grant.Verify(tc.token, tc.pub, tc.opts)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got.Expired(now) != tc.wantExpired {
					t.Fatalf("Expired(now) = %v, want %v", got.Expired(now), tc.wantExpired)
				}
				return
			}
			if err == nil {
				t.Fatal("verified, want rejection")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.wantMsg)
			}
		})
	}
}

// reuid rewrites both jti and grant_uid, so the token is consistent and
// only the UID itself is wrong.
func reuid(t *testing.T, tok string, key *jose.JSONWebKey, uid string) string {
	t.Helper()
	return rewrite(t, tok, key, func(m map[string]any) {
		m["jti"] = uid
		if g, ok := m["grant"].(map[string]any); ok {
			for _, k := range []string{"grantUid", "grant_uid"} {
				if _, ok := g[k]; ok {
					g[k] = uid
				}
			}
		}
	})
}

// reclaim re-signs tok with a new jti, so the signature is valid and only
// the claims disagree.
func reclaim(t *testing.T, tok string, key *jose.JSONWebKey, jti string) string {
	t.Helper()
	return rewrite(t, tok, key, func(m map[string]any) { m["jti"] = jti })
}

// rewrite re-signs tok's claims with key after edit.
func rewrite(t *testing.T, tok string, key *jose.JSONWebKey, edit func(map[string]any)) string {
	t.Helper()
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(m)
	obj, err := signer.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return forged
}

func ptr(k jose.JSONWebKey) *jose.JSONWebKey { return &k }

func tamper(t *testing.T, b64 string) string {
	t.Helper()
	payload, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Replace(string(payload), `"max":4`, `"max":400`, 1)
	if s == string(payload) {
		t.Fatal("tamper target not found in payload")
	}
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func algNone(payload string) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT","kid":"x"}`))
	return hdr + "." + payload + "."
}

func hs256(t *testing.T, payload string, pub jose.JSONWebKey) string {
	t.Helper()
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT","kid":"` + pub.KeyID + `"}`))
	pubBytes, err := pub.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, pubBytes)
	mac.Write([]byte(hdr + "." + payload))
	return hdr + "." + payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Sign refuses anything a home would refuse later, and any key that
// cannot produce an allowed signature.
func TestSignRefuses(t *testing.T) {
	key, err := grant.GenerateKey(jose.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public()
	now := time.Unix(1_700_000_000, 0).UTC()
	cases := []struct {
		name    string
		edit    func(*core.Grant)
		key     *jose.JSONWebKey // nil signs with an EdDSA key
		noKey   bool             // sign with a nil key
		wantErr error            // errors.Is target
		wantMsg string           // substring of the error, when there is no sentinel
	}{
		{name: "a DNS-1123 label signs", edit: func(g *core.Grant) { g.UID = "storm-123" }},
		{name: "uppercase is refused at signing", edit: func(g *core.Grant) { g.UID = "Storm" }, wantErr: grant.ErrBadUID},
		{name: "a path is refused at signing", edit: func(g *core.Grant) { g.UID = "../g" }, wantErr: grant.ErrBadUID},
		{name: "an empty uid is refused", edit: func(g *core.Grant) { g.UID = "" }, wantMsg: "required to sign"},
		{name: "an empty issuer is refused", edit: func(g *core.Grant) { g.Issuer = "" }, wantMsg: "required to sign"},
		{name: "an empty audience is refused", edit: func(g *core.Grant) { g.Audience = "" }, wantMsg: "required to sign"},
		{name: "no key is refused", noKey: true, wantMsg: "private key"},
		{name: "a public key is refused", key: &pub, wantMsg: "private key"},
		{name: "an HS256 key is refused", key: &jose.JSONWebKey{Key: []byte("secret"), Algorithm: string(jose.HS256)}, wantMsg: "not allowed"},
		{name: "an alg that does not fit the key material is refused",
			key: &jose.JSONWebKey{Key: ec, Algorithm: string(jose.EdDSA), KeyID: "k"}, wantMsg: "algorithm"},
		{name: "a grant that protojson cannot encode is refused",
			edit: func(g *core.Grant) { g.Audience = "node-\xff" }, wantMsg: "UTF-8"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := sample(now)
			if tc.edit != nil {
				tc.edit(&g)
			}
			k := tc.key
			if k == nil && !tc.noKey {
				k = key
			}
			tok, err := grant.Sign(g, k, now)
			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Sign = %v, want %v", err, tc.wantErr)
				}
			case tc.wantMsg != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantMsg) {
					t.Fatalf("Sign = %v, want an error containing %q", err, tc.wantMsg)
				}
			default:
				if err != nil || tok == "" {
					t.Fatalf("Sign = %q, %v, want a token", tok, err)
				}
			}
			if err != nil && tok != "" {
				t.Fatalf("Sign returned token %q with error %v", tok, err)
			}
		})
	}
}
