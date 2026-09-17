package grant_test

import (
	"crypto/hmac"
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
		Policy: core.Policy{Durability: core.Sync, PSISomeAvg10Park: 20},
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	for _, alg := range []jose.SignatureAlgorithm{jose.EdDSA, jose.ES256} {
		t.Run(string(alg), func(t *testing.T) {
			key, err := grant.GenerateKey(alg)
			if err != nil {
				t.Fatal(err)
			}
			g := sample(now)
			tok, err := grant.Sign(g, key, now)
			if err != nil {
				t.Fatal(err)
			}
			h, err := grant.Parse(tok)
			if err != nil || h.KeyID != key.KeyID || h.Algorithm != alg {
				t.Fatalf("parse = %+v %v, want kid %s alg %s", h, err, key.KeyID, alg)
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

func TestVerifyRejections(t *testing.T) {
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

	cases := []struct {
		name   string
		token  string
		pub    *jose.JSONWebKey
		opts   grant.VerifyOptions
		want   error // errors.Is target, or nil to only require failure
		wantOK bool
	}{
		{name: "good", token: good, pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}, wantOK: true},
		{name: "wrong audience", token: good, pub: &pub, opts: grant.VerifyOptions{Audience: "node-b"}, want: grant.ErrWrongAudience},
		{name: "empty audience option", token: good, pub: &pub, opts: grant.VerifyOptions{}, want: grant.ErrWrongAudience},
		{name: "wrong issuer", token: good, pub: &pub, opts: grant.VerifyOptions{Audience: "node-a", Issuer: "https://other"}, want: grant.ErrWrongIssuer},
		{name: "wrong key", token: good, pub: ptr(other.Public()), opts: grant.VerifyOptions{Audience: "node-a"}},
		{name: "key alg mismatch", token: good, pub: ptr(ecKey.Public()), opts: grant.VerifyOptions{Audience: "node-a"}, want: grant.ErrKeyMismatchAlg},
		{name: "tampered payload", token: parts[0] + "." + tamper(t, parts[1]) + "." + parts[2], pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}},
		{name: "alg none", token: algNone(parts[1]), pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}},
		{name: "alg HS256 with public key bytes", token: hs256(t, parts[1], pub), pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}},
		{name: "garbage", token: "not.a.jwt", pub: &pub, opts: grant.VerifyOptions{Audience: "node-a"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := grant.Verify(tc.token, tc.pub, tc.opts)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("verified, want rejection")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestExpiredTokenVerifiesButLeaseIsPast(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	key, _ := grant.GenerateKey(jose.ES256)
	pub := key.Public()
	g := sample(now)
	g.LeaseExpiry = now.Add(-time.Hour)
	tok, err := grant.Sign(g, key, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := grant.Verify(tok, &pub, grant.VerifyOptions{Audience: "node-a"})
	if err != nil {
		t.Fatalf("expired token must still verify (expiry is the ledger's miss, not an auth error): %v", err)
	}
	if !got.Expired(now) {
		t.Fatal("lease not reported expired")
	}
}

func TestClaimMismatchIsRejected(t *testing.T) {
	// A token whose registered jti disagrees with grant.grant_uid: re-sign
	// the payload honestly with the same key so only the mismatch is at
	// fault.
	now := time.Unix(1_700_000_000, 0).UTC()
	key, _ := grant.GenerateKey(jose.EdDSA)
	pub := key.Public()
	tok, err := grant.Sign(sample(now), key, now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var m map[string]any
	_ = json.Unmarshal(payload, &m)
	m["jti"] = "someone-else"
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	b, _ := json.Marshal(m)
	obj, err := signer.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	forged, _ := obj.CompactSerialize()
	if _, err := grant.Verify(forged, &pub, grant.VerifyOptions{Audience: "node-a"}); !errors.Is(err, grant.ErrClaimMismatch) {
		t.Fatalf("err = %v, want ErrClaimMismatch", err)
	}
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
