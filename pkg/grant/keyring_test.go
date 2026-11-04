package grant_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/Azure/fiberd/pkg/grant"
)

// ringNow has no monotonic reading and no sub-second part, so it survives
// a JSON round trip unchanged.
var ringNow = time.Date(2026, time.October, 31, 12, 0, 0, 0, time.UTC)

func ringKey(t *testing.T, alg jose.SignatureAlgorithm) jose.JSONWebKey {
	t.Helper()
	k, err := grant.GenerateKey(alg)
	if err != nil {
		t.Fatalf("GenerateKey(%s): %v", alg, err)
	}
	return *k
}

func encodeRing(t *testing.T, r grant.KeyRing) []byte {
	t.Helper()
	raw, err := r.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return raw
}

func ringKIDs(r grant.KeyRing) []string {
	out := make([]string, 0, len(r))
	for _, k := range r {
		out = append(out, k.JWK.KeyID)
	}
	return out
}

func until(at time.Time) *time.Time { return &at }

// privateD is the base64url private parameter d of k, read from its own
// JSON.
func privateD(t *testing.T, k jose.JSONWebKey) string {
	t.Helper()
	raw, err := json.Marshal(k)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("decode key: %v", err)
	}
	d, _ := fields["d"].(string)
	if d == "" {
		t.Fatalf("key %q has no d in its JSON", k.KeyID)
	}
	return d
}

// memStore is a KeyStore in memory. Nil raw means nothing is stored.
type memStore struct {
	raw     []byte
	loads   int
	creates int
	// loadErr, when set, is asked before every load with the load's
	// number, counted from 1. A non-nil answer is what the load returns.
	loadErr func(n int) error
	// create, when set, replaces the store's create.
	create func(s *memStore, raw []byte) error
}

func (s *memStore) Load(context.Context) ([]byte, error) {
	s.loads++
	if s.loadErr != nil {
		if err := s.loadErr(s.loads); err != nil {
			return nil, err
		}
	}
	if s.raw == nil {
		return nil, grant.ErrNoKeyRing
	}
	return slices.Clone(s.raw), nil
}

func (s *memStore) Create(_ context.Context, raw []byte) error {
	s.creates++
	if s.create != nil {
		return s.create(s, raw)
	}
	if s.raw != nil {
		return grant.ErrKeyRingExists
	}
	s.raw = slices.Clone(raw)
	return nil
}

// TestDecodeKeyRing reads back what Encode wrote and refuses every ring
// an issuer must not sign or publish from. No error carries key material.
func TestDecodeKeyRing(t *testing.T) {
	current := ringKey(t, jose.EdDSA)
	older := ringKey(t, jose.ES256)
	oldest := ringKey(t, jose.EdDSA)

	mismatched := ringKey(t, jose.EdDSA)
	mismatched.Algorithm = string(jose.ES256)
	notAllowed := ringKey(t, jose.EdDSA)
	notAllowed.Algorithm = string(jose.HS256)
	encryption := ringKey(t, jose.EdDSA)
	encryption.Use = "enc"
	noKID := ringKey(t, jose.EdDSA)
	noKID.KeyID = ""
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongCurve := jose.JSONWebKey{Key: p384, KeyID: "p384", Algorithm: string(jose.ES256), Use: "sig"}
	secrets := []string{privateD(t, current), privateD(t, older), privateD(t, oldest), privateD(t, mismatched),
		privateD(t, notAllowed), privateD(t, encryption), privateD(t, noKID), privateD(t, wrongCurve)}

	cases := []struct {
		name string
		// raw is decoded when set, else ring encoded.
		raw  []byte
		ring grant.KeyRing
		// wantErr is a substring of the error. Empty means success.
		wantErr string
	}{
		{name: "one signing key", ring: grant.KeyRing{{JWK: current}}},
		{name: "every key newest first", ring: grant.KeyRing{
			{JWK: current},
			{JWK: older, SignedUntil: until(ringNow)},
			{JWK: oldest, SignedUntil: until(ringNow.Add(-time.Hour))},
		}},
		{name: "retired keys with equal signedUntil", ring: grant.KeyRing{
			{JWK: current},
			{JWK: older, SignedUntil: until(ringNow)},
			{JWK: oldest, SignedUntil: until(ringNow)},
		}},
		{name: "a retired first key still decodes", ring: grant.KeyRing{
			{JWK: current, SignedUntil: until(ringNow)},
			{JWK: older, SignedUntil: until(ringNow.Add(-time.Hour))},
		}},
		{name: "a use left empty", ring: func() grant.KeyRing {
			k := current
			k.Use = ""
			return grant.KeyRing{{JWK: k}}
		}()},

		{name: "no bytes", raw: []byte{}, wantErr: "grant: key ring: empty"},
		{name: "not JSON", raw: []byte("{not json"), wantErr: "decode"},
		{name: "an empty array", raw: []byte("[]"), wantErr: "holds no key"},
		{name: "null", raw: []byte("null"), wantErr: "holds no key"},
		{name: "public key only", ring: grant.KeyRing{{JWK: current.Public()}}, wantErr: "key 0: key " + fmt.Sprintf("%q", current.KeyID) + " holds no private key"},
		{name: "alg does not match the key", ring: grant.KeyRing{{JWK: mismatched}}, wantErr: "does not match its alg"},
		{name: "an ES256 key on the wrong curve", ring: grant.KeyRing{{JWK: wrongCurve}}, wantErr: "does not match its alg"},
		{name: "an alg fiberd does not accept", ring: grant.KeyRing{{JWK: notAllowed}}, wantErr: "fiberd accepts"},
		{name: "an encryption key", ring: grant.KeyRing{{JWK: encryption}}, wantErr: `use "enc"`},
		{name: "a key without a kid", ring: grant.KeyRing{{JWK: noKID}}, wantErr: "key 0: key has no kid"},
		{name: "a bad key after a good one", ring: grant.KeyRing{
			{JWK: current},
			{JWK: mismatched, SignedUntil: until(ringNow)},
		}, wantErr: "key 1:"},
		{name: "a retired key without signedUntil", ring: grant.KeyRing{
			{JWK: current},
			{JWK: older},
		}, wantErr: "key 1 has no signedUntil"},
		{name: "a retired key with a zero signedUntil", ring: grant.KeyRing{
			{JWK: current},
			{JWK: older, SignedUntil: &time.Time{}},
		}, wantErr: "key 1 has no signedUntil"},
		{name: "retired keys out of order", ring: grant.KeyRing{
			{JWK: current},
			{JWK: older, SignedUntil: until(ringNow.Add(-time.Hour))},
			{JWK: oldest, SignedUntil: until(ringNow)},
		}, wantErr: "key 2 has signedUntil"},
		// Regression: the order was checked from index 2 on only, so a
		// retired key 0 was never compared with key 1.
		{name: "a retired first key older than key 1", ring: grant.KeyRing{
			{JWK: current, SignedUntil: until(ringNow.Add(-time.Hour))},
			{JWK: older, SignedUntil: until(ringNow)},
		}, wantErr: "key 1 has signedUntil"},
		{name: "a repeated kid", ring: grant.KeyRing{
			{JWK: current},
			{JWK: current, SignedUntil: until(ringNow)},
		}, wantErr: "key 1 repeats kid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.raw
			if raw == nil {
				raw = encodeRing(t, tc.ring)
			}
			got, err := grant.DecodeKeyRing(raw)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("DecodeKeyRing = %v, want an error holding %q", ringKIDs(got), tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("DecodeKeyRing error %q does not hold %q", err, tc.wantErr)
				}
				for _, d := range secrets {
					if strings.Contains(err.Error(), d) {
						t.Errorf("DecodeKeyRing error %q carries private key material", err)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeKeyRing: %v", err)
			}
			if !reflect.DeepEqual(ringKIDs(got), ringKIDs(tc.ring)) {
				t.Fatalf("kids = %v, want %v", ringKIDs(got), ringKIDs(tc.ring))
			}
			for i := range got {
				if got[i].JWK.IsPublic() {
					t.Errorf("key %d lost its private half", i)
				}
				want, have := tc.ring[i].SignedUntil, got[i].SignedUntil
				if (want == nil) != (have == nil) || (want != nil && !want.Equal(*have)) {
					t.Errorf("key %d signedUntil = %v, want %v", i, have, want)
				}
			}
		})
	}
}

// TestLoadOrCreate drives LoadOrCreate over a store in memory. A ring is
// created only when nothing is stored, a lost race returns the winner, and
// a stored ring that does not decode is never overwritten.
func TestLoadOrCreate(t *testing.T) {
	present := ringKey(t, jose.EdDSA)
	older := ringKey(t, jose.ES256)
	winner := ringKey(t, jose.EdDSA)
	known := map[string]bool{present.KeyID: true, older.KeyID: true, winner.KeyID: true}

	presentData := encodeRing(t, grant.KeyRing{{JWK: present}})
	twoData := encodeRing(t, grant.KeyRing{{JWK: present}, {JWK: older, SignedUntil: until(ringNow)}})
	winnerData := encodeRing(t, grant.KeyRing{{JWK: winner}})
	brokenData := []byte("{not json")
	publicData := encodeRing(t, grant.KeyRing{{JWK: present.Public()}})
	unavailable := errors.New("store unavailable")
	es256 := func() (grant.KeyRing, error) { return grant.NewKeyRing(jose.ES256) }

	cases := []struct {
		name string
		// stored is what the store holds before the call, nil for nothing.
		stored   []byte
		loadErr  func(n int) error
		create   func(s *memStore, raw []byte) error
		generate func() (grant.KeyRing, error)
		nilStore bool

		wantCreates int
		// wantKIDs lists the returned kids. Nil means one fresh key.
		wantKIDs []string
		// wantAlg is the alg of a fresh key, EdDSA when empty.
		wantAlg jose.SignatureAlgorithm
		// wantErr is a substring of the error. Empty means success.
		wantErr string
		// wantErrIs, when set, must be wrapped in the error.
		wantErrIs error
		// wantStored is what the store must hold after the call. Nil
		// means what it held before, or the ring returned on success.
		wantStored []byte
	}{
		{name: "creates one EdDSA key when nothing is stored", wantCreates: 1},
		{name: "creates the ring generate makes", generate: es256, wantCreates: 1, wantAlg: jose.ES256},
		{name: "a wrapped no-ring answer still creates",
			loadErr: func(n int) error {
				if n == 1 {
					return fmt.Errorf("secret absent: %w", grant.ErrNoKeyRing)
				}
				return nil
			},
			wantCreates: 1},
		{name: "loads when present", stored: presentData, wantKIDs: []string{present.KeyID}},
		{name: "loads every key newest first", stored: twoData, wantKIDs: []string{present.KeyID, older.KeyID}},
		{name: "a lost create race returns the stored ring",
			create: func(s *memStore, _ []byte) error {
				// Another replica stores its ring first.
				s.raw = winnerData
				return fmt.Errorf("conflict: %w", grant.ErrKeyRingExists)
			},
			wantCreates: 1, wantKIDs: []string{winner.KeyID}, wantStored: winnerData},
		{name: "a lost create race to a ring that does not decode",
			create: func(s *memStore, _ []byte) error {
				s.raw = brokenData
				return grant.ErrKeyRingExists
			},
			wantCreates: 1, wantErr: "grant: stored key ring: decode", wantStored: brokenData},
		{name: "a lost create race and the re-read fails",
			loadErr: func(n int) error {
				if n > 1 {
					return unavailable
				}
				return nil
			},
			create:      func(*memStore, []byte) error { return grant.ErrKeyRingExists },
			wantCreates: 1, wantErr: "grant: load key ring", wantErrIs: unavailable},
		{name: "a lost create race but the re-read finds nothing",
			create:      func(*memStore, []byte) error { return grant.ErrKeyRingExists },
			wantCreates: 1, wantErr: "reads as missing", wantErrIs: grant.ErrNoKeyRing},
		{name: "create fails",
			create:      func(*memStore, []byte) error { return unavailable },
			wantCreates: 1, wantErr: "grant: create key ring", wantErrIs: unavailable},
		{name: "load fails", loadErr: func(int) error { return unavailable },
			wantErr: "grant: load key ring", wantErrIs: unavailable},
		{name: "a stored ring that does not decode is not overwritten", stored: brokenData, wantErr: "grant: stored key ring"},
		{name: "a stored public key is not overwritten", stored: publicData, wantErr: "holds no private key"},
		{name: "a stored empty value is not overwritten", stored: []byte{}, wantErr: "grant: stored key ring: empty"},
		{name: "generate fails",
			generate: func() (grant.KeyRing, error) { return nil, unavailable },
			wantErr:  "grant: generate key ring", wantErrIs: unavailable},
		{name: "a generated ring that does not decode is never stored",
			generate: func() (grant.KeyRing, error) { return grant.KeyRing{{JWK: present.Public()}}, nil },
			wantErr:  "grant: generated key ring"},
		{name: "no store", nilStore: true, wantErr: "needs a key store"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &memStore{raw: slices.Clone(tc.stored), loadErr: tc.loadErr, create: tc.create}
			var store grant.KeyStore = s
			if tc.nilStore {
				store = nil
			}
			got, err := grant.LoadOrCreate(t.Context(), store, tc.generate)
			if s.creates != tc.wantCreates {
				t.Errorf("Create called %d times, want %d", s.creates, tc.wantCreates)
			}

			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("LoadOrCreate = %v, want an error holding %q", ringKIDs(got), tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("LoadOrCreate error %q does not hold %q", err, tc.wantErr)
				}
				if tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs) {
					t.Errorf("LoadOrCreate error %q does not wrap %q", err, tc.wantErrIs)
				}
				if strings.Contains(err.Error(), privateD(t, present)) {
					t.Errorf("LoadOrCreate error %q carries private key material", err)
				}
				want := tc.wantStored
				if want == nil {
					want = tc.stored
				}
				if !slices.Equal(s.raw, want) {
					t.Errorf("store after the error holds %q, want %q", s.raw, want)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadOrCreate: %v", err)
			}

			if tc.wantKIDs != nil {
				if !reflect.DeepEqual(ringKIDs(got), tc.wantKIDs) {
					t.Errorf("kids = %v, want %v", ringKIDs(got), tc.wantKIDs)
				}
			} else {
				if len(got) != 1 {
					t.Fatalf("LoadOrCreate returned %d keys, want one fresh key", len(got))
				}
				wantAlg := tc.wantAlg
				if wantAlg == "" {
					wantAlg = jose.EdDSA
				}
				if fresh := got[0]; known[fresh.JWK.KeyID] || fresh.JWK.Algorithm != string(wantAlg) || fresh.SignedUntil != nil {
					t.Errorf("fresh key = %v, want a new unretired %s key", fresh, wantAlg)
				}
			}
			if _, err := got.Signing(); err != nil {
				t.Errorf("Signing on the returned ring: %v", err)
			}
			// The store holds exactly the returned ring.
			stored, err := grant.DecodeKeyRing(s.raw)
			if err != nil {
				t.Fatalf("decode the stored ring: %v", err)
			}
			if !reflect.DeepEqual(ringKIDs(stored), ringKIDs(got)) {
				t.Errorf("stored kids = %v, returned kids = %v", ringKIDs(stored), ringKIDs(got))
			}
			if tc.wantStored != nil && !slices.Equal(s.raw, tc.wantStored) {
				t.Errorf("store holds %q, want %q", s.raw, tc.wantStored)
			}
		})
	}
}

func TestKeyRingSigning(t *testing.T) {
	current := ringKey(t, jose.EdDSA)
	previous := ringKey(t, jose.ES256)
	mismatched := ringKey(t, jose.EdDSA)
	mismatched.Algorithm = string(jose.ES256)

	cases := []struct {
		name    string
		ring    grant.KeyRing
		wantKID string
		wantErr string
	}{
		{name: "one current key", ring: grant.KeyRing{{JWK: current}}, wantKID: current.KeyID},
		{name: "index 0 over a retired key", ring: grant.KeyRing{
			{JWK: current},
			{JWK: previous, SignedUntil: until(ringNow)},
		}, wantKID: current.KeyID},
		{name: "an ES256 current key", ring: grant.KeyRing{
			{JWK: previous},
			{JWK: current, SignedUntil: until(ringNow)},
		}, wantKID: previous.KeyID},
		{name: "a retired first key", ring: grant.KeyRing{
			{JWK: current, SignedUntil: until(ringNow)},
			{JWK: previous, SignedUntil: until(ringNow.Add(-time.Hour))},
		}, wantErr: "retired"},
		{name: "an empty ring", ring: grant.KeyRing{}, wantErr: "no signing key"},
		{name: "a nil ring", wantErr: "no signing key"},
		{name: "a public first key", ring: grant.KeyRing{{JWK: current.Public()}}, wantErr: "no private key"},
		{name: "a first key whose alg does not match", ring: grant.KeyRing{{JWK: mismatched}}, wantErr: "does not match its alg"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.ring.Signing()
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("Signing = %q, want an error holding %q", got.KeyID, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("Signing error %q does not hold %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Signing: %v", err)
			}
			if got.KeyID != tc.wantKID || got.IsPublic() {
				t.Fatalf("Signing = kid %q (public %v), want the private key %q", got.KeyID, got.IsPublic(), tc.wantKID)
			}
			// Signing returns a copy, so the ring keeps its key.
			got.KeyID = "changed"
			if tc.ring[0].JWK.KeyID != tc.wantKID {
				t.Errorf("changing the returned key changed the ring to %q", tc.ring[0].JWK.KeyID)
			}
		})
	}
}

func TestKeyRingPublic(t *testing.T) {
	current := ringKey(t, jose.EdDSA)
	previous := ringKey(t, jose.ES256)
	oldest := ringKey(t, jose.EdDSA)

	cases := []struct {
		name     string
		ring     grant.KeyRing
		wantKIDs []string
	}{
		{name: "no keys", wantKIDs: []string{}},
		{name: "one key", ring: grant.KeyRing{{JWK: current}}, wantKIDs: []string{current.KeyID}},
		{name: "every key, retired ones included", ring: grant.KeyRing{
			{JWK: current},
			{JWK: previous, SignedUntil: until(ringNow)},
			{JWK: oldest, SignedUntil: until(ringNow.Add(-time.Hour))},
		}, wantKIDs: []string{current.KeyID, previous.KeyID, oldest.KeyID}},
		// Regression: an invalid entry was served as an empty JWK.
		{name: "an invalid entry is left out", ring: grant.KeyRing{
			{JWK: current},
			{JWK: jose.JSONWebKey{KeyID: "invalid", Algorithm: string(jose.EdDSA)}, SignedUntil: until(ringNow)},
		}, wantKIDs: []string{current.KeyID}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set := tc.ring.Public()
			gotKIDs := []string{}
			for i := range set.Keys {
				k := &set.Keys[i]
				gotKIDs = append(gotKIDs, k.KeyID)
				if !k.IsPublic() || k.Algorithm == "" {
					t.Errorf("JWKS key %q is private or lost its alg", k.KeyID)
				}
			}
			if !reflect.DeepEqual(gotKIDs, tc.wantKIDs) {
				t.Errorf("JWKS kids = %v, want %v", gotKIDs, tc.wantKIDs)
			}
			raw, err := json.Marshal(set)
			if err != nil {
				t.Fatalf("marshal JWKS: %v", err)
			}
			var served struct {
				Keys []map[string]any `json:"keys"`
			}
			if err := json.Unmarshal(raw, &served); err != nil {
				t.Fatalf("decode JWKS: %v", err)
			}
			for _, k := range served.Keys {
				if _, ok := k["d"]; ok {
					t.Errorf("JWKS key %v carries the private field d", k["kid"])
				}
			}
			// Public never strips the ring's own keys.
			for i := range tc.ring {
				if tc.ring[i].JWK.IsPublic() {
					t.Errorf("Public made ring key %d public", i)
				}
			}
		})
	}
}

// TestStoredKeyRedacted proves fmt and a logr logger never show the
// private key of a StoredKey, while its JSON for the store still holds it.
func TestStoredKeyRedacted(t *testing.T) {
	keys := []grant.StoredKey{
		{JWK: ringKey(t, jose.EdDSA)},
		{JWK: ringKey(t, jose.ES256), SignedUntil: until(ringNow)},
	}

	cases := []struct {
		name   string
		format func(t *testing.T, k grant.StoredKey) string
		// keepsD is true for the store's own encoding, which must keep
		// the private key.
		keepsD bool
	}{
		{name: "String", format: func(_ *testing.T, k grant.StoredKey) string { return k.String() }},
		{name: "%v", format: func(_ *testing.T, k grant.StoredKey) string { return fmt.Sprintf("%v", k) }},
		{name: "%+v", format: func(_ *testing.T, k grant.StoredKey) string { return fmt.Sprintf("%+v", k) }},
		{name: "%#v", format: func(_ *testing.T, k grant.StoredKey) string { return fmt.Sprintf("%#v", k) }},
		{name: "%v of a pointer", format: func(_ *testing.T, k grant.StoredKey) string { return fmt.Sprintf("%v", &k) }},
		{name: "%+v inside a ring", format: func(_ *testing.T, k grant.StoredKey) string { return fmt.Sprintf("%+v", grant.KeyRing{k}) }},
		{name: "MarshalLog", format: func(_ *testing.T, k grant.StoredKey) string { return fmt.Sprintf("%+v", k.MarshalLog()) }},
		{name: "MarshalLog as JSON", format: func(t *testing.T, k grant.StoredKey) string {
			raw, err := json.Marshal(k.MarshalLog())
			if err != nil {
				t.Fatalf("marshal MarshalLog: %v", err)
			}
			return string(raw)
		}},
		{name: "the StoredKey as JSON", keepsD: true, format: func(t *testing.T, k grant.StoredKey) string {
			raw, err := json.Marshal(k)
			if err != nil {
				t.Fatalf("marshal StoredKey: %v", err)
			}
			return string(raw)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range keys {
				d := privateD(t, k.JWK)
				got := tc.format(t, k)
				if strings.Contains(got, d) != tc.keepsD {
					t.Errorf("%s of key %q holds its private d: %v, want %v", tc.name, k.JWK.KeyID, !tc.keepsD, tc.keepsD)
				}
				if !strings.Contains(got, k.JWK.KeyID) {
					t.Errorf("%s of key %q = %q, want the kid shown", tc.name, k.JWK.KeyID, got)
				}
			}
		})
	}
}
