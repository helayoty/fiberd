package grant

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// StoredKey is one entry of a KeyRing. SignedUntil is unset for the key
// that signs today and holds a time once the key has been superseded. A
// superseded key stays in the ring so that homes can still verify the
// grants it signed.
//
// JWK holds private key material, and json.Marshal writes it out because
// the store needs it. String, GoString and MarshalLog show only the kid,
// the alg and SignedUntil, so fmt and a logr logger print a StoredKey
// without key material. A KeyRing handed to a logger is still encoded
// with json.Marshal, so log the kids of a ring and never the ring itself.
type StoredKey struct {
	JWK         jose.JSONWebKey `json:"jwk"`
	SignedUntil *time.Time      `json:"signedUntil,omitempty"`
}

// storedKeyLog is the form of a StoredKey that logs and fmt may show.
type storedKeyLog struct {
	KID         string     `json:"kid"`
	Alg         string     `json:"alg"`
	SignedUntil *time.Time `json:"signedUntil,omitempty"`
}

// retired reports whether k has been superseded. A zero time counts as
// unset.
func (k StoredKey) retired() bool { return k.SignedUntil != nil && !k.SignedUntil.IsZero() }

// signedUntilText is SignedUntil in RFC 3339, or "unset" for the signing
// key.
func (k StoredKey) signedUntilText() string {
	if !k.retired() {
		return "unset"
	}
	return k.SignedUntil.UTC().Format(time.RFC3339)
}

// String implements fmt.Stringer without key material.
func (k StoredKey) String() string {
	return fmt.Sprintf("{kid=%q alg=%q signedUntil=%s}", k.JWK.KeyID, k.JWK.Algorithm, k.signedUntilText())
}

// GoString implements fmt.GoStringer, which %#v uses, without key
// material.
func (k StoredKey) GoString() string {
	return fmt.Sprintf("grant.StoredKey{KID:%q, Alg:%q, SignedUntil:%q}", k.JWK.KeyID, k.JWK.Algorithm, k.signedUntilText())
}

// MarshalLog implements logr.Marshaler. A logr sink encodes what it
// returns in place of the StoredKey, so a logged key never carries key
// material.
func (k StoredKey) MarshalLog() any {
	return storedKeyLog{KID: k.JWK.KeyID, Alg: k.JWK.Algorithm, SignedUntil: k.SignedUntil}
}

// KeyRing is an issuer's signing keys, newest first. Index 0 signs today.
// Every later entry is retired, and the ring keeps it so that its public
// half stays in the JWKS while grants it signed are still live.
type KeyRing []StoredKey

// NewKeyRing is a ring of one fresh key for alg, made by GenerateKey.
func NewKeyRing(alg jose.SignatureAlgorithm) (KeyRing, error) {
	jwk, err := GenerateKey(alg)
	if err != nil {
		return nil, fmt.Errorf("grant: generate signing key: %w", err)
	}
	return KeyRing{{JWK: *jwk}}, nil
}

// DecodeKeyRing reads a ring that Encode wrote. It refuses an empty ring,
// an entry that is not a private signing key fiberd accepts, a repeated
// kid, and an order that is not newest first. Only index 0 may lack a
// SignedUntil, and no SignedUntil is later than the one before it. Every
// error names the entry by index. None carries key material.
func DecodeKeyRing(raw []byte) (KeyRing, error) {
	r, err := decodeKeyRing(raw)
	if err != nil {
		return nil, fmt.Errorf("grant: key ring: %w", err)
	}
	return r, nil
}

func decodeKeyRing(raw []byte) (KeyRing, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty")
	}
	var r KeyRing
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if len(r) == 0 {
		return nil, errors.New("holds no key")
	}
	kids := make([]string, 0, len(r))
	for i := range r {
		if err := checkRingKey(&r[i].JWK); err != nil {
			return nil, fmt.Errorf("key %d: %w", i, err)
		}
		kid := r[i].JWK.KeyID
		if slices.Contains(kids, kid) {
			return nil, fmt.Errorf("key %d repeats kid %q", i, kid)
		}
		kids = append(kids, kid)
		if i == 0 {
			continue
		}
		if !r[i].retired() {
			return nil, fmt.Errorf("key %d has no signedUntil, but only key 0 may sign", i)
		}
		// Index 0 may be retired too, so key 1 is compared with it as
		// well as every later key with the one before it.
		if prev := r[i-1]; prev.retired() && r[i].SignedUntil.After(*prev.SignedUntil) {
			return nil, fmt.Errorf("key %d has signedUntil %s, later than %s of key %d, but keys must be newest first",
				i, r[i].signedUntilText(), prev.signedUntilText(), i-1)
		}
	}
	return r, nil
}

// Encode is the ring as JSON, private keys included, for a KeyStore.
func (r KeyRing) Encode() ([]byte, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("grant: encode key ring: %w", err)
	}
	return raw, nil
}

// Signing returns a copy of the key that signs today, which is index 0
// while it is not retired. It is an error when the ring is empty, when its
// first key is retired, or when that key is not a private key fiberd
// accepts.
func (r KeyRing) Signing() (*jose.JSONWebKey, error) {
	if len(r) == 0 {
		return nil, errors.New("grant: key ring holds no signing key")
	}
	first := r[0]
	if first.retired() {
		return nil, fmt.Errorf("grant: the newest key %q was retired at %s, no key signs today",
			first.JWK.KeyID, first.signedUntilText())
	}
	if err := checkRingKey(&first.JWK); err != nil {
		return nil, fmt.Errorf("grant: signing key: %w", err)
	}
	k := first.JWK
	return &k, nil
}

// Public is the public half of every key, retired ones included. It is
// the JWKS an issuer with this ring serves.
//
// A ring assigned directly rather than read by DecodeKeyRing may hold an
// invalid or symmetric key. Its public copy would be an empty JWK, served
// as {}. Public skips such an entry.
func (r KeyRing) Public() jose.JSONWebKeySet {
	set := jose.JSONWebKeySet{}
	for i := range r {
		if !r[i].JWK.Valid() {
			continue
		}
		pub := r[i].JWK.Public()
		if pub.Key == nil {
			continue
		}
		set.Keys = append(set.Keys, pub)
	}
	return set
}

// checkRingKey accepts a private signing key with a kid whose algorithm
// fiberd allows and whose key type matches that algorithm.
func checkRingKey(k *jose.JSONWebKey) error {
	if !k.Valid() {
		return errors.New("not a valid JWK")
	}
	if k.IsPublic() {
		return fmt.Errorf("key %q holds no private key", k.KeyID)
	}
	if k.KeyID == "" {
		return errors.New("key has no kid")
	}
	if k.Use != "" && k.Use != "sig" {
		return fmt.Errorf("key %q has use %q, want sig", k.KeyID, k.Use)
	}
	alg := jose.SignatureAlgorithm(k.Algorithm)
	if !allowed(alg) {
		return fmt.Errorf("key %q has alg %q, fiberd accepts %v", k.KeyID, k.Algorithm, AllowedAlgorithms)
	}
	var match bool
	switch alg {
	case jose.EdDSA:
		_, match = k.Key.(ed25519.PrivateKey)
	case jose.ES256:
		ec, ok := k.Key.(*ecdsa.PrivateKey)
		match = ok && ec.Curve == elliptic.P256()
	}
	if !match {
		return fmt.Errorf("key %q does not match its alg %q", k.KeyID, k.Algorithm)
	}
	return nil
}

// Key store errors.
var (
	// ErrNoKeyRing is KeyStore.Load's answer when nothing is stored.
	ErrNoKeyRing = errors.New("grant: no key ring is stored")
	// ErrKeyRingExists is KeyStore.Create's answer when a ring is already
	// stored, such as when another replica created it first.
	ErrKeyRingExists = errors.New("grant: a key ring is already stored")
)

// KeyStore keeps an encoded KeyRing. The Kubernetes controller backs it
// with a Secret. Load returns ErrNoKeyRing, possibly wrapped, when
// nothing is stored. Create stores raw only when nothing is stored yet,
// and returns ErrKeyRingExists, possibly wrapped, otherwise. Create never
// overwrites a stored ring.
type KeyStore interface {
	Load(ctx context.Context) ([]byte, error)
	Create(ctx context.Context, raw []byte) error
}

// LoadOrCreate returns the ring in store. When nothing is stored it
// stores the ring generate makes. A nil generate makes one EdDSA key. A
// create that loses a race to another replica re-reads the store and
// returns what it holds, so every replica signs with the same key.
//
// A stored ring that does not decode is an error. It is never
// overwritten, because that would drop keys homes still trust.
func LoadOrCreate(ctx context.Context, store KeyStore, generate func() (KeyRing, error)) (KeyRing, error) {
	if store == nil {
		return nil, errors.New("grant: LoadOrCreate needs a key store")
	}
	if generate == nil {
		generate = func() (KeyRing, error) { return NewKeyRing(jose.EdDSA) }
	}

	r, err := loadKeyRing(ctx, store)
	if err == nil {
		return r, nil
	}
	if !errors.Is(err, ErrNoKeyRing) {
		return nil, err
	}

	fresh, err := generate()
	if err != nil {
		return nil, fmt.Errorf("grant: generate key ring: %w", err)
	}
	raw, err := fresh.Encode()
	if err != nil {
		return nil, err
	}
	// A ring that cannot be read back would stop every replica, and it is
	// never overwritten. Check it before it is stored, and return it as
	// every later load will see it.
	r, err = decodeKeyRing(raw)
	if err != nil {
		return nil, fmt.Errorf("grant: generated key ring: %w", err)
	}
	err = store.Create(ctx, raw)
	switch {
	case err == nil:
		return r, nil
	case errors.Is(err, ErrKeyRingExists):
		// Another replica stored a ring between the load and the create.
		// Its keys win and the ones generated here are dropped.
		stored, rerr := loadKeyRing(ctx, store)
		if errors.Is(rerr, ErrNoKeyRing) {
			return nil, fmt.Errorf("grant: the key ring was already stored but reads as missing: %w", rerr)
		}
		return stored, rerr
	default:
		return nil, fmt.Errorf("grant: create key ring: %w", err)
	}
}

// loadKeyRing reads and decodes the stored ring. Nothing stored is
// returned as ErrNoKeyRing.
func loadKeyRing(ctx context.Context, store KeyStore) (KeyRing, error) {
	raw, err := store.Load(ctx)
	if err != nil {
		if errors.Is(err, ErrNoKeyRing) {
			return nil, err
		}
		return nil, fmt.Errorf("grant: load key ring: %w", err)
	}
	r, err := decodeKeyRing(raw)
	if err != nil {
		return nil, fmt.Errorf("grant: stored key ring: %w", err)
	}
	return r, nil
}
