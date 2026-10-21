package artifact

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// The fleet wrap key and sealed author images.
//
// An author's images.tar is the zygote's memory at READY, made off-home
// by a party that holds no master. zygotectl build seals it under a fresh
// random content key in the chunked stream format, and wraps that key to
// the fleet's X25519 public key with HPKE (DHKEM X25519, HKDF-SHA256,
// AES-256-GCM, base mode). The pair derives from the master, so every
// home re-derives the private half and nothing new is kept. Authors hold
// the public half only, which opens nothing.
//
// The wrapped key, the HPKE encapsulation, the wrap key id and the
// plaintext tar's sha256 travel twice. They sit in the sealed file's
// header, which is the associated data of every chunk, and they are
// returned as ImagesSeal for config.json. The open requires the two to
// agree and the HPKE info binds the wrapped key to the sha and the key
// id, so none of them moves between artifacts.

// wrapKeyID prefixes the public key when its kid is hashed.
const wrapKeyID = "fiberd-wrap-kid\n"

// imagesDomain is the seal label of an author's images.
const imagesDomain = "images:"

// WrapKey is the fleet's X25519 key pair. The private half is derived
// on a home from the master and never serialised.
type WrapKey struct {
	ID   string
	priv *ecdh.PrivateKey
}

// WrapPublicKey is the public half authors seal images to.
type WrapPublicKey struct {
	ID  string
	pub *ecdh.PublicKey
}

// DeriveWrapKey derives the fleet wrap pair from the master seal key.
// The same master always gives the same pair and the same key id.
func DeriveWrapKey(k *SealKey) (*WrapKey, error) {
	if k == nil {
		return nil, errors.New("artifact: no seal key")
	}
	seed, err := hkdf.Key(sha256.New, k.Key, nil, infoWrap, 32)
	if err != nil {
		return nil, err
	}
	priv, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		return nil, err
	}
	return &WrapKey{ID: wrapKID(priv.PublicKey().Bytes()), priv: priv}, nil
}

func wrapKID(pub []byte) string {
	sum := sha256.Sum256(append([]byte(wrapKeyID), pub...))
	return base64.RawURLEncoding.EncodeToString(sum[:12])
}

// Public returns the half authors get.
func (w *WrapKey) Public() *WrapPublicKey {
	return &WrapPublicKey{ID: w.ID, pub: w.priv.PublicKey()}
}

// PublicJWK is the public half as an OKP X25519 JWK with a kid, what
// grant-issuer keygen writes to fleet-pub.json.
func (w *WrapKey) PublicJWK() ([]byte, error) {
	return w.Public().JWK()
}

// okpJWK is the JWK shape of an X25519 key. go-jose knows Ed25519 under
// OKP only, so this one is read and written here.
type okpJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	D   string `json:"d,omitempty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
}

// JWK renders the public key as an OKP X25519 JWK.
func (p *WrapPublicKey) JWK() ([]byte, error) {
	return json.MarshalIndent(okpJWK{Kty: "OKP", Crv: "X25519",
		X: base64.RawURLEncoding.EncodeToString(p.pub.Bytes()), Kid: p.ID, Use: "enc", Alg: "ECDH-ES"}, "", "  ")
}

// ParseWrapPublicKey reads an OKP X25519 public JWK. The kid must be the
// one its public key gives, so a mislabelled file is refused.
func ParseWrapPublicKey(b []byte) (*WrapPublicKey, error) {
	var j okpJWK
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, fmt.Errorf("artifact: wrap key: %w", err)
	}
	if j.Kty != "OKP" || j.Crv != "X25519" {
		return nil, errors.New("artifact: wrap key: want an OKP X25519 JWK")
	}
	if j.D != "" {
		return nil, errors.New("artifact: wrap key: a private key, want the public half")
	}
	x, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("artifact: wrap key: x: %w", err)
	}
	pub, err := ecdh.X25519().NewPublicKey(x)
	if err != nil {
		return nil, fmt.Errorf("artifact: wrap key: %w", err)
	}
	if j.Kid != wrapKID(x) {
		return nil, errors.New("artifact: wrap key: kid is not the key's")
	}
	return &WrapPublicKey{ID: j.Kid, pub: pub}, nil
}

// LoadWrapPublicKey reads fleet-pub.json.
func LoadWrapPublicKey(path string) (*WrapPublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := ParseWrapPublicKey(b)
	if err != nil {
		return nil, fmt.Errorf("%w (%s)", err, path)
	}
	return p, nil
}

// ImagesSeal is what config.json carries about a sealed images.tar. A
// home needs all four to open it, and each is also bound into the
// sealed file.
type ImagesSeal struct {
	KeyID   string `json:"wrap_key"`
	Enc     []byte `json:"enc"`
	Wrapped []byte `json:"wrapped_key"`
	SHA256  string `json:"sha256"`
}

func imagesContext(sha string) SealContext {
	return SealContext{Domain: imagesDomain + sha}
}

// imagesInfo is the HPKE info the content key is wrapped under. It names
// the plaintext hash and the wrap key, so a wrapped key unwraps only for
// the images it was made for.
func imagesInfo(kid, sha string) []byte {
	return []byte(infoImages + imagesDomain + sha + " key:" + kid)
}

// SealImages seals the plaintext tar at src into dst for the fleet key
// pub and returns what config.json must carry. src is read twice, once
// to hash it and once to seal it, so a 512 MiB tar never sits in
// memory. The name images.tar is bound into the file key whatever dst
// is called.
func SealImages(src, dst string, pub *WrapPublicKey) (ImagesSeal, error) {
	if pub == nil {
		return ImagesSeal{}, errors.New("artifact: no fleet wrap key")
	}
	sha, err := fileSHA256(src)
	if err != nil {
		return ImagesSeal{}, err
	}
	ck := make([]byte, 32)
	if _, err := rand.Read(ck); err != nil {
		return ImagesSeal{}, err
	}
	pk, err := hpke.NewDHKEMPublicKey(pub.pub)
	if err != nil {
		return ImagesSeal{}, err
	}
	enc, sender, err := hpke.NewSender(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), imagesInfo(pub.ID, sha))
	if err != nil {
		return ImagesSeal{}, err
	}
	wrapped, err := sender.Seal(nil, ck)
	if err != nil {
		return ImagesSeal{}, err
	}
	h := sealHeader{Key: pub.ID, Context: imagesContext(sha), Wrap: &wrapHeader{Enc: enc, Wrapped: wrapped}}
	sum := sha256.New()
	if err := sealFile(src, dst, ck, fileImages, h, sum); err != nil {
		_ = os.Remove(dst)
		return ImagesSeal{}, fmt.Errorf("artifact: seal images: %w", err)
	}
	if hex.EncodeToString(sum.Sum(nil)) != sha {
		_ = os.Remove(dst)
		return ImagesSeal{}, errors.New("artifact: seal images: the tar changed while it was sealed")
	}
	return ImagesSeal{KeyID: pub.ID, Enc: enc, Wrapped: wrapped, SHA256: sha}, nil
}

// OpenImages opens the sealed tar at src into dst, written owner-only,
// using the fleet key derived from k and the metadata config.json
// carries. The file is refused before any of it is decrypted when its
// header does not say what s says, and the plaintext is refused after
// when it does not hash to s.SHA256. On error dst is removed.
func OpenImages(src, dst string, k *SealKey, s ImagesSeal) error {
	w, err := DeriveWrapKey(k)
	if err != nil {
		return err
	}
	if err := checkSHA256Hex("images hash", s.SHA256); err != nil {
		return err
	}
	if s.KeyID != w.ID {
		return fmt.Errorf("%w: images sealed for fleet key %q, this home derives %q", ErrSealed, s.KeyID, w.ID)
	}
	want := imagesContext(s.SHA256)
	keyFor := func(h sealHeader) ([]byte, error) {
		switch {
		case h.Key != s.KeyID:
			return nil, fmt.Errorf("%w: sealed with key %q, config says %q", ErrSealed, h.Key, s.KeyID)
		case h.Wrap == nil:
			return nil, fmt.Errorf("%w: not sealed as author images", ErrSealed)
		case !sameSealContext(h.Context, want):
			return nil, fmt.Errorf("%w: sealed as %q, config says %s", ErrSealed, h.Context.Domain, s.SHA256[:12])
		case subtle.ConstantTimeCompare(h.Wrap.Enc, s.Enc) != 1 || subtle.ConstantTimeCompare(h.Wrap.Wrapped, s.Wrapped) != 1:
			return nil, fmt.Errorf("%w: the wrapped key is not the one config names", ErrSealed)
		}
		priv, err := hpke.NewDHKEMPrivateKey(w.priv)
		if err != nil {
			return nil, err
		}
		rcpt, err := hpke.NewRecipient(h.Wrap.Enc, priv, hpke.HKDFSHA256(), hpke.AES256GCM(), imagesInfo(s.KeyID, s.SHA256))
		if err != nil {
			return nil, fmt.Errorf("%w: wrapped key does not unwrap", ErrSealed)
		}
		ck, err := rcpt.Open(nil, h.Wrap.Wrapped)
		if err != nil || len(ck) != 32 {
			return nil, fmt.Errorf("%w: wrapped key does not unwrap", ErrSealed)
		}
		return ck, nil
	}
	sum := sha256.New()
	if _, err := openFile(src, dst, fileImages, keyFor, sum); err != nil {
		_ = os.Remove(dst)
		return fmt.Errorf("artifact: open images: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum.Sum(nil))), []byte(s.SHA256)) != 1 {
		_ = os.Remove(dst)
		return fmt.Errorf("artifact: open images: %w: plaintext does not hash to the sha256 config names", ErrSealed)
	}
	return nil
}
