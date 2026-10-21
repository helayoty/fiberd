package artifact

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Sealed directory artifacts. Tenant memory leaves a home only sealed.
// Every file of a delta is encrypted with AES-256-GCM under a key for its
// session domain. That key derives from a master key shared by the homes
// that move sessions between them. Each file has a random salt and its own
// subkey bound to its name. It is sealed in chunks whose nonce is the
// chunk's index plus a last-chunk flag, so chunks cannot be reordered,
// dropped, cut short or moved to another file. The file's header (domain,
// session, fence, expiry) is the associated data of every chunk, so a
// sealed file opens only for its own session and not after it expires.
//
// The same stream format carries two more kinds of template memory, each
// under its own key. A parent checkpoint (seal_parent.go) is sealed under
// a key derived from the master and the parent's content hash. An
// author's images.tar (wrap.go) is sealed under a random content key
// that is wrapped to the fleet's public key. The HKDF info strings below
// keep the three kinds of key apart, and every open derives its key from
// the kind the caller asked for, never from the header.

const (
	AnnotationDomain  = "io.fiberd.domain"
	AnnotationExpires = "io.fiberd.expires"
	AnnotationSealKey = "io.fiberd.seal_key"

	sealMagic = "fiberd-seal-v1\n"
	sealChunk = 1 << 20
	sealKeyID = "fiberd-seal-kid\n"

	// The HKDF info prefixes. One per kind of key, so no two kinds ever
	// derive the same key from one master.
	infoDelta  = "fiberd-delta-v1 domain:"
	infoParent = "fiberd-parent-v1 "
	infoWrap   = "fiberd-template-wrap-v1"
	infoImages = "fiberd-images-v1 "
)

// SealKey is the master key deltas are sealed under.
type SealKey struct {
	ID  string
	Key []byte // 32 bytes
}

// SealContext is what a sealed file is bound to. A delta's Expires is the
// instant it stops opening. A parent's is zero, which means never, and a
// zero expiry is accepted for parent contexts only.
type SealContext struct {
	Domain  string    `json:"domain"`
	Session string    `json:"session"`
	Fence   string    `json:"fence,omitempty"`
	Expires time.Time `json:"expires"`
}

// sealHeader is the plaintext prefix of a sealed file and the associated
// data of every chunk in it. Wrap is set for an author's images only.
type sealHeader struct {
	Key     string      `json:"key"`
	Salt    []byte      `json:"salt"`
	Context SealContext `json:"context"`
	Wrap    *wrapHeader `json:"wrap,omitempty"`
}

// wrapHeader is the part of a header that is set for author images only,
// the HPKE encapsulation and the content key wrapped under it.
type wrapHeader struct {
	Enc     []byte `json:"enc"`
	Wrapped []byte `json:"wrapped"`
}

// GenerateSealKey returns a fresh master seal key as a symmetric JWK.
func GenerateSealKey() (*jose.JSONWebKey, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return &jose.JSONWebKey{Key: k, KeyID: sealKID(k), Algorithm: "A256GCM", Use: "enc"}, nil
}

func sealKID(k []byte) string {
	sum := sha256.Sum256(append([]byte(sealKeyID), k...))
	return base64.RawURLEncoding.EncodeToString(sum[:12])
}

// LoadSealKey reads a master seal key (a 32-byte symmetric JWK with a
// kid, as GenerateSealKey makes).
func LoadSealKey(path string) (*SealKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(b, &jwk); err != nil {
		return nil, fmt.Errorf("artifact: seal key %s: %w", path, err)
	}
	k, err := SealKeyFromJWK(&jwk)
	if err != nil {
		return nil, fmt.Errorf("artifact: seal key %s: %w", path, err)
	}
	return k, nil
}

// SealKeyFromJWK takes the master seal key out of its JWK.
func SealKeyFromJWK(jwk *jose.JSONWebKey) (*SealKey, error) {
	k, ok := jwk.Key.([]byte)
	if !ok || len(k) != 32 || jwk.KeyID == "" {
		return nil, errors.New("want a 32-byte symmetric JWK with a kid")
	}
	return &SealKey{ID: jwk.KeyID, Key: k}, nil
}

// SealDir writes every file PushDir would push from src, sealed for c,
// into dst under the same names. A delta always expires, so a zero
// Expires is refused here rather than sealed as a file nothing opens.
func SealDir(src, dst string, k *SealKey, c SealContext) error {
	if k == nil {
		return errors.New("artifact: no seal key")
	}
	if c.Expires.IsZero() {
		return errors.New("artifact: a delta needs an expiry")
	}
	dk, err := deltaKey(k, c.Domain)
	if err != nil {
		return err
	}
	return sealDirWith(src, dst, dk, sealHeader{Key: k.ID, Context: c})
}

// OpenDir replaces every sealed file in dir by its plaintext. It refuses
// any file not sealed with k for domain and session, or expired at now,
// and a directory whose files were sealed for different contexts, so one
// delta cannot be assembled from files of several parks. It returns the
// one context the files were sealed with. On error, dir holds a mix of
// sealed and plain files, and the caller must remove it.
func OpenDir(dir string, k *SealKey, domain, session string, now time.Time) (SealContext, error) {
	if k == nil {
		return SealContext{}, errors.New("artifact: no seal key")
	}
	keyFor := func(h sealHeader) ([]byte, error) {
		switch {
		case h.Key != k.ID:
			return nil, fmt.Errorf("%w: sealed with key %q, this home has %q", ErrSealed, h.Key, k.ID)
		case h.Wrap != nil:
			return nil, fmt.Errorf("%w: sealed as author images, not a delta", ErrSealed)
		case h.Context.Domain != domain || h.Context.Session != session:
			return nil, fmt.Errorf("%w: sealed for %s/%s, not %s/%s", ErrSealed, h.Context.Domain, h.Context.Session, domain, session)
		case h.Context.Expires.IsZero():
			// Only a parent never expires, and a parent is never a delta.
			return nil, fmt.Errorf("%w: a delta without an expiry", ErrExpired)
		case !now.Before(h.Context.Expires):
			return nil, fmt.Errorf("%w: at %s", ErrExpired, h.Context.Expires.Format(time.RFC3339))
		}
		return deltaKey(k, domain)
	}
	return openDirWith(dir, keyFor)
}

// sealDirWith seals every pushable file of src into dst under the domain
// key dk, each with a fresh salt under the header h.
func sealDirWith(src, dst string, dk []byte, h sealHeader) error {
	names, err := pushableNames(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	for _, n := range names {
		if err := sealFile(filepath.Join(src, n), filepath.Join(dst, n), dk, n, h, nil); err != nil {
			return fmt.Errorf("artifact: seal %s: %w", n, err)
		}
	}
	return nil
}

// openDirWith opens every pushable file of dir in place. keyFor judges
// each file's header and returns the domain key it opens under. All
// files must carry one context.
func openDirWith(dir string, keyFor func(sealHeader) ([]byte, error)) (SealContext, error) {
	names, err := pushableNames(dir)
	if err != nil {
		return SealContext{}, err
	}
	if len(names) == 0 {
		return SealContext{}, fmt.Errorf("%w: nothing sealed in %s", ErrSealed, dir)
	}
	var got SealContext
	for i, n := range names {
		path := filepath.Join(dir, n)
		h, err := openFile(path, path+".open.tmp", n, keyFor, nil)
		if err == nil && i > 0 && !sameSealContext(got, h.Context) {
			err = fmt.Errorf("%w: sealed for another context than %s", ErrSealed, names[0])
		}
		if err != nil {
			_ = os.Remove(path + ".open.tmp")
			return SealContext{}, fmt.Errorf("artifact: open %s: %w", n, err)
		}
		if err := os.Rename(path+".open.tmp", path); err != nil {
			return SealContext{}, err
		}
		got = h.Context
	}
	return got, nil
}

// sameSealContext reports whether two files were sealed for one context.
func sameSealContext(a, b SealContext) bool {
	return a.Domain == b.Domain && a.Session == b.Session && a.Fence == b.Fence && a.Expires.Equal(b.Expires)
}

// deltaKey is the key every file of a session domain is sealed under.
func deltaKey(k *SealKey, domain string) ([]byte, error) {
	return hkdf.Key(sha256.New, k.Key, nil, infoDelta+domain, 32)
}

// fileAEAD derives a file's own key from the domain key, the file's salt
// and its name, so no two files share a key and a file does not open
// under another name.
func fileAEAD(dk []byte, name string, salt []byte) (cipher.AEAD, error) {
	fk, err := hkdf.Key(sha256.New, dk, salt, "file:"+name, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(fk)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func chunkNonce(i uint64, last bool) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[3:11], i)
	if last {
		n[11] = 1
	}
	return n
}

// sealFile seals src into dst under the domain key dk, bound to name,
// with the header h after a fresh salt is drawn into it. sum, when set,
// sees the plaintext as it is read.
func sealFile(src, dst string, dk []byte, name string, h sealHeader, sum hash.Hash) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	h.Salt = make([]byte, 32)
	if _, err := rand.Read(h.Salt); err != nil {
		return err
	}
	hb, err := json.Marshal(h)
	if err != nil {
		return err
	}
	prefix := binary.BigEndian.AppendUint32([]byte(sealMagic), uint32(len(hb)))
	prefix = append(prefix, hb...)
	aead, err := fileAEAD(dk, name, h.Salt)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
	}()
	w := bufio.NewWriter(out)
	if _, err := w.Write(prefix); err != nil {
		return err
	}
	r := bufio.NewReaderSize(in, sealChunk+1)
	buf := make([]byte, sealChunk)
	sealed := make([]byte, 0, sealChunk+aead.Overhead())
	for i := uint64(0); ; i++ {
		n, err := io.ReadFull(r, buf)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return err
		}
		last := n < sealChunk
		if !last {
			if _, perr := r.Peek(1); perr == io.EOF {
				last = true
			}
		}
		if sum != nil {
			sum.Write(buf[:n])
		}
		if _, err := w.Write(aead.Seal(sealed[:0], chunkNonce(i, last), buf[:n], prefix)); err != nil {
			return err
		}
		if last {
			return w.Flush()
		}
	}
}

func readSealHeader(r *bufio.Reader) (sealHeader, []byte, error) {
	var h sealHeader
	prefix := make([]byte, len(sealMagic)+4)
	if _, err := io.ReadFull(r, prefix); err != nil || !bytes.Equal(prefix[:len(sealMagic)], []byte(sealMagic)) {
		return h, nil, fmt.Errorf("%w: not sealed", ErrSealed)
	}
	n := binary.BigEndian.Uint32(prefix[len(sealMagic):])
	if n > 1<<16 {
		return h, nil, fmt.Errorf("%w: header of %d bytes", ErrSealed, n)
	}
	hb := make([]byte, n)
	if _, err := io.ReadFull(r, hb); err != nil {
		return h, nil, fmt.Errorf("%w: header cut short", ErrSealed)
	}
	if err := json.Unmarshal(hb, &h); err != nil {
		return h, nil, fmt.Errorf("%w: header: %w", ErrSealed, err)
	}
	return h, append(prefix, hb...), nil
}

// openFile opens src into dst, which is written owner-only. The magic and
// the header are read first, then keyFor judges the header and returns
// the domain key. Nothing in the header is believed until the first
// chunk opens under that key, since the header is its associated data.
// sum, when set, sees the plaintext as it is written. On error dst may
// hold a partial plaintext, and the caller removes it.
func openFile(src, dst, name string, keyFor func(sealHeader) ([]byte, error), sum hash.Hash) (h sealHeader, err error) {
	in, err := os.Open(src)
	if err != nil {
		return h, err
	}
	defer func() { _ = in.Close() }()
	r := bufio.NewReaderSize(in, sealChunk+64)
	h, prefix, err := readSealHeader(r)
	if err != nil {
		return h, err
	}
	dk, err := keyFor(h)
	if err != nil {
		return h, err
	}
	aead, err := fileAEAD(dk, name, h.Salt)
	if err != nil {
		return h, err
	}
	// Plaintext session state stays owner-only.
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return h, err
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
	}()
	w := bufio.NewWriter(out)
	buf := make([]byte, sealChunk+aead.Overhead())
	plain := make([]byte, 0, sealChunk)
	for i := uint64(0); ; i++ {
		n, err := io.ReadFull(r, buf)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return h, err
		}
		last := n < len(buf)
		if !last {
			if _, perr := r.Peek(1); perr == io.EOF {
				last = true
			}
		}
		p, err := aead.Open(plain[:0], chunkNonce(i, last), buf[:n], prefix)
		if err != nil {
			return h, fmt.Errorf("%w: chunk %d", ErrSealed, i)
		}
		if sum != nil {
			sum.Write(p)
		}
		if _, err := w.Write(p); err != nil {
			return h, err
		}
		if last {
			return h, w.Flush()
		}
	}
}
