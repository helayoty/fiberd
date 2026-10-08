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

const (
	AnnotationDomain  = "io.fiberd.domain"
	AnnotationExpires = "io.fiberd.expires"
	AnnotationSealKey = "io.fiberd.seal_key"

	sealMagic = "fiberd-seal-v1\n"
	sealChunk = 1 << 20
	sealKeyID = "fiberd-seal-kid\n"
)

// SealKey is the master key deltas are sealed under.
type SealKey struct {
	ID  string
	Key []byte // 32 bytes
}

// SealContext is what a sealed file is bound to.
type SealContext struct {
	Domain  string    `json:"domain"`
	Session string    `json:"session"`
	Fence   string    `json:"fence,omitempty"`
	Expires time.Time `json:"expires"`
}

type sealHeader struct {
	Key     string      `json:"key"`
	Salt    []byte      `json:"salt"`
	Context SealContext `json:"context"`
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
// into dst under the same names.
func SealDir(src, dst string, k *SealKey, c SealContext) error {
	if k == nil {
		return errors.New("artifact: no seal key")
	}
	names, err := pushableNames(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	for _, n := range names {
		if err := sealFile(filepath.Join(src, n), filepath.Join(dst, n), k, c); err != nil {
			return fmt.Errorf("artifact: seal %s: %w", n, err)
		}
	}
	return nil
}

// OpenDir replaces every sealed file in dir by its plaintext. It refuses
// any file not sealed with k for domain and session, or expired at now.
// It returns the context the files were sealed with. On error, dir holds a
// mix of sealed and plain files, and the caller must remove it.
func OpenDir(dir string, k *SealKey, domain, session string, now time.Time) (SealContext, error) {
	if k == nil {
		return SealContext{}, errors.New("artifact: no seal key")
	}
	names, err := pushableNames(dir)
	if err != nil {
		return SealContext{}, err
	}
	if len(names) == 0 {
		return SealContext{}, fmt.Errorf("%w: nothing sealed in %s", ErrSealed, dir)
	}
	var got SealContext
	for _, n := range names {
		path := filepath.Join(dir, n)
		c, err := openFile(path, path+".open.tmp", k, domain, session, now)
		if err != nil {
			_ = os.Remove(path + ".open.tmp")
			return SealContext{}, fmt.Errorf("artifact: open %s: %w", n, err)
		}
		if err := os.Rename(path+".open.tmp", path); err != nil {
			return SealContext{}, err
		}
		got = c
	}
	return got, nil
}

func fileAEAD(k *SealKey, domain, name string, salt []byte) (cipher.AEAD, error) {
	dk, err := hkdf.Key(sha256.New, k.Key, nil, "fiberd-delta-v1 domain:"+domain, 32)
	if err != nil {
		return nil, err
	}
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

func sealFile(src, dst string, k *SealKey, c SealContext) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	h := sealHeader{Key: k.ID, Salt: make([]byte, 32), Context: c}
	if _, err := rand.Read(h.Salt); err != nil {
		return err
	}
	hb, err := json.Marshal(h)
	if err != nil {
		return err
	}
	prefix := binary.BigEndian.AppendUint32([]byte(sealMagic), uint32(len(hb)))
	prefix = append(prefix, hb...)
	aead, err := fileAEAD(k, c.Domain, filepath.Base(dst), h.Salt)
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

func openFile(src, dst string, k *SealKey, domain, session string, now time.Time) (c SealContext, err error) {
	in, err := os.Open(src)
	if err != nil {
		return c, err
	}
	defer func() { _ = in.Close() }()
	r := bufio.NewReaderSize(in, sealChunk+64)
	h, prefix, err := readSealHeader(r)
	if err != nil {
		return c, err
	}
	switch {
	case h.Key != k.ID:
		return c, fmt.Errorf("%w: sealed with key %q, this home has %q", ErrSealed, h.Key, k.ID)
	case h.Context.Domain != domain || h.Context.Session != session:
		return c, fmt.Errorf("%w: sealed for %s/%s, not %s/%s", ErrSealed, h.Context.Domain, h.Context.Session, domain, session)
	case !now.Before(h.Context.Expires):
		return c, fmt.Errorf("%w: at %s", ErrExpired, h.Context.Expires.Format(time.RFC3339))
	}
	aead, err := fileAEAD(k, domain, filepath.Base(src), h.Salt)
	if err != nil {
		return c, err
	}
	// Plaintext session state stays owner-only.
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return c, err
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
			return c, err
		}
		last := n < len(buf)
		if !last {
			if _, perr := r.Peek(1); perr == io.EOF {
				last = true
			}
		}
		p, err := aead.Open(plain[:0], chunkNonce(i, last), buf[:n], prefix)
		if err != nil {
			return c, fmt.Errorf("%w: chunk %d", ErrSealed, i)
		}
		if _, err := w.Write(p); err != nil {
			return c, err
		}
		if last {
			return h.Context, w.Flush()
		}
	}
}
