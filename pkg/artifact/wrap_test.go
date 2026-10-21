package artifact_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/helayoty/fiberd/pkg/artifact"
)

func masterKey(fill byte) *artifact.SealKey {
	return &artifact.SealKey{ID: "k" + string(rune('0'+fill)), Key: bytes.Repeat([]byte{fill}, 32)}
}

// TestDeriveWrapKey: the fleet pair is a pure function of the master, and
// its public JWK round-trips with the same kid.
func TestDeriveWrapKey(t *testing.T) {
	ref, err := artifact.DeriveWrapKey(masterKey(1))
	if err != nil {
		t.Fatal(err)
	}
	refJWK, err := ref.PublicJWK()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		master *artifact.SealKey
		same   bool
	}{
		{name: "the same master again", master: masterKey(1), same: true},
		{name: "the same bytes under another kid", master: &artifact.SealKey{ID: "renamed", Key: bytes.Repeat([]byte{1}, 32)}, same: true},
		{name: "another master", master: masterKey(2)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w, err := artifact.DeriveWrapKey(c.master)
			if err != nil {
				t.Fatal(err)
			}
			jwk, err := w.PublicJWK()
			if err != nil {
				t.Fatal(err)
			}
			if (w.ID == ref.ID) != c.same || bytes.Equal(jwk, refJWK) != c.same {
				t.Fatalf("kid %s, want same=%v as %s", w.ID, c.same, ref.ID)
			}
			p, err := artifact.ParseWrapPublicKey(jwk)
			if err != nil {
				t.Fatal(err)
			}
			if p.ID != w.ID {
				t.Fatalf("parsed kid %s, want %s", p.ID, w.ID)
			}
			again, err := p.JWK()
			if err != nil || !bytes.Equal(again, jwk) {
				t.Fatalf("JWK did not round-trip: %v", err)
			}
			var raw map[string]string
			if err := json.Unmarshal(jwk, &raw); err != nil {
				t.Fatal(err)
			}
			if raw["kty"] != "OKP" || raw["crv"] != "X25519" || raw["kid"] != w.ID || raw["d"] != "" {
				t.Fatalf("public JWK = %s", jwk)
			}
		})
	}
	if _, err := artifact.DeriveWrapKey(nil); err == nil {
		t.Fatal("DeriveWrapKey(nil) succeeded")
	}
}

func TestParseWrapPublicKey(t *testing.T) {
	w, err := artifact.DeriveWrapKey(masterKey(1))
	if err != nil {
		t.Fatal(err)
	}
	good, err := w.PublicJWK()
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]string
	if err := json.Unmarshal(good, &fields); err != nil {
		t.Fatal(err)
	}
	with := func(change func(m map[string]string)) string {
		m := map[string]string{}
		for k, v := range fields {
			m[k] = v
		}
		change(m)
		b, _ := json.Marshal(m)
		return string(b)
	}
	cases := []struct {
		name string
		file string // "-" for no file
		ok   bool
		msg  string
	}{
		{name: "the written key loads", file: string(good), ok: true},
		{name: "a missing file", file: "-", msg: "no such file"},
		{name: "not JSON", file: "{", msg: "wrap key"},
		{name: "an Ed25519 key", file: with(func(m map[string]string) { m["crv"] = "Ed25519" }), msg: "OKP X25519"},
		{name: "a symmetric key", file: with(func(m map[string]string) { m["kty"] = "oct" }), msg: "OKP X25519"},
		{name: "a private key", file: with(func(m map[string]string) { m["d"] = m["x"] }), msg: "private key"},
		{name: "x of the wrong length", file: with(func(m map[string]string) { m["x"] = m["x"][:20] }), msg: "wrap key"},
		{name: "x that is not base64url", file: with(func(m map[string]string) { m["x"] = "!" + m["x"][1:] }), msg: "x:"},
		{name: "a kid that is not the key's", file: with(func(m map[string]string) { m["kid"] = "other" }), msg: "kid is not the key's"},
		{name: "no kid", file: with(func(m map[string]string) { delete(m, "kid") }), msg: "kid is not the key's"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fleet-pub.json")
			if c.file != "-" {
				writeFile(t, path, c.file)
			}
			p, err := artifact.LoadWrapPublicKey(path)
			if !c.ok {
				if err == nil || !strings.Contains(err.Error(), c.msg) {
					t.Fatalf("LoadWrapPublicKey = %v, want %q", err, c.msg)
				}
				return
			}
			if err != nil || p.ID != w.ID {
				t.Fatalf("LoadWrapPublicKey = %+v, %v; want kid %s", p, err, w.ID)
			}
		})
	}
}

// imagesTar is a plaintext tar stand-in of n bytes.
func imagesTar(t *testing.T, n int) (path, sha string) {
	t.Helper()
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*13 + n)
	}
	path = filepath.Join(t.TempDir(), "images.tar")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return path, hex.EncodeToString(sum[:])
}

func sealImages(t *testing.T, master *artifact.SealKey, size int) (sealed string, s artifact.ImagesSeal, sha string) {
	t.Helper()
	w, err := artifact.DeriveWrapKey(master)
	if err != nil {
		t.Fatal(err)
	}
	src, sha := imagesTar(t, size)
	sealed = filepath.Join(t.TempDir(), "images.tar")
	s, err = artifact.SealImages(src, sealed, w.Public())
	if err != nil {
		t.Fatal(err)
	}
	return sealed, s, sha
}

func TestSealImagesRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		size int
	}{
		{name: "empty", size: 0},
		{name: "one chunk", size: 1000},
		{name: "three chunks", size: 2*sealChunk + 5},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			master := masterKey(1)
			sealed, s, sha := sealImages(t, master, c.size)
			if s.SHA256 != sha || len(s.Enc) != 32 || len(s.Wrapped) != 32+16 {
				t.Fatalf("ImagesSeal = %+v, want sha %s, a 32-byte enc and a 48-byte wrapped key", s, sha[:12])
			}
			w, _ := artifact.DeriveWrapKey(master)
			if s.KeyID != w.ID {
				t.Fatalf("sealed for %s, the fleet key is %s", s.KeyID, w.ID)
			}
			b, err := os.ReadFile(sealed)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(b, []byte("fiberd-seal-v1\n")) || !bytes.Contains(b, []byte("images:"+sha)) {
				t.Fatal("the sealed file has no header with the images label")
			}
			// It serialises for config.json and back.
			var again artifact.ImagesSeal
			j, _ := json.Marshal(s)
			if err := json.Unmarshal(j, &again); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(t.TempDir(), "images.tar.open")
			if err := artifact.OpenImages(sealed, out, master, again); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(got)
			if len(got) != c.size || hex.EncodeToString(sum[:]) != sha {
				t.Fatalf("opened %d bytes hashing to %x, want %d bytes and %s", len(got), sum[:6], c.size, sha[:12])
			}
			if fi, _ := os.Stat(out); fi.Mode().Perm() != 0o600 {
				t.Fatalf("opened images have mode %v, want 0600", fi.Mode().Perm())
			}
		})
	}
}

// TestSealImagesFresh: two seals of one tar share nothing but the hash.
func TestSealImagesFresh(t *testing.T) {
	master := masterKey(1)
	w, _ := artifact.DeriveWrapKey(master)
	src, _ := imagesTar(t, 100)
	a, err := artifact.SealImages(src, filepath.Join(t.TempDir(), "a"), w.Public())
	if err != nil {
		t.Fatal(err)
	}
	b, err := artifact.SealImages(src, filepath.Join(t.TempDir(), "b"), w.Public())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		same bool
		x, y []byte
	}{
		{name: "the hash", same: true, x: []byte(a.SHA256), y: []byte(b.SHA256)},
		{name: "the encapsulation", x: a.Enc, y: b.Enc},
		{name: "the wrapped key", x: a.Wrapped, y: b.Wrapped},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if bytes.Equal(c.x, c.y) != c.same {
				t.Fatalf("same = %v, want %v", !c.same, c.same)
			}
		})
	}
}

func TestOpenImagesRefuses(t *testing.T) {
	master := masterKey(1)
	sealed, s, sha := sealImages(t, master, 2*sealChunk+5)
	_, other, otherSHA := sealImages(t, master, 777)
	mutate := func(f func(s *artifact.ImagesSeal)) artifact.ImagesSeal {
		m := s
		m.Enc = append([]byte{}, s.Enc...)
		m.Wrapped = append([]byte{}, s.Wrapped...)
		f(&m)
		return m
	}
	cases := []struct {
		name   string
		master *artifact.SealKey
		src    func(t *testing.T) string
		seal   artifact.ImagesSeal
		want   error
		msg    string
	}{
		{name: "no master", src: func(*testing.T) string { return sealed }, seal: s, msg: "no seal key"},
		{name: "another fleet key", master: masterKey(2), src: func(*testing.T) string { return sealed }, seal: s,
			want: artifact.ErrSealed, msg: "this home derives"},
		{name: "a sha that is not hex", master: master, src: func(*testing.T) string { return sealed },
			seal: mutate(func(s *artifact.ImagesSeal) { s.SHA256 = strings.ToUpper(sha) }), msg: "not a sha256"},
		{name: "the config of another artifact", master: master, src: func(*testing.T) string { return sealed }, seal: other,
			want: artifact.ErrSealed, msg: "config says " + otherSHA[:12]},
		{name: "another artifact's wrapped key", master: master, src: func(*testing.T) string { return sealed },
			seal: mutate(func(s *artifact.ImagesSeal) { s.Wrapped = other.Wrapped }), want: artifact.ErrSealed, msg: "not the one config names"},
		{name: "another artifact's encapsulation", master: master, src: func(*testing.T) string { return sealed },
			seal: mutate(func(s *artifact.ImagesSeal) { s.Enc = other.Enc }), want: artifact.ErrSealed, msg: "not the one config names"},
		{name: "the hash of another tar", master: master, src: func(*testing.T) string { return sealed },
			seal: mutate(func(s *artifact.ImagesSeal) { s.SHA256 = otherSHA }), want: artifact.ErrSealed, msg: "config says"},
		{name: "a forged kid", master: master, src: func(*testing.T) string { return sealed },
			seal: mutate(func(s *artifact.ImagesSeal) { s.KeyID = "forged" }), want: artifact.ErrSealed},
		// Regression: an images.tar pushed in the clear is refused before
		// anything in it is parsed.
		{name: "plaintext input", master: master, seal: s, want: artifact.ErrSealed, msg: "not sealed",
			src: func(t *testing.T) string { p, _ := imagesTar(t, 2*sealChunk+5); return p }},
		{name: "a tampered chunk", master: master, seal: s, want: artifact.ErrSealed, msg: "chunk 2",
			src: func(t *testing.T) string {
				return copyWith(t, sealed, func(b []byte) []byte {
					p, c := sealedChunks(t, b)
					c[2][0] ^= 1
					return join(p, c...)
				})
			}},
		{name: "reordered chunks", master: master, seal: s, want: artifact.ErrSealed, msg: "chunk 0",
			src: func(t *testing.T) string {
				return copyWith(t, sealed, func(b []byte) []byte {
					p, c := sealedChunks(t, b)
					return join(p, c[1], c[0], c[2])
				})
			}},
		{name: "a truncated stream", master: master, seal: s, want: artifact.ErrSealed, msg: "chunk 1",
			src: func(t *testing.T) string {
				return copyWith(t, sealed, func(b []byte) []byte {
					p, c := sealedChunks(t, b)
					return join(p, c[0], c[1])
				})
			}},
		{name: "a header that names another hash", master: master, seal: s, want: artifact.ErrSealed,
			src: func(t *testing.T) string {
				return copyWith(t, sealed, func(b []byte) []byte {
					return bytes.Replace(b, []byte("images:"+sha), []byte("images:"+otherSHA), 1)
				})
			}},
		{name: "a parent presented as images", master: master, seal: s, want: artifact.ErrSealed, msg: "config says",
			src: func(t *testing.T) string {
				dir := sealParent(t, master, shaA)
				return filepath.Join(dir, "pages-1.img")
			}},
		{name: "a missing file", master: master, seal: s, msg: "no such file",
			src: func(t *testing.T) string { return filepath.Join(t.TempDir(), "gone") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "images.tar.open")
			err := artifact.OpenImages(c.src(t), out, c.master, c.seal)
			if err == nil || (c.want != nil && !errors.Is(err, c.want)) || !strings.Contains(err.Error(), c.msg) {
				t.Fatalf("OpenImages = %v, want %v with %q", err, c.want, c.msg)
			}
			if _, serr := os.Stat(out); serr == nil {
				t.Fatal("a refused open left its output")
			}
		})
	}
}

// copyWith writes f(contents of src) to a fresh file.
func copyWith(t *testing.T, src string, f func([]byte) []byte) string {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "images.tar")
	if err := os.WriteFile(dst, f(b), 0o644); err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestSealImagesErrors(t *testing.T) {
	w, _ := artifact.DeriveWrapKey(masterKey(1))
	cases := []struct {
		name string
		pub  *artifact.WrapPublicKey
		src  func(t *testing.T) string
		dst  func(t *testing.T) string
		msg  string
	}{
		{name: "no fleet key", src: func(t *testing.T) string { p, _ := imagesTar(t, 10); return p },
			dst: func(t *testing.T) string { return filepath.Join(t.TempDir(), "out") }, msg: "no fleet wrap key"},
		{name: "a missing source", pub: w.Public(), src: func(t *testing.T) string { return filepath.Join(t.TempDir(), "gone") },
			dst: func(t *testing.T) string { return filepath.Join(t.TempDir(), "out") }, msg: "no such file"},
		{name: "a destination that cannot be made", pub: w.Public(), src: func(t *testing.T) string { p, _ := imagesTar(t, 10); return p },
			dst: func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing", "out") }, msg: "no such file"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := artifact.SealImages(c.src(t), c.dst(t), c.pub)
			if err == nil || !strings.Contains(err.Error(), c.msg) {
				t.Fatalf("SealImages = %v, want %q", err, c.msg)
			}
		})
	}
}
