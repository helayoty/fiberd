package artifact_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/artifact"
)

const (
	shaA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	shaB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// sealedChunks splits a sealed file into its prefix (magic, length and
// header) and its chunks of chunk size plus the 16-byte GCM tag.
func sealedChunks(t *testing.T, b []byte) (prefix []byte, chunks [][]byte) {
	t.Helper()
	magic := len("fiberd-seal-v1\n")
	if len(b) < magic+4 {
		t.Fatalf("sealed file of %d bytes has no header", len(b))
	}
	n := int(binary.BigEndian.Uint32(b[magic : magic+4]))
	prefix = b[:magic+4+n]
	rest := b[len(prefix):]
	for len(rest) > 0 {
		c := min(len(rest), sealChunk+16)
		chunks = append(chunks, rest[:c])
		rest = rest[c:]
	}
	return prefix, chunks
}

// join rebuilds a sealed file from its parts.
func join(prefix []byte, chunks ...[]byte) []byte {
	out := append([]byte{}, prefix...)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}

// writeFiles writes a directory of files.
func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		writeFile(t, filepath.Join(dir, name), body)
	}
}

// parentFiles is a two-file parent, pages-1.img spanning three chunks
// so chunks can be swapped and dropped, and its pagemap.
func parentFiles() map[string]string {
	pages := make([]byte, 2*sealChunk+100)
	for i := range pages {
		pages[i] = byte(i * 7)
	}
	return map[string]string{"pages-1.img": string(pages), "pagemap-1.img": "pagemap bytes"}
}

func sealParent(t *testing.T, key *artifact.SealKey, sha string) string {
	t.Helper()
	src, dst := t.TempDir(), t.TempDir()
	writeFiles(t, src, parentFiles())
	if err := artifact.SealParentDir(src, dst, key, sha); err != nil {
		t.Fatal(err)
	}
	return dst
}

// rewrite applies f to a sealed file in dir.
func rewrite(t *testing.T, dir, name string, f func(b []byte) []byte) {
	t.Helper()
	path := filepath.Join(dir, name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, f(b), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestSealParentRoundTrip seals a parent, checks nothing of it is in the
// clear, opens it and compares. The label is accepted with a zero expiry,
// which is a parent's only expiry.
func TestSealParentRoundTrip(t *testing.T) {
	key := &artifact.SealKey{ID: "k", Key: bytes.Repeat([]byte{3}, 32)}
	cases := []struct {
		name string
		sha  string
	}{
		{name: "a parent opens under its own sha", sha: shaA},
		{name: "another sha is another parent", sha: shaB},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := sealParent(t, key, c.sha)
			want := parentFiles()
			for name, plain := range want {
				b, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.HasPrefix(b, []byte("fiberd-seal-v1\n")) || bytes.Contains(b, []byte(plain[:min(64, len(plain))])) {
					t.Fatalf("%s is not sealed", name)
				}
				if !bytes.Contains(b, []byte("parent:"+c.sha)) {
					t.Fatalf("%s header does not carry the label parent:%s", name, c.sha[:12])
				}
			}
			if err := artifact.OpenParentDir(dir, key, c.sha); err != nil {
				t.Fatal(err)
			}
			for name, plain := range want {
				b, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					t.Fatal(err)
				}
				if string(b) != plain {
					t.Fatalf("%s opened to %d bytes, want %d", name, len(b), len(plain))
				}
				if fi, _ := os.Stat(filepath.Join(dir, name)); fi.Mode().Perm() != 0o600 {
					t.Fatalf("%s opened with mode %v, want 0600", name, fi.Mode().Perm())
				}
			}
		})
	}
}

func TestOpenParentDirRefuses(t *testing.T) {
	key := &artifact.SealKey{ID: "k", Key: bytes.Repeat([]byte{3}, 32)}
	otherBytes := &artifact.SealKey{ID: "k", Key: bytes.Repeat([]byte{4}, 32)}
	otherID := &artifact.SealKey{ID: "k2", Key: bytes.Repeat([]byte{3}, 32)}
	cases := []struct {
		name string
		key  *artifact.SealKey
		sha  string
		dir  func(t *testing.T) string
		want error
		msg  string // a substring the error must carry
	}{
		{name: "no key", sha: shaA, dir: func(t *testing.T) string { return sealParent(t, key, shaA) }, msg: "no seal key"},
		{name: "a sha that is not hex", key: key, sha: strings.ToUpper(shaA),
			dir: func(t *testing.T) string { return sealParent(t, key, shaA) }, msg: "not a sha256"},
		// A parent copied to another sha's tag: the label says shaA, the
		// delta names shaB.
		{name: "the wrong sha label", key: key, sha: shaB,
			dir: func(t *testing.T) string { return sealParent(t, key, shaA) }, want: artifact.ErrSealed, msg: "not parent " + shaB[:12]},
		{name: "another master with another kid", key: otherID, sha: shaA,
			dir: func(t *testing.T) string { return sealParent(t, key, shaA) }, want: artifact.ErrSealed, msg: "this home has"},
		{name: "another master with the same kid", key: otherBytes, sha: shaA,
			dir: func(t *testing.T) string { return sealParent(t, key, shaA) }, want: artifact.ErrSealed, msg: "chunk 0"},
		// Regression: a parent pushed in the clear must fail the magic
		// check, before anything in it is parsed.
		{name: "plaintext input", key: key, sha: shaA, want: artifact.ErrSealed, msg: "not sealed",
			dir: func(t *testing.T) string {
				dir := t.TempDir()
				writeFiles(t, dir, parentFiles())
				return dir
			}},
		{name: "nothing sealed", key: key, sha: shaA, want: artifact.ErrSealed, msg: "nothing sealed",
			dir: func(t *testing.T) string { return t.TempDir() }},
		{name: "a tampered chunk", key: key, sha: shaA, want: artifact.ErrSealed, msg: "chunk 1",
			dir: func(t *testing.T) string {
				dir := sealParent(t, key, shaA)
				rewrite(t, dir, "pages-1.img", func(b []byte) []byte {
					p, c := sealedChunks(t, b)
					c[1][10] ^= 1
					return join(p, c...)
				})
				return dir
			}},
		{name: "a tampered header", key: key, sha: shaA, want: artifact.ErrSealed,
			dir: func(t *testing.T) string {
				dir := sealParent(t, key, shaA)
				rewrite(t, dir, "pages-1.img", func(b []byte) []byte {
					// Change the salt, which is in the header only.
					i := bytes.Index(b, []byte(`"salt":"`)) + len(`"salt":"`)
					if b[i] == 'A' {
						b[i] = 'B'
					} else {
						b[i] = 'A'
					}
					return b
				})
				return dir
			}},
		{name: "reordered chunks", key: key, sha: shaA, want: artifact.ErrSealed, msg: "chunk 0",
			dir: func(t *testing.T) string {
				dir := sealParent(t, key, shaA)
				rewrite(t, dir, "pages-1.img", func(b []byte) []byte {
					p, c := sealedChunks(t, b)
					return join(p, c[1], c[0], c[2])
				})
				return dir
			}},
		{name: "a dropped last chunk", key: key, sha: shaA, want: artifact.ErrSealed, msg: "chunk 1",
			dir: func(t *testing.T) string {
				dir := sealParent(t, key, shaA)
				rewrite(t, dir, "pages-1.img", func(b []byte) []byte {
					p, c := sealedChunks(t, b)
					return join(p, c[0], c[1])
				})
				return dir
			}},
		{name: "a last chunk cut short", key: key, sha: shaA, want: artifact.ErrSealed, msg: "chunk 2",
			dir: func(t *testing.T) string {
				dir := sealParent(t, key, shaA)
				rewrite(t, dir, "pages-1.img", func(b []byte) []byte { return b[:len(b)-1] })
				return dir
			}},
		{name: "a chunk moved to another file", key: key, sha: shaA, want: artifact.ErrSealed,
			dir: func(t *testing.T) string {
				dir := sealParent(t, key, shaA)
				b, err := os.ReadFile(filepath.Join(dir, "pages-1.img"))
				if err != nil {
					t.Fatal(err)
				}
				rewrite(t, dir, "pagemap-1.img", func([]byte) []byte { return b })
				return dir
			}},
		{name: "files of two parents", key: key, sha: shaA, want: artifact.ErrSealed,
			dir: func(t *testing.T) string {
				dir, other := sealParent(t, key, shaA), sealParent(t, key, shaB)
				if err := os.Rename(filepath.Join(other, "pagemap-1.img"), filepath.Join(dir, "pagemap-1.img")); err != nil {
					t.Fatal(err)
				}
				return dir
			}},
		// Key separation: a delta sealed for the domain parent:<sha> with
		// the same master is not a parent.
		{name: "a delta sealed as parent:sha", key: key, sha: shaA, want: artifact.ErrSealed,
			dir: func(t *testing.T) string {
				src, dst := t.TempDir(), t.TempDir()
				writeFiles(t, src, parentFiles())
				sc := artifact.SealContext{Domain: "parent:" + shaA, Expires: time.Now().Add(time.Hour)}
				if err := artifact.SealDir(src, dst, key, sc); err != nil {
					t.Fatal(err)
				}
				return dst
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := c.dir(t)
			err := artifact.OpenParentDir(dir, c.key, c.sha)
			if err == nil || (c.want != nil && !errors.Is(err, c.want)) || !strings.Contains(err.Error(), c.msg) {
				t.Fatalf("OpenParentDir = %v, want %v with %q", err, c.want, c.msg)
			}
			if entries, _ := os.ReadDir(dir); len(entries) > 0 {
				for _, e := range entries {
					if strings.HasSuffix(e.Name(), ".tmp") {
						t.Fatalf("a refused open left %s", e.Name())
					}
				}
			}
		})
	}
}

func TestSealParentDirErrors(t *testing.T) {
	key := &artifact.SealKey{ID: "k", Key: make([]byte, 32)}
	cases := []struct {
		name string
		key  *artifact.SealKey
		sha  string
		src  func(t *testing.T) string
		msg  string
	}{
		{name: "no key", sha: shaA, src: func(t *testing.T) string { return t.TempDir() }, msg: "no seal key"},
		{name: "a short sha", key: key, sha: shaA[:63], src: func(t *testing.T) string { return t.TempDir() }, msg: "not a sha256"},
		{name: "an uppercase sha", key: key, sha: strings.ToUpper(shaA), src: func(t *testing.T) string { return t.TempDir() }, msg: "not a sha256"},
		{name: "a missing source", key: key, sha: shaA, src: func(t *testing.T) string { return filepath.Join(t.TempDir(), "gone") }, msg: "no such file"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := artifact.SealParentDir(c.src(t), t.TempDir(), c.key, c.sha)
			if err == nil || !strings.Contains(err.Error(), c.msg) {
				t.Fatalf("SealParentDir = %v, want %q", err, c.msg)
			}
		})
	}
}

// TestZeroExpiry: a zero expiry is a parent's and no delta's. Regression
// for the delta side, which old code refused only because now is never
// before the zero time.
func TestZeroExpiry(t *testing.T) {
	key := &artifact.SealKey{ID: "k", Key: bytes.Repeat([]byte{5}, 32)}
	cases := []struct {
		name string
		run  func(t *testing.T) error
		want error
		msg  string
	}{
		{name: "a parent context never expires", run: func(t *testing.T) error {
			return artifact.OpenParentDir(sealParent(t, key, shaA), key, shaA)
		}},
		{name: "a delta sealed with a zero expiry is refused", msg: "needs an expiry", run: func(t *testing.T) error {
			src := t.TempDir()
			writeFiles(t, src, parentFiles())
			return artifact.SealDir(src, t.TempDir(), key, artifact.SealContext{Domain: "D", Session: "S"})
		}},
		{name: "a delta presented with a zero expiry is refused", want: artifact.ErrExpired, msg: "without an expiry", run: func(t *testing.T) error {
			src := t.TempDir()
			writeFiles(t, src, map[string]string{"a.img": "pages"})
			dst := t.TempDir()
			if err := artifact.SealDir(src, dst, key, artifact.SealContext{Domain: "D", Session: "S", Expires: time.Now().Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			// The header is associated data, so a zero expiry written
			// into it is refused for the expiry before the chunk fails.
			rewrite(t, dst, "a.img", func(b []byte) []byte {
				i := bytes.Index(b, []byte(`"expires":"`)) + len(`"expires":"`)
				j := i + bytes.IndexByte(b[i:], '"')
				zero := []byte("0001-01-01T00:00:00Z")
				out := append([]byte{}, b[:i]...)
				out = append(out, zero...)
				out = append(out, b[j:]...)
				// Keep the header length right.
				magic := len("fiberd-seal-v1\n")
				n := binary.BigEndian.Uint32(out[magic:magic+4]) - uint32(j-i) + uint32(len(zero))
				binary.BigEndian.PutUint32(out[magic:magic+4], n)
				return out
			})
			_, err := artifact.OpenDir(dst, key, "D", "S", time.Now())
			return err
		}},
		{name: "a parent opened as a delta is refused for its expiry", want: artifact.ErrExpired, run: func(t *testing.T) error {
			_, err := artifact.OpenDir(sealParent(t, key, shaA), key, "parent:"+shaA, "", time.Now())
			return err
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.run(t)
			if c.want == nil && c.msg == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || (c.want != nil && !errors.Is(err, c.want)) || !strings.Contains(err.Error(), c.msg) {
				t.Fatalf("got %v, want %v with %q", err, c.want, c.msg)
			}
		})
	}
}
