package artifact_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/helayoty/fiberd/pkg/artifact"
)

// sealChunk is the plaintext size of one sealed chunk, a wire constant.
const sealChunk = 1 << 20

func TestSealKeys(t *testing.T) {
	gen, err := artifact.GenerateSealKey()
	if err != nil {
		t.Fatal(err)
	}
	gen2, err := artifact.GenerateSealKey()
	if err != nil {
		t.Fatal(err)
	}
	if gen.KeyID == gen2.KeyID || bytes.Equal(gen.Key.([]byte), gen2.Key.([]byte)) {
		t.Fatal("two generated seal keys are the same")
	}
	short := *gen
	short.Key = make([]byte, 16)
	noKID := *gen
	noKID.KeyID = ""
	ed := *genKey(t, jose.EdDSA)
	cases := []struct {
		name string
		file string // "-" for no file
		ok   bool
	}{
		{name: "a generated key loads", file: jwkJSON(t, *gen), ok: true},
		{name: "a missing file", file: "-"},
		{name: "not JSON", file: "{"},
		{name: "a 16-byte key", file: jwkJSON(t, short)},
		{name: "a key without a kid", file: jwkJSON(t, noKID)},
		{name: "an asymmetric key", file: jwkJSON(t, ed)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "seal.jwk")
			if c.file != "-" {
				writeFile(t, path, c.file)
			}
			k, err := artifact.LoadSealKey(path)
			if !c.ok {
				if err == nil {
					t.Fatalf("LoadSealKey accepted %s", c.file)
				}
				return
			}
			if err != nil || k.ID != gen.KeyID || !bytes.Equal(k.Key, gen.Key.([]byte)) {
				t.Fatalf("LoadSealKey = %+v, %v; want the generated key %s", k, err, gen.KeyID)
			}
		})
	}
}

// TestSealSizes round-trips plaintexts around the chunk size. A file of
// n whole chunks seals to n chunks, with no empty one after them.
func TestSealSizes(t *testing.T) {
	key := &artifact.SealKey{ID: "k", Key: bytes.Repeat([]byte{7}, 32)}
	sc := artifact.SealContext{Domain: "D", Session: "S", Expires: time.Now().Add(time.Hour)}
	cases := []struct {
		name   string
		size   int
		chunks int
	}{
		{name: "empty", size: 0, chunks: 1},
		{name: "one byte", size: 1, chunks: 1},
		{name: "a byte short of a chunk", size: sealChunk - 1, chunks: 1},
		{name: "exactly a chunk", size: sealChunk, chunks: 1},
		{name: "a byte past a chunk", size: sealChunk + 1, chunks: 2},
		{name: "exactly two chunks", size: 2 * sealChunk, chunks: 2},
	}
	overhead := -1 // the header's size, the same for every case
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			plain := make([]byte, c.size)
			for i := range plain {
				plain[i] = byte(i * 31)
			}
			src, dst := t.TempDir(), t.TempDir()
			writeFile(t, filepath.Join(src, "pages-1.img"), string(plain))
			if err := artifact.SealDir(src, dst, key, sc); err != nil {
				t.Fatal(err)
			}
			fi, err := os.Stat(filepath.Join(dst, "pages-1.img"))
			if err != nil {
				t.Fatal(err)
			}
			header := int(fi.Size()) - c.size - 16*c.chunks
			if overhead >= 0 && header != overhead {
				t.Fatalf("sealed %d bytes: %d chunks would leave a %d-byte header, others have %d", fi.Size(), c.chunks, header, overhead)
			}
			overhead = header
			if _, err := artifact.OpenDir(dst, key, "D", "S", time.Now()); err != nil {
				t.Fatal(err)
			}
			if b, _ := os.ReadFile(filepath.Join(dst, "pages-1.img")); !bytes.Equal(b, plain) {
				t.Fatalf("opened %d bytes, want the %d sealed", len(b), len(plain))
			}
		})
	}
}

func TestSealDirErrors(t *testing.T) {
	key := &artifact.SealKey{ID: "k", Key: make([]byte, 32)}
	sc := artifact.SealContext{Domain: "D", Session: "S", Expires: time.Now().Add(time.Hour)}
	cases := []struct {
		name string
		key  *artifact.SealKey
		// setup returns the source and destination directories.
		setup func(t *testing.T) (src, dst string)
		want  error // nil when any error will do
	}{
		{name: "no key", setup: func(t *testing.T) (string, string) { return t.TempDir(), t.TempDir() }},
		{name: "a missing source", key: key, want: os.ErrNotExist,
			setup: func(t *testing.T) (string, string) { return filepath.Join(t.TempDir(), "missing"), t.TempDir() }},
		{name: "a destination under a regular file", key: key, want: syscall.ENOTDIR,
			setup: func(t *testing.T) (string, string) {
				root := t.TempDir()
				writeFile(t, filepath.Join(root, "file"), "")
				return t.TempDir(), filepath.Join(root, "file", "dst")
			}},
		{name: "a directory where a sealed file goes", key: key, want: syscall.EISDIR,
			setup: func(t *testing.T) (string, string) {
				src, dst := t.TempDir(), t.TempDir()
				writeFile(t, filepath.Join(src, "pages-1.img"), "pages")
				writeFile(t, filepath.Join(dst, "pages-1.img", "inner"), "")
				return src, dst
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src, dst := c.setup(t)
			err := artifact.SealDir(src, dst, c.key, sc)
			if err == nil || (c.want != nil && !errors.Is(err, c.want)) {
				t.Fatalf("SealDir = %v, want %v", err, c.want)
			}
		})
	}
}

func TestOpenDirErrors(t *testing.T) {
	key := &artifact.SealKey{ID: "k", Key: make([]byte, 32)}
	cases := []struct {
		name string
		key  *artifact.SealKey
		dir  func(t *testing.T) string
		want error // nil when any error will do
	}{
		{name: "no key", dir: func(t *testing.T) string { return t.TempDir() }},
		{name: "a missing directory", key: key, want: os.ErrNotExist,
			dir: func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing") }},
		{name: "nothing sealed", key: key, want: artifact.ErrSealed, dir: func(t *testing.T) string {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "dump.log"), "logs never travel")
			return dir
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := artifact.OpenDir(c.dir(t), c.key, "D", "S", time.Now())
			if err == nil || (c.want != nil && !errors.Is(err, c.want)) {
				t.Fatalf("OpenDir = %v, want %v", err, c.want)
			}
			if c.key == nil && !strings.Contains(err.Error(), "no seal key") {
				t.Fatalf("OpenDir without a key = %v", err)
			}
		})
	}
}
