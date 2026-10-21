package artifact_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/helayoty/fiberd/pkg/artifact"
)

// Seal and open of 32 MiB, the size of the refzygote parent. Numbers,
// not claims. Run with go test -run x -bench Seal -benchtime 5x.

const benchSize = 32 << 20

func benchPlain(b *testing.B) string {
	b.Helper()
	dir := b.TempDir()
	buf := make([]byte, benchSize)
	for i := range buf {
		buf[i] = byte(i * 17)
	}
	if err := os.WriteFile(filepath.Join(dir, "pages-1.img"), buf, 0o644); err != nil {
		b.Fatal(err)
	}
	return dir
}

func BenchmarkSealParent32MiB(b *testing.B) {
	key := &artifact.SealKey{ID: "k", Key: bytes.Repeat([]byte{3}, 32)}
	src := benchPlain(b)
	b.SetBytes(benchSize)
	b.ResetTimer()
	for b.Loop() {
		if err := artifact.SealParentDir(src, b.TempDir(), key, shaA); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOpenParent32MiB(b *testing.B) {
	key := &artifact.SealKey{ID: "k", Key: bytes.Repeat([]byte{3}, 32)}
	src := benchPlain(b)
	sealed := b.TempDir()
	if err := artifact.SealParentDir(src, sealed, key, shaA); err != nil {
		b.Fatal(err)
	}
	sb, err := os.ReadFile(filepath.Join(sealed, "pages-1.img"))
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(benchSize)
	b.ResetTimer()
	for b.Loop() {
		b.StopTimer()
		dir := b.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "pages-1.img"), sb, 0o644); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		if err := artifact.OpenParentDir(dir, key, shaA); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSealImages32MiB(b *testing.B) {
	w, err := artifact.DeriveWrapKey(&artifact.SealKey{ID: "k", Key: bytes.Repeat([]byte{3}, 32)})
	if err != nil {
		b.Fatal(err)
	}
	src := filepath.Join(benchPlain(b), "pages-1.img")
	b.SetBytes(benchSize)
	b.ResetTimer()
	for b.Loop() {
		if _, err := artifact.SealImages(src, filepath.Join(b.TempDir(), "images.tar"), w.Public()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOpenImages32MiB(b *testing.B) {
	master := &artifact.SealKey{ID: "k", Key: bytes.Repeat([]byte{3}, 32)}
	w, err := artifact.DeriveWrapKey(master)
	if err != nil {
		b.Fatal(err)
	}
	src := filepath.Join(benchPlain(b), "pages-1.img")
	sealed := filepath.Join(b.TempDir(), "images.tar")
	s, err := artifact.SealImages(src, sealed, w.Public())
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(benchSize)
	b.ResetTimer()
	for b.Loop() {
		out := filepath.Join(b.TempDir(), "images.tar.open")
		if err := artifact.OpenImages(sealed, out, master, s); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSHA256of32MiB is what a hash check alone costs, for scale.
func BenchmarkSHA256of32MiB(b *testing.B) {
	src := filepath.Join(benchPlain(b), "pages-1.img")
	b.SetBytes(benchSize)
	b.ResetTimer()
	for b.Loop() {
		data, err := os.ReadFile(src)
		if err != nil {
			b.Fatal(err)
		}
		sum := sha256.Sum256(data)
		_ = hex.EncodeToString(sum[:])
	}
}
