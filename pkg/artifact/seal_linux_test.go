//go:build linux

package artifact_test

import (
	"errors"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/helayoty/fiberd/pkg/artifact"
)

// TestSealFullDevice seals into /dev/full, where every write fails as on
// a full disk: the seal must fail, not leave a short file unnoticed.
func TestSealFullDevice(t *testing.T) {
	key := &artifact.SealKey{ID: "k", Key: make([]byte, 32)}
	sc := artifact.SealContext{Domain: "D", Session: "S", Expires: time.Now().Add(time.Hour)}
	cases := []struct {
		name string
		size int
	}{
		{name: "a file smaller than the write buffer fails on flush", size: 10},
		{name: "a chunk written straight through fails", size: 2 * sealChunk},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := t.TempDir()
			writeFile(t, filepath.Join(src, "full"), strings.Repeat("x", c.size))
			err := artifact.SealDir(src, "/dev", key, sc)
			if !errors.Is(err, syscall.ENOSPC) {
				t.Fatalf("SealDir into /dev/full = %v, want ENOSPC", err)
			}
		})
	}
}
