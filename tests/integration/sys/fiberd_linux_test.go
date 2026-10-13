//go:build linux && integration

package systest

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/helayoty/fiberd/pkg/fiberd"
)

// TestFiberdEnsurePrivateReadOnly checks that a private state directory
// whose mode fiberd cannot tighten, because it sits on a read-only
// mount, is refused before a key is written through it. The unit test
// of ensurePrivate fakes the chmod that refuses. This one mounts the
// file system that does.
func TestFiberdEnsurePrivateReadOnly(t *testing.T) {
	cases := []struct {
		name string
		mode os.FileMode // the private directory's mode before the mount
	}{
		{name: "a private dir fibers could read", mode: 0o755},
		{name: "a private dir already fiberd's alone", mode: 0o700},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := t.TempDir()
			private := filepath.Join(state, "private")
			if err := os.Mkdir(private, tc.mode); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mount(private, private, "", syscall.MS_BIND, ""); err != nil {
				t.Fatalf("bind mount: %v", err)
			}
			t.Cleanup(func() { _ = syscall.Unmount(private, syscall.MNT_DETACH) })
			if err := syscall.Mount("", private, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY, ""); err != nil {
				t.Fatalf("read-only remount: %v", err)
			}
			c := fiberd.Config{Node: fiberd.Node{StateDir: state}, Registry: fiberd.Registry{Deltas: "r.example/d"}}
			_, err := c.LoadDeltaKeys()
			for _, want := range []string{"private state dir", "read-only file system"} {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("LoadDeltaKeys = %v, want it to mention %q", err, want)
				}
			}
			fi, err := os.Lstat(private)
			if err != nil || fi.Mode().Perm() != tc.mode {
				t.Fatalf("private dir mode = %v, %v; want it left at %v", fi.Mode(), err, tc.mode)
			}
			if entries, _ := os.ReadDir(private); len(entries) != 0 {
				t.Fatalf("private dir holds %v, want no key written", entries)
			}
		})
	}
}
