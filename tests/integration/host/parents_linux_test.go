//go:build linux && integration

package hosttest

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/runtime/host"
)

// TestParentStoreMovesAcrossFilesystems checks a template cache whose
// parent store sits on another file system. The warm instance's
// self-checkpoint cannot be renamed into it, so the template stays warm
// without a parent and its parks are full images. On one file system
// the checkpoint is filed and parks are deltas over it.
func TestParentStoreMovesAcrossFilesystems(t *testing.T) {
	if st, err := os.Stat("/dev/shm"); err != nil || !st.IsDir() {
		t.Skip("no /dev/shm for a store on another file system")
	}
	cases := []struct {
		name  string
		other bool // the store is on another file system
		delta bool // the park is a delta
	}{
		{name: "the store on another file system: parks are full images", other: true},
		{name: "the store on the cache's file system: parks are deltas", delta: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cache string
			r, h := prepared(t, checkpointing{newFake(core.TierCheckpoint)}, sized, func(c *host.Config) {
				cache = c.TemplateCache
				if !tc.other {
					return
				}
				store, err := os.MkdirTemp("/dev/shm", "hosttest-")
				if err != nil {
					t.Skipf("cannot write /dev/shm: %v", err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(store) })
				if err := os.MkdirAll(cache, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(store, filepath.Join(cache, "parents")); err != nil {
					t.Fatal(err)
				}
			})
			ref, err := r.Park(context.Background(), h.ID, false)
			if err != nil {
				t.Fatalf("Park: %v", err)
			}
			b, err := os.ReadFile(filepath.Join(ref, "manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			var m struct {
				Delta  bool   `json:"delta"`
				Parent string `json:"parent_sha256"`
			}
			if err := json.Unmarshal(b, &m); err != nil {
				t.Fatal(err)
			}
			stored := exists(filepath.Join(cache, "parents", shaOf("zygote pages of g1"), "pages"))
			if m.Delta != tc.delta || stored != tc.delta || (tc.delta && m.Parent != shaOf("zygote pages of g1")) {
				t.Fatalf("manifest = %+v, parent stored %v, want delta %v", m, stored, tc.delta)
			}
			if tc.delta && exists(filepath.Join(cache, "zygote-images", "g1")) {
				t.Fatal("the filed self-checkpoint was left in the cache")
			}
		})
	}
}
