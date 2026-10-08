//go:build linux

package host

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDiscardDelta(t *testing.T) {
	cases := []struct {
		name    string
		ref     func(deltas, outside string) string
		wantErr bool
		gone    bool // the ref's directory no longer exists
	}{
		{name: "a claimed copy in the delta store is removed",
			ref: func(d, _ string) string { return filepath.Join(d, "g1", "claimed-s-1") }, gone: true},
		{name: "a path outside the delta store is refused",
			ref: func(_, o string) string { return o }, wantErr: true},
		{name: "a path climbing out of the store is refused",
			ref: func(d, o string) string { return filepath.Join(d, "..", filepath.Base(o)) }, wantErr: true},
		{name: "the store itself is refused",
			ref: func(d, _ string) string { return d }, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			deltas, outside := filepath.Join(root, "deltas"), filepath.Join(root, "outside")
			for _, d := range []string{filepath.Join(deltas, "g1", "claimed-s-1"), outside} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			r := &Runtime{cfg: Config{DeltaDir: deltas}}
			ref := tc.ref(deltas, outside)
			err := r.DiscardDelta(context.Background(), ref)
			if (err != nil) != tc.wantErr {
				t.Fatalf("DiscardDelta(%s) = %v, want error %v", ref, err, tc.wantErr)
			}
			if _, serr := os.Stat(ref); os.IsNotExist(serr) != tc.gone {
				t.Fatalf("%s gone = %v, want %v", ref, os.IsNotExist(serr), tc.gone)
			}
			if _, serr := os.Stat(outside); serr != nil {
				t.Fatalf("outside directory touched: %v", serr)
			}
		})
	}
}
