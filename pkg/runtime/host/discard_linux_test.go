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
		fence   string // the manifest's fence, "" for no manifest
		wantErr bool
		gone    bool // the ref's directory no longer exists
		// portsLeft is how many of the two held ports (g1/1/1 on 20000,
		// g1/1/2 on 20001) are still held afterwards.
		portsLeft int
	}{
		{name: "a claimed copy in the delta store is removed",
			ref: func(d, _ string) string { return filepath.Join(d, "g1", "claimed-s-1") }, gone: true, portsLeft: 2},
		{name: "a parked delta claimed elsewhere is removed and gives its port back",
			ref: func(d, _ string) string { return filepath.Join(d, "g1", "claimed-s-1") }, fence: "g1/1/1", gone: true, portsLeft: 1},
		{name: "a delta of another fence frees no port but its own",
			ref: func(d, _ string) string { return filepath.Join(d, "g1", "claimed-s-1") }, fence: "g1/1/9", gone: true, portsLeft: 2},
		{name: "a path outside the delta store is refused",
			ref: func(_, o string) string { return o }, wantErr: true, portsLeft: 2},
		{name: "a path climbing out of the store is refused",
			ref: func(d, o string) string { return filepath.Join(d, "..", filepath.Base(o)) }, wantErr: true, portsLeft: 2},
		{name: "the store itself is refused",
			ref: func(d, _ string) string { return d }, wantErr: true, portsLeft: 2},
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
			r := &Runtime{cfg: Config{DeltaDir: deltas}, ports: map[int]string{20000: "g1/1/1", 20001: "g1/1/2"}}
			ref := tc.ref(deltas, outside)
			if tc.fence != "" {
				if err := writeJSON(filepath.Join(ref, "manifest.json"), manifest{Fence: tc.fence, GrantUID: "g1", Endpoint: "tcp://127.0.0.1:20000"}); err != nil {
					t.Fatal(err)
				}
			}
			err := r.DiscardDelta(context.Background(), ref)
			if (err != nil) != tc.wantErr {
				t.Fatalf("DiscardDelta(%s) = %v, want error %v", ref, err, tc.wantErr)
			}
			if len(r.ports) != tc.portsLeft {
				t.Fatalf("ports held = %v, want %d", r.ports, tc.portsLeft)
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
