//go:build linux

package host

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
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

// TestSweepDeltas lays out a delta store with parked deltas, claimed
// copies, a crashed park's staging file, scratch and an engine log, and
// sweeps it. Every entry under a grant that keep does not name goes, with
// the port its manifest's fence held. Scratch, the engine logs and
// anything outside the store stay.
func TestSweepDeltas(t *testing.T) {
	// The store's entries, relative to it. A fence gives the entry a
	// manifest whose fence holds a port. file marks a plain file.
	layout := []struct {
		path  string
		fence string
		file  bool
	}{
		{path: "g1/1-1", fence: "g1/1/1"},
		{path: "g1/1-2", fence: "g1/1/2"},
		{path: "g1/claimed-s-abc-1"},
		{path: "g1/claimed-s-def-2"},
		{path: "g1/1-3.slice", file: true},
		{path: "g1/.import-x"},
		{path: "g2/1-1"},
		{path: ".engine-logs/g1"},
		{path: "stray", file: true},
	}
	all := []string{"g1/1-1", "g1/1-2", "g1/claimed-s-abc-1", "g1/claimed-s-def-2", "g1/1-3.slice", "g2/1-1"}
	cases := []struct {
		name    string
		keep    []string // relative to the store
		raw     []string // kept as given, not joined to the store
		missing bool     // the store does not exist
		// linked reaches the store through a symlink, while keep names
		// the real path, as when -delta-dir was respelt between boots.
		linked bool
		// wantGone is what the sweep removed, relative to the store.
		wantGone  []string
		portsLeft int // of the two held ports, g1/1/1 on 20000 and g1/1/2 on 20001
	}{
		{name: "what no parked session names goes, with its port",
			keep:     []string{"g1/1-1", "g1/claimed-s-def-2"},
			wantGone: []string{"g1/1-2", "g1/claimed-s-abc-1", "g1/1-3.slice", "g2/1-1"}, portsLeft: 1},
		{name: "a keep naming every delta removes nothing", keep: all, portsLeft: 2},
		{name: "a keep in another spelling still names its delta",
			keep: []string{"g1/1-2", "g1/claimed-s-abc-1", "g1/claimed-s-def-2", "g1/1-3.slice", "g2/1-1"},
			raw:  []string{"DELTAS/g1/./1-1/"}, portsLeft: 2},
		{name: "a keep naming the real path keeps a delta reached through a symlink", linked: true,
			keep:     []string{"g1/1-1", "g1/claimed-s-def-2"},
			wantGone: []string{"g1/1-2", "g1/claimed-s-abc-1", "g1/1-3.slice", "g2/1-1"}, portsLeft: 1},
		{name: "an empty keep sweeps every delta but scratch", wantGone: all},
		{name: "a store that does not exist sweeps nothing", missing: true, portsLeft: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			deltas, outside := filepath.Join(root, "deltas"), filepath.Join(root, "outside")
			if err := os.MkdirAll(outside, 0o755); err != nil {
				t.Fatal(err)
			}
			if !tc.missing {
				for _, e := range layout {
					p := filepath.Join(deltas, e.path)
					if e.file {
						if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
							t.Fatal(err)
						}
						continue
					}
					if err := os.MkdirAll(p, 0o755); err != nil {
						t.Fatal(err)
					}
					if e.fence != "" {
						if err := writeJSON(filepath.Join(p, "manifest.json"), manifest{Fence: e.fence, GrantUID: "g1"}); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			dir := deltas
			if tc.linked {
				dir = filepath.Join(root, "link")
				if err := os.Symlink(deltas, dir); err != nil {
					t.Fatal(err)
				}
			}
			r := &Runtime{cfg: Config{DeltaDir: dir}, ports: map[int]string{20000: "g1/1/1", 20001: "g1/1/2"}}
			var keep []string
			for _, k := range tc.keep {
				keep = append(keep, filepath.Join(deltas, k))
			}
			for _, k := range tc.raw {
				keep = append(keep, strings.Replace(k, "DELTAS", deltas, 1))
			}
			n, err := r.SweepDeltas(context.Background(), keep)
			if err != nil {
				t.Fatalf("SweepDeltas = %v", err)
			}
			if n != len(tc.wantGone) {
				t.Fatalf("SweepDeltas removed %d, want %d", n, len(tc.wantGone))
			}
			if len(r.ports) != tc.portsLeft {
				t.Fatalf("ports held = %v, want %d", r.ports, tc.portsLeft)
			}
			if tc.missing {
				return
			}
			for _, e := range layout {
				_, serr := os.Stat(filepath.Join(deltas, e.path))
				if gone := os.IsNotExist(serr); gone != slices.Contains(tc.wantGone, e.path) {
					t.Fatalf("%s gone = %v, want %v", e.path, gone, !gone)
				}
			}
			if _, serr := os.Stat(outside); serr != nil {
				t.Fatalf("outside directory touched: %v", serr)
			}
		})
	}
}
