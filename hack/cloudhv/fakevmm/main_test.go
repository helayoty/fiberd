package main

import (
	"errors"
	"net/http"
	"testing"
)

// TestParseRestore checks that the fake takes the restore options v54.0
// takes and refuses the ones it refuses.
func TestParseRestore(t *testing.T) {
	cases := []struct {
		name    string
		opts    string
		wantDir string
		refused bool
	}{
		{name: "no mode", opts: "source_url=file:///snap", wantDir: "/snap"},
		{name: "copy", opts: "source_url=file:///snap,memory_restore_mode=copy", wantDir: "/snap"},
		{name: "ondemand", opts: "source_url=file:///snap,memory_restore_mode=ondemand", wantDir: "/snap"},
		{name: "copyonwrite", opts: "source_url=file:///snap,memory_restore_mode=copyonwrite", wantDir: "/snap"},
		{name: "resume", opts: "source_url=file:///snap,resume=false", wantDir: "/snap"},
		{name: "prefault with copy", opts: "source_url=file:///snap,memory_restore_mode=copy,prefault=on", wantDir: "/snap"},
		{name: "prefault with no mode", opts: "source_url=file:///snap,prefault=on", wantDir: "/snap"},
		{name: "prefault with ondemand", opts: "source_url=file:///snap,memory_restore_mode=ondemand,prefault=on", refused: true},
		{name: "prefault with copyonwrite", opts: "source_url=file:///snap,prefault=on,memory_restore_mode=copyonwrite", refused: true},
		{name: "unknown mode", opts: "source_url=file:///snap,memory_restore_mode=cow", refused: true},
		{name: "unknown option", opts: "source_url=file:///snap,bogus=1", refused: true},
		{name: "source not a file url", opts: "source_url=/snap", refused: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := parseRestore(tc.opts)
			if tc.refused {
				var ae *apiError
				if !errors.As(err, &ae) || ae.code != http.StatusBadRequest {
					t.Fatalf("parseRestore(%q) = %q, %v, want a 400 refusal", tc.opts, dir, err)
				}
				return
			}
			if err != nil || dir != tc.wantDir {
				t.Fatalf("parseRestore(%q) = %q, %v, want %q", tc.opts, dir, err, tc.wantDir)
			}
		})
	}
}
