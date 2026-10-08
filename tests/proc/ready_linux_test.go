//go:build linux

package proctest

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestMisusedReadinessPipeDoesNotWedgeZygote pins that a fiber which
// writes to or closes the readiness pipe at its fd 3 is refused, and that
// fz_report from a fiber fails instead of reaching the pipe. The zygote
// must not block in waitpid on a live child, so each case ends with a plain
// clone on the same zygote, bounded by the clone deadline.
func TestMisusedReadinessPipeDoesNotWedgeZygote(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		// wantErr is a fragment of the clone error, or "" when the clone
		// must succeed.
		wantErr string
	}{
		{name: "stray byte on fd 3", payload: `{"ready_misuse": 1}`, wantErr: "readiness pipe instead of reporting ready"},
		{name: "fd 3 closed without reporting", payload: `{"ready_misuse": 2}`, wantErr: "closed the readiness pipe without reporting ready"},
		{name: "fz_report from a fiber fails instead of reaching the pipe", payload: `{"ready_misuse": 3}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			be, w := warmDirect(t, dir, nil)
			_, err := cloneDirect(t, be, w, dir, "gd/2-1", tc.payload)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("clone: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("clone = %v, want an error mentioning %q", err, tc.wantErr)
			}
			// The same zygote serves the next clone.
			f, err := cloneDirect(t, be, w, dir, "gd/2-2", "")
			if err != nil {
				t.Fatalf("clone after the misused pipe: %v (the zygote is wedged)", err)
			}
			if got := talk(t, filepath.Join(dir, "gd-2-2.sock"), "fence"); got != f.ID {
				t.Fatalf("fence = %q, want %s", got, f.ID)
			}
		})
	}
}
