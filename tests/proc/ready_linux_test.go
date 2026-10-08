//go:build linux

package proctest

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestMisusedReadinessPipeDoesNotWedgeZygote: the readiness pipe sits at
// the fiber's fd 3, and a workload that writes to it, closes it or calls
// fz_report (which wrote to it, since the child inherited the zygote's
// control descriptor number) used to leave the zygote blocked in waitpid
// on a child that was alive and well, with every later clone of the
// grant behind it. The zygote now refuses such a fiber with an ERROR and
// serves the next clone. Each case ends with a plain clone on the same
// zygote, bounded by the clone deadline, so a wedge fails rather than
// hangs.
func TestMisusedReadinessPipeDoesNotWedgeZygote(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		// wantErr is a fragment of the clone error, "" when the clone
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
