//go:build linux

package agent

import (
	"path/filepath"
	"testing"
)

// TestProcOptions checks that the fork backend gets -criu and the bind of the
// host's root a resume restores under, inside the private directory.
func TestProcOptions(t *testing.T) {
	cases := []struct {
		name, state, criu string
	}{
		{name: "defaults", state: "/var/lib/fiberd", criu: "criu"},
		{name: "a criu path", state: "/s", criu: "/opt/criu/sbin/criu"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{StateDir: tc.state, CRIUBin: tc.criu}
			o := c.procOptions()
			if want := filepath.Join(tc.state, "private", "root"); o.CRIU != tc.criu || o.RootBind != want {
				t.Fatalf("procOptions = CRIU %q RootBind %q, want %q %q", o.CRIU, o.RootBind, tc.criu, want)
			}
		})
	}
}
