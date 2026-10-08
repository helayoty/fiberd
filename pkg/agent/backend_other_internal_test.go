//go:build !linux

package agent

import "testing"

// TestProcOptions: off Linux the fork backend only gets -criu.
func TestProcOptions(t *testing.T) {
	cases := []struct {
		name, criu string
	}{
		{name: "defaults", criu: "criu"},
		{name: "a criu path", criu: "/opt/criu/sbin/criu"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{StateDir: "/s", CRIUBin: tc.criu}
			if o := c.procOptions(); o.CRIU != tc.criu {
				t.Fatalf("procOptions CRIU %q, want %q", o.CRIU, tc.criu)
			}
		})
	}
}
