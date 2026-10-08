//go:build !linux

package caps_test

import (
	"testing"

	"github.com/helayoty/fiberd/pkg/sys/caps"
)

// TestNoCapabilities: off Linux there are no capabilities to hold or
// to narrow.
func TestNoCapabilities(t *testing.T) {
	cases := []struct {
		name string
		keep []int
	}{
		{name: "nothing kept"},
		{name: "the proc set", keep: caps.Proc},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := caps.Extra(tc.keep); got != nil {
				t.Fatalf("Extra = %v, want nil", got)
			}
			if err := caps.Narrow(tc.keep); err != nil {
				t.Fatalf("Narrow = %v, want nil", err)
			}
		})
	}
}
