package cli

import (
	"runtime/debug"
	"testing"
)

// TestVersion checks that a stamped version wins, then the module
// version Go recorded, and "dev" when there is neither.
func TestVersion(t *testing.T) {
	built := func(v string) *debug.BuildInfo { return &debug.BuildInfo{Main: debug.Module{Version: v}} }
	cases := []struct {
		name    string
		stamped string
		info    *debug.BuildInfo
		want    string
	}{
		{name: "the stamp wins", stamped: "v0.1.0", info: built("v0.0.0-20260101000000-abcdef123456"), want: "v0.1.0"},
		{name: "go install records the module version", info: built("v0.2.0"), want: "v0.2.0"},
		{name: "a VCS pseudo-version is kept", info: built("v0.0.0-20260101000000-abcdef123456+dirty"), want: "v0.0.0-20260101000000-abcdef123456+dirty"},
		{name: "a devel build is dev", info: built("(devel)"), want: "dev"},
		{name: "no version is dev", info: built(""), want: "dev"},
		{name: "no build info is dev", want: "dev"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := version(tc.stamped, tc.info); got != tc.want {
				t.Fatalf("version(%q) = %q, want %q", tc.stamped, got, tc.want)
			}
		})
	}
}
