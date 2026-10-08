//go:build linux

package controller

import (
	"testing"

	"github.com/helayoty/fiberd/pkg/backend"
	gvisorbackend "github.com/helayoty/fiberd/pkg/backend/gvisor"
	hlbackend "github.com/helayoty/fiberd/pkg/backend/hyperlight"
	procbackend "github.com/helayoty/fiberd/pkg/backend/proc"
	runcbackend "github.com/helayoty/fiberd/pkg/backend/runc"
)

// TestIsolatingMatchesTheBackends checks that the runtimes the controller
// lets serve UNTRUSTED are the ones whose backend says it isolates tenants.
func TestIsolatingMatchesTheBackends(t *testing.T) {
	cases := []struct {
		runtime string
		backend any // a nil pointer of the backend's type
	}{
		{"proc", (*procbackend.Backend)(nil)},
		{"runc", (*runcbackend.Backend)(nil)},
		{"gvisor", (*gvisorbackend.Backend)(nil)},
		{"hyperlight", (*hlbackend.Backend)(nil)},
	}
	covered := map[string]bool{}
	for _, tc := range cases {
		covered[tc.runtime] = true
	}
	for name := range isolating {
		if !covered[name] {
			t.Errorf("isolating names %q, which no backend case covers", name)
		}
	}
	for _, tc := range cases {
		t.Run(tc.runtime, func(t *testing.T) {
			iso, ok := tc.backend.(backend.Isolator)
			want := ok && iso.IsolatesTenants()
			if got := isolating[tc.runtime]; got != want {
				t.Fatalf("isolating[%q] = %v, but the backend isolates tenants = %v", tc.runtime, got, want)
			}
		})
	}
}
