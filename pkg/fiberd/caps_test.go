package fiberd

import (
	"errors"
	"slices"
	"testing"

	"github.com/Azure/fiberd/pkg/sys/caps"
)

// TestNarrowCaps checks that fiberd narrows only for a measured runtime that
// holds more than it needs, and fails closed when it cannot. -all-caps is
// the only way to run on with every capability.
func TestNarrowCaps(t *testing.T) {
	cases := []struct {
		name       string
		runtime    string
		engine     string
		allCaps    bool
		extra      []int
		narrowErr  error
		wantCall   bool
		wantNarrow []int // the keep list Narrow gets
		wantErr    error
	}{
		{name: "proc narrows to its set", runtime: "proc", extra: []int{caps.Kill}, wantCall: true, wantNarrow: caps.Proc},
		{name: "runc narrows to its set", runtime: "runc", extra: []int{caps.Kill}, wantCall: true, wantNarrow: caps.Runc},
		{name: "gvisor narrows to its set", runtime: "gvisor", extra: []int{caps.Kill}, wantCall: true, wantNarrow: caps.GVisor},
		{name: "hyperlight narrows to nothing", runtime: "hyperlight", extra: []int{caps.Kill}, wantCall: true, wantNarrow: []int{}},
		{name: "nothing extra is held", runtime: "proc"},
		{name: "cloudhv keeps what it has", runtime: "cloudhv", extra: []int{caps.Kill}},
		{name: "stub keeps what it has", runtime: "stub", extra: []int{caps.Kill}},
		{name: "all-caps skips narrowing", runtime: "proc", allCaps: true, extra: []int{caps.Kill}, narrowErr: caps.ErrCannotNarrow},
		{
			name: "cannot narrow fails closed", runtime: "proc", extra: []int{caps.Kill},
			narrowErr: caps.ErrCannotNarrow, wantCall: true, wantNarrow: caps.Proc, wantErr: caps.ErrCannotNarrow,
		},
		{
			name: "runc cannot narrow fails closed", runtime: "runc", extra: []int{caps.Kill},
			narrowErr: caps.ErrCannotNarrow, wantCall: true, wantNarrow: caps.Runc, wantErr: caps.ErrCannotNarrow,
		},
		{
			name: "an engine on proc adds its uid changes", runtime: "proc", engine: "/usr/bin/engine", extra: []int{caps.Kill},
			wantCall: true, wantNarrow: append(append([]int{}, caps.Proc...), caps.Chown, caps.SetUID, caps.SetGID),
		},
		{
			name: "an engine on gvisor adds SETPCAP and CHOWN", runtime: "gvisor", engine: "/usr/bin/engine", extra: []int{caps.Kill},
			wantCall: true, wantNarrow: append(append([]int{}, caps.GVisor...), caps.Chown, caps.SetPCAP),
		},
		{
			name: "an engine on hyperlight needs only what starting it needs", runtime: "hyperlight", engine: "/usr/bin/engine", extra: []int{caps.Kill},
			wantCall: true, wantNarrow: caps.Engine,
		},
		{name: "an engine on an unmeasured runtime changes nothing", runtime: "cloudhv", engine: "/usr/bin/engine", extra: []int{caps.Kill}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oldExtra, oldNarrow := capsExtra, capsNarrow
			t.Cleanup(func() { capsExtra, capsNarrow = oldExtra, oldNarrow })
			capsExtra = func([]int) []int { return tc.extra }
			var got []int
			called := false
			capsNarrow = func(keep []int) error {
				got, called = keep, true
				return tc.narrowErr
			}
			c := Config{Runtime: Runtime{Name: tc.runtime}, Node: Node{AllCaps: tc.allCaps}}
			c.Runtime.Engine.Command = tc.engine
			err := c.NarrowCaps()
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("NarrowCaps: err = %v, want %v", err, tc.wantErr)
			}
			if called != tc.wantCall {
				t.Fatalf("Narrow called: %v, want %v", called, tc.wantCall)
			}
			if !slices.Equal(got, tc.wantNarrow) {
				t.Fatalf("Narrow got keep %v, want %v", got, tc.wantNarrow)
			}
		})
	}
}
