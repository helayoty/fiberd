package agent

import (
	"errors"
	"slices"
	"testing"

	"github.com/helayoty/fiberd/pkg/sys/caps"
)

// TestNarrowCaps checks that the agent narrows only for a measured runtime that
// holds more than it needs, and fails closed when it cannot. -all-caps is
// the only way to run on with every capability.
func TestNarrowCaps(t *testing.T) {
	cases := []struct {
		name       string
		runtime    string
		allCaps    bool
		extra      []int
		narrowErr  error
		wantNarrow []int // the keep list Narrow gets, nil when not called
		wantErr    error
	}{
		{name: "proc narrows to its set", runtime: "proc", extra: []int{caps.Kill}, wantNarrow: caps.Proc},
		{name: "runc narrows to its set", runtime: "runc", extra: []int{caps.Kill}, wantNarrow: caps.Runc},
		{name: "nothing extra is held", runtime: "proc"},
		{name: "unmeasured runtime keeps what it has", runtime: "gvisor", extra: []int{caps.Kill}},
		{name: "stub keeps what it has", runtime: "stub", extra: []int{caps.Kill}},
		{name: "all-caps skips narrowing", runtime: "proc", allCaps: true, extra: []int{caps.Kill}, narrowErr: caps.ErrCannotNarrow},
		{
			name: "cannot narrow fails closed", runtime: "proc", extra: []int{caps.Kill},
			narrowErr: caps.ErrCannotNarrow, wantNarrow: caps.Proc, wantErr: caps.ErrCannotNarrow,
		},
		{
			name: "runc cannot narrow fails closed", runtime: "runc", extra: []int{caps.Kill},
			narrowErr: caps.ErrCannotNarrow, wantNarrow: caps.Runc, wantErr: caps.ErrCannotNarrow,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oldExtra, oldNarrow := capsExtra, capsNarrow
			t.Cleanup(func() { capsExtra, capsNarrow = oldExtra, oldNarrow })
			capsExtra = func([]int) []int { return tc.extra }
			var got []int
			capsNarrow = func(keep []int) error {
				got = keep
				return tc.narrowErr
			}
			c := Config{RuntimeName: tc.runtime, AllCaps: tc.allCaps}
			err := c.NarrowCaps()
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("NarrowCaps: err = %v, want %v", err, tc.wantErr)
			}
			if !slices.Equal(got, tc.wantNarrow) {
				t.Fatalf("Narrow got keep %v, want %v", got, tc.wantNarrow)
			}
		})
	}
}
