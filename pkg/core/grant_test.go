package core_test

import (
	"testing"

	"github.com/helayoty/fiberd/pkg/core"
)

// TestIsolationNames checks that ParseIsolation accepts the proto names in
// any case and the empty string, refuses anything else, and that String
// gives back the proto name. Only Trusted runs outside an isolating
// runtime.
func TestIsolationNames(t *testing.T) {
	cases := []struct {
		in            string
		want          core.Isolation
		wantName      string
		wantUntrusted bool
		wantErr       bool
	}{
		{in: "UNTRUSTED", want: core.Untrusted, wantName: "UNTRUSTED", wantUntrusted: true},
		{in: "trusted", want: core.Trusted, wantName: "TRUSTED"},
		{in: "", want: core.IsolationUnspecified, wantName: "ISOLATION_UNSPECIFIED", wantUntrusted: true},
		{in: "isolation_unspecified", want: core.IsolationUnspecified, wantName: "ISOLATION_UNSPECIFIED", wantUntrusted: true},
		{in: "Unspecified", want: core.IsolationUnspecified, wantName: "ISOLATION_UNSPECIFIED", wantUntrusted: true},
		{in: "sandboxed", wantErr: true},
	}
	for _, tc := range cases {
		t.Run("parse "+tc.in, func(t *testing.T) {
			got, err := core.ParseIsolation(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseIsolation(%q) = %v %v, want error %v", tc.in, got, err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if got != tc.want || got.String() != tc.wantName || got.Untrusted() != tc.wantUntrusted {
				t.Fatalf("ParseIsolation(%q) = %v (%s, untrusted %v), want %v (%s, untrusted %v)",
					tc.in, got, got, got.Untrusted(), tc.want, tc.wantName, tc.wantUntrusted)
			}
		})
	}
}

// TestEndpointModeNames checks that ParseEndpointMode accepts the proto
// names in any case and the empty string as direct, refuses anything else,
// and that String gives back the proto name.
func TestEndpointModeNames(t *testing.T) {
	cases := []struct {
		in       string
		want     core.EndpointMode
		wantName string
		wantErr  bool
	}{
		{in: "", want: core.EndpointDirect, wantName: "DIRECT"},
		{in: "direct", want: core.EndpointDirect, wantName: "DIRECT"},
		{in: "HANDOFF", want: core.EndpointHandoff, wantName: "HANDOFF"},
		{in: "Handoff", want: core.EndpointHandoff, wantName: "HANDOFF"},
		{in: "proxy", wantErr: true},
	}
	for _, tc := range cases {
		t.Run("parse "+tc.in, func(t *testing.T) {
			got, err := core.ParseEndpointMode(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseEndpointMode(%q) = %v %v, want error %v", tc.in, got, err, tc.wantErr)
			}
			if err == nil && (got != tc.want || got.String() != tc.wantName) {
				t.Fatalf("ParseEndpointMode(%q) = %v (%s), want %v (%s)", tc.in, got, got, tc.want, tc.wantName)
			}
		})
	}
}

// TestTierNames checks that ParseTier accepts the proto enum names and the
// short forms in any case, refuses anything else, and that String gives
// back the proto name.
func TestTierNames(t *testing.T) {
	cases := []struct {
		in       string
		want     core.Tier
		wantName string
		wantErr  bool
	}{
		{in: "FIBER_BASIC", want: core.TierBasic, wantName: "FIBER_BASIC"},
		{in: "warm", want: core.TierWarm, wantName: "FIBER_WARM"},
		{in: "fiber_checkpoint", want: core.TierCheckpoint, wantName: "FIBER_CHECKPOINT"},
		{in: "Snapshot", want: core.TierSnapshot, wantName: "FIBER_SNAPSHOT"},
		{in: "FIBER_FABRIC", want: core.TierFabric, wantName: "FIBER_FABRIC"},
		{in: "", want: core.TierUnspecified, wantName: "TIER_UNSPECIFIED"},
		{in: "tier_unspecified", want: core.TierUnspecified, wantName: "TIER_UNSPECIFIED"},
		{in: "UNSPECIFIED", want: core.TierUnspecified, wantName: "TIER_UNSPECIFIED"},
		{in: "FIBER_GOLD", wantErr: true},
	}
	for _, tc := range cases {
		t.Run("parse "+tc.in, func(t *testing.T) {
			got, err := core.ParseTier(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseTier(%q) = %v %v, want error %v", tc.in, got, err, tc.wantErr)
			}
			if err == nil && (got != tc.want || got.String() != tc.wantName) {
				t.Fatalf("ParseTier(%q) = %v (%s), want %v (%s)", tc.in, got, got, tc.want, tc.wantName)
			}
		})
	}
}

// TestActionNames checks the name each clone action is audited under.
func TestActionNames(t *testing.T) {
	cases := []struct {
		act  core.Action
		want string
	}{
		{act: core.ActCreate, want: "create"},
		{act: core.ActAttach, want: "attach"},
		{act: core.ActResume, want: "resume"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			if got := tc.act.String(); got != tc.want {
				t.Fatalf("Action(%d).String() = %q, want %q", tc.act, got, tc.want)
			}
		})
	}
}
