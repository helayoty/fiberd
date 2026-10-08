package grant_test

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/core"
	"github.com/helayoty/fiberd/pkg/grant"
)

// A grant survives the trip to the wire and back. Optional parts stay
// absent on the wire when the grant leaves them unset.
func TestProtoRoundTrip(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	full := sample(now)
	full.CallerThumbprint = "" // carried in the cnf claim, not the proto

	cases := []struct {
		name         string
		g            core.Grant
		wantLease    bool
		wantDevBytes uint64 // 0 with wantDev false means no device budget on the wire
		wantDev      bool
	}{
		{name: "every field set", g: full, wantLease: true, wantDev: true, wantDevBytes: 1 << 30},
		{name: "zero grant has no lease and no device budget", g: core.Grant{UID: "g"}},
		{name: "a device class without bytes still travels",
			g: core.Grant{UID: "g", DeviceBudget: core.DeviceBudget{Class: "gpu"}}, wantDev: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := grant.ToProto(tc.g)
			if (p.GetLeaseExpiry() != nil) != tc.wantLease {
				t.Fatalf("lease on wire = %v, want %v", p.GetLeaseExpiry(), tc.wantLease)
			}
			if (p.GetDeviceBudget() != nil) != tc.wantDev || p.GetDeviceBudget().GetBytes() != tc.wantDevBytes {
				t.Fatalf("device budget on wire = %v, want present %v with %d bytes", p.GetDeviceBudget(), tc.wantDev, tc.wantDevBytes)
			}
			if got := grant.FromProto(p); got != tc.g {
				t.Fatalf("round trip\n got %+v\nwant %+v", got, tc.g)
			}
		})
	}
}

// FromProto reads what a peer sent, so it tolerates nil parts and an
// out-of-range lease.
func TestFromProtoTolerates(t *testing.T) {
	cases := []struct {
		name string
		p    *grantv1.CapacityGrant
		want core.Grant
	}{
		{name: "a nil message is the zero grant", p: nil, want: core.Grant{}},
		{name: "a lease past year 9999 is ignored",
			p:    &grantv1.CapacityGrant{GrantUid: "g", LeaseExpiry: &timestamppb.Timestamp{Seconds: 1 << 62}},
			want: core.Grant{UID: "g"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := grant.FromProto(tc.p); got != tc.want {
				t.Fatalf("FromProto = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestDeadline(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	cases := []struct {
		name   string
		ts     *timestamppb.Timestamp
		want   time.Duration
		wantOK bool
	}{
		{name: "no deadline", ts: nil},
		{name: "an invalid timestamp is no deadline", ts: &timestamppb.Timestamp{Nanos: -1}},
		{name: "a future deadline is the time left", ts: timestamppb.New(now.Add(3 * time.Second)), want: 3 * time.Second, wantOK: true},
		{name: "a past deadline is negative", ts: timestamppb.New(now.Add(-time.Second)), want: -time.Second, wantOK: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := grant.Deadline(tc.ts, now)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("Deadline = %v, %v, want %v, %v", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}
