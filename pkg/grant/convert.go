// Package grant encodes CapacityGrant as a signed JWT and verifies it
// offline. Phase 1 holds only the proto <-> core conversion and an
// insecure development verifier; Phase 2 adds signing, JWKS and the
// issuer.
package grant

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	grantv1 "github.com/helayoty/fiberd/api/grant/v1"
	"github.com/helayoty/fiberd/pkg/core"
)

// FromProto converts the wire message to the home-invariant core type.
func FromProto(p *grantv1.CapacityGrant) core.Grant {
	g := core.Grant{
		UID:            p.GetGrantUid(),
		Issuer:         p.GetIssuer(),
		Audience:       p.GetAudience(),
		TemplateDigest: p.GetTemplateDigest(),
		FiberMax:       int(p.GetFibers().GetMax()),
		FiberWarm:      int(p.GetFibers().GetWarm()),
		WBudgetBytes:   p.GetWBudgetBytes(),
		MinTier:        core.Tier(p.GetMinTier()),
	}
	if ts := p.GetLeaseExpiry(); ts != nil && ts.IsValid() {
		g.LeaseExpiry = ts.AsTime()
	}
	if pol := p.GetPolicy(); pol != nil {
		g.Policy = core.Policy{
			Durability:       core.Durability(pol.GetDurability()),
			SessionClass:     pol.GetSessionClass(),
			AuditClass:       pol.GetAuditClass(),
			PSISomeAvg10Shed: float64(pol.GetPsiSomeAvg10Shed()),
			PSISomeAvg10Park: float64(pol.GetPsiSomeAvg10Park()),
		}
	}
	if d := p.GetDeviceBudget(); d != nil {
		g.DeviceBudget = core.DeviceBudget{Bytes: d.GetBytes(), Class: d.GetClass()}
	}
	return g
}

// ToProto converts the core type back to the wire message.
func ToProto(g core.Grant) *grantv1.CapacityGrant {
	p := &grantv1.CapacityGrant{
		GrantUid:       g.UID,
		Issuer:         g.Issuer,
		Audience:       g.Audience,
		TemplateDigest: g.TemplateDigest,
		Fibers:         &grantv1.FiberLimits{Max: uint32(g.FiberMax), Warm: uint32(g.FiberWarm)},
		WBudgetBytes:   g.WBudgetBytes,
		MinTier:        grantv1.Tier(g.MinTier),
		Policy: &grantv1.Policy{
			Durability:       grantv1.Durability(g.Policy.Durability),
			SessionClass:     g.Policy.SessionClass,
			AuditClass:       g.Policy.AuditClass,
			PsiSomeAvg10Shed: float32(g.Policy.PSISomeAvg10Shed),
			PsiSomeAvg10Park: float32(g.Policy.PSISomeAvg10Park),
		},
	}
	if !g.LeaseExpiry.IsZero() {
		p.LeaseExpiry = timestamppb.New(g.LeaseExpiry.UTC())
	}
	if g.DeviceBudget.Bytes > 0 || g.DeviceBudget.Class != "" {
		p.DeviceBudget = &grantv1.DeviceBudget{Bytes: g.DeviceBudget.Bytes, Class: g.DeviceBudget.Class}
	}
	return p
}

// Deadline converts a proto timestamp deadline into a duration from now.
func Deadline(ts *timestamppb.Timestamp, now time.Time) (time.Duration, bool) {
	if ts == nil || !ts.IsValid() {
		return 0, false
	}
	return ts.AsTime().Sub(now), true
}
