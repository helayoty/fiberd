package core

import (
	"fmt"
	"strings"
	"time"
)

// Durability selects when the audit record for an operation must be
// durable. It is chosen per grant and priced as activation latency.
type Durability int

const (
	DurabilityUnspecified Durability = iota
	// BestEffort appends the record and acks the caller without an fsync.
	// A crash can lose records the OS has not flushed yet.
	BestEffort
	// Sync acks the caller only once the record is durable on local disk.
	Sync
)

// Isolation is whether the issuer trusts the grant's code with the host
// kernel. Unspecified is untrusted.
type Isolation int

const (
	IsolationUnspecified Isolation = iota
	// Untrusted means only a runtime that sandboxes fibers from the host
	// kernel (an Isolator reporting true) may serve the grant.
	Untrusted
	// Trusted means any runtime may serve the grant, even one whose
	// fibers share the host kernel and the agent's uid.
	Trusted
)

// Untrusted reports whether i requires an isolating runtime.
func (i Isolation) Untrusted() bool { return i != Trusted }

func (i Isolation) String() string {
	switch i {
	case Untrusted:
		return "UNTRUSTED"
	case Trusted:
		return "TRUSTED"
	default:
		return "ISOLATION_UNSPECIFIED"
	}
}

// ParseIsolation accepts the proto names, case-insensitively.
func ParseIsolation(s string) (Isolation, error) {
	switch strings.ToUpper(s) {
	case "UNTRUSTED":
		return Untrusted, nil
	case "TRUSTED":
		return Trusted, nil
	case "", "ISOLATION_UNSPECIFIED", "UNSPECIFIED":
		return IsolationUnspecified, nil
	}
	return IsolationUnspecified, fmt.Errorf("unknown isolation %q", s)
}

// EndpointMode is how callers reach a grant's fibers.
type EndpointMode int

const (
	// EndpointDirect means each fiber listens on its own endpoint.
	EndpointDirect EndpointMode = iota
	// EndpointHandoff means the agent accepts each connection and passes
	// it to the fiber, which never listens.
	EndpointHandoff
)

func (m EndpointMode) String() string {
	if m == EndpointHandoff {
		return "HANDOFF"
	}
	return "DIRECT"
}

// ParseEndpointMode accepts the proto names, case-insensitively.
func ParseEndpointMode(s string) (EndpointMode, error) {
	switch strings.ToUpper(s) {
	case "", "DIRECT":
		return EndpointDirect, nil
	case "HANDOFF":
		return EndpointHandoff, nil
	}
	return EndpointDirect, fmt.Errorf("unknown endpoint mode %q", s)
}

// Policy is the per-grant session, durability, pressure, isolation and
// endpoint class. The PSI watermarks are "memory some avg10" percentages
// on the grant's cgroup. The home sets them below its own eviction
// threshold so park fires first.
type Policy struct {
	Durability       Durability
	SessionClass     string
	AuditClass       string
	PSISomeAvg10Shed float64
	PSISomeAvg10Park float64
	Isolation        Isolation
	EndpointMode     EndpointMode
}

// DeviceBudget is the per-fiber slice of the grant's engine device state
// a fiber may hold (its share of a KV cache, of VRAM): the device-side
// twin of WBudgetBytes. Zero bytes means the grant needs no device.
type DeviceBudget struct {
	Bytes uint64
	Class string // "gpu", "sim" (the reference engine's simulated device); "" = any
}

// Grant is the home-invariant, proto-free twin of api/grant/v1
// CapacityGrant. It is what a Verifier returns after checking the signed
// grant offline, and what the ledger stores. Its authenticated arrival is
// the proof that admission and billing already happened; nothing on the
// warm path re-checks that.
type Grant struct {
	UID            string
	Issuer         string // OIDC issuer URL; also what Miss.issuer reports
	Audience       string // the home that may exercise this grant
	TemplateDigest string // OCI digest of the zygote artifact or image
	// Tenant is who the grant belongs to at the issuer (a Kubernetes
	// namespace, a Slurm account). It is the first half of the session
	// domain: a parked session is filed under it, so another tenant's
	// grant on the same template never finds it. Empty means the grant
	// runs anonymous fibers only.
	Tenant       string
	FiberMax     int // <= 0 means unlimited (ceiling is the cgroup only)
	FiberWarm    int
	WBudgetBytes uint64 // per-fiber dirtied working set ceiling; 0 = unlimited
	MinTier      Tier
	LeaseExpiry  time.Time // zero = no expiry
	Policy       Policy
	DeviceBudget DeviceBudget
	// CallerThumbprint is the x5t#S256 of the one client certificate the
	// grant may be presented over.
	CallerThumbprint string
	// Token is the signed grant this value was verified from. The agent
	// sets it on admit so the ledger snapshot carries the proof, not only
	// the claims. Boot verifies every entry's token again before
	// re-admitting it and drops an entry without one. A Verifier leaves it
	// empty.
	Token string
}

// Expired reports whether the lease has lapsed at now. Revocation is lease
// non-renewal: an expired grant is treated as capacity the home no longer
// holds, which is a miss keyed on control-plane health, not an auth error.
func (g Grant) Expired(now time.Time) bool {
	return !g.LeaseExpiry.IsZero() && !now.Before(g.LeaseExpiry)
}
