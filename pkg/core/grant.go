package core

import "time"

// Durability selects when the audit record for an operation must be
// remote. It is chosen per grant and priced as activation latency.
type Durability int

const (
	DurabilityUnspecified Durability = iota
	// BestEffort: append locally, ack the caller, ship later. Loss window
	// equals the spool's flush interval.
	BestEffort
	// Sync: the record is remote before the caller is acked.
	Sync
)

// Policy is the per-grant session, durability and pressure class. The PSI
// watermarks are "memory some avg10" percentages on the grant's cgroup;
// the home sets them below its own eviction threshold so park fires first.
type Policy struct {
	Durability       Durability
	SessionClass     string
	AuditClass       string
	PSISomeAvg10Shed float64
	PSISomeAvg10Park float64
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
	FiberMax       int    // <= 0 means unlimited (ceiling is the cgroup only)
	FiberWarm      int
	WBudgetBytes   uint64 // per-fiber dirtied working set ceiling; 0 = unlimited
	MinTier        Tier
	LeaseExpiry    time.Time // zero = no expiry
	Policy         Policy
	DeviceBudget   DeviceBudget
}

// Expired reports whether the lease has lapsed at now. Revocation is lease
// non-renewal: an expired grant is treated as capacity the home no longer
// holds, which is a miss keyed on control-plane health, not an auth error.
func (g Grant) Expired(now time.Time) bool {
	return !g.LeaseExpiry.IsZero() && !now.Before(g.LeaseExpiry)
}
