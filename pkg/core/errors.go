package core

import "errors"

// Core errors.
var (
	ErrPayloadTooLarge = errors.New("fiberd: payload exceeds 4096 bytes")
	ErrDeadline        = errors.New("fiberd: clone missed deadline")
	ErrWrongAudience   = errors.New("fiberd: grant audience is not this home")
	ErrNotReady        = errors.New("fiberd: template not ready on this home")
	// ErrVerifyUnavailable is wrapped by a Verifier that cannot decide
	// because its key material is missing or stale, not because the token
	// is bad. That is a reachability problem, so the answer is SHED (back
	// off), never Unauthenticated (give up).
	ErrVerifyUnavailable = errors.New("fiberd: cannot verify offline; key material unavailable")
	// ErrDeltaTooLarge means the session's parked state exceeds the
	// grant's W budget, so it stays put. The Miss names the home that has
	// it.
	ErrDeltaTooLarge = errors.New("fiberd: parked state exceeds w_budget_bytes; not moving it")
	// ErrIncompatible means the session's parked state was made on a
	// platform (architecture, kernel, libc) this home cannot restore. It
	// stays put, and the Miss names the home that has it.
	ErrIncompatible = errors.New("fiberd: parked state was made on an incompatible platform; not moving it")
	// ErrNeedsDevice means the grant needs a device this home's template
	// does not offer. Like a tier gap it is a FailedPrecondition, never a
	// silent CPU-only fiber.
	ErrNeedsDevice = errors.New("fiberd: grant needs a device class this home does not offer")
	// ErrDeviceMismatch means the session's parked device slice was saved
	// by an engine of another class or layout than the grant's engine
	// here, or the grant has no engine here. The session stays in the
	// registry, and like a tier gap it is a FailedPrecondition.
	ErrDeviceMismatch = errors.New("fiberd: parked device state needs an engine of another class or layout; not moving it")
	// ErrNeedsIsolation means the grant is untrusted and this home's
	// runtime does not sandbox fibers from the host kernel. It is a
	// FailedPrecondition, like a tier gap.
	ErrNeedsIsolation = errors.New("fiberd: untrusted grant needs a runtime that isolates tenants")
	// ErrNeedsHandoff means the grant wants handoff and this home does not
	// hand connections to fibers (no -handoff-listen, or a backend that
	// cannot). It is a FailedPrecondition, like a tier gap.
	ErrNeedsHandoff = errors.New("fiberd: handoff grant needs a home that hands connections to fibers")
	// ErrNeedsWorkspace means the grant sets a disk budget and this home's
	// runtime gives fibers no workspace. It is a FailedPrecondition, like
	// a tier gap.
	ErrNeedsWorkspace = errors.New("fiberd: grant with a disk budget needs a runtime that gives fibers a workspace")
	// ErrNoWorkspace means a file call named a fiber whose grant has no
	// disk budget, so the fiber has no workspace.
	ErrNoWorkspace = errors.New("fiberd: the fiber's grant has no workspace (disk_budget_bytes is zero)")
	// ErrDeltaQuota means parking the fiber would take the grant's parked
	// deltas past its quota on this home. The fiber keeps running, and the
	// caller backs off (SHED) or releases something.
	ErrDeltaQuota = errors.New("fiberd: grant's parked deltas would exceed its quota on this home")
	// ErrCallerMismatch means the grant is bound to a client certificate
	// other than the one the request arrived over.
	ErrCallerMismatch = errors.New("fiberd: grant is bound to another caller's certificate")
	// ErrUnboundGrant means the home requires bound grants and this one
	// names no caller certificate.
	ErrUnboundGrant = errors.New("fiberd: grant is not bound to a caller certificate")
	// ErrHandoffUnbound means a handoff grant names no caller certificate.
	// Handoff checks the caller's certificate in the fiber, so it needs
	// one.
	ErrHandoffUnbound = errors.New("fiberd: handoff grant is not bound to a caller certificate")
	// ErrNoTenant: a named session was cloned or parked under a grant
	// without a tenant. A named session is filed under its tenant, so
	// without one there is nothing to file it under or to look it up by.
	// It is a FailedPrecondition, like a tier gap. Anonymous fibers are
	// unaffected.
	ErrNoTenant = errors.New("fiberd: named session needs a grant with a tenant")
	// ErrNoPool is a Pooler's answer for a grant whose template cannot be
	// restored ahead of its fibers. The refill loop remembers it.
	ErrNoPool = errors.New("pool: the grant's template cannot pool")
	// ErrYielded is a Pooler's answer for a fill it gave up because a
	// clone asked for the runtime meanwhile. The refill loop holds the
	// grant's next fill as it does after a failure.
	ErrYielded = errors.New("pool: the fill yielded to a clone")
)

// Audit errors.
var (
	ErrAudit = errors.New("audit: record not durable")
	// ErrAuditChain means a spool's records do not chain (one was edited,
	// removed or reordered) or a checkpoint's signature does not hold.
	ErrAuditChain = errors.New("audit: spool does not verify")
)

// Ledger errors.
var (
	ErrGrantUnknown = errors.New("ledger: grant not held by this home")
	// ErrGrantExpired means the lease lapsed. Revocation is lease
	// non-renewal, so this is lost capacity, not an auth failure.
	ErrGrantExpired = errors.New("ledger: grant lease expired")
	// ErrGrantRevoked means the home removed the grant. Its tokens
	// are refused until the deny-list entry lapses. Like an expired lease,
	// it is a capacity miss.
	ErrGrantRevoked = errors.New("ledger: grant revoked on this home")
	// ErrGrantChanged means a re-delivery of an admitted grant names
	// another tenant, template or session class. Those fields key what
	// the home holds for the grant, so they never change in place.
	ErrGrantChanged = errors.New("ledger: a grant uid keeps its tenant, template and session class")
	// ErrNeedsTier means the runtime's tier is below the grant's min_tier
	// or what the session needs (a parked delta requires TierCheckpoint).
	// A lesser mechanism never stands in.
	ErrNeedsTier = errors.New("ledger: runtime tier below what the grant or session requires")
	// ErrGrantFull means the grant's running fibers are at fibers.max. The
	// home never mints past the charged block.
	ErrGrantFull = errors.New("ledger: grant at fibers.max, no capacity for a new fiber")
	// ErrFiberUnknown means no fiber by that ID runs in this epoch. Every
	// fiber from before a restart is unknown by construction.
	ErrFiberUnknown = errors.New("ledger: fiber unknown in this epoch")
)
