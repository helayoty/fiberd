package core

import "errors"

// Agent errors.
var (
	ErrPayloadTooLarge = errors.New("agent: payload exceeds 4096 bytes")
	ErrDeadline        = errors.New("agent: clone missed deadline")
	ErrWrongAudience   = errors.New("agent: grant audience is not this home")
	ErrNotReady        = errors.New("agent: template not ready on this home")
	// ErrVerifyUnavailable is wrapped by a Verifier that cannot decide
	// because its key material is missing or stale, not because the token
	// is bad. That is a reachability problem, so the answer is SHED (back
	// off), never Unauthenticated (give up).
	ErrVerifyUnavailable = errors.New("agent: cannot verify offline; key material unavailable")
	// ErrDeltaTooLarge means the session's parked state exceeds the
	// grant's W budget, so it stays put. The Miss names the home that has
	// it.
	ErrDeltaTooLarge = errors.New("agent: parked state exceeds w_budget_bytes; not moving it")
	// ErrIncompatible means the session's parked state was made on a
	// platform (architecture, kernel, libc) this home cannot restore. It
	// stays put, and the Miss names the home that has it.
	ErrIncompatible = errors.New("agent: parked state was made on an incompatible platform; not moving it")
	// ErrNeedsDevice means the grant needs a device this home's template
	// does not offer. Like a tier gap it is a FailedPrecondition, never a
	// silent CPU-only fiber.
	ErrNeedsDevice = errors.New("agent: grant needs a device class this home does not offer")
	// ErrNeedsIsolation means the grant is untrusted and this home's
	// runtime does not sandbox fibers from the host kernel. It is a
	// FailedPrecondition, like a tier gap.
	ErrNeedsIsolation = errors.New("agent: untrusted grant needs a runtime that isolates tenants")
	// ErrNeedsHandoff means the grant wants handoff and this home does not
	// hand connections to fibers (no -handoff-listen, or a backend that
	// cannot). It is a FailedPrecondition, like a tier gap.
	ErrNeedsHandoff = errors.New("agent: handoff grant needs a home that hands connections to fibers")
	// ErrDeltaQuota means parking the fiber would take the grant's parked
	// deltas past its quota on this home. The fiber keeps running, and the
	// caller backs off (SHED) or releases something.
	ErrDeltaQuota = errors.New("agent: grant's parked deltas would exceed its quota on this home")
	// ErrCallerMismatch means the grant is bound to a client certificate
	// other than the one the request arrived over.
	ErrCallerMismatch = errors.New("agent: grant is bound to another caller's certificate")
	// ErrUnboundGrant means the home requires bound grants and this one
	// names no caller certificate.
	ErrUnboundGrant = errors.New("agent: grant is not bound to a caller certificate")
	// ErrHandoffUnbound means a handoff grant names no caller certificate.
	// Handoff checks the caller's certificate in the fiber, so it needs
	// one.
	ErrHandoffUnbound = errors.New("agent: handoff grant is not bound to a caller certificate")
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
	// ErrGrantRevoked means the home's lane removed the grant. Its tokens
	// are refused until the deny-list entry lapses. Like an expired lease,
	// it is a capacity miss.
	ErrGrantRevoked = errors.New("ledger: grant revoked on this home")
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
