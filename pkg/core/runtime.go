package core

import (
	"context"
	"time"
)

// Tier is advertised runtime capability. Values match api/grant/v1 Tier so
// a grant's min_tier compares directly. Conformance to the verbs does not
// imply the mechanics; grants are placed against the tier, and Clone(S) on
// a parked session MUST fail rather than silently fork a fresh amnesiac
// fiber when the runtime lacks TierCheckpoint.
type Tier int

const (
	TierUnspecified Tier = iota
	// TierBasic: create a worker in an existing warm sandbox. Correct
	// semantics, pod-class latency. Every runtime qualifies.
	TierBasic
	// TierWarm: zygote fork, copy-on-write. Millisecond activation and
	// density. Single-tenant per grant by definition.
	TierWarm
	// TierCheckpoint: per-fiber delta checkpoint + restore. Park/resume,
	// the entire session model, requires this.
	TierCheckpoint
	// TierSnapshot: microVM or gVisor snapshot-restore per fiber.
	// Multi-tenant per node.
	TierSnapshot
	// TierFabric is reserved. Nothing implements it.
	TierFabric
)

func (t Tier) String() string {
	switch t {
	case TierBasic:
		return "FIBER_BASIC"
	case TierWarm:
		return "FIBER_WARM"
	case TierCheckpoint:
		return "FIBER_CHECKPOINT"
	case TierSnapshot:
		return "FIBER_SNAPSHOT"
	case TierFabric:
		return "FIBER_FABRIC"
	default:
		return "TIER_UNSPECIFIED"
	}
}

// CloneSource selects the birth mechanism for a fiber.
type CloneSource int

const (
	SourceZygote CloneSource = iota // fork the warm template
	SourceDelta                     // restore a parked per-fiber delta
	SourceCold                      // full create; the honest fallback
)

// CloneSpec is everything the runtime needs to birth one fiber. Grant
// carries the template digest and the W budget; Fence is the identity the
// child adopts after the fork, never before.
type CloneSpec struct {
	Grant    Grant
	Source   CloneSource
	Ref      string // delta ref when Source == SourceDelta
	Fence    Fence
	Deadline time.Duration // hard budget: exceeding it is an error, not a late fiber
	Payload  []byte        // opaque data handed to the fiber at birth
}

// FiberHandle is what the runtime knows about a running fiber. Endpoint is
// returned directly to the caller; fibers never join any service registry.
type FiberHandle struct {
	ID       string
	Endpoint string // host:port or unix socket path
	Started  time.Time
}

// FiberStats is the runtime's measurement of one fiber. WUsedBytes is the
// dirtied working set: the fiber's private pages since fork.
type FiberStats struct {
	WUsedBytes uint64
	// DeviceUsedBytes is the fiber's slice of the engine's device state,
	// as the engine reports it; 0 when the grant has no device.
	DeviceUsedBytes uint64
}

// DeviceCapable is implemented by runtimes whose warm template can hold
// device state for its fibers (an engine that reports slices). A grant
// with a device budget is admitted only where this answers true; the
// class is the grant's DeviceBudget.Class ("" for any).
type DeviceCapable interface {
	OffersDevice(grantUID, class string) bool
}

// FiberExit is reported when a fiber dies on its own: the kernel killed it
// for exceeding its W budget (Reason "oom"), it exited, or was signalled.
type FiberExit struct {
	FiberID string
	Reason  string // "oom" | "exit" | "signal"
	Detail  string
}

// SessionDomain is the namespace a session name lives in when it moves
// between homes: the grant's session_class when the issuer set one, else
// the template digest. Two homes each hold their own grant; what they
// share is the template (a session's state is a delta over its pages)
// or an issuer-chosen class.
func (g Grant) SessionDomain() string {
	if g.Policy.SessionClass != "" {
		return g.Policy.SessionClass
	}
	return g.TemplateDigest
}

// DeltaPublisher is implemented by runtimes that can put a parked delta
// where other homes can find it. The agent calls it after every park of a
// named session; the returned handle is remembered with the session.
type DeltaPublisher interface {
	PublishDelta(ctx context.Context, deltaRef string, g Grant, session string) (remote string, err error)
}

// RemoteDelta is what a finder learns about a parked session elsewhere
// without pulling it: how much it costs to move, and where it lives.
type RemoteDelta struct {
	WBytes uint64
	Home   string
	Handle string // opaque; passed back to Claim
}

// DeltaFinder is implemented by runtimes that can look a session up in
// the shared store and bring its delta here. Claim pulls the delta (and,
// if needed, the parent checkpoint it depends on), makes the remote copy
// unavailable to others, and returns a local delta ref for SourceDelta.
//
// FindDelta may return a *RemoteMiss as its error when the session exists
// but this home must not take it (the state was made on an incompatible
// platform); the agent turns that into a miss naming the preferred home.
// Any other error means the store is unreachable.
type DeltaFinder interface {
	FindDelta(ctx context.Context, g Grant, session string) (RemoteDelta, bool, error)
	ClaimDelta(ctx context.Context, g Grant, session string, rd RemoteDelta) (deltaRef string, err error)
	// Owned reports whether a locally parked delta is still ours: false
	// when another home has claimed the session since we published it.
	Owned(ctx context.Context, deltaRef string) bool
}

// Runtime is the seam between the invariant core and a mechanism. This
// interface is what keeps the core identical across homes and tiers.
type Runtime interface {
	Tier() Tier

	// PrepareTemplate makes the grant's template warm on this home (boots
	// the zygote, pulls the artifact). Idempotent. Grant readiness is this
	// call returning nil.
	PrepareTemplate(ctx context.Context, g Grant) error

	// Clone births a fiber. spec.Deadline is a hard budget.
	Clone(ctx context.Context, spec CloneSpec) (FiberHandle, error)

	// Park checkpoints the fiber's delta over the zygote and releases its
	// running-tier resources. sync means the delta is durable before the
	// call returns. Returns the delta ref for a later SourceDelta clone.
	Park(ctx context.Context, fiberID string, sync bool) (deltaRef string, err error)

	// Release destroys the fiber; discard also deletes any parked delta
	// belonging to the same session.
	Release(ctx context.Context, fiberID string, discard bool) error

	// List rebuilds the ledger's view of reality at startup; discrepancies
	// resolve in favor of what is actually running.
	List(ctx context.Context) ([]FiberHandle, error)

	// Stats measures one running fiber.
	Stats(ctx context.Context, fiberID string) (FiberStats, error)

	// Exits delivers fibers that died without a Park or Release. The agent
	// frees their ledger slot and writes the audit record.
	Exits() <-chan FiberExit
}
