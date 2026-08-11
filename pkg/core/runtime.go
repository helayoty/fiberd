package core

import (
	"context"
	"time"
)

// Tier is advertised runtime capability. Conformance to the verbs does not
// imply the mechanics; the scheduler (or platform) places grants against the
// tier, and Clone(S) on a parked session MUST fail rather than silently fork
// a fresh amnesiac fiber when the runtime lacks TierCheckpoint.
type Tier int

const (
	// TierBasic: create a worker in an existing warm sandbox. Correct
	// semantics, pod-class latency. Every runtime qualifies; this is v0.
	TierBasic Tier = iota
	// TierWarm: zygote fork / snapshot clone, CoW. The ms + density claim.
	TierWarm
	// TierCheckpoint: per-fiber delta checkpoint + restore. Park/resume —
	// the entire session model — requires this.
	TierCheckpoint
)

// CloneSource selects the birth mechanism for a fiber.
type CloneSource int

const (
	SourceZygote CloneSource = iota // fork the warm template
	SourceDelta                     // restore a parked per-fiber delta
	SourceCold                      // full create; the honest fallback
)

// FiberHandle is what the runtime knows about a running fiber. Endpoint is
// returned directly to the caller — fibers never join EndpointSlices.
type FiberHandle struct {
	ID       string
	Endpoint string // host:port or uds path inside the grant's netns
	Started  time.Time
}

// Runtime is the seam to CRI. The real implementation wraps
// k8s.io/cri-api (CreateContainer against the grant sandbox for v0/v1,
// CloneFiber verbs once they exist); this interface is what keeps the core
// identical across Kubernetes and standalone deployments.
type Runtime interface {
	Tier() Tier

	// Clone births a fiber inside sandboxID from src. deadline is a hard
	// budget: exceeding it must return an error, not a late fiber.
	Clone(ctx context.Context, sandboxID string, src CloneSource, ref string, fence Fence, deadline time.Duration) (FiberHandle, error)

	// Park checkpoints the fiber's delta over the zygote and releases its
	// running-tier resources. Returns the delta ref for later SourceDelta.
	Park(ctx context.Context, fiberID string, sync bool) (deltaRef string, err error)

	Release(ctx context.Context, fiberID string) error

	// List rebuilds the ledger's view of reality at startup; discrepancies
	// resolve in favor of what is actually running.
	List(ctx context.Context, sandboxID string) ([]FiberHandle, error)
}
