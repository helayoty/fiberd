// Package adapter defines the seam between the invariant core and its two
// homes. Adapters diverge; the ledger, fence, sessions, and budget never
// fork. An adapter is conformant iff the core runs unmodified beneath it.
package adapter

import (
	"context"
	"time"
)

// Grant is the supply-side artifact: authority issued once, charged at
// admission, exercised locally, revoked asynchronously.
type Grant struct {
	UID      string
	FiberMax int
	// WarmCount is the warm floor (fibers.warm): the number of fibers the
	// node should keep pre-forked and hot so the first Clone is an attach,
	// not a cold fork.
	//
	// TODO(poc): WarmCount is carried here but never enforced. main.go calls
	// AdmitGrant(uid, sandboxID, FiberMax) and drops WarmCount on the floor;
	// the Ledger has no notion of a warm floor and nothing pre-forks or
	// backfills fibers to keep `warm` hot. Thread WarmCount into the ledger
	// (or a warm-pool manager) and add a backfill loop that mints up to
	// WarmCount idle fibers per grant and refills after each attach/park.
	WarmCount int
	SandboxID string    // filled by the adapter once the sandbox exists
	Expiry    time.Time //zero = no expiry (skeleton)
}

type GrantEventKind int

const (
	GrantAdded GrantEventKind = iota
	GrantRevoked
)

type GrantEvent struct {
	Kind  GrantEventKind
	Grant Grant
}

// GrantSource is the async lane. In Kubernetes it is an informer on Grant
// objects (v0: balloon pods with annotations); standalone it is the
// platform's delivery of signed grants. It may be down indefinitely: the
// warm path never reads from it.
type GrantSource interface {
	Watch(ctx context.Context) (<-chan GrantEvent, error)
}

// SandboxProvider answers "where do fibers live for this grant". Kubernetes:
// locate the pod sandbox kubelet already built and inherit its cgroup slice.
// Standalone: call RunPodSandbox and own the hierarchy — no kubelet exists.
type SandboxProvider interface {
	EnsureSandbox(ctx context.Context, g Grant) (sandboxID string, err error)
}

// StatusSink ships batched status and the audit spool upward on the async
// lane: fibers{running,resident,parked}, demand rates, utilization
// integrals, and the advertised thrash rate. Loss window = flush interval.
type StatusSink interface {
	Flush(ctx context.Context, grantUID string, snapshot map[string]any) error
}
