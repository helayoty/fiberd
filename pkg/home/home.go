// Package home defines the seam between the invariant core and the
// environment that holds a grant: a standalone host, a Kubernetes grant
// Pod, a Slurm allocation. Homes differ only in how signed grants arrive
// ahead of time, how control-plane liveness is observed, how readiness is
// published, and which cgroup subtree the agent owns. A home is conformant
// iff grant-conform passes against it with pkg/core unmodified.
package home

import (
	"context"
	"log"

	"github.com/helayoty/fiberd/pkg/core"
)

// EventKind is what happened on the async grant lane.
type EventKind int

const (
	// GrantAdded carries a signed token to pre-admit (warm the template
	// before the first Clone). The agent verifies it like any other.
	GrantAdded EventKind = iota
	// GrantRemoved names a grant the home no longer holds. Its fibers
	// drain by lease non-renewal; this only stops new admissions early.
	GrantRemoved
)

type GrantEvent struct {
	Kind  EventKind
	Token []byte // GrantAdded
	UID   string // GrantRemoved
}

// Home is what cmd/fiberd wires around the agent.
type Home interface {
	Name() string
	// Grants is the async lane: pre-warm deliveries and removals. A home
	// with no such lane returns a nil channel; grants then arrive only
	// inside Clone requests.
	Grants(ctx context.Context) (<-chan GrantEvent, error)
	// Health is the control-plane liveness the miss codes key on.
	Health() *core.SourceHealth
	// CgroupRoot is the delegated cgroup v2 subtree the runtime may carve.
	CgroupRoot() string
	// AdvertisedEndpoint is the address callers reach this home at.
	AdvertisedEndpoint() string
	// PublishReady tells the home's control plane that the grant's
	// template is warm (a readiness gate, a status stream, nothing).
	PublishReady(ctx context.Context, grantUID string, ready bool) error
	// Scope is what this home asserts about where it runs (namespace,
	// service account, fabric claim, job). Stamped on audit records;
	// nil on a standalone host. Scope is visible, never a third validity
	// term: a home that loses it revokes fences (Agent.BumpEpoch) or
	// grants (GrantRemoved), and the core keeps min(lease, fence).
	Scope() []core.ScopeClaim
	// Fabric provisions the grant's fabric channel, the devices its
	// engine may drive, and returns how to release it: a static set here,
	// a DRA claim under Kubernetes, the allocation's GRES under Slurm.
	Fabric(ctx context.Context, g core.Grant) (core.FabricChannel, func(), error)
	// Run drives whatever the home needs in the background (issuer polls,
	// watches) until ctx ends.
	Run(ctx context.Context)
}

// Drive consumes the home's grant lane into the agent: verify and admit
// on GrantAdded, revoke on GrantRemoved. Returns when the lane closes or
// ctx ends.
func Drive(ctx context.Context, h Home, a *core.Agent) {
	ch, err := h.Grants(ctx)
	if err != nil {
		log.Printf("home %s: grant lane: %v", h.Name(), err)
		return
	}
	if ch == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			switch ev.Kind {
			case GrantAdded:
				g, err := a.Verify.Verify(ctx, ev.Token)
				if err != nil {
					log.Printf("home %s: grant on the lane did not verify: %v", h.Name(), err)
					continue
				}
				if code, err := a.Admit(ctx, g); err != nil {
					log.Printf("home %s: admit %s: %v (%d)", h.Name(), g.UID, err, code)
					continue
				}
				_ = h.PublishReady(ctx, g.UID, true)
			case GrantRemoved:
				a.Revoke(ev.UID)
				_ = h.PublishReady(ctx, ev.UID, false)
			}
		}
	}
}
