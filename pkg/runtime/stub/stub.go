// Package stub is a TierWarm in-memory runtime for tests and for the v0
// process tier, where fibers are processes inside the grant pod's own
// container (nothing for kubelet to reap). The real CRI runtime wraps
// k8s.io/cri-api: CreateContainer-with-checkpoint for v1, CloneFiber verbs
// once they land.
package stub

import (
	"context"
	"fmt"
	"sync"
	"time"

	"fiberd/pkg/core"
)

type Runtime struct {
	mu     sync.Mutex
	fibers map[string]core.FiberHandle
	parked map[string][]byte // deltaRef -> fake delta
	port   int
}

func New() *Runtime {
	return &Runtime{fibers: map[string]core.FiberHandle{}, parked: map[string][]byte{}, port: 30000}
}

func (r *Runtime) Tier() core.Tier { return core.TierCheckpoint }

// TODO(poc): this Clone does no real work. It allocates a fake endpoint and
// records a handle in a map — there is no fork/CoW of a zygote (TierWarm), no
// checkpoint restore of a delta (TierCheckpoint), no identity scrub, and the
// deadline is ignored. Replace with the real CRI path: CreateContainer /
// CreateContainer-with-checkpoint against the grant sandbox for v0/v1, and the
// CloneFiber verb once it lands, honoring the hard deadline and reporting the
// true birth mechanism.
func (r *Runtime) Clone(_ context.Context, sandboxID string, src core.CloneSource, ref string, f core.Fence, _ time.Duration) (core.FiberHandle, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if src == core.SourceDelta {
		if _, ok := r.parked[ref]; !ok {
			return core.FiberHandle{}, fmt.Errorf("stub: unknown delta %q", ref)
		}
		delete(r.parked, ref)
	}
	r.port++
	h := core.FiberHandle{
		ID:       f.String(),
		Endpoint: fmt.Sprintf("127.0.0.1:%d", r.port),
		Started:  time.Now(),
	}
	r.fibers[h.ID] = h
	_ = sandboxID
	return h, nil
}

// TODO(poc): this Park does not checkpoint anything. It drops the fiber from
// the map and stores an empty byte slice as the "delta"; the `sync` flag is
// ignored, so there is no real CRIU (or equivalent) checkpoint of the fiber's
// delta over the zygote and nothing durable to restore on resume. Implement
// the real checkpoint path (CRIU / CheckpointPod per KEP-5823), writing the
// per-fiber delta to the checkpoint store and honoring sync durability.
func (r *Runtime) Park(_ context.Context, fiberID string, _ bool) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.fibers[fiberID]; !ok {
		return "", fmt.Errorf("stub: unknown fiber %q", fiberID)
	}
	delete(r.fibers, fiberID)
	ref := "delta-" + fiberID
	r.parked[ref] = []byte{}
	return ref, nil
}

func (r *Runtime) Release(_ context.Context, fiberID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.fibers, fiberID)
	return nil
}

func (r *Runtime) List(_ context.Context, _ string) ([]core.FiberHandle, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]core.FiberHandle, 0, len(r.fibers))
	for _, h := range r.fibers {
		out = append(out, h)
	}
	return out, nil
}
