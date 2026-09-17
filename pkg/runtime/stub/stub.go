// Package stub is an in-memory runtime for tests and for the conformance
// suite's first target. It creates no processes. It does model the parts
// of the contract the ledger and the protocol depend on: fake endpoints,
// parked deltas, a per-fiber dirtied working set taken from the clone
// payload (`{"dirty_bytes": N}`), and a kernel-style OOM exit when that
// working set exceeds the grant's w_budget_bytes.
package stub

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/helayoty/fiberd/pkg/core"
)

type fiber struct {
	h core.FiberHandle
	w uint64
}

type Runtime struct {
	mu        sync.Mutex
	tier      core.Tier
	fibers    map[string]fiber
	parked    map[string]uint64 // deltaRef -> W the delta carries
	templates map[string]bool
	pressure  map[string]float64
	port      int
	exits     chan core.FiberExit
}

// New returns a runtime advertising TierCheckpoint (park/resume works).
func New() *Runtime { return NewWithTier(core.TierCheckpoint) }

// NewWithTier lets tests and the conformance driver pick the advertised
// tier, for example TierWarm to exercise the tier-floor cases.
func NewWithTier(t core.Tier) *Runtime {
	return &Runtime{
		tier:      t,
		fibers:    map[string]fiber{},
		parked:    map[string]uint64{},
		templates: map[string]bool{},
		port:      30000,
		exits:     make(chan core.FiberExit, 1024),
	}
}

func (r *Runtime) Tier() core.Tier { return r.tier }

func (r *Runtime) PrepareTemplate(_ context.Context, g core.Grant) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.templates[g.TemplateDigest] = true
	return nil
}

type payload struct {
	DirtyBytes  uint64 `json:"dirty_bytes"`
	DeviceBytes uint64 `json:"device_bytes"`
}

// OffersDevice implements core.DeviceCapable: the stub simulates an
// engine for every template, so device budgets are admitted and enforced
// on the payload's device_bytes.
func (r *Runtime) OffersDevice(string, string) bool { return true }

func (r *Runtime) Clone(_ context.Context, spec core.CloneSpec) (core.FiberHandle, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var w, dev uint64
	if spec.Source == core.SourceDelta {
		carried, ok := r.parked[spec.Ref]
		if !ok {
			return core.FiberHandle{}, fmt.Errorf("stub: unknown delta %q", spec.Ref)
		}
		delete(r.parked, spec.Ref)
		w = carried
	}
	if len(spec.Payload) > 0 {
		var p payload
		if err := json.Unmarshal(spec.Payload, &p); err == nil {
			w += p.DirtyBytes
			dev = p.DeviceBytes
		}
	}
	r.port++
	h := core.FiberHandle{
		ID:       spec.Fence.String(),
		Endpoint: fmt.Sprintf("tcp://127.0.0.1:%d", r.port),
		Started:  time.Now(),
	}
	r.fibers[h.ID] = fiber{h: h, w: w}

	// Over budget: the kernel would OOM-kill the fiber's cgroup as soon as
	// it dirtied past memory.max. Model that as an immediate exit.
	if spec.Grant.WBudgetBytes > 0 && w > spec.Grant.WBudgetBytes {
		delete(r.fibers, h.ID)
		r.exits <- core.FiberExit{FiberID: h.ID, Reason: "oom",
			Detail: fmt.Sprintf("dirtied %d > w_budget %d", w, spec.Grant.WBudgetBytes)}
	} else if spec.Grant.DeviceBudget.Bytes > 0 && dev > spec.Grant.DeviceBudget.Bytes {
		// The engine reported a slice past the device budget: the home
		// kills the fiber as it would for W.
		delete(r.fibers, h.ID)
		r.exits <- core.FiberExit{FiberID: h.ID, Reason: "oom",
			Detail: fmt.Sprintf("device %d > device_budget %d", dev, spec.Grant.DeviceBudget.Bytes)}
	}
	return h, nil
}

func (r *Runtime) Park(_ context.Context, fiberID string, _ bool) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.fibers[fiberID]
	if !ok {
		return "", fmt.Errorf("stub: unknown fiber %q", fiberID)
	}
	delete(r.fibers, fiberID)
	ref := "delta-" + fiberID
	r.parked[ref] = f.w
	return ref, nil
}

func (r *Runtime) Release(_ context.Context, fiberID string, discard bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.fibers, fiberID)
	if discard {
		delete(r.parked, "delta-"+fiberID)
	}
	return nil
}

func (r *Runtime) List(context.Context) ([]core.FiberHandle, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]core.FiberHandle, 0, len(r.fibers))
	for _, f := range r.fibers {
		out = append(out, f.h)
	}
	return out, nil
}

func (r *Runtime) Stats(_ context.Context, fiberID string) (core.FiberStats, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.fibers[fiberID]
	if !ok {
		return core.FiberStats{}, fmt.Errorf("stub: unknown fiber %q", fiberID)
	}
	return core.FiberStats{WUsedBytes: f.w}, nil
}

func (r *Runtime) Exits() <-chan core.FiberExit { return r.exits }

// HasDelta implements core.DeltaChecker. The stub keeps deltas in memory,
// so after a restart none exist: parked sessions are dropped, which is
// what the conformance suite expects of a target without durable deltas.
func (r *Runtime) HasDelta(ref string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.parked[ref]
	return ok
}

// SetPressure fakes PSI for a grant; Pressure implements
// core.PressureSource so the ladder can be exercised without a kernel.
func (r *Runtime) SetPressure(grantUID string, someAvg10 float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pressure == nil {
		r.pressure = map[string]float64{}
	}
	r.pressure[grantUID] = someAvg10
}

func (r *Runtime) Pressure(grantUID string) (float64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pressure[grantUID], nil
}
