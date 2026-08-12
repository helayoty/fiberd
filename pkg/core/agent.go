package core

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// CloneRequest is the ENTIRE clone-time surface. Admission completeness is
// structural, not policy: there is no field with which to shape a workload.
// Everything executable — image, command, env, mounts, security context,
// resources — was fixed by the template admitted at grant creation.
type CloneRequest struct {
	GrantUID string
	Deadline time.Duration
	Session  string // optional: "" = anonymous fiber
	Payload  []byte // opaque, size-capped, delivered as data, never config
}

type CloneResponse struct {
	FiberID    string
	Endpoint   string
	Fence      Fence
	Resolution string // "attach" | "resume" | "create"
}

// StatusCode mirrors the wire semantics forced by constraint (a)/(e).
type StatusCode int

const (
	OK StatusCode = iota
	// DeferredFallback: miss while the control plane is healthy — the
	// caller may fall through to ordinary pod creation.
	DeferredFallback
	// Shed: miss while the control plane is unreachable, or budget
	// backpressure. 429 + Retry-After; never queue on a dead control plane.
	Shed
	Invalid
)

// Auditor is append-locally, ship-async. Under durability SYNC, Append must
// not return until the record is remote — Clone acks after it.
type Auditor interface {
	Append(ctx context.Context, event string, f Fence, session string) error
}

// Verifier checks the caller's grant-scoped capability offline: cached JWKS
// for Kubernetes, ed25519 over the signed grant standalone. Never a
// control-plane round trip.
type Verifier interface {
	Verify(ctx context.Context, token []byte, grantUID string) error
}

const maxPayload = 4096

var (
	ErrPayloadTooLarge = errors.New("agent: payload exceeds clone.payloadMaxBytes")
	ErrDeadline        = errors.New("agent: clone missed deadline")
)

// Agent wires the eight subcomponents. One per node; same struct in both
// deployments — only the adapter-injected Verifier and sandbox mapping vary.
//
// TODO(poc): the pressure controller is not wired in. The design specifies
// a controller with two inputs — kernel PSI on the grant's cgroup slice and
// ledger-derived device pressure (engine KV occupancy + queue depth) — driving
// one ladder, cheapest-first: shed new clones -> park over-quota capacity ->
// yield/evict the grant. None of that exists here: the only backpressure is
// Budget.Take (thrash rate), there is no PSI/device-pressure reader, and the
// park/yield rungs are never triggered. Add a PressureController field and a
// background loop that samples both inputs and applies shed/park/yield.
type Agent struct {
	Ledger  *Ledger
	Budget  *Budget
	Runtime Runtime
	Audit   Auditor
	Verify  Verifier

	Health *SourceHealth

	// SandboxFor maps a grant to its sandbox: in Kubernetes the pod sandbox
	// kubelet built; standalone, one the adapter created itself.
	SandboxFor func(grantUID string) (string, bool)
}

// Clone is the warm path. Every hop below is node-local memory or disk.
func (a *Agent) Clone(ctx context.Context, token []byte, req CloneRequest) (CloneResponse, StatusCode, error) {
	// 1. Frontend: authn + admission completeness.
	if len(req.Payload) > maxPayload {
		return CloneResponse{}, Invalid, ErrPayloadTooLarge
	}
	if err := a.Verify.Verify(ctx, token, req.GrantUID); err != nil {
		return CloneResponse{}, Invalid, fmt.Errorf("capability: %w", err)
	}

	// 2. Budget: backpressure before any work.
	if err := a.Budget.Take(); err != nil {
		return CloneResponse{}, Shed, err
	}

	// 3. Ledger: resolve attach | resume | create, mint or reuse the fence.
	// Capacity is reserved inside Resolve. ErrGrantFull and ErrGrantUnknown
	// ("capacity not on this node") map to DEFERRED_FALLBACK while the grant
	// lane is healthy and SHED while it is not — a miss must not queue into
	// a dead control plane. Nil Health fails toward healthy, matching boot
	// bias. ErrNeedsTier is a local capability gap and always falls back.
	act, fence, ref, commit, unlock, err := a.Ledger.Resolve(req.GrantUID, req.Session, a.Runtime.Tier())
	if err != nil {
		if unlock != nil {
			unlock()
		}
		return CloneResponse{}, a.capacityMiss(err), err
	}
	defer unlock()

	if act == ActAttach {
		_ = a.Audit.Append(ctx, "attach", fence, req.Session)
		return CloneResponse{FiberID: fence.String(), Endpoint: ref, Fence: fence, Resolution: "attach"}, OK, nil
	}

	// 4. Runtime: the one fork or restore call, under a hard deadline.
	sandbox, ok := a.SandboxFor(req.GrantUID)
	if !ok {
		return CloneResponse{}, a.capacityMiss(ErrGrantUnknown), ErrGrantUnknown
	}
	src, srcRef := SourceZygote, ""
	if act == ActResume {
		src, srcRef = SourceDelta, ref
	}
	rctx, cancel := context.WithTimeout(ctx, req.Deadline)
	defer cancel()
	// TODO(poc): identity scrub at the fork boundary is not performed. The
	// design requires that Clone "scrubs inherited descriptors, baked tokens,
	// and entropy: identity is assigned after the fork, never baked into the
	// template". Nothing here or in the stub runtime scrubs the freshly forked
	// fiber, so a create/resume could inherit the zygote's or parent's fds,
	// tokens, and RNG state. Implement scrub-on-clone (in the zygote manager /
	// Runtime.Clone path) and only assign the fence-derived identity afterward.
	h, err := a.Runtime.Clone(rctx, sandbox, src, srcRef, fence, req.Deadline)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return CloneResponse{}, DeferredFallback, ErrDeadline
		}
		return CloneResponse{}, DeferredFallback, err
	}

	commit(Session{
		Name: req.Session, GrantUID: req.GrantUID,
		State: StateRunning, Fence: fence, Handle: h,
	})

	// 5. Audit: append before ack under SYNC, after under BEST_EFFORT —
	// the Auditor implementation owns that distinction.
	_ = a.Audit.Append(ctx, "clone", fence, req.Session)

	resolution := "create"
	if act == ActResume {
		resolution = "resume"
	}
	return CloneResponse{
		FiberID:    h.ID,
		Endpoint:   h.Endpoint,
		Fence:      fence,
		Resolution: resolution,
	}, OK, nil
}

// capacityMiss maps "capacity not on this node" to the two miss codes.
// ErrNeedsTier and other local failures stay DEFERRED_FALLBACK regardless
// of lane health — they are not a control-plane reachability question.
func (a *Agent) capacityMiss(err error) StatusCode {
	if (errors.Is(err, ErrGrantFull) || errors.Is(err, ErrGrantUnknown)) &&
		a.Health != nil && !a.Health.Healthy(time.Now()) {
		return Shed
	}
	return DeferredFallback
}

// Park checkpoints a named session's delta and frees its running tier.
// The ledger is told on success so the fiber's fibers.max slot is returned
// and a later Clone(S) resolves to ActResume against the delta.
func (a *Agent) Park(ctx context.Context, fiberID string, sync bool) (string, error) {
	ref, err := a.Runtime.Park(ctx, fiberID, sync)
	if err == nil {
		a.Ledger.OnPark(fiberID, ref)
		_ = a.Audit.Append(ctx, "park", Fence{}, fiberID)
	}
	return ref, err
}

func (a *Agent) Release(ctx context.Context, fiberID string) error {
	err := a.Runtime.Release(ctx, fiberID)
	if err == nil {
		a.Ledger.OnRelease(fiberID)
		_ = a.Audit.Append(ctx, "release", Fence{}, fiberID)
	}
	return err
}
