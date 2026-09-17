package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// CloneRequest is the ENTIRE clone-time surface. Admission completeness is
// structural, not policy: there is no field with which to shape a workload.
// Everything executable — image, command, env, mounts, security context,
// resources — was fixed by the template admitted at grant creation.
type CloneRequest struct {
	GrantJWT []byte        // the signed grant; verified offline
	Session  string        // optional: "" = anonymous fiber
	Deadline time.Duration // hard budget for the runtime work
	Payload  []byte        // opaque, size-capped, delivered as data, never config
}

type CloneResponse struct {
	FiberID  string
	Endpoint string
	Fence    Fence
	Kind     Action
}

// StatusCode is the transport-agnostic outcome. pkg/rpc maps it to gRPC
// codes and attaches a Miss detail to the two miss codes.
type StatusCode int

const (
	OK StatusCode = iota
	// DeferredFallback: miss while the control plane is healthy — the
	// caller falls back to its home's ordinary provisioning path.
	DeferredFallback
	// Shed: miss while the control plane is unreachable, or budget
	// backpressure. Back off; never queue on a dead control plane.
	Shed
	// Invalid: the request itself is malformed (payload too large).
	Invalid
	// Unauthenticated: the grant did not verify, or is not for this home.
	Unauthenticated
	// NeedsTier: the grant or session demands a tier this runtime lacks.
	// Never satisfied by a lesser mechanism.
	NeedsTier
	// NotFound: no such fiber in this epoch.
	NotFound
	// Internal: the runtime or audit spool failed in a way that is not a
	// capacity question.
	Internal
)

// Verifier checks a signed grant offline and returns its contents. Never a
// control-plane round trip: cached JWKS, or a public key held locally.
type Verifier interface {
	Verify(ctx context.Context, token []byte) (Grant, error)
}

const MaxPayload = 4096

// Default runtime deadlines when the caller sets none. A fork is
// millisecond work; a restore of a parked delta is sub-second work, so
// the two defaults differ. A caller with tighter needs sets its own.
const (
	DefaultCreateDeadline = 50 * time.Millisecond
	DefaultResumeDeadline = 2 * time.Second
)

var (
	ErrPayloadTooLarge = errors.New("agent: payload exceeds 4096 bytes")
	ErrDeadline        = errors.New("agent: clone missed deadline")
	ErrWrongAudience   = errors.New("agent: grant audience is not this home")
	ErrNotReady        = errors.New("agent: template not ready on this home")
	// ErrVerifyUnavailable is wrapped by a Verifier that cannot decide
	// because its key material is missing or stale, not because the token
	// is bad. That is a control-plane reachability problem: the answer is
	// SHED (back off), never Unauthenticated (give up).
	ErrVerifyUnavailable = errors.New("agent: cannot verify offline; key material unavailable")
	// ErrDeltaTooLarge: the session's parked state exceeds the grant's W
	// budget, so it is not moved here. The Miss names the home that has
	// it.
	ErrDeltaTooLarge = errors.New("agent: parked state exceeds w_budget_bytes; not moving it")
	// ErrIncompatible: the session's parked state was made on a platform
	// (architecture, kernel, libc) this home cannot restore. Not moved
	// here; the Miss names the home that has it.
	ErrIncompatible = errors.New("agent: parked state was made on an incompatible platform; not moving it")
)

// DeadlineAdvisor is implemented by runtimes whose create or resume is
// slower than a process fork: what a Clone without an explicit deadline
// is given. The caller's own deadline is always honoured as is.
type DeadlineAdvisor interface {
	DefaultDeadlines() (create, resume time.Duration)
}

// RemoteMiss wraps a capacity miss with the home the caller should prefer
// (where the session's state lives). pkg/rpc copies it into Miss.
type RemoteMiss struct {
	Err           error
	PreferredHome string
}

func (m *RemoteMiss) Error() string { return m.Err.Error() }
func (m *RemoteMiss) Unwrap() error { return m.Err }

// Agent wires the subcomponents. One per home instance; the same struct
// everywhere — only the injected Verifier, Runtime and health source vary.
type Agent struct {
	// NodeID is this home's identity; a grant's audience must match it.
	// Empty disables the check (tests).
	NodeID string

	Ledger  *Ledger
	Budget  *Budget
	Runtime Runtime
	Audit   Auditor
	Verify  Verifier
	Health  *SourceHealth
	// Pressure, when set, is consulted before any new fiber: a grant that
	// is shedding answers SHED. Nil means no pressure input.
	Pressure *PressureController
	// Store, when set, receives a ledger snapshot after every state
	// transition, so a restart can re-admit grants and remember parked
	// sessions.
	Store *SnapshotStore
	// SweepInterval paces the lease reaper (default 5s).
	SweepInterval time.Duration
	// MobilityBudget overrides the grant's w_budget_bytes as the largest
	// parked state this home will pull (tests, or a home-level cap).
	MobilityBudget func(g Grant) uint64

	// StatusInterval paces the W sampler and the Watch stream. Zero means
	// one second.
	StatusInterval time.Duration

	admitMu   sync.Mutex
	admitting map[string]chan struct{}

	changedMu sync.Mutex
	changed   []chan struct{}

	// pending holds exits that arrived before the fiber was committed to
	// the ledger (a child can die before Clone returns). Clone drains it
	// right after commit so the slot is never leaked.
	pendingMu sync.Mutex
	pending   map[string]FiberExit
}

// Clone is the warm path. Every hop below is home-local memory or disk.
func (a *Agent) Clone(ctx context.Context, req CloneRequest) (CloneResponse, StatusCode, error) {
	// 1. Frontend: admission completeness and authn.
	if len(req.Payload) > MaxPayload {
		return CloneResponse{}, Invalid, ErrPayloadTooLarge
	}
	g, err := a.Verify.Verify(ctx, req.GrantJWT)
	if err != nil {
		if errors.Is(err, ErrVerifyUnavailable) {
			return CloneResponse{}, Shed, fmt.Errorf("capability: %w", err)
		}
		return CloneResponse{}, Unauthenticated, fmt.Errorf("capability: %w", err)
	}
	if a.NodeID != "" && g.Audience != a.NodeID {
		return CloneResponse{}, Unauthenticated, fmt.Errorf("%w: aud=%q node=%q", ErrWrongAudience, g.Audience, a.NodeID)
	}

	// 2. Self-admission: a verified grant that names this home is admitted
	// on first sight. Its signature is the async lane's proof, carried
	// inline. The template is warmed synchronously; homes pre-warm grants
	// they are told about ahead of time so this is normally a no-op.
	if _, known := a.Ledger.Grant(g.UID); !known {
		if code, err := a.Admit(ctx, g); err != nil {
			return CloneResponse{}, code, err
		}
	}

	// 3. Backpressure before any work: the thrash budget, then the pressure
	// ladder's shed rung. Attach is exempt from the ladder (it creates
	// nothing) but not from the budget, so it is checked after the resolve
	// for the ladder only.
	if err := a.Budget.Take(); err != nil {
		return CloneResponse{}, Shed, err
	}
	shedding := a.Pressure != nil && a.Pressure.Shedding(g.UID)

	// 3b. Mobility: a named session this home does not hold may be parked
	// elsewhere. Ask the shared store; bring it here if its delta fits the
	// grant's W budget, else send the caller to the home that has it.
	if req.Session != "" {
		if code, err := a.locate(ctx, g, req.Session); err != nil {
			return CloneResponse{}, code, err
		}
	}

	// 4. Ledger: resolve attach | resume | create, mint or reuse the fence.
	act, fence, ref, commit, unlock, err := a.Ledger.Resolve(g.UID, req.Session, a.Runtime.Tier())
	if err != nil {
		if unlock != nil {
			unlock()
		}
		return CloneResponse{}, a.missCode(err), err
	}
	defer unlock()

	if act == ActAttach {
		if err := a.audit(ctx, g.Policy.Durability, AuditRecord{Event: "attach", Fence: fence, Session: req.Session}); err != nil {
			return CloneResponse{}, Internal, err
		}
		return CloneResponse{FiberID: fence.String(), Endpoint: ref, Fence: fence, Kind: ActAttach}, OK, nil
	}
	if shedding {
		// A new fiber under memory pressure: refuse. The reservation is
		// returned by the deferred unlock. Always SHED: this is the home's
		// own pressure, not a control-plane question.
		return CloneResponse{}, Shed, ErrPressure
	}

	// 5. Runtime: the one fork or restore call, under a hard deadline.
	deadline := req.Deadline
	if deadline <= 0 {
		create, resume := DefaultCreateDeadline, DefaultResumeDeadline
		if adv, ok := a.Runtime.(DeadlineAdvisor); ok {
			if c, r := adv.DefaultDeadlines(); c > 0 && r > 0 {
				create, resume = c, r
			}
		}
		deadline = create
		if act == ActResume {
			deadline = resume
		}
	}
	spec := CloneSpec{Grant: g, Source: SourceZygote, Fence: fence, Deadline: deadline, Payload: req.Payload}
	if act == ActResume {
		spec.Source, spec.Ref = SourceDelta, ref
	}
	rctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	h, err := a.Runtime.Clone(rctx, spec)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return CloneResponse{}, DeferredFallback, ErrDeadline
		}
		return CloneResponse{}, DeferredFallback, err
	}

	commit(Session{Name: req.Session, GrantUID: g.UID, State: StateRunning, Fence: fence, Handle: h})

	// 6. Audit before ack: under Sync the record is remote first.
	if err := a.audit(ctx, g.Policy.Durability, AuditRecord{Event: act.String(), Fence: fence, Session: req.Session, FiberID: h.ID}); err != nil {
		return CloneResponse{}, Internal, err
	}
	a.notify()

	// The fiber may already have died (for example OOM at birth) before
	// the commit above made it known; settle that now rather than leak.
	a.pendingMu.Lock()
	ex, died := a.pending[h.ID]
	delete(a.pending, h.ID)
	a.pendingMu.Unlock()
	if died {
		a.OnExit(ctx, ex)
	}
	return CloneResponse{FiberID: h.ID, Endpoint: h.Endpoint, Fence: fence, Kind: act}, OK, nil
}

// locate settles where a named session's parked state is before Resolve:
//
//   - parked here and still ours: nothing to do, Resolve resumes it;
//   - parked here but claimed elsewhere since: forget it, then as unknown;
//   - unknown here and found in the shared store: claim it (pull delta
//     and parent) if w_used <= w_budget, so Resolve resumes it; else a
//     capacity miss naming the home that holds it.
func (a *Agent) locate(ctx context.Context, g Grant, session string) (StatusCode, error) {
	finder, ok := a.Runtime.(DeltaFinder)
	if !ok {
		return OK, nil
	}
	if st, ref, known := a.Ledger.SessionState(g.UID, session); known {
		if st != StateParked || finder.Owned(ctx, ref) {
			return OK, nil
		}
		log.Printf("mobility: session %s/%s was claimed by another home; forgetting the local copy", g.UID, session)
		a.Ledger.ForgetSession(g.UID, session)
		_ = a.audit(ctx, BestEffort, AuditRecord{Event: "migrate-out", Fence: Fence{GrantUID: g.UID, Epoch: a.Ledger.Epoch()}, Session: session})
	}
	rd, found, err := finder.FindDelta(ctx, g, session)
	if err != nil {
		var rm *RemoteMiss
		if errors.As(err, &rm) {
			// Found, but this home must not take it (platform parity):
			// a miss that names where the state is, like too-large.
			return a.missCode(err), err
		}
		log.Printf("mobility: find %s/%s: %v", g.UID, session, err)
		return OK, nil // the store is unreachable; create fresh, as any home without a store would
	}
	if !found {
		return OK, nil
	}
	budget := g.WBudgetBytes
	if a.MobilityBudget != nil {
		budget = a.MobilityBudget(g)
	}
	if budget > 0 && rd.WBytes > budget {
		err := &RemoteMiss{Err: fmt.Errorf("%w: %d > %d, parked on %s", ErrDeltaTooLarge, rd.WBytes, budget, rd.Home), PreferredHome: rd.Home}
		return a.missCode(err), err
	}
	ref, err := finder.ClaimDelta(ctx, g, session, rd)
	if err != nil {
		err = &RemoteMiss{Err: fmt.Errorf("%w: claim: %w", ErrNotReady, err), PreferredHome: rd.Home}
		return a.missCode(err), err
	}
	a.Ledger.RestoreParked(SessionSnapshot{Name: session, GrantUID: g.UID, State: StateParked, DeltaRef: ref})
	_ = a.audit(ctx, g.Policy.Durability, AuditRecord{Event: "migrate-in", Fence: Fence{GrantUID: g.UID, Epoch: a.Ledger.Epoch()}, Session: session, Detail: fmt.Sprintf("from %s, %d bytes", rd.Home, rd.WBytes)})
	return OK, nil
}

// Admit records a verified grant and warms its template. Concurrent
// admissions of the same UID wait for the first; a second delivery of an
// already-admitted grant refreshes it in place.
func (a *Agent) Admit(ctx context.Context, g Grant) (StatusCode, error) {
	if g.MinTier > a.Runtime.Tier() {
		return NeedsTier, fmt.Errorf("%w: grant needs %s, runtime is %s", ErrNeedsTier, g.MinTier, a.Runtime.Tier())
	}
	if g.Expired(a.Ledger.Now()) {
		// Capacity the home does not hold; the miss code follows lane
		// health like any other capacity miss.
		return a.missCode(ErrGrantExpired), ErrGrantExpired
	}
	a.admitMu.Lock()
	if a.admitting == nil {
		a.admitting = make(map[string]chan struct{})
	}
	if wait, inflight := a.admitting[g.UID]; inflight {
		a.admitMu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return DeferredFallback, ctx.Err()
		}
		if _, ok := a.Ledger.Grant(g.UID); ok {
			return OK, nil
		}
		return a.missCode(ErrNotReady), ErrNotReady
	}
	done := make(chan struct{})
	a.admitting[g.UID] = done
	a.admitMu.Unlock()
	defer func() {
		a.admitMu.Lock()
		delete(a.admitting, g.UID)
		a.admitMu.Unlock()
		close(done)
	}()

	if err := a.Runtime.PrepareTemplate(ctx, g); err != nil {
		return a.missCode(ErrNotReady), fmt.Errorf("%w: %w", ErrNotReady, err)
	}
	a.Ledger.AdmitGrant(g)
	_ = a.audit(ctx, BestEffort, AuditRecord{Event: "admit", Fence: Fence{GrantUID: g.UID, Epoch: a.Ledger.Epoch()}, Detail: g.TemplateDigest})
	a.notify()
	return OK, nil
}

// missCode maps a resolve failure to the outcome. "Capacity not on this
// home" (unknown, full, expired, not ready) is SHED while the grant lane
// is unhealthy and DEFERRED_FALLBACK while it is healthy — a miss must not
// queue into a dead control plane. Nil Health fails toward healthy,
// matching boot bias. A tier gap is neither: it is FailedPrecondition.
func (a *Agent) missCode(err error) StatusCode {
	if errors.Is(err, ErrNeedsTier) {
		return NeedsTier
	}
	if a.Health != nil && !a.Health.Healthy(time.Now()) {
		return Shed
	}
	return DeferredFallback
}

// Park checkpoints a named session's delta and frees its running tier.
func (a *Agent) Park(ctx context.Context, fiberID string, sync bool) (string, StatusCode, error) {
	fence, ok := a.Ledger.Fiber(fiberID)
	if !ok {
		return "", NotFound, ErrFiberUnknown
	}
	ref, err := a.Runtime.Park(ctx, fiberID, sync)
	if err != nil {
		return "", Internal, err
	}
	session := a.Ledger.OnPark(fiberID, ref)
	if err := a.audit(ctx, a.durability(fence.GrantUID), AuditRecord{Event: "park", Fence: fence, FiberID: fiberID, Session: session, Detail: ref}); err != nil {
		return ref, Internal, err
	}
	// A named session's delta is published so any home can claim it;
	// failure to publish leaves it resumable here only.
	if pub, ok := a.Runtime.(DeltaPublisher); ok && session != "" {
		g, _ := a.Ledger.Grant(fence.GrantUID)
		if remote, err := pub.PublishDelta(ctx, ref, g, session); err != nil {
			log.Printf("mobility: publish %s/%s: %v", fence.GrantUID, session, err)
		} else {
			_ = a.audit(ctx, BestEffort, AuditRecord{Event: "publish", Fence: fence, Session: session, Detail: remote})
		}
	}
	a.notify()
	return ref, OK, nil
}

// Release destroys a fiber and frees its name; discard also drops any
// parked delta of the same session.
func (a *Agent) Release(ctx context.Context, fiberID string, discard bool) (StatusCode, error) {
	fence, ok := a.Ledger.Fiber(fiberID)
	if !ok {
		return NotFound, ErrFiberUnknown
	}
	if err := a.Runtime.Release(ctx, fiberID, discard); err != nil {
		return Internal, err
	}
	a.Ledger.OnRelease(fiberID)
	if err := a.audit(ctx, a.durability(fence.GrantUID), AuditRecord{Event: "release", Fence: fence, FiberID: fiberID}); err != nil {
		return Internal, err
	}
	a.notify()
	return OK, nil
}

// Yield is the ladder's last rung and the reaper's verb: the grant is
// revoked and every running fiber under it is released, each with its
// audit record. Parked deltas are kept (they are the only state that
// cannot be rebuilt); nothing new is admitted under this UID until the
// home delivers the grant again.
func (a *Agent) Yield(ctx context.Context, grantUID string, reason string) {
	fibers := a.Ledger.FibersOf(grantUID)
	a.Ledger.RevokeGrant(grantUID)
	for _, f := range fibers {
		fence, ok := a.Ledger.Fiber(f.ID)
		if !ok {
			continue
		}
		if err := a.Runtime.Release(ctx, f.ID, false); err != nil {
			log.Printf("yield %s: release %s: %v", grantUID, f.ID, err)
		}
		a.Ledger.OnRelease(f.ID)
		_ = a.audit(ctx, BestEffort, AuditRecord{Event: "yield", Fence: fence, Session: f.Session, FiberID: f.ID, Detail: reason})
	}
	_ = a.audit(ctx, BestEffort, AuditRecord{Event: "revoke", Fence: Fence{GrantUID: grantUID, Epoch: a.Ledger.Epoch()}, Detail: reason})
	a.notify()
}

// Run drives the background loops until ctx ends: fiber exits from the
// runtime, and the W sampler that feeds the ledger and the budget.
func (a *Agent) Run(ctx context.Context) {
	interval := a.StatusInterval
	if interval <= 0 {
		interval = time.Second
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	sweepEvery := a.SweepInterval
	if sweepEvery <= 0 {
		sweepEvery = 5 * time.Second
	}
	sweep := time.NewTicker(sweepEvery)
	defer sweep.Stop()
	exits := a.Runtime.Exits()
	for {
		select {
		case <-ctx.Done():
			return
		case ex, ok := <-exits:
			if !ok {
				exits = nil
				continue
			}
			a.OnExit(ctx, ex)
		case <-tick.C:
			a.sample(ctx)
		case <-sweep.C:
			if n := a.Sweep(ctx); n > 0 {
				log.Printf("reaper: %d grant(s) yielded on lease expiry", n)
			}
		}
	}
}

// OnExit records a fiber that died without Park or Release: the slot is
// freed and an audit record written. Run feeds it from Runtime.Exits; a
// home that learns of deaths another way (a cgroup event, a supervisor)
// may call it directly. An exit for a fiber not yet committed is held
// until its Clone commits.
func (a *Agent) OnExit(ctx context.Context, ex FiberExit) {
	fence, session, ok := a.Ledger.OnFiberExit(ex.FiberID)
	if !ok {
		a.pendingMu.Lock()
		if a.pending == nil {
			a.pending = make(map[string]FiberExit)
		}
		a.pending[ex.FiberID] = ex
		a.pendingMu.Unlock()
		return
	}
	// The record is written before anything else observes the freed slot
	// through Watch; the slot itself was freed atomically above.
	if err := a.audit(ctx, a.durability(fence.GrantUID), AuditRecord{Event: ex.Reason, Fence: fence, Session: session, FiberID: ex.FiberID, Detail: ex.Detail}); err != nil {
		log.Printf("audit: %s %s: %v", ex.Reason, ex.FiberID, err)
	}
	a.notify()
}

func (a *Agent) sample(ctx context.Context) {
	ids := a.Ledger.RunningFibers()
	var total uint64
	for _, id := range ids {
		st, err := a.Runtime.Stats(ctx, id)
		if err != nil {
			continue
		}
		a.Ledger.SetFiberW(id, st.WUsedBytes)
		total += st.WUsedBytes
	}
	if len(ids) > 0 && a.Budget != nil {
		a.Budget.ObserveWorkingSet(float64(total) / float64(len(ids)))
	}
}

// Watch streams the per-grant status: on every change and at least every
// StatusInterval. The channel closes when ctx ends.
func (a *Agent) Watch(ctx context.Context) <-chan []Status {
	out := make(chan []Status, 1)
	ch := a.subscribe()
	interval := a.StatusInterval
	if interval <= 0 {
		interval = time.Second
	}
	go func() {
		defer close(out)
		defer a.unsubscribe(ch)
		tick := time.NewTicker(interval)
		defer tick.Stop()
		emit := func() bool {
			select {
			case out <- a.Ledger.Statuses():
				return true
			case <-ctx.Done():
				return false
			}
		}
		if !emit() {
			return
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-ch:
				if !emit() {
					return
				}
			case <-tick.C:
				if !emit() {
					return
				}
			}
		}
	}()
	return out
}

func (a *Agent) subscribe() chan struct{} {
	ch := make(chan struct{}, 1)
	a.changedMu.Lock()
	a.changed = append(a.changed, ch)
	a.changedMu.Unlock()
	return ch
}

func (a *Agent) unsubscribe(ch chan struct{}) {
	a.changedMu.Lock()
	defer a.changedMu.Unlock()
	for i, c := range a.changed {
		if c == ch {
			a.changed = append(a.changed[:i], a.changed[i+1:]...)
			return
		}
	}
}

// notify wakes Watch subscribers and persists the ledger. Every state
// transition ends here, so the snapshot never lags a transition.
func (a *Agent) notify() {
	if a.Store != nil {
		if err := a.Store.Save(a.Ledger.Snapshot()); err != nil {
			log.Printf("snapshot: %v", err)
		}
	}
	a.changedMu.Lock()
	defer a.changedMu.Unlock()
	for _, ch := range a.changed {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (a *Agent) durability(grantUID string) Durability {
	if g, ok := a.Ledger.Grant(grantUID); ok {
		return g.Policy.Durability
	}
	return BestEffort
}

func (a *Agent) audit(ctx context.Context, d Durability, rec AuditRecord) error {
	if a.Audit == nil {
		return nil
	}
	if d == DurabilityUnspecified {
		d = BestEffort
	}
	err := a.Audit.Append(ctx, d, rec)
	if err != nil && d != Sync {
		log.Printf("audit: %s: %v", rec.Event, err)
		return nil
	}
	return err
}
