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
	// CallerThumbprint is the x5t#S256 of the client certificate the
	// request arrived over.
	CallerThumbprint string
}

type CloneResponse struct {
	FiberID  string
	Endpoint string
	Fence    Fence
	Kind     Action
	// RoutingKey and ServerKeySHA256 are set for a handoff fiber. They are
	// the TLS server name to send to Endpoint and the pin of the key the
	// fiber must present.
	RoutingKey      string
	ServerKeySHA256 string
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
	// NeedsTier: the grant or session demands a tier this runtime lacks,
	// or the grant lacks what a named session needs (a tenant). Never
	// satisfied by a lesser mechanism.
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

// sweepEvery paces the lease reaper.
const sweepEvery = 5 * time.Second

// DeadlineAdvisor is implemented by runtimes whose create or resume is
// slower than a process fork: what a Clone without an explicit deadline
// is given. The caller's own deadline is always honoured as is.
type DeadlineAdvisor interface {
	DefaultDeadlines() (create, resume time.Duration)
}

// ScopeClaim is one fact a home asserts about where it runs: the
// namespace and service account of a grant Pod, the DRA claim behind a
// fabric channel, the Slurm job. The core never interprets a claim; it
// stamps them on audit records (and, later, on fiber credentials) so a
// reader can check integrity against facts the home vouched for.
type ScopeClaim struct {
	Name  string
	Value string
}

// FabricChannel is what a home provisions for a grant's engine: the
// devices it may drive. Standalone: a static set; Kubernetes: a DRA
// claim; Slurm: the allocation's GRES. It is grant-scoped and released
// with the grant; nothing per fiber refers to it except through its
// fence.
type FabricChannel struct {
	Kind    string   // "static", "dra", "gres", "" for none
	Devices []string // device paths or ids as the engine expects them
	Detail  string   // the claim, the allocation: for the audit record
}

// FabricAware is implemented by runtimes that pass a grant's fabric
// channel to its warm instance (as the engine's device environment).
type FabricAware interface {
	AttachFabric(grantUID string, fc FabricChannel)
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
	// RequireBoundGrants refuses grants without a caller certificate
	// binding. Set it whenever the transport is mutual TLS.
	RequireBoundGrants bool

	Ledger  *Ledger
	Budget  *Budget
	Runtime Runtime
	Audit   Auditor
	Verify  Verifier
	Health  *SourceHealth
	// Pressure, when set, is consulted before any new fiber: a grant that
	// is shedding answers SHED. Nil means no pressure input.
	Pressure *PressureController
	// Store, when set, receives a ledger snapshot after every transition
	// a restart needs, so boot can re-admit grants and remember parked
	// sessions.
	Store *SnapshotStore
	// MobilityBudget overrides the grant's w_budget_bytes as the largest
	// parked state this home will pull (tests, or a home-level cap).
	MobilityBudget func(g Grant) uint64

	// StatusInterval paces the W sampler and the Watch stream. Zero means
	// one second.
	StatusInterval time.Duration

	// Scope, when set, is what the home asserts about where this agent
	// runs (namespace, service account, fabric claim, ...); it is stamped
	// on every audit record. Nil on a standalone host.
	Scope func() []ScopeClaim
	// Fabric, when set, provisions a grant's fabric channel (the devices
	// its engine may use) before its template is warmed, and returns how
	// to release it. Nil means grants get no devices.
	Fabric func(ctx context.Context, g Grant) (FabricChannel, func(), error)
	// Epoch, when set, lets BumpEpoch revoke every fence in place.
	Epoch *EpochStore
	// Revoked, when set, is the deny-list Remove adds to and Admit
	// refuses from. Nil means a removed grant is re-admitted by the next
	// Clone that presents a valid token for it.
	Revoked *Revoked

	fabricMu sync.Mutex
	fabrics  map[string]func() // grant uid -> release

	admitMu   sync.Mutex
	admitting map[string]chan struct{}

	changedMu sync.Mutex
	changed   []chan struct{}

	// pending holds exits that arrived before the fiber was committed to
	// the ledger (a child can die before Clone returns). OnExit's lookup
	// and the commit both run under pendingMu, so no exit is lost between.
	pendingMu sync.Mutex
	pending   map[string]FiberExit
	// exitLookedUp, when set, is called by OnExit once it has looked the
	// fiber up, with whether the ledger knew it. Tests use it to order an
	// exit against a commit.
	exitLookedUp func(fiberID string, known bool)

	// held are snapshot grants boot could not verify because the verifier
	// was unavailable, with their parked sessions. They are not admitted,
	// but every snapshot written carries them until the grant is admitted
	// again or a later boot finds it expired.
	heldMu sync.Mutex
	held   map[string]*heldGrant
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
	g.Token = string(req.GrantJWT)
	if a.NodeID != "" && g.Audience != a.NodeID {
		return CloneResponse{}, Unauthenticated, fmt.Errorf("%w: aud=%q node=%q", ErrWrongAudience, g.Audience, a.NodeID)
	}
	switch {
	case g.CallerThumbprint != "" && g.CallerThumbprint != req.CallerThumbprint:
		return CloneResponse{}, Unauthenticated, ErrCallerMismatch
	case g.CallerThumbprint == "" && a.RequireBoundGrants:
		return CloneResponse{}, Unauthenticated, ErrUnboundGrant
	case g.CallerThumbprint == "" && g.Policy.EndpointMode == EndpointHandoff:
		return CloneResponse{}, Unauthenticated, ErrHandoffUnbound
	}
	// A named session is filed under the grant's tenant when it parks
	// and looked up by it when it resumes. A grant without one cannot do
	// either, so it runs anonymous fibers only. Refused up front, not at
	// the park that would have failed.
	if req.Session != "" && g.Tenant == "" {
		return CloneResponse{}, NeedsTier, fmt.Errorf("%w: grant %s, session %q", ErrNoTenant, g.UID, req.Session)
	}

	// 2. Self-admission: a verified grant that names this home is admitted
	// on first sight. Its signature is the async lane's proof, carried
	// inline. The template is warmed synchronously; homes pre-warm grants
	// they are told about ahead of time so this is normally a no-op.
	if held, known := a.Ledger.Grant(g.UID); !known {
		if code, err := a.Admit(ctx, g); err != nil {
			return CloneResponse{}, code, err
		}
	} else if held.CallerThumbprint != g.CallerThumbprint {
		// The token names another caller than the admitted grant, as when
		// the issuer re-mints the UID with a new cnf. Park, Release and
		// Watch authorize against the admitted grant, so a fiber from this
		// token would answer to the wrong caller. Refuse until the grant is
		// delivered again.
		return CloneResponse{}, Unauthenticated, fmt.Errorf("%w: the token names another caller than the admitted grant", ErrCallerMismatch)
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
	// grant's W budget, else send the caller to the home that has it. This
	// runs under the session's gate, which resolveHeld then takes over. Two
	// first sights of one session wait for each other, so the second finds
	// what the first claimed instead of claiming it again.
	var hold *sessionHold
	if req.Session != "" {
		hold = a.Ledger.holdSession(g.UID, req.Session)
		if code, err := a.locate(ctx, g, req.Session); err != nil {
			hold.release()
			return CloneResponse{}, code, err
		}
	}

	// 4. Ledger: resolve attach | resume | create, mint or reuse the fence.
	act, fence, ref, commit, unlock, err := a.Ledger.resolveHeld(hold, g.UID, req.Session, a.Runtime.Tier())
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
		return a.routed(CloneResponse{FiberID: fence.String(), Endpoint: ref, Fence: fence, Kind: ActAttach}), OK, nil
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
		if errors.Is(err, ErrPressure) {
			// The grant is at its own task limit. That is its own
			// pressure, not a capacity question for the control plane.
			return CloneResponse{}, Shed, err
		}
		return CloneResponse{}, DeferredFallback, err
	}

	// 6. Audit before commit and ack, so under Sync the record is durable
	// first. A failed record rolls the birth back. The fiber is released
	// uncommitted, its slot returns and a resumed session stays parked. If
	// the release itself fails, the fiber is committed anyway so a process
	// that may still run stays counted.
	if err := a.audit(ctx, g.Policy.Durability, AuditRecord{Event: act.String(), Fence: fence, Session: req.Session, FiberID: h.ID}); err != nil {
		if rerr := a.Runtime.Release(ctx, h.ID, false); rerr != nil {
			log.Printf("clone: roll back %s: %v", h.ID, rerr)
			committed, ex, died := a.commitHeld(commit, Session{Name: req.Session, GrantUID: g.UID, State: StateRunning, Fence: fence, Handle: h, DeltaRef: spec.Ref})
			if !committed {
				log.Printf("clone: %s may still run under a revoked grant or epoch and could not be released", h.ID)
			} else if died {
				a.OnExit(ctx, ex)
			}
			return CloneResponse{}, Internal, err
		}
		a.pendingMu.Lock()
		delete(a.pending, h.ID)
		a.pendingMu.Unlock()
		return CloneResponse{}, Internal, err
	}

	// 7. Commit. The ledger refuses if the grant was revoked or the epoch
	// moved while the runtime worked. The sweep missed this fiber, so it is
	// released here with the miss a sweep implies. A resumed session stays
	// parked with its delta. A committed resume keeps that delta's ref,
	// so the next park or a discarding release can drop it. An exit held
	// for the fiber (OOM at birth) is settled below.
	committed, ex, died := a.commitHeld(commit, Session{Name: req.Session, GrantUID: g.UID, State: StateRunning, Fence: fence, Handle: h, DeltaRef: spec.Ref})
	if !committed {
		code, cerr := a.swept(g, fence)
		if rerr := a.Runtime.Release(ctx, h.ID, false); rerr != nil {
			// Not committed either, since there is no grant entry or epoch
			// to count it under. The runtime's List at the next start finds
			// it.
			log.Printf("clone: %s born under a revoked grant or epoch could not be released: %v", h.ID, rerr)
		}
		_ = a.audit(ctx, BestEffort, AuditRecord{Event: "release", Fence: fence, Session: req.Session, FiberID: h.ID, Detail: cerr.Error()})
		return CloneResponse{}, code, cerr
	}
	if act == ActResume {
		// The session runs here now. Its published copy is older state
		// that no home may take and no later Clone may fall back to, so
		// the tag goes. The delta itself stays until the next park or a
		// discarding release.
		if req.Session != "" {
			a.retireDelta(ctx, fence, req.Session, ref)
		}
		a.persist() // the session runs now, so boot must not resume it
	}
	a.notify()
	if died {
		a.OnExit(ctx, ex)
	}
	return a.routed(CloneResponse{FiberID: h.ID, Endpoint: h.Endpoint, Fence: fence, Kind: act}), OK, nil
}

// commitHeld commits a fiber and takes any exit held for it, under pendingMu.
func (a *Agent) commitHeld(commit func(Session) bool, s Session) (committed bool, ex FiberExit, died bool) {
	a.pendingMu.Lock()
	defer a.pendingMu.Unlock()
	committed = commit(s)
	ex, died = a.pending[s.Handle.ID]
	delete(a.pending, s.Handle.ID)
	return committed, ex, died
}

// routed adds what a caller needs to reach a handoff fiber.
func (a *Agent) routed(r CloneResponse) CloneResponse {
	if hr, ok := a.Runtime.(HandoffRouter); ok {
		if key, pin, ok := hr.HandoffRoute(r.FiberID); ok {
			r.RoutingKey, r.ServerKeySHA256 = key, pin
		}
	}
	return r
}

// locate settles where a named session's parked state is before
// resolveHeld runs.
//
//   - Parked here and still ours. resolveHeld resumes it.
//   - Parked here but claimed elsewhere since. It is forgotten and then
//     treated as unknown.
//   - Unknown here but in the shared store. It is claimed, with its delta
//     and parent, if w_used <= w_budget. Otherwise the clone gets a
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
		// The copy here is older state no one may resume. It goes, with
		// the delta quota and the port it held.
		log.Printf("mobility: session %s/%s was claimed by another home; dropping the local copy", g.UID, session)
		a.Ledger.ForgetSession(g.UID, session)
		a.persist()
		fence := Fence{GrantUID: g.UID, Epoch: a.Ledger.Epoch()}
		a.discardDelta(ctx, fence, session, ref)
		_ = a.audit(ctx, BestEffort, AuditRecord{Event: "migrate-out", Fence: fence, Session: session})
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
	if err := a.Ledger.restoreParked(SessionSnapshot{Name: session, GrantUID: g.UID, State: StateParked, DeltaRef: ref}); err != nil {
		if !errors.Is(err, errSessionHeld) {
			// The grant was revoked while the claim ran. The claim took the
			// store's tag, so the copy at ref is the only one. It stays on
			// disk, unregistered, and the caller gets the miss a revocation
			// implies.
			code, cerr := a.swept(g, Fence{GrantUID: g.UID, Epoch: a.Ledger.Epoch()})
			log.Printf("WARNING: mobility: %s/%s was claimed from %s but its grant was revoked meanwhile (%v); the only copy of its state is kept at %s and is not registered", g.UID, session, rd.Home, cerr, ref)
			_ = a.audit(ctx, BestEffort, AuditRecord{Event: "migrate-in", Fence: Fence{GrantUID: g.UID, Epoch: a.Ledger.Epoch()}, Session: session, Detail: fmt.Sprintf("from %s, kept unregistered at %s: %v", rd.Home, ref, cerr)})
			return code, cerr
		}
		// The session arrived here meanwhile. The entry already here is
		// the one that resumes, and this claim pulled a second copy.
		// resolveHeld attaches or resumes.
		log.Printf("mobility: %s/%s is already here; dropping the copy claimed meanwhile, %s", g.UID, session, ref)
		if dd, ok := a.Runtime.(DeltaDiscarder); ok {
			if err := dd.DiscardDelta(ctx, ref); err != nil {
				log.Printf("mobility: discard %s: %v", ref, err)
			}
		}
		return OK, nil
	}
	a.persist()
	// The session is ours now either way. A sync audit failure still
	// refuses this clone, as Park and Release do after their change.
	if err := a.audit(ctx, g.Policy.Durability, AuditRecord{Event: "migrate-in", Fence: Fence{GrantUID: g.UID, Epoch: a.Ledger.Epoch()}, Session: session, Detail: fmt.Sprintf("from %s, %d bytes", rd.Home, rd.WBytes)}); err != nil {
		return Internal, err
	}
	return OK, nil
}

// DeltaDiscarder is implemented by runtimes that can drop a local delta
// ref nothing will resume, such as a claim that found the session already
// here. Without it the copy is left in place and logged.
type DeltaDiscarder interface {
	DiscardDelta(ctx context.Context, deltaRef string) error
}

// Admit records a verified grant and warms its template. Concurrent
// admissions of the same UID wait for the first; a second delivery of an
// already-admitted grant refreshes it in place.
func (a *Agent) Admit(ctx context.Context, g Grant) (StatusCode, error) {
	if g.MinTier > a.Runtime.Tier() {
		return NeedsTier, fmt.Errorf("%w: grant needs %s, runtime is %s", ErrNeedsTier, g.MinTier, a.Runtime.Tier())
	}
	if g.Policy.Isolation.Untrusted() {
		if iso, ok := a.Runtime.(Isolator); !ok || !iso.IsolatesTenants() {
			return NeedsTier, fmt.Errorf("%w: grant %s is %s", ErrNeedsIsolation, g.UID, g.Policy.Isolation)
		}
	}
	if g.Policy.EndpointMode == EndpointHandoff {
		if hr, ok := a.Runtime.(HandoffRouter); !ok || !hr.HandsOff() {
			return NeedsTier, fmt.Errorf("%w: grant %s", ErrNeedsHandoff, g.UID)
		}
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
	// Denied is checked once this admission is in admitting. A Remove
	// that denies the UID either is seen here or waits for this admission
	// and yields what it admitted.
	if a.Revoked != nil && a.Revoked.Denied(g.UID, g.LeaseExpiry, a.Ledger.Now()) {
		return a.missCode(ErrGrantRevoked), fmt.Errorf("%w: %s", ErrGrantRevoked, g.UID)
	}

	// The fabric channel comes before the template: an engine needs its
	// devices at warm-up. It is released with the grant.
	var fabric FabricChannel
	if a.Fabric != nil {
		fc, release, err := a.Fabric(ctx, g)
		if err != nil {
			return a.missCode(ErrNotReady), fmt.Errorf("%w: fabric: %w", ErrNotReady, err)
		}
		fabric = fc
		a.fabricMu.Lock()
		if a.fabrics == nil {
			a.fabrics = map[string]func(){}
		}
		if old := a.fabrics[g.UID]; old != nil {
			old()
		}
		a.fabrics[g.UID] = release
		a.fabricMu.Unlock()
		if fa, ok := a.Runtime.(FabricAware); ok {
			fa.AttachFabric(g.UID, fc)
		}
	}
	if err := a.Runtime.PrepareTemplate(ctx, g); err != nil {
		a.releaseFabric(g.UID)
		return a.missCode(ErrNotReady), fmt.Errorf("%w: %w", ErrNotReady, err)
	}
	if g.DeviceBudget.Bytes > 0 {
		// The template is warm, so the runtime now knows whether its
		// engine holds a device of the class the grant budgets for.
		dc, ok := a.Runtime.(DeviceCapable)
		if !ok || !dc.OffersDevice(g.UID, g.DeviceBudget.Class) {
			// The grant is refused, so nothing would release its channel.
			a.releaseFabric(g.UID)
			return NeedsTier, fmt.Errorf("%w: class %q", ErrNeedsDevice, g.DeviceBudget.Class)
		}
	}
	a.Ledger.AdmitGrant(g)
	a.restoreHeld(g.UID)
	detail := g.TemplateDigest
	if fabric.Kind != "" {
		detail += fmt.Sprintf(" fabric=%s devices=%d %s", fabric.Kind, len(fabric.Devices), fabric.Detail)
	}
	_ = a.audit(ctx, BestEffort, AuditRecord{Event: "admit", Fence: Fence{GrantUID: g.UID, Epoch: a.Ledger.Epoch()}, Detail: detail})
	a.persist()
	a.notify()
	return OK, nil
}

// releaseFabric gives a grant's fabric channel back, if it holds one.
func (a *Agent) releaseFabric(grantUID string) {
	a.fabricMu.Lock()
	release := a.fabrics[grantUID]
	delete(a.fabrics, grantUID)
	a.fabricMu.Unlock()
	if release != nil {
		release()
	}
}

// Revoke drops a grant and releases its fabric channel. Remove, the reaper
// and the ladder's last rung all go through it. It releases no fibers and
// denies nothing. Yield and Remove do that.
func (a *Agent) Revoke(grantUID string) {
	a.Ledger.RevokeGrant(grantUID)
	a.releaseFabric(grantUID)
}

// Remove is the home taking a grant away (GrantRemoved on its lane). The
// UID is denied until every token for it has expired. The grant is yielded
// so its running fibers stop now, not at lease expiry. Parked deltas are
// kept but cannot resume here while the UID is denied.
func (a *Agent) Remove(ctx context.Context, grantUID string) {
	if a.Revoked != nil {
		g, known := a.Ledger.Grant(grantUID)
		lease := g.LeaseExpiry
		if !known {
			// The grant was swept on lease expiry already, or never
			// admitted, so there is no lease to go by, and a zero one
			// would deny the UID for good. Deny it for the ttl from now
			// instead. Only a grant admitted with no lease is denied for
			// good.
			lease = a.Ledger.Now()
		}
		if err := a.Revoked.Add(grantUID, lease, a.Ledger.Now()); err != nil {
			log.Printf("WARNING: revoke %s: persisting the deny-list: %v; it is denied until the agent restarts", grantUID, err)
		}
		// An admission that passed its deny check before the Add above
		// may still be warming. The yield below waits for it, so it
		// finds the grant that admission admits.
		a.admitMu.Lock()
		wait := a.admitting[grantUID]
		a.admitMu.Unlock()
		if wait != nil {
			select {
			case <-wait:
			case <-ctx.Done():
			}
		}
	}
	a.Yield(ctx, grantUID, "removed by the home")
}

// Redeliver lifts a removed grant's denial when the home's lane delivers
// it again (GrantAdded). The lane is the authority. A token that only
// arrives in a Clone request never lifts it.
func (a *Agent) Redeliver(ctx context.Context, grantUID string) {
	if a.Revoked == nil {
		return
	}
	lifted, err := a.Revoked.Clear(grantUID)
	if err != nil {
		log.Printf("WARNING: redeliver %s: persisting the deny-list: %v", grantUID, err)
	}
	if lifted {
		_ = a.audit(ctx, BestEffort, AuditRecord{Event: "redeliver", Fence: Fence{GrantUID: grantUID, Epoch: a.Ledger.Epoch()}, Detail: "the home delivered the grant again"})
	}
}

// BumpEpoch is scope loss without a restart: the home has learned that
// what everything was minted under is gone (its namespace, its
// service-account issuer, a fabric claim) while the agent lives. The
// epoch advances and is persisted, every running fiber is released with
// an audit record naming the reason, and every fence minted before is
// invalid from here: Park and Release answer NotFound, new clones carry
// the new epoch. Grants stay admitted and parked sessions keep their
// deltas; a home that lost a grant's own scope revokes that grant too.
func (a *Agent) BumpEpoch(ctx context.Context, reason string) (uint64, error) {
	if a.Epoch == nil {
		return 0, errors.New("agent: no epoch store to bump")
	}
	next, err := a.Epoch.Bump()
	if err != nil {
		return 0, err
	}
	// Move the epoch first, then sweep. A clone that resolved under the
	// old epoch and commits after this is refused by the ledger and
	// released by its Clone, so nothing minted before survives. A fiber
	// minted under the new epoch between the two calls is kept.
	a.Ledger.BumpEpoch(next)
	released := 0
	for _, id := range a.Ledger.RunningFibers() {
		fence, ok := a.Ledger.Fiber(id)
		if !ok || fence.Epoch >= next {
			continue
		}
		if err := a.Runtime.Release(ctx, id, false); err != nil {
			log.Printf("epoch bump: release %s: %v", id, err)
		}
		// Parked deltas stay. A running fiber's resumed-from delta was
		// consumed by that resume and goes with the fiber.
		if session, deltaRef := a.Ledger.OnRelease(id); deltaRef != "" {
			a.discardDelta(ctx, fence, session, deltaRef)
		}
		if err := a.audit(ctx, a.durability(fence.GrantUID), AuditRecord{Event: "scope-revoked", Fence: fence, FiberID: id, Detail: reason}); err != nil {
			log.Printf("epoch bump: audit %s: %v", id, err)
		}
		released++
	}
	log.Printf("epoch bumped to %d (%s): %d running fibers released, prior fences invalid", next, reason, released)
	a.persist()
	a.notify()
	return next, nil
}

// missCode maps a resolve failure to the outcome. "Capacity not on this
// home" (unknown, full, expired, not ready) is SHED while the grant lane
// is unhealthy and DEFERRED_FALLBACK while it is healthy — a miss must not
// queue into a dead control plane. Nil Health fails toward healthy,
// matching boot bias. A tier, device, isolation or handoff gap is
// neither. It is FailedPrecondition.
func (a *Agent) missCode(err error) StatusCode {
	if errors.Is(err, ErrNeedsTier) || errors.Is(err, ErrNeedsDevice) || errors.Is(err, ErrNeedsIsolation) || errors.Is(err, ErrNeedsHandoff) || errors.Is(err, ErrNoTenant) {
		return NeedsTier
	}
	if a.Health != nil && !a.Health.Healthy(time.Now()) {
		return Shed
	}
	return DeferredFallback
}

// swept names why a clone's commit was refused. The grant was removed
// (denied) or yielded (unknown), or the epoch moved under its fence. Each
// means this home does not hold the capacity, so the code is a miss code
// and the consumer falls back or backs off. NotFound is only for Park and
// Release on a dead fence.
func (a *Agent) swept(g Grant, fence Fence) (StatusCode, error) {
	if epoch := a.Ledger.Epoch(); epoch != fence.Epoch {
		err := fmt.Errorf("%w: epoch moved from %d to %d during clone", ErrFiberUnknown, fence.Epoch, epoch)
		return a.missCode(err), err
	}
	if a.Revoked != nil && a.Revoked.Denied(g.UID, g.LeaseExpiry, a.Ledger.Now()) {
		err := fmt.Errorf("%w: %s, during clone", ErrGrantRevoked, g.UID)
		return a.missCode(err), err
	}
	err := fmt.Errorf("%w: %s revoked during clone", ErrGrantUnknown, g.UID)
	return a.missCode(err), err
}

// Park checkpoints a named session's delta and frees its running tier.
//
// The ledger follows the runtime. Once Runtime.Park returns a ref, the
// delta exists, so the session is parked in the ledger even if a later
// step fails. Otherwise the slot leaks and the delta is orphaned. A failed
// sync audit is returned only after the snapshot and watchers see it.
func (a *Agent) Park(ctx context.Context, fiberID string, sync bool) (string, StatusCode, error) {
	fence, ok := a.Ledger.Fiber(fiberID)
	if !ok {
		return "", NotFound, ErrFiberUnknown
	}
	// Clone refuses a named session under a grant without a tenant, so
	// this holds unless the grant was delivered again without one since.
	// Nothing is parked, because a named delta is filed under the tenant.
	if session := a.Ledger.FiberSession(fiberID); session != "" {
		if g, known := a.Ledger.Grant(fence.GrantUID); known && g.Tenant == "" {
			return "", NeedsTier, fmt.Errorf("%w: grant %s, session %q", ErrNoTenant, g.UID, session)
		}
		// The session's gate, which Clone holds through a resume. A
		// Clone(S) that arrives during the park waits until the delta is
		// parked and published, so it never resumes a checkpoint that
		// is then published as the session's current state.
		hold := a.Ledger.holdSession(fence.GrantUID, session)
		defer hold.release()
	}
	ref, perr := a.Runtime.Park(ctx, fiberID, sync)
	if ref == "" {
		// Nothing was parked, so the fiber runs on and the ledger is right.
		if errors.Is(perr, ErrDeltaQuota) {
			return "", Shed, perr
		}
		if perr == nil {
			perr = errors.New("park: the runtime returned no delta ref")
		}
		return "", Internal, perr
	}
	session, superseded := a.Ledger.OnPark(fiberID, ref)
	if perr != nil {
		log.Printf("park %s: parked as %s, then: %v", fiberID, ref, perr)
	}
	aerr := a.audit(ctx, a.durability(fence.GrantUID), AuditRecord{Event: "park", Fence: fence, FiberID: fiberID, Session: session, Detail: ref})
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
	// The delta this incarnation was resumed from is older than the one
	// just written. Nothing resumes it again.
	if superseded != "" && superseded != ref {
		a.discardDelta(ctx, fence, session, superseded)
	}
	a.persist()
	a.notify()
	switch {
	case perr != nil:
		return ref, Internal, perr
	case aerr != nil:
		return ref, Internal, aerr
	}
	return ref, OK, nil
}

// Release destroys a fiber and frees its name. discard also drops the
// delta the session was resumed from, here and in the store. The ledger
// knows that delta, not the runtime, since a park stores it under the
// parked incarnation and the running one has another fence. As in Park,
// a sync audit record that fails after the ledger changed is reported
// only after the snapshot and the watchers have seen the change.
func (a *Agent) Release(ctx context.Context, fiberID string, discard bool) (StatusCode, error) {
	fence, ok := a.Ledger.Fiber(fiberID)
	if !ok {
		return NotFound, ErrFiberUnknown
	}
	if err := a.Runtime.Release(ctx, fiberID, discard); err != nil {
		return Internal, err
	}
	session, deltaRef := a.Ledger.OnRelease(fiberID)
	if discard && deltaRef != "" {
		a.discardDelta(ctx, fence, session, deltaRef)
	}
	err := a.audit(ctx, a.durability(fence.GrantUID), AuditRecord{Event: "release", Fence: fence, FiberID: fiberID})
	a.notify()
	if err != nil {
		return Internal, err
	}
	return OK, nil
}

// retireDelta withdraws a delta's published copy, on a runtime that
// publishes. A failure leaves the copy to its expiry and is logged, as a
// failed publish is.
func (a *Agent) retireDelta(ctx context.Context, fence Fence, session, deltaRef string) {
	rt, ok := a.Runtime.(DeltaRetirer)
	if !ok {
		return
	}
	if err := rt.RetireDelta(ctx, deltaRef); err != nil {
		log.Printf("mobility: retire %s: %v", deltaRef, err)
		return
	}
	_ = a.audit(ctx, BestEffort, AuditRecord{Event: "retire", Fence: fence, Session: session, Detail: deltaRef})
}

// discardDelta drops a delta nothing will resume again: its published
// copy, if the resume that superseded it could not withdraw it, then the
// local one.
func (a *Agent) discardDelta(ctx context.Context, fence Fence, session, deltaRef string) {
	a.retireDelta(ctx, fence, session, deltaRef)
	dd, ok := a.Runtime.(DeltaDiscarder)
	if !ok {
		return
	}
	if err := dd.DiscardDelta(ctx, deltaRef); err != nil {
		log.Printf("discard %s: %v", deltaRef, err)
		return
	}
	_ = a.audit(ctx, BestEffort, AuditRecord{Event: "discard", Fence: fence, Session: session, Detail: deltaRef})
}

// Yield is the ladder's last rung and the reaper's verb: the grant is
// revoked and every running fiber under it is released, each with its
// audit record. Parked deltas are kept (they are the only state that
// cannot be rebuilt). A valid token presented again re-admits the grant.
// Only Remove denies it.
func (a *Agent) Yield(ctx context.Context, grantUID string, reason string) {
	// Revoke first, then list. A clone that commits after the revocation
	// is refused by the ledger and released by its Clone, so the list
	// below holds every fiber the grant has.
	a.Revoke(grantUID)
	fibers := a.Ledger.FibersOf(grantUID)
	for _, f := range fibers {
		fence, ok := a.Ledger.Fiber(f.ID)
		if !ok {
			continue
		}
		if err := a.Runtime.Release(ctx, f.ID, false); err != nil {
			log.Printf("yield %s: release %s: %v", grantUID, f.ID, err)
		}
		// Parked deltas stay. A running fiber's resumed-from delta was
		// consumed by that resume and goes with the fiber.
		if _, deltaRef := a.Ledger.OnRelease(f.ID); deltaRef != "" {
			a.discardDelta(ctx, fence, f.Session, deltaRef)
		}
		_ = a.audit(ctx, BestEffort, AuditRecord{Event: "yield", Fence: fence, Session: f.Session, FiberID: f.ID, Detail: reason})
	}
	// The warm template goes with the fibers. A re-admission warms it
	// again.
	if td, ok := a.Runtime.(TemplateDropper); ok {
		td.DropTemplate(grantUID)
	}
	_ = a.audit(ctx, BestEffort, AuditRecord{Event: "revoke", Fence: Fence{GrantUID: grantUID, Epoch: a.Ledger.Epoch()}, Detail: reason})
	a.persist()
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

// OnExit records a fiber that died without Park or Release. The slot is
// freed and an audit record written. Run feeds it from Runtime.Exits, and
// a Clone that commits replays an exit held for it. An exit for a fiber
// not yet committed is held until its Clone commits.
func (a *Agent) OnExit(ctx context.Context, ex FiberExit) {
	a.pendingMu.Lock()
	fence, session, deltaRef, ok := a.Ledger.OnFiberExit(ex.FiberID)
	if !ok {
		if a.pending == nil {
			a.pending = make(map[string]FiberExit)
		}
		a.pending[ex.FiberID] = ex
	}
	a.pendingMu.Unlock()
	if a.exitLookedUp != nil {
		a.exitLookedUp(ex.FiberID, ok)
	}
	if !ok {
		return
	}
	// A resumed delta is consumed. The fiber it became is gone, so the
	// delta goes too. Nothing can resume it, and it holds delta quota.
	if deltaRef != "" {
		a.discardDelta(ctx, fence, session, deltaRef)
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

// persist writes the ledger snapshot. Only transitions boot reads back
// call it, which are admit, revoke, park, resume, claim, forget and an
// epoch move. Creating, attaching, releasing and exiting a fiber change
// nothing Reconcile restores, so a warm-path clone writes no file.
func (a *Agent) persist() {
	if a.Store == nil {
		return
	}
	if err := a.Store.Persist(a.snapshot); err != nil {
		log.Printf("snapshot: %v", err)
	}
}

// notify wakes Watch subscribers. Every state transition ends here.
func (a *Agent) notify() {
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
	if a.Scope != nil && rec.Scope == nil {
		if claims := a.Scope(); len(claims) > 0 {
			rec.Scope = make(map[string]string, len(claims))
			for _, c := range claims {
				rec.Scope[c.Name] = c.Value
			}
		}
	}
	err := a.Audit.Append(ctx, d, rec)
	if err != nil && d != Sync {
		log.Printf("audit: %s: %v", rec.Event, err)
		return nil
	}
	return err
}
