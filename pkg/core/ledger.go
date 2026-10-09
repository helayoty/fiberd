package core

import (
	"sort"
	"sync"
	"time"
)

// SessionState is the ladder: it is the same triple as the density budget.
type SessionState int

const (
	StateRunning SessionState = iota // running tier: cgroup, fds, address
	StateParked                      // activatable tier: delta on disk
)

// Session couples a stable identity (Name — what "my worker" refers to)
// with a mutable incarnation (Fence — what credentials and claims bind to).
// The name survives incarnations; nothing else does.
type Session struct {
	Name     string
	GrantUID string
	State    SessionState
	Fence    Fence
	Handle   FiberHandle // valid when StateRunning
	// DeltaRef is the parked delta, or, while running, the delta this
	// incarnation was resumed from ("" after a create). That delta stays
	// until the next park supersedes it or a Release discards it.
	DeltaRef string
}

// Action is the resolved outcome of Clone(S): one verb, three costs.
type Action int

const (
	ActCreate Action = iota // S unknown (or anonymous): fork zygote, ms
	ActAttach               // S running: return existing endpoint, ~free
	ActResume               // S parked: restore delta, sub-second
)

func (a Action) String() string {
	switch a {
	case ActAttach:
		return "attach"
	case ActResume:
		return "resume"
	default:
		return "create"
	}
}

// Status is the batched, per-grant view a home publishes. It is the only
// thing a control plane ever sees; never individual fibers.
type Status struct {
	GrantUID   string
	Running    int
	Parked     int
	WUsedBytes uint64
	Latest     Fence // the most recently minted fence for the grant
}

// Ledger is the home-authoritative record of grants and sessions. It is a
// cache of reality: at startup it is rebuilt from Runtime.List reconciled
// against the on-disk snapshot, and discrepancies resolve in favor of what
// is actually running (Phase 3.5 wires the snapshot).
type Ledger struct {
	epoch uint64

	// Now is the clock used for lease expiry. Tests inject it.
	Now func() time.Time

	mu       sync.Mutex
	grants   map[string]*grantEntry
	sessions map[string]*Session  // key: grantUID + "/" + name
	fibers   map[string]*fiberRef // key: fiber (handle) ID

	// perSession serializes concurrent Clone(S) on the same name — this is
	// what makes the verb idempotent under retry. Entries are refcounted
	// and deleted when the last in-flight resolveHeld drops them, so the map is
	// bounded by concurrency, not by session names ever seen.
	perSession map[string]*sessionGate

	// seqHigh is the last seq a revoked grant minted, so a re-admission
	// in the same epoch continues the sequence and never re-mints a
	// fence a released fiber held.
	seqHigh map[string]uint64
}

type sessionGate struct {
	mu   sync.Mutex
	refs int
}

type grantEntry struct {
	grant   Grant
	nextSeq uint64
	live    int // running fibers, reserved at resolveHeld, freed at park/release/exit
}

// fiberRef lets park/release/exit resolve a fiber ID back to the grant
// slot it occupies and, for named sessions, the session to transition.
type fiberRef struct {
	grantUID   string
	sessionKey string // "" for anonymous fibers
	fence      Fence
	wUsed      uint64
}

func NewLedger(epoch uint64) *Ledger {
	return &Ledger{
		epoch:      epoch,
		Now:        time.Now,
		grants:     make(map[string]*grantEntry),
		sessions:   make(map[string]*Session),
		fibers:     make(map[string]*fiberRef),
		perSession: make(map[string]*sessionGate),
		seqHigh:    make(map[string]uint64),
	}
}

func (l *Ledger) Epoch() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.epoch
}

// BumpEpoch moves the ledger to a new epoch in place: every fence minted
// from here on carries it, and every fence minted before is stale by
// construction. The agent releases the running fibers after this call,
// and a clone in flight cannot commit under the old epoch. Parked
// sessions keep their deltas and resume under the new epoch.
func (l *Ledger) BumpEpoch(epoch uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if epoch > l.epoch {
		l.epoch = epoch
	}
}

// AdmitGrant records a verified grant. Its authenticated arrival IS the
// proof that admission and quota already happened; nothing is re-checked
// on the warm path. Idempotent on the UID: a re-delivery refreshes the
// mutable fields in place and never resets nextSeq (fences would be
// reminted) or live (the ceiling would be corrupted). A grant admitted
// again after a revocation continues where it left off.
func (l *Ledger) AdmitGrant(g Grant) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e, ok := l.grants[g.UID]; ok {
		e.grant = g
		return
	}
	l.grants[g.UID] = &grantEntry{grant: g, nextSeq: l.seqHigh[g.UID]}
}

// Grant returns the admitted grant, if any.
func (l *Ledger) Grant(uid string) (Grant, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.grants[uid]
	if !ok {
		return Grant{}, false
	}
	return e.grant, true
}

// GrantBoundTo reports whether the admitted grant uid is bound to the
// client certificate with this thumbprint. An unknown grant is bound to
// nobody.
func (l *Ledger) GrantBoundTo(uid, thumbprint string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.grants[uid]
	return ok && e.grant.CallerThumbprint == thumbprint
}

// RevokeGrant drops the grant. Fibers under it drain by lease
// non-renewal; the reaper (Phase 3.5) tears them down. The last minted
// seq is kept for a re-admission.
func (l *Ledger) RevokeGrant(uid string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e, ok := l.grants[uid]; ok {
		l.seqHigh[uid] = e.nextSeq
	}
	delete(l.grants, uid)
}

func (l *Ledger) acquireSession(key string) *sessionGate {
	l.mu.Lock()
	gate := l.perSession[key]
	if gate == nil {
		gate = &sessionGate{}
		l.perSession[key] = gate
	}
	gate.refs++
	l.mu.Unlock()
	gate.mu.Lock()
	return gate
}

func (l *Ledger) releaseSession(key string, gate *sessionGate) {
	gate.mu.Unlock()
	l.mu.Lock()
	gate.refs--
	if gate.refs == 0 {
		delete(l.perSession, key)
	}
	l.mu.Unlock()
}

// sessionHold is a session's gate taken before resolveHeld. It serializes
// what a caller does first, such as claiming the session's parked state
// from another home, so two first sights of one session claim it once.
// resolveHeld takes the hold over, and the unlock it returns releases it.
type sessionHold struct {
	l    *Ledger
	key  string
	gate *sessionGate
	once sync.Once
}

func (l *Ledger) holdSession(grantUID, session string) *sessionHold {
	key := grantUID + "/" + session
	return &sessionHold{l: l, key: key, gate: l.acquireSession(key)}
}

// release lets the gate go. A nil hold (an anonymous fiber) has none.
func (h *sessionHold) release() {
	if h != nil {
		h.once.Do(func() { h.l.releaseSession(h.key, h.gate) })
	}
}

// resolveHeld decides which of the three paths Clone takes and mints the
// fence for it. The caller does the runtime work and then commits, both
// under the session hold, so one session never runs twice.
//
// Capacity is RESERVED here, not at commit: the runtime clone runs for
// milliseconds between the two, and reserving late would let a concurrent
// burst overshoot fibers.max. If the caller never commits, unlock returns
// the reservation.
//
// commit records nothing and returns false if the grant was revoked or
// the epoch moved meanwhile, even if the grant came back. Such a fiber
// would hold a fence nothing can revoke, so the caller releases it.
//
// tier is the runtime's advertised tier. A grant whose min_tier exceeds it,
// or a parked session on a sub-checkpoint runtime, is ErrNeedsTier: never
// a fresh fork.
//
// hold is nil for an anonymous fiber. Every unlock returned releases it,
// on the error paths too.
func (l *Ledger) resolveHeld(hold *sessionHold, grantUID, session string, tier Tier) (Action, Fence, string, func(Session) bool, func(), error) {
	key := grantUID + "/" + session

	l.mu.Lock()
	defer l.mu.Unlock()

	unlockNoReserve := func() { hold.release() }

	// Re-check under the lock we now hold: the grant may have been revoked
	// while we waited on the session mutex.
	g, ok := l.grants[grantUID]
	if !ok {
		return 0, Fence{}, "", nil, unlockNoReserve, ErrGrantUnknown
	}
	if g.grant.Expired(l.Now()) {
		return 0, Fence{}, "", nil, unlockNoReserve, ErrGrantExpired
	}
	if g.grant.MinTier > tier {
		return 0, Fence{}, "", nil, unlockNoReserve, ErrNeedsTier
	}

	reserved, committed := false, false

	unlock := func() {
		if reserved && !committed {
			l.mu.Lock()
			g.live--
			l.mu.Unlock()
		}
		hold.release()
	}

	mint := func() Fence {
		g.nextSeq++
		return Fence{GrantUID: grantUID, Epoch: l.epoch, Seq: g.nextSeq}
	}
	commit := func(s Session) bool {
		l.mu.Lock()
		defer l.mu.Unlock()
		// The check and the insert share one hold of l.mu, which
		// RevokeGrant and BumpEpoch also take. A revocation either sees
		// the fiber or refuses it, never neither. Comparing the entry by
		// pointer, not presence, catches a revoke then re-admission.
		if l.grants[grantUID] != g || s.Fence.Epoch != l.epoch {
			return false
		}
		committed = true
		if s.Handle.ID != "" {
			ref := &fiberRef{grantUID: grantUID, fence: s.Fence}
			if s.Name != "" {
				ref.sessionKey = key
			}
			l.fibers[s.Handle.ID] = ref
		}
		if s.Name != "" {
			l.sessions[key] = &s
		}
		return true
	}

	reserve := func() error {
		if g.grant.FiberMax > 0 && g.live >= g.grant.FiberMax {
			return ErrGrantFull
		}
		g.live++
		reserved = true
		return nil
	}

	if session != "" {
		if s, ok := l.sessions[key]; ok {
			switch s.State {
			case StateRunning:
				// Attach returns the EXISTING fence: the incarnation did
				// not change, so neither does what credentials bind to.
				return ActAttach, s.Fence, s.Handle.Endpoint, commit, unlock, nil
			case StateParked:
				if tier < TierCheckpoint {
					return 0, Fence{}, "", nil, unlock, ErrNeedsTier
				}
				if err := reserve(); err != nil {
					return 0, Fence{}, "", nil, unlock, err
				}
				return ActResume, mint(), s.DeltaRef, commit, unlock, nil
			}
		}
	}
	if err := reserve(); err != nil {
		return 0, Fence{}, "", nil, unlock, err
	}
	return ActCreate, mint(), "", commit, unlock, nil
}

// SessionState reports a named session's state, if the ledger knows it.
func (l *Ledger) SessionState(grantUID, session string) (SessionState, string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s, ok := l.sessions[grantUID+"/"+session]
	if !ok {
		return 0, "", false
	}
	return s.State, s.DeltaRef, true
}

// ForgetSession drops a parked session (its delta was claimed elsewhere).
func (l *Ledger) ForgetSession(grantUID, session string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if s, ok := l.sessions[grantUID+"/"+session]; ok && s.State == StateParked {
		delete(l.sessions, grantUID+"/"+session)
	}
}

// Fiber returns the fence of a running fiber, or false if the ID is not
// known in this epoch.
func (l *Ledger) Fiber(fiberID string) (Fence, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ref, ok := l.fibers[fiberID]
	if !ok {
		return Fence{}, false
	}
	return ref.fence, true
}

// FiberSession is the session name a running fiber carries, "" for an
// anonymous or unknown fiber.
func (l *Ledger) FiberSession(fiberID string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	ref, ok := l.fibers[fiberID]
	if !ok || ref.sessionKey == "" {
		return ""
	}
	if s, ok := l.sessions[ref.sessionKey]; ok {
		return s.Name
	}
	return ""
}

// FibersOf lists the running fibers of one grant with their session name
// and last sampled W, for the pressure ladder.
func (l *Ledger) FibersOf(grantUID string) []FiberInfo {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []FiberInfo
	for id, ref := range l.fibers {
		if ref.grantUID != grantUID {
			continue
		}
		fi := FiberInfo{ID: id, WUsed: ref.wUsed}
		if ref.sessionKey != "" {
			if s, ok := l.sessions[ref.sessionKey]; ok {
				fi.Session = s.Name
			}
		}
		out = append(out, fi)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// RunningFibers lists the IDs of every running fiber, for the sampler.
func (l *Ledger) RunningFibers() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	ids := make([]string, 0, len(l.fibers))
	for id := range l.fibers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// SetFiberW records the latest dirtied-working-set measurement.
func (l *Ledger) SetFiberW(fiberID string, bytes uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ref, ok := l.fibers[fiberID]; ok {
		ref.wUsed = bytes
	}
}

// OnPark records a successful runtime Park: the fiber leaves the running
// tier (freeing its slot) and, for a named session, the delta ref is kept
// so a later Clone(S) resolves to ActResume. Returns the session name
// ("" for an anonymous fiber, whose delta nobody can ask for) and the
// delta the parked incarnation was resumed from, which this park
// supersedes ("" after a create).
func (l *Ledger) OnPark(fiberID, deltaRef string) (session, superseded string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ref, ok := l.fibers[fiberID]
	if !ok {
		return "", ""
	}
	delete(l.fibers, fiberID)
	if g, ok := l.grants[ref.grantUID]; ok {
		g.live--
	}
	if ref.sessionKey != "" {
		if s, ok := l.sessions[ref.sessionKey]; ok {
			superseded = s.DeltaRef
			s.State = StateParked
			s.DeltaRef = deltaRef
			s.Handle = FiberHandle{}
			return s.Name, superseded
		}
	}
	return "", ""
}

// OnRelease records a successful runtime Release: the slot is freed and
// the session name, if any, is forgotten. Returns that name and the delta
// the released incarnation was resumed from, for a discard ("" when
// there is none).
func (l *Ledger) OnRelease(fiberID string) (session, deltaRef string) {
	_, session, deltaRef, _ = l.onGone(fiberID)
	return session, deltaRef
}

// OnFiberExit records a fiber that died on its own (OOM, exit, signal).
// The slot is freed and a named session is forgotten: its state is gone,
// and pretending it is parked would resume nothing. Returns the fence the
// fiber held and the session name, for the audit record, and the delta
// the fiber was resumed from, for a discard.
func (l *Ledger) OnFiberExit(fiberID string) (fence Fence, session, deltaRef string, ok bool) {
	return l.onGone(fiberID)
}

func (l *Ledger) onGone(fiberID string) (fence Fence, name, deltaRef string, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ref, ok := l.fibers[fiberID]
	if !ok {
		return Fence{}, "", "", false
	}
	delete(l.fibers, fiberID)
	if g, ok := l.grants[ref.grantUID]; ok {
		g.live--
	}
	if ref.sessionKey != "" {
		if s, ok := l.sessions[ref.sessionKey]; ok {
			name, deltaRef = s.Name, s.DeltaRef
		}
		delete(l.sessions, ref.sessionKey)
	}
	return ref.fence, name, deltaRef, true
}

// Statuses computes the view for every admitted grant, sorted by UID.
// One pass over the fibers and one over the sessions, however many
// grants there are.
func (l *Ledger) Statuses() []Status {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Status, 0, len(l.grants))
	slot := make(map[string]int, len(l.grants))
	for uid, e := range l.grants {
		slot[uid] = len(out)
		out = append(out, Status{GrantUID: uid, Running: e.live,
			Latest: Fence{GrantUID: uid, Epoch: l.epoch, Seq: e.nextSeq}})
	}
	for _, ref := range l.fibers {
		if i, ok := slot[ref.grantUID]; ok {
			out[i].WUsedBytes += ref.wUsed
		}
	}
	for _, s := range l.sessions {
		if i, ok := slot[s.GrantUID]; ok && s.State == StateParked {
			out[i].Parked++
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GrantUID < out[j].GrantUID })
	return out
}
